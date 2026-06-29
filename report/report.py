"""
Report Generator Module
Generates a modern HTML penetration testing report using Jinja2.
"""

import json
import html
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader, Undefined


# ---------------------------------------------------------------------------
# Single source of truth for Nikto severity classification (Fix #4)
# Used by both _calculate_statistics() and exposed to the template via context
# so report.html never needs to re-implement this logic independently.
# ---------------------------------------------------------------------------
SEVERITY_RULES = [
    ("critical", ["critical", "remote code execution", "rce"]),
    ("high",     ["sql injection", "xss", "cross site scripting",
                  "command injection", "file include", "file inclusion"]),
    ("medium",   ["misconfiguration", "misconfig", "directory listing",
                  "information disclosure"]),
    ("low",      ["low"]),
]

def classify_nikto_finding(finding: dict) -> str:
    """
    Classify a single Nikto finding into a severity level.
    Single definition used by both Python stats and exposed to Jinja2
    so the template never duplicates this logic (Fix #4).
    """
    desc = (finding.get("description", "") or "").lower()
    risk = (finding.get("risk", "") or "").lower()
    combined = desc + " " + risk

    for severity, keywords in SEVERITY_RULES:
        if any(kw in combined for kw in keywords):
            return severity
    return "informational"


class ReportGenerator:
    """Generate comprehensive HTML reports from reconnaissance data."""

    RISK_MAP = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 0
    }

    # Priority order for recommendations display (Fix #6)
    REC_PRIORITY_PREFIXES = [
        "Replace FTP",
        "Replace Telnet",
        "Restrict RDP",
        "Implement parameterized",
        "Implement Content Security",
        "Remove or restrict access",
        "Remove phpMyAdmin",
        "Enforce HTTPS",
        "Restrict database",
        "Disable directory listing",
        "Close or restrict",
        "Remove or obfuscate",
        "Update all outdated",
        "Add X-Frame-Options",
        "Configure SMTP",
        "Disable password-based SSH",
        "Harden WordPress",
    ]

    def __init__(self, results: Dict[str, Any], output_path: str,
                 template_dir: Path, assets_dir: Optional[Path] = None):
        self.results = results
        self.output_path = output_path
        self.template_dir = template_dir
        self.assets_dir = assets_dir or (template_dir.parent / "assets")

    def _calculate_statistics(self) -> Dict[str, Any]:
        """Compute aggregate statistics from all scan results."""
        stats = {
            "total_open_ports": 0,
            "total_directories": 0,
            "total_vulnerabilities": 0,
            "total_subdomains": 0,
            "total_emails": 0,
            "total_hosts": 0,
            "total_ips": 0,
            "risk_counts": {
                "critical": 0, "high": 0, "medium": 0,
                "low": 0, "informational": 0
            },
            "services": {},
            "top_ports": []
        }

        # Nmap stats
        nmap_data = self.results.get("nmap") or {}
        ports = nmap_data.get("ports") or []
        # Guard: ensure ports is actually a list (Fix #3)
        if not isinstance(ports, list):
            ports = []
        open_ports = [p for p in ports if isinstance(p, dict) and p.get("state") == "open"]
        stats["total_open_ports"] = len(open_ports)

        for p in open_ports:
            svc = p.get("service", "unknown") or "unknown"
            stats["services"][svc] = stats["services"].get(svc, 0) + 1

        stats["top_ports"] = [
            p["port"] for p in sorted(open_ports, key=lambda x: x.get("port", 0))[:20]
        ]

        # Gobuster stats
        gobuster_data = self.results.get("gobuster") or {}
        dirs = gobuster_data.get("directories") or []
        if not isinstance(dirs, list):
            dirs = []
        stats["total_directories"] = len(dirs)

        # Nikto stats — use shared classify_nikto_finding() (Fix #4)
        nikto_data = self.results.get("nikto") or {}
        findings = nikto_data.get("findings") or []
        if not isinstance(findings, list):
            findings = []
        stats["total_vulnerabilities"] = len(findings)

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = classify_nikto_finding(finding)
            stats["risk_counts"][severity] += 1

        # theHarvester stats
        harvester_data = self.results.get("harvester") or {}
        stats["total_emails"]    = len(harvester_data.get("emails") or [])
        stats["total_subdomains"] = len(harvester_data.get("subdomains") or [])
        stats["total_hosts"]     = len(harvester_data.get("hosts") or [])
        stats["total_ips"]       = len(harvester_data.get("ips") or [])

        # Fallback: if nothing was classified, mark all as informational
        if (all(v == 0 for v in stats["risk_counts"].values())
                and stats["total_vulnerabilities"] > 0):
            stats["risk_counts"]["informational"] = stats["total_vulnerabilities"]

        return stats

    def _generate_recommendations(self) -> list:
        """Generate remediation advice based on findings, ordered by priority (Fix #6)."""
        recommendations = set()

        nmap_data     = self.results.get("nmap") or {}
        gobuster_data = self.results.get("gobuster") or {}
        nikto_data    = self.results.get("nikto") or {}

        # Open ports
        open_ports   = [p for p in (nmap_data.get("ports") or [])
                        if isinstance(p, dict) and p.get("state") == "open"]
        services_set = set(p.get("service", "") or "" for p in open_ports)

        if "ftp" in services_set:
            recommendations.add("Replace FTP with SFTP or FTPS for secure file transfer.")
        if "telnet" in services_set:
            recommendations.add("Replace Telnet with SSH for remote administration.")
        if services_set & {"http", "http-alt", "http-proxy"}:
            recommendations.add(
                "Enforce HTTPS with valid TLS certificates and "
                "HTTP Strict Transport Security (HSTS)."
            )
        if services_set & {"mysql", "postgresql"}:
            recommendations.add(
                "Restrict database ports to trusted IPs only. "
                "Use strong authentication and encryption."
            )
        if services_set & {"ms-sql-s", "ms-sql"}:
            recommendations.add(
                "Ensure MSSQL is not exposed to the public internet. "
                "Use Windows Authentication mode."
            )
        if services_set & {"rdp", "ms-wbt-server"}:
            recommendations.add(
                "Restrict RDP access with VPN and "
                "Network Level Authentication (NLA)."
            )
        if "smtp" in services_set:
            recommendations.add(
                "Configure SMTP with TLS and SPF/DKIM/DMARC records "
                "to prevent email spoofing."
            )
        if "ssh" in services_set:
            recommendations.add(
                "Disable password-based SSH authentication. "
                "Use key-based authentication only."
            )
        if len(open_ports) > 10:
            recommendations.add(
                f"Close or restrict {len(open_ports)} open ports. "
                "Only expose necessary services to the internet."
            )

        # Gobuster findings
        directories = gobuster_data.get("directories") or []
        found_paths = [
            d.get("url", d.get("path", "")) for d in directories
            if isinstance(d, dict)
        ]
        for path in found_paths:
            lp = path.lower()
            if any(x in lp for x in [".git", ".svn", ".env", "backup", "config", "admin"]):
                recommendations.add(
                    f"Remove or restrict access to exposed sensitive paths ({path})."
                )
            if "wp-admin" in lp or "wp-content" in lp:
                recommendations.add(
                    "Harden WordPress installation: update core, plugins, and themes. "
                    "Remove unused installations."
                )
            if "phpmyadmin" in lp:
                recommendations.add(
                    "Remove phpMyAdmin or restrict access with "
                    "IP whitelisting and authentication."
                )
            if any(x in lp for x in ["dashboard", "logs", "debug", "test"]):
                recommendations.add(
                    f"Remove or password-protect development/debug endpoints ({path})."
                )
        if directories:
            recommendations.add(
                "Disable directory listing on web servers "
                "to prevent information disclosure."
            )

        # Nikto findings
        nikto_findings = nikto_data.get("findings") or []
        descriptions   = " ".join(
            (f.get("description", "") or "") for f in nikto_findings
            if isinstance(f, dict)
        ).lower()
        headers = nikto_data.get("headers") or {}

        if "x-powered-by" in descriptions or "x-powered-by" in str(headers).lower():
            recommendations.add(
                "Remove or obfuscate X-Powered-By and Server headers "
                "to reduce attack surface."
            )
        if "directory listing" in descriptions:
            recommendations.add(
                "Disable directory listing in web server configuration."
            )
        if any(kw in descriptions for kw in ["outdated", "old version", "deprecated"]):
            recommendations.add(
                "Update all outdated web server software, libraries, and components "
                "to latest stable versions."
            )
        if "sql injection" in descriptions:
            recommendations.add(
                "Implement parameterized queries and input validation "
                "to prevent SQL injection."
            )
        if "cross site scripting" in descriptions or "xss" in descriptions:
            recommendations.add(
                "Implement Content Security Policy (CSP) headers and output encoding "
                "to prevent XSS."
            )
        if "clickjacking" in descriptions:
            recommendations.add(
                "Add X-Frame-Options (DENY) or "
                "Content-Security-Policy: frame-ancestors headers."
            )

        if not recommendations:
            recommendations.update([
                "Conduct regular security assessments and vulnerability scans.",
                "Implement a Web Application Firewall (WAF) for additional protection.",
                "Enable comprehensive logging and monitoring with alerting.",
            ])

        # Sort by known priority order first, then alphabetically for the rest (Fix #6)
        def priority_key(rec: str) -> tuple:
            for i, prefix in enumerate(self.REC_PRIORITY_PREFIXES):
                if rec.startswith(prefix):
                    return (0, i, rec)
            return (1, 0, rec)

        return sorted(list(recommendations), key=priority_key)

    def _serialize_for_template(self, obj):
        """
        Safe JSON serialization fallback for json.dumps (Fix #2).
        Handles sets, datetimes, Paths, and any other non-serializable type
        gracefully instead of raising TypeError.
        """
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Path):
            return str(obj)
        # Last resort: convert to string so json.dumps never crashes
        try:
            return str(obj)
        except Exception:
            return "<unserializable>"

    def _safe_list(self, data, key: str) -> list:
        """Return a guaranteed list from nested result data."""
        value = (data or {}).get(key)
        if isinstance(value, list):
            return value
        return []

    def generate(self) -> str:
        """Generate the HTML report using Jinja2 template."""
        stats           = self._calculate_statistics()
        recommendations = self._generate_recommendations()

        # Fix #7: guarantee duration_seconds is always an int
        raw_duration = self.results.get("metadata", {}).get("duration_seconds", 0)
        try:
            duration_seconds = int(raw_duration)
        except (TypeError, ValueError):
            duration_seconds = 0

        # Fix #5: use scan start_time as scan_date when available, fall back to now
        start_time_raw = self.results.get("metadata", {}).get("start_time", "")
        if start_time_raw:
            try:
                scan_date = datetime.fromisoformat(str(start_time_raw)).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            except (ValueError, TypeError):
                scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        else:
            scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Fix #1: sanitize stats_json — strip any HTML/script-injectable characters
        # before serializing so |safe in template cannot be exploited.
        raw_stats_json = json.dumps(stats, default=self._serialize_for_template)
        # Escape </script> sequences that could break out of the JS block
        safe_stats_json = raw_stats_json.replace("</", "<\\/")

        # Nikto findings: attach pre-computed severity so template never
        # re-implements classification logic (Fix #4)
        nikto_findings_raw = self.results.get("nikto", {}).get("findings") or []
        if not isinstance(nikto_findings_raw, list):
            nikto_findings_raw = []
        nikto_findings_enriched = []
        for f in nikto_findings_raw:
            if isinstance(f, dict):
                enriched = dict(f)
                enriched["_severity"] = classify_nikto_finding(f)
                nikto_findings_enriched.append(enriched)

        context = {
            "target":      self.results.get("metadata", {}).get("target", "Unknown"),
            "target_type": self.results.get("metadata", {}).get("target_type", "unknown") or "unknown",
            "scan_date":   scan_date,                          # Fix #5
            "start_time":  start_time_raw,
            "end_time":    self.results.get("metadata", {}).get("end_time", ""),
            "duration_seconds": duration_seconds,              # Fix #7
            "tools_executed":   self.results.get("metadata", {}).get("tools_executed") or [],

            # Nmap — guaranteed lists (Fix #3)
            "nmap_host_status": self.results.get("nmap", {}).get("host_status", "Not scanned"),
            "nmap_os":          self.results.get("nmap", {}).get("os", ""),
            "nmap_ip":          self.results.get("nmap", {}).get("ip_address", ""),
            "nmap_hostname":    self.results.get("nmap", {}).get("hostname", ""),
            "nmap_ports":       self._safe_list(self.results.get("nmap"), "ports"),

            # Gobuster
            "gobuster_directories": self._safe_list(self.results.get("gobuster"), "directories"),

            # Nikto — enriched with _severity field (Fix #4)
            "nikto_scan_info": self.results.get("nikto", {}).get("scan_info") or {},
            "nikto_server":    self.results.get("nikto", {}).get("server_banner", ""),
            "nikto_findings":  nikto_findings_enriched,

            # theHarvester
            "harvester_emails":     self._safe_list(self.results.get("harvester"), "emails"),
            "harvester_hosts":      self._safe_list(self.results.get("harvester"), "hosts"),
            "harvester_subdomains": self._safe_list(self.results.get("harvester"), "subdomains"),
            "harvester_ips":        self._safe_list(self.results.get("harvester"), "ips"),

            # Stats & recommendations
            "stats":         stats,
            "recommendations": recommendations,

            # Fix #1: pre-sanitized JSON string for the chart script block
            "stats_json": safe_stats_json,
        }

        # Load Jinja2 environment — autoescape handles all {{ }} variables;
        # stats_json is sanitized above so |safe is safe to use (Fix #1)
        env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )

        template_file = "report.html"
        template_path = self.template_dir / template_file
        if not template_path.exists():
            raise FileNotFoundError(f"Report template not found: {template_path}")

        template = env.get_template(template_file)

        # Fix #3: wrap render in try/except to surface template errors clearly
        try:
            html_content = template.render(**context)
        except Exception as e:
            raise RuntimeError(
                f"Failed to render report template '{template_file}': {e}"
            ) from e

        output_path = Path(self.output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_content, encoding="utf-8")

        return str(output_path.resolve())
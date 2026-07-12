"""
theHarvester Scanner Module
Performs passive OSINT gathering (emails, subdomains, hosts, IPs).
"""

import subprocess
import json
from pathlib import Path


class HarvesterScanner:
    """Orchestrates theHarvester passive reconnaissance."""

    def __init__(self, target: str, output_dir: Path, logger=None):
        self.target = target
        self.output_dir = output_dir
        self.logger = logger
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _parse_source_output(self, output_base: str) -> dict:
        """Parse theHarvester output files from a single source run."""
        result = {"emails": [], "hosts": [], "subdomains": [], "ips": []}

        json_path = Path(output_base + ".json")
        xml_path = Path(output_base + ".xml")

        # Prefer JSON
        if json_path.exists():
            try:
                with open(json_path, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    result["emails"] = data.get("emails", []) or []
                    hosts = data.get("hosts", []) or []
                    for h in hosts:
                        if isinstance(h, dict):
                            hostname = h.get("hostname", h.get("host", ""))
                            ip = h.get("ip", h.get("ip_address", ""))
                            if hostname:
                                result["hosts"].append({"hostname": hostname, "ip": ip or ""})
                                result["subdomains"].append(hostname)
                            if ip:
                                result["ips"].append(ip)
                        elif isinstance(h, str):
                            result["hosts"].append({"hostname": h, "ip": ""})
                            result["subdomains"].append(h)
                    result["ips"].extend(data.get("ips", []) or [])
                    result["subdomains"].extend(data.get("subdomains", []) or [])
            except Exception:
                pass

        # Fallback to XML
        if not result["emails"] and not result["hosts"] and xml_path.exists():
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(str(xml_path))
                root = tree.getroot()
                for email in root.findall(".//email"):
                    if email.text:
                        result["emails"].append(email.text.strip())
                for host in root.findall(".//host"):
                    hostname_elem = host.find("hostname")
                    ip_elem = host.find("ip")
                    hostname = hostname_elem.text.strip() if hostname_elem is not None and hostname_elem.text else ""
                    ip = ip_elem.text.strip() if ip_elem is not None and ip_elem.text else ""
                    if hostname:
                        result["hosts"].append({"hostname": hostname, "ip": ip})
                        result["subdomains"].append(hostname)
                    if ip:
                        result["ips"].append(ip)
                for sub in root.findall(".//subdomain"):
                    if sub.text:
                        result["subdomains"].append(sub.text.strip())
            except Exception:
                pass

        # Cleanup temp files for this source
        for ext in [".json", ".xml", ".html"]:
            try:
                Path(output_base + ext).unlink(missing_ok=True)
            except Exception:
                pass

        return result

    def _merge_results(self, merged: dict, new: dict):
        """Merge new source results into the cumulative dict."""
        for email in new.get("emails", []):
            if email not in merged["emails"]:
                merged["emails"].append(email)
        for host in new.get("hosts", []):
            hostname = host.get("hostname", "")
            if hostname and not any(h.get("hostname") == hostname for h in merged["hosts"]):
                merged["hosts"].append(host)
        for sub in new.get("subdomains", []):
            if sub not in merged["subdomains"]:
                merged["subdomains"].append(sub)
        for ip in new.get("ips", []):
            if ip not in merged["ips"]:
                merged["ips"].append(ip)

    def scan(self) -> bool:
        """Run theHarvester against multiple search sources, aggregating all results."""
        output_base = str(self.output_dir / "harvester_src")

        sources = [
            "baidu", "bing", "brave", "duckduckgo", "yahoo",
            "certspotter", "commoncrawl", "crtsh",
            "bevigil",
            "bitbucket", "github-code", "gitlab",
            "bufferoverun", "fofa", "fullhunt", "hackertarget",
            "netlas", "onyphe", "otx", "rapiddns", "robtex",
            "shodan", "subdomaincenter", "subdomainfinderc99",
            "threatcrowd", "urlscan", "virustotal", "waybackarchive",
            "whoisxml", "windvane", "zoomeye",
            "builtwith", "censys", "chaos", "criminalip",
            "dehashed", "hunter", "hunterhow", "intelx",
            "leakix", "leaklookup", "pentesttools", "projectdiscovery",
            "rocketreach", "securityscorecard", "securityTrails",
            "thc", "tomba", "venacus",
            "haveibeenpwned", "hudsonrock",
        ]

        merged = {"emails": [], "hosts": [], "subdomains": [], "ips": []}
        success_count = 0

        for source in sources:
            cmd = [
                "theHarvester",
                "-d", self.target,
                "-b", source,
                "-f", output_base,
            ]

            self.logger.info(f"  Running: theHarvester -d {self.target} -b {source}")

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

                # Parse output from this source and merge
                source_result = self._parse_source_output(output_base)
                self._merge_results(merged, source_result)

                if result.returncode == 0:
                    success_count += 1
                else:
                    self.logger.debug(f"  [!] theHarvester ({source}) exit code: {result.returncode}")

            except subprocess.TimeoutExpired:
                self.logger.warning(f"  [!] theHarvester ({source}) timed out")
                continue
            except FileNotFoundError:
                self.logger.error("  [!] theHarvester executable not found")
                return False
            except Exception as e:
                self.logger.error(f"  [!] theHarvester ({source}) failed: {e}")
                continue

        self.logger.info(f"  Sources completed: {success_count}/{len(sources)}")

        # Save aggregated results
        final_json = self.output_dir / "harvester.json"
        with open(final_json, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2)

        if merged["emails"] or merged["hosts"] or merged["subdomains"]:
            self.logger.info(f"  [✓] theHarvester completed — "
                             f"{len(merged['emails'])} emails, "
                             f"{len(merged['subdomains'])} subdomains, "
                             f"{len(merged['ips'])} IPs")
            return True
        else:
            self.logger.warning("  [!] theHarvester produced no results")
            return False
"""
JSON Parser Module
Parses JSON output files from security tools.
"""

import json
from typing import Dict, Any


class JsonParser:
    """Parse JSON-formatted output from various security tools."""

    def parse_gobuster_json(self, json_path: str) -> Dict[str, Any]:
        """
        Parse Gobuster JSON output.

        Gobuster JSON format (one JSON object per line):
        {"path":"/admin","status":200,"size":1234}
        """
        result = {
            "directories": [],
            "errors": []
        }

        try:
            with open(json_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if "path" in entry:
                            result["directories"].append({
                                "url": entry.get("path", ""),
                                "status": entry.get("status", 0),
                                "size": str(entry.get("size", "")),
                                "method": entry.get("method", "GET")
                            })
                    except json.JSONDecodeError:
                        continue

            # Sort by status code
            result["directories"].sort(key=lambda d: d["status"])

        except FileNotFoundError:
            raise FileNotFoundError(f"Gobuster JSON file not found: {json_path}")
        except Exception as e:
            raise ValueError(f"Failed to parse Gobuster JSON: {e}")

        return result

    def parse_harvester_json(self, json_path: str) -> Dict[str, Any]:
        """
        Parse theHarvester JSON output.

        Structure varies by version. Common format:
        {
            "emails": ["a@b.com", ...],
            "hosts": [{"hostname": "...", "ip": "..."}, ...],
            "interesting_urls": [...]
        }
        """
        result = {
            "emails": [],
            "hosts": [],
            "subdomains": [],
            "ips": []
        }

        try:
            with open(json_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)

            # Emails
            emails = data.get("emails", [])
            if isinstance(emails, list):
                result["emails"] = [e.strip() for e in emails if e.strip()]

            # Hosts (various possible formats)
            hosts = data.get("hosts", data.get("hostnames", []))
            if isinstance(hosts, list):
                for h in hosts:
                    if isinstance(h, dict):
                        hostname = h.get("hostname", h.get("host", ""))
                        ip = h.get("ip", h.get("ip_address", ""))
                        result["hosts"].append({
                            "hostname": hostname.strip() if hostname else "",
                            "ip": ip.strip() if ip else ""
                        })
                        if hostname and hostname not in result["subdomains"]:
                            result["subdomains"].append(hostname.strip())
                        if ip and ip not in result["ips"]:
                            result["ips"].append(ip.strip())
                    elif isinstance(h, str):
                        result["hosts"].append({"hostname": h.strip(), "ip": ""})
                        if h.strip() not in result["subdomains"]:
                            result["subdomains"].append(h.strip())

            # IPs
            ips = data.get("ips", [])
            if isinstance(ips, list):
                for ip in ips:
                    if ip not in result["ips"]:
                        result["ips"].append(ip)

            # Subdomains
            subdomains = data.get("subdomains", [])
            if isinstance(subdomains, list):
                for s in subdomains:
                    if s not in result["subdomains"]:
                        result["subdomains"].append(s)

        except FileNotFoundError:
            raise FileNotFoundError(f"theHarvester JSON file not found: {json_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse theHarvester JSON: {e}")
        except Exception as e:
            raise ValueError(f"Failed to parse theHarvester JSON: {e}")

        return result

    def parse_generic_json(self, json_path: str) -> Dict[str, Any]:
        """
        Parse any generic JSON file and return as dict.
        """
        try:
            with open(json_path, "r", encoding="utf-8", errors="replace") as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"JSON file not found: {json_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON file: {e}")
"""
TXT Parser Module
Parses text output files from security tools using regex and string processing.
"""

import re
from typing import Dict, Any, List


class TxtParser:
    """Parse text-based output from various security tools."""

    def parse_gobuster(self, txt_path: str) -> Dict[str, Any]:
        """
        Parse Gobuster plaintext output.

        Structure returned:
        {
            "directories": [{"url": str, "status": int, "size": str}, ...],
            "errors": [str, ...]
        }
        """
        result = {
            "directories": [],
            "errors": []
        }

        # Pattern: /path (Status: 200) [Size: 1234]
        dir_pattern = re.compile(
            r'(https?://\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*([^\]]+)\]'
        )
        # Alternate pattern: /path (Status: 200) [Size: 1234]
        alt_pattern = re.compile(
            r'(\/\S+)\s+\(Status:\s*(\d+)\)'
        )

        try:
            with open(txt_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()

                    # Try full URL pattern first
                    match = dir_pattern.search(line)
                    if match:
                        result["directories"].append({
                            "url": match.group(1),
                            "status": int(match.group(2)),
                            "size": match.group(3).strip()
                        })
                        continue

                    # Try relative path pattern
                    match = alt_pattern.search(line)
                    if match:
                        result["directories"].append({
                            "url": match.group(1),
                            "status": int(match.group(2)),
                            "size": ""
                        })
                        continue

                    # Error lines
                    if any(keyword in line.lower() for keyword in
                           ["error", "timeout", "failed", "invalid"]):
                        result["errors"].append(line)

        except FileNotFoundError:
            raise FileNotFoundError(f"Gobuster output file not found: {txt_path}")
        except Exception as e:
            raise ValueError(f"Failed to parse Gobuster output: {e}")

        return result

    def parse_nikto_text(self, txt_path: str) -> Dict[str, Any]:
        """
        Parse Nikto plaintext output (fallback when XML parsing fails).

        Structure returned:
        {
            "scan_info": {},
            "findings": [{"description": str, "uri": str, "method": str}, ...]
        }
        """
        result = {
            "scan_info": {},
            "findings": []
        }

        finding_pattern = re.compile(
            r'^\+?\s*(OSVDB-\d+)?\s*:?\s*(GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|TRACE|CONNECT)?\s*(\S+)\s*(.*)'
        )

        try:
            with open(txt_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Banner / server info
                    if ":" in line and len(line) < 200:
                        parts = line.split(":", 1)
                        key = parts[0].strip().lower().replace(" ", "_")
                        val = parts[1].strip()
                        if key in ["server", "x-powered-by", "x-aspnet-version"]:
                            result["scan_info"][key] = val

                    # Finding line
                    match = finding_pattern.search(line)
                    if match:
                        finding = {
                            "osvdb": match.group(1) or "",
                            "method": match.group(2) or "",
                            "uri": match.group(3) or "",
                            "description": match.group(4) or line
                        }
                        result["findings"].append(finding)

        except FileNotFoundError:
            raise FileNotFoundError(f"Nikto text file not found: {txt_path}")
        except Exception as e:
            raise ValueError(f"Failed to parse Nikto text output: {e}")

        return result

    def parse_harvester_text(self, txt_path: str) -> Dict[str, Any]:
        """
        Parse theHarvester plaintext output.

        Structure returned:
        {
            "emails": [str, ...],
            "hosts": [str, ...],
            "ips": [str, ...]
        }
        """
        result = {
            "emails": [],
            "hosts": [],
            "ips": []
        }

        email_pattern = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        host_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')

        try:
            with open(txt_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            # Extract emails
            emails = email_pattern.findall(content)
            result["emails"] = list(set(emails))

            # Extract IPs
            ips = ip_pattern.findall(content)
            # Filter out 0.0.0.0 and obvious non-routable
            result["ips"] = list(set(
                ip for ip in ips if ip != "0.0.0.0"
            ))

            # Extract hosts/domains
            hosts = host_pattern.findall(content)
            # Filter out common non-host matches
            filtered = []
            for h in hosts:
                if not any(x in h for x in ['localhost', 'example']) and \
                   not h.endswith('.local'):
                    filtered.append(h)
            result["hosts"] = list(set(filtered))

        except FileNotFoundError:
            raise FileNotFoundError(f"theHarvester text file not found: {txt_path}")
        except Exception as e:
            raise ValueError(f"Failed to parse theHarvester text: {e}")

        return result
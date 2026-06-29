"""
XML Parser Module
Parses Nmap, Nikto, and theHarvester XML output files.
"""

import xml.etree.ElementTree as ET
from typing import Dict, Any, List
import re


class XMLParser:
    """Parse various XML output formats from security tools."""

    def parse_nmap(self, xml_path: str) -> Dict[str, Any]:
        """
        Parse Nmap XML output.

        Structure returned:
        {
            "host_status": str,
            "hostname": str,
            "ip_address": str,
            "os": str,
            "ports": [{"port": int, "protocol": str, "state": str, "service": str, "version": str}, ...]
        }
        """
        result = {
            "host_status": "unknown",
            "hostname": "",
            "ip_address": "",
            "os": "",
            "ports": [],
            "raw_data": {}
        }

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            # Process each host
            for host in root.findall(".//host"):
                # Host status
                status = host.find("status")
                if status is not None:
                    result["host_status"] = status.get("state", "unknown")

                # Address
                address = host.find("address")
                if address is not None:
                    addr_type = address.get("addrtype", "")
                    if addr_type == "ipv4":
                        result["ip_address"] = address.get("addr", "")
                    elif addr_type == "ipv6":
                        if not result["ip_address"]:
                            result["ip_address"] = address.get("addr", "")

                # Hostnames
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    for h in hostnames.findall("hostname"):
                        name = h.get("name", "")
                        if name and not result["hostname"]:
                            result["hostname"] = name

                # OS detection
                os_elem = host.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        result["os"] = osmatch.get("name", "")

                # Ports
                ports = host.find("ports")
                if ports is not None:
                    for port in ports.findall("port"):
                        port_data = {
                            "port": int(port.get("portid", 0)),
                            "protocol": port.get("protocol", ""),
                            "state": "unknown",
                            "service": "",
                            "version": "",
                            "product": "",
                            "extrainfo": ""
                        }

                        state_elem = port.find("state")
                        if state_elem is not None:
                            port_data["state"] = state_elem.get("state", "unknown")

                        service_elem = port.find("service")
                        if service_elem is not None:
                            port_data["service"] = service_elem.get("name", "")
                            port_data["product"] = service_elem.get("product", "")
                            port_data["version"] = service_elem.get("version", "")
                            port_data["extrainfo"] = service_elem.get("extrainfo", "")

                            # Combine product and version
                            if port_data["product"]:
                                if port_data["version"]:
                                    port_data["version"] = f"{port_data['product']} {port_data['version']}"
                                else:
                                    port_data["version"] = port_data["product"]

                        result["ports"].append(port_data)

            # Sort ports by port number
            result["ports"].sort(key=lambda p: p["port"])

        except ET.ParseError as e:
            raise ValueError(f"Failed to parse Nmap XML: {e}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Nmap XML file not found: {xml_path}")

        return result

    def parse_nikto(self, xml_path: str) -> Dict[str, Any]:
        """
        Parse Nikto XML output.

        Structure returned:
        {
            "scan_info": {"host": str, "ip": str, "port": int},
            "findings": [{"id": str, "osvdb": str, "method": str, "uri": str, "description": str, ...}, ...]
        }
        """
        result = {
            "scan_info": {},
            "findings": [],
            "server_banner": "",
            "headers": {}
        }

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            # Scan information
            for key in ["host", "ip", "port", "banner"]:
                elem = root.find(f".//{key}")
                if elem is not None and key == "banner":
                    result["server_banner"] = elem.text or ""
                elif elem is not None:
                    result["scan_info"][key] = elem.text or elem.get("value", "")

            # Findings
            for item in root.findall(".//item"):
                finding = {}
                for child in item:
                    tag = child.tag.lower()
                    text = child.text or ""
                    finding[tag] = text
                if finding:
                    result["findings"].append(finding)

            # Also parse plaintext output if XML doesn't have structured items
            # Check for ntool entries (alternate Nikto XML format)
            if not result["findings"]:
                for ntool in root.findall(".//niktoscan"):
                    for item in ntool.findall(".//item"):
                        finding = {}
                        for child in item:
                            tag = child.tag.lower()
                            text = child.text or ""
                            finding[tag] = text
                        if finding:
                            result["findings"].append(finding)

        except ET.ParseError:
            # Nikto sometimes produces malformed XML; try reading as text
            raise ValueError(f"Failed to parse Nikto XML: {xml_path}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Nikto XML file not found: {xml_path}")

        return result

    def parse_harvester(self, xml_path: str) -> Dict[str, Any]:
        """
        Parse theHarvester XML output.

        Structure returned:
        {
            "emails": [str, ...],
            "hosts": [{"hostname": str, "ip": str}, ...],
            "subdomains": [str, ...],
            "ips": [str, ...]
        }
        """
        result = {
            "emails": [],
            "hosts": [],
            "subdomains": [],
            "ips": []
        }

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            # Emails
            seen_emails = set()
            for email in root.findall(".//email"):
                text = email.text
                if text and text not in seen_emails:
                    seen_emails.add(text)
                    result["emails"].append(text.strip())

            # Hosts (with IPs)
            seen_hosts = set()
            for host in root.findall(".//host"):
                hostname_elem = host.find("hostname")
                ip_elem = host.find("ip")
                hostname = hostname_elem.text.strip() if hostname_elem is not None and hostname_elem.text else ""
                ip = ip_elem.text.strip() if ip_elem is not None and ip_elem.text else ""

                if hostname and hostname not in seen_hosts:
                    seen_hosts.add(hostname)
                    result["hosts"].append({"hostname": hostname, "ip": ip})
                    result["subdomains"].append(hostname)
                    if ip:
                        result["ips"].append(ip)

            # Direct subdomain entries
            for sub in root.findall(".//subdomain"):
                text = sub.text
                if text and text.strip() not in seen_hosts:
                    seen_hosts.add(text.strip())
                    result["subdomains"].append(text.strip())
                    result["hosts"].append({"hostname": text.strip(), "ip": ""})

            # Deduplicate IPs
            result["ips"] = list(set(result["ips"]))

        except ET.ParseError as e:
            raise ValueError(f"Failed to parse theHarvester XML: {e}")
        except FileNotFoundError:
            raise FileNotFoundError(f"theHarvester XML file not found: {xml_path}")

        return result
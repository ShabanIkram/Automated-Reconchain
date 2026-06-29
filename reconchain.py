#!/usr/bin/env python3
"""
ReconChain — Automated Reconnaissance Framework
One Command. Complete Recon.

Author: Shelby
License: MIT
"""

import argparse
import logging
import os
import sys
import shutil
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.nmap_scan import NmapScanner
from scanner.gobuster_scan import GobusterScanner
from scanner.nikto_scan import NiktoScanner
from scanner.harvester_scan import HarvesterScanner
from parser.xml_parser import XMLParser
from parser.txt_parser import TxtParser
from parser.json_parser import JsonParser
from report.report import ReportGenerator

# ─── Logging Configuration ───────────────────────────────────────────────

def setup_logging(log_dir: Path) -> logging.Logger:
    """Configure logging with file and console handlers."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "recon.log"

    logger = logging.getLogger("ReconChain")
    logger.setLevel(logging.DEBUG)

    # File handler — detailed
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))

    # Console handler — info and above
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        "%(asctime)s | %(message)s", datefmt="%H:%M:%S"
    ))

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# ─── Input Validation ────────────────────────────────────────────────────

def validate_target(target: str) -> str:
    """Validate and sanitize target input to prevent injection."""
    import re
    # Strip protocol if present
    target = re.sub(r'^https?://', '', target.strip().lower())
    # Remove path/query fragments for base target
    target = target.split('/')[0]
    # Remove any non-alphanumeric, dot, or hyphen characters
    cleaned = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
    if not cleaned:
        raise ValueError(f"Invalid target provided: '{target}'")
    return cleaned


def validate_ip(ip: str) -> bool:
    """Basic IP address validation."""
    import re
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return False


def is_domain(value: str) -> bool:
    """Check if target is a domain (contains a dot, not an IP)."""
    import re
    if validate_ip(value):
        return False
    return '.' in value and not value.startswith('.')


# ─── Tool Detection ──────────────────────────────────────────────────────

def check_tool(tool_name: str) -> bool:
    """Check if a required tool is installed and accessible."""
    return shutil.which(tool_name) is not None


def check_dependencies(tools: list) -> dict:
    """Check multiple tools and return availability status."""
    status = {}
    for tool in tools:
        status[tool] = check_tool(tool)
    return status


# ─── Phase Execution ─────────────────────────────────────────────────────

class ReconChain:
    """Main orchestration class for automated reconnaissance."""

    def __init__(self, target: str, output_dir: str, wordlist: str = None,
                 threads: int = 10, full: bool = False):
        self.target = target
        self.target_type = "ip" if validate_ip(target) else "domain"
        self.output_dir = Path(output_dir)
        self.wordlist = wordlist or self._default_wordlist()
        self.threads = threads
        self.full = full
        self.start_time = datetime.now()

        # Create output structure
        self.nmap_dir = self.output_dir / "nmap"
        self.gobuster_dir = self.output_dir / "gobuster"
        self.nikto_dir = self.output_dir / "nikto"
        self.harvester_dir = self.output_dir / "harvester"
        self.log_dir = self.output_dir / "logs"

        for d in [self.nmap_dir, self.gobuster_dir, self.nikto_dir,
                  self.harvester_dir, self.log_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # Setup logging
        self.logger = setup_logging(self.log_dir)

        # Scanner instances
        self.nmap_scanner = NmapScanner(self.target, self.nmap_dir, self.logger)
        self.gobuster_scanner = GobusterScanner(self.target, self.gobuster_dir,
                                                 self.wordlist, self.threads, self.logger)
        self.nikto_scanner = NiktoScanner(self.target, self.nikto_dir, self.logger)
        self.harvester_scanner = HarvesterScanner(self.target, self.harvester_dir, self.logger)

        # Parsed results accumulator
        self.results = {
            "nmap": {},
            "gobuster": {},
            "nikto": {},
            "harvester": {},
            "metadata": {
                "target": self.target,
                "target_type": self.target_type,
                "start_time": self.start_time.isoformat(),
                "end_time": None,
                "duration_seconds": 0,
                "tools_executed": []
            }
        }

    def _default_wordlist(self) -> str:
        """Find a default wordlist on the system."""
        candidates = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/common.txt",
        ]
        for wl in candidates:
            if os.path.exists(wl):
                return wl
        # Fallback: use embedded wordlist
        embedded = Path(__file__).parent / "wordlists" / "common.txt"
        if embedded.exists():
            return str(embedded)
        return "/usr/share/wordlists/dirb/common.txt"

    def _parse_results(self):
        """Parse all collected scan outputs."""
        self.logger.info("Parsing scan results...")

        # Parse Nmap XML
        nmap_xml = self.nmap_dir / "nmap.xml"
        if nmap_xml.exists():
            parser = XMLParser()
            try:
                self.results["nmap"] = parser.parse_nmap(str(nmap_xml))
                self.logger.info(f"  [+] Nmap: {len(self.results['nmap'].get('ports', []))} ports found")
            except Exception as e:
                self.logger.error(f"  [!] Nmap XML parse error: {e}")

        # Parse Gobuster output
        gobuster_output = self.gobuster_dir / "gobuster.txt"
        if gobuster_output.exists():
            parser = TxtParser()
            try:
                self.results["gobuster"] = parser.parse_gobuster(str(gobuster_output))
                self.logger.info(f"  [+] Gobuster: {len(self.results['gobuster'].get('directories', []))} directories found")
            except Exception as e:
                self.logger.error(f"  [!] Gobuster parse error: {e}")

        # Also try JSON if available
        gobuster_json = self.gobuster_dir / "gobuster.json"
        if gobuster_json.exists():
            parser = JsonParser()
            try:
                self.results["gobuster_json"] = parser.parse_gobuster_json(str(gobuster_json))
            except Exception as e:
                self.logger.debug(f"Gobuster JSON parse skipped: {e}")

        # Parse Nikto XML
        nikto_xml = self.nikto_dir / "nikto.xml"
        if nikto_xml.exists():
            parser = XMLParser()
            try:
                self.results["nikto"] = parser.parse_nikto(str(nikto_xml))
                self.logger.info(f"  [+] Nikto: {len(self.results['nikto'].get('findings', []))} findings")
            except Exception as e:
                self.logger.error(f"  [!] Nikto XML parse error: {e}")

        # Parse theHarvester output
        # Try JSON first (preferred)
        harvester_json = self.harvester_dir / "harvester.json"
        if harvester_json.exists():
            parser = JsonParser()
            try:
                self.results["harvester"] = parser.parse_harvester_json(str(harvester_json))
                self.logger.info(f"  [+] theHarvester (JSON): {len(self.results['harvester'].get('emails', []))} emails, "
                                 f"{len(self.results['harvester'].get('hosts', []))} hosts")
            except Exception as e:
                self.logger.error(f"  [!] theHarvester JSON parse error: {e}")
        else:
            # Fallback to XML
            harvester_xml = self.harvester_dir / "harvester.xml"
            if harvester_xml.exists():
                parser = XMLParser()
                try:
                    self.results["harvester"] = parser.parse_harvester(str(harvester_xml))
                    self.logger.info(f"  [+] theHarvester (XML): {len(self.results['harvester'].get('emails', []))} emails, "
                                     f"{len(self.results['harvester'].get('hosts', []))} hosts")
                except Exception as e:
                    self.logger.error(f"  [!] theHarvester XML parse error: {e}")

    def _generate_report(self, output_file: str):
        """Generate the final HTML report."""
        self.logger.info("Generating HTML report...")

        # Compute end time / duration
        end_time = datetime.now()
        self.results["metadata"]["end_time"] = end_time.isoformat()
        self.results["metadata"]["duration_seconds"] = int((end_time - self.start_time).total_seconds())

        generator = ReportGenerator(
            results=self.results,
            output_path=output_file,
            template_dir=Path(__file__).parent / "report" / "templates",
            assets_dir=Path(__file__).parent / "report" / "assets"
        )
        report_path = generator.generate()
        self.logger.info(f"  [+] Report saved to: {report_path}")
        return report_path

    def run_nmap(self):
        """Execute Nmap scan phase."""
        if not check_tool("nmap"):
            self.logger.warning("  [!] nmap not found. Skipping Nmap scan.")
            return False
        self.logger.info("[*] Phase 1/4: Nmap Scan")
        self.results["metadata"]["tools_executed"].append("nmap")
        return self.nmap_scanner.scan()

    def run_gobuster(self):
        """Execute Gobuster directory enumeration phase."""
        if not check_tool("gobuster"):
            self.logger.warning("  [!] gobuster not found. Skipping Gobuster scan.")
            return False
        self.logger.info("[*] Phase 2/4: Gobuster Directory Enumeration")
        self.results["metadata"]["tools_executed"].append("gobuster")
        return self.gobuster_scanner.scan()

    def run_nikto(self):
        """Execute Nikto web vulnerability scan phase."""
        if not check_tool("nikto"):
            self.logger.warning("  [!] nikto not found. Skipping Nikto scan.")
            return False
        self.logger.info("[*] Phase 3/4: Nikto Web Vulnerability Scan")
        self.results["metadata"]["tools_executed"].append("nikto")
        return self.nikto_scanner.scan()

    def run_harvester(self):
        """Execute theHarvester passive OSINT phase."""
        if not check_tool("theHarvester"):
            self.logger.warning("  [!] theHarvester not found. Skipping theHarvester scan.")
            return False
        self.logger.info("[*] Phase 4/4: theHarvester OSINT Gathering")
        self.results["metadata"]["tools_executed"].append("theHarvester")
        return self.harvester_scanner.scan()

    def run_all(self):
        """Run all reconnaissance phases sequentially."""
        self.logger.info("=" * 60)
        self.logger.info("  ReconChain — Automated Reconnaissance Framework")
        self.logger.info(f"  Target: {self.target}")
        self.logger.info(f"  Start Time: {self.start_time}")
        self.logger.info("=" * 60)

        # Phase 1: Nmap
        self.run_nmap()

        # Phase 2: Gobuster (needs web service, skip if only IP without HTTP detection)
        self.run_gobuster()

        # Phase 3: Nikto (needs web service)
        self.run_nikto()

        # Phase 4: theHarvester (domain only)
        if self.target_type == "domain":
            self.run_harvester()
        else:
            self.logger.info("  [-] Skipping theHarvester: target is an IP address (domain required)")

        # Parse all results
        self._parse_results()

        return self.results


# ─── Command-Line Interface ──────────────────────────────────────────────

def main():
    banner = """
    ╔══════════════════════════════════════════╗
    ║         ReconChain v1.0                  ║
    ║   One Command. Complete Recon.           ║
    ╚══════════════════════════════════════════╝
    """
    parser = argparse.ArgumentParser(
        description="ReconChain — Automated Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python reconchain.py --target example.com --output report.html
  python reconchain.py --target 192.168.1.1 --nmap --gobuster
  python reconchain.py --target example.com --full --wordlist /path/to/wordlist.txt
        """
    )

    parser.add_argument("--target", "-t", required=True,
                        help="Target domain, IP address, or URL")
    parser.add_argument("--output", "-o", default="reconchain_report.html",
                        help="Output HTML report path (default: reconchain_report.html)")
    parser.add_argument("--output-dir", default="output",
                        help="Directory for scan outputs (default: output/)")
    parser.add_argument("--wordlist", "-w", default=None,
                        help="Path to wordlist for directory enumeration")
    parser.add_argument("--threads", default=10, type=int,
                        help="Number of threads (default: 10)")
    parser.add_argument("--full", action="store_true",
                        help="Run all available tools (equivalent to --nmap --gobuster --nikto --harvester)")

    # Individual phase flags
    parser.add_argument("--nmap", action="store_true", help="Run only Nmap scan")
    parser.add_argument("--gobuster", action="store_true", help="Run only Gobuster dir enumeration")
    parser.add_argument("--nikto", action="store_true", help="Run only Nikto web scan")
    parser.add_argument("--harvester", action="store_true", help="Run only theHarvester OSINT")

    args = parser.parse_args()

    print(banner)

    # Validate target
    try:
        target = validate_target(args.target)
    except ValueError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    # Check which phases to run
    has_phase_flags = any([args.nmap, args.gobuster, args.nikto, args.harvester])

    if args.full:
        phases = ["nmap", "gobuster", "nikto", "harvester"]
    elif has_phase_flags:
        phases = []
        if args.nmap:
            phases.append("nmap")
        if args.gobuster:
            phases.append("gobuster")
        if args.nikto:
            phases.append("nikto")
        if args.harvester:
            phases.append("harvester")
    else:
        # Default: run all
        phases = ["nmap", "gobuster", "nikto", "harvester"]

    # Check dependencies
    tool_map = {
        "nmap": "nmap",
        "gobuster": "gobuster",
        "nikto": "nikto",
        "harvester": "theHarvester"
    }
    missing = []
    for phase in phases:
        tool = tool_map.get(phase)
        if tool and not check_tool(tool):
            missing.append(tool)

    if missing:
        print(f"[!] Missing required tools: {', '.join(missing)}")
        print("[!] Install them and ensure they're in your PATH.")
        print("    Kali: sudo apt install nmap gobuster nikto theharvester")
        if not args.full and has_phase_flags:
            # Only warn, don't exit if user specified individual phases
            pass
        else:
            sys.exit(1)

    # Initialize ReconChain
    rc = ReconChain(
        target=target,
        output_dir=args.output_dir,
        wordlist=args.wordlist,
        threads=args.threads,
        full=args.full
    )

    # Run specified phases
    try:
        for phase in phases:
            if phase == "nmap":
                rc.run_nmap()
            elif phase == "gobuster":
                rc.run_gobuster()
            elif phase == "nikto":
                rc.run_nikto()
            elif phase == "harvester":
                if rc.target_type == "domain":
                    rc.run_harvester()
                else:
                    rc.logger.info("  [-] Skipping theHarvester: target is an IP address")

        # Parse results and generate report
        rc._parse_results()
        report_path = rc._generate_report(args.output)

        duration = int((datetime.now() - rc.start_time).total_seconds())
        print(f"\n[+] ReconChain completed in {duration} seconds.")
        print(f"[+] Report: {report_path}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        rc.logger.warning("Scan interrupted by user (KeyboardInterrupt)")
        # Try to generate report with what we have
        try:
            rc._parse_results()
            rc._generate_report(args.output)
            print(f"[+] Partial report saved to: {args.output}")
        except Exception:
            print("[!] Could not generate partial report.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        rc.logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
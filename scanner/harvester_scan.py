"""
theHarvester Scanner Module
Performs passive OSINT gathering (emails, subdomains, hosts, IPs).
"""

import subprocess
from pathlib import Path


class HarvesterScanner:
    """Orchestrates theHarvester passive reconnaissance."""

    def __init__(self, target: str, output_dir: Path, logger=None):
        self.target = target
        self.output_dir = output_dir
        self.logger = logger
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def scan(self) -> bool:
        """Run theHarvester against multiple search sources."""
        # Save output with base filename; theHarvester adds .xml/.json/.html
        output_base = str(self.output_dir / "harvester")

        # All available theHarvester sources for maximum coverage
        sources = [
            # Search Engines
            "baidu", "bing", "brave", "duckduckgo", "yahoo",

            # Certificate Transparency
            "certspotter", "commoncrawl", "crtsh",

            # Mobile / API Security
            "bevigil",

            # Code Repositories
            "bitbucket", "github-code", "gitlab",

            # Network / IP Intelligence
            "bufferoverun", "fofa", "fullhunt", "hackertarget",
            "netlas", "onyphe", "otx", "rapiddns", "robtex",
            "shodan", "subdomaincenter", "subdomainfinderc99",
            "threatcrowd", "urlscan", "virustotal", "waybackarchive",
            "whoisxml", "windvane", "zoomeye",

            # Commercial / Paid Intelligence Platforms
            "builtwith", "censys", "chaos", "criminalip",
            "dehashed", "hunter", "hunterhow", "intelx",
            "leakix", "leaklookup", "pentesttools", "projectdiscovery",
            "rocketreach", "securityscorecard", "securityTrails",
            "thc", "tomba", "venacus",

            # Breach / Exposure Data
            "haveibeenpwned", "hudsonrock",
        ]

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
                    timeout=120,  # 2 minutes per source
                )

                if result.returncode != 0:
                    self.logger.debug(f"  [!] theHarvester ({source}) exit code: {result.returncode}")
                else:
                    success_count += 1

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

        # Check what files were created
        xml_path = self.output_dir / "harvester.xml"
        json_path = self.output_dir / "harvester.json"

        if xml_path.exists() or json_path.exists():
            self.logger.info(f"  [✓] theHarvester completed")
            if xml_path.exists():
                self.logger.info(f"      XML: {xml_path}")
            if json_path.exists():
                self.logger.info(f"      JSON: {json_path}")
            return True
        else:
            self.logger.warning("  [!] theHarvester produced no output files")
            return False
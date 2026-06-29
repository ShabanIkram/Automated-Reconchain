"""
Nmap Scanner Module
Performs host discovery, port scanning, service/version detection, OS detection,
and default NSE script scanning.
"""

import subprocess
import os
from pathlib import Path


class NmapScanner:
    """Orchestrates Nmap scans and saves raw outputs."""

    def __init__(self, target: str, output_dir: Path, logger):
        self.target = target
        self.output_dir = output_dir
        self.logger = logger
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def scan(self) -> bool:
        """Execute the Nmap scan with service/version/OS detection and default scripts."""
        xml_path = self.output_dir / "nmap.xml"
        normal_path = self.output_dir / "nmap.txt"

        cmd = [
            "nmap",
            "-sS",            # TCP SYN scan
            "-sV",            # Version detection
            "-O",             # OS detection
            "-Pn",            # Treat all hosts as online (skip host discovery)
            "--script=default",  # Default NSE scripts
            "-oX", str(xml_path),   # XML output
            "-oN", str(normal_path), # Normal output
            self.target
        ]

        self.logger.info(f"  Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
            )

            # Also save stderr for debugging
            err_path = self.output_dir / "nmap_stderr.txt"
            with open(err_path, "w") as f:
                f.write(result.stderr)

            if result.returncode == 0:
                self.logger.info(f"  [✓] Nmap scan completed successfully")
                self.logger.info(f"      XML: {xml_path}")
                self.logger.info(f"      TXT: {normal_path}")
                return True
            else:
                self.logger.warning(f"  [!] Nmap returned exit code {result.returncode}")
                if "requires root privileges" in result.stderr.lower():
                    self.logger.warning("      OS detection requires root. Consider running with sudo.")
                return False

        except subprocess.TimeoutExpired:
            self.logger.error("  [!] Nmap scan timed out after 10 minutes")
            return False
        except FileNotFoundError:
            self.logger.error("  [!] nmap executable not found")
            return False
        except Exception as e:
            self.logger.error(f"  [!] Nmap scan failed: {e}")
            return False
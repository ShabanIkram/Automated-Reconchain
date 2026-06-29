"""
Nikto Scanner Module
Performs web server vulnerability scanning.
"""

import subprocess
from pathlib import Path


class NiktoScanner:
    """Orchestrates Nikto web vulnerability scans."""

    def __init__(self, target: str, output_dir: Path, logger=None):
        self.target = target
        self.output_dir = output_dir
        self.logger = logger
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _get_target(self) -> str:
        """Format target for Nikto."""
        # Nikto accepts hosts without protocol
        target_clean = self.target
        if target_clean.startswith("http://"):
            target_clean = target_clean[7:]
        elif target_clean.startswith("https://"):
            target_clean = target_clean[8:]
        return target_clean

    def scan(self) -> bool:
        """Run Nikto vulnerability scan and save XML output."""
        target_host = self._get_target()
        xml_path = self.output_dir / "nikto.xml"
        txt_path = self.output_dir / "nikto.txt"

        cmd = [
            "nikto",
            "-h", target_host,
            "-o", str(xml_path),
            "-Format", "xml",
            "-output", str(txt_path),
        ]

        self.logger.info(f"  Running: nikto -h {target_host}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=900,  # 15 minutes — Nikto can be slow
            )

            # Save stderr
            err_path = self.output_dir / "nikto_stderr.txt"
            with open(err_path, "w") as f:
                f.write(result.stderr)

            # Nikto often exits with code 0 even with findings
            self.logger.info(f"  [✓] Nikto scan completed (exit code: {result.returncode})")
            self.logger.info(f"      XML: {xml_path}")
            return True

        except subprocess.TimeoutExpired:
            self.logger.error("  [!] Nikto scan timed out after 15 minutes")
            return False
        except FileNotFoundError:
            self.logger.error("  [!] nikto executable not found")
            return False
        except Exception as e:
            self.logger.error(f"  [!] Nikto scan failed: {e}")
            return False
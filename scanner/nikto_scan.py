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

        cmd = [
            "nikto",
            "-h", target_host,
            "-o", str(xml_path),
            "-Format", "xml",
            "-maxtime", "600s",  # Limit scan to 10 minutes per host
        ]

        self.logger.info(f"  Running: nikto -h {target_host} -maxtime 600s")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=900,  # 15 min subprocess timeout (buffer above maxtime)
            )

            err_path = self.output_dir / "nikto_stderr.txt"
            with open(err_path, "w") as f:
                f.write(result.stderr)

            if xml_path.exists() and xml_path.stat().st_size > 0:
                self.logger.info(f"  [✓] Nikto scan completed (exit code: {result.returncode})")
                self.logger.info(f"      XML: {xml_path}")
                return True
            else:
                self.logger.warning(f"  [!] Nikto produced no XML output (exit code: {result.returncode})")
                stderr_out = result.stderr.strip()
                if stderr_out:
                    self.logger.warning(f"      stderr: {stderr_out[:300]}")
                return False

        except subprocess.TimeoutExpired:
            self.logger.error("  [!] Nikto scan timed out after 15 minutes")
            return False
        except FileNotFoundError:
            self.logger.error("  [!] nikto executable not found")
            return False
        except Exception as e:
            self.logger.error(f"  [!] Nikto scan failed: {e}")
            return False
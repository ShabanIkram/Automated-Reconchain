"""
Nmap Scanner Module
Performs host discovery, port scanning, service/version detection, OS detection,
and default NSE script scanning.
"""

import subprocess
import os
import platform
from pathlib import Path


class NmapScanner:
    """Orchestrates Nmap scans and saves raw outputs."""

    def __init__(self, target: str, output_dir: Path, logger):
        self.target = target
        self.output_dir = output_dir
        self.logger = logger
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _has_raw_socket_privileges(self) -> bool:
        """Check if we have privileges for SYN scan (-sS)."""
        if platform.system() == "Windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0

    def scan(self) -> bool:
        """Execute the Nmap scan with service/version/OS detection and default scripts."""
        xml_path = self.output_dir / "nmap.xml"
        normal_path = self.output_dir / "nmap.txt"

        # Use -sT (TCP connect) without root; -sS (SYN) requires root/raw sockets
        scan_type = "-sS" if self._has_raw_socket_privileges() else "-sT"
        if scan_type == "-sT":
            self.logger.info("  [i] Non-root detected — using TCP connect scan (-sT)")

        cmd = [
            "nmap",
            scan_type,        # TCP SYN or connect scan
            "-sV",            # Version detection
            "-Pn",            # Treat all hosts as online (skip host discovery)
            "--script=default",  # Default NSE scripts
            "-oX", str(xml_path),   # XML output
            "-oN", str(normal_path), # Normal output
            self.target
        ]

        # Only attempt OS detection with root (requires raw sockets)
        if self._has_raw_socket_privileges():
            cmd.insert(3, "-O")

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
"""
Gobuster Scanner Module
Performs directory/file enumeration on web targets.
"""

import subprocess
from pathlib import Path


class GobusterScanner:
    """Orchestrates Gobuster directory enumeration."""

    def __init__(self, target: str, output_dir: Path, wordlist: str,
                 threads: int = 10, logger=None):
        self.target = target
        self.output_dir = output_dir
        self.wordlist = wordlist
        self.threads = threads
        self.logger = logger
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _get_url(self) -> str:
        """Construct a URL from the target."""
        # If target already looks like a URL, use as-is
        if self.target.startswith("http://") or self.target.startswith("https://"):
            return self.target
        # If it's an IP or domain, assume HTTP
        return f"http://{self.target}"

    def scan(self) -> bool:
        """Run Gobuster directory enumeration."""
        url = self._get_url()
        output_txt = self.output_dir / "gobuster.txt"
        output_json = self.output_dir / "gobuster.json"

        # Check wordlist exists
        if not Path(self.wordlist).exists():
            self.logger.warning(f"  [!] Wordlist not found: {self.wordlist}")
            self.logger.warning("  [!] Try: sudo apt install wordlists")
            self.logger.warning("  [!] Or: wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt")
            return False

        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", self.wordlist,
            "-t", str(self.threads),
            "-o", str(output_txt),
            "-q",               # Quiet mode
            "--no-color",
            "-e",               # Expanded mode (full URLs)
            "-l",               # Include length of response
        ]

        # Use JSON output if supported
        cmd.extend(["-j", str(output_json)])

        self.logger.info(f"  Running: gobuster dir -u {url} -w {Path(self.wordlist).name} -t {self.threads}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            # Save stderr for diagnostics
            err_path = self.output_dir / "gobuster_stderr.txt"
            with open(err_path, "w") as f:
                f.write(result.stderr)

            if result.returncode == 0:
                self.logger.info(f"  [✓] Gobuster scan completed successfully")
                self.logger.info(f"      Output: {output_txt}")
                return True
            else:
                self.logger.warning(f"  [!] Gobuster returned exit code {result.returncode}")
                if "error" in result.stderr.lower():
                    self.logger.warning(f"      {result.stderr.strip()}")
                return False

        except subprocess.TimeoutExpired:
            self.logger.error("  [!] Gobuster scan timed out after 10 minutes")
            return False
        except FileNotFoundError:
            self.logger.error("  [!] gobuster executable not found")
            return False
        except Exception as e:
            self.logger.error(f"  [!] Gobuster scan failed: {e}")
            return False
<div align="center">

# ⛓️ ReconChain

**One Command. Complete Recon.**

ReconChain is an automated reconnaissance framework that chains multiple industry-standard security tools into a single, streamlined workflow. It automates the information-gathering phase of penetration testing — parsing tool outputs, correlating findings, and generating professional HTML reports.

> ⚠️ **Legal Disclaimer:** This tool is intended for authorized penetration testing and security research only. Always obtain written permission before scanning any target. Unauthorized use is illegal and unethical.

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Reconnaissance Phases](#-reconnaissance-phases)
- [Output & Reporting](#-output--reporting)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Requirements](#-requirements)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

- 🔗 **Chained Workflow** — Tools run sequentially, each building on previous results
- 📊 **Rich HTML Reports** — Bootstrap 5 dark theme with interactive Chart.js visualizations
- 🎯 **Risk Categorization** — Findings classified as Critical / High / Medium / Low / Info
- 🛡️ **Remediation Guidance** — Actionable recommendations included per finding
- 💾 **Raw Output Preserved** — XML, JSON, and TXT scan files saved to `output/`
- 🧩 **Modular Design** — Enable or disable individual phases via CLI flags
- ⚡ **Multi-threaded** — Configurable thread count for faster enumeration
- 📁 **OSINT Integration** — Passive reconnaissance via theHarvester

---

## 🔍 Reconnaissance Phases

| Phase | Tool | Purpose |
|-------|------|---------|
| **Phase 1** | [Nmap](https://nmap.org) | Host discovery, port scanning, service/version detection, OS fingerprinting, NSE scripts |
| **Phase 2** | [Gobuster](https://github.com/OJ/gobuster) | Directory and file enumeration on discovered web servers |
| **Phase 3** | [Nikto](https://cirt.net/Nikto2) | Web vulnerability scanning, misconfiguration detection, outdated software |
| **Phase 4** | [theHarvester](https://github.com/laramies/theHarvester) | Passive OSINT — emails, subdomains, hosts, IP addresses |

Each phase feeds its results into the next, creating a comprehensive attack-surface map.

---

## 📈 Output & Reporting

ReconChain generates a single self-contained HTML report with:

- **Executive Summary** — Statistics cards with total findings, open ports, and risk breakdown
- **Interactive Charts** — Vulnerability severity distribution and service breakdown (Chart.js)
- **Findings Table** — Sortable, filterable table of all discovered issues
- **Risk Badges** — Color-coded severity indicators per finding
- **Remediation Recommendations** — Suggested fixes based on discovered vulnerabilities
- **Raw Files** — All tool outputs preserved in `output/` for further manual analysis

```
output/
├── nmap_scan.xml
├── gobuster_results.txt
├── nikto_report.json
├── harvester_results.json
└── report.html          ← Main deliverable
```

---

## ⚙️ Installation

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.8+ | Core runtime |
| Nmap | Latest | `sudo apt install nmap` |
| Gobuster | Latest | `sudo apt install gobuster` |
| Nikto | Latest | `sudo apt install nikto` |
| theHarvester | Latest | Pre-installed on Kali Linux |

> Kali Linux is strongly recommended — all security tools come pre-installed.

### Step-by-step Setup

```bash
# 1. Clone the repository
git clone https://github.com/ShabanIkram/Automated-Reconchain.git
cd Automated-Reconchain

# 2. (Optional) Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
.\venv\Scripts\activate         # Windows

# 3. Install Python dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic Scan

```bash
python reconchain.py --target example.com
```

### Full Scan (All Phases)

```bash
python reconchain.py --target example.com --full
```

### Custom Scan with Options

```bash
python reconchain.py --target example.com \
  --nmap \
  --gobuster \
  --nikto \
  --harvester \
  --wordlist /usr/share/wordlists/dirb/common.txt \
  --threads 20 \
  --output-dir ./results
```

### CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--target`, `-t` | *required* | Target domain, IP, or CIDR range |
| `--output`, `-o` | `report.html` | Output report filename |
| `--output-dir` | `./output` | Directory to save all results |
| `--wordlist` | built-in | Wordlist for Gobuster enumeration |
| `--threads` | `10` | Number of threads for enumeration |
| `--full` | `false` | Run all phases |
| `--nmap` | `false` | Enable Nmap phase only |
| `--gobuster` | `false` | Enable Gobuster phase only |
| `--nikto` | `false` | Enable Nikto phase only |
| `--harvester` | `false` | Enable theHarvester phase only |

---

## 📁 Project Structure

```
recon_chain/
├── reconchain.py          # Main entry point & CLI
├── requirements.txt       # Python dependencies
├── README.md
├── LICENSE
│
├── scanner/               # Tool wrappers & execution logic
│   ├── nmap_scanner.py
│   ├── gobuster_scanner.py
│   ├── nikto_scanner.py
│   └── harvester_scanner.py
│
├── parser/                # Output parsers for each tool
│   ├── nmap_parser.py
│   ├── gobuster_parser.py
│   ├── nikto_parser.py
│   └── harvester_parser.py
│
├── report/                # Report generation
│   └── report.py          # HTML report builder (Jinja2)
│
├── logs                   # Runtime logs (gitignored)
└── output                 # Scan results & reports (gitignored)
```

---

## 📦 Requirements

```txt
jinja2
```

Install all dependencies with:

```bash
pip install -r requirements.txt
```

---

## 🤝 Contributing

Contributions are welcome! To get started:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

Please ensure your code follows PEP 8 style guidelines and includes appropriate comments.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

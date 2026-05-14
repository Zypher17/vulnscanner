# VulnScanner 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

**VulnScanner** is a modular, high-performance vulnerability assessment framework designed for security researchers and penetration testers. It combines automated service fingerprinting, template-based vulnerability probing, and an integrated **SearchSploit** engine to streamline reconnaissance and exploit research.

---

## 🚀 Key Features

*   **SearchSploit Engine**: Integrated Exploit-DB matching for discovered services. Provides precise, Kali-style local file paths for exploit payloads.
*   **ShadowRecon Dashboard**: A professional, interactive HTML/CSS dashboard for high-signal reporting.
*   **Async Core**: High-concurrency engine for rapid, non-blocking network scanning.
*   **Template-Driven Detection**: Modular YAML-based probing for web misconfigurations (XSS, SQLi, Open Redirects, etc.).
*   **Service Fingerprinting**: Advanced banner grabbing and version detection.
*   **User Attribution**: Built-in support for custom branding and attribution in findings and reports.

---

## 🛠 Installation

```bash
# Clone the repository
git clone https://github.com/Zypher17/vulnscanner.git
cd vulnscanner

# Install dependencies
pip install -r requirements.txt

# Install as an editable package
pip install -e .
```

---

## 📖 Usage

### 1. Vulnerability Scanning
Run a targeted scan to identify open ports, grab banners, and probe for common vulnerabilities:

```bash
python -m scanner.main scan <TARGET_IP> --ports 22,80,443 --export-html report.html
```

### 2. Exploit Research
Quickly find local exploit payloads using the integrated SearchSploit engine:

```bash
python -m scanner.main search "Apache Struts"
```

---

## 🏗 Project Architecture

*   `scanner/core/`: The asynchronous engine, scanner, and exploit database interface.
*   `scanner/modules/`: Specialized check modules (HTTP, SSH, SearchSploit, etc.).
*   `scanner/data/`: Exploit database (`exploits.csv`) and risk summary mappings.
*   `scanner/templates/`: YAML-based definitions for automated security checks.

---

## 🛡 Disclaimer
*This framework is designed for authorized security research, educational purposes, and home lab environments only. Use responsibly and adhere to all applicable laws and ethical guidelines.*

## 📜 Roadmap
- [ ] Add OS fingerprinting.
- [ ] Implement support for custom user-agent templates.
- [ ] Enhance report generation to PDF/HTML with hardening playbooks.
- [ ] Integrate OSV/NVD database APIs.

## 🤝 Attribution
Built by **Zypher17** with significant contributions to the Extended UI and SearchSploit integration logic.

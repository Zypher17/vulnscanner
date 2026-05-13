# VulnScanner 🛡️

A professional, modular, and async-driven vulnerability assessment framework in Python. Designed for security researchers and CTF participants to map attack surfaces, research vulnerabilities using **Exploit-DB**, and identify web misconfigurations through automated, defensive probing.

## Features
- **Template-Driven Engine**: Extensible detection using YAML templates for rapid, modular security probing.
- **Async Engine**: High-performance, non-blocking network and HTTP scanning.
- **Service Fingerprinting**: Advanced service and version detection with a context-aware KB.
- **Defensive Probing**: Safe identification of XSS, SQLi indicators, Open Redirects, and Command Injection—without weaponized payloads.
- **Professional Reporting**: Export findings as structured JSON or high-signal plaintext summaries.
- **Persistence**: Built-in caching engine for high-speed repeated assessments.

## Installation
```bash
git clone https://github.com/Zypher17/vulnscanner.git
cd vulnscanner
pip install -e .
```

## Usage
Run the framework using the module flag:

**Scan a target:**
```bash
python -m scanner.main 127.0.0.1 --ports 8080,9000
```

**Export reports:**
```bash
python -m scanner.main 127.0.0.1 --export-html report.html --export-notes notes.txt
```

## Configuration & Profiles
Customize detection by adding new rules to `scanner/templates/web_vulns.yaml`.

## Roadmap
- [ ] Add OS fingerprinting.
- [ ] Implement support for custom user-agent templates.
- [ ] Enhance report generation to PDF/HTML with hardening playbooks.
- [ ] Integrate OSV/NVD database APIs.

## License
MIT License.

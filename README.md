# ShadowRecon (formerly VulnScanner) 🛡️

A professional, modular, and async-driven vulnerability assessment framework in Python. Designed for security researchers and CTF participants to map attack surfaces, research vulnerabilities using a built-in **SearchSploit Engine**, and identify web misconfigurations through automated, defensive probing.

## Features
- **ShadowRecon Dashboard**: A modern, interactive HTML/CSS dashboard for professional assessment reporting.
- **SearchSploit Engine**: Integrated Exploit-DB matching for discovered services and versions.
- **Service Fingerprinting**: Advanced banner grabbing and version detection.
- **Template-Driven Engine**: Extensible detection using YAML templates for rapid, modular security probing.
- **Async Engine**: High-performance, non-blocking network and HTTP scanning.
- **Defensive Probing**: Safe identification of XSS, SQLi indicators, Open Redirects, and Command Injection.

## Usage
Run the framework using the module flag:

**Scan a target:**
```bash
python -m scanner.main scan 127.0.0.1 --ports 22,80,8080 --export-html report.html
```

**Search for exploits manually:**
```bash
python -m scanner.main search "Apache Struts"
```

**Export reports:**
```bash
python -m scanner.main scan 127.0.0.1 --export-html report.html --export-notes notes.txt
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

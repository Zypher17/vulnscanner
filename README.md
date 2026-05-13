# VulnScanner 🛡️

VulnScanner is a professional, modular, and async-driven vulnerability assessment framework built in Python. Designed for security researchers and CTF participants, it enables rapid service identification, vulnerability research using **Exploit-DB**, and automated detection of web misconfigurations through safe, non-exploitative probing.

## Features
- **Interactive CLI**: Powered by `rich` with ASCII branding, real-time status logging, and structured tables.
- **Scanning Profiles**: Use `--profile` (quick, web, full, lab) for instant target configuration.
- **Async Engine**: High-performance, non-blocking port scanning and service probing using `asyncio`.
- **Dynamic Exploit-DB Integration**: Automatically queries `searchsploit` for real-time exploit matches and CVE identifiers.
- **Web Vulnerability Probes**: Performs safe, non-destructive checks for XSS, SQL Injection indicators, Open Redirects, Command Injection, exposed sensitive paths, and missing security headers.
- **Service Fingerprinting**: Advanced banner parsing for accurate service and version detection.
- **Database Exposure Detection**: Probes for open ports for MongoDB, Redis, MySQL, and PostgreSQL.
- **Format Flexibility**: Output in human-readable text or machine-ready JSON.

## Requirements
- Python 3.7+
- `httpx` & `rich` libraries: `pip install httpx rich`
- `searchsploit` (part of the `exploitdb` package, recommended for Kali/Linux).

## Installation
```bash
git clone https://github.com/Zypher17/vulnscanner.git
cd vulnscanner
```

## Usage
Run the tool as a module:

**Scan a target with a profile:**
```bash
python -m vulnscanner.main 10.10.10.5 --profile quick
```

**Target a web server specifically:**
```bash
python -m vulnscanner.main example.com --profile web
```

**Scan a network range:**
```bash
python -m vulnscanner.main 192.168.1.0/24 --profile full
```

**JSON output for automation:**
```bash
python -m vulnscanner.main example.com --format json
```

## Example Output
```text
[*] Starting scan for 127.0.0.1...
[+] 127.0.0.1 is up. Found 1 open ports. Running vulnerability checks...

+----------+-----------+------+-------------------------------------------+
| Severity | Target    | Port | Issue                                     |
+==========+===========+======+===========================================+
|   HIGH   | 127.0.0.1 | 8080 | Exploit-DB: Apache 2.4.41 RCE              |
|  MEDIUM  | 127.0.0.1 | 8080 | Exposed Sensitive Path: /admin/           |
+----------+-----------+------+-------------------------------------------+
```

## Configuration & Profiles
Profiles map to standard port sets for quick scanning:
- `quick`: 22, 80, 443
- `web`: 80, 443, 8000, 8080, 8443
- `full`: 1-1000
- `lab`: 8080, 9000

## Roadmap
- [ ] Add OS fingerprinting based on TTL and window sizes.
- [ ] Implement support for custom user-agent templates.
- [ ] Export reports directly to PDF/HTML.
- [ ] Support for external CVE databases like OSV/NVD APIs.

## Contributing
Contributions are welcome! Please fork the repository, make your changes, and submit a pull request.

## License
This project is licensed under the MIT License.

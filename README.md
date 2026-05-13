# VulnScanner 🛡️

A professional, modular, and async-driven vulnerability assessment framework in Python. Designed for security researchers and CTF players (TryHackMe/HackTheBox) to quickly identify services and correlate them with known exploits in **Exploit-DB**, and detect common web misconfigurations and vulnerabilities through safe probing.

## Features
- **Interactive UI**: Powered by `rich` with ASCII banners, real-time progress bars, and structured tables.
- **Scanning Profiles**: Use `--profile` (quick, web, full, lab) for instant configuration.
- **Host Discovery & Port Scanning**: Non-blocking TCP connect scanning using `asyncio`.
- **Deep Service Fingerprinting**: Normalizes banners and extracts versions from SSH, FTP, HTTP headers, and common DBs.
- **Exploit-DB Integration**: Dynamically queries `searchsploit` for real-time exploit matches, including CVE IDs.
- **Web Vulnerability Probes**: Safely probes for indicators of XSS, SQL Injection, Open Redirects, Command Injection, exposed sensitive paths, and missing security headers.
- **Database Exposure Detection**: Identifies open ports for common database services.
- **CIDR & Network Support**: Scan single IPs, domains, or entire subnets (e.g., `192.168.1.0/24`).
- **Colorized Reporting**: High-signal output with severity-based color coding.

## Installation

### Requirements
- Python 3.7+
- `httpx` & `rich` libraries: `pip install httpx rich`
- `searchsploit`: (Optional, recommended for Linux/Kali) `sudo apt install exploitdb`

### Setup
```bash
git clone https://github.com/Zypher17/vulnscanner.git
cd vulnscanner
```

## Usage
Run the tool as a module:

**Scan a single IP with the "quick" profile:**
```bash
python -m vulnscanner.main 10.10.10.5 --profile quick
```

**Target a web server specifically (includes XSS, header checks, etc.):**
```bash
python -m vulnscanner.main example.com --profile web
```

**Scan a network range with full auditing (ports 1-1000):**
```bash
python -m vulnscanner.main 192.168.1.0/24 --profile full
```

**Run the specific lab profile for testing:**
```bash
python -m vulnscanner.main 127.0.0.1 --profile lab
```

**Output to JSON for automation:**
```bash
python -m vulnscanner.main example.com --format json
```

## Testing on Windows
If you don't have `searchsploit` (Exploit-DB) installed, the tool will automatically fallback to a `mock_searchsploit.py` script for demonstration.

1. Start the mock target: `python vuln_site.py`
2. Run the scanner: `python -m vulnscanner.main 127.0.0.1 --profile lab`


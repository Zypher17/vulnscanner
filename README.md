# VulnScanner 🛡️

A professional, modular, and async-driven defensive vulnerability assessment framework in Python. Designed for security researchers and CTF players (TryHackMe/HackTheBox) to quickly identify services and correlate them with known exploits in **Exploit-DB**.

## Features
- **Host Discovery & Port Scanning**: Non-blocking TCP connect scanning using `asyncio`.
- **Deep Service Fingerprinting**: Normalizes banners and extracts versions from SSH, FTP, and HTTP headers.
- **Exploit-DB Integration**: Dynamically queries `searchsploit` for real-time exploit matches.
- **CIDR & Network Support**: Scan single IPs, domains, or entire subnets (e.g., `192.168.1.0/24`).
- **Colorized Reporting**: High-signal output with severity-based color coding.
- **Strictly Defensive**: No exploitation payloads or brute-forcing.

## Installation

### Requirements
- Python 3.7+
- `httpx` library: `pip install httpx`
- `searchsploit`: (Optional, recommended for Linux/Kali) `sudo apt install exploitdb`

### Setup
```bash
git clone https://github.com/Zypher17/vulnscanner.git
cd vulnscanner
```

## Usage
Run the tool as a module:

**Scan a single IP:**
```bash
python -m vulnscanner.main 10.10.10.5
```

**Scan a network range with specific ports:**
```bash
python -m vulnscanner.main 192.168.1.0/24 -p 22,80,443
```

**Output to JSON for automation:**
```bash
python -m vulnscanner.main example.com --format json
```

## Testing on Windows
If you don't have `searchsploit` (Exploit-DB) installed, the tool will automatically fallback to a `mock_searchsploit.py` script for demonstration.

1. Start the mock target: `python vuln_site.py`
2. Run the scanner: `python -m vulnscanner.main 127.0.0.1 -p 8080`

## Safety & Legal Disclaimer
**FOR AUTHORIZED DEFENSIVE ASSESSMENTS ONLY.**
The authors are not responsible for any misuse. Always obtain explicit permission before scanning any network.

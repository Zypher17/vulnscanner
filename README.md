# VulnScanner 🛡️

A professional, modular, and async-driven vulnerability assessment framework in Python. Designed for security researchers and CTF players (TryHackMe/HackTheBox) to quickly identify services and correlate them with known exploits in **Exploit-DB**.

## Features
- **Interactive UI**: Powered by `rich` with ASCII banners, real-time progress bars, and structured tables.
- **Scanning Profiles**: Use `--profile` (quick, web, full) for instant configuration.
- **Host Discovery & Port Scanning**: Non-blocking TCP connect scanning using `asyncio`.
- **Deep Service Fingerprinting**: Normalizes banners and extracts versions from SSH, FTP, and HTTP headers.
- **Exploit-DB Integration**: Dynamically queries `searchsploit` for real-time exploit matches.
- **CIDR & Network Support**: Scan single IPs, domains, or entire subnets (e.g., `192.168.1.0/24`).

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

**Target a web server specifically:**
```bash
python -m vulnscanner.main example.com --profile web
```

**Scan a network range with full auditing:**
```bash
python -m vulnscanner.main 192.168.1.0/24 --profile full
```

**Output to JSON for automation:**
```bash
python -m vulnscanner.main example.com --format json
```

## Testing on Windows
If you don't have `searchsploit` (Exploit-DB) installed, the tool will automatically fallback to a `mock_searchsploit.py` script for demonstration.

1. Start the mock target: `python vuln_site.py`
2. Run the scanner: `python -m vulnscanner.main 127.0.0.1 -p 8080`

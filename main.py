import asyncio
import argparse
import os
import sys
import time
from .scanner import Scanner
from .checker import Checker
from .reporter import Reporter
from .utils import parse_targets

async def process_target(target: str, ports: list, scanner: Scanner, checker: Checker):
    print(f"[*] Starting scan for {target}...")
    host = await scanner.scan_host(target, ports)
    
    if not host.alive:
        print(f"[-] {target} is down or no ports found.")
        return []

    print(f"[+] {target} is up. Found {len(host.ports)} open ports. Running vulnerability checks...")
    findings = await checker.run_checks(host)
    return findings

async def run_scan(target_str: str, port_range: str, output_format: str, concurrency: int):
    targets = parse_targets(target_str)
    if not targets:
        print("[!] No valid targets found.")
        return

    # Parse port range
    ports = []
    try:
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p.strip()) for p in port_range.split(',')]
    except ValueError:
        print(f"[!] Invalid port range: {port_range}")
        return

    data_dir = os.path.join(os.path.dirname(__file__), "data")
    scanner = Scanner(concurrency=concurrency)
    checker = Checker(data_dir=data_dir)
    
    start_time = time.time()
    
    all_findings = []
    # Process targets sequentially to avoid overwhelming network, but scanner handles concurrency internally
    for target in targets:
        findings = await process_target(target, ports, scanner, checker)
        all_findings.extend(findings)
    
    end_time = time.time()
    duration = end_time - start_time

    print(f"\n[*] Scan complete. Duration: {duration:.2f} seconds.")
    
    if output_format == "json":
        print(Reporter.to_json(all_findings))
    else:
        print("\n" + "="*20 + " FINAL VULNERABILITY REPORT " + "="*20)
        print(Reporter.to_text(all_findings))

def main():
    # Enable ANSI colors on Windows 10+
    if os.name == 'nt':
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

    parser = argparse.ArgumentParser(description="Professional Vulnerability Framework")
    parser.add_argument("target", help="Target IP, CIDR (e.g. 192.168.1.0/24), or domain")
    parser.add_argument("-p", "--ports", default="21,22,80,443,3306,5432,8080", help="Port range (1-100) or list (22,80)")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("-c", "--concurrency", type=int, default=200, help="Max concurrent connections")
    
    args = parser.parse_args()
    
    try:
        asyncio.run(run_scan(args.target, args.ports, args.format, args.concurrency))
    except KeyboardInterrupt:
        print("\n[!] User interrupted. Exiting...")
    except Exception as e:
        print(f"\n[!] Fatal Error: {e}")

if __name__ == "__main__":
    main()

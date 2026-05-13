"""
Main entry point for VulnScanner.
"""
import asyncio
import logging
import argparse
from core.scanner import Scanner
from core.checker import Checker

logger = logging.getLogger("vulnscanner")

def parse_args():
    parser = argparse.ArgumentParser(description="VulnScanner: Defensive Vulnerability Assessment")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("target", help="Target IP address")
    
    return parser.parse_args()

async def run():
    args = parse_args()
    if args.command == "scan":
        scanner = Scanner()
        checker = Checker()
        host = await scanner.scan_host(args.target, [80, 443, 22])
        if host.alive:
            findings = await checker.run_checks(host)
            for f in findings:
                logger.warning(f"Found {f.title} on {f.host}:{f.port}")

if __name__ == "__main__":
    asyncio.run(run())

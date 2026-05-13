"""
VulnScanner: A professional vulnerability assessment framework.
"""
import asyncio
import logging
import argparse
import sys
import os

# Ensure the parent directory is in the path to allow module imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from vulnscanner.core.scanner import Scanner
from vulnscanner.core.checker import Checker
from vulnscanner.reporter_html import HTMLReporter
from vulnscanner.utils.notes_exporter import NotesExporter
from vulnscanner.utils.utils import parse_targets

# Professional logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("VulnScanner")

def parse_arguments():
    parser = argparse.ArgumentParser(description="VulnScanner: Advanced Defensive Reconnaissance")
    parser.add_argument("target", help="Target IP or range")
    parser.add_argument("-p", "--ports", default="80,443,8080,9000", help="Ports")
    parser.add_argument("--export-html", help="HTML report output path")
    parser.add_argument("--export-notes", help="Plaintext notes output path")
    return parser.parse_args()

async def run_scan(target, port_range, args):
    scanner = Scanner()
    # Ensure relative paths for data and templates
    checker = Checker(data_dir=os.path.join(os.path.dirname(__file__), "data"), 
                      templates_dir=os.path.join(os.path.dirname(__file__), "templates"))
    
    ports = [int(p) for p in port_range.split(',')]
    host = await scanner.scan_host(target, ports)
    
    if host.alive:
        logger.info(f"Target {target} is up. Running checks...")
        findings = await checker.run_checks(host)
        
        if args.export_html:
            html = HTMLReporter.generate(findings, target)
            with open(args.export_html, "w") as f:
                f.write(html)
            logger.info(f"HTML report saved to {args.export_html}")
            
        if args.export_notes:
            notes = NotesExporter.generate(findings, target)
            with open(args.export_notes, "w") as f:
                f.write(notes)
            logger.info(f"Notes saved to {args.export_notes}")
            
        for f in findings:
            logger.warning(f"Vulnerability found: {f.title} [{f.severity}]")

async def main():
    args = parse_arguments()
    logger.info(f"Initiating scan on {args.target}")
    await run_scan(args.target, args.ports, args)

if __name__ == "__main__":
    asyncio.run(main())

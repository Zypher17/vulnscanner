"""
VulnScanner: A professional vulnerability assessment framework.
"""
import asyncio
import argparse
import os
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# Add the parent directory to sys.path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.core.scanner import Scanner
from scanner.core.checker import Checker
from scanner.reporter_html import HTMLReporter
from scanner.utils.notes_exporter import NotesExporter
from scanner.utils.utils import parse_targets

console = Console()

BANNER = """
[bold cyan]
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
[/bold cyan]
[bold white]VulnScanner v2.2 | Security Research Framework | Developed by Zypher17[/bold white]
"""

def display_summary_table(findings):
    table = Table(title="Vulnerability Summary", box=box.ROUNDED, header_style="bold magenta")
    table.add_column("Severity", justify="center")
    table.add_column("Target", justify="left")
    table.add_column("Port", justify="center")
    table.add_column("Issue", justify="left")
    
    severity_colors = {
        "critical": "[bold red]CRITICAL[/bold red]",
        "high": "[bold red]HIGH[/bold red]",
        "medium": "[bold yellow]MEDIUM[/bold yellow]",
        "low": "[bold blue]LOW[/bold blue]",
        "none": "[green]INFO[/green]"
    }
    
    for f in findings:
        table.add_row(
            severity_colors.get(f.severity.upper(), f.severity),
            f.host,
            str(f.port),
            f.title
        )
    
    console.print(table)

async def run_scan(target, port_range, args):
    console.print(Panel(BANNER, border_style="cyan"))
    
    scanner = Scanner()
    checker = Checker(data_dir="data", templates_dir="templates")
    
    ports = [int(p) for p in port_range.split(',')]
    host = await scanner.scan_host(target, ports)
    
    if host.alive:
        console.print(f"[bold green]✓[/bold green] Target {target} is up. Running checks...")
        findings = await checker.run_checks(host)
        
        if not findings:
            console.print("[bold green]No vulnerabilities found! Good job.[/bold green]")
            return

        display_summary_table(findings)
        
        if args.export_html:
            html = HTMLReporter.generate(findings, target)
            with open(args.export_html, "w") as f:
                f.write(html)
            console.print(f"[bold green]✓[/bold green] Report exported to [bold cyan]{args.export_html}[/bold cyan]")
            
        if args.export_notes:
            notes = NotesExporter.generate(findings, target)
            with open(args.export_notes, "w") as f:
                f.write(notes)
            console.print(f"[bold green]✓[/bold green] Notes saved to [bold cyan]{args.export_notes}[/bold cyan]")
            
    else:
        console.print(f"[bold red]✗[/bold red] Target {target} appears to be down.")

def parse_arguments():
    parser = argparse.ArgumentParser(description="VulnScanner: Advanced Defensive Reconnaissance")
    parser.add_argument("target", help="Target IP or range")
    parser.add_argument("-p", "--ports", default="80,443,8080,9000", help="Ports")
    parser.add_argument("--export-html", help="HTML report output path")
    parser.add_argument("--export-notes", help="Plaintext notes output path")
    return parser.parse_args()

async def main():
    args = parse_arguments()
    await run_scan(args.target, args.ports, args)

if __name__ == "__main__":
    asyncio.run(main())

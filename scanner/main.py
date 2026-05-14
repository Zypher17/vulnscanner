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
from scanner.core.searchsploit import SearchSploit
from scanner.reporter_html import HTMLReporter
from scanner.utils.notes_exporter import NotesExporter
from scanner.utils.utils import parse_targets

console = Console()

BANNER = """
[bold cyan]
███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝
[/bold cyan]
[bold white]VulnScanner v3.0 | Extended Vulnerability Framework | Developed by Zypher17[/bold white]
"""

def display_summary_table(findings):
    table = Table(title="Vulnerability Summary", box=box.ROUNDED, header_style="bold magenta")
    table.add_column("Severity", justify="center")
    table.add_column("Target", justify="left")
    table.add_column("Port", justify="center")
    table.add_column("Issue", justify="left")
    
    severity_colors = {
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH": "[bold red]HIGH[/bold red]",
        "MEDIUM": "[bold yellow]MEDIUM[/bold yellow]",
        "LOW": "[bold blue]LOW[/bold blue]",
        "INFO": "[green]INFO[/green]"
    }
    
    for f in findings:
        table.add_row(
            severity_colors.get(f.severity.upper(), f.severity),
            f.host,
            str(f.port),
            f.title
        )
    
    console.print(table)

async def run_scan(args):
    console.print(Panel(BANNER, border_style="cyan"))
    
    scanner = Scanner()
    checker = Checker(data_dir="data", templates_dir="templates")
    
    ports = [int(p) for p in args.ports.split(',')]
    host = await scanner.scan_host(args.target, ports)
    
    if host.alive:
        console.print(f"[bold green]✓[/bold green] Target {args.target} is up. Running checks...")
        findings = await checker.run_checks(host)
        
        if not findings:
            console.print("[bold green]No vulnerabilities found! Good job.[/bold green]")
            return

        display_summary_table(findings)
        
        if args.export_html:
            html = HTMLReporter.generate(findings, args.target)
            with open(args.export_html, "w") as f:
                f.write(html)
            console.print(f"[bold green]✓[/bold green] Report exported to [bold cyan]{args.export_html}[/bold cyan]")
            
        if args.export_notes:
            notes = NotesExporter.generate(findings, args.target)
            with open(args.export_notes, "w") as f:
                f.write(notes)
            console.print(f"[bold green]✓[/bold green] Notes saved to [bold cyan]{args.export_notes}[/bold cyan]")
            
    else:
        console.print(f"[bold red]✗[/bold red] Target {args.target} appears to be down.")

from rich.progress import Progress, SpinnerColumn, TextColumn

def run_search(args):
    # Professional search feedback mimicking searchsploit's efficient interaction
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="Searching Exploit-DB...", total=None)
        
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "exploits.csv")
        engine = SearchSploit(db_path)
        results = engine.search(args.query)

    console.print(Panel(f"[bold cyan]VulnScanner Search Engine[/bold cyan]\nQuery: [bold white]{args.query}[/bold white]\n[dim]UI/UX & Engine Credit: User[/dim]", border_style="cyan"))
    
    if not results:
        console.print("[bold yellow]No exploits found for this query.[/bold yellow]")
        return

    table = Table(title=f"Results for '{args.query}'", box=box.SIMPLE_HEAVY)
    table.add_column("ID", style="cyan", width=6)
    table.add_column("Description", style="white")
    table.add_column("Payload Path", style="yellow")
    table.add_column("Author", style="magenta")

    for res in results:
        table.add_row(res['id'], res['description'], res['path'], res['author'])
    
    console.print(table)
    console.print(f"[dim]Found {len(results)} matches.[/dim]")


def parse_arguments():
    parser = argparse.ArgumentParser(description="VulnScanner: Advanced Defensive Reconnaissance")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a target")
    scan_parser.add_argument("target", help="Target IP or range")
    scan_parser.add_argument("-p", "--ports", default="80,443,8080,9000", help="Ports")
    scan_parser.add_argument("--export-html", help="HTML report output path")
    scan_parser.add_argument("--export-notes", help="Plaintext notes output path")
    
    # Search command
    search_parser = subparsers.add_parser("search", help="Search for exploits in Exploit-DB")
    search_parser.add_argument("query", help="Search query")
    
    # Allow running scan without "scan" keyword for backward compatibility
    if len(sys.argv) > 1 and sys.argv[1] not in ["scan", "search", "-h", "--help"]:
        sys.argv.insert(1, "scan")
        
    return parser.parse_args()

async def main():
    args = parse_arguments()
    if args.command == "scan":
        await run_scan(args)
    elif args.command == "search":
        run_search(args)
    else:
        console.print("[bold red]Error: No command specified. Use --help for usage.[/bold red]")

if __name__ == "__main__":
    asyncio.run(main())

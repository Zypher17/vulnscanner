import asyncio
import argparse
import os
import sys
import time
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.live import Live
from rich import box

from .scanner import Scanner
from .checker import Checker
from .reporter import Reporter
from .utils import parse_targets

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
[bold white]Vulnerability Assessment Framework | v2.1 | Developed by Zypher17[/bold white]
"""

async def process_target(target: str, ports: list, scanner: Scanner, checker: Checker, progress: Progress):
    task_id = progress.add_task(f"[cyan]Scanning {target}...", total=len(ports))
    host = await scanner.scan_host(target, ports)
    progress.update(task_id, completed=len(ports), description=f"[green]Scan complete for {target}")
    
    if not host.alive:
        return []

    check_task = progress.add_task(f"[yellow]Analyzing {target}...", total=1)
    findings = await checker.run_checks(host)
    progress.update(check_task, completed=1, description=f"[green]Analysis complete for {target}")
    
    return findings

def display_summary_table(findings):
    table = Table(title="Vulnerability Summary", box=box.ROUNDED, header_style="bold magenta")
    table.add_column("Severity", justify="center")
    table.add_column("Target", justify="left")
    table.add_column("Port", justify="center")
    table.add_column("Issue", justify="left")
    
    severity_colors = {
        "critical": "[bold red]CRITICAL[/bold red]",
        "high": "[red]HIGH[/red]",
        "medium": "[yellow]MEDIUM[/yellow]",
        "low": "[blue]LOW[/blue]",
        "none": "[green]INFO[/green]"
    }
    
    for f in findings:
        table.add_row(
            severity_colors.get(f.severity.value.lower(), f.severity.value),
            f.host,
            str(f.port),
            f.title
        )
    
    console.print(table)

async def run_scan(target_str: str, port_range: str, output_format: str, concurrency: int):
    console.print(Panel(BANNER, border_style="cyan"))
    
    targets = parse_targets(target_str)
    if not targets:
        console.print("[bold red][!] No valid targets found.[/bold red]")
        return

    ports = []
    try:
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p.strip()) for p in port_range.split(',')]
    except ValueError:
        console.print(f"[bold red][!] Invalid port range: {port_range}[/bold red]")
        return

    data_dir = os.path.join(os.path.dirname(__file__), "data")
    scanner = Scanner(concurrency=concurrency)
    checker = Checker(data_dir=data_dir)
    
    start_time = time.time()
    all_findings = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        for target in targets:
            findings = await process_target(target, ports, scanner, checker, progress)
            all_findings.extend(findings)
    
    duration = time.time() - start_time
    console.print(f"\n[bold green]✓[/bold green] Scan completed in [bold cyan]{duration:.2f}[/bold cyan] seconds.")
    
    if not all_findings:
        console.print("[bold green]No vulnerabilities found! Good job.[/bold green]")
        return

    if output_format == "json":
        print(Reporter.to_json(all_findings))
    else:
        display_summary_table(all_findings)
        console.print("\n[bold cyan]Detailed Findings:[/bold cyan]")
        console.print(Reporter.to_text(all_findings))

def main():
    if os.name == 'nt':
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

    parser = argparse.ArgumentParser(description="VulnScanner: Professional Vulnerability Framework")
    parser.add_argument("target", help="Target IP, CIDR, or domain")
    parser.add_argument("-p", "--ports", default="21,22,80,443,3306,5432,8080,9000", help="Port range (1-100) or list (22,80)")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("-c", "--concurrency", type=int, default=200, help="Max concurrent connections")
    parser.add_argument("--profile", choices=["quick", "web", "full", "lab"], help="Pre-defined scanning profiles")
    
    args = parser.parse_args()
    
    if args.profile == "quick":
        args.ports = "22,80,443"
    elif args.profile == "web":
        args.ports = "80,443,8000,8080,8443"
    elif args.profile == "full":
        args.ports = "1-1000"
    elif args.profile == "lab":
        args.ports = "8080,9000"

    try:
        asyncio.run(run_scan(args.target, args.ports, args.format, args.concurrency))
    except KeyboardInterrupt:
        console.print("\n[bold red][!] User interrupted. Exiting...[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red][!] Fatal Error: {e}[/bold red]")

if __name__ == "__main__":
    main()

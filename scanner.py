import asyncio
import httpx
import re
from typing import List, Dict, Any
from .models import Host, Port
from rich.console import Console 

console = Console()

class Scanner:
    def __init__(self, timeout: float = 1.0, concurrency: int = 100):
        self.timeout = timeout
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)

    async def scan_port(self, host_addr: str, port_number: int) -> Port:
        async with self.semaphore:
            port = Port(number=port_number)
            try:
                # Force HTTP detection if common web port
                if port_number in [80, 443, 8080, 9000]:
                    await self._identify_http(host_addr, port)
                else:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host_addr, port_number),
                        timeout=self.timeout
                    )
                    port.is_open = True
                    
                    # Try to grab banner
                    try:
                        banner_bytes = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
                        port.banner = banner_bytes.decode(errors='ignore').strip()
                        self._parse_banner(port)
                    except Exception:
                        pass
                    
                    writer.close()
                    await writer.wait_closed()
                
                # Post-scan service mapping if still unknown
                if not port.service:
                    if port_number == 22: port.service = "ssh"
                    elif port_number == 21: port.service = "ftp"
                    elif port_number == 3306: port.service = "mysql"
                    elif port_number == 5432: port.service = "postgresql"
                    elif port_number == 6379: port.service = "redis"
                    elif port_number == 27017: port.service = "mongodb"
                        
            except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
                port.is_open = False
            except Exception as e:
                console.log(f"[bold red]Warning: Error scanning port {host_addr}:{port_number}: {e}[/bold red]")
                port.is_open = False
            return port

    def _parse_banner(self, port: Port):
        banner = port.banner
        if not banner: return

        if "SSH-" in banner:
            port.service = "ssh"
            match = re.search(r'OpenSSH[_-]([\d\.]+p\d+)?', banner)
            port.version = f"OpenSSH {match.group(1)}" if match else "SSH Server"
        elif "220" in banner:
            port.service = "ftp"
            if "vsFTPd" in banner: port.version = re.search(r'vsFTPd ([\d.]+)', banner).group(1) if re.search(r'vsFTPd ([\d.]+)', banner) else "vsFTPd"
            else: port.version = "FTP Server"

    async def _identify_http(self, host_addr: str, port: Port):
        protocol = "https" if port.number == 443 else "http"
        url = f"{protocol}://{host_addr}:{port.number}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                response = await client.get(url)
                port.is_open = True
                port.service = "http"
                
                server_header = response.headers.get("Server", "")
                if server_header:
                    match = re.search(r'^([a-zA-Z0-9._-]+)/([\d.]+)', server_header)
                    port.version = f"{match.group(1)} {match.group(2)}" if match else server_header
                
                title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                if title_match:
                    port.title = title_match.group(1).strip()
        except Exception:
            # If HTTP identification fails, treat as open but keep service unknown
            port.is_open = True 

    async def scan_host(self, host_addr: str, ports: List[int]) -> Host:
        host = Host(addr=host_addr)
        tasks = [self.scan_port(host_addr, p) for p in ports]
        results = await asyncio.gather(*tasks)
        host.ports = [p for p in results if p.is_open]
        if host.ports:
            host.alive = True
        return host

import asyncio
import httpx
import re
from typing import List
from .models import Host, Port


class Scanner:
    def __init__(self, timeout: float = 1.0, concurrency: int = 100):
        self.timeout = timeout
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)

    async def scan_port(self, host_addr: str, port_number: int) -> Port:
        async with self.semaphore:
            port = Port(number=port_number)
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host_addr, port_number),
                    timeout=self.timeout
                )
                port.is_open = True
                
                # Try to grab banner
                try:
                    banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                    port.banner = banner.decode(errors='ignore').strip()
                    self._parse_banner(port)
                except Exception:
                    pass
                
                writer.close()
                await writer.wait_closed()
                
                # Specific service identification
                if port_number in [80, 443, 8080]:
                    await self._identify_http(host_addr, port)
                elif port_number == 22:
                    port.service = "ssh"
                elif port_number == 21:
                    port.service = "ftp"
                elif port_number == 3306:
                    port.service = "mysql"
                elif port_number == 5432:
                    port.service = "postgresql"
                    
            except Exception:
                port.is_open = False
            return port

    def _parse_banner(self, port: Port):
        banner = port.banner
        if not banner:
            return

        # SSH banner cleaning
        if "SSH-" in banner:
            port.service = "ssh"
            # Extract OpenSSH version if present
            match = re.search(r'OpenSSH[_-]([\d.]+)', banner)
            if match:
                port.version = f"OpenSSH {match.group(1)}"
            else:
                port.version = banner.split('-')[-1] # Fallback
        
        # FTP banner cleaning
        elif "220" in banner:
            port.service = "ftp"
            if "vsFTPd" in banner:
                match = re.search(r'vsFTPd ([\d.]+)', banner)
                if match:
                    port.version = f"vsFTPd {match.group(1)}"

    async def _identify_http(self, host_addr: str, port: Port):
        protocol = "https" if port.number == 443 else "http"
        url = f"{protocol}://{host_addr}:{port.number}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                response = await client.get(url)
                port.service = "http"
                
                # Extract Server header
                server_header = response.headers.get("Server", "")
                if server_header:
                    # Clean server header (e.g., "Apache/2.4.41 (Ubuntu)" -> "Apache 2.4.41")
                    match = re.search(r'^([a-zA-Z]+)/([\d.]+)', server_header)
                    if match:
                        port.version = f"{match.group(1)} {match.group(2)}"
                    else:
                        port.version = server_header
                
                # Simple title extraction
                title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                if title_match:
                    port.title = title_match.group(1).strip()
        except Exception:
            pass

    async def scan_host(self, host_addr: str, ports: List[int]) -> Host:
        host = Host(addr=host_addr)
        tasks = [self.scan_port(host_addr, p) for p in ports]
        results = await asyncio.gather(*tasks)
        host.ports = [p for p in results if p.is_open]
        if host.ports:
            host.alive = True
        return host

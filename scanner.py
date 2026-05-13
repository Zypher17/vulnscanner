import asyncio
import httpx
import re
from typing import List, Dict, Any
from .models import Host, Port
from rich.console import Console # Added for logging warnings

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
                # Use a shorter timeout for initial connection attempt
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host_addr, port_number),
                    timeout=self.timeout
                )
                port.is_open = True
                
                # Try to grab banner
                try:
                    # Read a larger chunk to capture more banner information
                    banner_bytes = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
                    port.banner = banner_bytes.decode(errors='ignore').strip()
                    self._parse_banner(port) # Parse banner for service and version
                except asyncio.TimeoutError:
                    # If banner read times out, it might still be an open port
                    pass
                except Exception as e:
                    console.log(f"Warning: Error reading banner from {host_addr}:{port_number}: {e}")
                
                # Close connection cleanly
                writer.close()
                await writer.wait_closed()
                
                # Attempt service identification if not already known from banner
                if not port.service:
                    if port_number in [80, 443, 8080, 9000]:
                        port.service = "http"
                    elif port_number == 22:
                        port.service = "ssh"
                    elif port_number == 21:
                        port.service = "ftp"
                    elif port_number == 3306:
                        port.service = "mysql"
                    elif port_number == 5432:
                        port.service = "postgresql"
                    elif port_number == 6379:
                        port.service = "redis"
                    elif port_number == 27017:
                        port.service = "mongodb"
                        
            except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
                port.is_open = False
            except Exception as e:
                console.log(f"Warning: Error scanning port {host_addr}:{port_number}: {e}")
                port.is_open = False # Assume closed if any other error occurs
            return port

    def _parse_banner(self, port: Port):
        banner = port.banner
        if not banner:
            return

        # --- Generic Banner Parsing ---
        # Attempt to identify common services and versions from raw banner text.
        
        # SSH banner cleaning
        if "SSH-" in banner:
            port.service = "ssh"
            # Extract OpenSSH version (e.g., "OpenSSH_7.9p1 Debian-9ubuntu1")
            match = re.search(r'OpenSSH[_-]([\d\.]+p\d+)?', banner)
            if match:
                version_part = match.group(1)
                if version_part:
                    port.version = f"OpenSSH {version_part.split('p')[0]}" # e.g., "OpenSSH 7.9"
                else:
                    port.version = "OpenSSH"
            else:
                # Fallback for other SSH servers
                port.version = "SSH Server"
            
            # Attempt to detect OS from banner if available
            os_match = re.search(r'\((.*?)\)', banner) # e.g., (Ubuntu), (Debian)
            if os_match:
                port.os = os_match.group(1)

        # FTP banner cleaning (e.g., "220 (vsFTPd 3.0.3)")
        elif "220" in banner:
            port.service = "ftp"
            if "vsFTPd" in banner:
                match = re.search(r'vsFTPd ([\d.]+)', banner)
                if match:
                    port.version = f"vsFTPd {match.group(1)}"
            elif "ProFTPD" in banner:
                match = re.search(r'ProFTPD ([\d.]+)', banner)
                if match:
                    port.version = f"ProFTPD {match.group(1)}"
            else:
                port.version = "FTP Server"
            
            # Attempt to detect OS from banner if available (less common for FTP)
            os_match = re.search(r'\((.*?)\)', banner)
            if os_match:
                port.os = os_match.group(1)

        # HTTP header analysis (done in _identify_http, but banner might contain info too)
        # We rely on _identify_http for HTTP, but could parse generic server banners here if needed.

        # Generic Service Mapping (if not identified above)
        # This mapping is basic and can be expanded.
        if not port.service:
            if port.number == 80 or port.number == 443 or port.number == 8080 or port.number == 9000:
                port.service = "http"
            elif port_number == 3306:
                port.service = "mysql"
            elif port_number == 5432:
                port.service = "postgresql"
            elif port_number == 6379:
                port.service = "redis"
            elif port_number == 27017:
                port.service = "mongodb"

    async def _identify_http(self, host_addr: str, port: Port):
        # Use httpx for HTTP requests
        protocol = "https" if port.number == 443 else "http"
        url = f"{protocol}://{host_addr}:{port.number}"
        
        try:
            # Use a client with follow_redirects enabled and verify=False for simplicity
            async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                response = await client.get(url)
                port.service = "http"
                
                # Extract Server header for version information
                server_header = response.headers.get("Server", "")
                if server_header:
                    # Try to parse common "Server: Software/Version (Details)" format
                    match = re.search(r'^([a-zA-Z0-9._-]+)/([\d.]+)', server_header)
                    if match:
                        port.version = f"{match.group(1)} {match.group(2)}"
                    else:
                        port.version = server_header # Use raw header if parsing fails
                
                # Extract HTML title for potential misconfiguration checks (like admin panels)
                title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                if title_match:
                    port.title = title_match.group(1).strip()

                # Attempt to extract OS from headers if available (less common than banners)
                # e.g., some servers might include OS info
                # For simplicity, we rely more on banner parsing for OS, but could add header checks here.

        except httpx.ConnectError:
            port.is_open = False # Connection failed
        except httpx.TimeoutException:
            # Port is open but timed out during HTTP request
            port.is_open = True # Keep it open, but might not get full info
        except Exception as e:
            console.log(f"Warning: Error during HTTP identification for {host_addr}:{port.number}: {e}")
            # If any error occurs during HTTP, we might not get full details, but port is considered open if connection was made.

    async def scan_host(self, host_addr: str, ports: List[int]) -> Host:
        host = Host(addr=host_addr)
        tasks = [self.scan_port(host_addr, p) for p in ports]
        # Execute port scans concurrently
        results = await asyncio.gather(*tasks)
        
        # Filter for open ports and update host object
        host.ports = [p for p in results if p.is_open]
        if host.ports:
            host.alive = True
        return host

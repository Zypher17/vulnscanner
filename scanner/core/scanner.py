"""
Core engine orchestrating scans with result caching and concurrent workers.
"""
import asyncio
from typing import List
from scanner.models import Host, Port, logger
from scanner.utils.cache import ResultCache

class Scanner:
    def __init__(self, concurrency: int = 100):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.cache = ResultCache()

    async def scan_port(self, host_addr: str, port: int) -> Port:
        # Check cache before scanning
        cached = self.cache.get(host_addr, port)
        if cached:
            return Port(**cached)

        async with self.semaphore:
            p = Port(number=port)
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host_addr, port), 
                    timeout=1.5
                )
                p.is_open = True
                
                # Attempt basic banner grabbing
                try:
                    banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                    p.banner = banner.decode('utf-8', errors='ignore').strip()
                    self._identify_service(p)
                except Exception:
                    pass
                
                writer.close()
                await writer.wait_closed()
            except Exception:
                p.is_open = False
            
            # Default service names if not identified by banner
            if p.is_open and not p.service:
                if port == 22: p.service = "ssh"
                elif port == 21: p.service = "ftp"
                elif port == 80 or port == 8080 or port == 9000: p.service = "http"
                elif port == 443: p.service = "https"
                elif port == 3306: p.service = "mysql"

            # Cache the result
            # Convert dataclass to dict for caching
            cache_data = {
                "number": p.number,
                "is_open": p.is_open,
                "service": p.service,
                "version": p.version
            }
            self.cache.set(host_addr, port, cache_data)
            return p

    def _identify_service(self, port: Port):
        if not port.banner:
            return
        
        banner = port.banner.lower()
        if "ssh" in banner:
            port.service = "ssh"
            if "openssh" in banner:
                import re
                match = re.search(r"openssh[_-]([\d.]+)", banner)
                if match: port.version = match.group(1)
        elif "220" in banner and "ftp" in banner:
            port.service = "ftp"
        elif "mysql" in banner:
            port.service = "mysql"
        elif "apache" in banner:
            port.service = "http"
            import re
            match = re.search(r"apache/([\d.]+)", banner)
            if match: port.version = match.group(1)
        elif "nginx" in banner:
            port.service = "http"
            import re
            match = re.search(r"nginx/([\d.]+)", banner)
            if match: port.version = match.group(1)

    async def scan_host(self, host_addr: str, ports: List[int]) -> Host:
        logger.info(f"Scanning target: {host_addr}")
        tasks = [self.scan_port(host_addr, p) for p in ports]
        results = await asyncio.gather(*tasks)
        
        host = Host(addr=host_addr, ports=[p for p in results if p.is_open])
        host.alive = len(host.ports) > 0
        return host

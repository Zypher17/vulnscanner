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
                conn = asyncio.open_connection(host_addr, port)
                _, writer = await asyncio.wait_for(conn, timeout=1.5)
                p.is_open = True
                writer.close()
                await writer.wait_closed()
            except Exception:
                p.is_open = False
            
            # Cache the result
            self.cache.set(host_addr, port, p.__dict__)
            return p

    async def scan_host(self, host_addr: str, ports: List[int]) -> Host:
        logger.info(f"Scanning target: {host_addr}")
        tasks = [self.scan_port(host_addr, p) for p in ports]
        results = await asyncio.gather(*tasks)
        
        host = Host(addr=host_addr, ports=[p for p in results if p.is_open])
        host.alive = len(host.ports) > 0
        return host

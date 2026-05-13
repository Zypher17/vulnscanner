"""
Core Scanner module for network discovery.
"""
import asyncio
from typing import List
from models import Host, Port, logger

class Scanner:
    def __init__(self, timeout: float = 2.0, concurrency: int = 100):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)

    async def scan_port(self, host_addr: str, port: int) -> Port:
        async with self.semaphore:
            p = Port(number=port)
            try:
                conn = asyncio.open_connection(host_addr, port)
                _, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                p.is_open = True
                writer.close()
                await writer.wait_closed()
            except Exception:
                p.is_open = False
            return p

    async def scan_host(self, host_addr: str, ports: List[int]) -> Host:
        logger.info(f"Scanning host: {host_addr}")
        tasks = [self.scan_port(host_addr, p) for p in ports]
        results = await asyncio.gather(*tasks)
        host = Host(addr=host_addr, ports=[p for p in results if p.is_open])
        host.alive = len(host.ports) > 0
        return host

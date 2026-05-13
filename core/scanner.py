import asyncio
import socket
from typing import List
from models import Host, Port

class Scanner:
    def __init__(self, concurrency: int = 100):
        self.semaphore = asyncio.Semaphore(concurrency)

    async def scan_port(self, host_addr: str, port: int) -> Port:
        async with self.semaphore:
            p = Port(number=port)
            try:
                # Basic TCP Connect check
                conn = asyncio.open_connection(host_addr, port)
                _, writer = await asyncio.wait_for(conn, timeout=1.0)
                p.is_open = True
                writer.close()
                await writer.wait_closed()
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                p.is_open = False
            return p

    async def scan_host(self, host_addr: str, ports: List[int]) -> Host:
        host = Host(addr=host_addr, ports=[])
        tasks = [self.scan_port(host_addr, p) for p in ports]
        results = await asyncio.gather(*tasks)
        host.ports = [p for p in results if p.is_open]
        host.alive = len(host.ports) > 0
        return host

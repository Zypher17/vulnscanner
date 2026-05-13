"""
VulnScanner: A professional vulnerability assessment framework.
"""
import asyncio
import logging
from typing import List, Optional
from dataclasses import dataclass, field

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("vulnscanner")

@dataclass
class Port:
    number: int
    is_open: bool = False
    service: Optional[str] = None
    version: Optional[str] = None

@dataclass
class Host:
    addr: str
    alive: bool = False
    ports: List[Port] = field(default_factory=list)

@dataclass
class Finding:
    host: str
    port: int
    title: str
    severity: str
    description: str
    evidence: str
    remediation: str
    exploitation_note: str
    cve_id: Optional[str] = None
    links: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

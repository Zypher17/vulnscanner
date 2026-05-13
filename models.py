from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Port:
    number: int
    is_open: bool = False
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    cve_id: Optional[str] = None
    
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
    public_exploit_available: bool = False
    vendor_links: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

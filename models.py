from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Port:
    number: int
    protocol: str = "tcp"
    is_open: bool = False
    banner: str = ""
    service: str = ""        # e.g., "http", "ssh", "ftp", "mysql"
    version: str = ""        # e.g., "OpenSSH 7.9", "vsFTPd 2.3.4"
    title: str = ""          # e.g., HTML page title for HTTP
    os: str = ""             # Potential OS detected from banner


@dataclass
class Host:
    addr: str
    alive: bool = False
    ports: List[Port] = field(default_factory=list)


@dataclass
class Finding:
    host: str
    port: int
    service: str
    code: str                    # e.g., "EDB-MATCH", "HTTP-EXPOSED_ADMIN"
    severity: Severity
    title: str
    description: str
    evidence: str                
    remediation: str             
    exploitation_note: str       
    cve_ids: List[str] = field(default_factory=list)
    edb_ids: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)

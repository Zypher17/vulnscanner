import ipaddress
from typing import List

def parse_targets(target_str: str) -> List[str]:
    """
    Parses a target string which can be a single IP, a CIDR range, or a comma-separated list.
    """
    targets = []
    items = [i.strip() for i in target_str.split(',')]
    
    for item in items:
        try:
            # Check if it's a CIDR network
            if '/' in item:
                network = ipaddress.ip_network(item, strict=False)
                targets.extend([str(ip) for ip in network.hosts()])
            else:
                # Validate as single IP or just treat as domain
                try:
                    ipaddress.ip_address(item)
                    targets.append(item)
                except ValueError:
                    # Likely a domain name
                    targets.append(item)
        except Exception:
            # Fallback for unexpected formats
            targets.append(item)
            
    return list(dict.fromkeys(targets)) # Remove duplicates

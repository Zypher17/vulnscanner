import os
from scanner.models import Host, Finding
from scanner.core.searchsploit import SearchSploit

async def check(host: Host) -> list:
    findings = []
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "exploits.csv")
    engine = SearchSploit(db_path)

    for port in host.ports:
        if not port.is_open or not port.service:
            continue
        
        matches = engine.match_service(port.service, port.version)
        for match in matches:
            findings.append(Finding(
                host=host.addr,
                port=port.number,
                title=f"Exploit Found: {match['description']}",
                severity="HIGH",
                description=f"An exploit was found in Exploit-DB matching the service {port.service} {port.version or ''}.",
                evidence=f"Exploit-DB ID: {match['id']}\nPayload Path: {match['path']}\nAuthor: {match['author']}\nTool Credit: Extended UI by User",
                remediation="Update the service to a version not affected by this exploit, or apply relevant patches.",
                exploitation_note="This is a known exploit from Exploit-DB. Path assumes standard Kali Linux exploit-db structure.",
                links=[f"https://www.exploit-db.com/exploits/{match['id']}"]
            ))
    
    return findings

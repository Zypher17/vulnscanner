import json
import os
import asyncio
import httpx
from typing import List, Dict, Any
from .models import Host, Port, Finding, Severity


class BaseCheck:
    def __init__(self, knowledge_base: Dict[str, Any]):
        self.kb = knowledge_base

    async def check(self, host: Host, port: Port) -> List[Finding]:
        raise NotImplementedError


class ExploitDBCheck(BaseCheck):
    async def check(self, host: Host, port: Port) -> List[Finding]:
        findings = []
        query = ""
        if port.service and port.version:
            query = f"{port.service} {port.version}"
        elif port.version:
            query = port.version
        elif port.service:
            if port.service not in ["http", "tcp", "unknown"]:
                query = port.service
        
        if not query or len(query) < 3:
            return findings

        try:
            process = await asyncio.create_subprocess_exec(
                'searchsploit', query, '--json',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        except FileNotFoundError:
            try:
                process = await asyncio.create_subprocess_exec(
                    'python', 'mock_searchsploit.py', query,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            except Exception:
                return findings

        try:
            stdout, _ = await process.communicate()
            if process.returncode == 0 and stdout:
                data = json.loads(stdout.decode(errors='ignore'))
                results = data.get('RESULTS_EXPLOIT', [])
                
                seen_titles = set()
                for result in results:
                    title = result.get('Title')
                    if title in seen_titles: continue
                    seen_titles.add(title)
                    
                    if len(findings) >= 10: break
                    
                    findings.append(Finding(
                        host=host.addr,
                        port=port.number,
                        service=port.service or "unknown",
                        code="EDB-MATCH",
                        severity=Severity.HIGH,
                        title=f"Exploit-DB: {title}",
                        description=f"Public exploit found for '{query}'.",
                        evidence=f"EDB-ID: {result.get('EDB-ID')}\nPath: {result.get('Path')}",
                        remediation="Update the service to a patched version. Review EDB details.",
                        exploitation_note="Highly exploitable via public PoC.",
                        edb_ids=[result.get('EDB-ID')],
                        links=[f"https://www.exploit-db.com/exploits/{result.get('EDB-ID')}"]
                    ))
        except Exception:
            pass
            
        return findings


class HTTPCheck(BaseCheck):
    async def check(self, host: Host, port: Port) -> List[Finding]:
        findings = []
        if port.service != "http": return findings

        title = (port.title or "").lower()
        targets = ["admin", "login", "manager", "dashboard", "control panel", "setup", "config"]
        
        for t in targets:
            if t in title:
                findings.append(Finding(
                    host=host.addr,
                    port=port.number,
                    service="http",
                    code="HTTP-EXPOSED_ADMIN",
                    severity=Severity.MEDIUM,
                    title=f"Potentially Exposed Management Interface ({t})",
                    description="The page title suggests an administrative or login interface.",
                    evidence=f"Title: {port.title}",
                    remediation="Ensure the interface is protected by strong auth and not publicly accessible.",
                    exploitation_note="Attackers target these for brute-forcing or unauthorized access."
                ))
                break
        
        # ACTIVE XSS CHECK
        try:
            xss_payload = "<script>alert('XSS')</script>"
            protocol = "https" if port.number == 443 else "http"
            # Try common parameters like 'name', 'q', 'search'
            for param in ['name', 'q', 'search', 'id']:
                url = f"{protocol}://{host.addr}:{port.number}/?{param}={xss_payload}"
                async with httpx.AsyncClient(timeout=2.0, verify=False) as client:
                    response = await client.get(url)
                    if xss_payload in response.text:
                        findings.append(Finding(
                            host=host.addr,
                            port=port.number,
                            service="http",
                            code="HTTP-XSS",
                            severity=Severity.HIGH,
                            title="Reflected Cross-Site Scripting (XSS) Detected",
                            description=f"The application reflects user input from the '{param}' parameter without sanitization.",
                            evidence=f"Payload reflected in response: {url}",
                            remediation="Implement proper output encoding and use a Content Security Policy (CSP).",
                            exploitation_note="An attacker could execute malicious scripts in the victim's browser."
                        ))
                        break # Found one, move on
        except Exception:
            pass

        return findings


class Checker:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.kb = self._load_kb(data_dir)
        self.checks = [
            ExploitDBCheck(self.kb),
            HTTPCheck(self.kb)
        ]

    def _load_kb(self, data_dir: str) -> Dict[str, Any]:
        kb = {}
        for name in ['risk_summary']:
            path = os.path.join(data_dir, f"{name}.json")
            if os.path.exists(path) and os.path.getsize(path) > 0:
                with open(path, 'r') as f:
                    kb[name] = json.load(f)
            else:
                kb[name] = {}
        return kb

    async def run_checks(self, host: Host) -> List[Finding]:
        all_findings = []
        for port in host.ports:
            tasks = [c.check(host, port) for c in self.checks]
            results = await asyncio.gather(*tasks)
            for r in results:
                all_findings.extend(r)
        return all_findings

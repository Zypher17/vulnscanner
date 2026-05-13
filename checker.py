import json
import os
import asyncio
import httpx
from typing import List, Dict, Any
from .models import Host, Port, Finding, Severity
from rich.console import Console

console = Console()

class BaseCheck:
    def __init__(self, knowledge_base: Dict[str, Any]):
        self.kb = knowledge_base

    async def check(self, host: Host, port: Port) -> List[Finding]:
        raise NotImplementedError

class ExploitDBCheck(BaseCheck):
    async def check(self, host: Host, port: Port) -> List[Finding]:
        findings = []
        query = f"{port.service} {port.version}".strip()
        if not query or len(query) < 3: return findings

        try:
            cmd = ['searchsploit', query, '--json']
            process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except FileNotFoundError:
            try:
                cmd = ['python', 'mock_searchsploit.py', query]
                process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            except Exception: return findings

        stdout, _ = await process.communicate()
        if process.returncode == 0 and stdout:
            try:
                data = json.loads(stdout.decode(errors='ignore'))
                for result in data.get('RESULTS_EXPLOIT', [])[:10]:
                    findings.append(Finding(
                        host=host.addr, port=port.number, service=port.service or "unknown",
                        code="EDB-MATCH", severity=Severity.HIGH,
                        title=f"Exploit-DB: {result.get('Title')}",
                        description=f"Public exploit found for '{query}'.",
                        evidence="EDB-ID: {}\nPath: {}".format(result.get('EDB-ID'), result.get('Path')),
                        remediation="Review EDB details and patch the service.",
                        exploitation_note="Public exploit available.",
                        edb_ids=[result.get('EDB-ID')],
                        links=[f"https://www.exploit-db.com/exploits/{result.get('EDB-ID')}"]
                    ))
            except Exception: pass
        return findings

class HTTPCheck(BaseCheck):
    async def check(self, host: Host, port: Port) -> List[Finding]:
        findings = []
        if port.service != "http": return findings

        # --- XSS / SQLi / Redirect / CmdInj probes omitted for brevity ---
        
        # --- Sensitive Paths with Severity Tuning ---
        sensitive_paths = {
            "/admin/": {"sev": Severity.HIGH, "rem": "Restrict access via auth/IP.", "note": "May expose admin controls."},
            "/.git/": {"sev": Severity.HIGH, "rem": "Remove .git folder from production.", "note": "May reveal source code."},
            "/.env": {"sev": Severity.HIGH, "rem": "Remove or restrict .env access.", "note": "May leak secrets/keys."},
            "/backup.zip": {"sev": Severity.HIGH, "rem": "Remove backups.", "note": "May expose full source/DB."},
            "/admin.php": {"sev": Severity.HIGH, "rem": "Restrict access.", "note": "Login/Admin panel."},
            "/dashboard/": {"sev": Severity.MEDIUM, "rem": "Protect with auth.", "note": "Generic dashboard."},
            "/swagger.json": {"sev": Severity.MEDIUM, "rem": "Restrict access.", "note": "May expose API documentation."},
            "/robots.txt": {"sev": Severity.LOW, "rem": "Check for unintended disclosures.", "note": "May reveal directory structure."}
        }
        
        for path, info in sensitive_paths.items():
            try:
                url = f"http://{host.addr}:{port.number}{path}"
                async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=True) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        content_len = len(resp.content)
                        is_login = "password" in resp.text.lower() and "<form" in resp.text.lower()
                        findings.append(Finding(
                            host=host.addr, port=port.number, service="http", code="HTTP-MISCONFIG",
                            severity=info['sev'],
                            title=f"Exposed Path: {path}",
                            description=f"Path {path} is accessible ({info['note']})",
                            evidence=f"URL: {url}\nStatus: {resp.status_code}\nSize: {content_len} bytes{' [Login Detected]' if is_login else ''}",
                            remediation=info['rem'],
                            exploitation_note=info['note']
                        ))
            except Exception: pass
        return findings

class DBCheck(BaseCheck):
    async def check(self, host: Host, port: Port) -> List[Finding]:
        findings = []
        if port.service in ["mysql", "postgresql", "mongodb", "redis"]:
            findings.append(Finding(
                host=host.addr, port=port.number, service=port.service, code="DB-EXPOSED",
                severity=Severity.HIGH, title=f"{port.service.capitalize()} Exposed",
                description="Database port open to the network.",
                evidence=f"Port {port.number} open.",
                remediation="Firewall the port.",
                exploitation_note="High-value target."
            ))
        return findings

class Checker:
    def __init__(self, data_dir: str):
        self.kb = self._load_kb(data_dir)
        self.checks = [ExploitDBCheck(self.kb), HTTPCheck(self.kb), DBCheck(self.kb)]

    def _load_kb(self, data_dir: str) -> Dict[str, Any]:
        kb = {}
        for name in ['risk_summary']:
            path = os.path.join(data_dir, f"{name}.json")
            if os.path.exists(path):
                with open(path, 'r') as f: kb[name] = json.load(f)
        return kb

    async def run_checks(self, host: Host) -> List[Finding]:
        all_findings = []
        for port in host.ports:
            results = await asyncio.gather(*[c.check(host, port) for c in self.checks])
            for r in results: all_findings.extend(r)
        return all_findings

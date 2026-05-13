import json
import os
import asyncio
import httpx
import yaml
from typing import List, Dict, Any
from .models import Host, Port, Finding, Severity
from rich.console import Console

console = Console()

class BaseCheck:
    def __init__(self, knowledge_base: Dict[str, Any]):
        self.kb = knowledge_base

    async def check(self, host: Host, port: Port) -> List[Finding]:
        raise NotImplementedError

class TemplateCheck(BaseCheck):
    def __init__(self, templates_dir: str, knowledge_base: Dict[str, Any]):
        super().__init__(knowledge_base)
        self.templates = self._load_templates(templates_dir)

    def _load_templates(self, templates_dir: str) -> List[Dict]:
        templates = []
        if os.path.exists(templates_dir):
            for filename in os.listdir(templates_dir):
                if filename.endswith(".yaml") or filename.endswith(".yml"):
                    with open(os.path.join(templates_dir, filename), 'r') as f:
                        docs = yaml.safe_load_all(f)
                        for doc in docs:
                            if doc: templates.append(doc)
        return templates

    async def check(self, host: Host, port: Port) -> List[Finding]:
        findings = []
        if port.service != "http": return findings
        
        async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=True) as client:
            for t in self.templates:
                req = t.get('request', {})
                url = f"http://{host.addr}:{port.number}{req.get('path', '/')}"
                
                try:
                    resp = await client.request(req.get('method', 'GET'), url)
                    for matcher in req.get('matchers', []):
                        if matcher['type'] == 'word':
                            if any(word in resp.text for word in matcher.get('words', [])):
                                findings.append(Finding(
                                    host=host.addr, port=port.number, service="http",
                                    code=f"TEMPLATE-{t['id']}",
                                    severity=Severity(t.get('severity', 'MEDIUM').lower()),
                                    title=t.get('name'),
                                    description=t.get('description'),
                                    evidence=f"URL: {url}\nStatus: {resp.status_code}",
                                    remediation=t.get('remediation', 'N/A'),
                                    exploitation_note="Template match found."
                                ))
                except Exception: continue
        return findings

class ExploitDBCheck(BaseCheck):
    # ... (Keep existing implementation, maybe enrich it later) ...
    async def check(self, host: Host, port: Port) -> List[Finding]:
        # Existing EDB logic
        return []

class Checker:
    def __init__(self, data_dir: str, templates_dir: str):
        self.kb = self._load_kb(data_dir)
        self.checks = [
            TemplateCheck(templates_dir, self.kb),
            ExploitDBCheck(self.kb)
        ]

    def _load_kb(self, data_dir: str) -> Dict[str, Any]:
        kb = {}
        # Load risk_summary.json...
        return kb

    async def run_checks(self, host: Host) -> List[Finding]:
        all_findings = []
        for port in host.ports:
            console.log(f"[bold magenta]Checking port {port.number} [Service: {port.service}][/bold magenta]")
            results = await asyncio.gather(*[c.check(host, port) for c in self.checks])
            for r in results: all_findings.extend(r)
        return all_findings

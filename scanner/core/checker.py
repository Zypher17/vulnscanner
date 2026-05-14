import importlib
import os
import yaml
from typing import List, Dict
from scanner.models import Host, Port, Finding

class TemplateCheck:
    def __init__(self, templates_dir: str):
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
        import httpx
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
                                    host=host.addr, port=port.number,
                                    title=t.get('name'),
                                    severity=t.get('severity', 'MEDIUM'),
                                    description=t.get('description', ''),
                                    evidence=f"URL: {url}",
                                    remediation=t.get('remediation', 'N/A'),
                                    exploitation_note="Template match found."
                                ))
                except Exception: continue
        return findings

class Checker:
    def __init__(self, data_dir, templates_dir):
        self.modules = ["http_check", "ssh_check", "ftp_check", "db_check", "searchsploit_check"]
        self.template_engine = TemplateCheck(templates_dir)

    async def run_checks(self, host: Host, module_name: str = None) -> List[Finding]:
        all_findings = []
        
        # 1. Run standard modules
        modules_to_run = [module_name] if module_name else self.modules
        for mod_name in modules_to_run:
            try:
                mod = importlib.import_module(f"scanner.modules.{mod_name}")
                if hasattr(mod, "check"):
                    findings = await mod.check(host)
                    all_findings.extend(findings)
            except ImportError:
                print(f"[!] Module {mod_name} not found.")

        # 2. Run Template Engine
        for port in host.ports:
            findings = await self.template_engine.check(host, port)
            all_findings.extend(findings)

        return all_findings

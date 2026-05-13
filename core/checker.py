import importlib
from typing import List
from models import Host, Port, Finding

class Checker:
    def __init__(self):
        self.modules = ["http_check", "ssh_check", "ftp_check", "db_check"]

    async def run_checks(self, host: Host, module_name: str = None) -> List[Finding]:
        all_findings = []
        modules_to_run = [module_name] if module_name else self.modules
        
        for mod_name in modules_to_run:
            try:
                mod = importlib.import_module(f"modules.{mod_name}")
                if hasattr(mod, "check"):
                    findings = await mod.check(host)
                    all_findings.extend(findings)
            except ImportError:
                print(f"[!] Module {mod_name} not found.")
        return all_findings

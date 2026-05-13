import json
from typing import List
from dataclasses import asdict
from .models import Finding, Severity

# Simple ANSI colors for Windows/Linux terminals
C_RED = "\033[91m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_GREEN = "\033[92m"
C_BOLD = "\033[1m"
C_END = "\033[0m"

class Reporter:
    @staticmethod
    def _get_color(severity: Severity) -> str:
        if severity == Severity.CRITICAL: return C_RED + C_BOLD
        if severity == Severity.HIGH: return C_RED
        if severity == Severity.MEDIUM: return C_YELLOW
        if severity == Severity.LOW: return C_BLUE
        return C_GREEN

    @staticmethod
    def to_text(findings: List[Finding]) -> str:
        if not findings:
            return f"{C_GREEN}[+] No vulnerabilities identified.{C_END}"
        
        output = []
        # Sort findings by severity (Critical first)
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.NONE: 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.severity, 5))

        for f in sorted_findings:
            color = Reporter._get_color(f.severity)
            
            block = [
                f"{C_BOLD}Host: {f.host} | Port: {f.port} ({f.service}){C_END}",
                f"{color}Issue: {f.code} [{f.severity.upper()}]{C_END}",
                f"{C_BOLD}Title:{C_END} {f.title}",
                f"{C_BOLD}Description:{C_END} {f.description}",
                f"{C_BOLD}Evidence:{C_END}\n{f.evidence}",
                f"{C_BOLD}Remediation:{C_END} {f.remediation}",
                f"{C_BOLD}Risk Note:{C_END} {f.exploitation_note}"
            ]
            
            if f.links:
                block.append(f"{C_BOLD}Links:{C_END} {', '.join(f.links)}")
            
            output.append("\n".join(block))
            output.append("-" * 50)
            
        return "\n".join(output)

    @staticmethod
    def to_json(findings: List[Finding]) -> str:
        return json.dumps([asdict(f) for f in findings], indent=2)

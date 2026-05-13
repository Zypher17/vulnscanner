import datetime
from typing import List
from scanner.models import Finding

class NotesExporter:
    @staticmethod
    def generate(findings: List[Finding], target: str) -> str:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        notes = f"VulnScanner Reconnaissance Report - {target}\n"
        notes += f"Generated on: {timestamp}\n"
        notes += "=" * 50 + "\n\n"
        
        if not findings:
            notes += "No vulnerabilities discovered.\n"
        else:
            for f in findings:
                notes += f"Finding: {f.title}\n"
                notes += f"Severity: {f.severity}\n"
                notes += f"Target/Port: {f.host}:{f.port}\n"
                notes += f"Description: {f.description}\n"
                notes += f"Evidence: {f.evidence}\n"
                notes += f"Remediation: {f.remediation}\n"
                notes += f"Exploitation Logic (Conceptual): {f.exploitation_note}\n"
                if f.links:
                    notes += f"References: {', '.join(f.links)}\n"
                notes += "-" * 30 + "\n\n"
        return notes

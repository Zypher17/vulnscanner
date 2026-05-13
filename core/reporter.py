import json
from typing import List
from models import Finding

class Reporter:
    @staticmethod
    def to_text(findings: List[Finding]) -> str:
        output = ""
        for f in findings:
            output += f"Host: {f.host}:{f.port}\nTitle: {f.title}\nSeverity: {f.severity}\nEvidence: {f.evidence}\n\n"
        return output

    @staticmethod
    def to_json(findings: List[Finding]) -> str:
        return json.dumps([f.__dict__ for f in findings], indent=4)

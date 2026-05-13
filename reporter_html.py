from typing import List
from .models import Finding
import datetime

class HTMLReporter:
    @staticmethod
    def generate(findings: List[Finding], target: str) -> str:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>VulnScanner Report - {target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f4f4f9; }}
        h1 {{ color: #333; }}
        .finding {{ background: white; padding: 15px; margin-bottom: 10px; border-left: 5px solid #dc3545; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .severity-HIGH {{ border-left-color: #dc3545; }}
        .severity-MEDIUM {{ border-left-color: #ffc107; }}
        .severity-LOW {{ border-left-color: #0d6efd; }}
        .code {{ font-family: monospace; background: #eee; padding: 2px 4px; }}
    </style>
</head>
<body>
    <h1>VulnScanner Report</h1>
    <p>Target: <b>{target}</b></p>
    <p>Generated: {timestamp}</p>
    <hr>
"""
        if not findings:
            html += "<p>No vulnerabilities found.</p>"
        else:
            for f in findings:
                sev_class = f"severity-{f.severity.upper()}"
                html += f"""
                <div class="finding {sev_class}">
                    <h2>{f.title}</h2>
                    <p><b>Severity:</b> {f.severity.upper()} | <b>Service:</b> {f.service} | <b>Port:</b> {f.port}</p>
                    <p><b>Description:</b> {f.description}</p>
                    <p><b>Evidence:</b><pre>{f.evidence}</pre></p>
                    <p><b>Remediation:</b> {f.remediation}</p>
                    <p><b>Risk Note:</b> {f.exploitation_note}</p>
                </div>
                """
        html += "</body></html>"
        return html

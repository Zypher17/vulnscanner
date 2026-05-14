from typing import List
from .models import Finding
import datetime
import json

class HTMLReporter:
    @staticmethod
    def generate(findings: List[Finding], target: str) -> str:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Summary stats
        critical = len([f for f in findings if f.severity.upper() == "CRITICAL"])
        high = len([f for f in findings if f.severity.upper() == "HIGH"])
        medium = len([f for f in findings if f.severity.upper() == "MEDIUM"])
        low = len([f for f in findings if f.severity.upper() == "LOW"])
        info = len([f for f in findings if f.severity.upper() == "INFO" or f.severity.upper() == "NONE"])

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowRecon Dashboard - {target}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #f8fafc;
            --primary: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #3b82f6;
            --info: #10b981;
        }}
        body {{ 
            font-family: 'Inter', sans-serif; 
            margin: 0; 
            background: var(--bg); 
            color: var(--text);
            line-height: 1.5;
        }}
        .sidebar {{
            position: fixed;
            left: 0; top: 0; bottom: 0;
            width: 240px;
            background: #020617;
            padding: 20px;
            border-right: 1px solid #334155;
        }}
        .main {{
            margin-left: 280px;
            padding: 40px;
            max-width: 1000px;
        }}
        .header {{
            margin-bottom: 40px;
        }}
        .header h1 {{ margin: 0; font-size: 2.5rem; color: var(--primary); }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: var(--card-bg);
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid #334155;
        }}
        .stat-val {{ font-size: 2rem; font-weight: 600; }}
        .stat-label {{ font-size: 0.875rem; color: #94a3b8; text-transform: uppercase; }}
        
        .finding {{ 
            background: var(--card-bg); 
            padding: 25px; 
            margin-bottom: 24px; 
            border-radius: 12px; 
            border-left: 6px solid var(--primary);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            transition: transform 0.2s;
        }}
        .finding:hover {{ transform: translateY(-2px); }}
        .finding h2 {{ margin-top: 0; font-size: 1.5rem; }}
        .badge {{
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-right: 8px;
        }}
        .sev-critical {{ background: var(--critical); }}
        .sev-high {{ background: var(--high); }}
        .sev-medium {{ background: var(--medium); }}
        .sev-low {{ background: var(--low); }}
        .sev-info {{ background: var(--info); }}

        .meta {{ color: #94a3b8; font-size: 0.875rem; margin-bottom: 16px; }}
        .description {{ margin-bottom: 16px; }}
        .evidence {{ 
            background: #020617; 
            padding: 16px; 
            border-radius: 8px; 
            font-family: monospace; 
            font-size: 0.875rem; 
            overflow-x: auto;
            border: 1px solid #334155;
        }}
        .links a {{ color: var(--primary); text-decoration: none; }}
        .links a:hover {{ text-decoration: underline; }}
        
        .footer {{ margin-top: 60px; color: #64748b; font-size: 0.875rem; border-top: 1px solid #334155; padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="sidebar">
        <h2 style="color: var(--primary)">ShadowRecon</h2>
        <p style="color: #64748b; font-size: 0.875rem;">Vulnerability Framework</p>
        <nav style="margin-top: 40px;">
            <div style="color: var(--primary); font-weight: 600;">Dashboard</div>
            <div style="margin-top: 12px; color: #94a3b8;">Scanner Results</div>
            <div style="margin-top: 12px; color: #94a3b8;">Exploit Search</div>
            <div style="margin-top: 12px; color: #94a3b8;">Hardening Plans</div>
        </nav>
    </div>

    <div class="main">
        <div class="header">
            <h1>Assessment Report</h1>
            <p>Target: <span style="color: var(--primary); font-weight: 600;">{target}</span> | Scanned on: {timestamp}</p>
        </div>

        <div class="stats">
            <div class="stat-card"><div class="stat-val" style="color: var(--critical)">{critical}</div><div class="stat-label">Critical</div></div>
            <div class="stat-card"><div class="stat-val" style="color: var(--high)">{high}</div><div class="stat-label">High</div></div>
            <div class="stat-card"><div class="stat-val" style="color: var(--medium)">{medium}</div><div class="stat-label">Medium</div></div>
            <div class="stat-card"><div class="stat-val" style="color: var(--low)">{low}</div><div class="stat-label">Low</div></div>
        </div>

        <div id="findings">
"""
        if not findings:
            html += """
            <div style="text-align: center; padding: 60px; background: var(--card-bg); border-radius: 12px;">
                <h3 style="color: #10b981;">✓ No vulnerabilities detected</h3>
                <p style="color: #94a3b8;">The target attack surface appears minimal based on current probes.</p>
            </div>
            """
        else:
            for f in findings:
                sev = f.severity.upper()
                sev_class = f"sev-{sev.lower()}"
                
                # Process evidence and links outside the f-string to avoid backslashes in 3.11
                evidence_html = f.evidence.replace("\n", "<br>")
                links_html = "".join([f'<a href="{link}" target="_blank">{link}</a><br>' for link in f.links])
                
                html += f"""
                <div class="finding" style="border-left-color: var(--{sev.lower()})">
                    <span class="badge {sev_class}">{sev}</span>
                    <span style="color: #94a3b8; font-size: 0.875rem;">Port: {f.port}</span>
                    <h2>{f.title}</h2>
                    <div class="meta">Service Identification: {getattr(f, 'service', 'Unknown')}</div>
                    <div class="description">{f.description}</div>
                    <div class="evidence"><b>Evidence:</b><br>{evidence_html}</div>
                    <p><b>Remediation:</b> {f.remediation}</p>
                    <div class="links">
                        <b>References:</b><br>
                        {links_html}
                    </div>
                </div>
                """
        
        html += """
        </div>
        <div class="footer">
            &copy; 2026 ShadowRecon Framework | Developed for Authorized Security Research
        </div>
    </div>
</body>
</html>
"""
        return html

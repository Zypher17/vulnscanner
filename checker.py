import asyncio
import httpx
import re
from typing import List, Dict, Any
from .models import Host, Port, Finding, Severity
from .utils import parse_targets # Assuming parse_targets is in utils

class BaseCheck:
    def __init__(self, knowledge_base: Dict[str, Any]):
        self.kb = knowledge_base

    async def check(self, host: Host, port: Port) -> List[Finding]:
        raise NotImplementedError

class ExploitDBCheck(BaseCheck):
    async def check(self, host: Host, port: Port) -> List[Finding]:
        findings = []
        query = ""
        # Prioritize service and version for a more specific search query
        if port.service and port.version:
            query = f"{port.service} {port.version}"
        elif port.version:
            query = port.version
        elif port.service and port.service not in ["http", "tcp", "unknown"]:
            query = port.service
        
        # Avoid searching for very short or generic terms
        if not query or len(query.strip()) < 3:
            return findings

        try:
            # Try real searchsploit first
            # Use a list for command arguments
            cmd_args = ['searchsploit', query, '--json']
            process = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        except FileNotFoundError:
            # Fallback for Windows testing using our mock script
            try:
                cmd_args = ['python', 'mock_searchsploit.py', query]
                process = await asyncio.create_subprocess_exec(
                    *cmd_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            except Exception:
                # If fallback also fails, log and continue
                console.log(f"Warning: Could not run searchsploit or mock_searchsploit for query: {query}")
                return findings

        try:
            stdout, stderr = await process.communicate()
            if process.returncode == 0 and stdout:
                data = json.loads(stdout.decode(errors='ignore'))
                results = data.get('RESULTS_EXPLOIT', [])
                
                seen_titles = set()
                for result in results:
                    title = result.get('Title')
                    if title in seen_titles: continue
                    seen_titles.add(title)
                    
                    # Limit to avoid overwhelming output
                    if len(findings) >= 10: break
                    
                    # Extract CVEs if available in searchsploit output, otherwise leave empty
                    cve_ids = result.get('CVEs', []) if 'CVEs' in result else []
                    if not cve_ids and result.get('CWE'):
                        # Sometimes CWE is listed, try to infer CVE if possible, but usually not direct
                        pass # For now, stick to explicit CVEs

                    findings.append(Finding(
                        host=host.addr,
                        port=port.number,
                        service=port.service or "unknown",
                        code="EDB-MATCH", # Generic code for ExploitDB match
                        severity=Severity.HIGH, # Default to HIGH as a CVE match is serious
                        title=f"Exploit-DB: {title}",
                        description=f"Public exploit found for '{query}'. Version: {port.version or 'N/A'}.",
                        evidence=f"EDB-ID: {result.get('EDB-ID')}
Path: {result.get('Path')}",
                        remediation="Update the service to a patched version. Review Exploit-DB details for specific mitigation steps.",
                        exploitation_note="This service version is associated with a public exploit in Exploit-DB, indicating potential for unauthorized access or system compromise.",
                        edb_ids=[result.get('EDB-ID')] if result.get('EDB-ID') else [],
                        cve_ids=cve_ids,
                        links=[f"https://www.exploit-db.com/exploits/{result.get('EDB-ID')}"] if result.get('EDB-ID') else []
                    ))
            elif stderr:
                # Log stderr if searchsploit/mock failed but returned non-zero exit code
                console.log(f"Warning: searchsploit stderr for '{query}': {stderr.decode(errors='ignore')}")
        except Exception as e:
            console.log(f"Error processing ExploitDBCheck for {host.addr}:{port.number} with query '{query}': {e}")
            
        return findings


class HTTPCheck(BaseCheck):
    async def check(self, host: Host, port: Port) -> List[Finding]:
        findings = []
        if port.service != "http": return findings

        # --- XSS Detection ---
        try:
            # Use a more robust XSS payload for better detection
            xss_payload_script = "<script>console.log('XSS-Vuln-Test')</script>"
            xss_payload_img = "<img src=x onerror=alert('XSS')>"
            
            # Common parameters that might reflect input
            params_to_test = ['name', 'q', 'search', 'id', 'user', 'query', 'redirect']
            
            for param in params_to_test:
                # Test with script tag first, then img tag if script is blocked or encoded
                for payload in [xss_payload_script, xss_payload_img]:
                    # Basic URL encoding for the payload
                    encoded_payload = httpx.utils.encode_byte_range(payload.encode()).decode()
                    
                    url = f"http://{host.addr}:{port.number}/?{param}={encoded_payload}"
                    
                    async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                        response = await client.get(url)
                        
                        # Check if the raw payload (or a slightly altered version) is in the response text
                        # This is a heuristic and might have false positives/negatives
                        if payload in response.text:
                            findings.append(Finding(
                                host=host.addr,
                                port=port.number,
                                service="http",
                                code="HTTP-REFLECTED-XSS",
                                severity=Severity.HIGH,
                                title="Reflected Cross-Site Scripting (XSS) Detected",
                                description=f"The application reflects user input from the '{param}' parameter without proper sanitization or output encoding.",
                                evidence=f"Payload reflected: {url}",
                                remediation="Implement strict output encoding for all user-supplied data displayed in HTML. Use a Content Security Policy (CSP) to mitigate XSS attacks.",
                                exploitation_note="An attacker could inject malicious JavaScript into the victim's browser session, leading to session hijacking, phishing, or data theft."
                            ))
                            # Found XSS, no need to test other params for this port
                            break 
                if any(f.code == "HTTP-REFLECTED-XSS" for f in findings): break
        except Exception as e:
            console.log(f"Error during XSS check for {host.addr}:{port.number}: {e}")

        # --- Common Misconfigurations and Security Headers ---
        try:
            # Check common sensitive paths
            sensitive_paths = ["/admin/", "/login/", "/manager/", "/dashboard/", "/admin.php", "/wp-admin/", "/backup.zip", "/.git/", "/.env", "/robots.txt"]
            for path in sensitive_paths:
                test_url = f"http://{host.addr}:{port.number}{path}"
                async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                    response = await client.get(test_url)
                    # Infer vulnerability based on status code and content
                    if response.status_code in [200, 204] and len(response.content) > 100: # Some content, not just empty
                        finding_title = f"Exposed Sensitive Path: {path}"
                        severity = Severity.MEDIUM
                        description = f"Path '{path}' returned a successful response, potentially exposing sensitive information or interfaces."
                        remediation = f"Restrict access to '{path}'. Implement authentication and authorization."
                        exploitation_note = "Attackers can discover sensitive endpoints through enumeration and exploit them for unauthorized access or information disclosure."

                        # Specific checks for robots.txt
                        if path == "/robots.txt":
                            if "Disallow: /admin" in response.text or "Disallow: /wp-admin" in response.text:
                                finding_title = "robots.txt discloses sensitive paths"
                                severity = Severity.LOW
                                description = "robots.txt explicitly lists disallowed paths, which can aid attackers in discovering admin areas."
                                remediation = "Consider removing or obfuscating sensitive path information from robots.txt."

                        findings.append(Finding(
                            host=host.addr,
                            port=port.number,
                            service="http",
                            code="HTTP-MISCONFIG",
                            severity=severity,
                            title=finding_title,
                            description=description,
                            evidence=f"URL: {test_url}
Status Code: {response.status_code}
Content Length: {len(response.content)}",
                            remediation=remediation,
                            exploitation_note=exploitation_note
                        ))
                    elif response.status_code in [401, 403]: # Unauthorized/Forbidden might be a misconfiguration
                         findings.append(Finding(
                            host=host.addr,
                            port=port.number,
                            service="http",
                            code="HTTP-ACCESS_DENIED",
                            severity=Severity.LOW,
                            title=f"Path '{path}' returned {response.status_code}",
                            description=f"Path '{path}' returned an access denied status code.",
                            evidence=f"URL: {test_url}
Status Code: {response.status_code}",
                            remediation="Ensure proper access controls are in place.",
                            exploitation_note="While not a direct vulnerability, this can indicate interesting endpoints that may be misconfigured."
                        ))

            # Check for common security headers
            async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                response = await client.get(f"http://{host.addr}:{port.number}/")
                headers = response.headers
                
                security_headers = {
                    "Strict-Transport-Security": "HSTS header missing or misconfigured.",
                    "Content-Security-Policy": "CSP header missing or misconfigured.",
                    "X-Content-Type-Options": "X-Content-Type-Options header missing.",
                    "X-Frame-Options": "X-Frame-Options header missing.",
                    "Referrer-Policy": "Referrer-Policy header missing or misconfigured."
                }
                
                for header, description in security_headers.items():
                    if header not in headers or not headers[header]:
                        severity = Severity.LOW if "missing" in description else Severity.MEDIUM
                        findings.append(Finding(
                            host=host.addr,
                            port=port.number,
                            service="http",
                            code="HTTP-SECURITY-HEADER",
                            severity=severity,
                            title=f"{header} Header Issue",
                            description=description,
                            evidence=f"Missing or misconfigured header: {header}",
                            remediation=f"Implement appropriate security headers like {header} with recommended policies.",
                            exploitation_note="Missing or weak security headers can expose the application to various attacks like clickjacking, XSS, or insecure transport."
                        ))

        except Exception as e:
            console.log(f"Error during HTTPCheck for {host.addr}:{port.number}: {e}")
        
        return findings


class DBCheck(BaseCheck):
    async def check(self, host: Host, port: Port) -> List[Finding]:
        findings = []
        # This is a very basic check for exposed DB ports.
        # Actual vulnerability detection would require more complex interaction.
        if port.service in ["mysql", "postgresql", "mongodb", "redis"]: # Added more common DBs
            findings.append(Finding(
                host=host.addr,
                port=port.number,
                service=port.service,
                code="DB-EXPOSED",
                severity=Severity.HIGH, # High severity as DBs are critical assets
                title=f"{port.service.capitalize()} Database Exposed",
                description="Database service port is open to the network. This could lead to unauthorized access if not properly secured.",
                evidence=f"Service: {port.service}, Port: {port.number}",
                remediation="Firewall the database port to only allow access from trusted IPs. Implement strong authentication and encryption.",
                exploitation_note="Exposed database servers are prime targets for attackers seeking to steal or manipulate data."
            ))
        return findings


class Checker:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.kb = self._load_kb(data_dir)
        self.checks = [
            ExploitDBCheck(self.kb),
            HTTPCheck(self.kb),
            DBCheck(self.kb)
        ]

    def _load_kb(self, data_dir: str) -> Dict[str, Any]:
        kb = {}
        # Only risk_summary is loaded as banners.json and cves.json are now largely replaced by searchsploit
        for name in ['risk_summary']:
            path = os.path.join(data_dir, f"{name}.json")
            if os.path.exists(path) and os.path.getsize(path) > 0:
                try:
                    with open(path, 'r') as f:
                        kb[name] = json.load(f)
                except json.JSONDecodeError:
                    console.log(f"Warning: Could not decode JSON from {path}")
                    kb[name] = {}
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

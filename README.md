# Inj3ctScan.py
Inj3ctScan: A Python-based web vulnerability scanner. Tests for SQLi, XSS, Command Injection, and more with quick, fast, or slow modes. Features colorful CLI, form detection, and JSON reporting. Requires requests, beautifulsoup4, colorama. For educational use only—scan responsibly!

# Inj3ctScan - Web Vulnerability Scanner

![Inj3ctScan Banner](https://via.placeholder.com/800x200.png?text=Inj3ctScan) <!-- Replace with actual banner image if you have one -->

**Inj3ctScan** is a Python-based tool designed to scan websites for common security vulnerabilities. Built for educational purposes and security testing, it empowers users to identify weaknesses in web applications with ease. Whether you're a beginner learning about web security or a pentester prototyping scans, Inj3ctScan has you covered.

⚠️ **Disclaimer**: Use responsibly and only on targets you own or have explicit permission to test.

## Features
- **Multi-Vulnerability Testing**: Detects SQL Injection (SQLi), XSS, Command Injection, XXE, SSTI, LDAP Injection, JavaScript Injection, Host Header Injection, and CSRF.
- **Flexible Scan Modes**:
  - *Quick*: 10 payloads for rapid checks.
  - *Fast*: 50 payloads with form testing.
  - *Slow*: 100 payloads with deep header analysis.
- **User-Agent Spoofing**: Randomizes headers to mimic real browsers.
- **Form Detection**: Automatically tests GET/POST forms.
- **Colorful CLI**: Stylized output with `colorama`.
- **JSON Reporting**: Saves results for analysis.

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/[your-username]/inj3ctscan.git
   cd inj3ctscan
   pip3 install -r requirements.txt
   pip install requests beautifulsoup4 colorama
   python3 inj3ctscan.py



   Enter target URL: http://test.com
   Enter test number or name: 8 (XSS)
   Select scan mode: fast
   [*] Scanning http://test.com for xss vulnerabilities...
   [+] Scan completed in 2.34 seconds
   === Scan Results ===
   URL: http://test.com
   [!] XSS: VULNERABLE - Payload: <script>alert('xss')</script> (Type: GET)
      Evidence: <html><script>alert('xss')</script>...
   [+] Completed: Completed
   [+] Results saved to scan_results.json

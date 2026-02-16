#!/usr/bin/env python3
"""
IIS Bug Bounty Hunter v2.0 - Advanced IIS Vulnerability Scanner
Author: Security Researcher
Description: Comprehensive tool for finding vulnerabilities on Microsoft IIS servers
             Enhanced with SSL/TLS analysis, WebDAV scanning, request smuggling,
             CVE checks, source code disclosure, and more.
"""

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

print("""

███╗░░██╗██╗░░░██╗██╗░░░░░██╗░░░░░██████╗░░█████╗░░█████╗░  ░█████╗░██╗░░██╗
████╗░██║██║░░░██║██║░░░░░██║░░░░░╚════██╗██╔══██╗██╔══██╗  ██╔══██╗██║░██╔╝
██╔██╗██║██║░░░██║██║░░░░░██║░░░░░░░███╔═╝██║░░██║██║░░██║  ██║░░██║█████═╝░
██║╚████║██║░░░██║██║░░░░░██║░░░░░██╔══╝░░██║░░██║██║░░██║  ██║░░██║██╔═██╗░
██║░╚███║╚██████╔╝███████╗███████╗███████╗╚█████╔╝╚█████╔╝  ╚█████╔╝██║░╚██╗
╚═╝░░╚══╝░╚═════╝░╚══════╝╚══════╝░╚══════╝░╚════╝░░╚════╝░  ░╚════╝░╚═╝░░╚═╝

iis_bug_bounty_hunter_v2.py - - –>  NULL200OK 💀🔥
Created by NABEEL 🔥💀
IIS Bug Bounty Hunter v2.0 - Advanced IIS Vulnerability Scanner
Author: Nabeel
Description: Comprehensive tool for finding vulnerabilities on Microsoft IIS servers
             Enhanced with SSL/TLS analysis, WebDAV scanning, request smuggling,
             CVE checks, source code disclosure, and more.
Intelligent security scanner with context-aware detection,
validation-based verification, and minimal false positives.
""")

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# Global configuration
CONFIG = {
    'timeout': 10,
    'threads': 20,
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'output_dir': 'results',
    'wordlists': {
        'extensions': ['aspx', 'asp', 'ashx', 'asmx', 'wsdl', 'xml', 'zip', 'txt', 'dll', 'config', 'bak', 'old', 'backup', 'save', 'orig', 'swp', 'tmp'],
        'common_names': ['admin', 'backup', 'config', 'web', 'index', 'default', 'login', 'api', 'test', 'dev', 'staging', 'prod', 'uat', 'old', 'new', 'temp', 'data', 'files', 'uploads', 'images', 'css', 'js', 'scripts', 'includes', 'bin', 'app_data', 'app_code', 'app_start', 'content', 'views', 'controllers'],
        'iis_files': ['web.config', 'global.asax', 'packages.config', 'Web.Debug.config', 'Web.Release.config', 'connectionStrings.config', 'appSettings.config', 'machine.config', 'root.config', 'default.aspx', 'index.aspx', 'login.aspx', 'admin.aspx', 'error.aspx', '404.aspx', '500.aspx', 'iisstart.htm', 'welcome.png', 'aspnet_client', 'trace.axd', 'elmah.axd', 'crypt.axd', 'error.axd', 'crossdomain.xml', 'clientaccesspolicy.xml', 'robots.txt', 'sitemap.xml']
    }
}

# IIS Tilde Enumeration patterns
TILDE_PATTERNS = [
    '~1', '~2', '~3', '~4', '~5', '~6', '~7', '~8', '~9',
    '~10', '~11', '~12', '~13', '~14', '~15', '~16', '~17', '~18', '~19', '~20'
]


class Colors:
    """Color codes for terminal output"""
    HEADER = Fore.MAGENTA
    OKBLUE = Fore.BLUE
    OKCYAN = Fore.CYAN
    OKGREEN = Fore.GREEN
    WARNING = Fore.YELLOW
    FAIL = Fore.RED
    ENDC = Style.RESET_ALL
    BOLD = Style.BRIGHT


class Logger:
    """Logging utility with colors"""
    
    @staticmethod
    def info(msg):
        print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} {msg}")
    
    @staticmethod
    def success(msg):
        print(f"{Colors.OKGREEN}[SUCCESS]{Colors.ENDC} {msg}")
    
    @staticmethod
    def warning(msg):
        print(f"{Colors.WARNING}[WARNING]{Colors.ENDC} {msg}")
    
    @staticmethod
    def error(msg):
        print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} {msg}")
    
    @staticmethod
    def banner(msg):
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKCYAN}{msg.center(60)}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")


class IISBugBountyHunter:
    """Main class for IIS Bug Bounty Hunting"""
    
    def __init__(self, target, output_dir=None, threads=20, timeout=10, wordlist=None, rate_limit=0, modules=None):
        self.target = target.rstrip('/')
        self.parsed = urlparse(self.target)
        self.domain = self.parsed.netloc
        self.timeout = timeout
        self.threads = threads
        self.rate_limit = rate_limit  # seconds between requests
        self.modules = modules or ['all']  # which modules to run
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': CONFIG['user_agent']})
        self.session.verify = False
        
        # Load custom wordlist if provided
        if wordlist and os.path.isfile(wordlist):
            with open(wordlist, 'r') as f:
                custom_words = [line.strip() for line in f if line.strip()]
                CONFIG['wordlists']['common_names'].extend(custom_words)
            Logger.success(f"Loaded {len(custom_words)} custom words from {wordlist}")
        
        # Setup output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = output_dir or f"{CONFIG['output_dir']}/{self.domain}_{timestamp}"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Results storage
        self.results = {
            'target': self.target,
            'scan_date': datetime.now().isoformat(),
            'recon': {},
            'fingerprinting': {},
            'tilde_enum': [],
            'fuzzing': [],
            'vulnerabilities': [],
            'findings': [],
            'ssl_info': {},
            'webdav': []
        }
        
        Logger.info(f"Output directory: {self.output_dir}")
    
    def save_results(self):
        """Save results to JSON, TXT, and HTML files"""
        # JSON format
        json_file = os.path.join(self.output_dir, 'results.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        Logger.success(f"Results saved to JSON: {json_file}")
        
        # TXT format
        txt_file = os.path.join(self.output_dir, 'results.txt')
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(self._format_txt_results())
        Logger.success(f"Results saved to TXT: {txt_file}")
        
        # HTML format
        html_file = os.path.join(self.output_dir, 'report.html')
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(self._generate_html_report())
        Logger.success(f"Results saved to HTML: {html_file}")
    
    def _format_txt_results(self):
        """Format results as plain text"""
        lines = []
        lines.append("="*80)
        lines.append("IIS BUG BOUNTY HUNTER - SCAN RESULTS")
        lines.append("="*80)
        lines.append(f"Target: {self.results['target']}")
        lines.append(f"Scan Date: {self.results['scan_date']}")
        lines.append("="*80)
        
        # Recon section
        lines.append("\n[RECONNAISSANCE]")
        if self.results['recon']:
            for key, value in self.results['recon'].items():
                lines.append(f"  {key}: {value}")
        
        # SSL/TLS section
        lines.append("\n[SSL/TLS INFORMATION]")
        if self.results['ssl_info']:
            for key, value in self.results['ssl_info'].items():
                lines.append(f"  {key}: {value}")
        
        # Fingerprinting section
        lines.append("\n[IIS FINGERPRINTING]")
        if self.results['fingerprinting']:
            for key, value in self.results['fingerprinting'].items():
                lines.append(f"  {key}: {value}")
        
        # Tilde enumeration
        lines.append("\n[TILDE ENUMERATION FINDINGS]")
        for finding in self.results['tilde_enum']:
            lines.append(f"  [+] {finding['type']}: {finding['path']} ({finding['status']})")
        
        # Fuzzing results
        lines.append("\n[FUZZING RESULTS]")
        for result in self.results['fuzzing']:
            lines.append(f"  [+] {result['url']} - Status: {result['status']} - Size: {result.get('size', 'N/A')}")
        
        # WebDAV findings
        lines.append("\n[WEBDAV FINDINGS]")
        for item in self.results['webdav']:
            lines.append(f"  [+] {item}")
        
        # Vulnerabilities
        lines.append("\n[VULNERABILITIES FOUND]")
        for vuln in self.results['vulnerabilities']:
            lines.append(f"  [!] {vuln['severity']}: {vuln['title']}")
            lines.append(f"      URL: {vuln['url']}")
            lines.append(f"      Description: {vuln['description']}")
            lines.append(f"      Remediation: {vuln.get('remediation', 'N/A')}")
            lines.append("")
        
        # Additional findings
        lines.append("\n[ADDITIONAL FINDINGS]")
        for finding in self.results['findings']:
            lines.append(f"  [*] {finding['type']}: {finding.get('details', '')}")
        
        lines.append("="*80)
        lines.append("END OF REPORT")
        lines.append("="*80)
        
        return '\n'.join(lines)
    
    def _generate_html_report(self):
        """Generate HTML report"""
        css_styles = """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            line-height: 1.6;
            min-height: 100vh;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { 
            text-align: center; 
            padding: 40px 20px;
            background: linear-gradient(135deg, #0f3460 0%, #533483 100%);
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }
        header h1 { color: #fff; font-size: 2.5em; margin-bottom: 10px; }
        header p { color: #a0a0a0; }
        .scan-info { 
            background: rgba(255,255,255,0.05);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .section { 
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
        }
        .section h2 { 
            color: #e94560;
            border-bottom: 2px solid #e94560;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .finding { 
            background: rgba(233, 69, 96, 0.1);
            border-left: 4px solid #e94560;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        .success-finding { 
            background: rgba(0, 255, 136, 0.1);
            border-left: 4px solid #00ff88;
        }
        .warning-finding { 
            background: rgba(255, 193, 7, 0.1);
            border-left: 4px solid #ffc107;
        }
        .info-finding { 
            background: rgba(0, 123, 255, 0.1);
            border-left: 4px solid #007bff;
        }
        table { 
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td { 
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        th { 
            background: rgba(233, 69, 96, 0.3);
            color: #fff;
        }
        tr:hover { background: rgba(255,255,255,0.05); }
        .badge { 
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: black; }
        .badge-low { background: #28a745; color: white; }
        .badge-info { background: #17a2b8; color: white; }
        .stats { 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card { 
            background: linear-gradient(135deg, #0f3460 0%, #533483 100%);
            padding: 25px;
            border-radius: 15px;
            text-align: center;
        }
        .stat-card h3 { font-size: 2.5em; color: #e94560; }
        .stat-card p { color: #a0a0a0; }
        footer { 
            text-align: center;
            padding: 20px;
            color: #666;
            margin-top: 40px;
        }
        code { 
            background: rgba(0,0,0,0.3);
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
        pre { 
            background: rgba(0,0,0,0.3);
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            margin: 10px 0;
        }
        details {
            margin: 10px 0;
            padding: 10px;
            background: rgba(0,0,0,0.2);
            border-radius: 5px;
        }
        summary {
            cursor: pointer;
            font-weight: bold;
            color: #e94560;
        }
        """
        
        vuln_count = len(self.results['vulnerabilities'])
        tilde_count = len(self.results['tilde_enum'])
        fuzz_count = len(self.results['fuzzing'])
        finding_count = len(self.results['findings'])
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IIS Bug Bounty Hunter v2 - Report</title>
    <style>{css_styles}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1>IIS Bug Bounty Hunter v2</h1>
            <p>Advanced IIS Security Assessment Report</p>
        </header>
        
        <div class="scan-info">
            <h3>Scan Information</h3>
            <p><strong>Target:</strong> <code>{self.results['target']}</code></p>
            <p><strong>Scan Date:</strong> {self.results['scan_date']}</p>
            <p><strong>Domain:</strong> {self.domain}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>{vuln_count}</h3>
                <p>Vulnerabilities</p>
            </div>
            <div class="stat-card">
                <h3>{tilde_count}</h3>
                <p>Tilde Findings</p>
            </div>
            <div class="stat-card">
                <h3>{fuzz_count}</h3>
                <p>Fuzzing Hits</p>
            </div>
            <div class="stat-card">
                <h3>{finding_count}</h3>
                <p>Total Findings</p>
            </div>
        </div>
"""
        
        # Reconnaissance section
        html += """
        <div class="section">
            <h2>Reconnaissance</h2>
"""
        if self.results['recon']:
            html += "<table><tr><th>Property</th><th>Value</th></tr>"
            for key, value in self.results['recon'].items():
                html += f"<tr><td>{key}</td><td><code>{value}</code></td></tr>"
            html += "</table>"
        else:
            html += "<p>No reconnaissance data collected.</p>"
        html += "</div>"
        
        # SSL/TLS section
        html += """
        <div class="section">
            <h2>SSL/TLS Analysis</h2>
"""
        if self.results['ssl_info']:
            html += "<table><tr><th>Property</th><th>Value</th></tr>"
            for key, value in self.results['ssl_info'].items():
                html += f"<tr><td>{key}</td><td><code>{value}</code></td></tr>"
            html += "</table>"
        else:
            html += "<p>No SSL/TLS information (target may be HTTP).</p>"
        html += "</div>"
        
        # Fingerprinting section
        html += """
        <div class="section">
            <h2>IIS Fingerprinting</h2>
"""
        if self.results['fingerprinting']:
            html += "<table><tr><th>Indicator</th><th>Status</th></tr>"
            for key, value in self.results['fingerprinting'].items():
                status_class = "success-finding" if value else "info-finding"
                html += f'<tr class="{status_class}"><td>{key}</td><td>{"Detected" if value else "Not Found"}</td></tr>'
            html += "</table>"
        else:
            html += "<p>No fingerprinting data collected.</p>"
        html += "</div>"
        
        # Tilde enumeration section
        html += """
        <div class="section">
            <h2>Tilde Enumeration (8.3 Short Names)</h2>
"""
        if self.results['tilde_enum']:
            html += "<table><tr><th>Type</th><th>Path</th><th>Status</th><th>Notes</th></tr>"
            for finding in self.results['tilde_enum']:
                html += f"<tr><td>{finding['type']}</td><td><code>{finding['path']}</code></td><td>{finding['status']}</td><td>{finding.get('notes', '')}</td></tr>"
            html += "</table>"
        else:
            html += "<p>No tilde enumeration findings.</p>"
        html += "</div>"
        
        # WebDAV section
        html += """
        <div class="section">
            <h2>WebDAV Findings</h2>
"""
        if self.results['webdav']:
            html += "<ul>"
            for item in self.results['webdav']:
                html += f"<li>{item}</li>"
            html += "</ul>"
        else:
            html += "<p>No WebDAV findings.</p>"
        html += "</div>"
        
        # Fuzzing section
        html += """
        <div class="section">
            <h2>Fuzzing Results</h2>
"""
        if self.results['fuzzing']:
            html += "<table><tr><th>URL</th><th>Status</th><th>Size</th><th>Title</th></tr>"
            for result in self.results['fuzzing']:
                html += f"<tr><td><code>{result['url']}</code></td><td>{result['status']}</td><td>{result.get('size', 'N/A')}</td><td>{result.get('title', 'N/A')}</td></tr>"
            html += "</table>"
        else:
            html += "<p>No fuzzing results.</p>"
        html += "</div>"
        
        # Vulnerabilities section
        html += """
        <div class="section">
            <h2>Vulnerabilities</h2>
"""
        if self.results['vulnerabilities']:
            for vuln in self.results['vulnerabilities']:
                severity_class = f"badge-{vuln['severity'].lower()}"
                evidence_html = f'<p><strong>Evidence:</strong> <pre>{vuln.get("evidence", "")}</pre></p>' if vuln.get('evidence') else ''
                remediation_html = f'<p><strong>Remediation:</strong> {vuln.get("remediation", "N/A")}</p>'
                html += f"""
                <div class="finding">
                    <span class="badge {severity_class}">{vuln['severity']}</span>
                    <h4>{vuln['title']}</h4>
                    <p><strong>URL:</strong> <code>{vuln['url']}</code></p>
                    <p><strong>Description:</strong> {vuln['description']}</p>
                    {evidence_html}
                    {remediation_html}
                </div>
                """
        else:
            html += "<p>No vulnerabilities found.</p>"
        html += "</div>"
        
        # Additional findings
        if self.results['findings']:
            html += """
            <div class="section">
                <h2>Additional Findings</h2>
            """
            for finding in self.results['findings']:
                html += f"<details><summary>{finding['type']}</summary><p>{finding.get('details', '')}</p></details>"
            html += "</div>"
        
        # Footer
        html += f"""
        <footer>
            <p>Generated by IIS Bug Bounty Hunter v2 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>
"""
        return html

    # ==================== PHASE 1: RECONNAISSANCE ====================
    
    def perform_recon(self):
        """Perform basic reconnaissance on the target"""
        Logger.banner("PHASE 1: RECONNAISSANCE")
        
        try:
            # DNS resolution
            Logger.info("Resolving DNS...")
            try:
                ip = socket.gethostbyname(self.domain)
                self.results['recon']['ip_address'] = ip
                Logger.success(f"IP Address: {ip}")
            except socket.gaierror:
                Logger.warning("Could not resolve DNS")
            
            # Basic HTTP request
            Logger.info("Probing target...")
            response = self.session.get(self.target, timeout=self.timeout)
            
            self.results['recon']['status_code'] = response.status_code
            self.results['recon']['server'] = response.headers.get('Server', 'Unknown')
            self.results['recon']['content_type'] = response.headers.get('Content-Type', 'Unknown')
            self.results['recon']['content_length'] = len(response.content)
            
            Logger.info(f"Status Code: {response.status_code}")
            Logger.info(f"Server: {response.headers.get('Server', 'Unknown')}")
            
        except Exception as e:
            Logger.error(f"Recon error: {str(e)}")
    
    # ==================== SSL/TLS ANALYSIS ====================
    
    def check_ssl_tls(self):
        """Check SSL/TLS configuration if HTTPS"""
        if self.parsed.scheme != 'https':
            Logger.info("Target is HTTP, skipping SSL/TLS analysis")
            return
        
        Logger.banner("SSL/TLS ANALYSIS")
        host = self.parsed.hostname
        port = self.parsed.port or 443
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    cipher = ssock.cipher()
                    
                    self.results['ssl_info']['tls_version'] = version
                    self.results['ssl_info']['cipher'] = cipher[0] if cipher else 'Unknown'
                    
                    # Check for weak protocols (attempt to connect with SSLv3, TLSv1.0, TLSv1.1)
                    weak_protocols = []
                    for proto, name in [(ssl.PROTOCOL_SSLv23, 'SSLv3'), (ssl.PROTOCOL_TLSv1, 'TLSv1.0'), (ssl.PROTOCOL_TLSv1_1, 'TLSv1.1')]:
                        try:
                            context_weak = ssl.SSLContext(proto)
                            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                                with context_weak.wrap_socket(sock, server_hostname=host) as ssock_weak:
                                    weak_protocols.append(name)
                        except:
                            pass
                    
                    if weak_protocols:
                        self.results['vulnerabilities'].append({
                            'title': 'Weak SSL/TLS Protocols Supported',
                            'severity': 'Medium',
                            'url': self.target,
                            'description': f'The server supports outdated protocols: {", ".join(weak_protocols)}',
                            'remediation': 'Disable SSLv3, TLSv1.0, and TLSv1.1. Enable TLSv1.2 and TLSv1.3 only.'
                        })
                        Logger.warning(f"Weak protocols: {', '.join(weak_protocols)}")
                    
                    # Check certificate expiration
                    if cert:
                        from datetime import datetime
                        exp_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_left = (exp_date - datetime.now()).days
                        self.results['ssl_info']['cert_expires'] = exp_date.strftime('%Y-%m-%d')
                        if days_left < 30:
                            self.results['vulnerabilities'].append({
                                'title': 'SSL Certificate Expiring Soon',
                                'severity': 'Low',
                                'url': self.target,
                                'description': f'Certificate expires in {days_left} days on {exp_date.strftime("%Y-%m-%d")}',
                                'remediation': 'Renew the SSL certificate before expiration.'
                            })
                            Logger.warning(f"Certificate expires in {days_left} days")
                    
                    Logger.success(f"TLS version: {version}, Cipher: {cipher[0] if cipher else 'Unknown'}")
                    
        except Exception as e:
            Logger.error(f"SSL/TLS analysis error: {str(e)}")
    
    # ==================== PHASE 2: IIS FINGERPRINTING ====================
    
    def fingerprint_iis(self):
        """Fingerprint IIS server and detect technologies"""
        Logger.banner("PHASE 2: IIS FINGERPRINTING")
        
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            headers = response.headers
            content = response.text
            
            # Check for IIS indicators
            indicators = {
                'iis_detected': False,
                'asp_net_detected': False,
                'aspx_detected': False,
                'viewstate_detected': False,
                'iis_version': None,
                'asp_net_version': None,
                'mvc_detected': False,
                'webdav_enabled': False
            }
            
            # Server header
            server = headers.get('Server', '')
            if 'Microsoft-IIS' in server:
                indicators['iis_detected'] = True
                match = re.search(r'Microsoft-IIS/(\d+\.\d+)', server)
                if match:
                    indicators['iis_version'] = match.group(1)
                Logger.success(f"IIS Detected: {server}")
            elif 'IIS' in server:
                indicators['iis_detected'] = True
                Logger.success(f"IIS Detected (version unknown): {server}")
            
            # X-Powered-By header
            x_powered = headers.get('X-Powered-By', '')
            if 'ASP.NET' in x_powered:
                indicators['asp_net_detected'] = True
                Logger.success(f"ASP.NET Detected: {x_powered}")
            
            # X-AspNet-Version header
            asp_version = headers.get('X-AspNet-Version', '')
            if asp_version:
                indicators['asp_net_version'] = asp_version
                indicators['asp_net_detected'] = True
                Logger.success(f"ASP.NET Version: {asp_version}")
            
            # X-AspNetMvc-Version header
            mvc_version = headers.get('X-AspNetMvc-Version', '')
            if mvc_version:
                indicators['mvc_detected'] = True
                Logger.success(f"ASP.NET MVC Version: {mvc_version}")
            
            # Check for ViewState
            if '__VIEWSTATE' in content or 'name="_VIEWSTATE"' in content:
                indicators['viewstate_detected'] = True
                Logger.success("ViewState detected in page content")
            
            # Check for ASPX extensions in content
            if '.aspx' in content or '.asp' in content:
                indicators['aspx_detected'] = True
                Logger.success("ASPX/ASP references found")
            
            # Check for ASP.NET session cookie
            cookies = response.cookies
            for cookie in cookies:
                if 'ASP.NET_SessionId' in cookie.name or 'ASPSESSION' in cookie.name:
                    indicators['asp_net_detected'] = True
                    Logger.success(f"ASP.NET Session Cookie: {cookie.name}")
            
            # Check for WebDAV via OPTIONS
            try:
                options_resp = self.session.options(self.target, timeout=self.timeout)
                if 'PROPFIND' in options_resp.headers.get('Allow', ''):
                    indicators['webdav_enabled'] = True
                    Logger.success("WebDAV appears to be enabled (PROPFIND allowed)")
            except:
                pass
            
            self.results['fingerprinting'] = indicators
            
            # Determine if target is IIS
            if indicators['iis_detected'] or indicators['asp_net_detected']:
                Logger.success("Target appears to be running Microsoft IIS/ASP.NET")
            else:
                Logger.warning("Target may not be running IIS/ASP.NET")
                
        except Exception as e:
            Logger.error(f"Fingerprinting error: {str(e)}")
    
    # ==================== PHASE 3: TILDE ENUMERATION ====================
    
    def check_tilde_vulnerability(self):
        """Check if target is vulnerable to IIS tilde enumeration"""
        Logger.banner("PHASE 3: TILDE ENUMERATION CHECK")
        
        try:
            # Test 1: Request non-existent file (should return 404)
            test_404 = self.session.get(
                f"{self.target}/nonexistent12345.txt",
                timeout=self.timeout
            )
            
            # Test 2: Request with tilde pattern
            test_tilde = self.session.get(
                f"{self.target}/ASPNET~1",
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Test 3: Request another tilde pattern
            test_tilde2 = self.session.get(
                f"{self.target}/ADMIN~1",
                timeout=self.timeout,
                allow_redirects=False
            )
            
            Logger.info(f"404 Test Status: {test_404.status_code}")
            Logger.info(f"Tilde Test 1 Status: {test_tilde.status_code}")
            Logger.info(f"Tilde Test 2 Status: {test_tilde2.status_code}")
            
            # Analyze responses
            vulnerable = False
            
            # If tilde requests return different status codes than 404, it might be vulnerable
            if test_tilde.status_code != test_404.status_code:
                Logger.success("Potential tilde enumeration vulnerability detected!")
                vulnerable = True
            elif test_tilde.status_code in [200, 301, 302, 403]:
                Logger.success("Tilde pattern returned interesting status code")
                vulnerable = True
            
            if vulnerable:
                self.results['vulnerabilities'].append({
                    'title': 'IIS Tilde Enumeration (8.3 Short Name Disclosure)',
                    'severity': 'High',
                    'url': self.target,
                    'description': 'The server may be vulnerable to IIS 8.3 short name enumeration, allowing attackers to discover hidden files and directories.',
                    'evidence': f'404 response: {test_404.status_code}, Tilde response: {test_tilde.status_code}',
                    'remediation': 'Disable 8.3 name creation on NTFS volumes or apply Microsoft patch.'
                })
            
            return vulnerable
            
        except Exception as e:
            Logger.error(f"Tilde check error: {str(e)}")
            return False
    
    def enumerate_tilde_names(self):
        """Enumerate 8.3 short names using tilde patterns"""
        Logger.banner("ENUMERATING 8.3 SHORT NAMES")
        
        prefixes = CONFIG['wordlists']['common_names']
        extensions = CONFIG['wordlists']['extensions']
        
        found_items = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            # Test directory patterns
            for prefix in prefixes:
                for pattern in TILDE_PATTERNS[:5]:  # Test first 5 patterns
                    url = f"{self.target}/{prefix.upper()}{pattern}"
                    futures.append(executor.submit(self._test_tilde_url, url, 'directory'))
            
            # Test file patterns
            for prefix in prefixes:
                for ext in extensions:
                    for pattern in TILDE_PATTERNS[:3]:
                        url = f"{self.target}/{prefix.upper()}{pattern}.{ext.upper()}"
                        futures.append(executor.submit(self._test_tilde_url, url, 'file'))
            
            # Collect results
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_items.append(result)
                    self.results['tilde_enum'].append(result)
                    Logger.success(f"Found: {result['path']} ({result['status']})")
        
        Logger.info(f"Found {len(found_items)} potential short names")
        return found_items
    
    def _test_tilde_url(self, url, item_type):
        """Test a single tilde URL"""
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            
            # Interesting status codes
            if response.status_code in [200, 301, 302, 403, 401]:
                return {
                    'type': item_type,
                    'path': urlparse(url).path,
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content),
                    'notes': 'Potential short name exists'
                }
        except:
            pass
        return None
    
    # ==================== PHASE 4: ADVANCED FUZZING ====================
    
    def fuzz_directories(self):
        """Fuzz for common IIS directories"""
        Logger.banner("PHASE 4: DIRECTORY FUZZING")
        
        directories = CONFIG['wordlists']['common_names'] + [
            'aspnet_client', 'bin', 'App_Data', 'App_Code', 'App_Start', 'Content', 'Scripts', 'Views', 'Controllers',
            'backup', 'bak', 'old', 'test', 'dev', 'staging', 'prod', 'uploads', 'files', 'documents', 'images', 'css', 'js',
            'web', 'www', 'wwwroot', 'inetpub', 'iisstart', 'default', 'aspnet', 'aspx', 'asp', 'cgi-bin', 'includes', 'logs',
            'trace.axd', 'elmah.axd', 'error', 'errors', 'admin', 'api'
        ]
        
        found_dirs = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_directory, d): d for d in directories}
            
            for future in as_completed(futures):
                if self.rate_limit:
                    time.sleep(self.rate_limit)
                result = future.result()
                if result:
                    found_dirs.append(result)
                    self.results['fuzzing'].append(result)
                    Logger.success(f"Directory found: {result['url']} ({result['status']})")
        
        Logger.info(f"Found {len(found_dirs)} directories")
        return found_dirs
    
    def _test_directory(self, directory):
        """Test a single directory"""
        try:
            url = f"{self.target}/{directory}"
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            if response.status_code in [200, 301, 302, 403, 401, 407]:
                # Get page title
                title = "N/A"
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title_tag = soup.find('title')
                    if title_tag:
                        title = title_tag.string[:50] if title_tag.string else "N/A"
                except:
                    pass
                
                return {
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content),
                    'title': title,
                    'type': 'directory'
                }
        except:
            pass
        return None
    
    def fuzz_files(self):
        """Fuzz for sensitive IIS files"""
        Logger.banner("FILE FUZZING")
        
        files = []
        
        # Generate file list
        for name in CONFIG['wordlists']['common_names']:
            for ext in CONFIG['wordlists']['extensions']:
                files.append(f"{name}.{ext}")
        
        # Add specific IIS files
        files.extend(CONFIG['wordlists']['iis_files'])
        
        found_files = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_file, f): f for f in files}
            
            for future in as_completed(futures):
                if self.rate_limit:
                    time.sleep(self.rate_limit)
                result = future.result()
                if result:
                    found_files.append(result)
                    self.results['fuzzing'].append(result)
                    Logger.success(f"File found: {result['url']} ({result['status']})")
                    
                    # Check for sensitive files
                    self._check_sensitive_file(result)
        
        Logger.info(f"Found {len(found_files)} files")
        return found_files
    
    def _test_file(self, filename):
        """Test a single file"""
        try:
            url = f"{self.target}/{filename}"
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            if response.status_code in [200, 301, 302, 401, 403]:
                return {
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content),
                    'type': 'file'
                }
        except:
            pass
        return None
    
    def _check_sensitive_file(self, result):
        """Check if file is sensitive and add vulnerability"""
        url = result['url'].lower()
        
        sensitive_patterns = {
            'web.config': ('web.config Exposure', 'Critical', 'web.config file may contain sensitive configuration including connection strings, credentials, and application settings.'),
            'connectionstrings': ('Connection Strings Exposed', 'Critical', 'Database connection strings with credentials may be exposed.'),
            'global.asax': ('Global.asax Exposed', 'High', 'Application-level events and configuration may be exposed.'),
            'trace.axd': ('Trace.axd Enabled', 'Critical', 'ASP.NET trace viewer is enabled, may expose sensitive application data.'),
            'elmah.axd': ('ELMAH Error Log Exposed', 'Critical', 'Error logging module is exposed, may contain sensitive error details.'),
            '.bak': ('Backup File Exposed', 'High', 'Backup file may contain source code or sensitive data.'),
            '.zip': ('Archive File Exposed', 'High', 'Archive file may contain source code or sensitive data.'),
            '.config': ('Config File Exposed', 'High', 'Configuration file may contain sensitive settings.'),
            '.old': ('Old File Exposed', 'Medium', 'Old/backup file may contain sensitive information.'),
            '.save': ('Backup File Exposed', 'Medium', 'Backup file may contain sensitive information.'),
            '.orig': ('Original File Exposed', 'Medium', 'Original file may contain sensitive information.'),
        }
        
        for pattern, (title, severity, description) in sensitive_patterns.items():
            if pattern in url:
                self.results['vulnerabilities'].append({
                    'title': title,
                    'severity': severity,
                    'url': result['url'],
                    'description': description,
                    'evidence': f"Status: {result['status']}, Size: {result['size']} bytes",
                    'remediation': 'Remove the file from public access or restrict permissions.'
                })
                Logger.warning(f"SENSITIVE: {title} at {result['url']}")
    
    def fuzz_backup_files(self):
        """Fuzz for backup and old versions of files"""
        Logger.banner("BACKUP FILE FUZZING")
        
        backup_extensions = ['.bak', '.old', '.orig', '.save', '.swp', '.tmp', '.copy', '.backup', '~', '.back', '.bk', '.sav', '.old2']
        backup_suffixes = ['_backup', '_old', '_copy', '_bak', '.backup', '.old', '_save', '_orig', '-backup', '-old', '-copy']
        
        targets = ['web.config', 'global.asax', 'index.aspx', 'default.aspx', 'admin.aspx', 'login.aspx']
        
        backup_files = []
        
        for target in targets:
            # Test backup extensions
            for ext in backup_extensions:
                result = self._test_file(f"{target}{ext}")
                if result:
                    backup_files.append(result)
                    self.results['fuzzing'].append(result)
                    self.results['vulnerabilities'].append({
                        'title': 'Backup File Exposure',
                        'severity': 'High',
                        'url': result['url'],
                        'description': f'Backup file {target}{ext} was found, may contain sensitive source code or configuration.',
                        'evidence': f"Size: {result['size']} bytes",
                        'remediation': 'Remove backup files from the web root.'
                    })
                    Logger.success(f"Backup found: {result['url']}")
            
            # Test backup suffixes
            for suffix in backup_suffixes:
                name, ext = os.path.splitext(target)
                backup_name = f"{name}{suffix}{ext}"
                result = self._test_file(backup_name)
                if result:
                    backup_files.append(result)
                    self.results['fuzzing'].append(result)
                    self.results['vulnerabilities'].append({
                        'title': 'Backup File Exposure',
                        'severity': 'High',
                        'url': result['url'],
                        'description': f'Backup file {backup_name} was found.',
                        'evidence': f"Size: {result['size']} bytes",
                        'remediation': 'Remove backup files from the web root.'
                    })
                    Logger.success(f"Backup found: {result['url']}")
        
        return backup_files
    
    # ==================== SOURCE CODE DISCLOSURE CHECKS ====================
    
    def check_source_code_disclosure(self):
        """Check for source code disclosure vulnerabilities"""
        Logger.banner("SOURCE CODE DISCLOSURE CHECKS")
        
        # Techniques: ::$DATA, trailing dot, %20, etc.
        tests = [
            ('/$FILE_NAME::$DATA', 'NTFS Alternate Data Stream'),
            ('/.aspx.', 'Trailing dot'),
            ('/.aspx%20', 'Space at end'),
            ('/.aspx;', 'Semicolon'),
            ('/.aspx.aspx', 'Double extension'),
        ]
        
        for ext in ['.asp', '.aspx', '.ashx', '.asmx']:
            for suffix, desc in tests:
                url = f"{self.target}/index{ext}{suffix}"
                try:
                    response = self.session.get(url, timeout=self.timeout)
                    if response.status_code == 200 and len(response.text) > 0:
                        # Check if it looks like source code
                        if '<%' in response.text or 'Page Language=' in response.text:
                            self.results['vulnerabilities'].append({
                                'title': 'Source Code Disclosure',
                                'severity': 'Critical',
                                'url': url,
                                'description': f'Source code may be disclosed via {desc} technique.',
                                'evidence': f'Status: {response.status_code}, Content snippet: {response.text[:200]}',
                                'remediation': 'Apply appropriate IIS request filtering and ensure proper handler mappings.'
                            })
                            Logger.success(f"Possible source disclosure: {url}")
                except:
                    pass
    
    # ==================== PATH TRAVERSAL CHECKS ====================
    
    def check_path_traversal(self):
        """Check for path traversal vulnerabilities"""
        Logger.banner("PATH TRAVERSAL CHECKS")
        
        payloads = [
            '../../../../windows/win.ini',
            '../../../../etc/passwd',
            '....//....//....//windows/win.ini',
            '..\\..\\..\\windows\\win.ini',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows/win.ini',
            '..;/windows/win.ini',
        ]
        
        base_url = self.target + '/'  # Ensure trailing slash for join
        
        for payload in payloads:
            url = urljoin(base_url, payload)
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    # Look for indicators of successful traversal
                    if '[extensions]' in response.text or 'root:' in response.text or '[fonts]' in response.text:
                        self.results['vulnerabilities'].append({
                            'title': 'Path Traversal',
                            'severity': 'Critical',
                            'url': url,
                            'description': f'Path traversal vulnerability detected using payload: {payload}',
                            'evidence': f'Response contains: {response.text[:200]}',
                            'remediation': 'Implement proper input validation and use safe file access methods.'
                        })
                        Logger.success(f"Path traversal found: {url}")
            except:
                pass
    
    # ==================== WEBDAV SCANNING ====================
    
    def scan_webdav(self):
        """Check for WebDAV vulnerabilities"""
        Logger.banner("WEBDAV SCANNING")
        
        # Check if WebDAV is enabled via OPTIONS
        try:
            options_resp = self.session.options(self.target, timeout=self.timeout)
            allow_header = options_resp.headers.get('Allow', '')
            if 'PROPFIND' in allow_header or 'PROPPATCH' in allow_header:
                self.results['webdav'].append(f"WebDAV methods allowed: {allow_header}")
                Logger.success("WebDAV methods detected")
                
                # Check for dangerous methods
                dangerous = ['PUT', 'DELETE', 'MOVE', 'COPY']
                found = [m for m in dangerous if m in allow_header.upper()]
                if found:
                    self.results['vulnerabilities'].append({
                        'title': 'Dangerous WebDAV Methods Enabled',
                        'severity': 'High',
                        'url': self.target,
                        'description': f'The following WebDAV methods are enabled: {", ".join(found)}',
                        'remediation': 'Disable unnecessary WebDAV methods or disable WebDAV entirely.'
                    })
                    Logger.warning(f"Dangerous WebDAV methods: {found}")
                
                # Test PROPFIND
                propfind_data = """<?xml version="1.0"?>
<propfind xmlns="DAV:">
  <prop>
    <displayname/>
    <getcontentlength/>
    <getcontenttype/>
  </prop>
</propfind>"""
                headers = {'Content-Type': 'application/xml'}
                pf_resp = self.session.request('PROPFIND', self.target, data=propfind_data, headers=headers, timeout=self.timeout)
                if pf_resp.status_code in [207, 200]:
                    self.results['webdav'].append("PROPFIND successful - WebDAV is active")
                    Logger.success("PROPFIND succeeded")
                    
                    # Check for CVE-2017-7269 (WebDAV RCE in IIS 6.0)
                    if self.results['fingerprinting'].get('iis_version') == '6.0':
                        self.results['vulnerabilities'].append({
                            'title': 'CVE-2017-7269 - IIS 6.0 WebDAV RCE',
                            'severity': 'Critical',
                            'url': self.target,
                            'description': 'IIS 6.0 with WebDAV enabled is vulnerable to remote code execution via a crafted PROPFIND request.',
                            'remediation': 'Upgrade IIS or disable WebDAV.'
                        })
                        Logger.warning("IIS 6.0 WebDAV - likely vulnerable to CVE-2017-7269")
        except Exception as e:
            Logger.error(f"WebDAV scan error: {str(e)}")
    
    # ==================== HTTP REQUEST SMUGGLING ====================
    
    def check_request_smuggling(self):
        """Basic check for HTTP request smuggling (CL.TE / TE.CL)"""
        Logger.banner("HTTP REQUEST SMUGGLING CHECKS")
        
        # Test CL.TE
        cl_te_payload = """POST / HTTP/1.1
Host: {host}
Content-Length: 4
Transfer-Encoding: chunked

1
Z
Q""".replace("\n", "\r\n")
        
        # Test TE.CL
        te_cl_payload = """POST / HTTP/1.1
Host: {host}
Content-Length: 6
Transfer-Encoding: chunked

0

X""".replace("\n", "\r\n")
        
        host = self.parsed.netloc
        port = self.parsed.port or (443 if self.parsed.scheme == 'https' else 80)
        
        try:
            # CL.TE test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.parsed.scheme == 'https':
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.parsed.hostname)
            sock.connect((self.parsed.hostname, port))
            sock.send(cl_te_payload.format(host=host).encode())
            time.sleep(1)
            response = sock.recv(4096).decode(errors='ignore')
            sock.close()
            
            if 'Z' in response:  # Smuggling may cause the next request to be appended
                self.results['vulnerabilities'].append({
                    'title': 'HTTP Request Smuggling (CL.TE)',
                    'severity': 'High',
                    'url': self.target,
                    'description': 'Server may be vulnerable to CL.TE request smuggling.',
                    'remediation': 'Apply vendor patches and ensure consistent handling of Content-Length and Transfer-Encoding.'
                })
                Logger.success("Potential CL.TE smuggling detected")
            
            # TE.CL test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.parsed.scheme == 'https':
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.parsed.hostname)
            sock.connect((self.parsed.hostname, port))
            sock.send(te_cl_payload.format(host=host).encode())
            time.sleep(1)
            response = sock.recv(4096).decode(errors='ignore')
            sock.close()
            
            if 'X' in response:
                self.results['vulnerabilities'].append({
                    'title': 'HTTP Request Smuggling (TE.CL)',
                    'severity': 'High',
                    'url': self.target,
                    'description': 'Server may be vulnerable to TE.CL request smuggling.',
                    'remediation': 'Apply vendor patches and ensure consistent handling of Content-Length and Transfer-Encoding.'
                })
                Logger.success("Potential TE.CL smuggling detected")
                
        except Exception as e:
            Logger.error(f"Request smuggling check error: {str(e)}")
    
    # ==================== CVE CHECKS ====================
    
    def check_cve_2021_31166(self):
        """Check for CVE-2021-31166 (HTTP Protocol Stack Remote Code Execution)"""
        try:
            headers = {
                'Accept-Encoding': 'identity,*;q=0',
                'Range': 'bytes=0-18446744073709551615'
            }
            
            response = self.session.get(
                self.target,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 416:  # Range Not Satisfiable
                Logger.info("Target may be vulnerable to CVE-2021-31166 (requires further testing)")
                self.results['findings'].append({
                    'type': 'Potential CVE-2021-31166',
                    'details': 'HTTP Range header handling detected - may be vulnerable to RCE. Further testing required.'
                })
                
        except Exception as e:
            Logger.error(f"CVE-2021-31166 check error: {str(e)}")
    
    def check_cve_2015_1635(self):
        """Check for CVE-2015-1635 (IIS Schannel) - MS15-034"""
        try:
            headers = {
                'Range': 'bytes=0-18446744073709551615'
            }
            response = self.session.get(self.target, headers=headers, timeout=self.timeout)
            if response.status_code == 416:
                self.results['vulnerabilities'].append({
                    'title': 'CVE-2015-1635 (MS15-034) - HTTP.sys RCE',
                    'severity': 'Critical',
                    'url': self.target,
                    'description': 'IIS with HTTP.sys is vulnerable to remote code execution via a crafted Range header.',
                    'evidence': f'Server returned 416 Range Not Satisfiable with oversized range.',
                    'remediation': 'Apply Microsoft security update MS15-034.'
                })
                Logger.warning("Potential MS15-034 vulnerability detected")
        except Exception as e:
            Logger.error(f"CVE-2015-1635 check error: {str(e)}")
    
    # ==================== ASP.NET DEBUGGING ====================
    
    def check_aspnet_debugging(self):
        """Check for ASP.NET debugging enabled"""
        debug_paths = ['/trace.axd', '/elmah.axd', '/debug.axd', '/WebResource.axd?d=debug']
        
        for path in debug_paths:
            url = urljoin(self.target, path)
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    if 'ASP.NET Trace' in response.text or 'ELMAH' in response.text:
                        self.results['vulnerabilities'].append({
                            'title': 'ASP.NET Debugging Interface Exposed',
                            'severity': 'High',
                            'url': url,
                            'description': f'{path} is accessible and may leak sensitive application information.',
                            'remediation': 'Disable debugging in production and restrict access to these pages.'
                        })
                        Logger.warning(f"Debug interface exposed: {url}")
            except:
                pass
    
    # ==================== TELERIK UI VULNERABILITIES ====================
    
    def check_telerik_ui(self):
        """Check for Telerik UI ASP.NET AJAX vulnerabilities"""
        telerik_paths = ['/Telerik.Web.UI.WebResource.axd', '/Telerik.Web.UI.DialogHandler.axd']
        
        for path in telerik_paths:
            url = urljoin(self.target, path)
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    # Look for Telerik version disclosure
                    if 'RadScriptManager' in response.text or 'Telerik' in response.text:
                        self.results['vulnerabilities'].append({
                            'title': 'Telerik UI ASP.NET AJAX Exposed',
                            'severity': 'High',
                            'url': url,
                            'description': 'Telerik UI handler exposed. May be vulnerable to known deserialization attacks (CVE-2017-11317, CVE-2019-18935).',
                            'remediation': 'Upgrade Telerik UI to latest version and apply security patches.'
                        })
                        Logger.warning(f"Telerik handler exposed: {url}")
            except:
                pass
    
    # ==================== HTTP METHOD FUZZING (PUT) ====================
    
    def test_http_put(self):
        """Test if PUT method is allowed and can upload files"""
        Logger.banner("HTTP PUT METHOD TEST")
        
        test_file_name = f"iis_test_{int(time.time())}.txt"
        test_content = "IIS Bug Bounty Hunter Test"
        url = urljoin(self.target, test_file_name)
        
        try:
            # First check OPTIONS
            options_resp = self.session.options(self.target, timeout=self.timeout)
            if 'PUT' in options_resp.headers.get('Allow', ''):
                # Attempt to PUT
                put_resp = self.session.put(url, data=test_content, timeout=self.timeout)
                if put_resp.status_code in [200, 201, 204]:
                    self.results['vulnerabilities'].append({
                        'title': 'HTTP PUT Method Enabled',
                        'severity': 'High',
                        'url': self.target,
                        'description': f'PUT method is allowed. Successfully uploaded {test_file_name}.',
                        'evidence': f'PUT returned status {put_resp.status_code}',
                        'remediation': 'Disable PUT method unless absolutely required and properly secured.'
                    })
                    Logger.success(f"PUT succeeded - uploaded {test_file_name}")
                    
                    # Try to DELETE
                    del_resp = self.session.delete(url, timeout=self.timeout)
                    if del_resp.status_code in [200, 202, 204]:
                        self.results['vulnerabilities'].append({
                            'title': 'HTTP DELETE Method Enabled',
                            'severity': 'High',
                            'url': self.target,
                            'description': 'DELETE method is allowed, can delete files.',
                            'remediation': 'Disable DELETE method unless required.'
                        })
                        Logger.success("DELETE also allowed")
                    else:
                        Logger.info("DELETE not allowed (or file not found)")
                else:
                    Logger.info(f"PUT not allowed (status {put_resp.status_code})")
            else:
                Logger.info("PUT method not advertised in OPTIONS")
        except Exception as e:
            Logger.error(f"PUT test error: {str(e)}")
    
    # ==================== PHASE 5: VULNERABILITY CHECKS ====================
    
    def check_common_vulnerabilities(self):
        """Run all vulnerability checks"""
        Logger.banner("PHASE 5: VULNERABILITY CHECKS")
        
        checks = [
            self._check_misconfigured_headers,
            self._check_http_methods,
            self._check_directory_listing,
            self._check_iis_version_disclosure,
            self._check_viewstate_deserialization,
            self.check_cve_2021_31166,
            self.check_cve_2015_1635,
            self.check_aspnet_debugging,
            self.check_telerik_ui,
            self.check_source_code_disclosure,
            self.check_path_traversal,
            self.scan_webdav,
            self.check_request_smuggling,
            self.test_http_put,
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                Logger.error(f"Check failed: {str(e)}")
    
    def _check_misconfigured_headers(self):
        """Check for security headers"""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            headers = response.headers
            
            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'Referrer-Policy',
                'Permissions-Policy'
            ]
            
            missing = [h for h in security_headers if h not in headers]
            
            if missing:
                self.results['findings'].append({
                    'type': 'Missing Security Headers',
                    'details': f"Missing: {', '.join(missing)}"
                })
                Logger.warning(f"Missing security headers: {', '.join(missing)}")
                
        except Exception as e:
            Logger.error(f"Header check error: {str(e)}")
    
    def _check_http_methods(self):
        """Check for dangerous HTTP methods"""
        try:
            response = self.session.options(self.target, timeout=self.timeout)
            allow_header = response.headers.get('Allow', '')
            
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PROPFIND', 'MOVE', 'COPY']
            found_dangerous = [m for m in dangerous_methods if m in allow_header.upper()]
            
            if found_dangerous:
                self.results['vulnerabilities'].append({
                    'title': 'Dangerous HTTP Methods Enabled',
                    'severity': 'Medium',
                    'url': self.target,
                    'description': f'The following dangerous HTTP methods are enabled: {", ".join(found_dangerous)}',
                    'evidence': f'Allow header: {allow_header}',
                    'remediation': 'Disable unnecessary HTTP methods.'
                })
                Logger.warning(f"Dangerous HTTP methods: {', '.join(found_dangerous)}")
                
        except Exception as e:
            Logger.error(f"HTTP methods check error: {str(e)}")
    
    def _check_directory_listing(self):
        """Check for directory listing enabled"""
        try:
            test_dirs = ['/images/', '/css/', '/js/', '/uploads/', '/files/', '/assets/']
            
            for dir_path in test_dirs:
                url = f"{self.target}{dir_path}"
                response = self.session.get(url, timeout=self.timeout)
                
                if 'Index of' in response.text or 'Directory Listing' in response.text:
                    self.results['vulnerabilities'].append({
                        'title': 'Directory Listing Enabled',
                        'severity': 'Medium',
                        'url': url,
                        'description': 'Directory listing is enabled, which may expose sensitive files.',
                        'evidence': 'Directory index page detected',
                        'remediation': 'Disable directory browsing in IIS.'
                    })
                    Logger.warning(f"Directory listing enabled: {url}")
                    break
                    
        except Exception as e:
            Logger.error(f"Directory listing check error: {str(e)}")
    
    def _check_iis_version_disclosure(self):
        """Check for IIS version disclosure"""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            server = response.headers.get('Server', '')
            
            if 'Microsoft-IIS' in server:
                self.results['findings'].append({
                    'type': 'IIS Version Disclosure',
                    'details': server
                })
                Logger.info(f"IIS version disclosed: {server}")
                
        except Exception as e:
            Logger.error(f"Version disclosure check error: {str(e)}")
    
    def _check_viewstate_deserialization(self):
        """Check for potential ViewState deserialization issues"""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            
            if '__VIEWSTATE' in response.text:
                # Extract ViewState value
                match = re.search(r'id="__VIEWSTATE"[^>]*value="([^"]*)"', response.text)
                if match:
                    viewstate = match.group(1)
                    
                    # Check if ViewState is not encrypted (MAC only or no protection)
                    if len(viewstate) < 100:
                        Logger.warning("Short ViewState detected - may be vulnerable to deserialization")
                        self.results['vulnerabilities'].append({
                            'title': 'Potential ViewState Deserialization',
                            'severity': 'High',
                            'url': self.target,
                            'description': 'ASP.NET ViewState detected with potentially weak protection. May be vulnerable to deserialization attacks if machine key is known.',
                            'evidence': f'ViewState length: {len(viewstate)}',
                            'remediation': 'Enable ViewState encryption and ensure machine keys are strong and rotated.'
                        })
                    else:
                        Logger.info("ViewState detected with encryption (longer length)")
                        
        except Exception as e:
            Logger.error(f"ViewState check error: {str(e)}")
    
    # ==================== MAIN RUN ====================
    
    def run_full_scan(self):
        """Run all scanning phases based on selected modules"""
        Logger.banner("IIS BUG BOUNTY HUNTER v2 - STARTING SCAN")
        Logger.info(f"Target: {self.target}")
        Logger.info(f"Threads: {self.threads}")
        Logger.info(f"Timeout: {self.timeout}s")
        Logger.info(f"Rate limit: {self.rate_limit}s")
        Logger.info(f"Modules: {', '.join(self.modules)}")
        
        start_time = time.time()
        
        # Module mapping
        module_actions = {
            'recon': self.perform_recon,
            'ssl': self.check_ssl_tls,
            'fingerprint': self.fingerprint_iis,
            'tilde': [self.check_tilde_vulnerability, self.enumerate_tilde_names],
            'fuzz': [self.fuzz_directories, self.fuzz_files, self.fuzz_backup_files],
            'vulns': self.check_common_vulnerabilities,
        }
        
        # Run modules
        if 'all' in self.modules:
            modules_to_run = module_actions.keys()
        else:
            modules_to_run = [m for m in self.modules if m in module_actions]
        
        for module in modules_to_run:
            actions = module_actions[module]
            if isinstance(actions, list):
                for action in actions:
                    action()
            else:
                actions()
        
        # Save results
        self.save_results()
        
        elapsed = time.time() - start_time
        Logger.banner("SCAN COMPLETE")
        Logger.success(f"Scan completed in {elapsed:.2f} seconds")
        Logger.info(f"Results saved to: {self.output_dir}")
        
        # Summary
        Logger.info(f"Vulnerabilities found: {len(self.results['vulnerabilities'])}")
        Logger.info(f"Tilde findings: {len(self.results['tilde_enum'])}")
        Logger.info(f"Fuzzing hits: {len(self.results['fuzzing'])}")


def main():
    parser = argparse.ArgumentParser(
        description='IIS Bug Bounty Hunter v2 - Advanced IIS Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 iis_bug_bounty_hunter_v2.py -u https://example.com
  python3 iis_bug_bounty_hunter_v2.py -u https://example.com -t 50 -o /path/to/output --rate-limit 0.5
  python3 iis_bug_bounty_hunter_v2.py -u https://example.com --modules recon,fingerprint,tilde
  python3 iis_bug_bounty_hunter_v2.py -u https://example.com --wordlist mywords.txt

Modules:
  recon        - Basic reconnaissance (DNS, initial request)
  ssl          - SSL/TLS analysis (if HTTPS)
  fingerprint  - IIS/ASP.NET fingerprinting
  tilde        - Tilde enumeration checks
  fuzz         - Directory/file fuzzing
  vulns        - All vulnerability checks
  all          - Run all modules (default)
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://example.com)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Output directory (default: results/<domain>_<timestamp>)')
    parser.add_argument('--wordlist', help='Custom wordlist file for fuzzing (one word per line)')
    parser.add_argument('--rate-limit', type=float, default=0, help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--modules', default='all', help='Comma-separated list of modules to run (default: all)')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        Logger.error("URL must start with http:// or https://")
        sys.exit(1)
    
    # Parse modules
    modules = [m.strip() for m in args.modules.split(',')]
    
    # Run scanner
    scanner = IISBugBountyHunter(
        target=args.url,
        output_dir=args.output,
        threads=args.threads,
        timeout=args.timeout,
        wordlist=args.wordlist,
        rate_limit=args.rate_limit,
        modules=modules
    )
    
    try:
        scanner.run_full_scan()
    except KeyboardInterrupt:
        Logger.warning("\nScan interrupted by user")
        scanner.save_results()
        sys.exit(0)
    except Exception as e:
        Logger.error(f"Scan failed: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()

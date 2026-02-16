# IIS-Bug-Bounty-Hunter-v2
A comprehensive security assessment tool for finding vulnerabilities in Microsoft IIS servers. Designed for bug bounty hunters, penetration testers, and security researchers.

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 

## 🚀 Features

- **Reconnaissance** – DNS resolution, initial HTTP probing, server header analysis.
- **SSL/TLS Analysis** – Checks for weak protocols (SSLv3, TLSv1.0/1.1), cipher strength, certificate expiration.
- **IIS Fingerprinting** – Detects IIS version, ASP.NET, ViewState, MVC, and WebDAV.
- **Tilde Enumeration** – Tests for IIS 8.3 short name disclosure (CVE-2021-31166 related) and enumerates possible short names.
- **Advanced Fuzzing** – Scans for directories, sensitive files, backup files, and common IIS artifacts.
- **WebDAV Scanning** – Identifies enabled WebDAV, dangerous methods (PUT, DELETE), and CVE-2017-7269 (IIS 6.0 RCE).
- **HTTP Request Smuggling** – Basic detection of CL.TE and TE.CL vulnerabilities.
- **CVE Checks** – Dedicated tests for CVE-2015-1635 (MS15-034 HTTP.sys RCE) and CVE-2021-31166 (HTTP Protocol Stack RCE).
- **Source Code Disclosure** – Tests `::$DATA`, trailing dots, and URL encoding tricks.
- **Path Traversal** – Attempts to read system files via `../` payloads.
- **ASP.NET Debugging** – Detects exposed `trace.axd`, `elmah.axd`, and debug handlers.
- **Telerik UI** – Identifies exposed Telerik handlers and warns about known deserialization vulnerabilities (CVE-2017-11317, CVE-2019-18935).
- **HTTP Method Fuzzing** – Tests for PUT/DELETE methods and attempts to upload/delete a test file.
- **Security Headers Check** – Reports missing security headers.
- **Directory Listing Detection** – Finds enabled directory browsing.
- **ViewState Analysis** – Detects ViewState and warns about potential weak encryption.
- **Custom Wordlists** – Use your own wordlists for fuzzing.
- **Rate Limiting** – Configurable delay between requests to avoid WAF blocks.
- **Modular Scanning** – Run only specific phases (recon, ssl, fingerprint, tilde, fuzz, vulns).
- **Multi-format Reporting** – Saves results in JSON, TXT, and a beautiful HTML report.

- ## 📦 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/NULL200OK/IIS-Bug-Bounty-Hunter-v2.git
   cd IIS-Bug-Bounty-Hunter-v2

 2. **Make the script executable (optional)**
   ```bash
   chmod +x iis_bug_bounty_hunter_v2.py
3.**Usage**
  ```bash
  python3 iis_bug_bounty_hunter_v2.py -u <TARGET_URL> [options]
4. **Basic Example**
   ```bash
   python3 iis_bug_bounty_hunter_v2.py -u https://example.com
5. **Advanced Example**
  ```bash
  python3 iis_bug_bounty_hunter_v2.py -u https://example.com -t 50 --timeout 15 -o ./scan_results --wordlist my_words.txt --rate-limit 0.5 --modules recon,fingerprint,tilde,fuzz
6. **Scan with custom wordlist and rate limiting**
 ```bash
 python3 iis_bug_bounty_hunter_v2.py -u https://testsite.com --wordlist my_aspnet_words.txt --rate-limit 1
7. **Run only reconnaissance and fingerprinting**
 ```bash
python3 iis_bug_bounty_hunter_v2.py -u https://testsite.com --modules recon,fingerprint
8. **Full scan with high concurrency**
 ```bash
python3 iis_bug_bounty_hunter_v2.py -u https://testsite.com -t 100 --timeout 5




  

   
   

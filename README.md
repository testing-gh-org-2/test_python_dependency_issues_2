# Vulnerable Python Test Application

⚠️ **WARNING: This application contains intentional security vulnerabilities for testing and SBOM generation purposes only. DO NOT use in production!**

## Purpose

This project is designed to:
- Generate Software Bill of Materials (SBOM) with vulnerable dependencies
- Test vulnerability scanning tools across all severity levels
- Demonstrate common security issues in Python applications

## Vulnerabilities by Severity

### 🔴 CRITICAL Severity (Score 9.0-10.0)

#### Code Vulnerabilities:
1. **Remote Code Execution via Pickle** (`/load_data`)
   - Insecure deserialization allows arbitrary code execution
   - CVSS: 10.0

2. **Arbitrary File Upload** (`/upload`)
   - No file type or content validation
   - Can lead to remote code execution
   - CVSS: 9.8

3. **Direct Code Execution via eval()** (`/calculate`)
   - User input passed directly to eval()
   - Complete system compromise possible
   - CVSS: 10.0

4. **YAML Deserialization RCE** (`/load_config`)
   - Unsafe YAML loading with arbitrary code execution
   - CVSS: 9.8

#### Dependency Vulnerabilities:
- **Django 3.2.12** - CVE-2022-28346 (SQL Injection) - CVSS 9.8
- **Pillow 8.3.2** - CVE-2022-22817 (Buffer Overflow) - CVSS 9.8
- **paramiko 2.10.1** - CVE-2022-24302 (Auth bypass) - CVSS 9.8

---

### 🟠 HIGH Severity (Score 7.0-8.9)

#### Code Vulnerabilities:
1. **SQL Injection** (`/user`)
   - Unparameterized SQL queries
   - Database compromise
   - CVSS: 8.8

2. **XML External Entity (XXE)** (`/parse_xml`)
   - Allows reading arbitrary files
   - CVSS: 8.2

3. **Server-Side Request Forgery** (`/fetch`)
   - Access to internal network resources
   - CVSS: 8.6

4. **OS Command Injection** (`/ping`)
   - Arbitrary system command execution
   - CVSS: 8.8

5. **Path Traversal** (`/read_file`)
   - Read arbitrary files from filesystem
   - CVSS: 7.5

6. **Hardcoded Secret Key**
   - Session hijacking possible
   - CVSS: 7.4

#### Dependency Vulnerabilities:
- **Flask 2.0.0** - CVE-2023-30861 (Cookie parsing) - CVSS 7.5
- **requests 2.25.0** - CVE-2023-32681 (Header leak) - CVSS 6.1
- **Jinja2 2.11.3** - CVE-2024-22195 (XSS) - CVSS 6.1
- **lxml 4.6.3** - CVE-2021-43818 (XXE) - CVSS 7.1
- **PyYAML 5.3.1** - CVE-2020-14343 (Code execution) - CVSS 9.8

---

### 🟡 MEDIUM Severity (Score 4.0-6.9)

#### Code Vulnerabilities:
1. **Cross-Site Scripting (XSS)** (`/search`)
   - Reflected XSS allows script injection
   - CVSS: 6.1

2. **Server-Side Template Injection** (`/hello`)
   - Can lead to information disclosure or RCE
   - CVSS: 6.5

3. **Missing CSRF Protection** (`/transfer`)
   - State-changing operations without tokens
   - CVSS: 6.5

4. **Insecure Session Management** (`/login`)
   - No secure or httponly flags
   - CVSS: 5.3

5. **Open Redirect** (`/redirect`)
   - Unvalidated redirects for phishing
   - CVSS: 4.7

6. **Debug Mode Enabled**
   - Exposes sensitive information
   - CVSS: 5.3

7. **Insecure Cookie Configuration**
   - Session hijacking risk
   - CVSS: 5.3

#### Dependency Vulnerabilities:
- **Werkzeug 2.0.0** - CVE-2023-25577 (Security bypass) - CVSS 5.3
- **cryptography 3.3.1** - CVE-2023-23931 (Cipher weakness) - CVSS 6.5
- **certifi 2021.5.30** - CVE-2022-23491 (Cert validation) - CVSS 6.8

---

### 🟢 LOW Severity (Score 0.1-3.9)

#### Code Vulnerabilities:
1. **Information Disclosure** (`/divide`)
   - Verbose error messages with stack traces
   - CVSS: 3.7

2. **Weak Password Requirements** (`/register`)
   - No complexity enforcement
   - CVSS: 3.1

3. **Missing Security Headers** (`/page`)
   - No X-Frame-Options, CSP, etc.
   - CVSS: 3.1

4. **Predictable Resource IDs** (`/invoice/<id>`)
   - Sequential IDs enable enumeration (IDOR)
   - CVSS: 3.5

5. **Verbose Server Banner** (`/info`)
   - Information disclosure
   - CVSS: 2.7

6. **CORS Misconfiguration**
   - Allows all origins
   - CVSS: 3.1

#### Dependency Vulnerabilities:
- **urllib3 1.26.4** - CVE-2021-33503 (ReDoS) - CVSS 5.9
- **setuptools 56.0.0** - CVE-2022-40897 (ReDoS) - CVSS 5.9

---

## Vulnerability Statistics

- **Total Code Vulnerabilities**: 24
  - Critical: 4
  - High: 6
  - Medium: 7
  - Low: 7

- **Total Dependency CVEs**: 14
  - Critical: 3
  - High: 5
  - Medium: 3
  - Low: 2

---

## Authentication Module (auth.py)

Additional vulnerabilities in the authentication module:

1. **Hardcoded Credentials** (HIGH) - Default admin credentials in code
2. **Weak Hashing** (MEDIUM) - MD5 used for password hashing
3. **Insecure Deserialization** (CRITICAL) - Pickle vulnerability
4. **Hardcoded Encryption Key** (HIGH) - Static encryption key
5. **Insecure Random** (MEDIUM) - Using random instead of secrets for tokens
6. **Path Traversal** (HIGH) - Unsanitized file path handling
7. **Plaintext Password Storage** (HIGH) - Passwords stored without encryption
8. **Timing Attack** (LOW) - Direct string comparison for authentication

---

## Installation

```bash
pip install -r requirements.txt
```

## Usage

**DO NOT RUN THIS APPLICATION ON A PUBLIC NETWORK!**

For testing purposes only:

```bash
python app.py
```

The app will run on `http://0.0.0.0:5000`

## Testing Endpoints

### Critical Vulnerabilities
- `POST /load_data` - Pickle deserialization
- `POST /upload` - File upload
- `GET /calculate?expr=1+1` - Code execution
- `POST /load_config` - YAML deserialization

### High Vulnerabilities
- `GET /user?id=1` - SQL injection
- `POST /parse_xml` - XXE injection
- `GET /fetch?url=http://example.com` - SSRF
- `GET /ping?host=localhost` - Command injection
- `GET /read_file?file=readme.txt` - Path traversal

### Medium Vulnerabilities
- `GET /search?q=<script>alert(1)</script>` - XSS
- `GET /hello?name={{7*7}}` - SSTI
- `POST /transfer` - CSRF
- `POST /login` - Insecure session
- `GET /redirect?url=http://evil.com` - Open redirect

### Low Vulnerabilities
- `GET /divide?a=10&b=0` - Error disclosure
- `POST /register` - Weak passwords
- `GET /page` - Missing headers
- `GET /invoice/123` - IDOR
- `GET /info` - Information disclosure

## SBOM Generation

Generate SBOM using various tools:

```bash
# Using pip-audit
pip-audit -r requirements.txt

# Using CycloneDX
cyclonedx-py -r -i requirements.txt -o sbom.json

# Using Syft
syft dir:. -o cyclonedx-json

# Using SPDX
pip install spdx-tools
```

## Security Testing Tools

Test this application with:

### Static Analysis (SAST)
```bash
# Bandit
bandit -r . -f json -o bandit_report.json

# Semgrep
semgrep --config=auto .
```

### Dependency Scanning
```bash
# pip-audit
pip-audit

# Safety
safety check

# Grype
grype dir:.
```

### Dynamic Analysis (DAST)
- OWASP ZAP
- Burp Suite
- Nikto

## Legal Disclaimer

This code is provided for **educational and testing purposes only**. The vulnerabilities are intentional and should **never** be deployed to production environments. Use at your own risk.

## License

This is demonstration code for security testing. No warranty provided.

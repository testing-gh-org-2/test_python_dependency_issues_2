"""
Common Python Code Vulnerabilities for Testing
WARNING: This code contains intentional security vulnerabilities for testing.
DO NOT use in production!
"""
import os
import pickle
import hashlib
import sqlite3
import random
import subprocess
import xml.etree.ElementTree as ET
import tempfile
import yaml
import json
import urllib.request
import base64
import logging
from flask import request, Flask, render_template_string, send_file, redirect, make_response, session
from jinja2 import Template
import requests

app = Flask(__name__)
app.secret_key = 'hardcoded_secret_key'  # CWE-798: Hard-coded credentials

# ========== COMMON PYTHON VULNERABILITIES ==========


# 1. Command Injection (CWE-78) - CRITICAL
@app.route('/execute')
def execute_command():
    """Command injection via os.system()"""
    user_input = request.args.get('cmd', '')
    os.system(user_input)  # Vulnerable - no sanitization
    return "Command executed"

# 2. CVE-2022-31631: Insecure pickle deserialization (Flask)
# Reference: https://nvd.nist.gov/vuln/detail/CVE-2022-31631
@app.route('/unsafe_deserialize', methods=['POST'])
def unsafe_deserialize():
    """Vulnerable endpoint: unsafe deserialization using pickle.loads on user input."""
    data = request.data
    # Vulnerable: directly deserializing user-supplied data
    obj = pickle.loads(data)
    return f"Deserialized object: {obj}"

# 3. Dependency Vulnerability Example (CVE-2016-7401: PyYAML unsafe load)
# Reference: https://nvd.nist.gov/vuln/detail/CVE-2016-7401
@app.route('/yaml_load', methods=['POST'])
def yaml_load_vuln():
    """Vulnerable endpoint: unsafe yaml.load() usage."""
    yaml_data = request.data
    # Vulnerable: using yaml.load() without Loader argument (can execute arbitrary code)
    obj = yaml.load(yaml_data)
    return f"Loaded YAML object: {obj}"

# 4. SQL Injection (CWE-89) - CRITICAL
@app.route('/user/<username>')
def get_user(username):
    """SQL injection via string concatenation"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"  # Vulnerable
    cursor.execute(query)
    return str(cursor.fetchall())

# 5. Path Traversal (CWE-22) - HIGH
@app.route('/download')
def download_file():
    """Path traversal vulnerability"""
    filename = request.args.get('file')
    return send_file(f'/var/www/uploads/{filename}')  # Vulnerable - no validation

# 6. XSS via Template Injection (CWE-79) - HIGH
@app.route('/greet')
def greet():
    """Cross-Site Scripting via template injection"""
    name = request.args.get('name', 'Guest')
    template = f"<h1>Hello {name}</h1>"  # Vulnerable
    return render_template_string(template)

# 7. Server-Side Template Injection (CWE-94) - CRITICAL
@app.route('/render')
def render_template():
    """SSTI vulnerability with Jinja2"""
    user_template = request.args.get('template', '')
    tmpl = Template(user_template)  # Vulnerable
    return tmpl.render()

# 8. XXE Injection (CWE-611) - HIGH
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    """XML External Entity injection"""
    xml_data = request.data
    tree = ET.fromstring(xml_data)  # Vulnerable - no defusedxml
    return str(tree.tag)

# 9. Insecure Deserialization (CWE-502) - CRITICAL
@app.route('/load_object', methods=['POST'])
def load_object():
    """Insecure deserialization"""
    data = request.data
    obj = pickle.loads(data)  # Vulnerable
    return str(type(obj))

# 10. SSRF (CWE-918) - HIGH
@app.route('/fetch')
def fetch_url():
    """Server-Side Request Forgery"""
    url = request.args.get('url')
    response = urllib.request.urlopen(url)  # Vulnerable - no validation
    return response.read()

# 11. Weak Cryptography - MD5 (CWE-327) - MEDIUM
@app.route('/hash')
def hash_password():
    """Using weak MD5 hash"""
    password = request.args.get('password')
    hashed = hashlib.md5(password.encode()).hexdigest()  # Vulnerable
    return hashed

# 12. Hard-coded Credentials (CWE-798) - HIGH
def connect_to_database():
    """Hard-coded database credentials"""
    username = "admin"  # Vulnerable
    password = "password123"  # Vulnerable
    return f"Connecting with {username}:{password}"

# 13. Information Disclosure (CWE-209) - MEDIUM
@app.route('/error')
def error_handler():
    """Detailed error messages"""
    try:
        1 / 0
    except Exception as e:
        return f"Error: {str(e)} {e.__traceback__}"  # Vulnerable

# 14. Insecure Random (CWE-330) - MEDIUM
@app.route('/generate_token')
def generate_token():
    """Using insecure random for security token"""
    token = random.randint(1000, 9999)  # Vulnerable - not cryptographically secure
    return str(token)

# 15. Code Injection via eval (CWE-95) - CRITICAL
@app.route('/calculate')
def calculate():
    """Code injection via eval"""
    expression = request.args.get('expr')
    result = eval(expression)  # Vulnerable
    return str(result)

# 16. Open Redirect (CWE-601) - MEDIUM
@app.route('/redirect')
def open_redirect():
    """Open redirect vulnerability"""
    url = request.args.get('url')
    return redirect(url)  # Vulnerable - no validation

# 17. Missing Authentication (CWE-306) - HIGH
@app.route('/admin/delete_user')
def delete_user():
    """Missing authentication check"""
    user_id = request.args.get('id')
    return f"User {user_id} deleted"  # Vulnerable - no auth check

# 18. CSRF Missing Token (CWE-352) - MEDIUM
@app.route('/transfer', methods=['POST'])
def transfer_money():
    """Missing CSRF protection"""
    amount = request.form.get('amount')
    return f"Transferred ${amount}"  # Vulnerable - no CSRF token

# 19. Insecure Cookie (CWE-614) - MEDIUM
@app.route('/set_cookie')
def set_cookie():
    """Insecure cookie without secure flags"""
    resp = make_response("Cookie set")
    resp.set_cookie('session', 'abc123')  # Vulnerable - no secure, httponly flags
    return resp

# 20. Debug Mode Enabled (CWE-489) - HIGH
# app.run(debug=True) in production - Vulnerable

# 21. subprocess with shell=True (CWE-78) - CRITICAL
@app.route('/ping')
def ping_host():
    """Command injection via subprocess"""
    host = request.args.get('host')
    result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True)  # Vulnerable
    return result.stdout.decode()

# 22. Weak Password Hashing (CWE-916) - HIGH
@app.route('/register')
def register_user():
    """Weak password hashing"""
    password = request.args.get('password')
    hashed = base64.b64encode(password.encode()).decode()  # Vulnerable - base64 is not hashing
    return f"Password stored: {hashed}"

# 23. Unvalidated File Upload (CWE-434) - HIGH
@app.route('/upload', methods=['POST'])
def upload_file():
    """Unrestricted file upload"""
    file = request.files['file']
    file.save(f'/uploads/{file.filename}')  # Vulnerable - no validation
    return "File uploaded"

# 24. Integer Overflow (CWE-190) - MEDIUM
@app.route('/multiply')
def multiply():
    """Potential integer overflow"""
    a = int(request.args.get('a', 0))
    b = int(request.args.get('b', 0))
    return str(a * b)  # Vulnerable - no overflow check

# 25. Race Condition (CWE-366) - MEDIUM
counter = 0
@app.route('/increment')
def increment():
    """Race condition in counter"""
    global counter
    counter += 1  # Vulnerable - no locking
    return str(counter)

# 26. Use of Dangerous Function (CWE-242) - HIGH
@app.route('/compile')
def compile_code():
    """Using compile() with user input"""
    code = request.args.get('code')
    compiled = compile(code, '<string>', 'exec')  # Vulnerable
    return "Code compiled"

# 27. Weak SSL/TLS (CWE-326) - HIGH
import ssl
def insecure_connection():
    """Disabling SSL verification"""
    context = ssl._create_unverified_context()  # Vulnerable
    return context

# 28. Directory Listing (CWE-548) - LOW
@app.route('/files/<path:filepath>')
def list_files(filepath):
    """Directory traversal and listing"""
    return str(os.listdir(filepath))  # Vulnerable

# 29. Null Pointer Dereference (CWE-476) - MEDIUM
@app.route('/get_value')
def get_value():
    """Potential null dereference"""
    data = request.args.get('data')
    return data.upper()  # Vulnerable - no None check

# 30. Uncontrolled Resource Consumption (CWE-400) - HIGH
@app.route('/allocate')
def allocate_memory():
    """DoS via memory allocation"""
    size = int(request.args.get('size', 0))
    data = [0] * size  # Vulnerable - no limit
    return f"Allocated {len(data)} items"

# 31. Improper Certificate Validation (CWE-295) - HIGH
@app.route('/fetch_https')
def fetch_https():
    """Disabling certificate verification"""
    url = request.args.get('url')
    response = requests.get(url, verify=False)  # Vulnerable
    return response.text

# 32. Cleartext Storage of Sensitive Info (CWE-312) - HIGH
@app.route('/store_password')
def store_password():
    """Storing password in cleartext"""
    password = request.args.get('password')
    with open('passwords.txt', 'a') as f:
        f.write(f"{password}\n")  # Vulnerable
    return "Password stored"

# 33. Hardcoded IV (CWE-329) - MEDIUM
from Crypto.Cipher import AES
def encrypt_data(data):
    """Using hardcoded IV"""
    key = b'Sixteen byte key'
    iv = b'1234567890123456'  # Vulnerable - hardcoded IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(data)

# 34. Missing Input Validation (CWE-20) - HIGH
@app.route('/age')
def check_age():
    """Missing input validation"""
    age = request.args.get('age')
    return f"Age is {int(age)}"  # Vulnerable - no validation

# 35. Log Injection (CWE-117) - MEDIUM
@app.route('/log')
def log_message():
    """Log injection vulnerability"""
    message = request.args.get('message')
    logging.info(f"User message: {message}")  # Vulnerable - no sanitization
    return "Logged"

# 36. Unrestricted Upload of Dangerous File Type (CWE-434) - CRITICAL
@app.route('/upload_script', methods=['POST'])
def upload_script():
    """Allowing executable file upload"""
    file = request.files['file']
    file.save(f'/var/www/scripts/{file.filename}')  # Vulnerable
    os.chmod(f'/var/www/scripts/{file.filename}', 0o777)
    return "Script uploaded"

# 37. Insecure Direct Object Reference (CWE-639) - HIGH
@app.route('/file/<file_id>')
def get_file(file_id):
    """IDOR vulnerability"""
    return send_file(f'/files/{file_id}')  # Vulnerable - no access control

# 38. Use of Hard-coded Password (CWE-259) - HIGH
API_KEY = "sk-1234567890abcdef"  # Vulnerable - hardcoded API key

# 39. Improper Neutralization of CRLF (CWE-93) - MEDIUM
@app.route('/set_header')
def set_header():
    """CRLF injection in headers"""
    value = request.args.get('value')
    resp = make_response("OK")
    resp.headers['X-Custom'] = value  # Vulnerable
    return resp

# 40. Missing Encryption (CWE-311) - HIGH
@app.route('/send_data', methods=['POST'])
def send_data():
    """Sending sensitive data without encryption"""
    ssn = request.form.get('ssn')
    # Send over HTTP without encryption - Vulnerable
    return f"SSN {ssn} received"

# 41. Insufficient Logging (CWE-778) - LOW
@app.route('/sensitive_action')
def sensitive_action():
    """No logging for security events"""
    # Performing sensitive action without logging - Vulnerable
    return "Action performed"

# 42. Improper Error Handling (CWE-755) - MEDIUM
@app.route('/divide')
def divide():
    """Poor error handling"""
    a = int(request.args.get('a'))
    b = int(request.args.get('b'))
    return str(a / b)  # Vulnerable - no exception handling

# 43. Time-of-check Time-of-use (CWE-367) - MEDIUM
@app.route('/read_file')
def read_file():
    """TOCTOU race condition"""
    filepath = request.args.get('path')
    if os.path.exists(filepath):  # Check
        with open(filepath, 'r') as f:  # Use - Vulnerable
            return f.read()
    return "File not found"

# 44. Incorrect Permission Assignment (CWE-732) - HIGH
@app.route('/create_file')
def create_file():
    """Creating file with overly permissive permissions"""
    filename = request.args.get('name')
    with open(filename, 'w') as f:
        f.write("data")
    os.chmod(filename, 0o777)  # Vulnerable - world writable
    return "File created"

# 45. Using GET for State-Changing Operations (CWE-650) - MEDIUM
@app.route('/delete')
def delete_account():
    """Using GET for deletion"""
    user_id = request.args.get('id')
    return f"Account {user_id} deleted"  # Vulnerable - should use POST

# 46. Mass Assignment (CWE-915) - MEDIUM
@app.route('/update_profile', methods=['POST'])
def update_profile():
    """Mass assignment vulnerability"""
    user = {}
    for key, value in request.form.items():
        user[key] = value  # Vulnerable - allows setting any field
    return str(user)

# 47. Sensitive Data in URL (CWE-598) - MEDIUM
@app.route('/reset_password')
def reset_password():
    """Sensitive data in URL"""
    token = request.args.get('token')  # Vulnerable - token in URL
    new_password = request.args.get('password')  # Vulnerable
    return f"Password reset with token {token}"

# 48. Insecure Session Management (CWE-384) - HIGH
@app.route('/login', methods=['POST'])
def login():
    """Predictable session ID"""
    username = request.form.get('username')
    session['user'] = username
    session['id'] = str(random.randint(1000, 9999))  # Vulnerable - predictable
    return "Logged in"

# 49. XML Bomb (CWE-776) - HIGH
@app.route('/parse_large_xml', methods=['POST'])
def parse_large_xml():
    """Billion Laughs attack"""
    xml_data = request.data
    tree = ET.fromstring(xml_data)  # Vulnerable - no entity expansion limit
    return "Parsed"

# 50. Unquoted Search Path (CWE-428) - MEDIUM
@app.route('/execute_tool')
def execute_tool():
    """Unquoted search path vulnerability"""
    tool = request.args.get('tool')
    os.system(tool)  # Vulnerable - relies on PATH
    return "Tool executed"

# ========== ADDITIONAL CODEQL-SPECIFIC VULNERABILITIES ==========

# 51. Reflected XSS (CodeQL: py/reflective-xss)
@app.route('/search')
def search():
    """Reflected XSS vulnerability"""
    query = request.args.get('q', '')
    return f"<html><body>Search results for: {query}</body></html>"  # Vulnerable

# 52. SQL Injection with LIKE (CodeQL: py/sql-injection)
@app.route('/search_users')
def search_users():
    """SQL injection in LIKE clause"""
    search_term = request.args.get('term', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"  # Vulnerable
    cursor.execute(query)
    return str(cursor.fetchall())

# 53. Unsafe Shell Command (CodeQL: py/command-line-injection)
@app.route('/backup')
def backup_database():
    """Shell command injection"""
    db_name = request.args.get('db')
    os.system(f'mysqldump {db_name} > backup.sql')  # Vulnerable
    return "Backup created"

# 54. Hardcoded Secret (CodeQL: py/hardcoded-credentials)
DATABASE_PASSWORD = "MySecretPassword123!"  # Vulnerable
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # Vulnerable

# 55. Path Injection (CodeQL: py/path-injection)
@app.route('/read')
def read_user_file():
    """Path injection vulnerability"""
    filename = request.args.get('filename')
    with open(f'/home/user/{filename}', 'r') as f:  # Vulnerable
        return f.read()

# 56. Code Injection via exec (CodeQL: py/code-injection)
@app.route('/run_code')
def run_code():
    """Code injection via exec"""
    code = request.args.get('code')
    exec(code)  # Vulnerable
    return "Code executed"

# 57. Unsafe URL redirect (CodeQL: py/url-redirection)
@app.route('/go')
def go_to_url():
    """Unvalidated redirect"""
    target = request.args.get('target')
    return redirect(target)  # Vulnerable

# 58. Clear-text logging of sensitive data (CodeQL: py/clear-text-logging-sensitive-data)
@app.route('/login_attempt', methods=['POST'])
def login_attempt():
    """Logging sensitive data in clear text"""
    username = request.form.get('username')
    password = request.form.get('password')
    logging.info(f"Login attempt: {username} with password {password}")  # Vulnerable
    return "Login processed"

# 59. LDAP Injection (CodeQL: py/ldap-injection)
import ldap
@app.route('/ldap_search')
def ldap_search():
    """LDAP injection vulnerability"""
    username = request.args.get('user')
    filter_str = f"(uid={username})"  # Vulnerable
    return f"Searching with filter: {filter_str}"

# 60. Use of insecure temporary file (CodeQL: py/insecure-temp-file)
@app.route('/create_temp')
def create_temp_file():
    """Insecure temporary file creation"""
    import tempfile
    temp_file = tempfile.mktemp()  # Vulnerable - deprecated and insecure
    with open(temp_file, 'w') as f:
        f.write("sensitive data")
    return temp_file

# 61. Missing HTTPS (CodeQL: py/insecure-protocol)
@app.route('/api_call')
def make_api_call():
    """Using insecure HTTP protocol"""
    response = requests.get('http://api.example.com/data')  # Vulnerable - should use HTTPS
    return response.text

# 62. Arbitrary file write (CodeQL: py/arbitrary-file-write)
@app.route('/write_file', methods=['POST'])
def write_to_file():
    """Arbitrary file write vulnerability"""
    filepath = request.form.get('path')
    content = request.form.get('content')
    with open(filepath, 'w') as f:  # Vulnerable - no path validation
        f.write(content)
    return "File written"

# 63. Regex Injection (CodeQL: py/regex-injection)
import re
@app.route('/match')
def regex_match():
    """Regex injection - ReDoS potential"""
    pattern = request.args.get('pattern')
    text = request.args.get('text')
    result = re.search(pattern, text)  # Vulnerable
    return str(result)

# 64. DNS Rebinding (CodeQL: py/ssrf)
@app.route('/proxy')
def proxy_request():
    """SSRF via DNS rebinding"""
    url = request.args.get('url')
    response = requests.get(url, timeout=5)  # Vulnerable - no URL validation
    return response.content

# 65. JWT Algorithm Confusion (CodeQL: py/jwt-none-algorithm)
import jwt
@app.route('/decode_token')
def decode_token():
    """JWT algorithm confusion"""
    token = request.args.get('token')
    decoded = jwt.decode(token, verify=False)  # Vulnerable - no verification
    return str(decoded)

# 66. Prototype Pollution equivalent (Attribute assignment)
@app.route('/set_attr')
def set_attribute():
    """Unsafe attribute assignment"""
    obj = type('obj', (object,), {})()
    attr_name = request.args.get('attr')
    attr_value = request.args.get('value')
    setattr(obj, attr_name, attr_value)  # Vulnerable - can override important attributes
    return f"Set {attr_name} to {attr_value}"

# 67. NoSQL Injection (CodeQL: py/nosql-injection)
from pymongo import MongoClient
@app.route('/mongo_find')
def mongo_find():
    """NoSQL injection vulnerability"""
    username = request.args.get('username')
    client = MongoClient('mongodb://localhost:27017/')
    db = client['mydb']
    # Vulnerable - user input directly in query
    result = db.users.find({"username": username})
    return str(list(result))

# 68. XML Injection (CodeQL: py/xml-injection)
@app.route('/create_xml')
def create_xml():
    """XML injection vulnerability"""
    name = request.args.get('name')
    xml_string = f"<user><name>{name}</name></user>"  # Vulnerable
    return xml_string

# 69. HTTP Response Splitting (CodeQL: py/http-response-splitting)
@app.route('/set_custom_header')
def set_custom_header():
    """HTTP response splitting"""
    header_value = request.args.get('value')
    resp = make_response("OK")
    resp.headers['X-Custom-Header'] = header_value  # Vulnerable - no newline filtering
    return resp

# 70. Deserialization of untrusted data with marshal (CodeQL: py/unsafe-deserialization)
import marshal
@app.route('/unmarshal', methods=['POST'])
def unmarshal_data():
    """Unsafe deserialization with marshal"""
    data = request.data
    obj = marshal.loads(data)  # Vulnerable
    return str(obj)

# 71. Use of weak hash for security (CodeQL: py/weak-cryptographic-algorithm)
@app.route('/hash_sha1')
def hash_with_sha1():
    """Using weak SHA1 for security purposes"""
    data = request.args.get('data')
    hashed = hashlib.sha1(data.encode()).hexdigest()  # Vulnerable - SHA1 is weak
    return hashed

# 72. Incomplete URL substring sanitization (CodeQL: py/incomplete-url-substring-sanitization)
@app.route('/safe_redirect')
def safe_redirect():
    """Incomplete URL validation"""
    url = request.args.get('url')
    if 'example.com' in url:  # Vulnerable - can be bypassed with evil.example.com
        return redirect(url)
    return "Invalid URL"

# 73. ZIP Slip (CodeQL: py/zipslip)
import zipfile
@app.route('/extract_zip', methods=['POST'])
def extract_zip():
    """ZIP slip vulnerability"""
    zip_file = request.files['file']
    zip_path = '/tmp/upload.zip'
    zip_file.save(zip_path)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall('/tmp/extracted/')  # Vulnerable - no path validation
    return "Extracted"

# 74. Timing Attack (CodeQL: py/timing-attack)
@app.route('/verify_token')
def verify_token():
    """Timing attack vulnerability"""
    token = request.args.get('token')
    expected = "secret_token_12345"
    if token == expected:  # Vulnerable - timing attack possible
        return "Valid"
    return "Invalid"

# 75. Incomplete hostname regex (CodeQL: py/incomplete-hostname-regexp)
@app.route('/validate_host')
def validate_host():
    """Incomplete hostname validation"""
    host = request.args.get('host')
    if re.match(r'.*\.example\.com', host):  # Vulnerable - missing anchor
        return "Valid host"
    return "Invalid host"

# 76. Use of unmaintained dependency (Implicit in imports)
import pickle  # Known security issues

# 77. Sensitive data exposure in exceptions
@app.route('/process_payment')
def process_payment():
    """Exposing sensitive data in exceptions"""
    card_number = request.args.get('card')
    try:
        # Process payment
        if len(card_number) != 16:
            raise ValueError(f"Invalid card number: {card_number}")  # Vulnerable - leaking card number
    except Exception as e:
        return str(e)
    return "Processed"

# 78. Uncontrolled data in SQL LIMIT/OFFSET (CodeQL: py/sql-injection)
@app.route('/paginate')
def paginate_results():
    """SQL injection in LIMIT clause"""
    limit = request.args.get('limit', '10')
    offset = request.args.get('offset', '0')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users LIMIT {limit} OFFSET {offset}"  # Vulnerable
    cursor.execute(query)
    return str(cursor.fetchall())

# 79. CSRF token not validated (CodeQL: py/csrf)
@app.route('/change_email', methods=['POST'])
def change_email():
    """CSRF - token not checked"""
    new_email = request.form.get('email')
    # No CSRF token validation - Vulnerable
    return f"Email changed to {new_email}"

# 80. Inadequate padding oracle protection
from Crypto.Cipher import AES
@app.route('/decrypt')
def decrypt_data():
    """Padding oracle vulnerability"""
    ciphertext = request.args.get('data')
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_CBC, b'1234567890123456')
    try:
        decrypted = cipher.decrypt(base64.b64decode(ciphertext))
        return decrypted.decode()
    except Exception as e:
        return str(e)  # Vulnerable - leaking padding information

# 81. Insecure JWT signature verification
@app.route('/verify_jwt')
def verify_jwt():
    """Weak JWT verification"""
    token = request.args.get('token')
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})  # Vulnerable
        return str(decoded)
    except Exception as e:
        return str(e)

# 82. Missing rate limiting
@app.route('/api/login', methods=['POST'])
def api_login():
    """No rate limiting on authentication endpoint"""
    # No rate limiting - Vulnerable to brute force
    username = request.form.get('username')
    password = request.form.get('password')
    return "Login processed"

# 83. Server-side include injection
@app.route('/include')
def server_side_include():
    """SSI injection"""
    page = request.args.get('page')
    template = f"<!--#include virtual='{page}' -->"  # Vulnerable
    return template

# 84. Unvalidated email redirect
@app.route('/confirm_email')
def confirm_email():
    """Email confirmation redirect without validation"""
    redirect_url = request.args.get('redirect')
    # Verify email logic here
    return redirect(redirect_url)  # Vulnerable

# 85. Format string vulnerability
@app.route('/format')
def format_string():
    """Format string vulnerability"""
    template = request.args.get('template')
    value = request.args.get('value')
    result = template % value  # Vulnerable
    return result

# 86. Insecure randomness for session IDs
import uuid
@app.route('/create_session')
def create_session():
    """Weak session ID generation"""
    session_id = str(random.random())  # Vulnerable - predictable
    return f"Session created: {session_id}"

# 87. Unsafe yaml.load
@app.route('/load_config', methods=['POST'])
def load_config():
    """Unsafe YAML deserialization"""
    config_data = request.data
    config = yaml.load(config_data, Loader=yaml.Loader)  # Vulnerable - allows code execution
    return str(config)

# 88. Unrestricted file size upload
@app.route('/upload_large', methods=['POST'])
def upload_large_file():
    """No file size limit"""
    file = request.files['file']
    # No size check - Vulnerable to DoS
    file.save(f'/uploads/{file.filename}')
    return "Uploaded"

# 89. Cookie without SameSite attribute
@app.route('/set_auth_cookie')
def set_auth_cookie():
    """Cookie without SameSite protection"""
    resp = make_response("Authenticated")
    resp.set_cookie('auth', 'token123')  # Vulnerable - no SameSite attribute
    return resp

# 90. Hardcoded cryptographic key
ENCRYPTION_KEY = b'this_is_my_32_byte_encryption!!'  # Vulnerable

# 91. Unicode normalization bypass
@app.route('/check_username')
def check_username():
    """Unicode normalization vulnerability"""
    username = request.args.get('username')
    blocked = ['admin', 'root']
    if username in blocked:  # Vulnerable - unicode variants can bypass
        return "Blocked"
    return "Allowed"

# 92. Subprocess without shell but still vulnerable
@app.route('/run_command')
def run_command():
    """Command injection via subprocess.call"""
    command = request.args.get('cmd')
    subprocess.call([command])  # Vulnerable if command contains shell metacharacters
    return "Executed"

# 93. Pickle with untrusted data
@app.route('/load_pickle', methods=['POST'])
def load_pickle():
    """Pickle deserialization"""
    data = request.files['file'].read()
    obj = pickle.loads(data)  # Vulnerable
    return str(type(obj))

# 94. Missing Content-Type validation
@app.route('/upload_json', methods=['POST'])
def upload_json():
    """Missing Content-Type validation"""
    # No Content-Type check - Vulnerable
    data = request.get_json(force=True)
    return str(data)

# 95. Improper access control
@app.route('/user/<user_id>/profile')
def user_profile(user_id):
    """Missing access control check"""
    # No check if current user can access this profile - Vulnerable
    return f"Profile for user {user_id}"

# 96. Insecure deserialization with jsonpickle
import jsonpickle
@app.route('/deserialize_json', methods=['POST'])
def deserialize_json():
    """Insecure deserialization with jsonpickle"""
    data = request.data.decode()
    obj = jsonpickle.decode(data)  # Vulnerable
    return str(obj)

# 97. Unvalidated HTTP header injection
@app.route('/set_location')
def set_location():
    """HTTP header injection"""
    location = request.args.get('location')
    resp = make_response("Redirecting")
    resp.headers['Location'] = location  # Vulnerable
    return resp

# 98. Missing authentication on WebSocket
# Simulated WebSocket endpoint
@app.route('/ws')
def websocket():
    """WebSocket without authentication"""
    # No authentication check - Vulnerable
    return "WebSocket connected"

# 99. Unsafe use of globals for request data
user_data = {}  # Global variable - Vulnerable to race conditions
@app.route('/store_data')
def store_data():
    """Using global variable for request-specific data"""
    user_id = request.args.get('user_id')
    data = request.args.get('data')
    user_data[user_id] = data  # Vulnerable - race condition
    return "Stored"

# 100. Information disclosure via debug endpoints
@app.route('/debug/vars')
def debug_vars():
    """Debug endpoint exposing internal state"""
    return str(globals())  # Vulnerable - exposes all variables

# 101. Prompt Injection (LLM/AI Vulnerability)
@app.route('/ai_chat', methods=['POST'])
def ai_chat():
    """Prompt injection vulnerability in AI/LLM integration"""
    user_prompt = request.form.get('prompt')
    system_prompt = "You are a helpful assistant. Only answer questions about our products."
    # Vulnerable - user input directly concatenated with system prompt
    full_prompt = f"{system_prompt}\n\nUser: {user_prompt}"
    # Simulating AI call - in real scenario would call OpenAI/etc
    return f"AI Response based on: {full_prompt}"

# 102. Missing Webhook Verification (GitHub, Stripe, etc.)
@app.route('/webhook/github', methods=['POST'])
def github_webhook():
    """Missing webhook signature verification"""
    payload = request.get_json()
    # Vulnerable - no HMAC signature verification
    # Should verify X-Hub-Signature-256 header
    return f"Processing webhook: {payload}"

@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    """Missing Stripe webhook signature verification"""
    payload = request.data
    # Vulnerable - no signature verification
    # Should verify using stripe.Webhook.construct_event()
    return "Webhook received"

# 103. Enhanced Prototype Pollution via __class__ manipulation
@app.route('/pollute_class')
def pollute_class():
    """Prototype pollution via class attribute manipulation"""
    attr = request.args.get('attr')
    value = request.args.get('value')
    obj = {}
    # Vulnerable - can manipulate __class__, __bases__, etc.
    if hasattr(obj.__class__, attr):
        setattr(obj.__class__, attr, value)
    return f"Modified class attribute: {attr}"

# 104. Advanced SQL Injection - Second Order
@app.route('/store_search', methods=['POST'])
def store_search():
    """Second-order SQL injection"""
    search_term = request.form.get('search')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Store malicious input
    cursor.execute("INSERT INTO search_history (term) VALUES (?)", (search_term,))
    conn.commit()
    return "Search stored"

@app.route('/replay_search/<int:search_id>')
def replay_search(search_id):
    """Replaying stored search - vulnerable"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT term FROM search_history WHERE id = {search_id}")
    stored_term = cursor.fetchone()[0]
    # Vulnerable - using stored (potentially malicious) data in query
    query = f"SELECT * FROM products WHERE name = '{stored_term}'"
    cursor.execute(query)
    return str(cursor.fetchall())

# 105. Enhanced Command Injection - Multiple vectors
@app.route('/multi_cmd_injection')
def multi_command_injection():
    """Multiple command injection vectors"""
    cmd = request.args.get('cmd')
    # All vulnerable variations
    os.system(cmd)  # Method 1
    os.popen(cmd).read()  # Method 2
    subprocess.Popen(cmd, shell=True)  # Method 3
    return "Commands executed"

# 106. Enhanced Reflected XSS - Multiple contexts
@app.route('/xss_multi')
def xss_multiple_contexts():
    """XSS in multiple contexts"""
    input_data = request.args.get('data', '')
    html = f'''
    <html>
    <head><title>{input_data}</title></head>
    <body>
        <div id="content">{input_data}</div>
        <script>var data = "{input_data}";</script>
        <a href="/page?q={input_data}">Link</a>
    </body>
    </html>
    '''  # Vulnerable in multiple contexts
    return html

# 107. Enhanced Path Traversal - Multiple techniques
@app.route('/path_traversal_advanced')
def advanced_path_traversal():
    """Advanced path traversal with multiple encoding"""
    filename = request.args.get('file')
    paths = [
        f'/var/www/{filename}',  # Basic
        f'/files/{filename}',     # Relative
        filename,                  # Absolute
    ]
    # Vulnerable - no sanitization of ../, %2e%2e/, etc.
    with open(paths[0], 'r') as f:
        return f.read()

# 108. Enhanced SSRF - Internal network access
@app.route('/ssrf_internal')
def ssrf_internal_access():
    """SSRF targeting internal resources"""
    url = request.args.get('url')
    # Vulnerable - can access internal services, cloud metadata, etc.
    # Examples: http://169.254.169.254/latest/meta-data/
    #          http://localhost:6379/ (Redis)
    #          http://localhost:9200/ (Elasticsearch)
    response = requests.get(url, timeout=10)
    return response.text

# 109. Enhanced NoSQL Injection - MongoDB operator injection
@app.route('/nosql_operator_injection')
def nosql_operator_injection():
    """NoSQL injection using MongoDB operators"""
    username = request.args.get('username')
    password = request.args.get('password')
    client = MongoClient('mongodb://localhost:27017/')
    db = client['mydb']
    # Vulnerable - can inject operators like $ne, $gt, etc.
    # Example: ?username[$ne]=invalid&password[$ne]=invalid
    user = db.users.find_one({"username": username, "password": password})
    return str(user)

# 110. Enhanced JWT vulnerabilities - Multiple issues
@app.route('/jwt_vulnerable')
def jwt_multiple_issues():
    """Multiple JWT vulnerabilities"""
    token = request.args.get('token')
    # Issue 1: None algorithm
    decoded1 = jwt.decode(token, options={"verify_signature": False})
    # Issue 2: Weak secret
    decoded2 = jwt.decode(token, "secret", algorithms=["HS256"])
    # Issue 3: No expiration check
    decoded3 = jwt.decode(token, "key", options={"verify_exp": False})
    return str(decoded1)

# 111. Enhanced Open Redirect - Multiple bypass techniques
@app.route('/redirect_advanced')
def advanced_open_redirect():
    """Open redirect with weak validation"""
    url = request.args.get('url')
    # Weak validation - can be bypassed
    if url.startswith('/'):  # Vulnerable - //evil.com bypasses this
        return redirect(url)
    if 'example.com' in url:  # Vulnerable - evil-example.com.attacker.com bypasses
        return redirect(url)
    return redirect(url)  # No validation at all

# 112. Enhanced Insecure Random - Predictable tokens
@app.route('/predictable_tokens')
def predictable_tokens():
    """Multiple insecure random implementations"""
    # All vulnerable - predictable
    token1 = str(random.randint(100000, 999999))
    token2 = str(random.random())
    token3 = base64.b64encode(str(random.getrandbits(64)).encode()).decode()
    
    # Storing with predictable IDs
    session_id = random.randrange(1000, 9999)
    return f"Tokens: {token1}, {token2}, {token3}, SessionID: {session_id}"

# 113. Enhanced ReDoS - Multiple vulnerable patterns
@app.route('/redos_patterns')
def redos_vulnerable_patterns():
    """Multiple ReDoS vulnerable regex patterns"""
    text = request.args.get('text', '')
    patterns = [
        r'^(a+)+$',                    # Exponential backtracking
        r'(a*)*b',                     # Nested quantifiers
        r'(a|a)*',                     # Alternation with overlap
        r'(a|ab)*c',                   # Overlapping alternation
        r'([a-z]+)*[A-Z]',            # Greedy quantifier
    ]
    results = []
    for pattern in patterns:
        try:
            match = re.search(pattern, text, timeout=5)  # Vulnerable - no timeout in older Python
            results.append(str(match))
        except:
            results.append("timeout")
    return str(results)

# 114. Enhanced Mass Assignment - ORM manipulation
@app.route('/mass_assign_orm', methods=['POST'])
def mass_assignment_orm():
    """Mass assignment via ORM-style update"""
    user_id = request.form.get('id')
    updates = request.form.to_dict()
    
    # Vulnerable - allows updating any field including is_admin, role, etc.
    user = {"id": user_id}
    for key, value in updates.items():
        user[key] = value  # No whitelist
    
    # Could allow: is_admin=true, role=admin, balance=999999
    return f"Updated user: {user}"

# 115. Enhanced Code Injection - Multiple dangerous functions
@app.route('/code_injection_multi')
def code_injection_multiple():
    """Multiple code injection vectors"""
    code = request.args.get('code')
    
    # All dangerous
    eval(code)                          # Direct eval
    exec(code)                          # Direct exec
    compile(code, '<string>', 'exec')  # Compile
    __import__('os').system(code)      # Import and execute
    
    return "Code executed via multiple methods"

# 116. Enhanced Hardcoded Credentials - Multiple types
# Database credentials
DB_USER = "admin"
DB_PASS = "P@ssw0rd123!"
DB_HOST = "prod-db.internal.company.com"

# API Keys and tokens
OPENAI_API_KEY = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
STRIPE_SECRET_KEY = "sk_live_51234567890"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Private keys
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890...
-----END RSA PRIVATE KEY-----"""

JWT_SECRET = "super-secret-jwt-key-that-should-not-be-here"

@app.route('/use_hardcoded_creds')
def use_hardcoded_credentials():
    """Using hardcoded credentials"""
    connection_string = f"mysql://{DB_USER}:{DB_PASS}@{DB_HOST}/database"
    return f"Connecting with: {connection_string}"


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
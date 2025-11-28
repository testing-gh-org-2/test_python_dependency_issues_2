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


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
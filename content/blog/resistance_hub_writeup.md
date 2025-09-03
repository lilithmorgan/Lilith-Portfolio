---
title: "EotW CTF SS CASE IT 2025 - The Resistance Hub Writeup"
date: "2025-05-27"
description: "Infiltrating the resistance communication hub through source code analysis and Base64 decoding. Learn how to discover hidden secrets in JavaScript code and decode obfuscated intelligence data."
tags: ["web-security", "source-code-analysis", "base64", "javascript", "reconnaissance", "ctf", "steganography"]
---

## Infiltrating the Resistance Communication Network: Source Code Intelligence

**Category**: Web Exploitation  
**Points**: 75  
**Description**: In the year 2025, an AI regime has taken control of most critical infrastructure. A hacker known as 0x4m4 is leading the resistance movement, fighting to restore human autonomy. The resistance maintains a hidden communication hub where operatives share intelligence and coordinate attacks against the AI regime. Your mission is to infiltrate the Resistance Hub and find the secret flag hidden within their communication system.

## Challenge Context

The year is 2025, and the AI regime has established totalitarian control over critical infrastructure. In this dystopian landscape, a legendary hacker known as 0x4m4 leads a resistance movement fighting to restore human autonomy and freedom.

The resistance operates through a carefully concealed communication hub, hidden within seemingly innocent web pages. As an aspiring resistance operative, my mission was to infiltrate this hub and extract the secret flag that would grant access to their command network.

The application was accessible at `challs.0x4m4.com:8001` and appeared to be a sophisticated resistance communication platform.

## Initial Reconnaissance

When I first accessed the Resistance Hub, I was greeted with a professional-looking interface featuring:

1. A sleek, cyberpunk-themed design with resistance messaging
2. Various sections about the resistance movement and 0x4m4
3. Navigation elements and interactive components
4. References to secure communication and hidden intelligence

```bash
curl -s http://challs.0x4m4.com:8001/ | grep -i "secret\|hidden\|flag"
```

The challenge hint was particularly intriguing: *"Sometimes, the most valuable information isn't displayed on the screen. Look deeper into how the resistance stores their secrets."*

## Discovery Phase: Source Code Analysis

### Method 1: View Page Source

The most direct approach was examining the page source code:

```bash
# Using curl to fetch the raw HTML
curl -s http://challs.0x4m4.com:8001/ > resistance_hub.html

# Or using browser: Right-click → "View Page Source" (Ctrl+U)
```

### Method 2: Developer Tools Investigation

Using browser developer tools to inspect the page structure:

1. **F12** to open Developer Tools
2. **Sources tab** to examine JavaScript files
3. **Network tab** to monitor resource loading
4. **Console tab** to test JavaScript execution

### Method 3: JavaScript Analysis

The key breakthrough came when examining the JavaScript code embedded in the page. I discovered a function called `initSecurityModules()` that contained suspicious objects.

## Intelligence Extraction: Finding Hidden Secrets

### Discovering the Security Modules

Within the JavaScript source code, I found the `initSecurityModules()` function:

```javascript
function initSecurityModules() {
    const resistanceNetwork = {
        operatives: {
            leader: "0x4m4",
            status: "active",
            location: "classified"
        },
        communications: {
            encrypted: true,
            protocol: "resistance_secure_v2"
        },
        secretStorage: {
            operationInsight: "c3NjaXR7aDFkZDNuX2MwZDNfMXNfbjB0X3MzY3VyM19qczBuX3MzY3JldHN9:c29tZWhhc2g=",
            accessLevel: "classified",
            timestamp: "2025-05-27"
        }
    };
    
    // Additional resistance code...
}
```

### Identifying the Encoded Intelligence

The `operationInsight` property immediately caught my attention:

```javascript
operationInsight: "c3NjaXR7aDFkZDNuX2MwZDNfMXNfbjB0X3MzY3VyM19qczBuX3MzY3JldHN9:c29tZWhhc2g="
```

This string had several characteristics of encoded data:
- **Base64 pattern**: Alphanumeric characters with padding-like structure
- **Colon separator**: Suggesting two encoded components
- **Length**: Appropriate for a flag-sized payload

## Decoding the Resistance Intelligence

### Manual Base64 Decoding

The first part of the string (before the colon) appeared to be Base64 encoded:

```bash
echo "c3NjaXR7aDFkZDNuX2MwZDNfMXNfbjB0X3MzY3VyM19qczBuX3MzY3JldHN9" | base64 -d
```

**Result**: `sscit{h1dd3n_c0d3_1s_n0t_s3cur3_js0n_s3crets}`

### Verification and Analysis

To verify this was indeed the flag, I also decoded the second part:

```bash
echo "c29tZWhhc2g=" | base64 -d
```

**Result**: `somehash`

This confirmed that the resistance was using a format of `encoded_flag:encoded_hash` for their secret storage.

## Complete Exploitation Script

Here's my automated Python script for resistance hub infiltration:

```python
#!/usr/bin/env python3
import requests
import re
import base64
from bs4 import BeautifulSoup

class ResistanceHubExploit:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        
    def fetch_page_source(self):
        """Fetch and analyze the page source code"""
        print("[*] Infiltrating resistance hub...")
        
        response = self.session.get(self.base_url)
        
        if response.status_code == 200:
            print("[+] Successfully accessed resistance hub!")
            return response.text
        else:
            print(f"[-] Failed to access hub: {response.status_code}")
            return None
    
    def extract_javascript_secrets(self, html_content):
        """Extract and analyze JavaScript code for hidden secrets"""
        print("[*] Analyzing resistance communication protocols...")
        
        # Look for JavaScript containing secret storage
        js_pattern = r'secretStorage\s*:\s*{([^}]+)}'
        js_matches = re.findall(js_pattern, html_content, re.DOTALL)
        
        if js_matches:
            print("[+] Found secret storage in resistance code!")
            return js_matches[0]
        
        # Alternative: Look for operationInsight directly
        insight_pattern = r'operationInsight\s*:\s*["\']([^"\']+)["\']'
        insight_matches = re.findall(insight_pattern, html_content)
        
        if insight_matches:
            print("[+] Found operation insight data!")
            return insight_matches[0]
        
        return None
    
    def decode_operation_insight(self, encoded_data):
        """Decode the operation insight data"""
        print("[*] Decoding resistance intelligence...")
        
        # Split on colon if present
        if ':' in encoded_data:
            flag_part, hash_part = encoded_data.split(':', 1)
        else:
            flag_part = encoded_data
            hash_part = None
        
        try:
            # Decode the flag part
            decoded_flag = base64.b64decode(flag_part).decode('utf-8')
            print(f"[+] Decoded resistance intelligence: {decoded_flag}")
            
            # Decode hash part if present
            if hash_part:
                decoded_hash = base64.b64decode(hash_part).decode('utf-8')
                print(f"[+] Decoded verification hash: {decoded_hash}")
            
            return decoded_flag
            
        except Exception as e:
            print(f"[-] Failed to decode intelligence: {e}")
            return None
    
    def analyze_javascript_objects(self, html_content):
        """Analyze JavaScript objects for hidden data"""
        print("[*] Analyzing resistance JavaScript objects...")
        
        # Extract JavaScript object definitions
        soup = BeautifulSoup(html_content, 'html.parser')
        scripts = soup.find_all('script')
        
        for script in scripts:
            if script.string:
                # Look for object definitions
                if 'secretStorage' in script.string:
                    print("[+] Found secretStorage object!")
                    
                    # Extract the operationInsight value
                    insight_match = re.search(r'operationInsight\s*:\s*["\']([^"\']+)["\']', script.string)
                    if insight_match:
                        return insight_match.group(1)
        
        return None
    
    def exploit(self):
        """Main resistance hub infiltration flow"""
        print(f"[*] Starting infiltration of {self.base_url}")
        
        # Fetch page source
        html_content = self.fetch_page_source()
        if not html_content:
            return None
        
        # Method 1: Look for JavaScript secrets
        secret_data = self.extract_javascript_secrets(html_content)
        if secret_data:
            if ':' in secret_data:
                # Full operationInsight string
                flag = self.decode_operation_insight(secret_data)
            else:
                # Just the encoded part
                flag = self.decode_operation_insight(secret_data)
            
            if flag:
                return flag
        
        # Method 2: Analyze JavaScript objects
        insight_data = self.analyze_javascript_objects(html_content)
        if insight_data:
            flag = self.decode_operation_insight(insight_data)
            if flag:
                return flag
        
        print("[-] No resistance intelligence found")
        return None

if __name__ == "__main__":
    target = "http://challs.0x4m4.com:8001"
    exploit = ResistanceHubExploit(target)
    flag = exploit.exploit()
    
    if flag:
        print(f"\n[+] MISSION ACCOMPLISHED!")
        print(f"[+] Resistance access key obtained: {flag}")
        print(f"[+] Welcome to the resistance network!")
    else:
        print("\n[-] Mission failed: Unable to extract resistance intelligence")
```

## Running the Infiltration

When I executed the complete infiltration:

```bash
python3 exploit.py
[*] Starting infiltration of http://challs.0x4m4.com:8001
[*] Infiltrating resistance hub...
[+] Successfully accessed resistance hub!
[*] Analyzing resistance communication protocols...
[+] Found secret storage in resistance code!
[*] Decoding resistance intelligence...
[+] Decoded resistance intelligence: sscit{h1dd3n_c0d3_1s_n0t_s3cur3_js0n_s3crets}
[+] Decoded verification hash: somehash

[+] MISSION ACCOMPLISHED!
[+] Resistance access key obtained: sscit{h1dd3n_c0d3_1s_n0t_s3cur3_js0n_s3crets}
[+] Welcome to the resistance network!
```

## Alternative Discovery Methods

### Method 1: Browser Developer Tools

1. **Open Developer Tools** (F12)
2. **Navigate to Sources tab**
3. **Search for "secretStorage"** (Ctrl+Shift+F)
4. **Locate the operationInsight property**
5. **Copy the Base64 string**
6. **Decode using online tools or command line**

### Method 2: Command Line Investigation

```bash
# Fetch page and search for Base64 patterns
curl -s http://challs.0x4m4.com:8001/ | grep -o '[A-Za-z0-9+/]\{20,\}=*' | while read line; do
    decoded=$(echo "$line" | base64 -d 2>/dev/null)
    if [[ "$decoded" == *"sscit{"* ]]; then
        echo "Found flag: $decoded"
    fi
done
```

### Method 3: JavaScript Console Execution

In the browser console:

```javascript
// Access the resistance network object
console.log(resistanceNetwork.secretStorage.operationInsight);

// Decode the Base64 string
const encoded = "c3NjaXR7aDFkZDNuX2MwZDNfMXNfbjB0X3MzY3VyM19qczBuX3MzY3JldHN9";
const decoded = atob(encoded);
console.log("Flag:", decoded);
```

## Technical Deep Dive

### Understanding Base64 Encoding

Base64 encoding is commonly used to encode binary data in ASCII format:

```python
import base64

# Encoding
original = "sscit{h1dd3n_c0d3_1s_n0t_s3cur3_js0n_s3crets}"
encoded = base64.b64encode(original.encode()).decode()
print(f"Encoded: {encoded}")

# Decoding
decoded = base64.b64decode(encoded).decode()
print(f"Decoded: {decoded}")
```

### JavaScript Object Security

The challenge demonstrates poor security practices:

```javascript
// Insecure: Storing secrets in client-side JavaScript
const secrets = {
    apiKey: "base64_encoded_secret",
    flag: "encoded_flag_data"
};

// Secure: Never store secrets in client-side code
// Use server-side authentication and authorization instead
```

## Key Learnings

This challenge taught me several important concepts:

1. **Source Code Analysis**: Always examine client-side code for sensitive information
2. **Base64 Recognition**: Identifying encoded data patterns
3. **JavaScript Security**: Understanding client-side security limitations
4. **Reconnaissance Methodology**: Systematic approach to information gathering
5. **Encoding/Decoding**: Practical cryptographic operations

## Prevention Measures

To prevent similar vulnerabilities:

### 1. Never Store Secrets Client-Side

```javascript
// DON'T DO THIS
const config = {
    apiKey: "secret_key_here",
    flag: "encoded_flag"
};

// DO THIS INSTEAD
// Store secrets server-side and use proper authentication
```

### 2. Implement Proper Authentication

```javascript
// Secure approach
async function getSecretData() {
    const token = await authenticate();
    const response = await fetch('/api/secrets', {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
}
```

## Conclusion

The Resistance Hub challenge was an excellent introduction to client-side security analysis and the dangers of storing sensitive information in JavaScript code. By systematically examining the page source and identifying Base64-encoded data, I was able to successfully infiltrate the resistance communication network and extract the hidden access key.

This challenge highlighted several critical security concepts:
- The importance of never storing secrets in client-side code
- How to recognize and decode common encoding schemes
- The value of thorough source code analysis during security assessments
- The need for proper authentication and authorization mechanisms

The successful infiltration demonstrates how easily accessible client-side code can be to attackers, and why sensitive operations must always be performed server-side with proper security controls.

The resistance access key was: `sscit{h1dd3n_c0d3_1s_n0t_s3cur3_js0n_s3crets}`

Welcome to the resistance network! The fight against AI oppression continues! 🔓💻 
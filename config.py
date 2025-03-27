#!/usr/bin/env python3

# Default configuration for Bug Bounty AI tool
import os

# Directory for outputs and results
DEFAULT_OUTPUT_DIR = "results"

# Create results directory if it doesn't exist
os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)

# Tool paths (assuming Kali Linux default installations)
TOOL_PATHS = {
    # Core scanning tools
    "nmap": "/usr/bin/nmap",
    "sqlmap": "/usr/bin/sqlmap",
    "ffuf": "/usr/bin/ffuf",
    "nikto": "/usr/bin/nikto",
    "nuclei": "/usr/bin/nuclei",
    "gobuster": "/usr/bin/gobuster",
    "feroxbuster": "/usr/bin/feroxbuster",
    
    # AI integration
    "ollama": "/usr/local/bin/ollama",
    
    # Web scanning
    "zap": "/usr/share/zaproxy/zap.sh",
    "zap-cli": "/usr/local/bin/zap-cli",
    "wpscan": "/usr/bin/wpscan",
    "joomscan": "/usr/bin/joomscan", 
    "droopescan": "/usr/bin/droopescan",
    "whatweb": "/usr/bin/whatweb",
    "xsstrike": "/opt/XSStrike/xsstrike.py",
    
    # SSL/TLS
    "sslyze": "/usr/bin/sslyze",
    
    # Subdomain enumeration
    "amass": "/usr/bin/amass",
    "subfinder": "/usr/bin/subfinder",
    "assetfinder": "/usr/bin/assetfinder",
    "findomain": "/usr/bin/findomain",
    "dnsx": "/usr/bin/dnsx",
    "httpx": "/usr/bin/httpx",
    
    # DNS
    "dig": "/usr/bin/dig",
    "whois": "/usr/bin/whois",
    
    # Other utilities
    "curl": "/usr/bin/curl",
    "jq": "/usr/bin/jq"
}

# Default wordlists
WORDLISTS = {
    "directories": {
        "small": "/usr/share/wordlists/dirb/common.txt",
        "medium": "/usr/share/wordlists/dirb/big.txt",
        "large": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    },
    "subdomains": {
        "small": "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
        "medium": "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
        "large": "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
    },
    "web_content": {
        "small": "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt",
        "medium": "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt",
        "large": "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt"
    },
    "web_extensions": {
        "common": ["php", "asp", "aspx", "jsp", "html", "js", "do", "action", "cgi"],
        "detailed": ["php", "asp", "aspx", "jsp", "jspx", "do", "action", "cgi", "pl", "html", "htm", "js", "json", "xml", "zip", "bak", "old", "backup", "config", "conf", "sql", "txt"]
    },
    "logs": "/usr/share/wordlists/SecLists/Discovery/Web-Content/common-log-locations.txt",
    "passwords": {
        "small": "/usr/share/wordlists/fasttrack.txt",
        "medium": "/usr/share/wordlists/rockyou.txt"
    }
}

# Scan configurations
SCAN_CONFIGS = {
    "quick": {
        "nmap_flags": "-sV -sC --top-ports 1000",
        "ffuf_flags": "-c -t 50",
        "sqlmap_flags": "--batch --level=1 --risk=1",
        "nikto_flags": "-Tuning 123",
        "nuclei_flags": "-t cves/ -severity critical,high",
        "amass_flags": "-passive",
        "subfinder_flags": "",
        "gobuster_flags": "-t 50"
    },
    "normal": {
        "nmap_flags": "-sV -sC -p- --open",
        "ffuf_flags": "-c -t 100 -recursion",
        "sqlmap_flags": "--batch --level=2 --risk=2",
        "nikto_flags": "-Tuning x",
        "nuclei_flags": "-t cves/,vulnerabilities/ -severity critical,high,medium",
        "amass_flags": "-active",
        "subfinder_flags": "-all",
        "gobuster_flags": "-t 50"
    },
    "thorough": {
        "nmap_flags": "-sV -sC -p- -A --script=vuln --open",
        "ffuf_flags": "-c -t 150 -recursion -recursion-depth 2",
        "sqlmap_flags": "--batch --level=3 --risk=3 --all",
        "nikto_flags": "-Tuning x",
        "nuclei_flags": "-t cves/,vulnerabilities/,exposures/,misconfiguration/ -severity critical,high,medium,low",
        "amass_flags": "-active -brute -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
        "subfinder_flags": "-all -recursive",
        "gobuster_flags": "-t 100"
    }
}

# AI configuration
AI_CONFIG = {
    "ollama": {
        "default_model": "deepseek-r1:32b",
        "alternatives": ["llama3", "mistral", "mixtral", "gemma:7b"]
    },
    "openrouter": {
        "model": "qwen/qwq-32b",
        "max_tokens": 2000
    }
}

# AI personas for the interactive chat
AI_PERSONAS = {
    "hacker": {
        "name": "H4X0R",
        "description": "Elite ethical hacker with a focus on finding vulnerabilities quickly",
        "color": "\033[91m"  # Red
    },
    "pentester": {
        "name": "PenTester",
        "description": "Professional penetration tester following methodical approaches",
        "color": "\033[93m"  # Yellow
    },
    "bughunter": {
        "name": "BugHunter",
        "description": "Bug bounty hunter focused on finding reward-worthy vulnerabilities",
        "color": "\033[94m"  # Blue
    },
    "analyst": {
        "name": "SecAnalyst",
        "description": "Security analyst providing detailed analysis and remediation advice",
        "color": "\033[92m"  # Green
    }
}

# Target type configurations
TARGET_CONFIGS = {
    "ip": {
        "recon": {
            "nmap_os_detection": True,
            "geolocation": True,
            "whois": True,
            "reverse_dns": True
        },
        "port_scan": {
            "initial_ports": "top-1000",
            "full_scan_threshold": 5  # If less than this many ports open, do a full scan
        }
    },
    "domain": {
        "recon": {
            "whois": True,
            "dns_enum": True,
            "ip_geolocation": True
        },
        "subdomain_enum": {
            "passive_first": True,
            "active_if_results_under": 10,  # If passive finds under this many, do active
            "tools": ["amass", "subfinder", "assetfinder", "crt.sh"]
        }
    }
}

# Reporting configuration
REPORT_CONFIG = {
    "include_raw_output": True,
    "include_screenshots": False,
    "format": "markdown",
    "ai_analysis": True,
    "severity_levels": [
        "critical",
        "high",
        "medium",
        "low",
        "info"
    ]
}

# Add OWASP Top 10 specific configurations
OWASP_TOP_10 = {
    "A01:2021": {
        "name": "Broken Access Control",
        "tools": ["nuclei", "zap"],
        "tags": ["access-control", "idor", "authorization"]
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "tools": ["sslyze", "nuclei"],
        "tags": ["ssl", "tls", "crypto"]
    },
    "A03:2021": {
        "name": "Injection",
        "tools": ["sqlmap", "nuclei"],
        "tags": ["sqli", "xss", "injection", "xxe"]
    },
    "A04:2021": {
        "name": "Insecure Design",
        "tools": ["nuclei"],
        "tags": ["logic-flaw", "business-logic"]
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "tools": ["nuclei", "nikto"],
        "tags": ["misconfig", "default-config"]
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "tools": ["nuclei"],
        "tags": ["cve", "outdated"]
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "tools": ["nuclei", "hydra"],
        "tags": ["auth-bypass", "default-login", "weak-auth"]
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "tools": ["nuclei"],
        "tags": ["integrity", "deserialization"]
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "tools": ["ffuf"],
        "wordlists": ["/usr/share/wordlists/SecLists/Discovery/Web-Content/common-log-locations.txt"]
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery",
        "tools": ["nuclei"],
        "tags": ["ssrf"]
    }
} 
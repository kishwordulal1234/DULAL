#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess
import json
import time
import requests
import re
import readline
import shlex
import threading
import platform
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import logging
import colorama
from colorama import Fore, Style
from utils import is_valid_domain, is_valid_ip, is_valid_url, normalize_target, extract_domains_from_text, extract_ips_from_text, check_tool_availability
from urllib.parse import urlparse
from config import AI_CONFIG

# Initialize colorama
colorama.init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bug_bounty.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("BugBountyAI")

# Available Kali Linux tools with descriptions
KALI_TOOLS = {
    "nmap": "Network scanning and host discovery",
    "sqlmap": "Automated SQL injection tool",
    "ffuf": "Web fuzzer for discovering web content",
    "nikto": "Web server scanner",
    "nuclei": "Vulnerability scanner",
    "dirb": "Web content scanner",
    "gobuster": "Directory/file & DNS busting tool",
    "hydra": "Password cracking tool",
    "wpscan": "WordPress vulnerability scanner",
    "metasploit": "Exploitation framework",
    "aircrack-ng": "Wireless network security tools",
    "john": "Password cracker",
    "hashcat": "Password recovery tool",
    "wireshark": "Network protocol analyzer",
    "burpsuite": "Web application security testing",
    "zaproxy": "OWASP Zed Attack Proxy",
    "wfuzz": "Web application fuzzer",
    "dirbuster": "Directory brute force tool",
    "enum4linux": "Windows/Samba enumeration",
    "searchsploit": "Exploit database searcher",
    "responder": "LLMNR, NBT-NS and MDNS poisoner",
    "crackmapexec": "Active Directory assessment tool",
    "masscan": "Fast port scanner",
    "amass": "Network mapping of attack surfaces"
}

# AI personas for chat mode
AI_PERSONAS = {
    "hacker": {
        "name": "H4X0R",
        "color": Fore.RED,
        "prompt_prefix": "You are an elite ethical hacker. Think like a real hacker while helping the user. Be concise, technical, and slightly mysterious. Use hacker lingo occasionally."
    },
    "pentester": {
        "name": "PenTester",
        "color": Fore.BLUE,
        "prompt_prefix": "You are a professional penetration tester. Provide methodical, professional security advice while helping the user find vulnerabilities."
    },
    "bugbounty": {
        "name": "BugHunter",
        "color": Fore.GREEN,
        "prompt_prefix": "You are a bug bounty hunter. Focus on finding security issues that would qualify for bug bounties. Be thorough and explain your methodology."
    },
    "analyst": {
        "name": "SecAnalyst",
        "color": Fore.YELLOW,
        "prompt_prefix": "You are a security analyst. Provide detailed analysis of security findings and recommend mitigation strategies."
    }
}

class BugBountyAI:
    def __init__(self, target=None, output_dir="results", openrouter_api_key=None, scan_type="full", 
                 ollama_model="deepseek-r1:32b", ai_persona="hacker", chat_mode=False, use_openrouter=False, no_prompt=False):
        self.target = target
        self.output_dir = output_dir
        self.openrouter_api_key = openrouter_api_key
        self.scan_type = scan_type
        self.ollama_model = ollama_model
        self.ai_persona = ai_persona
        self.chat_mode = chat_mode
        self.use_openrouter = use_openrouter
        self.no_prompt = no_prompt
        self.chat_history = []
        self.current_scan_results = {}
        self.is_scanning = False
        self.scan_thread = None
        self.firewall_evasion = False
        
        # Create output directory if it doesn't exist
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Only validate target if not in chat mode and target is provided
        if not chat_mode and target:
            if not self._validate_target():
                logger.error(f"Invalid target: {target}")
                sys.exit(1)
            logger.info(f"Initialized BugBountyAI for target: {target}")
        elif chat_mode:
            logger.info("Initialized BugBountyAI in chat mode")
        
    def _validate_target(self):
        """Validate if the target is a valid domain, IP address, or URL"""
        if not self.target:
            return False
            
        target = self.target.strip()
        
        # Handle URLs properly
        if target.startswith(('http://', 'https://')):
            return is_valid_url(target)
        
        # Handle IP addresses
        if is_valid_ip(target):
            return True
            
        # Handle domains
        if is_valid_domain(target):
            return True
            
        return False
    
    def get_target_type(self):
        """Determine if the target is an IP address, domain, or URL"""
        if not self.target:
            return None
            
        target = self.target.strip()
        
        # Handle URLs
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            netloc = parsed.netloc
            if is_valid_ip(netloc):
                return "ip"
            else:
                return "domain"
        
        # Handle IP addresses
        if is_valid_ip(target):
            return "ip"
            
        # Handle domains
        if is_valid_domain(target):
            return "domain"
            
        return None
    
    def normalize_target(self):
        """Normalize the target to a consistent format"""
        if not self.target:
            return None
            
        target = self.target.strip()
        
        # Remove http/https from URLs
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.netloc
            
        return target
    
    def run_ip_reconnaissance(self, ip):
        """Run reconnaissance on an IP address"""
        print(f"{Fore.YELLOW}Starting reconnaissance on IP address: {ip}...{Style.RESET_ALL}")
        
        results = {
            "ip": ip,
            "ports": [],
            "os_info": None,
            "hostname": None,
            "geolocation": None,
            "asn_info": None
        }
        
        # Try to get hostname
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            results["hostname"] = hostname
            print(f"{Fore.GREEN}Hostname: {hostname}{Style.RESET_ALL}")
        except:
            print(f"{Fore.RED}Could not determine hostname for {ip}{Style.RESET_ALL}")
        
        # Run IP geolocation with curl
        try:
            output, _ = self.run_custom_command(f"curl -s https://ipinfo.io/{ip}/json")
            ip_info = json.loads(output)
            results["geolocation"] = {
                "country": ip_info.get("country", "Unknown"),
                "region": ip_info.get("region", "Unknown"),
                "city": ip_info.get("city", "Unknown"),
                "org": ip_info.get("org", "Unknown")
            }
            results["asn_info"] = ip_info.get("org", "Unknown")
            print(f"{Fore.GREEN}Geolocation: {ip_info.get('city', 'Unknown')}, {ip_info.get('region', 'Unknown')}, {ip_info.get('country', 'Unknown')}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Organization: {ip_info.get('org', 'Unknown')}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error getting geolocation: {str(e)}{Style.RESET_ALL}")
        
        # Run detailed OS detection with Nmap
        try:
            print(f"{Fore.CYAN}Running OS detection...{Style.RESET_ALL}")
            output, _ = self.run_custom_command(f"nmap -O {ip}")
            for line in output.splitlines():
                if "OS details:" in line:
                    os_info = line.split("OS details:")[1].strip()
                    results["os_info"] = os_info
                    print(f"{Fore.GREEN}OS Detection: {os_info}{Style.RESET_ALL}")
                    break
        except Exception as e:
            print(f"{Fore.RED}Error detecting OS: {str(e)}{Style.RESET_ALL}")
        
        return results
    
    def run_ip_port_scan(self, ip):
        """Run comprehensive port scan on an IP address"""
        print(f"{Fore.YELLOW}Starting comprehensive port scan on {ip}...{Style.RESET_ALL}")
        
        # Run a more comprehensive port scan for IP targets
        try:
            print(f"{Fore.CYAN}Running quick port scan (top 1000 ports)...{Style.RESET_ALL}")
            output, _ = self.run_custom_command(f"nmap -sV -sC --top-ports 1000 {ip}")
            
            # Extract open ports and services
            open_ports = []
            for line in output.splitlines():
                if "/tcp" in line and "open" in line:
                    port = line.split("/")[0].strip()
                    service = line.split("open")[1].strip()
                    open_ports.append((port, service))
                    print(f"{Fore.GREEN}Open port {port}: {service}{Style.RESET_ALL}")
            
            # If the initial scan found less than 5 ports, run a full port scan
            if len(open_ports) < 5:
                print(f"{Fore.CYAN}Running full port scan...{Style.RESET_ALL}")
                output, _ = self.run_custom_command(f"nmap -sV -sC -p- {ip}")
                
                # Extract additional open ports
                for line in output.splitlines():
                    if "/tcp" in line and "open" in line:
                        port = line.split("/")[0].strip()
                        service = line.split("open")[1].strip()
                        if (port, service) not in open_ports:
                            open_ports.append((port, service))
                            print(f"{Fore.GREEN}Additional open port {port}: {service}{Style.RESET_ALL}")
            
            return open_ports
        except Exception as e:
            print(f"{Fore.RED}Error during port scan: {str(e)}{Style.RESET_ALL}")
            return []
    
    def run_command(self, command, tool_name):
        """Run a shell command and return the output"""
        output_file = os.path.join(self.output_dir, f"{tool_name}_{int(time.time())}.txt")
        
        try:
            logger.info(f"Running {tool_name}: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True)
            
            with open(output_file, 'w') as f:
                f.write(result.stdout)
                if result.stderr:
                    f.write("\n\nERRORS:\n")
                    f.write(result.stderr)
            
            logger.info(f"{tool_name} completed. Output saved to {output_file}")
            return result.stdout, output_file
        except Exception as e:
            logger.error(f"Error running {tool_name}: {str(e)}")
            return None, None
    
    def run_nmap(self):
        """Run Nmap scan on the target"""
        command = ["nmap", "-sV", "-sC", "-p-", "--open", "-oN", f"{self.output_dir}/nmap_scan.txt", self.target]
        return self.run_command(command, "nmap")
    
    def run_sqlmap(self, urls):
        """Run SQLMap on discovered URLs"""
        results = []
        for url in urls:
            command = ["sqlmap", "-u", url, "--batch", "--level=3", "--risk=2"]
            output, file_path = self.run_command(command, f"sqlmap_{url.replace('://', '_').replace('/', '_')}")
            results.append((url, output, file_path))
        return results
    
    def run_ffuf(self):
        """Run ffuf for directory and file discovery"""
        wordlist = "/usr/share/wordlists/dirb/common.txt"  # Default Kali wordlist
        command = ["ffuf", "-u", f"https://{self.target}/FUZZ", "-w", wordlist, "-o", f"{self.output_dir}/ffuf_results.json", "-of", "json"]
        return self.run_command(command, "ffuf")
    
    def run_nikto(self):
        """Run Nikto web scanner"""
        command = ["nikto", "-h", self.target, "-output", f"{self.output_dir}/nikto_scan.txt"]
        return self.run_command(command, "nikto")
    
    def run_nuclei(self):
        """Run Nuclei for vulnerability scanning"""
        # Use nuclei with OWASP templates
        command = ["nuclei", "-u", self.target, "-o", f"{self.output_dir}/nuclei_results.txt", 
                   "-t", "cves/,vulnerabilities/,owasp/"]
        return self.run_command(command, "nuclei")
    
    def run_owasp_zap(self):
        """Run OWASP ZAP for web application scanning"""
        try:
            logger.info("Running OWASP ZAP scan")
            # Using ZAP in headless mode with API
            command = ["zap-cli", "--zap-path", "/usr/share/zaproxy", "quick-scan", "--self-contained",
                      "--start-options", "-config api.disablekey=true", "-t", f"https://{self.target}"]
            return self.run_command(command, "owasp_zap")
        except Exception as e:
            logger.error(f"Error running OWASP ZAP: {str(e)}")
            return None, None
    
    def run_owasp_top_10_scan(self):
        """Run specific scans for OWASP Top 10 vulnerabilities"""
        results = {}
        
        # A01:2021-Broken Access Control
        logger.info("Scanning for Broken Access Control (A01:2021)")
        command = ["nuclei", "-u", self.target, "-t", "vulnerabilities/misconfiguration/",
                  "-tags", "access-control,idor,authorization", "-o", f"{self.output_dir}/a01_broken_access.txt"]
        output, file_path = self.run_command(command, "a01_broken_access")
        results["a01_broken_access"] = {"output": output, "file": file_path}
        
        # A02:2021-Cryptographic Failures
        logger.info("Scanning for Cryptographic Failures (A02:2021)")
        command = ["sslyze", self.target, "--json_out", f"{self.output_dir}/a02_crypto_failures.json"]
        output, file_path = self.run_command(command, "a02_crypto_failures")
        results["a02_crypto_failures"] = {"output": output, "file": file_path}
        
        # A03:2021-Injection
        logger.info("Scanning for Injection vulnerabilities (A03:2021)")
        # SQLMap is already handled in the main workflow for discovered URLs
        # Additional XSS scanning
        command = ["nuclei", "-u", self.target, "-t", "vulnerabilities/generic/",
                  "-tags", "xss,injection,sqli,xxe", "-o", f"{self.output_dir}/a03_injection.txt"]
        output, file_path = self.run_command(command, "a03_injection")
        results["a03_injection"] = {"output": output, "file": file_path}
        
        # A04:2021-Insecure Design
        # This is more of an architectural issue, but we can scan for common manifestations
        logger.info("Scanning for Insecure Design issues (A04:2021)")
        command = ["nuclei", "-u", self.target, "-t", "vulnerabilities/generic/",
                  "-tags", "logic-flaw,business-logic", "-o", f"{self.output_dir}/a04_insecure_design.txt"]
        output, file_path = self.run_command(command, "a04_insecure_design")
        results["a04_insecure_design"] = {"output": output, "file": file_path}
        
        # A05:2021-Security Misconfiguration
        logger.info("Scanning for Security Misconfigurations (A05:2021)")
        command = ["nuclei", "-u", self.target, "-t", "vulnerabilities/misconfiguration/",
                  "-o", f"{self.output_dir}/a05_misconfig.txt"]
        output, file_path = self.run_command(command, "a05_misconfig")
        results["a05_misconfig"] = {"output": output, "file": file_path}
        
        # A06:2021-Vulnerable and Outdated Components
        logger.info("Scanning for Vulnerable Components (A06:2021)")
        command = ["nuclei", "-u", self.target, "-t", "vulnerabilities/cves/",
                  "-o", f"{self.output_dir}/a06_vuln_components.txt"]
        output, file_path = self.run_command(command, "a06_vuln_components")
        results["a06_vuln_components"] = {"output": output, "file": file_path}
        
        # A07:2021-Identification and Authentication Failures
        logger.info("Scanning for Authentication Failures (A07:2021)")
        command = ["nuclei", "-u", self.target, "-t", "vulnerabilities/generic/",
                  "-tags", "auth-bypass,default-login,weak-auth", "-o", f"{self.output_dir}/a07_auth_failures.txt"]
        output, file_path = self.run_command(command, "a07_auth_failures")
        results["a07_auth_failures"] = {"output": output, "file": file_path}
        
        # A08:2021-Software and Data Integrity Failures
        logger.info("Scanning for Integrity Failures (A08:2021)")
        command = ["nuclei", "-u", self.target, "-t", "vulnerabilities/generic/",
                  "-tags", "integrity,deserialization", "-o", f"{self.output_dir}/a08_integrity_failures.txt"]
        output, file_path = self.run_command(command, "a08_integrity_failures")
        results["a08_integrity_failures"] = {"output": output, "file": file_path}
        
        # A09:2021-Security Logging and Monitoring Failures
        # This is hard to test externally, but we can check for exposed logs
        logger.info("Scanning for Logging/Monitoring Failures (A09:2021)")
        command = ["ffuf", "-u", f"https://{self.target}/FUZZ", "-w", 
                  "/usr/share/wordlists/SecLists/Discovery/Web-Content/common-log-locations.txt",
                  "-o", f"{self.output_dir}/a09_logging_failures.json", "-of", "json"]
        output, file_path = self.run_command(command, "a09_logging_failures")
        results["a09_logging_failures"] = {"output": output, "file": file_path}
        
        # A10:2021-Server-Side Request Forgery
        logger.info("Scanning for SSRF vulnerabilities (A10:2021)")
        command = ["nuclei", "-u", self.target, "-t", "vulnerabilities/generic/",
                  "-tags", "ssrf", "-o", f"{self.output_dir}/a10_ssrf.txt"]
        output, file_path = self.run_command(command, "a10_ssrf")
        results["a10_ssrf"] = {"output": output, "file": file_path}
        
        return results
    
    def analyze_with_ollama(self, data, prompt_prefix="Analyze this security scan output and identify vulnerabilities:"):
        """Analyze data using Ollama's deepseek-r1:32b model"""
        try:
            logger.info("Analyzing data with Ollama (deepseek-r1:32b)")
            
            # Prepare the prompt with context
            prompt = f"{prompt_prefix}\n\n{data}"
            
            # Run Ollama command
            result = subprocess.run(
                ["ollama", "run", "deepseek-r1:32b", prompt],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Ollama error: {result.stderr}")
                return None
                
            return result.stdout
        except Exception as e:
            logger.error(f"Error using Ollama: {str(e)}")
            return None
    
    def analyze_with_openrouter(self, data, prompt_prefix="Analyze this security scan output and identify vulnerabilities:"):
        """Analyze data using OpenRouter's Qwen model"""
        if not self.openrouter_api_key:
            logger.warning("OpenRouter API key not provided, skipping analysis")
            return None
            
        try:
            logger.info("Analyzing data with OpenRouter (qwen/qwq-32b)")
            
            headers = {
                "Authorization": f"Bearer {self.openrouter_api_key}",
                "Content-Type": "application/json"
            }
            
            # Prepare the prompt with context
            prompt = f"{prompt_prefix}\n\n{data}"
            
            payload = {
                "model": "qwen/qwq-32b",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 2000
            }
            
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                json=payload
            )
            
            if response.status_code != 200:
                logger.error(f"OpenRouter API error: {response.text}")
                return None
                
            result = response.json()
            return result["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"Error using OpenRouter: {str(e)}")
            return None
    
    def extract_urls_from_ffuf(self, ffuf_output_file):
        """Extract discovered URLs from ffuf output"""
        try:
            with open(ffuf_output_file, 'r') as f:
                data = json.load(f)
                
            urls = []
            for result in data.get("results", []):
                if result.get("status", 0) in [200, 201, 202, 203, 204]:
                    urls.append(f"https://{self.target}/{result.get('url', '').split('FUZZ')[1]}")
            
            return urls
        except Exception as e:
            logger.error(f"Error extracting URLs from ffuf output: {str(e)}")
            return []
    
    def generate_report(self, scan_results):
        """Generate a comprehensive report from all scan results"""
        report_file = os.path.join(self.output_dir, "final_report.md")
        
        with open(report_file, 'w') as f:
            f.write(f"# Bug Bounty Scan Report for {self.target}\n\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Executive Summary\n\n")
            f.write("This report contains the findings from an automated bug bounty scan with a focus on OWASP Top 10 vulnerabilities.\n\n")
            
            f.write("## AI Analysis\n\n")
            if scan_results.get("ollama_analysis"):
                f.write("### Ollama Analysis\n\n")
                f.write(scan_results.get("ollama_analysis", "No analysis available") + "\n\n")
                
            if scan_results.get("openrouter_analysis"):
                f.write("### OpenRouter Analysis\n\n")
                f.write(scan_results.get("openrouter_analysis", "No analysis available") + "\n\n")
            
            f.write("## OWASP Top 10 Findings\n\n")
            
            owasp_categories = {
                "a01_broken_access": "A01:2021 - Broken Access Control",
                "a02_crypto_failures": "A02:2021 - Cryptographic Failures",
                "a03_injection": "A03:2021 - Injection",
                "a04_insecure_design": "A04:2021 - Insecure Design",
                "a05_misconfig": "A05:2021 - Security Misconfiguration",
                "a06_vuln_components": "A06:2021 - Vulnerable and Outdated Components",
                "a07_auth_failures": "A07:2021 - Identification and Authentication Failures",
                "a08_integrity_failures": "A08:2021 - Software and Data Integrity Failures",
                "a09_logging_failures": "A09:2021 - Security Logging and Monitoring Failures",
                "a10_ssrf": "A10:2021 - Server-Side Request Forgery"
            }
            
            if "owasp_top_10" in scan_results:
                for category_key, category_name in owasp_categories.items():
                    if category_key in scan_results["owasp_top_10"]:
                        f.write(f"### {category_name}\n\n")
                        data = scan_results["owasp_top_10"][category_key]
                        if isinstance(data, dict) and "file" in data:
                            f.write(f"Full results available in: {data['file']}\n\n")
                            if "output" in data and data["output"]:
                                # Extract and show only the first few findings
                                findings = data["output"].split("\n")
                                significant_findings = [line for line in findings if "[" in line and "]" in line][:5]
                                if significant_findings:
                                    f.write("Key findings:\n\n")
                                    for finding in significant_findings:
                                        f.write(f"- {finding}\n")
                                    f.write("\n")
                                else:
                                    f.write("No significant findings.\n\n")
            
            f.write("## Other Scan Results\n\n")
            
            for tool, data in scan_results.items():
                if tool not in ["ollama_analysis", "openrouter_analysis", "owasp_top_10"]:
                    f.write(f"### {tool.capitalize()} Results\n\n")
                    if isinstance(data, dict) and "file" in data:
                        f.write(f"Full results available in: {data['file']}\n\n")
                        if "summary" in data:
                            f.write(data["summary"] + "\n\n")
                    elif isinstance(data, str):
                        f.write(data + "\n\n")
            
            f.write("## Recommendations\n\n")
            f.write("Based on the findings, consider the following recommendations:\n\n")
            f.write("1. Review and patch identified vulnerabilities\n")
            f.write("2. Implement proper input validation and output encoding\n")
            f.write("3. Update outdated software and components\n")
            f.write("4. Implement proper access controls\n")
            f.write("5. Use secure cryptographic protocols and algorithms\n")
            f.write("6. Implement proper authentication mechanisms\n")
            f.write("7. Validate and sanitize all user inputs\n")
            f.write("8. Implement proper logging and monitoring\n")
            f.write("9. Use secure coding practices\n")
            f.write("10. Conduct regular security assessments\n\n")
            
            f.write("## Conclusion\n\n")
            f.write("This automated scan provides an initial assessment of potential security issues with a focus on OWASP Top 10 vulnerabilities. ")
            f.write("Manual verification is recommended for all findings to eliminate false positives.\n")
        
        logger.info(f"Report generated: {report_file}")
        return report_file
    
    def run_scan(self):
        """Run the complete bug bounty workflow"""
        scan_results = {}
        
        # Run Nmap scan
        nmap_output, nmap_file = self.run_nmap()
        if nmap_output:
            scan_results["nmap"] = {"output": nmap_output, "file": nmap_file}
        
        # Run ffuf for directory discovery
        ffuf_output, ffuf_file = self.run_ffuf()
        if ffuf_output:
            scan_results["ffuf"] = {"output": ffuf_output, "file": ffuf_file}
            
            # Extract URLs from ffuf results
            urls = self.extract_urls_from_ffuf(f"{self.output_dir}/ffuf_results.json")
            
            # Run SQLMap on discovered URLs
            if urls:
                sqlmap_results = self.run_sqlmap(urls[:5])  # Limit to first 5 URLs to avoid long scans
                scan_results["sqlmap"] = {"results": sqlmap_results}
        
        # Run Nikto
        nikto_output, nikto_file = self.run_nikto()
        if nikto_output:
            scan_results["nikto"] = {"output": nikto_output, "file": nikto_file}
        
        # Run Nuclei
        nuclei_output, nuclei_file = self.run_nuclei()
        if nuclei_output:
            scan_results["nuclei"] = {"output": nuclei_output, "file": nuclei_file}
        
        # Run OWASP ZAP
        zap_output, zap_file = self.run_owasp_zap()
        if zap_output:
            scan_results["owasp_zap"] = {"output": zap_output, "file": zap_file}
        
        # Run OWASP Top 10 specific scans
        owasp_results = self.run_owasp_top_10_scan()
        if owasp_results:
            scan_results["owasp_top_10"] = owasp_results
        
        # Combine all outputs for AI analysis
        combined_output = ""
        for tool, data in scan_results.items():
            if isinstance(data, dict) and "output" in data:
                combined_output += f"\n\n--- {tool.upper()} RESULTS ---\n\n"
                combined_output += data["output"]
            elif tool == "owasp_top_10":
                for owasp_category, owasp_data in data.items():
                    if isinstance(owasp_data, dict) and "output" in owasp_data:
                        combined_output += f"\n\n--- {owasp_category.upper()} RESULTS ---\n\n"
                        combined_output += owasp_data["output"]
        
        # Analyze with Ollama
        ollama_analysis = self.analyze_with_ollama(
            combined_output, 
            "You are a cybersecurity expert. Analyze these security scan results and identify vulnerabilities, their severity, and recommended fixes. Focus on the OWASP Top 10 vulnerabilities and provide detailed explanations:"
        )
        if ollama_analysis:
            scan_results["ollama_analysis"] = ollama_analysis
        
        # Analyze with OpenRouter
        openrouter_analysis = self.analyze_with_openrouter(
            combined_output,
            "You are a cybersecurity expert. Analyze these security scan results and identify vulnerabilities, their severity, and recommended fixes. Focus on the OWASP Top 10 vulnerabilities and provide detailed explanations:"
        )
        if openrouter_analysis:
            scan_results["openrouter_analysis"] = openrouter_analysis
        
        # Generate final report
        report_file = self.generate_report(scan_results)
        
        logger.info(f"Scan completed for {self.target}. Report available at {report_file}")
        return report_file
    
    def get_available_ollama_models(self):
        """Get list of available models from Ollama"""
        try:
            result = subprocess.run(["ollama", "list"], capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Error getting Ollama models: {result.stderr}")
                return []
            
            models = []
            lines = result.stdout.strip().split('\n')
            # Skip header line
            for line in lines[1:]:
                parts = line.split()
                if parts:
                    models.append(parts[0])
            
            return models
        except Exception as e:
            logger.error(f"Error listing Ollama models: {str(e)}")
            return []
    
    def run_custom_command(self, command_str):
        """Run a custom command and return the output"""
        try:
            # Split the command string into components
            command = shlex.split(command_str)
            tool_name = command[0]
            
            logger.info(f"Running custom command: {command_str}")
            
            # Check if firewall evasion is enabled
            if self.firewall_evasion and tool_name in ["nmap", "masscan"]:
                logger.info("Firewall evasion active, modifying scan parameters")
                if tool_name == "nmap":
                    # Add firewall evasion techniques to nmap
                    for i, arg in enumerate(command):
                        if arg.startswith('-'):
                            command[i] = arg + "D" if 'D' not in arg else arg
                    command.extend(["-f", "--data-length", "24", "--randomize-hosts"])
                elif tool_name == "masscan":
                    command.extend(["--rate", "10"])
            
            result = subprocess.run(command, capture_output=True, text=True)
            
            output_file = os.path.join(self.output_dir, f"custom_{tool_name}_{int(time.time())}.txt")
            with open(output_file, 'w') as f:
                f.write(f"Command: {command_str}\n\n")
                f.write(result.stdout)
                if result.stderr:
                    f.write("\n\nERRORS:\n")
                    f.write(result.stderr)
            
            logger.info(f"Custom command completed. Output saved to {output_file}")
            
            # Store the results
            self.current_scan_results[tool_name] = {
                "command": command_str,
                "output": result.stdout,
                "file": output_file
            }
            
            return result.stdout, output_file
        except Exception as e:
            logger.error(f"Error running custom command: {str(e)}")
            return f"Error: {str(e)}", None
    
    def chat_with_ollama(self, user_input, system_prompt=None):
        """Chat with Ollama model"""
        try:
            # Use the persona-specific prompt if system_prompt is not provided
            if not system_prompt and self.ai_persona in AI_PERSONAS:
                system_prompt = AI_PERSONAS[self.ai_persona]["prompt_prefix"]
            
            # Create a comprehensive prompt with context
            context = ""
            if self.current_scan_results:
                context += "Recent scan results:\n"
                for tool, data in self.current_scan_results.items():
                    if isinstance(data, dict) and "output" in data:
                        context += f"\n--- {tool.upper()} RESULTS ---\n"
                        # Limit the output to avoid overwhelming the model
                        output_excerpt = data["output"][:1000] + "..." if len(data["output"]) > 1000 else data["output"]
                        context += output_excerpt + "\n"
            
            # Prepare the prompt
            if system_prompt:
                prompt = f"{system_prompt}\n\nTarget: {self.target if self.target else 'Not specified'}\n\n{context}\n\nUser: {user_input}"
            else:
                prompt = f"Target: {self.target if self.target else 'Not specified'}\n\n{context}\n\nUser: {user_input}"
            
            # Run Ollama command
            logger.info(f"Querying Ollama model: {self.ollama_model}")
            result = subprocess.run(
                ["ollama", "run", self.ollama_model, prompt],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Ollama error: {result.stderr}")
                return "Error communicating with Ollama. Please check if it's running."
            
            # Save the interaction to history
            self.chat_history.append({"user": user_input, "ai": result.stdout})
            
            return result.stdout
        except Exception as e:
            logger.error(f"Error chatting with Ollama: {str(e)}")
            return f"Error: {str(e)}"
    
    def parse_intent(self, user_input):
        """Parse user input to identify intent and extract parameters"""
        user_input = user_input.lower()
        
        # Check for hack intent
        if (user_input == "hack" or "start hacking" in user_input or "hack the target" in user_input or 
            "attack" in user_input or "pwn" in user_input):
            if self.target:
                return {"intent": "hack", "target": self.target}
            else:
                return {"intent": "error", "message": "No target set. Please set a target first with 'set target example.com' or 'set target 192.168.1.1'"}
        
        # Check for subdomain enumeration intent (domain targets only)
        if ("find subdomains" in user_input or "enumerate subdomains" in user_input or 
            "subdomain enumeration" in user_input or "discover subdomains" in user_input):
            # Check if target is a domain
            if self.target and self.get_target_type() == "domain":
                return {"intent": "enumerate_subdomains", "target": self.target}
            elif self.target and self.get_target_type() == "ip":
                return {"intent": "error", "message": "Subdomain enumeration only works on domain targets, not IP addresses. Your current target is an IP address."}
            else:
                # Try to extract target from command
                target_match = re.search(r'(?:of|for|on)\s+([a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,})', user_input)
                if target_match:
                    target = target_match.group(1)
                    return {"intent": "enumerate_subdomains", "target": target}
                else:
                    return {"intent": "error", "message": "No domain target specified. Please set a domain target first with 'set target example.com'"}
        
        # Check for port scan intent
        if "port scan" in user_input or "scan ports" in user_input or "find open ports" in user_input or "nmap" in user_input:
            if self.target:
                return {"intent": "port_scan", "target": self.target}
            else:
                # Try to extract target from command (could be domain or IP)
                target_match = re.search(r'(?:of|for|on)\s+((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}))', user_input)
                if target_match:
                    target = target_match.group(1)
                    return {"intent": "port_scan", "target": target}
                else:
                    return {"intent": "error", "message": "No target specified. Please set a target first with 'set target example.com' or 'set target 192.168.1.1'"}
        
        # Check for vulnerability scan intent
        if "vuln scan" in user_input or "vulnerability scan" in user_input or "find vulnerabilities" in user_input:
            if self.target:
                return {"intent": "vuln_scan", "target": self.target}
            else:
                # Try to extract target from command (could be domain or IP)
                target_match = re.search(r'(?:of|for|on)\s+((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}))', user_input)
                if target_match:
                    target = target_match.group(1)
                    return {"intent": "vuln_scan", "target": target}
                else:
                    return {"intent": "error", "message": "No target specified. Please set a target first with 'set target example.com' or 'set target 192.168.1.1'"}
        
        # Check for web scan intent
        if "web scan" in user_input or "scan website" in user_input or "check website" in user_input:
            if self.target:
                return {"intent": "web_scan", "target": self.target}
            else:
                # Try to extract target from command
                target_match = re.search(r'(?:of|for|on)\s+((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}))', user_input)
                if target_match:
                    target = target_match.group(1)
                    return {"intent": "web_scan", "target": target}
                else:
                    return {"intent": "error", "message": "No target specified. Please set a target first with 'set target example.com' or 'set target 192.168.1.1'"}
        
        # Check for recon intent
        if "recon" in user_input or "reconnaissance" in user_input or "gather info" in user_input:
            if self.target:
                return {"intent": "recon", "target": self.target}
            else:
                # Try to extract target from command
                target_match = re.search(r'(?:of|for|on)\s+((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}))', user_input)
                if target_match:
                    target = target_match.group(1)
                    return {"intent": "recon", "target": target}
                else:
                    return {"intent": "error", "message": "No target specified. Please set a target first with 'set target example.com' or 'set target 192.168.1.1'"}
        
        # Check for scan intent with more specific patterns
        scan_patterns = [
            r"scan\s+(?:for\s+)?(?:open\s+)?ports?\s+(?:on\s+)?(.+)",
            r"run\s+nmap\s+(?:on\s+)?(.+)",
            r"check\s+(?:if\s+)?(.+)\s+is\s+vulnerable",
            r"test\s+(?:the\s+)?security\s+of\s+(.+)",
            r"scan\s+(.+)\s+for\s+vulnerabilities",
            r"scan\s+(.+)"
        ]
        
        for pattern in scan_patterns:
            match = re.search(pattern, user_input)
            if match:
                target = match.group(1).strip()
                return {"intent": "scan", "target": target}
        
        # Check for tool execution intent
        for tool in KALI_TOOLS.keys():
            if f"run {tool}" in user_input or f"execute {tool}" in user_input or f"use {tool}" in user_input:
                # Try to extract parameters
                params_pattern = f"(?:run|execute|use)\\s+{tool}\\s+(.+)"
                match = re.search(params_pattern, user_input)
                params = match.group(1) if match else ""
                return {"intent": "run_tool", "tool": tool, "params": params}
        
        # Check for changing target
        target_patterns = [
            r"set\s+target\s+(?:to\s+)?(.+)",
            r"change\s+target\s+(?:to\s+)?(.+)",
            r"target\s+is\s+(.+)",
            r"target\s+(.+)"
        ]
        
        for pattern in target_patterns:
            match = re.search(pattern, user_input)
            if match:
                target = match.group(1).strip()
                return {"intent": "set_target", "target": target}
        
        # Check for firewall evasion
        if "evade firewall" in user_input or "bypass firewall" in user_input or "firewall evasion" in user_input:
            return {"intent": "toggle_firewall_evasion"}
        
        # Check for switching AI model
        if "use model" in user_input or "switch model" in user_input or "change model" in user_input:
            model_pattern = r"(?:use|switch|change)\\s+model\\s+(?:to\s+)?(.+)"
            match = re.search(model_pattern, user_input)
            if match:
                model = match.group(1).strip()
                return {"intent": "switch_model", "model": model}
        
        # Check for switching persona
        if "switch persona" in user_input or "change persona" in user_input:
            persona_pattern = r"(?:switch|change)\\s+persona\\s+(?:to\s+)?(.+)"
            match = re.search(persona_pattern, user_input)
            if match:
                persona = match.group(1).strip()
                return {"intent": "switch_persona", "persona": persona}
        
        # Check for domain or IP pattern in the user input
        # This detects both IP addresses and domain names
        target_pattern = r'((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+))'
        target_match = re.search(target_pattern, user_input)
        if target_match and not any(x in user_input for x in ["scan", "target", "execute", "run", "use"]):
            target = target_match.group(0)
            return {"intent": "set_target_and_suggest_hack", "target": target}
        
        # Default to chat intent
        return {"intent": "chat", "message": user_input}
    
    def execute_intent(self, intent_data):
        """Execute the identified intent"""
        intent = intent_data.get("intent", "chat")
        
        if intent == "error":
            return intent_data.get("message", "An error occurred")
        
        elif intent == "hack":
            target = intent_data.get("target", self.target)
            if not target:
                return "No target specified. Please set a target first."
            
            # Run the complete hacking process
            return self.run_complete_hack(target)
        
        elif intent == "enumerate_subdomains":
            target = intent_data.get("target", self.target)
            if not target:
                return "No target specified. Please set a target first."
            
            # Set as current target if not already
            if self.target != target:
                self.target = target
                
            # Run subdomain enumeration
            print(f"{Fore.GREEN}Starting subdomain enumeration for {target}...{Style.RESET_ALL}")
            subdomains = self.run_subdomain_enumeration(target)
            
            # Format the response
            if len(subdomains) > 1:
                response = f"Found {len(subdomains)} subdomains for {target}:\n\n"
                for i, subdomain in enumerate(subdomains, 1):
                    response += f"{i}. {subdomain}\n"
            else:
                response = f"Could not find any subdomains for {target} or only the main domain is accessible."
            
            return response
            
        elif intent == "port_scan":
            target = intent_data.get("target", self.target)
            if not target:
                return "No target specified. Please set a target first."
            
            # Set as current target if not already
            if self.target != target:
                self.target = target
            
            # Run port scan
            print(f"{Fore.GREEN}Starting port scan on {target}...{Style.RESET_ALL}")
            port_results = self.run_port_scan([target])
            
            # Format the response
            response = f"Port scan results for {target}:\n\n"
            if target in port_results and port_results[target]:
                for port, service in port_results[target]:
                    response += f"Port {port}: {service}\n"
            else:
                response += "No open ports found or the host is not responding."
            
            return response
            
        elif intent == "vuln_scan":
            target = intent_data.get("target", self.target)
            if not target:
                return "No target specified. Please set a target first."
            
            # Set as current target if not already
            if self.target != target:
                self.target = target
            
            # Run vulnerability scan
            print(f"{Fore.GREEN}Starting vulnerability scan on {target}...{Style.RESET_ALL}")
            vuln_results = self.run_vulnerability_scan([target])
            
            # Format the response
            response = f"Vulnerability scan results for {target}:\n\n"
            if target in vuln_results and vuln_results[target]:
                for vuln in vuln_results[target]:
                    response += f"- {vuln}\n"
            else:
                response += "No vulnerabilities found or the host is not responding."
            
            return response
            
        elif intent == "web_scan":
            target = intent_data.get("target", self.target)
            if not target:
                return "No target specified. Please set a target first."
            
            # Set as current target if not already
            if self.target != target:
                self.target = target
            
            # Run web scan
            print(f"{Fore.GREEN}Starting web scan on {target}...{Style.RESET_ALL}")
            web_results = self.run_web_scan([target])
            
            # Format the response
            response = f"Web scan results for {target}:\n\n"
            if target in web_results:
                response += "Vulnerabilities:\n"
                if web_results[target]["vulnerabilities"]:
                    for vuln in web_results[target]["vulnerabilities"]:
                        response += f"- {vuln}\n"
                else:
                    response += "No web vulnerabilities found.\n"
                
                response += "\nDirectories:\n"
                if web_results[target]["directories"]:
                    for directory in web_results[target]["directories"][:15]:  # Limit to 15 directories to avoid verbose output
                        response += f"- {directory}\n"
                    if len(web_results[target]["directories"]) > 15:
                        response += f"- ... and {len(web_results[target]['directories']) - 15} more\n"
                else:
                    response += "No interesting directories found.\n"
            else:
                response += "Could not scan the target or the host is not responding."
            
            return response
            
        elif intent == "set_target_and_suggest_hack":
            self.target = intent_data["target"]
            return f"Target set to {self.target}. Would you like me to start hacking this target? Type 'hack' to begin a comprehensive scan."
        
        elif intent == "scan":
            target = intent_data["target"]
            self.target = target
            return self.start_scan_in_thread()
        
        elif intent == "run_tool":
            tool = intent_data["tool"]
            params = intent_data.get("params", "")
            
            if not self.target and not any(param for param in params.split() if "." in param):
                return f"Please set a target first with 'set target example.com'"
            
            # Construct the command
            if self.target and not any(param for param in params.split() if "." in param):
                command = f"{tool} {params} {self.target}"
            else:
                command = f"{tool} {params}"
            
            output, _ = self.run_custom_command(command)
            return f"Executed {tool}:\n\n{output[:1000]}..." if len(output) > 1000 else f"Executed {tool}:\n\n{output}"
        
        elif intent == "set_target":
            self.target = intent_data["target"]
            return f"Target set to {self.target}"
        
        elif intent == "toggle_firewall_evasion":
            self.firewall_evasion = not self.firewall_evasion
            return f"Firewall evasion {'enabled' if self.firewall_evasion else 'disabled'}"
        
        elif intent == "switch_model":
            requested_model = intent_data["model"]
            available_models = self.get_available_ollama_models()
            
            # Try to find the closest matching model
            matching_models = [model for model in available_models if requested_model.lower() in model.lower()]
            
            if matching_models:
                self.ollama_model = matching_models[0]
                return f"Switched to model: {self.ollama_model}"
            else:
                models_str = "\n".join(available_models)
                return f"Model '{requested_model}' not found. Available models:\n{models_str}"
        
        elif intent == "switch_persona":
            requested_persona = intent_data["persona"].lower()
            
            # Find the closest matching persona
            if requested_persona in AI_PERSONAS:
                self.ai_persona = requested_persona
                return f"Switched to {AI_PERSONAS[requested_persona]['name']} persona"
            else:
                personas_str = "\n".join([f"{persona}: {data['name']}" for persona, data in AI_PERSONAS.items()])
                return f"Persona '{requested_persona}' not found. Available personas:\n{personas_str}"
        
        elif intent == "chat":
            return self.chat_with_ollama(intent_data["message"])
        
        elif intent == "recon":
            target = intent_data.get("target", self.target)
            if not target:
                return "No target specified. Please set a target first."
            
            # Set as current target if not already
            if self.target != target:
                self.target = target
                
            target_type = self.get_target_type()
            print(f"{Fore.GREEN}Starting reconnaissance on {target} ({target_type.upper()})...{Style.RESET_ALL}")
            
            if target_type == "ip":
                # Run IP reconnaissance
                recon_results = self.run_ip_reconnaissance(target)
                
                # Format the response for IP recon
                response = f"Reconnaissance results for IP {target}:\n\n"
                
                if recon_results.get("hostname"):
                    response += f"Hostname: {recon_results['hostname']}\n"
                
                if recon_results.get("os_info"):
                    response += f"OS Detection: {recon_results['os_info']}\n"
                
                if recon_results.get("geolocation"):
                    geo = recon_results["geolocation"]
                    response += f"Geolocation: {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}, {geo.get('country', 'Unknown')}\n"
                
                if recon_results.get("asn_info"):
                    response += f"Organization: {recon_results['asn_info']}\n"
                
                # Add ports if discovered during recon
                if recon_results.get("ports"):
                    response += "\nDiscovered ports:\n"
                    for port, service in recon_results["ports"]:
                        response += f"- Port {port}: {service}\n"
            else:
                # Run domain reconnaissance
                try:
                    # Create target-specific directory for outputs
                    target_dir = os.path.join(self.output_dir, target.replace(".", "_"))
                    os.makedirs(target_dir, exist_ok=True)
                    
                    # Get IP address
                    ip = socket.gethostbyname(target)
                    response = f"Reconnaissance results for {target}:\n\n"
                    response += f"IP Address: {ip}\n"
                    
                    # Get WHOIS info
                    try:
                        output, _ = self.run_custom_command(f"whois {target}")
                        whois_file = os.path.join(target_dir, "whois.txt")
                        with open(whois_file, 'w') as f:
                            f.write(output)
                        print(f"{Fore.GREEN}WHOIS information retrieved and saved to {whois_file}{Style.RESET_ALL}")
                        
                        # Extract important WHOIS info
                        whois_data = {}
                        for line in output.splitlines():
                            for field in ["Registrar:", "Registrant", "Admin", "Tech", "Name Server:", "Created:", "Updated:", "Expires:"]:
                                if field in line:
                                    key = field.replace(":", "").strip().lower()
                                    value = line.split(field)[1].strip()
                                    whois_data[key] = value
                                    print(f"{Fore.GREEN}{field} {value}{Style.RESET_ALL}")
                    except Exception as e:
                        response += f"Error getting WHOIS info: {str(e)}\n"
                    
                    # DNS enumeration
                    try:
                        output, _ = self.run_custom_command(f"dig +nocmd {target} any +noall +answer")
                        if output.strip():
                            response += "\nDNS Records:\n"
                            for line in output.splitlines():
                                if target in line:
                                    response += f"- {line}\n"
                    except Exception as e:
                        response += f"Error performing DNS enumeration: {str(e)}\n"
                
                except Exception as e:
                    response = f"Error during domain reconnaissance: {str(e)}"
            
            return response
    
    def start_scan_in_thread(self):
        """Start the scan in a separate thread to keep the chat responsive"""
        if self.is_scanning:
            return "A scan is already in progress. Please wait for it to complete."
        
        if not self.target:
            return "Please set a target first with 'set target example.com'"
        
        self.is_scanning = True
        self.scan_thread = threading.Thread(target=self._run_scan_thread)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        return f"Starting scan against {self.target}. This will run in the background. You can continue chatting while it runs."
    
    def _run_scan_thread(self):
        """Run the scan in a separate thread"""
        try:
            self.run_scan()
        finally:
            self.is_scanning = False
    
    def run_subdomain_enumeration(self, domain):
        """Run enhanced subdomain enumeration with a focus on subfinder and httpx"""
        print(f"{Fore.YELLOW}Starting comprehensive subdomain enumeration for {domain}...{Style.RESET_ALL}")
        
        all_subdomains = set()
        alive_subdomains = set()
        
        # Function to add subdomains from a file to our set
        def add_subdomains_from_file(file_path):
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            subdomain = line.strip()
                            if subdomain:
                                all_subdomains.add(subdomain)
                except Exception as e:
                    print(f"{Fore.RED}Error reading {file_path}: {str(e)}{Style.RESET_ALL}")
        
        # Create a directory for all subdomain results
        subdomain_dir = os.path.join(self.output_dir, f"subdomains_{domain}")
        os.makedirs(subdomain_dir, exist_ok=True)
        
        # 1. First try subfinder (prioritized)
        try:
            print(f"{Fore.CYAN}Running subfinder for comprehensive subdomain discovery...{Style.RESET_ALL}")
            
            # Check if subfinder is installed
            if check_tool_availability("subfinder"):
                subfinder_file = os.path.join(subdomain_dir, "subfinder.txt")
                # Run subfinder with all sources for maximum coverage
                self.run_custom_command(f"subfinder -d {domain} -all -o {subfinder_file}")
                add_subdomains_from_file(subfinder_file)
                print(f"{Fore.GREEN}Subfinder found {len(all_subdomains)} subdomains{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}subfinder not found. Attempting to install...{Style.RESET_ALL}")
                if platform.system() == "Linux":
                    try:
                        self.run_custom_command("GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
                        print(f"{Fore.GREEN}subfinder installed successfully!{Style.RESET_ALL}")
                        # Run subfinder after installation
                        subfinder_file = os.path.join(subdomain_dir, "subfinder.txt")
                        self.run_custom_command(f"subfinder -d {domain} -all -o {subfinder_file}")
                        add_subdomains_from_file(subfinder_file)
                    except Exception as e:
                        print(f"{Fore.RED}Error installing subfinder: {str(e)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error running subfinder: {str(e)}{Style.RESET_ALL}")
        
        # 2. Use amass as backup
        if len(all_subdomains) < 5:
            try:
                print(f"{Fore.CYAN}Running amass for additional subdomain discovery...{Style.RESET_ALL}")
                if check_tool_availability("amass"):
                    amass_file = os.path.join(subdomain_dir, "amass.txt")
                    self.run_custom_command(f"amass enum -passive -d {domain} -o {amass_file}")
                    add_subdomains_from_file(amass_file)
                    print(f"{Fore.GREEN}Amass found additional subdomains. Total: {len(all_subdomains)}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}amass not found. Attempting to install...{Style.RESET_ALL}")
                    if platform.system() == "Linux":
                        try:
                            self.run_custom_command("apt-get update && apt-get install -y amass")
                            print(f"{Fore.GREEN}amass installed successfully!{Style.RESET_ALL}")
                            # Run amass after installation
                            amass_file = os.path.join(subdomain_dir, "amass.txt")
                            self.run_custom_command(f"amass enum -passive -d {domain} -o {amass_file}")
                            add_subdomains_from_file(amass_file)
                        except Exception as e:
                            print(f"{Fore.RED}Error installing amass: {str(e)}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error running amass: {str(e)}{Style.RESET_ALL}")
        
        # 3. Try other tools if we still have few results
        if len(all_subdomains) < 10:
            other_tools = [
                ("assetfinder", f"assetfinder --subs-only {domain} > {os.path.join(subdomain_dir, 'assetfinder.txt')}", "github.com/tomnomnom/assetfinder@latest"),
                ("findomain", f"findomain -t {domain} -o {os.path.join(subdomain_dir, 'findomain.txt')}", "github.com/Findomain/findomain/releases/latest/download/findomain-linux")
            ]
            
            for tool_name, command, install_source in other_tools:
                try:
                    print(f"{Fore.CYAN}Running {tool_name} for additional subdomain discovery...{Style.RESET_ALL}")
                    if check_tool_availability(tool_name):
                        self.run_custom_command(command)
                        add_subdomains_from_file(os.path.join(subdomain_dir, f"{tool_name}.txt"))
                        print(f"{Fore.GREEN}{tool_name} found additional subdomains. Total: {len(all_subdomains)}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}{tool_name} not found. Attempting to install...{Style.RESET_ALL}")
                        if platform.system() == "Linux":
                            try:
                                if "github.com" in install_source and install_source.endswith("latest"):
                                    self.run_custom_command(f"GO111MODULE=on go install -v {install_source}")
                                else:
                                    self.run_custom_command(f"wget {install_source} -O /usr/local/bin/{tool_name} && chmod +x /usr/local/bin/{tool_name}")
                                print(f"{Fore.GREEN}{tool_name} installed successfully!{Style.RESET_ALL}")
                                # Run the tool after installation
                                self.run_custom_command(command)
                                add_subdomains_from_file(os.path.join(subdomain_dir, f"{tool_name}.txt"))
                            except Exception as e:
                                print(f"{Fore.RED}Error installing {tool_name}: {str(e)}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}Error running {tool_name}: {str(e)}{Style.RESET_ALL}")
        
        # 4. Certificate transparency logs via crt.sh
        try:
            print(f"{Fore.CYAN}Querying crt.sh for certificates...{Style.RESET_ALL}")
            crtsh_file = os.path.join(subdomain_dir, "crtsh.txt")
            self.run_custom_command(f"curl -s 'https://crt.sh/?q=%.{domain}&output=json' | jq -r '.[].name_value' | sort -u > {crtsh_file}")
            add_subdomains_from_file(crtsh_file)
            print(f"{Fore.GREEN}Certificate transparency search found new subdomains. Total: {len(all_subdomains)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error querying crt.sh: {str(e)}{Style.RESET_ALL}")
        
        # 5. Save all discovered subdomains to a file
        all_subdomains_file = os.path.join(subdomain_dir, "all_subdomains.txt")
        with open(all_subdomains_file, 'w') as f:
            for subdomain in sorted(all_subdomains):
                f.write(f"{subdomain}\n")
        
        print(f"{Fore.GREEN}Found {len(all_subdomains)} total subdomains for {domain}.{Style.RESET_ALL}")
        
        # 6. Check which subdomains are alive using httpx
        print(f"{Fore.YELLOW}Checking alive subdomains and collecting details with httpx...{Style.RESET_ALL}")
        
        try:
            # First check if httpx is installed
            if not check_tool_availability("httpx"):
                print(f"{Fore.RED}httpx not found. Attempting to install...{Style.RESET_ALL}")
                if platform.system() == "Linux":
                    try:
                        self.run_custom_command("GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
                        print(f"{Fore.GREEN}httpx installed successfully!{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}Error installing httpx: {str(e)}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Falling back to manual checking...{Style.RESET_ALL}")
            
            if check_tool_availability("httpx"):
                # Use httpx with enhanced flags for better information gathering
                httpx_file = os.path.join(subdomain_dir, "httpx_details.json")
                httpx_cmd = (
                    f"cat {all_subdomains_file} | httpx -silent -status-code -title -technology -location " +
                    f"-server -ip -cdn -content-type -json -o {httpx_file}"
                )
                self.run_custom_command(httpx_cmd)
                
                # Parse httpx JSON output to extract alive subdomains and their details
                subdomain_details = {}
                if os.path.exists(httpx_file):
                    with open(httpx_file, 'r') as f:
                        for line in f:
                            try:
                                result = json.loads(line)
                                url = result.get("url", "")
                                if url:
                                    # Extract subdomain from URL
                                    parsed_url = urlparse(url)
                                    subdomain = parsed_url.netloc
                                    
                                    # Save to alive subdomains
                                    alive_subdomains.add(subdomain)
                                    
                                    # Store details
                                    subdomain_details[subdomain] = {
                                        "url": url,
                                        "status_code": result.get("status_code"),
                                        "title": result.get("title"),
                                        "server": result.get("server"),
                                        "technologies": result.get("technologies", []),
                                        "ip": result.get("ip"),
                                        "cdn": result.get("cdn", False),
                                        "content_type": result.get("content_type"),
                                        "location": result.get("location")
                                    }
                                    
                                    # Print information about the subdomain
                                    tech_str = ', '.join(result.get("technologies", []))
                                    print(f"{Fore.GREEN}Alive: {subdomain} [{result.get('status_code')}] - IP: {result.get('ip')} - Tech: {tech_str}{Style.RESET_ALL}")
                            except json.JSONDecodeError:
                                continue
                
                # Save subdomain details to a readable file
                details_file = os.path.join(subdomain_dir, "subdomain_details.txt")
                with open(details_file, 'w') as f:
                    f.write(f"Subdomain Details for {domain}\n")
                    f.write("=" * 50 + "\n\n")
                    
                    for subdomain, details in subdomain_details.items():
                        f.write(f"Subdomain: {subdomain}\n")
                        f.write(f"URL: {details['url']}\n")
                        f.write(f"Status Code: {details['status_code']}\n")
                        f.write(f"IP Address: {details['ip']}\n")
                        f.write(f"Title: {details['title']}\n")
                        f.write(f"Server: {details['server']}\n")
                        f.write(f"Technologies: {', '.join(details['technologies'])}\n")
                        f.write(f"CDN: {'Yes' if details['cdn'] else 'No'}\n")
                        f.write(f"Content Type: {details['content_type']}\n")
                        if details['location']:
                            f.write(f"Redirects to: {details['location']}\n")
                        f.write("\n" + "-" * 30 + "\n\n")
            else:
                # Manual checking as fallback
                print(f"{Fore.YELLOW}httpx not available, falling back to manual alive checking...{Style.RESET_ALL}")
                for subdomain in all_subdomains:
                    try:
                        # Try HTTP request first
                        try:
                            response = requests.get(f"http://{subdomain}", timeout=3, verify=False, allow_redirects=True)
                            alive_subdomains.add(subdomain)
                            # Print basic information
                            print(f"{Fore.GREEN}Alive: {subdomain} [{response.status_code}] - Redirect: {response.url if response.history else 'None'}{Style.RESET_ALL}")
                            continue
                        except requests.RequestException:
                            # Try HTTPS if HTTP fails
                            try:
                                response = requests.get(f"https://{subdomain}", timeout=3, verify=False, allow_redirects=True)
                                alive_subdomains.add(subdomain)
                                print(f"{Fore.GREEN}Alive: {subdomain} [{response.status_code}] - Redirect: {response.url if response.history else 'None'}{Style.RESET_ALL}")
                                continue
                            except requests.RequestException:
                                # If both fail, try a simple ping
                                output, _ = self.run_custom_command(f"ping -c 1 -W 2 {subdomain}")
                                if "1 received" in output:
                                    alive_subdomains.add(subdomain)
                                    print(f"{Fore.GREEN}Alive: {subdomain} (ping only){Style.RESET_ALL}")
                                    continue
                                else:
                                    print(f"{Fore.RED}Dead: {subdomain}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}Error checking {subdomain}: {str(e)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error checking alive subdomains: {str(e)}{Style.RESET_ALL}")
        
        # Save alive subdomains to a file
        alive_file = os.path.join(subdomain_dir, "alive_subdomains.txt")
        with open(alive_file, 'w') as f:
            for subdomain in sorted(alive_subdomains):
                f.write(f"{subdomain}\n")
        
        print(f"{Fore.GREEN}Found {len(all_subdomains)} total subdomains, {len(alive_subdomains)} are alive.{Style.RESET_ALL}")
        
        if alive_subdomains:
            return list(alive_subdomains)
        elif all_subdomains:
            # If no alive subdomains but we found some that didn't respond, return first 10
            print(f"{Fore.YELLOW}No alive subdomains found, returning the first 10 discovered subdomains.{Style.RESET_ALL}")
            return list(all_subdomains)[:10]
        else:
            # If no subdomains found, return the main domain
            return [domain]
    
    def run_port_scan(self, targets):
        """Run port scan on targets"""
        print(f"{Fore.YELLOW}Starting port scan on {len(targets)} targets...{Style.RESET_ALL}")
        
        all_results = {}
        for target in targets:
            print(f"{Fore.CYAN}Scanning ports on {target}...{Style.RESET_ALL}")
            
            # Initial quick scan for common ports
            output, _ = self.run_custom_command(f"nmap -sV -sC --top-ports 1000 {target}")
            
            # Extract open ports and services
            open_ports = []
            for line in output.splitlines():
                if "/tcp" in line and "open" in line:
                    port = line.split("/")[0].strip()
                    service = line.split("open")[1].strip()
                    open_ports.append((port, service))
                    print(f"{Fore.GREEN}Open port {port}: {service}{Style.RESET_ALL}")
            
            all_results[target] = open_ports
        
        return all_results
    
    def run_vulnerability_scan(self, targets):
        """Run vulnerability scans on targets"""
        print(f"{Fore.YELLOW}Starting vulnerability scan on {len(targets)} targets...{Style.RESET_ALL}")
        
        results = {}
        
        for target in targets:
            print(f"{Fore.CYAN}Scanning {target} for vulnerabilities...{Style.RESET_ALL}")
            
            # Run nuclei for vulnerability scanning
            output, _ = self.run_custom_command(f"nuclei -u {target} -t cves/,vulnerabilities/,exposures/ -severity critical,high,medium,low -o {self.output_dir}/nuclei_{target.replace(':', '_').replace('/', '_').replace('.', '_')}.txt")
            
            # Extract vulnerabilities
            vulnerabilities = []
            for line in output.splitlines():
                if "[critical]" in line.lower() or "[high]" in line.lower() or "[medium]" in line.lower():
                    vulnerabilities.append(line)
                    if "[critical]" in line.lower() or "[high]" in line.lower():
                        print(f"{Fore.RED}{line}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")
            
            results[target] = vulnerabilities
        
        return results
    
    def run_web_scan(self, targets):
        """Run comprehensive web vulnerability scans"""
        print(f"{Fore.YELLOW}Starting comprehensive web scan on {len(targets)} targets...{Style.RESET_ALL}")
        
        results = {}
        
        for target in targets:
            web_target = target
            if not (web_target.startswith("http://") or web_target.startswith("https://")):
                # First try HTTPS
                try:
                    requests.get(f"https://{web_target}", timeout=3, verify=False)
                    web_target = f"https://{web_target}"
                except:
                    # Fall back to HTTP
                    web_target = f"http://{web_target}"
            
            print(f"{Fore.CYAN}Starting comprehensive web scan for {web_target}...{Style.RESET_ALL}")
            
            # Create a directory for this target's results
            target_dir = os.path.join(self.output_dir, f"web_scan_{target.replace(':', '_').replace('/', '_').replace('.', '_')}")
            os.makedirs(target_dir, exist_ok=True)
            
            web_vulns = []
            directories = []
            
            # 1. Run whatweb for technology detection
            try:
                print(f"{Fore.CYAN}Detecting web technologies with whatweb...{Style.RESET_ALL}")
                whatweb_file = os.path.join(target_dir, "whatweb.txt")
                output, _ = self.run_custom_command(f"whatweb -a 3 {web_target} -v --log-json={whatweb_file}")
                
                # Get top technologies for focused testing
                technologies = []
                try:
                    if os.path.exists(whatweb_file):
                        with open(whatweb_file, 'r') as f:
                            whatweb_data = json.load(f)
                            for entry in whatweb_data:
                                if "plugins" in entry:
                                    technologies.extend(entry["plugins"].keys())
                except:
                    # If JSON parsing fails, extract from output
                    tech_matches = re.findall(r'\[(.*?)\]', output)
                    technologies.extend(tech_matches)
                
                # Clean up technology list
                technologies = [t for t in technologies if t.lower() not in 
                               ['country', 'ip', 'title', 'httpserver', 'uncommonheaders', 'html', 'script', 'url']]
                
                if technologies:
                    print(f"{Fore.GREEN}Detected technologies: {', '.join(technologies[:10])}{Style.RESET_ALL}")
                    web_vulns.append(f"[INFO] Detected technologies: {', '.join(technologies[:10])}")
            except Exception as e:
                print(f"{Fore.RED}Error running whatweb: {str(e)}{Style.RESET_ALL}")
            
            # 2. Run enhanced recursive directory bruteforcing
            try:
                print(f"{Fore.CYAN}Running enhanced recursive directory bruteforcing...{Style.RESET_ALL}")
                discovered_dirs = self.run_recursive_directory_bruteforce(web_target, max_depth=3, output_dir=target_dir)
                
                # Add discovered directories to our results
                if discovered_dirs:
                    directories.extend(discovered_dirs)
                    print(f"{Fore.GREEN}Found {len(discovered_dirs)} directories and files.{Style.RESET_ALL}")
                    
                    # Check for particularly interesting findings
                    sensitive_paths = ["admin", "backup", "config", "db", "dev", "jenkins", "wp-admin", ".git", ".svn", ".env"]
                    for path in discovered_dirs:
                        for sensitive in sensitive_paths:
                            if sensitive in path.lower():
                                web_vulns.append(f"[HIGH] Potentially sensitive path found: {path}")
                                print(f"{Fore.RED}[HIGH] Potentially sensitive path found: {path}{Style.RESET_ALL}")
                                break
                else:
                    print(f"{Fore.YELLOW}No directories found during recursive bruteforcing.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error during recursive directory bruteforcing: {str(e)}{Style.RESET_ALL}")
            
            # 3. Run Nikto for general vulnerabilities
            try:
                print(f"{Fore.CYAN}Running Nikto for vulnerability detection...{Style.RESET_ALL}")
                nikto_file = os.path.join(target_dir, "nikto.txt")
                output, _ = self.run_custom_command(f"nikto -h {web_target} -output {nikto_file}")
                
                nikto_vulns = []
                if output:
                    for line in output.splitlines():
                        if "+ " in line:  # Nikto findings usually start with "+ "
                            nikto_vulns.append(f"[Nikto] {line}")
                    
                    # Add serious findings to results
                    for vuln in nikto_vulns:
                        if any(kw in vuln.lower() for kw in ['critical', 'high', 'csrf', 'xss', 'sql', 'injection', 'overflow']):
                            web_vulns.append(f"[HIGH] {vuln}")
                            print(f"{Fore.RED}{vuln}{Style.RESET_ALL}")
                        else:
                            web_vulns.append(vuln)
                            
                print(f"{Fore.GREEN}Nikto found {len(nikto_vulns)} potential issues{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error running Nikto: {str(e)}{Style.RESET_ALL}")
            
            # 4. Run Nuclei with focused templates
            try:
                print(f"{Fore.CYAN}Running Nuclei scans for known vulnerabilities...{Style.RESET_ALL}")
                nuclei_file = os.path.join(target_dir, "nuclei.txt")
                output, _ = self.run_custom_command(f"nuclei -u {web_target} -t cves/,vulnerabilities/,exposures/,misconfigurations/ -severity critical,high,medium -o {nuclei_file}")
                
                nuclei_vulns = []
                if os.path.exists(nuclei_file):
                    with open(nuclei_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                nuclei_vulns.append(line.strip())
                                if "[critical]" in line.lower() or "[high]" in line.lower():
                                    print(f"{Fore.RED}{line.strip()}{Style.RESET_ALL}")
                                elif "[medium]" in line.lower():
                                    print(f"{Fore.YELLOW}{line.strip()}{Style.RESET_ALL}")
                
                web_vulns.extend(nuclei_vulns)
                print(f"{Fore.GREEN}Nuclei found {len(nuclei_vulns)} vulnerabilities{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error running Nuclei: {str(e)}{Style.RESET_ALL}")
            
            # 5. Run specific tool scans based on detected technologies
            if 'technologies' in locals():
                # WordPress scanning
                if any(t.lower() in ['wordpress', 'wp'] for t in technologies):
                    try:
                        print(f"{Fore.CYAN}WordPress detected, running WPScan...{Style.RESET_ALL}")
                        
                        # Check if wpscan is installed
                        if not check_tool_availability("wpscan"):
                            print(f"{Fore.RED}wpscan not found. Attempting to install...{Style.RESET_ALL}")
                            if platform.system() == "Linux":
                                try:
                                    self.run_custom_command("apt-get update && apt-get install -y wpscan")
                                    print(f"{Fore.GREEN}wpscan installed successfully!{Style.RESET_ALL}")
                                except Exception as e:
                                    print(f"{Fore.RED}Error installing wpscan: {str(e)}{Style.RESET_ALL}")
                        
                        if check_tool_availability("wpscan"):
                            wpscan_file = os.path.join(target_dir, "wpscan.txt")
                            output, _ = self.run_custom_command(f"wpscan --url {web_target} --output {wpscan_file} --format json")
                            
                            if os.path.exists(wpscan_file):
                                try:
                                    with open(wpscan_file, 'r') as f:
                                        wpscan_data = json.load(f)
                                        if 'vulnerabilities' in wpscan_data:
                                            for vuln_type, vulns in wpscan_data['vulnerabilities'].items():
                                                for vuln in vulns:
                                                    if 'title' in vuln:
                                                        web_vulns.append(f"[WordPress] {vuln['title']}")
                                                        print(f"{Fore.RED}[WordPress] {vuln['title']}{Style.RESET_ALL}")
                                except:
                                    # If JSON parsing fails, extract manually
                                    with open(wpscan_file, 'r') as f:
                                        content = f.read()
                                        vuln_matches = re.findall(r'\[!\] (.*?) identified', content)
                                        for match in vuln_matches:
                                            web_vulns.append(f"[WordPress] {match}")
                                            print(f"{Fore.RED}[WordPress] {match}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}Error running WPScan: {str(e)}{Style.RESET_ALL}")
                
                # Drupal scanning
                if any(t.lower() == 'drupal' for t in technologies):
                    try:
                        print(f"{Fore.CYAN}Drupal detected, running droopescan...{Style.RESET_ALL}")
                        droope_file = os.path.join(target_dir, "droopescan.txt")
                        output, _ = self.run_custom_command(f"droopescan scan drupal -u {web_target} -o {droope_file}")
                        
                        if output:
                            for line in output.splitlines():
                                if "Potentially interesting" in line or "is vulnerable" in line:
                                    web_vulns.append(f"[Drupal] {line}")
                                    print(f"{Fore.RED}[Drupal] {line}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}Error running droopescan: {str(e)}{Style.RESET_ALL}")
                
                # Joomla scanning
                if any(t.lower() == 'joomla' for t in technologies):
                    try:
                        print(f"{Fore.CYAN}Joomla detected, running joomscan...{Style.RESET_ALL}")
                        joomscan_file = os.path.join(target_dir, "joomscan.txt")
                        output, _ = self.run_custom_command(f"joomscan --url {web_target} --report {joomscan_file}")
                        
                        if output:
                            for line in output.splitlines():
                                if "[+] Vulnerability" in line or "[+] Critical" in line:
                                    web_vulns.append(f"[Joomla] {line}")
                                    print(f"{Fore.RED}[Joomla] {line}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}Error running joomscan: {str(e)}{Style.RESET_ALL}")
            
            # 6. Check for SQL injection in parameters
            print(f"{Fore.CYAN}Checking for SQL injection...{Style.RESET_ALL}")
            params_urls = []
            
            # Find potential parameters in discovered paths
            for directory in directories:
                # If this is a string (sometimes it could be a tuple from other functions)
                if isinstance(directory, str):
                    # Extract path without parameters if any
                    path = directory.split("?")[0] if "?" in directory else directory
                    
                    # Check if path ends with a file that might accept parameters
                    if any(ext in path.lower() for ext in ['.php', '.asp', '.aspx', '.jsp', '.do', '.action']):
                        full_url = directory if directory.startswith(('http://', 'https://')) else f"{web_target}{directory}"
                        params_urls.append(f"{full_url}?id=1")
            
            # Run SQLMap on discovered potential parameter URLs (limit to 5 to save time)
            for i, url in enumerate(params_urls[:5]):
                try:
                    print(f"{Fore.CYAN}Testing for SQL injection in {url}...{Style.RESET_ALL}")
                    
                    # Check if sqlmap is installed
                    if not check_tool_availability("sqlmap"):
                        print(f"{Fore.RED}sqlmap not found. Attempting to install...{Style.RESET_ALL}")
                        if platform.system() == "Linux":
                            try:
                                self.run_custom_command("apt-get update && apt-get install -y sqlmap")
                                print(f"{Fore.GREEN}sqlmap installed successfully!{Style.RESET_ALL}")
                            except Exception as e:
                                print(f"{Fore.RED}Error installing sqlmap: {str(e)}{Style.RESET_ALL}")
                                continue
                    
                    sqlmap_file = os.path.join(target_dir, f"sqlmap_{i}.txt")
                    output, _ = self.run_custom_command(f"sqlmap -u '{url}' --batch --level=2 --risk=2 --output-dir={target_dir}")
                    
                    if "is vulnerable" in output:
                        finding = f"[CRITICAL] SQL Injection found in {url}"
                        web_vulns.append(finding)
                        print(f"{Fore.RED}{finding}{Style.RESET_ALL}")
                        
                        # Try to exploit further
                        print(f"{Fore.CYAN}Attempting to exploit SQL injection...{Style.RESET_ALL}")
                        # Try to get database information
                        output, _ = self.run_custom_command(f"sqlmap -u '{url}' --batch --dbs --output-dir={target_dir}")
                        if "available databases" in output:
                            dbs_section = output.split("available databases")[1].split("\n\n")[0]
                            web_vulns.append(f"[CRITICAL] Available databases: {dbs_section}")
                            
                            # Try to get database tables from first database
                            db_match = re.search(r'\[*\] (\w+)', dbs_section)
                            if db_match:
                                first_db = db_match.group(1)
                                print(f"{Fore.CYAN}Attempting to extract tables from database {first_db}...{Style.RESET_ALL}")
                                output, _ = self.run_custom_command(f"sqlmap -u '{url}' --batch -D {first_db} --tables --output-dir={target_dir}")
                                if "tables found" in output:
                                    tables_section = output.split("tables found")[1].split("\n\n")[0]
                                    web_vulns.append(f"[CRITICAL] Tables in {first_db}: {tables_section}")
                except Exception as e:
                    print(f"{Fore.RED}Error running SQLMap: {str(e)}{Style.RESET_ALL}")
            
            # 7. Check for XSS vulnerabilities with XSStrike on forms
            try:
                print(f"{Fore.CYAN}Checking for XSS vulnerabilities...{Style.RESET_ALL}")
                
                # Check if the XSStrike path exists
                xsstrike_path = "/opt/XSStrike/xsstrike.py"
                if not os.path.exists(xsstrike_path):
                    print(f"{Fore.RED}XSStrike not found at {xsstrike_path}. Attempting to install...{Style.RESET_ALL}")
                    self.run_custom_command("git clone https://github.com/s0md3v/XSStrike.git /opt/XSStrike")
                    self.run_custom_command("pip3 install -r /opt/XSStrike/requirements.txt")
                
                if os.path.exists(xsstrike_path):
                    output, _ = self.run_custom_command(f"curl -s {web_target} | grep -i 'form'")
                    
                    if "form" in output.lower():
                        print(f"{Fore.CYAN}Forms detected, scanning for XSS...{Style.RESET_ALL}")
                        xss_file = os.path.join(target_dir, "xssstrike.txt")
                        output, _ = self.run_custom_command(f"python3 {xsstrike_path} -u {web_target} --file {xss_file}")
                        
                        if os.path.exists(xss_file):
                            with open(xss_file, 'r') as f:
                                xss_content = f.read()
                                if "Vulnerable" in xss_content:
                                    web_vulns.append(f"[HIGH] XSS vulnerability found on {web_target}")
                                    print(f"{Fore.RED}[HIGH] XSS vulnerability found on {web_target}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error checking for XSS: {str(e)}{Style.RESET_ALL}")
            
            # 8. Try automatic exploitation with Metasploit if major vulnerabilities found
            if any("CRITICAL" in vuln or "HIGH" in vuln for vuln in web_vulns):
                try:
                    print(f"{Fore.YELLOW}Critical vulnerabilities found. Attempting exploitation with Metasploit...{Style.RESET_ALL}")
                    
                    # Check if Metasploit is installed
                    if check_tool_availability("msfconsole"):
                        # Create a resource script for Metasploit
                        resource_file = os.path.join(target_dir, "msf_autoexploit.rc")
                        with open(resource_file, 'w') as f:
                            f.write(f"workspace -a {target.replace('.', '_')}\n")
                            f.write(f"db_nmap -sV {urlparse(web_target).netloc}\n")
                            f.write("use auxiliary/scanner/http/http_version\n")
                            f.write(f"set RHOSTS {urlparse(web_target).netloc}\n")
                            f.write("run\n")
                            f.write("use auxiliary/scanner/http/dir_scanner\n")
                            f.write(f"set RHOSTS {urlparse(web_target).netloc}\n")
                            f.write("run\n")
                            f.write("use auxiliary/scanner/http/files_dir\n")
                            f.write(f"set RHOSTS {urlparse(web_target).netloc}\n")
                            f.write("run\n")
                            f.write("use auxiliary/scanner/http/webdav_scanner\n")
                            f.write(f"set RHOSTS {urlparse(web_target).netloc}\n")
                            f.write("run\n")
                            f.write("use auxiliary/scanner/http/http_login\n")
                            f.write(f"set RHOSTS {urlparse(web_target).netloc}\n")
                            f.write("run\n")
                            f.write("vulns\n")
                            f.write("exit\n")
                        
                        msf_output_file = os.path.join(target_dir, "metasploit_output.txt")
                        print(f"{Fore.YELLOW}Running Metasploit scans (this may take a while)...{Style.RESET_ALL}")
                        output, _ = self.run_custom_command(f"msfconsole -q -r {resource_file} | tee {msf_output_file}")
                        
                        # Parse Metasploit output for exploitable vulnerabilities
                        if os.path.exists(msf_output_file):
                            with open(msf_output_file, 'r') as f:
                                msf_content = f.read()
                                if "Vulnerable" in msf_content or "successful login" in msf_content:
                                    web_vulns.append(f"[CRITICAL] Metasploit found exploitable vulnerabilities!")
                                    print(f"{Fore.RED}[CRITICAL] Metasploit found exploitable vulnerabilities!{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}Metasploit not available. Skipping automatic exploitation.{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}Error during Metasploit exploitation: {str(e)}{Style.RESET_ALL}")
            
            # 9. Save discovered information
            results[target] = {
                "vulnerabilities": web_vulns,
                "directories": directories,
                "scan_path": target_dir
            }
            
            print(f"{Fore.GREEN}Completed web scan for {web_target}.{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Found {len(web_vulns)} vulnerabilities and {len(directories)} directories/files.{Style.RESET_ALL}")
        
        return results
    
    def run_complete_hack(self, target):
        """Run a complete automated hacking workflow on a target (IP or domain)"""
        print(f"{Fore.YELLOW}Starting comprehensive hacking process for {target}...{Style.RESET_ALL}")
        
        # Set the target
        self.target = target
        
        # Determine target type
        target_type = self.get_target_type()
        
        # Create a results directory specifically for this target
        target_dir = os.path.join(self.output_dir, f"hack_{target.replace(':', '_').replace('/', '_').replace('.', '_')}_{int(time.time())}")
        os.makedirs(target_dir, exist_ok=True)
        
        # To store all results
        results = {
            "target": target,
            "target_type": target_type,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "reconnaissance": {},
            "subdomains": [],
            "port_scan": {},
            "vulnerability_scan": {},
            "web_scan": {},
            "critical_findings": []
        }
        
        # Phase 1: Basic Reconnaissance
        print(f"{Fore.YELLOW}Phase 1: Reconnaissance{Style.RESET_ALL}")
        
        if target_type == "ip":
            # Run IP-specific reconnaissance
            recon_results = self.run_ip_reconnaissance(target)
            results["reconnaissance"] = recon_results
            
            # Set targets for scanning (just the IP in this case)
            scan_targets = [target]
            
            # Save IP info to file
            with open(os.path.join(target_dir, "ip_info.json"), 'w') as f:
                json.dump(recon_results, f, indent=4)
        else:
            # Run domain-specific reconnaissance
            try:
                # Get IP address of the domain
                ip = socket.gethostbyname(target)
                results["reconnaissance"]["ip"] = ip
                print(f"{Fore.GREEN}IP Address: {ip}{Style.RESET_ALL}")
                
                # Try to get WHOIS info
                try:
                    output, _ = self.run_custom_command(f"whois {target}")
                    whois_file = os.path.join(target_dir, "whois.txt")
                    with open(whois_file, 'w') as f:
                        f.write(output)
                    print(f"{Fore.GREEN}WHOIS information retrieved and saved to {whois_file}{Style.RESET_ALL}")
                    
                    # Extract important WHOIS info
                    whois_data = {}
                    for line in output.splitlines():
                        for field in ["Registrar:", "Registrant", "Admin", "Tech", "Name Server:", "Created:", "Updated:", "Expires:"]:
                            if field in line:
                                key = field.replace(":", "").strip().lower()
                                value = line.split(field)[1].strip()
                                whois_data[key] = value
                                print(f"{Fore.GREEN}{field} {value}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}Error getting WHOIS info: {str(e)}{Style.RESET_ALL}")
                
                # DNS enumeration
                try:
                    output, _ = self.run_custom_command(f"dig +nocmd {target} any +noall +answer")
                    results["reconnaissance"]["dns_records"] = []
                    for line in output.splitlines():
                        if target in line:
                            results["reconnaissance"]["dns_records"].append(line)
                            print(f"{Fore.GREEN}DNS: {line}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}Error performing DNS enumeration: {str(e)}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error in basic domain reconnaissance: {str(e)}{Style.RESET_ALL}")
        
        # Phase 2: Subdomain Enumeration (for domains only)
        if target_type == "domain":
            print(f"{Fore.YELLOW}Phase 2: Subdomain Enumeration{Style.RESET_ALL}")
            subdomains = self.run_subdomain_enumeration(target)
            results["subdomains"] = subdomains
            scan_targets = subdomains  # Use the discovered subdomains for further scanning
            
            # If no subdomains found, just use the main domain
            if not subdomains:
                scan_targets = [target]
                print(f"{Fore.YELLOW}No subdomains found, using main domain for scanning{Style.RESET_ALL}")
        
        # Phase 3: Port Scanning
        print(f"{Fore.YELLOW}Phase 3: Port Scanning{Style.RESET_ALL}")
        
        # Use different port scanning methods based on target type
        if target_type == "ip":
            # More thorough port scan for IP targets
            open_ports = self.run_ip_port_scan(target)
            results["port_scan"][target] = open_ports
        else:
            # Standard port scan for domains
            port_results = self.run_port_scan(scan_targets)
            results["port_scan"] = port_results
        
        # Phase 4: Service Enumeration - based on open ports
        print(f"{Fore.YELLOW}Phase 4: Service Enumeration{Style.RESET_ALL}")
        service_results = {}
        
        for target_host in scan_targets:
            service_results[target_host] = {}
            
            # Get open ports for this target
            open_ports = []
            if target_host in results["port_scan"]:
                open_ports = results["port_scan"][target_host]
                
            if not open_ports:
                print(f"{Fore.YELLOW}No open ports found for {target_host}, skipping service enumeration{Style.RESET_ALL}")
                continue
                
            print(f"{Fore.CYAN}Performing service enumeration on {target_host}...{Style.RESET_ALL}")
            
            # Check for common services
            for port, service in open_ports:
                port_num = int(port.strip())
                service_name = service.lower()
                
                # FTP check
                if port_num == 21 or "ftp" in service_name:
                    try:
                        print(f"{Fore.CYAN}Checking FTP service on port {port}...{Style.RESET_ALL}")
                        output, _ = self.run_custom_command(f"nmap -sV -sC -p {port} {target_host} --script=ftp-*")
                        service_results[target_host]["ftp"] = output
                        
                        # Check for anonymous login
                        if "Anonymous FTP login allowed" in output:
                            finding = f"[HIGH] Anonymous FTP login allowed on {target_host}:{port}"
                            results["critical_findings"].append(finding)
                            print(f"{Fore.RED}{finding}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}Error checking FTP: {str(e)}{Style.RESET_ALL}")
                
                # SSH check
                if port_num == 22 or "ssh" in service_name:
                    try:
                        print(f"{Fore.CYAN}Checking SSH service on port {port}...{Style.RESET_ALL}")
                        output, _ = self.run_custom_command(f"nmap -sV -sC -p {port} {target_host} --script=ssh2-enum-algos,ssh-hostkey")
                        service_results[target_host]["ssh"] = output
                        
                        # Check for weak crypto
                        if "CBC mode" in output or "96-bit MAC" in output:
                            finding = f"[MEDIUM] SSH using weak crypto on {target_host}:{port}"
                            results["critical_findings"].append(finding)
                            print(f"{Fore.YELLOW}{finding}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}Error checking SSH: {str(e)}{Style.RESET_ALL}")
                
                # SMTP check
                if port_num == 25 or port_num == 587 or "smtp" in service_name:
                    try:
                        print(f"{Fore.CYAN}Checking SMTP service on port {port}...{Style.RESET_ALL}")
                        output, _ = self.run_custom_command(f"nmap -sV -sC -p {port} {target_host} --script=smtp-commands,smtp-enum-users,smtp-vuln-*")
                        service_results[target_host]["smtp"] = output
                        
                        # Check for user enumeration
                        if "VRFY" in output:
                            finding = f"[MEDIUM] SMTP VRFY command enabled on {target_host}:{port}"
                            results["critical_findings"].append(finding)
                            print(f"{Fore.YELLOW}{finding}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}Error checking SMTP: {str(e)}{Style.RESET_ALL}")
                
                # HTTP/HTTPS check
                if port_num in [80, 443, 8080, 8443] or any(s in service_name for s in ["http", "web"]):
                    try:
                        print(f"{Fore.CYAN}Checking HTTP(S) service on port {port}...{Style.RESET_ALL}")
                        protocol = "https" if port_num == 443 or port_num == 8443 or "ssl" in service_name or "https" in service_name else "http"
                        output, _ = self.run_custom_command(f"curl -sk {protocol}://{target_host}:{port} -I")
                        service_results[target_host][f"{protocol}_{port}"] = output
                        
                        # Note this for web scanning later
                        if "web_targets" not in results:
                            results["web_targets"] = []
                        results["web_targets"].append(f"{protocol}://{target_host}:{port}")
                    except Exception as e:
                        print(f"{Fore.RED}Error checking HTTP(S): {str(e)}{Style.RESET_ALL}")
                
                # Database check
                if port_num in [3306, 5432, 1433, 1521, 27017] or any(s in service_name for s in ["mysql", "postgresql", "mssql", "oracle", "mongo"]):
                    try:
                        print(f"{Fore.CYAN}Checking database service on port {port}...{Style.RESET_ALL}")
                        db_type = "mysql"
                        if "postgresql" in service_name or port_num == 5432:
                            db_type = "postgresql"
                        elif "mssql" in service_name or port_num == 1433:
                            db_type = "mssql"
                        elif "oracle" in service_name or port_num == 1521:
                            db_type = "oracle"
                        elif "mongo" in service_name or port_num == 27017:
                            db_type = "mongodb"
                            
                        output, _ = self.run_custom_command(f"nmap -sV -sC -p {port} {target_host} --script={db_type}-*")
                        service_results[target_host][db_type] = output
                        
                        if "authentication bypass" in output or "successful login" in output:
                            finding = f"[HIGH] Possible database authentication issue on {target_host}:{port}"
                            results["critical_findings"].append(finding)
                            print(f"{Fore.RED}{finding}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}Error checking database: {str(e)}{Style.RESET_ALL}")
        
        # Save service enumeration results
        results["service_enumeration"] = service_results
        
        # Phase 5: Vulnerability Scanning
        print(f"{Fore.YELLOW}Phase 5: Vulnerability Scanning{Style.RESET_ALL}")
        vuln_results = self.run_vulnerability_scan(scan_targets)
        results["vulnerability_scan"] = vuln_results
        
        # Extract critical findings from vulnerability scan
        for target_host, vulns in vuln_results.items():
            for vuln in vulns:
                if "[critical]" in vuln.lower() or "[high]" in vuln.lower():
                    results["critical_findings"].append(vuln)
        
        # Phase 6: Web Application Scanning (if web ports were detected)
        print(f"{Fore.YELLOW}Phase 6: Web Application Scanning{Style.RESET_ALL}")
        
        # Check if we have explicit web targets from service enumeration
        if "web_targets" in results:
            web_targets = results["web_targets"]
        else:
            # Default to standard HTTP/HTTPS
            web_targets = []
            for target_host in scan_targets:
                # Check if port 80 or 443 is open
                if target_host in results["port_scan"]:
                    ports = [p[0] for p in results["port_scan"][target_host]]
                    if "80" in ports:
                        web_targets.append(f"http://{target_host}")
                    if "443" in ports:
                        web_targets.append(f"https://{target_host}")
                
                # If no standard ports, just try HTTP for now
                if not web_targets:
                    web_targets = [f"http://{t}" for t in scan_targets]
        
        # Run web scans
        web_results = self.run_web_scan(web_targets)
        results["web_scan"] = web_results
        
        # Extract critical findings from web scan
        for target_host, target_results in web_results.items():
            for vuln in target_results["vulnerabilities"]:
                if "CRITICAL" in vuln or "HIGH" in vuln or "SQL Injection" in vuln or "XSS" in vuln:
                    results["critical_findings"].append(vuln)
        
        # Phase 7: Generate Comprehensive Report
        print(f"{Fore.YELLOW}Phase 7: Generating Comprehensive Report{Style.RESET_ALL}")
        
        # Save all raw results to JSON
        results_file = os.path.join(target_dir, "all_results.json")
        with open(results_file, 'w') as f:
            # Filter out complex objects that aren't JSON serializable
            serializable_results = {}
            for key, value in results.items():
                try:
                    json.dumps(value)
                    serializable_results[key] = value
                except:
                    serializable_results[key] = str(value)
            
            json.dump(serializable_results, f, indent=4)
        
        # Generate human-readable report
        report_file = os.path.join(target_dir, "hack_report.txt")
        
        with open(report_file, 'w') as f:
            f.write(f"# Comprehensive Hacking Report for {target}\n\n")
            f.write(f"Date: {results['timestamp']}\n")
            f.write(f"Target Type: {target_type.upper()}\n\n")
            
            f.write("## 1. Reconnaissance\n\n")
            
            if target_type == "ip":
                if "hostname" in results["reconnaissance"]:
                    f.write(f"Hostname: {results['reconnaissance']['hostname']}\n")
                if "os_info" in results["reconnaissance"]:
                    f.write(f"OS Detection: {results['reconnaissance']['os_info']}\n")
                if "geolocation" in results["reconnaissance"]:
                    geo = results["reconnaissance"]["geolocation"]
                    f.write(f"Geolocation: {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}, {geo.get('country', 'Unknown')}\n")
                if "asn_info" in results["reconnaissance"]:
                    f.write(f"Organization: {results['reconnaissance']['asn_info']}\n")
            else:
                f.write(f"Main Domain: {target}\n")
                if "ip" in results["reconnaissance"]:
                    f.write(f"IP Address: {results['reconnaissance']['ip']}\n")
                if "whois" in results["reconnaissance"]:
                    whois = results["reconnaissance"]["whois"]
                    if "registrar" in whois:
                        f.write(f"Registrar: {whois['registrar']}\n")
                    if "created" in whois:
                        f.write(f"Created: {whois['created']}\n")
                    if "expires" in whois:
                        f.write(f"Expires: {whois['expires']}\n")
                if "dns_records" in results["reconnaissance"]:
                    f.write("\nDNS Records:\n")
                    for record in results["reconnaissance"]["dns_records"]:
                        f.write(f"- {record}\n")
            
            if target_type == "domain":
                f.write("\n## 2. Subdomain Enumeration\n\n")
                if results["subdomains"]:
                    f.write(f"Total subdomains discovered: {len(results['subdomains'])}\n\n")
                    for i, subdomain in enumerate(results["subdomains"], 1):
                        f.write(f"{i}. {subdomain}\n")
                else:
                    f.write("No subdomains discovered.\n")
            
            f.write("\n## 3. Port Scanning\n\n")
            for target_host, ports in results["port_scan"].items():
                f.write(f"### {target_host}\n\n")
                if ports:
                    for port, service in ports:
                        f.write(f"* Port {port}: {service}\n")
                else:
                    f.write("No open ports found.\n")
                f.write("\n")
            
            if "service_enumeration" in results:
                f.write("## 4. Service Enumeration\n\n")
                for target_host, services in results["service_enumeration"].items():
                    if services:
                        f.write(f"### {target_host}\n\n")
                        for service_name, output in services.items():
                            f.write(f"#### {service_name.upper()}\n\n")
                            # Limit output to avoid extremely long reports
                            lines = output.splitlines()[:20]
                            for line in lines:
                                if line.strip():
                                    f.write(f"    {line}\n")
                            if len(output.splitlines()) > 20:
                                f.write(f"    ... (output truncated, see full logs in {target_dir})\n")
                            f.write("\n")
                    
            f.write("## 5. Vulnerability Scanning\n\n")
            for target_host, vulns in results["vulnerability_scan"].items():
                f.write(f"### {target_host}\n\n")
                if vulns:
                    for vuln in vulns:
                        f.write(f"* {vuln}\n")
                else:
                    f.write("No vulnerabilities found.\n")
                f.write("\n")
            
            f.write("## 6. Web Application Scanning\n\n")
            for target_host, target_results in results["web_scan"].items():
                f.write(f"### {target_host}\n\n")
                
                f.write("#### Vulnerabilities\n\n")
                if target_results["vulnerabilities"]:
                    for vuln in target_results["vulnerabilities"]:
                        f.write(f"* {vuln}\n")
                else:
                    f.write("No web vulnerabilities found.\n")
                
                f.write("\n#### Directories\n\n")
                if target_results["directories"]:
                    # Limit to first 20 directories to avoid extremely verbose reports
                    for i, directory in enumerate(target_results["directories"][:20]):
                        f.write(f"* {directory}\n")
                    if len(target_results["directories"]) > 20:
                        f.write(f"* ... and {len(target_results['directories']) - 20} more (see full logs)\n")
                else:
                    f.write("No interesting directories found.\n")
                f.write("\n")
            
            f.write("## 7. Critical Findings Summary\n\n")
            if results["critical_findings"]:
                f.write(f"Total critical/high severity issues: {len(results['critical_findings'])}\n\n")
                for i, finding in enumerate(results["critical_findings"], 1):
                    f.write(f"{i}. {finding}\n")
            else:
                f.write("No critical/high severity issues found.\n")
            
            f.write("\n\nThis report was automatically generated by BugBountyAI.\n")
            f.write(f"Full scan results are available in: {target_dir}\n")
        
        print(f"{Fore.GREEN}Hacking process completed! Report saved to {report_file}{Style.RESET_ALL}")
        
        # Phase 8: AI Analysis of findings
        print(f"{Fore.YELLOW}Phase 8: AI Analysis of Findings{Style.RESET_ALL}")
        
        # Read the report file for AI analysis
        with open(report_file, 'r') as f:
            report_content = f.read()
        
        analysis = self.chat_with_ollama(
            "Analyze this hacking report and provide a summary of the most important findings and recommended next steps. Be concise and focus on actionable security issues.",
            f"You are an expert security analyst reviewing a hacking report. The target was {target} ({target_type}). Provide a concise analysis of the most critical findings and recommend next steps for the security team."
        )
        
        # Append AI analysis to the report
        with open(report_file, 'a') as f:
            f.write("\n\n## 8. AI Analysis\n\n")
            f.write(analysis)
        
        print(f"{Fore.GREEN}AI analysis completed and added to the report.{Style.RESET_ALL}")
        
        return f"Completed comprehensive hacking of {target}. Found {len(results['critical_findings'])} critical issues. Full report available at {report_file}"
    
    def run_interactive_chat(self):
        """Run the interactive chat interface with a comprehensive bug bounty workflow"""
        print(f"{Style.BRIGHT}{Fore.RED}=== BUG BOUNTY AI: COMPREHENSIVE SECURITY TESTING PLATFORM ==={Style.RESET_ALL}")
        print(f"Type 'help' for assistance, 'methodology' for bug bounty steps, 'exit' to quit.\n")
        
        # If using Ollama, display available models
        if not self.use_openrouter:
            available_models = self.get_available_ollama_models()
            print(f"{Style.BRIGHT}Available Ollama models:{Style.RESET_ALL}")
            if available_models:
                for model in available_models:
                    print(f"  - {model}")
            else:
                print(f"{Fore.RED}No Ollama models found. Please make sure Ollama is installed and running.{Style.RESET_ALL}")
                print(f"You can install Ollama from https://ollama.ai")
                if not self.use_openrouter:
                    print(f"Alternatively, restart with -a openrouter to use OpenRouter API instead.")
                    return
        
            # Allow model selection if more than one is available or if no model was specified
            if (self.ollama_model is None or len(available_models) > 1) and not self.no_prompt:
                model_idx = 0
                
                if self.ollama_model is None or self.ollama_model not in available_models:
                    # Default to first available model
                    self.ollama_model = available_models[0] if available_models else "deepseek-r1:7b"
                
                print(f"\nCurrently using: {Fore.GREEN}{self.ollama_model}{Style.RESET_ALL}")
                
                # Ask if user wants to change the model
                change_model = input(f"Would you like to use a different model? (y/n): ").lower() == 'y'
                
                if change_model:
                    print("\nSelect a model:")
                    for i, model in enumerate(available_models):
                        print(f"  {i+1}. {model}")
                    
                    selection = input("\nEnter number: ")
                    try:
                        model_idx = int(selection) - 1
                        if 0 <= model_idx < len(available_models):
                            self.ollama_model = available_models[model_idx]
                            print(f"Model set to: {Fore.GREEN}{self.ollama_model}{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.RED}Invalid selection. Using {self.ollama_model}.{Style.RESET_ALL}")
                    except ValueError:
                        print(f"{Fore.RED}Invalid input. Using {self.ollama_model}.{Style.RESET_ALL}")
        else:
            # Using OpenRouter API
            print(f"{Fore.GREEN}Using OpenRouter API with model: {AI_CONFIG['openrouter']['model']}{Style.RESET_ALL}")
        
        print("\n" + "="*70)
        print(f"{Fore.RED}{Style.BRIGHT}COMPREHENSIVE BUG BOUNTY & PENETRATION TESTING PLATFORM{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Following industry-standard methodology for thorough security assessment{Style.RESET_ALL}")
        print("="*70 + "\n")
        
        # Enable readline for command history
        if platform.system() != "Windows":
            readline.parse_and_bind('tab: complete')
        
        # Ask for the target
        target_input = input(f"{Fore.RED}Enter a target domain, URL, or IP address: {Style.RESET_ALL}")
        
        # Extract domain or normalize IP from input
        target = target_input.strip()
        if target.startswith("http://") or target.startswith("https://"):
            target = target.split("//")[1].split("/")[0]
        if target.startswith("www."):
            target = target[4:]
        
        if target:
            self.target = target
            target_type = self.get_target_type()
            print(f"{Fore.GREEN}Target set to: {target} (detected as {target_type.upper()}){Style.RESET_ALL}")
            
            # Ask if user wants to start the comprehensive assessment immediately
            print(f"\n{Fore.CYAN}Ready to start comprehensive security assessment following best practices:{Style.RESET_ALL}")
            print(f"1. {Fore.YELLOW}Reconnaissance{Style.RESET_ALL} - Information gathering & asset discovery")
            print(f"2. {Fore.YELLOW}Scanning & Enumeration{Style.RESET_ALL} - Identifying attack surface")
            print(f"3. {Fore.YELLOW}Vulnerability Assessment{Style.RESET_ALL} - Finding security weaknesses")
            print(f"4. {Fore.YELLOW}Exploitation{Style.RESET_ALL} - Verifying vulnerabilities")
            print(f"5. {Fore.YELLOW}Reporting{Style.RESET_ALL} - Documenting findings\n")
            
            start_hack = input(f"{Fore.YELLOW}Start comprehensive security assessment on {target} now? (y/n): {Style.RESET_ALL}")
            if start_hack.lower() == 'y':
                hack_result = self.run_complete_hack(target)
                print(f"\n{Fore.GREEN}{hack_result}{Style.RESET_ALL}")
        
        # Main chat loop
        while True:
            # Create the prompt with appropriate persona color
            persona_data = AI_PERSONAS[self.ai_persona]
            prompt = f"{persona_data['color']}[{persona_data['name']}]{Style.RESET_ALL} "
            
            if self.target:
                target_type = self.get_target_type() or "unknown"
                type_indicator = f"{target_type.upper()}"
                prompt += f"{Fore.CYAN}({self.target} - {type_indicator}){Style.RESET_ALL} "
            
            try:
                user_input = input(f"\n{prompt}> ")
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except EOFError:
                print("\nExiting...")
                break
            
            if user_input.lower() in ['exit', 'quit', 'bye']:
                print("Goodbye!")
                break
            
            if not user_input.strip():
                continue
                
            if user_input.lower() == 'help':
                self._show_help()
                continue
            
            if user_input.lower() == 'tools':
                self._show_available_tools()
                continue
            
            if user_input.lower() == 'methodology':
                self._show_methodology()
                continue
            
            if user_input.lower() == 'hack' or user_input.lower() == 'start hacking':
                if self.target:
                    hack_result = self.run_complete_hack(self.target)
                    print(f"\n{Fore.GREEN}{hack_result}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}No target set. Use 'set target example.com' or 'set target 192.168.1.1' first.{Style.RESET_ALL}")
                continue
            
            if user_input.lower() == 'recon' or user_input.lower() == 'reconnaissance':
                if self.target:
                    print(f"{Fore.YELLOW}Starting reconnaissance phase on {self.target}...{Style.RESET_ALL}")
                    result = self.recon(self.target)
                    print(f"\n{result}")
                else:
                    print(f"{Fore.RED}No target set. Use 'set target example.com' or 'set target 192.168.1.1' first.{Style.RESET_ALL}")
                continue
            
            if user_input.lower() == 'scan status':
                if self.is_scanning:
                    print(f"{Fore.YELLOW}Scan is currently running against {self.target}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}No scan currently running{Style.RESET_ALL}")
                continue
            
            # Check for URL/domain/IP pattern in input
            # This regex matches IPs and domain names
            pattern = r'(https?://[^\s]+|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+))'
            target_match = re.search(pattern, user_input)
            
            if target_match and not user_input.lower().startswith(('run', 'execute', 'use', 'scan', 'set target')):
                new_target = target_match.group(1)
                
                # Extract domain from URL if needed
                if new_target.startswith("http://") or new_target.startswith("https://"):
                    new_target = new_target.split("//")[1].split("/")[0]
                
                # Set the new target
                self.target = new_target
                target_type = self.get_target_type()
                print(f"{Fore.YELLOW}Detected target: {new_target} (detected as {target_type.upper()}). Setting as target.{Style.RESET_ALL}")
                
                # Present comprehensive options for assessment
                print(f"\n{Fore.CYAN}Available assessment options for {new_target}:{Style.RESET_ALL}")
                print(f"1. {Fore.YELLOW}Quick Recon{Style.RESET_ALL} - Basic information gathering")
                print(f"2. {Fore.YELLOW}Full Recon{Style.RESET_ALL} - Comprehensive information gathering")
                print(f"3. {Fore.YELLOW}Subdomain Enumeration{Style.RESET_ALL} - Discover all subdomains")
                print(f"4. {Fore.YELLOW}Vulnerability Scan{Style.RESET_ALL} - Identify security weaknesses")
                print(f"5. {Fore.YELLOW}Complete Assessment{Style.RESET_ALL} - Full security assessment")
                
                choice = input(f"{Fore.YELLOW}Select an option (1-5) or 'n' to skip: {Style.RESET_ALL}")
                
                if choice == '1':
                    print(f"{Fore.YELLOW}Starting quick reconnaissance on {new_target}...{Style.RESET_ALL}")
                    result = self.recon(new_target)
                    print(f"\n{result}")
                elif choice == '2':
                    print(f"{Fore.YELLOW}Starting full reconnaissance on {new_target}...{Style.RESET_ALL}")
                    if target_type == "domain":
                        self.run_subdomain_enumeration(new_target)
                    result = self.recon(new_target)
                    print(f"\n{result}")
                elif choice == '3':
                    if target_type == "domain":
                        print(f"{Fore.YELLOW}Starting subdomain enumeration for {new_target}...{Style.RESET_ALL}")
                        self.run_subdomain_enumeration(new_target)
                    else:
                        print(f"{Fore.RED}Subdomain enumeration is only available for domains, not IP addresses.{Style.RESET_ALL}")
                elif choice == '4':
                    print(f"{Fore.YELLOW}Starting vulnerability scan on {new_target}...{Style.RESET_ALL}")
                    targets = [new_target]
                    if target_type == "domain":
                        subdomains = self.run_subdomain_enumeration(new_target)
                        if subdomains:
                            targets.extend(subdomains)
                    self.run_vulnerability_scan(targets)
                elif choice == '5':
                    print(f"{Fore.YELLOW}Starting complete security assessment on {new_target}...{Style.RESET_ALL}")
                    hack_result = self.run_complete_hack(new_target)
                    print(f"\n{Fore.GREEN}{hack_result}{Style.RESET_ALL}")
                
                continue
            
            # Parse and execute the user's intent
            intent_data = self.parse_intent(user_input)
            response = self.execute_intent(intent_data)
            
            print(f"\n{persona_data['color']}{persona_data['name']}:{Style.RESET_ALL} {response}")
    
    def _show_help(self):
        """Show help information"""
        print(f"\n{Style.BRIGHT}Available Commands:{Style.RESET_ALL}")
        print("  help                  - Show this help message")
        print("  methodology           - Show the bug bounty methodology steps")
        print("  tools                 - List available security testing tools")
        print("  exit, quit, bye       - Exit the program")
        print("  hack, start hacking   - Run comprehensive assessment on current target")
        print("  recon, reconnaissance - Run reconnaissance on the target")
        print("  scan <target>         - Run a basic scan on the target")
        print("  run <tool> <params>   - Run a specific tool with parameters")
        print("  set target <target>   - Set a new target (domain, URL, or IP)")
        print("  enumerate subdomains  - Find subdomains for the current domain target")
        print("  port scan             - Scan open ports on the current target")
        print("  vuln scan             - Run vulnerability scan on the current target")
        print("  web scan              - Run web application scan on the current target")
        print("  scan status           - Check if a scan is currently running")
        print("  evade firewall        - Toggle firewall evasion techniques")
        print("  use model <model>     - Switch to a different AI model")
        print("  switch persona <type> - Switch to a different AI persona")
        print("\nYou can also just enter a domain, URL, or IP address to set it as the target.")
        print("Or chat naturally with the AI for guidance on hacking techniques.")
        
    def _show_methodology(self):
        """Show the comprehensive bug bounty methodology"""
        print(f"\n{Style.BRIGHT}{Fore.CYAN}COMPREHENSIVE BUG BOUNTY METHODOLOGY{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}PHASE 1: PRE-ENGAGEMENT & RECONNAISSANCE{Style.RESET_ALL}")
        print("  1.1. Define scope and objectives")
        print("  1.2. Information gathering (passive)")
        print("       - OSINT, social media analysis, domain footprinting")
        print("       - WHOIS, DNS lookups, email harvesting")
        print("  1.3. Active information gathering")
        print("       - Network scanning, port detection")
        print("       - Service enumeration")
        
        print(f"\n{Fore.YELLOW}PHASE 2: DISCOVERY & ENUMERATION{Style.RESET_ALL}")
        print("  2.1. Domain discovery")
        print("       - Subdomain enumeration (amass, subfinder, crt.sh)")
        print("       - Checking alive domains (httpx)")
        print("       - Subdomain takeover testing")
        print("  2.2. Application mapping")
        print("       - Technology identification (Wappalyzer, WhatWeb)")
        print("       - Directory enumeration (ffuf, gobuster)")
        print("       - Parameter discovery (Arjun)")
        print("  2.3. Content discovery")
        print("       - Hidden files/directories")
        print("       - JS file analysis")
        print("       - Wayback machine examination")
        
        print(f"\n{Fore.YELLOW}PHASE 3: VULNERABILITY ASSESSMENT{Style.RESET_ALL}")
        print("  3.1. Automated scanning")
        print("       - Web vulnerability scanners (Nuclei, Nikto)")
        print("       - CMS scanners (WPScan, droopescan)")
        print("       - API testing")
        print("  3.2. Manual testing")
        print("       - Authentication testing")
        print("       - Authorization checks")
        print("       - Input validation (XSS, SQLi, CSRF)")
        print("       - Business logic flaws")
        
        print(f"\n{Fore.YELLOW}PHASE 4: EXPLOITATION{Style.RESET_ALL}")
        print("  4.1. Exploit development")
        print("       - Creating proof of concepts")
        print("       - Bypassing security controls")
        print("  4.2. Post-exploitation")
        print("       - Privilege escalation")
        print("       - Lateral movement")
        print("       - Data extraction")
        
        print(f"\n{Fore.YELLOW}PHASE 5: REPORTING{Style.RESET_ALL}")
        print("  5.1. Documentation")
        print("       - Vulnerability description")
        print("       - Steps to reproduce")
        print("       - Impact assessment")
        print("       - Remediation recommendations")
        print("  5.2. Responsible disclosure")
        print("       - Following program guidelines")
        print("       - Providing clear evidence")
        print("       - Verifying fixes")
    
    def _show_available_tools(self):
        """Show available security testing tools"""
        print(f"\n{Style.BRIGHT}Available Security Testing Tools:{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Reconnaissance Tools:{Style.RESET_ALL}")
        print("  nmap      - Network scanning and service detection")
        print("  whois     - Domain registration information")
        print("  dig       - DNS lookup utility")
        print("  theHarvester - Email and subdomain harvesting")
        
        print(f"\n{Fore.YELLOW}Subdomain Enumeration:{Style.RESET_ALL}")
        print("  amass     - In-depth subdomain enumeration")
        print("  subfinder - Fast passive subdomain discovery")
        print("  assetfinder - Find domains and subdomains")
        print("  knockpy   - Subdomain bruteforcing")
        print("  httpx     - Multi-purpose HTTP toolkit")
        
        print(f"\n{Fore.YELLOW}Content Discovery:{Style.RESET_ALL}")
        print("  ffuf      - Fast web fuzzer")
        print("  gobuster  - Directory/file & DNS busting")
        print("  dirsearch - Web path scanner")
        print("  feroxbuster - Recursive content discovery")
        
        print(f"\n{Fore.YELLOW}Vulnerability Scanning:{Style.RESET_ALL}")
        print("  nuclei    - Template-based vulnerability scanner")
        print("  nikto     - Web server scanner")
        print("  sqlmap    - SQL injection detection and exploitation")
        print("  wpscan    - WordPress vulnerability scanner")
        print("  XSStrike  - Advanced XSS detection")
        
        print(f"\n{Fore.YELLOW}Exploitation Tools:{Style.RESET_ALL}")
        print("  metasploit - Exploitation framework")
        print("  commix    - Command injection exploiter")
        print("  hydra     - Password brute-forcing")
        
        print(f"\n{Fore.YELLOW}Other Tools:{Style.RESET_ALL}")
        print("  waybackurls - Fetch URLs from Wayback Machine")
        print("  gau       - Get All URLs")
        print("  paramspider - Find parameters in URLs")
        print("  securitytrails - Domain and IP intelligence")
        print("  shodan    - Search engine for Internet-connected devices")
    
    def run_recursive_directory_bruteforce(self, web_target, max_depth=3, output_dir=None):
        """Run recursive directory brute-forcing with multiple wordlists"""
        print(f"{Fore.YELLOW}Starting recursive directory bruteforcing for {web_target}...{Style.RESET_ALL}")
        
        # Prepare output directory
        if not output_dir:
            target_dir = os.path.join(self.output_dir, f"dirbrute_{urlparse(web_target).netloc.replace(':', '_')}")
            os.makedirs(target_dir, exist_ok=True)
        else:
            target_dir = output_dir
            
        # Initialize results list
        all_directories = []
        discovered_endpoints = set()
        
        # First check if ffuf is installed
        if not check_tool_availability("ffuf"):
            print(f"{Fore.RED}ffuf not found. Attempting to install...{Style.RESET_ALL}")
            if platform.system() == "Linux":
                try:
                    self.run_custom_command("go install github.com/ffuf/ffuf/v2@latest")
                    print(f"{Fore.GREEN}ffuf installed successfully!{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}Error installing ffuf: {str(e)}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}Falling back to gobuster...{Style.RESET_ALL}")
                    self.run_custom_command("apt-get update && apt-get install -y gobuster")
        
        # Define wordlists to try (in order of size)
        wordlists = [
            "/usr/share/wordlists/dirb/common.txt",  # Start with smaller wordlist
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",  # More comprehensive
        ]
        
        # Check if wordlists exist, download if not
        for wordlist_path in wordlists:
            if not os.path.exists(wordlist_path):
                print(f"{Fore.YELLOW}Wordlist {wordlist_path} not found. Attempting to download...{Style.RESET_ALL}")
                if "dirb/common.txt" in wordlist_path:
                    try:
                        os.makedirs(os.path.dirname(wordlist_path), exist_ok=True)
                        self.run_custom_command(f"curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -o {wordlist_path}")
                        print(f"{Fore.GREEN}Downloaded common.txt wordlist{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}Error downloading wordlist: {str(e)}{Style.RESET_ALL}")
                elif "dirbuster/directory-list-2.3-medium.txt" in wordlist_path:
                    try:
                        os.makedirs(os.path.dirname(wordlist_path), exist_ok=True)
                        self.run_custom_command(f"curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt -o {wordlist_path}")
                        print(f"{Fore.GREEN}Downloaded directory-list-2.3-medium.txt wordlist{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}Error downloading wordlist: {str(e)}{Style.RESET_ALL}")
                        
        # Function to recursively perform directory bruteforce
        def brute_directory(url, current_depth=0, extensions=None):
            if current_depth >= max_depth:
                return []
                
            # Skip if we've already scanned this URL
            if url in discovered_endpoints:
                return []
                
            discovered_endpoints.add(url)
            
            # Build extensions argument for ffuf
            ext_arg = ""
            if extensions:
                ext_arg = f" -e {','.join(extensions)}"
            
            found_dirs = []
            
            # Try each wordlist in order, starting with smaller ones
            for wordlist in wordlists:
                if not os.path.exists(wordlist):
                    continue
                    
                output_file = os.path.join(target_dir, f"ffuf_{url.replace('://', '_').replace('/', '_')}_{current_depth}.json")
                
                # Run ffuf with JSON output
                if check_tool_availability("ffuf"):
                    ffuf_cmd = (
                        f"ffuf -u {url}/FUZZ -w {wordlist}{ext_arg} -mc 200,204,301,302,307,401,403,405 "
                        f"-s -o {output_file} -of json -recursion -recursion-depth 1"
                    )
                    self.run_custom_command(ffuf_cmd)
                else:
                    # Fallback to gobuster
                    gobuster_file = output_file.replace('.json', '.txt')
                    gobuster_cmd = f"gobuster dir -u {url} -w {wordlist}{ext_arg} -o {gobuster_file}"
                    self.run_custom_command(gobuster_cmd)
                    
                # Parse output
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r') as f:
                            ffuf_data = json.load(f)
                            if 'results' in ffuf_data:
                                for result in ffuf_data['results']:
                                    status = result.get('status', 0)
                                    if status in [200, 204, 301, 302, 307, 401, 403, 405]:
                                        path = result.get('url', '')
                                        if path:
                                            # Remove the FUZZ keyword if present
                                            path = path.replace('FUZZ', '')
                                            found_dirs.append(path)
                                            print(f"{Fore.GREEN}Found: {path} [{status}]{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}Error parsing ffuf output: {str(e)}{Style.RESET_ALL}")
                elif os.path.exists(gobuster_file):
                    # Parse gobuster output
                    try:
                        with open(gobuster_file, 'r') as f:
                            for line in f:
                                if "Status: 200" in line or "Status: 30" in line:
                                    path = line.split()[0]
                                    full_path = f"{url}/{path}"
                                    found_dirs.append(full_path)
                                    print(f"{Fore.GREEN}Found: {full_path}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}Error parsing gobuster output: {str(e)}{Style.RESET_ALL}")
            
            # Skip if no directories found
            if not found_dirs:
                return []
                
            # Record all found directories
            all_directories.extend(found_dirs)
            
            # For each directory, recursively scan
            recursive_results = []
            if current_depth < max_depth - 1:
                print(f"{Fore.YELLOW}Starting recursive scan at depth {current_depth+1}...{Style.RESET_ALL}")
                for directory in found_dirs:
                    # If it ends with a file extension, skip recursion
                    if '.' in directory.split('/')[-1]:
                        continue
                        
                    # Sleep briefly to avoid hammering the server
                    time.sleep(0.5)
                    
                    # Check different extensions in discovered dirs if we're less than max depth
                    if extensions and current_depth < max_depth - 1:
                        ext_results = brute_directory(directory, current_depth+1, extensions)
                        recursive_results.extend(ext_results)
            
            return found_dirs + recursive_results
        
        # Define interesting extensions to check
        web_extensions = ["php", "asp", "aspx", "jsp", "html", "js"]
        
        # Run the initial scan with no extensions
        print(f"{Fore.CYAN}Starting initial directory scan...{Style.RESET_ALL}")
        initial_results = brute_directory(web_target)
        
        # If initial results yield something, scan with extensions
        if initial_results:
            print(f"{Fore.CYAN}Found {len(initial_results)} endpoints, checking for file extensions...{Style.RESET_ALL}")
            ext_results = brute_directory(web_target, 0, web_extensions)
            
            # Check for specific technology directories based on initial findings
            tech_indicators = {
                "wp-": "WordPress",
                "wp-content": "WordPress",
                "wp-admin": "WordPress",
                "admin": "Admin Panel",
                "phpmyadmin": "phpMyAdmin",
                ".git": "Git Repository",
                "api": "API Endpoint"
            }
            
            for dir_path in initial_results:
                for indicator, tech_name in tech_indicators.items():
                    if indicator in dir_path.lower():
                        print(f"{Fore.YELLOW}Detected {tech_name} at {dir_path}, running targeted scan...{Style.RESET_ALL}")
                        
                        # Special case for WordPress
                        if tech_name == "WordPress":
                            wp_extensions = ["php"]
                            wp_results = brute_directory(dir_path, 0, wp_extensions)
                            
                            # If this is a wp-admin, try potential admin files
                            if "wp-admin" in dir_path.lower():
                                admin_wordlist = os.path.join(target_dir, "wp-admin-wordlist.txt")
                                with open(admin_wordlist, 'w') as f:
                                    for item in ["index.php", "admin.php", "options.php", "users.php", "plugins.php"]:
                                        f.write(f"{item}\n")
                                        
                                # Run scan with custom wordlist
                                wp_admin_file = os.path.join(target_dir, f"ffuf_wp_admin.json")
                                wp_admin_cmd = (
                                    f"ffuf -u {dir_path}/FUZZ -w {admin_wordlist} -mc 200,204,301,302,307,401,403,405 "
                                    f"-s -o {wp_admin_file} -of json"
                                )
                                self.run_custom_command(wp_admin_cmd)
                        
                        # Special case for API endpoints
                        if tech_name == "API Endpoint":
                            api_wordlist = os.path.join(target_dir, "api-wordlist.txt")
                            with open(api_wordlist, 'w') as f:
                                for item in ["v1", "v2", "v3", "users", "admin", "login", "auth", "data", "api"]:
                                    f.write(f"{item}\n")
                                    
                            # Run scan with custom wordlist
                            api_file = os.path.join(target_dir, f"ffuf_api.json")
                            api_cmd = (
                                f"ffuf -u {dir_path}/FUZZ -w {api_wordlist} -mc 200,204,301,302,307,401,403,405 "
                                f"-s -o {api_file} -of json"
                            )
                            self.run_custom_command(api_cmd)
                        
                        break
        
        # Save all discovered directories to a file
        all_dirs_file = os.path.join(target_dir, "all_discovered_directories.txt")
        with open(all_dirs_file, 'w') as f:
            for directory in sorted(set(all_directories)):
                f.write(f"{directory}\n")
        
        print(f"{Fore.GREEN}Recursive directory bruteforcing completed. Found {len(all_directories)} endpoints.{Style.RESET_ALL}")
        return all_directories

    def recon(self, target):
        """Perform basic reconnaissance on a target"""
        response = ""
        
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            # This is an IP address
            try:
                # Get geolocation and ASN information
                recon_results = self.get_ip_recon_data(target)
                
                response = f"Reconnaissance results for {target}:\n\n"
                
                if recon_results.get("hostname"):
                    response += f"Hostname: {recon_results['hostname']}\n"
                
                if recon_results.get("os_info"):
                    response += f"OS Detection: {recon_results['os_info']}\n"
                
                if recon_results.get("geolocation"):
                    geo = recon_results["geolocation"]
                    response += f"Geolocation: {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}, {geo.get('country', 'Unknown')}\n"
                
                if recon_results.get("asn_info"):
                    response += f"Organization: {recon_results['asn_info']}\n"
                
                # Add ports if discovered during recon
                if recon_results.get("ports"):
                    response += "\nDiscovered ports:\n"
                    for port, service in recon_results["ports"]:
                        response += f"- Port {port}: {service}\n"
            except Exception as e:
                response = f"Error during IP reconnaissance: {str(e)}"
        else:
            # This is a domain name
            try:
                ip = socket.gethostbyname(target)
                response = f"Reconnaissance results for {target}:\n\n"
                response += f"IP Address: {ip}\n"
                
                # Get WHOIS info
                try:
                    whois_data = {}
                    output, _ = self.run_custom_command(f"whois {target}")
                    
                    for line in output.splitlines():
                        if ":" in line:
                            key, value = line.split(":", 1)
                            key = key.strip()
                            value = value.strip()
                            
                            if key in ["Registrar", "Creation Date", "Updated Date", "Registry Expiry Date"]:
                                if key == "Creation Date":
                                    whois_data["Created"] = value
                                elif key == "Registry Expiry Date":
                                    whois_data["Expires"] = value
                                else:
                                    whois_data[key] = value
                    
                    if "Registrar" in whois_data:
                        response += f"Registrar: {whois_data['Registrar']}\n"
                    if "Created" in whois_data:
                        response += f"Created: {whois_data['Created']}\n"
                    if "Expires" in whois_data:
                        response += f"Expires: {whois_data['Expires']}\n"
                except Exception as e:
                    response += f"Error getting WHOIS info: {str(e)}\n"
                
                # DNS enumeration
                try:
                    output, _ = self.run_custom_command(f"dig +nocmd {target} any +noall +answer")
                    if output.strip():
                        response += "\nDNS Records:\n"
                        for line in output.splitlines():
                            if target in line:
                                response += f"- {line}\n"
                except Exception as e:
                    response += f"Error performing DNS enumeration: {str(e)}\n"
            
            except Exception as e:
                response = f"Error during domain reconnaissance: {str(e)}"
        
        return response

def main():
    parser = argparse.ArgumentParser(description="AI-Powered Bug Bounty Tool", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-m", "--model", help="Specify which Ollama model to use (e.g., deepseek-r1:7b)")
    parser.add_argument("-a", "--api", choices=["ollama", "openrouter"], help="Specify which AI API to use: ollama or openrouter")
    parser.add_argument("-k", "--api-key", help="OpenRouter API key (if using openrouter)")
    parser.add_argument("--persona", choices=["hacker", "pentester", "bughunter", "analyst"], default="hacker", 
                      help="Set the AI persona (default: hacker)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-prompt", action="store_true", help="Skip model selection prompt")
    args = parser.parse_args()
    
    # Always start in chat mode by default
    chat_mode = True
    target = None
    
    # Set up logging level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Check for OpenRouter API key in environment or argument
    openrouter_api_key = os.environ.get("OPENROUTER_API_KEY")
    if args.api_key:
        openrouter_api_key = args.api_key
    
    # Determine which AI provider to use
    use_openrouter = False
    if args.api == "openrouter":
        use_openrouter = True
        if not openrouter_api_key:
            print(f"{Fore.RED}Error: OpenRouter API key is required when using openrouter API.{Style.RESET_ALL}")
            print("Set it with -k/--api-key or as an environment variable OPENROUTER_API_KEY")
            return 1
    
    # Get default Ollama model or use specified one
    ollama_model = None  # This will trigger model selection prompt if not using OpenRouter
    if args.model and not use_openrouter:
        ollama_model = args.model
    
    if use_openrouter:
        print(f"{Fore.GREEN}Using OpenRouter API for AI capabilities{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Using Ollama for AI capabilities{Style.RESET_ALL}")
        
    # Initialize the scanner with chat mode enabled
    scanner = BugBountyAI(
        target=target,
        output_dir="results",
        openrouter_api_key=openrouter_api_key,
        scan_type="full",
        ollama_model=ollama_model,
        ai_persona=args.persona,
        chat_mode=chat_mode,
        use_openrouter=use_openrouter,
        no_prompt=args.no_prompt
    )
    
    # Always run in chat mode
    try:
        scanner.run_interactive_chat()
    except Exception as e:
        logger.error(f"Error in chat mode: {str(e)}")
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 
#!/usr/bin/env python3

import os
import re
import json
import requests
import socket
import subprocess
from urllib.parse import urlparse
import ipaddress
import dns.resolver
import warnings
import ssl
import platform
import sys
from datetime import datetime

# Ignore SSL warnings for requests
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def is_valid_domain(domain):
    """Check if a string is a valid domain name"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def is_valid_ip(ip):
    """Check if a string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_url(url):
    """Check if a string is a valid URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def normalize_target(target):
    """Normalize target to a consistent format"""
    if is_valid_url(target):
        parsed = urlparse(target)
        return parsed.netloc
    return target

def extract_root_domain(domain):
    """Extract the root domain from a subdomain"""
    parts = domain.split('.')
    if len(parts) > 2:
        return '.'.join(parts[-2:])
    return domain

def get_ip_for_target(target):
    """Get IP address for a target (domain or IP)"""
    if is_valid_ip(target):
        return target
    
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def check_tool_availability(tool_name):
    """Check if a tool is available in the system"""
    try:
        subprocess.run(["which", tool_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        # Try Windows 'where' command for Windows systems
        if platform.system() == "Windows":
            try:
                subprocess.run(["where", tool_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return True
            except subprocess.CalledProcessError:
                return False
        return False

def extract_domains_from_text(text):
    """Extract domain names from text"""
    pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    return re.findall(pattern, text)

def extract_ips_from_text(text):
    """Extract IP addresses from text"""
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(pattern, text)

def extract_urls_from_text(text):
    """Extract URLs from text"""
    pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    return re.findall(pattern, text)

def get_timestamp():
    """Get formatted timestamp for filenames and reports"""
    return datetime.now().strftime('%Y%m%d_%H%M%S')

def save_json(data, filename):
    """Save data as JSON file"""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def load_json(filename):
    """Load data from JSON file"""
    with open(filename, 'r') as f:
        return json.load(f)

def truncate_text(text, max_length=4000):
    """Truncate text to a maximum length for API calls"""
    if len(text) <= max_length:
        return text
    return text[:max_length-100] + "... [truncated]"

def safe_filename(name):
    """Convert string to a safe filename"""
    return re.sub(r'[^\w\-\.]', '_', name)

def check_internet_connection():
    """Check if there is an active internet connection"""
    try:
        requests.get("https://www.google.com", timeout=5, verify=False)
        return True
    except requests.ConnectionError:
        return False

def get_severity_color(severity):
    """Return ANSI color code for severity level"""
    colors = {
        "critical": "\033[91m",  # Red
        "high": "\033[91m",      # Red
        "medium": "\033[93m",    # Yellow
        "low": "\033[94m",       # Blue
        "info": "\033[92m",      # Green
        "unknown": "\033[0m"     # Default
    }
    return colors.get(severity.lower(), "\033[0m")

def colorize(text, color):
    """Add color to text"""
    reset = "\033[0m"
    return f"{color}{text}{reset}"

def is_port_open(ip, port, timeout=2):
    """Check if a port is open on the target"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, int(port)))
        sock.close()
        return result == 0
    except:
        return False

def check_ssl_cert(hostname, port=443):
    """Check SSL certificate details for a host"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": dict(x[0] for x in cert['subject']),
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "version": cert['version'],
                    "notBefore": cert['notBefore'],
                    "notAfter": cert['notAfter']
                }
    except:
        return None

def resolve_dns(domain, record_type="A"):
    """Resolve DNS records for a domain"""
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, record_type)
        return [answer.to_text() for answer in answers]
    except:
        return []

def is_running_as_root():
    """Check if the script is running with root privileges"""
    if platform.system() == "Windows":
        return True  # Windows doesn't have the same concept of root
    return os.geteuid() == 0

def check_kali_linux():
    """Check if the script is running on Kali Linux"""
    if platform.system() != "Linux":
        return False
    
    try:
        with open("/etc/os-release", "r") as f:
            content = f.read()
            return "Kali" in content
    except:
        return False

def format_time_elapsed(seconds):
    """Format seconds into a human-readable time format"""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        seconds = int(seconds % 60)
        return f"{minutes}m {seconds}s"
    else:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        seconds = int(seconds % 60)
        return f"{hours}h {minutes}m {seconds}s"

def ensure_dir_exists(directory):
    """Ensure a directory exists, creating it if necessary"""
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    return directory

def sanitize_directory_name(name):
    """Convert a string to a safe directory name"""
    return re.sub(r'[^\w\-]', '_', name) 
# BugBountyAI: AI-Powered Hacking Assistant

BugBountyAI is a comprehensive, automated bug bounty tool that integrates various security testing tools with AI capabilities. It acts as a virtual hacker assistant, helping you perform comprehensive security assessments on domains and IP addresses.

![BugBountyAI Screenshot](screenshots/demo.png)

## Features

### Core Features

- **Intelligent Chat Interface**: Ask questions or give commands in natural language
- **Dual AI Integration**: Choose between local Ollama models or cloud-based OpenRouter API
- **Multi-Target Support**: Scan both domains and IP addresses with specialized workflows
- **Automated Workflow**: Complete reconnaissance-to-reporting pipeline with a single command
- **Comprehensive Methodology**: Follow industry-standard bug bounty approaches

### Scanning Capabilities

- **Subdomain Enumeration**: Discover subdomains using multiple tools (amass, subfinder, assetfinder, crt.sh)
- **Port Scanning**: Comprehensive port discovery and service identification
- **Service Enumeration**: Targeted tests based on discovered services
- **Vulnerability Scanning**: Multiple tools for finding security weaknesses
- **Web Application Testing**: CMS detection, directory brute-forcing, and vulnerability scanning
- **OWASP Top 10 Coverage**: Specific tests for each OWASP Top 10 vulnerability category

### Advanced Features

- **Firewall Evasion**: Toggle firewall evasion techniques for stealth
- **AI Personas**: Choose between different AI personalities (Hacker, PenTester, BugHunter, SecAnalyst)
- **Customizable Scans**: Basic to thorough scan options
- **Multi-threading**: Scans run in background threads for enhanced performance
- **Cross-Platform**: Works on Linux, macOS, and Windows (best on Kali Linux)

## Installation

### Prerequisites

- Python 3.8+
- Kali Linux recommended (provides most tools preinstalled)
- Ollama for local AI capabilities or OpenRouter API key for cloud-based AI

### Automatic Installation

```bash
git clone https://github.com/yourusername/BugBountyAI.git
cd BugBountyAI
sudo bash install.sh
```

The installation script will:
1. Create a Python virtual environment
2. Install required Python dependencies
3. Check for required external tools and offer to install missing ones
4. Set up executable permissions and symlinks

### Manual Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

2. Ensure you have required external tools:
   - `nmap`, `whois`, `dig`, `curl`, `jq` (Basic tools)
   - `amass`, `subfinder`, `assetfinder`, `findomain`, `dnsx`, `httpx` (Subdomain enumeration)
   - `gobuster`, `feroxbuster`, `nikto`, `nuclei`, `sqlmap` (Scanning tools)
   - `whatweb`, `wpscan`, `joomscan` (Web scanners)

3. Install Ollama or obtain OpenRouter API key:
   - Ollama: Visit [ollama.ai](https://ollama.ai) and follow installation instructions
   - OpenRouter: Register at [openrouter.ai](https://openrouter.ai) to get an API key

## Usage

### Basic Usage

Start the tool in chat mode (default):

```bash
python bug_bounty_ai.py
```

With OpenRouter API:
```bash
python bug_bounty_ai.py -a openrouter -k YOUR_API_KEY
```

With Ollama specific model:
```bash
python bug_bounty_ai.py -a ollama -m llama3
```

### Command-Line Options

```
python bug_bounty_ai.py [-m MODEL_NAME] [-a API] [-k API_KEY] [--persona PERSONA] [-v] [--no-prompt]
```

Arguments:
- `-m, --model`: Specify which Ollama model to use (e.g., deepseek-r1:7b, llama3)
- `-a, --api`: Choose AI provider (ollama or openrouter)
- `-k, --api-key`: OpenRouter API key (if using openrouter)
- `--persona`: Set AI persona (hacker, pentester, bughunter, analyst)
- `-v, --verbose`: Enable verbose output
- `--no-prompt`: Skip model selection prompt

### Interactive Chat Mode

In chat mode, you can use natural language to interact with the AI assistant:

- `set target example.com` - Set a target domain
- `set target 192.168.1.1` - Set a target IP
- `enumerate subdomains` - Find subdomains for the current domain target
- `port scan` - Scan open ports on the current target
- `vuln scan` - Run vulnerability scan on the current target
- `web scan` - Run web application scan on the current target
- `hack` - Start a comprehensive assessment on the current target
- `tools` - List available Kali Linux tools
- `methodology` - Show the bug bounty methodology steps
- `help` - Show help information

You can also simply type a domain or IP address to set it as the target.

## Bug Bounty Methodology

BugBountyAI follows a comprehensive bug bounty methodology:

### Phase 1: Pre-Engagement & Reconnaissance
- Define scope and objectives
- Passive information gathering (OSINT, social media, domain footprinting)
- Active information gathering (network scanning, port detection)

### Phase 2: Discovery & Enumeration
- Domain discovery (subdomain enumeration)
- Application mapping (technology identification)
- Content discovery (hidden files, JS analysis)

### Phase 3: Vulnerability Assessment
- Automated scanning
- Manual testing
- Business logic analysis

### Phase 4: Exploitation
- Exploit development
- Post-exploitation
- Data extraction

### Phase 5: Reporting
- Documentation
- Responsible disclosure
- Verification

## Tool Integration

BugBountyAI integrates with numerous security tools across different categories:

### Reconnaissance Tools
- nmap, whois, dig, theHarvester

### Subdomain Enumeration
- amass, subfinder, assetfinder, knockpy, httpx

### Content Discovery
- ffuf, gobuster, dirsearch, feroxbuster

### Vulnerability Scanning
- nuclei, nikto, sqlmap, wpscan, XSStrike

### Exploitation Tools
- metasploit, commix, hydra

## Troubleshooting

### Common Issues

1. **Ollama not found**: Make sure Ollama is installed and in your PATH
2. **Missing tools**: Use the install script to identify and install missing tools
3. **Permission issues**: Run with appropriate permissions (sudo on Linux)
4. **Target validation failures**: Ensure targets are properly formatted
5. **Variable not defined errors**: Ensure the latest version of the script is being used

### Logs

Logs are stored in the results directory for troubleshooting.

## Contributing

Contributions are welcome! Here's how you can contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b new-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin new-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The developers of all the integrated security tools
- The Ollama team for making powerful AI models locally accessible
- The security community for inspiring this project

---

**Note**: This tool is developed for ethical hacking and security research purposes only. Always obtain proper authorization before scanning or testing any systems you don't own.

## Architecture

BugBountyAI is structured into several key components:

- `bug_bounty_ai.py`: Main application script
- `config.py`: Configuration settings for tools, wordlists, etc.
- `utils.py`: Utility functions and helpers
- `requirements.txt`: Python dependencies
- `install.sh`: Installation script

The tool uses a modular design that separates:
- Target validation and normalization
- Tool execution and command running
- Result parsing and analysis
- Reporting and output generation

## AI Features

BugBountyAI leverages Ollama models to:

1. **Understand natural language commands**: Parse user intent from chat messages
2. **Analyze scan results**: Provide insights on discovered vulnerabilities
3. **Generate comprehensive reports**: Create detailed security assessment reports
4. **Suggest next steps**: Recommend actions based on scan findings

### AI Personas

- **H4X0R**: An elite ethical hacker with concise, technical advice
- **PenTester**: Professional penetration tester with methodical approach
- **BugHunter**: Bug bounty hunter focused on finding security issues that would qualify for bounties
- **SecAnalyst**: Security analyst providing detailed analysis and mitigation strategies

## Examples

### Simple Enumeration

```
[H4X0R] > enumerate subdomains of example.com
```

### Comprehensive Hacking

```
[H4X0R] > hack the target
```

### Tool Execution

```
[H4X0R] > run nmap -sV -p- target.com
```

### Web Testing

```
[H4X0R] > check for SQL injection in target.com
```

## Security and Ethics

This tool is intended for legitimate security testing with proper authorization. Always:

1. Ensure you have permission to test the target
2. Follow responsible disclosure guidelines
3. Respect scope limitations and rules of engagement
4. Use the tool ethically and legally

Unauthorized testing may violate laws including the Computer Fraud and Abuse Act (US) and similar laws in other countries.

## Troubleshooting

### Common Issues

1. **Ollama not found**: Make sure Ollama is installed and in your PATH
2. **Missing tools**: Use the install script to identify and install missing tools
3. **Permission issues**: Run with appropriate permissions (sudo on Linux)
4. **Target validation failures**: Ensure targets are properly formatted
5. **Variable not defined errors**: Ensure the latest version of the script is being used

### Logs

Logs are stored in the results directory for troubleshooting.

## Contributing

Contributions are welcome! Here's how you can contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b new-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin new-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The developers of all the integrated security tools
- The Ollama team for making powerful AI models locally accessible
- The security community for inspiring this project

---

**Note**: This tool is developed for ethical hacking and security research purposes only. 
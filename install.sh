#!/bin/bash

echo "Installing Bug Bounty AI Tool..."

# Detect OS
OS=$(uname -s)
KALI=false

if [ "$OS" = "Linux" ]; then
  if grep -q "Kali" /etc/os-release 2>/dev/null; then
    KALI=true
    echo "Kali Linux detected. Proceeding with optimal setup."
  else
    echo "Linux detected, but not Kali. Some tools may need to be installed manually."
  fi
elif [ "$OS" = "Darwin" ]; then
  echo "macOS detected. Some tools may not be available or may require manual installation."
elif [[ "$OS" == MINGW* || "$OS" == MSYS* || "$OS" == CYGWIN* ]]; then
  echo "Windows detected. This tool is optimized for Linux/Kali. Some features may not work properly."
  echo "Consider using WSL (Windows Subsystem for Linux) with Kali for best results."
else
  echo "Unknown operating system. Proceeding with limited functionality."
fi

# Check if running as root on Linux
if [ "$OS" = "Linux" ] && [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Create results directory
echo "Creating results directory..."
mkdir -p results

# Create a virtual environment
echo "Creating Python virtual environment..."
if command -v python3 &> /dev/null; then
  python3 -m venv venv
  if [ "$OS" = "Windows" ]; then
    source venv/Scripts/activate
  else
    source venv/bin/activate
  fi
else
  echo "Error: Python 3 not found. Please install Python 3."
  exit 1
fi

# Install required Python packages
echo "Installing Python dependencies..."
if [ "$OS" = "Linux" ] || [ "$OS" = "Darwin" ]; then
  if command -v pip3 &> /dev/null; then
    pip3 install -r requirements.txt
  elif command -v pip &> /dev/null; then
    pip install -r requirements.txt
  else
    echo "Error: pip not found. Please install Python and pip."
    exit 1
  fi
else
  # Windows
  pip install -r requirements.txt
fi

# Check for required tools on Linux/Kali
if [ "$KALI" = true ]; then
  tools=(
    # Core scanning tools
    "nmap" "sqlmap" "ffuf" "nikto" "nuclei" "gobuster" "feroxbuster"
    # Web scanning
    "zaproxy" "zap-cli" "wpscan" "joomscan" "sslyze" "whatweb"
    # Advanced scanning
    "dirb" "wpscan" "metasploit-framework" "hydra" 
    # Subdomain enumeration
    "amass" "subfinder" "assetfinder" "findomain" "dnsx" "httpx"
    # DNS and other utilities
    "dig" "whois" "curl" "jq"
  )

  # Check for each tool and offer to install if missing
  for tool in "${tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
      echo "Warning: $tool is not installed. Some functionality may be limited."
      
      # Offer to install missing tools except Ollama
      if [ "$tool" != "ollama" ]; then
        read -p "Do you want to install $tool? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
          apt-get update
          
          case "$tool" in
            "zaproxy")
              apt-get install -y zaproxy
              ;;
            "zap-cli")
              pip3 install zapcli
              ;;
            "assetfinder" | "findomain" | "dnsx" | "httpx" | "subfinder" | "ffuf")
              echo "Installing GO tools..."
              if ! command -v go &> /dev/null; then
                echo "GO is not installed. Installing GO first..."
                apt-get install -y golang
              fi
              case "$tool" in
                "assetfinder")
                  go install github.com/tomnomnom/assetfinder@latest
                  ;;
                "findomain")
                  go install github.com/Findomain/findomain@latest
                  ;;
                "dnsx")
                  go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
                  ;;
                "httpx")
                  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
                  ;;
                "subfinder")
                  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
                  ;;
                "ffuf")
                  go install github.com/ffuf/ffuf/v2@latest
                  ;;
              esac
              ;;
            "nuclei")
              go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
              ;;
            *)
              apt-get install -y "$tool"
              ;;
          esac
        fi
      else
        echo "Ollama needs to be installed manually. Visit https://ollama.ai for installation instructions."
      fi
    else
      echo "$tool is already installed."
    fi
  done

  # Check for XSStrike and install if not present
  if [ ! -d "/opt/XSStrike" ]; then
    echo "XSStrike not found. Would you like to install it? (recommended for XSS testing)"
    read -p "(y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      git clone https://github.com/s0md3v/XSStrike.git /opt/XSStrike
      cd /opt/XSStrike
      pip3 install -r requirements.txt
      cd - > /dev/null
    fi
  fi

  # Download SecLists if not already present
  if [ ! -d "/usr/share/wordlists/SecLists" ]; then
    echo "SecLists not found. Would you like to download it? (recommended for comprehensive scanning)"
    read -p "(y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists
    fi
  fi
else
  # Non-Kali system
  echo "On non-Kali systems, make sure you have the following tools installed:"
  echo "- nmap: Network scanner"
  echo "- ollama: Local LLM runner"
  echo "- whois: Domain information lookup"
  echo "- dig: DNS lookup utility"
  echo "- curl: Command line tool for transferring data with URLs"
  echo "- jq: Command-line JSON processor"
  echo "- gobuster/dirb: Directory brute force tools"
  echo "Other tools like sqlmap, ffuf, nuclei, etc. will enhance functionality if available."
fi

# Make scripts executable
chmod +x bug_bounty_ai.py
chmod +x utils.py
chmod +x config.py

# Create symbolic link only on Linux/macOS
if [ "$OS" = "Linux" ] || [ "$OS" = "Darwin" ]; then
  if [ "$OS" = "Linux" ]; then
    ln -sf "$(pwd)/bug_bounty_ai.py" /usr/local/bin/bug-bounty-ai
  elif [ "$OS" = "Darwin" ]; then
    # Create a bin directory in user's home if it doesn't exist
    mkdir -p "$HOME/bin"
    ln -sf "$(pwd)/bug_bounty_ai.py" "$HOME/bin/bug-bounty-ai"
    echo "Added symbolic link to $HOME/bin/. Make sure this directory is in your PATH."
  fi
else
  echo "On Windows, you can run the tool with: python bug_bounty_ai.py"
fi

echo "Installation completed!"
echo "You can run the tool with: python bug_bounty_ai.py"
echo "The tool will operate in chat mode by default and prompt you for a target."
echo "For more options, run: python bug_bounty_ai.py --help"

# Check if Ollama is installed
if command -v ollama &> /dev/null; then
  # Check Ollama models
  echo "Checking for available Ollama models..."
  available_models=$(ollama list 2>/dev/null)
  
  if [ -z "$available_models" ]; then
    echo "No Ollama models found. You'll need to download at least one model."
    echo "Recommended: run 'ollama pull deepseek-r1:7b' for a good balance of size and capability."
    echo "Other options: 'ollama pull llama3', 'ollama pull mistral', or 'ollama pull gemma:7b'"
  else
    echo "Found Ollama models:"
    echo "$available_models"
  fi
  
  # Check if Ollama service is running
  if ! ps aux | grep -v grep | grep -q ollama; then
    echo ""
    echo "IMPORTANT: Ollama service does not appear to be running."
    if [ "$OS" = "Linux" ]; then
      echo "You can start it with: systemctl start ollama (if installed as a service)"
      echo "or manually with: ollama serve"
    elif [ "$OS" = "Darwin" ]; then
      echo "You can start it manually with: ollama serve"
    else
      echo "Make sure to start Ollama before using the chat mode."
    fi
  fi
else
  echo "Ollama is not installed. You'll need to install it to use the AI chat features."
  echo "Visit https://ollama.ai for installation instructions."
  echo "Alternatively, you can use OpenRouter API with the -a openrouter flag and an API key."
fi 
#!/bin/bash

# Argus-Scan Setup Script (Lightweight)
# Sets up Python environment and checks for system dependencies.

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_command() {
    command -v "$1" &> /dev/null
}

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}    Argus-Scan Environment Setup        ${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""

# --- System Dependency Check ---
log_info "Checking system dependencies..."

MISSING_TOOLS=0

# Nmap
if check_command nmap; then
    log_success "Nmap found."
else
    log_warn "Nmap NOT found."
    echo "      To install: ${YELLOW}sudo apt install nmap${NC}"
    MISSING_TOOLS=1
fi

# Nikto
if check_command nikto; then
    log_success "Nikto found."
else
    log_warn "Nikto NOT found."
    echo "      To install: ${YELLOW}sudo apt install nikto${NC}"
    MISSING_TOOLS=1
fi

# Nuclei
if check_command nuclei; then
    log_success "Nuclei found."
else
    log_warn "Nuclei NOT found."
    echo "      To install: Consult https://github.com/projectdiscovery/nuclei"
    echo "      Or use: ${YELLOW}go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${NC}"
    MISSING_TOOLS=1
fi

if [ $MISSING_TOOLS -eq 1 ]; then
    echo ""
    log_warn "Some system tools are missing. The Python script will run, but scans relying on these tools will fail."
    echo ""
fi

# --- Python Environment ---

log_info "Setting up Python environment..."

# Check Python 3
if ! check_command python3; then
    log_error "Python 3 is required but not found. Aborting."
    exit 1
fi

# Check/Install venv module
if ! python3 -c "import venv" &> /dev/null; then
    log_warn "python3-venv module missing. Attempting to install..."
    if command -v apt &> /dev/null; then
        sudo apt update && sudo apt install -y python3-venv
        if [ $? -ne 0 ]; then
             log_error "Failed to install python3-venv. Please install it manually."
             exit 1
        fi
    else
        log_error "Cannot auto-install python3-venv. Please install it manually."
        exit 1
    fi
fi

# Create venv
if [ ! -d "venv" ]; then
    log_info "Creating virtual environment 'venv'..."
    python3 -m venv venv
else
    log_info "Virtual environment 'venv' already exists."
fi

# Activate and Install Requirements
log_info "Installing Python dependencies..."
source venv/bin/activate

pip install --upgrade pip &> /dev/null
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    if [ $? -eq 0 ]; then
        log_success "Python dependencies installed successfully."
    else
        log_error "Failed to install Python dependencies."
        exit 1
    fi
else
    log_warn "requirements.txt not found. Skipping dependency installation."
fi

# --- Summary ---
echo ""
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "To start using Argus-Scan:"
echo -e "  1. ${YELLOW}source venv/bin/activate${NC}"
echo -e "${YELLOW}    python src/vapt.py --target <target>${NC}"
echo ""

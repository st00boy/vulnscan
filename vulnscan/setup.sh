#!/bin/bash
# ============================================================
#  VulnScan - Auto Setup Script
#  Author : st00boy
#  GitHub : https://github.com/st00boy
# ============================================================
# This script installs everything VulnScan needs automatically.
# Run it once after downloading the project.
# Usage: bash setup.sh
# ============================================================

RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
CYAN='\033[0;96m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

print_banner() {
  echo -e "${CYAN}"
  echo "  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗"
  echo "  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║"
  echo "   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║"
  echo -e "${RESET}"
  echo -e "  ${YELLOW}Auto Setup Script${RESET}  ${DIM}by st00boy — https://github.com/st00boy${RESET}"
  echo -e "  ${DIM}$(printf '─%.0s' {1..60})${RESET}"
  echo ""
}

log_ok()   { echo -e "  ${GREEN}[✓]${RESET} $1"; }
log_info() { echo -e "  ${CYAN}[*]${RESET} $1"; }
log_warn() { echo -e "  ${YELLOW}[!]${RESET} $1"; }
log_err()  { echo -e "  ${RED}[✗]${RESET} $1"; }
log_step() { echo -e "\n  ${BOLD}${CYAN}──── $1 ────${RESET}"; }

print_banner

# ── STEP 1: Check OS ──
log_step "Checking System"

OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  OS="linux"
  log_ok "Linux detected"
elif [[ "$OSTYPE" == "darwin"* ]]; then
  OS="mac"
  log_ok "macOS detected"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
  OS="windows"
  log_warn "Windows detected — use WSL or Git Bash for best results"
else
  log_warn "Unknown OS: $OSTYPE — proceeding anyway"
fi

# ── STEP 2: Check Python ──
log_step "Checking Python"

if command -v python3 &>/dev/null; then
  PYTHON=$(command -v python3)
  VERSION=$($PYTHON --version 2>&1)
  log_ok "Found: $VERSION ($PYTHON)"
elif command -v python &>/dev/null; then
  PYTHON=$(command -v python)
  VERSION=$($PYTHON --version 2>&1)
  if [[ "$VERSION" == *"3."* ]]; then
    log_ok "Found: $VERSION ($PYTHON)"
  else
    log_err "Python 3 required but found $VERSION"
    log_info "Install Python 3 from https://python.org/downloads"
    exit 1
  fi
else
  log_err "Python 3 not found!"
  log_info "Install from: https://python.org/downloads"
  exit 1
fi

# ── STEP 3: Check pip ──
log_step "Checking pip"

if $PYTHON -m pip --version &>/dev/null; then
  PIP_VERSION=$($PYTHON -m pip --version 2>&1)
  log_ok "pip found: $PIP_VERSION"
else
  log_warn "pip not found — attempting to install..."
  $PYTHON -m ensurepip --upgrade 2>/dev/null || {
    log_err "Could not install pip. Install manually: https://pip.pypa.io"
    exit 1
  }
  log_ok "pip installed successfully"
fi

# ── STEP 4: Install dependencies ──
log_step "Installing Dependencies"

log_info "Installing from requirements.txt..."
$PYTHON -m pip install -r requirements.txt --quiet --upgrade

if [ $? -eq 0 ]; then
  log_ok "requests installed"
  log_ok "urllib3 installed"
else
  log_err "Dependency install failed. Try: pip install requests urllib3"
  exit 1
fi

# ── STEP 5: Make scripts executable ──
log_step "Setting Permissions"

chmod +x vulnscan.py   && log_ok "vulnscan.py — executable"
chmod +x view_report.py && log_ok "view_report.py — executable"
chmod +x setup.sh       && log_ok "setup.sh — executable"

# ── STEP 6: Create output dirs ──
log_step "Creating Directories"

mkdir -p reports   && log_ok "reports/ created"
mkdir -p wordlists && log_ok "wordlists/ created"

# ── STEP 7: Verify structure ──
log_step "Verifying Installation"

REQUIRED_FILES=(
  "vulnscan.py"
  "modules/base.py"
  "modules/xss.py"
  "modules/sqli.py"
  "utils/helpers.py"
  "utils/banner.py"
  "utils/report.py"
  "dashboard.html"
)

ALL_OK=true
for f in "${REQUIRED_FILES[@]}"; do
  if [ -f "$f" ]; then
    log_ok "$f"
  else
    log_err "Missing: $f"
    ALL_OK=false
  fi
done

# ── DONE ──
echo ""
echo -e "  ${DIM}$(printf '─%.0s' {1..60})${RESET}"

if [ "$ALL_OK" = true ]; then
  echo -e "\n  ${GREEN}${BOLD}✓ VulnScan is ready!${RESET}\n"
  echo -e "  ${CYAN}Run the tool:${RESET}"
  echo -e "  ${DIM}$${RESET}  ${YELLOW}python3 vulnscan.py${RESET}               ${DIM}← interactive menu${RESET}"
  echo -e "  ${DIM}$${RESET}  ${YELLOW}python3 vulnscan.py http://target.com${RESET}  ${DIM}← direct scan${RESET}"
  echo -e "  ${DIM}$${RESET}  ${YELLOW}python3 vulnscan.py --list${RESET}         ${DIM}← list all modules${RESET}"
  echo -e "  ${DIM}$${RESET}  ${YELLOW}python3 view_report.py${RESET}             ${DIM}← view scan reports${RESET}"
  echo ""
  echo -e "  ${DIM}GitHub: https://github.com/st00boy${RESET}"
  echo -e "  ${RED}⚠  Only test systems you own or have permission to test.${RESET}"
  echo ""
else
  echo -e "\n  ${YELLOW}⚠ Setup completed with warnings — some files may be missing.${RESET}"
  echo -e "  Re-download the ZIP from https://github.com/st00boy/vulnscan\n"
fi

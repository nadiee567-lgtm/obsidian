#!/bin/bash
# OBSIDIAN Installer — Linux
# Installs OBSIDIAN on any Linux distribution

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${CYAN}${BOLD}⬛ OBSIDIAN — Linux Installer${NC}"
echo -e "${CYAN}────────────────────────────────────────${NC}"
echo ""

# Detect package manager
if command -v dnf &>/dev/null; then
    PKG="dnf"
    PKG_INSTALL="sudo dnf install -y"
elif command -v apt-get &>/dev/null; then
    PKG="apt"
    PKG_INSTALL="sudo apt-get install -y"
elif command -v pacman &>/dev/null; then
    PKG="pacman"
    PKG_INSTALL="sudo pacman -S --noconfirm"
else
    echo -e "${RED}[!] Package manager not recognized${NC}"
    exit 1
fi
echo -e "${BLUE}[*] Detected distro: $PKG${NC}"

# Detect RAM
RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
RAM_GB=$((RAM_MB / 1024))
echo -e "${BLUE}[*] RAM detected: ${RAM_GB}GB${NC}"
if [ $RAM_GB -lt 4 ]; then
    echo -e "${YELLOW}[!] Minimum 4GB RAM recommended${NC}"
elif [ $RAM_GB -ge 16 ]; then
    echo -e "${GREEN}[+] RAM sufficient for OBSIDIAN Professional${NC}"
elif [ $RAM_GB -ge 8 ]; then
    echo -e "${GREEN}[+] RAM sufficient for OBSIDIAN Analyst${NC}"
else
    echo -e "${GREEN}[+] RAM sufficient for OBSIDIAN Investigator${NC}"
fi

# Create directories
echo ""
echo -e "${BLUE}[*] Creating directory structure...${NC}"
mkdir -p ~/.obsidian
mkdir -p ~/obsidian-cases
mkdir -p ~/obsidian-static

# Check Python 3
echo -e "${BLUE}[*] Checking Python 3...${NC}"
if ! command -v python3 &>/dev/null; then
    echo -e "${YELLOW}[*] Installing Python 3...${NC}"
    $PKG_INSTALL python3 python3-pip
fi
PYTHON_VER=$(python3 --version 2>&1)
echo -e "${GREEN}[+] $PYTHON_VER${NC}"

# Install Python dependencies
echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
pip3 install flask flask-cors requests --quiet --break-system-packages 2>/dev/null || \
pip3 install flask flask-cors requests --quiet 2>/dev/null || \
pip3 install --user flask flask-cors requests --quiet
echo -e "${GREEN}[+] Flask, CORS, Requests installed${NC}"

# Install system tools
echo -e "${BLUE}[*] Installing recon tools...${NC}"
if [ "$PKG" = "dnf" ]; then
    sudo dnf install -y nmap whois curl wget 2>/dev/null || true
elif [ "$PKG" = "apt" ]; then
    sudo apt-get install -y nmap whois curl wget 2>/dev/null || true
elif [ "$PKG" = "pacman" ]; then
    sudo pacman -S --noconfirm nmap whois curl wget 2>/dev/null || true
fi

# Install optional OSINT tools
echo -e "${BLUE}[*] Installing optional OSINT tools...${NC}"
pip3 install holehe shodan --quiet --break-system-packages 2>/dev/null || \
pip3 install --user holehe shodan --quiet 2>/dev/null || true

# Download vis.js if missing
if [ ! -f ~/obsidian-static/vis-network.min.js ]; then
    echo -e "${BLUE}[*] Downloading vis-network.js...${NC}"
    curl -sL "https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js" \
         -o ~/obsidian-static/vis-network.min.js 2>/dev/null || \
    wget -q "https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js" \
         -O ~/obsidian-static/vis-network.min.js 2>/dev/null || true
    if [ -f ~/obsidian-static/vis-network.min.js ]; then
        echo -e "${GREEN}[+] vis-network.js downloaded${NC}"
    else
        echo -e "${YELLOW}[!] vis-network.js not downloaded — graph may not work offline${NC}"
    fi
fi

# Copy main files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo -e "${BLUE}[*] Installing OBSIDIAN to ~/.obsidian/...${NC}"
cp "$SCRIPT_DIR/obsidian_web.py" ~/.obsidian/obsidian_web.py

# OBSIDIAN is free and open -- no licenses or tiers.

# ── Tailscale -- remote access ─────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}━━━ Remote access with Tailscale (optional) ━━━${NC}"
echo -e "${CYAN}    Access OBSIDIAN from anywhere — traveling,${NC}"
echo -e "${CYAN}    from your phone, or any network. No port forwarding needed.${NC}"
echo ""
read -p "$(echo -e "${YELLOW}Install Tailscale for remote access? [Y/n]: ${NC}")" INSTALL_TAILSCALE
INSTALL_TAILSCALE=${INSTALL_TAILSCALE:-Y}

if [[ "$INSTALL_TAILSCALE" =~ ^[Yy]$ ]]; then
    if command -v tailscale &>/dev/null; then
        echo -e "${GREEN}[+] Tailscale is already installed${NC}"
        TS_IP=$(tailscale ip -4 2>/dev/null || echo "")
        if [ -n "$TS_IP" ]; then
            echo -e "${GREEN}[+] Your Tailscale IP: ${BOLD}$TS_IP${NC}"
            echo -e "${GREEN}[+] OBSIDIAN accessible at: http://$TS_IP:8767${NC}"
        else
            echo -e "${YELLOW}[!] Tailscale installed but not connected${NC}"
            echo -e "${YELLOW}    Run: sudo tailscale up${NC}"
        fi
    else
        echo -e "${BLUE}[*] Installing Tailscale...${NC}"
        curl -fsSL https://tailscale.com/install.sh | sh 2>/dev/null || true

        if command -v tailscale &>/dev/null; then
            echo -e "${GREEN}[+] Tailscale installed${NC}"
            sudo systemctl enable --now tailscaled 2>/dev/null || true
            echo ""
            echo -e "${YELLOW}${BOLD}━━━ IMPORTANT — Connect Tailscale ━━━${NC}"
            echo -e "${YELLOW}Run this command and open the link that appears:${NC}"
            echo -e "${BOLD}    sudo tailscale up${NC}"
            echo ""
            echo -e "${YELLOW}Then on your phone:${NC}"
            echo -e "  1. Install Tailscale from Play Store or App Store"
            echo -e "  2. Sign in with the same account"
            echo -e "  3. Open in your phone browser: ${BOLD}http://[YOUR-TAILSCALE-IP]:8767${NC}"
            echo ""
        else
            echo -e "${RED}[!] Could not install Tailscale automatically${NC}"
            echo -e "${YELLOW}    Install manually from: https://tailscale.com/download${NC}"
        fi
    fi
else
    echo -e "${CYAN}[i] Tailscale skipped — OBSIDIAN accessible on local network only${NC}"
    echo -e "${CYAN}    You can install it later from: https://tailscale.com/download${NC}"
fi

# Create global command
echo ""
echo -e "${BLUE}[*] Creating 'obsidian-web' command...${NC}"
mkdir -p ~/.local/bin
cat > ~/.local/bin/obsidian-web << 'EOF'
#!/bin/bash
cd ~/.obsidian
python3 obsidian_web.py "$@"
EOF
chmod +x ~/.local/bin/obsidian-web

# Add to PATH if missing
if ! grep -q 'export PATH.*\.local/bin' ~/.bashrc 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
fi

echo ""
echo -e "${GREEN}${BOLD}✅ OBSIDIAN installed successfully${NC}"
echo -e "${CYAN}────────────────────────────────────────${NC}"
echo -e "${BOLD}To start:${NC}"
echo -e "  ${YELLOW}obsidian-web${NC}           → Start server"
echo -e "  ${YELLOW}obsidian-web &${NC}         → Start in background"
echo ""
echo -e "${BOLD}Access:${NC}"
echo -e "  ${YELLOW}http://localhost:8767${NC}      → Local browser"
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -n "$LOCAL_IP" ]; then
    echo -e "  ${YELLOW}http://$LOCAL_IP:8767${NC}  → Local network / phone"
fi
TS_IP=$(tailscale ip -4 2>/dev/null || echo "")
if [ -n "$TS_IP" ]; then
    echo -e "  ${YELLOW}http://$TS_IP:8767${NC}     → ${GREEN}From anywhere (Tailscale)${NC}"
fi
echo ""
echo -e "${BOLD}Remote access from phone:${NC}"
echo -e "  1. Install Tailscale on your phone (Play Store / App Store)"
echo -e "  2. Sign in with the same account"
echo -e "  3. Open in browser: ${YELLOW}http://[TAILSCALE-IP]:8767${NC}"
echo ""
echo -e "${CYAN}⬛ OBSIDIAN — Your data. Your control.${NC}"
echo ""

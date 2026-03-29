#!/usr/bin/env bash
set -e

# ============================================================
#  Watson CTF Installer
#  "When you have eliminated the impossible, whatever remains,
#   however improbable, must be the truth." — but Watson does
#   the heavy lifting first.
# ============================================================

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
RED="\033[31m"
RESET="\033[0m"

banner() {
cat <<'EOF'

  ██╗    ██╗ █████╗ ████████╗███████╗ ██████╗ ███╗   ██╗
  ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██╔═══██╗████╗  ██║
  ██║ █╗ ██║███████║   ██║   ███████╗██║   ██║██╔██╗ ██║
  ██║███╗██║██╔══██║   ██║   ╚════██║██║   ██║██║╚██╗██║
  ╚███╔███╔╝██║  ██║   ██║   ███████║╚██████╔╝██║ ╚████║
   ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝

       F O R E N S I C S   C T F   S O L V E R
       "I observe, I deduce, I document."
                               — Dr. J.H. Watson
EOF
}

info()    { echo -e "${CYAN}[Watson]${RESET} $*"; }
success() { echo -e "${GREEN}[  OK  ]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[ WARN ]${RESET} $*"; }
error()   { echo -e "${RED}[ERROR ]${RESET} $*"; }

banner
echo ""
info "Commencing installation. Elementary, my dear user."
echo ""

# ------------------------------------------------------------------
# 1. Check Python >= 3.9
# ------------------------------------------------------------------
info "Checking Python version..."

PYTHON=$(command -v python3 || command -v python || true)
if [[ -z "$PYTHON" ]]; then
    error "Python not found. Please install Python >= 3.9 first."
    exit 1
fi

PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$("$PYTHON" -c "import sys; print(sys.version_info.major)")
PY_MINOR=$("$PYTHON" -c "import sys; print(sys.version_info.minor)")

if [[ "$PY_MAJOR" -lt 3 ]] || { [[ "$PY_MAJOR" -eq 3 ]] && [[ "$PY_MINOR" -lt 9 ]]; }; then
    error "Python $PY_VERSION found, but Watson requires >= 3.9."
    exit 1
fi
success "Python $PY_VERSION — satisfactory."

# ------------------------------------------------------------------
# 2. Install the pip package
# ------------------------------------------------------------------
info "Installing watson-ctf package (editable)..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$PYTHON" -m pip install -e "$SCRIPT_DIR" --quiet && success "watson-ctf installed." || {
    error "pip install failed. Try running with sudo or inside a virtualenv."
    exit 1
}

# ------------------------------------------------------------------
# 3. Detect OS and install system dependencies
# ------------------------------------------------------------------
SYSTEM_DEPS="binwalk foremost sleuthkit steghide exiftool qemu-utils"

detect_os() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    elif command -v brew &>/dev/null; then
        echo "brew"
    else
        echo "unknown"
    fi
}

OS_TYPE=$(detect_os)
info "Detected package manager: ${BOLD}$OS_TYPE${RESET}"

install_system_deps() {
    case "$OS_TYPE" in
        apt)
            info "Installing system dependencies via apt..."
            # exiftool is libimage-exiftool-perl on debian/ubuntu
            # qemu-utils for qemu-img
            sudo apt-get update -qq 2>/dev/null || warn "apt-get update failed, continuing..."
            for pkg in binwalk foremost sleuthkit steghide libimage-exiftool-perl qemu-utils; do
                sudo apt-get install -y -qq "$pkg" 2>/dev/null && success "$pkg installed." || warn "$pkg could not be installed — skipping."
            done
            ;;
        pacman)
            info "Installing system dependencies via pacman..."
            for pkg in binwalk foremost sleuthkit steghide perl-image-exiftool qemu; do
                sudo pacman -S --noconfirm --needed "$pkg" 2>/dev/null && success "$pkg installed." || warn "$pkg could not be installed — skipping."
            done
            ;;
        brew)
            info "Installing system dependencies via homebrew..."
            for pkg in binwalk foremost sleuthkit steghide exiftool qemu; do
                brew install "$pkg" 2>/dev/null && success "$pkg installed." || warn "$pkg could not be installed — skipping."
            done
            ;;
        *)
            warn "Unknown package manager. Please install manually: $SYSTEM_DEPS"
            warn "Supported: apt (Debian/Ubuntu), pacman (Arch), brew (macOS)"
            ;;
    esac
}

install_system_deps

# ------------------------------------------------------------------
# 4. Optional Python dependencies
# ------------------------------------------------------------------
info "Attempting to install optional Python dependencies..."
OPTIONAL_DEPS="mutagen pypdf scapy scipy numpy"
for dep in $OPTIONAL_DEPS; do
    "$PYTHON" -m pip install "$dep" --quiet 2>/dev/null && success "Python: $dep installed." || warn "Python: $dep could not be installed — some features will be limited."
done

# pytsk3 can be tricky
"$PYTHON" -m pip install pytsk3 --quiet 2>/dev/null && success "Python: pytsk3 installed." || warn "Python: pytsk3 not available — disk analysis will use sleuthkit CLI tools."

# ------------------------------------------------------------------
# 5. Run watson doctor
# ------------------------------------------------------------------
echo ""
info "Running ${BOLD}watson doctor${RESET} to check capabilities..."
echo ""
watson doctor 2>/dev/null || "$PYTHON" -m watson.cli doctor 2>/dev/null || warn "Could not run 'watson doctor' — check your PATH."

# ------------------------------------------------------------------
# 6. Closing quote
# ------------------------------------------------------------------
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  Installation complete.${RESET}"
echo ""
echo -e "  \"I had no keener pleasure than in following Holmes in his"
echo -e "   professional investigations, and in admiring the rapid"
echo -e "   deductions... Now Watson does the following for you.\""
echo ""
echo -e "  Run ${GREEN}watson examine <file>${RESET} to begin your investigation."
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

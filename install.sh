#!/usr/bin/env bash
set -e

# ============================================================
#  Watson CTF Installer
#  Usage: curl -fsSL https://raw.githubusercontent.com/Hum-Coder/WatsonCTF/main/install.sh | bash
#
#  "When you have eliminated the impossible, whatever remains,
#   however improbable, must be the truth." — but Watson does
#   the heavy lifting first.
# ============================================================

REPO_URL="https://github.com/Hum-Coder/WatsonCTF.git"
INSTALL_DIR="${HOME}/.local/share/watson-ctf"

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
# Parse --modules flag
# ------------------------------------------------------------------
SELECTED_MODULES=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --modules=*) SELECTED_MODULES="${1#*=}"; shift ;;
        --modules)   shift; SELECTED_MODULES="$1"; shift ;;
        *)           shift ;;
    esac
done

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
# 2. Clone or update the repo
# ------------------------------------------------------------------
if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Updating existing Watson installation at $INSTALL_DIR..."
    git -C "$INSTALL_DIR" pull --quiet && success "Repository updated." || warn "Could not update repo — using existing version."
else
    info "Cloning Watson into $INSTALL_DIR..."
    git clone --quiet "$REPO_URL" "$INSTALL_DIR" && success "Repository cloned." || {
        error "git clone failed. Check your internet connection."
        exit 1
    }
fi

# ------------------------------------------------------------------
# 3. Install the pip package (core only — no optional deps yet)
# ------------------------------------------------------------------
info "Installing watson-ctf package..."
"$PYTHON" -m pip install -e "$INSTALL_DIR" --quiet && success "watson-ctf installed." || {
    error "pip install failed. Try running with sudo or inside a virtualenv."
    exit 1
}

# ------------------------------------------------------------------
# 4. Interactive module selection (only if --modules not provided)
# ------------------------------------------------------------------
if [[ -z "$SELECTED_MODULES" ]]; then
    echo ""
    info "Which modules would you like to install?"
    echo ""
    echo "  [1] images      — PNG, JPEG, GIF steganography and metadata      (Pillow)"
    echo "  [2] audio       — Spectrogram, LSB, audio metadata               (mutagen, scipy, numpy)"
    echo "  [3] documents   — PDF analysis and text extraction                (pypdf, poppler-utils)"
    echo "  [4] containers  — ZIP extraction and binary carving               (binwalk)"
    echo "  [5] disk        — Disk image forensics, deleted file recovery     (sleuthkit, qemu)"
    echo ""
    printf "  Enter numbers separated by spaces, 'all', or press Enter for default [1 4]: "
    read -r MODULE_INPUT

    if [[ -z "$MODULE_INPUT" ]]; then
        MODULE_INPUT="1 4"
    fi

    if [[ "$MODULE_INPUT" == "all" ]]; then
        SELECTED_MODULES="images,audio,documents,containers,disk"
    else
        SELECTED_MODULES=""
        for num in $MODULE_INPUT; do
            case "$num" in
                1) SELECTED_MODULES="${SELECTED_MODULES:+$SELECTED_MODULES,}images" ;;
                2) SELECTED_MODULES="${SELECTED_MODULES:+$SELECTED_MODULES,}audio" ;;
                3) SELECTED_MODULES="${SELECTED_MODULES:+$SELECTED_MODULES,}documents" ;;
                4) SELECTED_MODULES="${SELECTED_MODULES:+$SELECTED_MODULES,}containers" ;;
                5) SELECTED_MODULES="${SELECTED_MODULES:+$SELECTED_MODULES,}disk" ;;
                *) warn "Unknown module number: $num — skipping." ;;
            esac
        done
    fi
fi

info "Selected modules: core, $SELECTED_MODULES"
echo ""

# ------------------------------------------------------------------
# 5. Detect OS
# ------------------------------------------------------------------
detect_os() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
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

# Helper: check if a module was selected
module_selected() {
    local mod="$1"
    echo "$SELECTED_MODULES" | tr ',' '\n' | grep -qx "$mod"
}

# ------------------------------------------------------------------
# 6. Install system dependencies — per selected module
# ------------------------------------------------------------------
install_pkg() {
    local pkg="$1"
    case "$OS_TYPE" in
        apt)
            sudo apt-get install -y -qq "$pkg" 2>/dev/null && success "$pkg installed." || warn "$pkg could not be installed — skipping."
            ;;
        dnf)
            sudo dnf install -y -q "$pkg" 2>/dev/null && success "$pkg installed." || warn "$pkg could not be installed — skipping."
            ;;
        yum)
            sudo yum install -y -q "$pkg" 2>/dev/null && success "$pkg installed." || warn "$pkg could not be installed — skipping."
            ;;
        pacman)
            sudo pacman -S --noconfirm --needed "$pkg" 2>/dev/null && success "$pkg installed." || warn "$pkg could not be installed — skipping."
            ;;
        brew)
            brew install "$pkg" 2>/dev/null && success "$pkg installed." || warn "$pkg could not be installed — skipping."
            ;;
        *)
            warn "Unknown package manager — cannot install $pkg automatically."
            ;;
    esac
}

install_system_deps() {
    if [[ "$OS_TYPE" == "unknown" ]]; then
        warn "Unknown package manager. Install system tools manually for your selected modules."
        return
    fi

    # Pre-update for apt/dnf/yum
    case "$OS_TYPE" in
        apt)
            sudo apt-get update -qq 2>/dev/null || warn "apt-get update failed, continuing..."
            ;;
        dnf|yum)
            sudo "$OS_TYPE" install -y -q epel-release 2>/dev/null || true
            ;;
    esac

    # containers module: binwalk
    if module_selected "containers"; then
        info "Installing system deps for module: containers"
        case "$OS_TYPE" in
            apt)             install_pkg "binwalk" ;;
            dnf|yum)         install_pkg "binwalk" ;;
            pacman)          install_pkg "binwalk" ;;
            brew)            install_pkg "binwalk" ;;
        esac
    fi

    # documents module: poppler-utils / poppler
    if module_selected "documents"; then
        info "Installing system deps for module: documents"
        case "$OS_TYPE" in
            apt)             install_pkg "poppler-utils" ;;
            dnf|yum)         install_pkg "poppler-utils" ;;
            pacman)          install_pkg "poppler" ;;
            brew)            install_pkg "poppler" ;;
        esac
    fi

    # disk module: sleuthkit + qemu
    if module_selected "disk"; then
        info "Installing system deps for module: disk"
        case "$OS_TYPE" in
            apt)
                install_pkg "sleuthkit"
                install_pkg "qemu-utils"
                ;;
            dnf|yum)
                install_pkg "sleuthkit"
                install_pkg "qemu-img"
                ;;
            pacman)
                install_pkg "sleuthkit"
                install_pkg "qemu"
                ;;
            brew)
                install_pkg "sleuthkit"
                install_pkg "qemu"
                ;;
        esac
    fi
}

install_system_deps

# ------------------------------------------------------------------
# 7. Install Python dependencies for selected modules
# ------------------------------------------------------------------
info "Installing Python dependencies for selected modules..."

# core always gets python-magic
"$PYTHON" -m pip install python-magic --quiet 2>/dev/null && success "Python: python-magic installed." || warn "Python: python-magic could not be installed — MIME detection will use extension fallback."

if module_selected "images"; then
    "$PYTHON" -m pip install Pillow --quiet 2>/dev/null && success "Python: Pillow installed." || warn "Python: Pillow could not be installed — image analysis limited."
fi

if module_selected "audio"; then
    for dep in mutagen scipy numpy; do
        "$PYTHON" -m pip install "$dep" --quiet 2>/dev/null && success "Python: $dep installed." || warn "Python: $dep could not be installed — audio analysis limited."
    done
fi

if module_selected "documents"; then
    "$PYTHON" -m pip install pypdf --quiet 2>/dev/null && success "Python: pypdf installed." || warn "Python: pypdf could not be installed — PDF analysis limited."
fi

if module_selected "disk"; then
    "$PYTHON" -m pip install pytsk3 --quiet 2>/dev/null && success "Python: pytsk3 installed." || warn "Python: pytsk3 not available — disk analysis will use sleuthkit CLI tools."
fi

# ------------------------------------------------------------------
# 8. Write the config file
# ------------------------------------------------------------------
info "Writing Watson config..."
mkdir -p "$HOME/.config/watson"
"$PYTHON" -c "
import json, sys
selected = '$SELECTED_MODULES'.split(',')
enabled = ['core'] + [m.strip() for m in selected if m.strip()]
json.dump({'enabled_modules': enabled}, sys.stdout)
" > "$HOME/.config/watson/modules.json" && success "Config written to ~/.config/watson/modules.json" || warn "Could not write config file."

# ------------------------------------------------------------------
# 9. Run watson doctor
# ------------------------------------------------------------------
echo ""
info "Running ${BOLD}watson doctor${RESET} to check capabilities..."
echo ""
watson doctor 2>/dev/null || "$PYTHON" -m watson.cli doctor 2>/dev/null || warn "Could not run 'watson doctor' — check your PATH."

# ------------------------------------------------------------------
# 10. Closing quote
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

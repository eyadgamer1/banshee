#!/usr/bin/env bash
# BANSHEE — one-line installer
# Usage: curl -sSL https://raw.githubusercontent.com/eyadgamer1/banshee/main/install.sh | bash
set -euo pipefail

REPO="https://github.com/eyadgamer1/banshee"
MIN_PYTHON="3.12"

WITH_GO=1
for arg in "$@"; do
    [[ "$arg" == "--no-go" ]] && WITH_GO=0
done

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'

info()    { echo -e "${GREEN}[*]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[x]${NC} $*"; exit 1; }

echo -e "${RED}"
cat << 'EOF'
  ██████╗  █████╗ ███╗   ██╗███████╗██╗  ██╗███████╗███████╗
  ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║  ██║██╔════╝██╔════╝
  ██████╔╝███████║██╔██╗ ██║███████╗███████║█████╗  █████╗
  ██╔══██╗██╔══██║██║╚██╗██║╚════██║██╔══██║██╔══╝  ██╔══╝
  ██████╔╝██║  ██║██║ ╚████║███████║██║  ██║███████╗███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝
EOF
echo -e "${NC}"
echo "  She sees everything you left exposed."
echo ""

# --- Python check ---
PYTHON=$(command -v python3 || command -v python || true)
[[ -z "$PYTHON" ]] && error "Python not found. Install Python >= $MIN_PYTHON first."

VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
info "Found Python $VER"

# Use the interpreter resolved above, not a hardcoded `python3`: on a host where
# only `python` exists that call is command-not-found, so the installer would
# refuse to install while contradicting the version it just printed.
"$PYTHON" -c "import sys; sys.exit(0 if sys.version_info >= (3,12) else 1)" \
    || error "Python $MIN_PYTHON+ required. Got $VER."

# --- Install method selection ---
if command -v uv &>/dev/null; then
    info "Installing via uv (fast)"
    uv tool install git+"$REPO" 2>/dev/null \
        || uv pip install git+"$REPO"
elif command -v pipx &>/dev/null; then
    info "Installing via pipx (isolated)"
    pipx install git+"$REPO"
else
    warn "uv/pipx not found — falling back to pip (consider using pipx for isolation)"
    pip install git+"$REPO"
fi

# --- Verify ---
if command -v banshee &>/dev/null; then
    info "BANSHEE installed successfully."
    echo ""
    banshee --version
else
    error "Installation succeeded but 'banshee' not in PATH. Check your shell PATH."
fi

# --- Go engine: bundled by default, one command instead of two ---
# Go is the tool's main speed/memory advantage, so it ships with the Python
# tool unless explicitly skipped. A failed/offline fetch here must never fail
# the whole install — it degrades to Python-only, same as --engine auto
# already does mid-scan when the binary can't be reached.
if [[ "$WITH_GO" == "1" ]]; then
    info "Fetching the Go engine (skip with: install.sh --no-go)"
    banshee install-engine || warn "Go engine fetch failed — banshee still works via --engine python."
else
    info "Skipping the Go engine (--no-go). Python-only; --engine auto will use it if you fetch it later with 'banshee install-engine'."
fi

echo ""
echo "  Run:  banshee --help"
echo "  Docs: $REPO"

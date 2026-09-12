#!/usr/bin/env bash
# BANSHEE — one-line installer
# Usage: curl -sSL https://raw.githubusercontent.com/eyadgamer1/banshee/main/install.sh | bash
set -euo pipefail

REPO="https://github.com/eyadgamer1/banshee"
MIN_PYTHON="3.12"
GO_VERSION="1.26.7"

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

# --- Go toolchain: ensured BEFORE the Python install, not after ---
# The Go engine is not a separate optional add-on — it's compiled from source
# as PART OF the `pip install`/`uv tool install` build itself (see
# hatch_build.py), then bundled straight into the wheel. That only works if
# `go` is already on PATH when pip/uv builds the package below, so Go setup
# has to happen first. A failed/offline Go install here must never fail the
# whole install — it degrades to a Python-only wheel, same as `--engine auto`
# already does mid-scan when no engine binary can be found.
ensure_go() {
    if command -v go &>/dev/null; then
        info "Found $(go version)"
        return 0
    fi
    warn "Go toolchain not found — installing it automatically"
    local os arch tarball
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) warn "no automatic Go install for arch $arch"; return 1 ;;
    esac
    case "$os" in
        linux)
            if command -v apt-get &>/dev/null; then
                sudo apt-get update -qq && sudo apt-get install -y golang-go && return 0
            elif command -v dnf &>/dev/null; then
                sudo dnf install -y golang && return 0
            elif command -v pacman &>/dev/null; then
                sudo pacman -Sy --noconfirm go && return 0
            fi
            ;;
        darwin)
            if command -v brew &>/dev/null; then
                brew install go && return 0
            fi
            ;;
        *)
            warn "no automatic Go install for OS $os"
            return 1
            ;;
    esac
    # Package manager unavailable or package missing — fetch the official tarball.
    tarball="go${GO_VERSION}.${os}-${arch}.tar.gz"
    info "Downloading Go ${GO_VERSION} from go.dev"
    curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}" || return 1
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${tarball}" || return 1
    rm -f "/tmp/${tarball}"
    export PATH="/usr/local/go/bin:$PATH"
    command -v go &>/dev/null
}

if [[ "$WITH_GO" == "1" ]]; then
    ensure_go || warn "Go setup failed — installing Python-only (fix Go, then reinstall, for the bundled engine)."
else
    info "Skipping Go (--no-go). Python-only wheel; --engine auto will use the Python engine."
fi

# --- Install method selection ---
# One command builds both halves: hatch_build.py compiles engine/ (if `go` is
# on PATH) and bundles the resulting binary into the same wheel this installs.
# No separate "fetch the engine" step, and no risk of Python and Go drifting
# to different versions — they come from the exact same build.
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

# --- Last-resort fallback: only reached if Go wasn't available at build time ---
# (e.g. WITH_GO was skipped, or ensure_go failed). Not the normal path anymore
# — bundling above already handles the common case in one shot.
if [[ "$WITH_GO" == "1" ]] && ! command -v go &>/dev/null; then
    info "Fetching a prebuilt engine instead (no local Go toolchain)"
    banshee install-engine || warn "Go engine fetch failed — banshee still works via --engine python."
fi

echo ""
echo "  Run:  banshee --help"
echo "  Docs: $REPO"

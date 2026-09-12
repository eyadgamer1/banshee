#!/usr/bin/env bash
# BANSHEE — one-line installer
# Usage: curl -sSL https://raw.githubusercontent.com/eyadgamer1/banshee/main/install.sh | bash
set -euo pipefail

REPO="https://github.com/eyadgamer1/banshee"
MIN_PYTHON="3.12"

WITH_GO=1
PREBUILT_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --no-go) WITH_GO=0 ;;
        --prebuilt) PREBUILT_ONLY=1 ;;
    esac
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

# --- Go engine: built from source by default, one command instead of two ---
# Go is the tool's main speed/memory advantage, so it ships with the Python
# tool unless explicitly skipped. Building from source (rather than fetching a
# GitHub Releases binary) is the default because the release binary and the
# just-installed Python wrapper can drift apart: the wrapper is whatever git
# ref pip/uv just checked out, but the release asset is whatever tag someone
# last cut. When they disagree on a flag (e.g. engine_go.py passing
# -watch-stdin to a release binary built before that flag existed), the
# engine dies instantly with "flag provided but not defined" and every scan
# silently reports 0 hosts. Building from the same commit that was just
# installed makes that whole class of bug impossible. A failed/offline
# build here must never fail the whole install — it degrades to Python-only,
# same as --engine auto already does mid-scan when the binary can't be reached.
GO_VERSION="1.26.7"
ENGINE_BIN="banshee-engine"
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) ENGINE_BIN="banshee-engine.exe" ;;
esac

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

build_engine_from_source() {
    local tmp banshee_bin dest_dir
    tmp=$(mktemp -d) || return 1
    info "Cloning engine source (same commit as the Python wrapper just installed)"
    git clone --depth 1 "${REPO}.git" "$tmp" &>/dev/null || { rm -rf "$tmp"; return 1; }
    ( cd "$tmp/engine" && go build -o "$ENGINE_BIN" ./cmd/banshee-engine ) || { rm -rf "$tmp"; return 1; }

    banshee_bin=$(command -v banshee) || { rm -rf "$tmp"; return 1; }
    dest_dir=$(dirname "$banshee_bin")
    if ! cp "$tmp/engine/$ENGINE_BIN" "$dest_dir/$ENGINE_BIN"; then
        rm -rf "$tmp"
        return 1
    fi
    chmod +x "$dest_dir/$ENGINE_BIN" 2>/dev/null || true
    rm -rf "$tmp"
    info "Built banshee-engine from source -> $dest_dir/$ENGINE_BIN"
    return 0
}

if [[ "$WITH_GO" == "1" ]]; then
    if [[ "$PREBUILT_ONLY" == "1" ]]; then
        info "Fetching prebuilt Go engine (--prebuilt requested)"
        banshee install-engine || warn "Go engine fetch failed — banshee still works via --engine python."
    elif command -v git &>/dev/null && ensure_go && build_engine_from_source; then
        info "Go engine ready — built from source, version-matched to this install."
    else
        warn "Building from source failed or Go/git unavailable — falling back to prebuilt release binary"
        banshee install-engine || warn "Go engine fetch failed — banshee still works via --engine python."
    fi
else
    info "Skipping the Go engine (--no-go). Python-only; --engine auto will use it if you fetch it later with 'banshee install-engine'."
fi

echo ""
echo "  Run:  banshee --help"
echo "  Docs: $REPO"

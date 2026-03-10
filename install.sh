#!/usr/bin/env bash
set -e

REPO="master-sauce/Nethawk"
BINARY_NAME="nethawk"
INSTALL_DIR="$HOME/.local/bin"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[nethawk]${NC} $*"; }
success() { echo -e "${GREEN}[nethawk]${NC} $*"; }
warn()    { echo -e "${YELLOW}[nethawk]${NC} $*"; }
error()   { echo -e "${RED}[nethawk] ERROR:${NC} $*" >&2; exit 1; }

# ── Detect OS / arch ──────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux*)   PLATFORM="linux" ;;
  Darwin*)  PLATFORM="macos" ;;
  *)        error "Unsupported OS: $OS" ;;
esac

# ── Installation logic ────────────────────────────────────────────────────────
install_via_download() {
  local url="$1"
  info "Downloading binary from GitHub..."

  mkdir -p "$INSTALL_DIR"
  TMP="$(mktemp)"

  if command -v curl &>/dev/null; then
    curl -fsSL "$url" -o "$TMP"
  elif command -v wget &>/dev/null; then
    wget -qO "$TMP" "$url"
  else
    error "Neither curl nor wget found. Please install one and retry."
  fi

  chmod +x "$TMP"
  mv "$TMP" "$INSTALL_DIR/$BINARY_NAME"
  success "Installed to $INSTALL_DIR/$BINARY_NAME"
}

install_via_go() {
  info "No pre-built binary for your platform. Trying 'go install'..."
  if ! command -v go &>/dev/null; then
    error "Go is not installed. Install it from https://go.dev/dl/ then re-run this script."
  fi
  go install "github.com/${REPO}@latest"
  success "Installed via 'go install'."
  # go installs to $GOPATH/bin or $HOME/go/bin — make sure that's on PATH too
  INSTALL_DIR="$(go env GOPATH)/bin"
}

case "$PLATFORM" in
  linux)
    install_via_download "${RAW_BASE}/Nethawk_linux"
    ;;
  macos)
    # No macOS binary in repo yet — fall back to go install
    warn "No macOS binary found in repo. Falling back to 'go install'."
    install_via_go
    ;;
esac

# ── PATH setup ────────────────────────────────────────────────────────────────
add_to_path() {
  local shell_rc="$1"
  local export_line="export PATH=\"\$PATH:${INSTALL_DIR}\""

  if [ -f "$shell_rc" ] && grep -qF "$INSTALL_DIR" "$shell_rc"; then
    warn "$INSTALL_DIR already in PATH (found in $shell_rc). Skipping."
    return
  fi

  echo "" >> "$shell_rc"
  echo "# Added by Nethawk installer" >> "$shell_rc"
  echo "$export_line" >> "$shell_rc"
  info "Added $INSTALL_DIR to PATH in $shell_rc"
}

SHELL_NAME="$(basename "${SHELL:-/bin/bash}")"
case "$SHELL_NAME" in
  zsh)   add_to_path "$HOME/.zshrc" ;;
  bash)  add_to_path "$HOME/.bashrc"; [ -f "$HOME/.bash_profile" ] && add_to_path "$HOME/.bash_profile" ;;
  fish)  
    mkdir -p "$HOME/.config/fish"
    FISH_LINE="set -gx PATH \$PATH $INSTALL_DIR"
    if ! grep -qF "$INSTALL_DIR" "$HOME/.config/fish/config.fish" 2>/dev/null; then
      echo "$FISH_LINE" >> "$HOME/.config/fish/config.fish"
      info "Added $INSTALL_DIR to PATH in fish config."
    fi
    ;;
  *)     add_to_path "$HOME/.profile" ;;
esac

# ── Also export for current session ──────────────────────────────────────────
export PATH="$PATH:$INSTALL_DIR"

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
if command -v "$BINARY_NAME" &>/dev/null; then
  success "✓ '$BINARY_NAME' is ready to use!"
else
  warn "'$BINARY_NAME' not found in current shell PATH yet."
  echo "  Run: export PATH=\"\$PATH:${INSTALL_DIR}\""
  echo "  Or open a new terminal session."
fi

echo ""
echo -e "  ${CYAN}Run:${NC} $BINARY_NAME --help"
echo ""

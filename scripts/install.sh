#!/usr/bin/env bash
set -euo pipefail

# AEGIS installer — curl -sSL https://raw.githubusercontent.com/eth0x1/aegis-preflight-cli/main/scripts/install.sh | bash
# Installs the aegis binary to ~/bin (or /usr/local/bin with --sudo).
# Requirements: Linux amd64, Docker, Go 1.27+ (for source build fallback).

INSTALL_DIR="${AEGIS_INSTALL_DIR:-$HOME/bin}"
REPO="eth0x1/aegis-preflight-cli"
BINARY_NAME="aegis"
MIN_GO_VERSION="1.27"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { printf "${GREEN}[aegis]${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}[aegis]${NC} %s\n" "$1"; }
error() { printf "${RED}[aegis]${NC} %s\n" "$1" >&2; exit 1; }

check_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  if [ "$os" != "Linux" ]; then
    error "Unsupported OS: $os (aegis requires Linux)"
  fi
  if [ "$arch" != "x86_64" ] && [ "$arch" != "amd64" ]; then
    error "Unsupported architecture: $arch (aegis requires amd64)"
  fi
}

check_docker() {
  if ! command -v docker &>/dev/null; then
    error "Docker is required but not found. Install Docker: https://docs.docker.com/engine/install/"
  fi
  if ! docker info &>/dev/null 2>&1; then
    warn "Docker daemon may not be running or user lacks permissions."
    warn "Try: sudo usermod -aG docker \$USER && newgrp docker"
  fi
}

check_gitleaks() {
  if ! command -v gitleaks &>/dev/null; then
    warn "gitleaks not found (required for PreFlight scanning)."
    warn "Install: https://github.com/gitleaks/gitleaks/releases"
    warn "Or: go install github.com/gitleaks/gitleaks/v8@latest"
  fi
}

version_ge() {
  [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

try_download_release() {
  local version
  version=$(curl -sfSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//') || return 1

  [ -z "$version" ] && return 1

  local url="https://github.com/$REPO/releases/download/$version/${BINARY_NAME}-linux-amd64"
  info "Downloading $BINARY_NAME $version..."
  curl -sfSL -o "$INSTALL_DIR/$BINARY_NAME" "$url" || return 1
  chmod +x "$INSTALL_DIR/$BINARY_NAME"
  info "Installed $BINARY_NAME $version to $INSTALL_DIR/$BINARY_NAME"
  return 0
}

build_from_source() {
  info "No pre-built release found. Building from source..."
  command -v go &>/dev/null || error "Go is required for source build. Install Go 1.27+: https://go.dev/dl/"

  local go_version
  go_version=$(go version | grep -oP 'go\K[0-9.]+')
  if ! version_ge "$go_version" "$MIN_GO_VERSION"; then
    error "Go $MIN_GO_VERSION+ required, found $go_version"
  fi

  local tmpdir
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT

  info "Cloning $REPO..."
  git clone --depth 1 "https://github.com/$REPO.git" "$tmpdir/aegis" 2>/dev/null || {
    error "Failed to clone repository"
  }

  cd "$tmpdir/aegis"
  info "Building..."
  go build -ldflags="-s -w" -o "$INSTALL_DIR/$BINARY_NAME" ./cmd/aegis/ || {
    error "Build failed"
  }
  info "Built and installed $BINARY_NAME to $INSTALL_DIR/$BINARY_NAME"
}

init_docker() {
  info "Running the complete checkout bootstrap..."
  if "$INSTALL_DIR/$BINARY_NAME" init 2>&1 | tail -5; then
    info "Sandbox images ready."
  else
    warn "Sandbox initialization had issues. Use ./build.sh from the source checkout."
  fi
}

main() {
  echo ""
  info "Installing aegis — zero-trust runtime for AI coding agents"
  echo ""

  check_platform

  mkdir -p "$INSTALL_DIR"

  if ! try_download_release; then
    build_from_source
  fi

  # Ensure install dir is in PATH
  if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    warn "$INSTALL_DIR is not in your PATH."
    warn "Add to your shell profile:"
    warn "  export PATH=\"$INSTALL_DIR:\$PATH\""
  fi

  check_docker
  check_gitleaks

  info "Verifying installation..."
  "$INSTALL_DIR/$BINARY_NAME" --version 2>/dev/null || "$INSTALL_DIR/$BINARY_NAME" --help >/dev/null 2>&1
  info "aegis installed successfully!"

  echo ""
  info "Quick start:"
  info "  ./build.sh      # complete source checkout bootstrap"
  info "  aegis           # launch TUI in current directory"
  echo ""

  read -r -p "Build sandbox images now? [Y/n] " answer
  if [ -z "$answer" ] || [ "$answer" = "Y" ] || [ "$answer" = "y" ]; then
    init_docker
  else
    info "Skipping. Run 'aegis init' when ready."
  fi
}

main "$@"

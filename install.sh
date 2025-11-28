#!/usr/bin/env bash
set -euo pipefail

# Shai-Hulud Guard One-Shot Installer & Runner
# Usage: curl -fsSL https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.sh | bash

VERSION="${SHAI_HULUD_VERSION:-v0.1-alpha.3}"
INSTALL_DIR="${SHAI_HULUD_INSTALL_DIR:-/usr/local/bin}"
REPO="idoxcloud/Shai-Hulud-Guard"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    echo -e "${BLUE}ℹ${NC} $*"
}

success() {
    echo -e "${GREEN}✓${NC} $*"
}

warn() {
    echo -e "${YELLOW}⚠${NC} $*"
}

error() {
    echo -e "${RED}✗${NC} $*" >&2
}

# Detect platform and architecture
detect_platform() {
    local os arch
    
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    
    case "$os" in
        darwin)
            os="darwin"
            ;;
        linux)
            os="linux"
            ;;
        mingw*|msys*|cygwin*|windows*)
            os="windows"
            ;;
        *)
            error "Unsupported operating system: $os"
            exit 1
            ;;
    esac
    
    case "$arch" in
        x86_64|amd64)
            arch="amd64"
            ;;
        arm64|aarch64)
            arch="arm64"
            ;;
        *)
            error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
    
    echo "${os}-${arch}"
}

# Check if running as root (for install command)
check_root() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Main installation logic
main() {
    echo ""
    echo "╔════════════════════════════════════════════╗"
    echo "║   Shai-Hulud Guard Installer & Runner      ║"
    echo "╚════════════════════════════════════════════╝"
    echo ""
    
    # Detect platform
    info "Detecting platform..."
    local platform
    platform=$(detect_platform)
    success "Detected platform: $platform"
    
    # Construct binary name and download URL
    local binary_name="shai-hulud-guard-${platform}"
    if [[ "$platform" == windows-* ]]; then
        binary_name="${binary_name}.exe"
    fi
    
    local download_url="https://github.com/${REPO}/releases/download/${VERSION}/${binary_name}"
    
    # Create temporary directory
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "${tmp_dir:-}"' EXIT
    
    local tmp_binary="${tmp_dir}/shai-hulud-guard"
    
    # Download binary
    info "Downloading ${binary_name} (${VERSION})..."
    if command -v curl &> /dev/null; then
        if ! curl -fsSL "$download_url" -o "$tmp_binary"; then
            error "Failed to download binary from ${download_url}"
            exit 1
        fi
    elif command -v wget &> /dev/null; then
        if ! wget -q "$download_url" -O "$tmp_binary"; then
            error "Failed to download binary from ${download_url}"
            exit 1
        fi
    else
        error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi
    
    success "Downloaded successfully"
    
    # Make binary executable
    chmod +x "$tmp_binary"
    
    # Check what action to perform
    local action="${1:-report}"
    
    case "$action" in
        install)
            info "Installing to ${INSTALL_DIR}..."
            if ! check_root; then
                error "Installation requires root privileges"
                echo ""
                echo "Please run with sudo:"
                echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | sudo bash -s install"
                exit 1
            fi
            
            if ! mkdir -p "$INSTALL_DIR"; then
                error "Failed to create directory: ${INSTALL_DIR}"
                exit 1
            fi
            
            if ! cp "$tmp_binary" "${INSTALL_DIR}/shai-hulud-guard"; then
                error "Failed to install binary to ${INSTALL_DIR}"
                exit 1
            fi
            
            success "Installed to ${INSTALL_DIR}/shai-hulud-guard"
            echo ""
            info "To install protection, run:"
            echo "  sudo shai-hulud-guard -install"
            echo ""
            info "To scan for threats, run:"
            echo "  shai-hulud-guard -report"
            ;;
            
        report|scan)
            info "Running security report..."
            echo ""
            "$tmp_binary" -report
            echo ""
            success "Report complete"
            echo ""
            warn "To install permanently, run:"
            echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | sudo bash -s install"
            ;;
            
        guard-install)
            info "Installing Shai-Hulud Guard protection..."
            if ! check_root; then
                error "Guard installation requires root privileges"
                echo ""
                echo "Please run with sudo:"
                echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | sudo bash -s guard-install"
                exit 1
            fi
            echo ""
            "$tmp_binary" -install -yes
            ;;
            
        guard-uninstall)
            info "Uninstalling Shai-Hulud Guard protection..."
            if ! check_root; then
                error "Guard uninstallation requires root privileges"
                echo ""
                echo "Please run with sudo:"
                echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | sudo bash -s guard-uninstall"
                exit 1
            fi
            echo ""
            "$tmp_binary" -uninstall -yes
            ;;
            
        status)
            info "Checking protection status..."
            echo ""
            "$tmp_binary" -status
            ;;
            
        *)
            error "Unknown action: $action"
            echo ""
            echo "Usage:"
            echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash                       # Run report"
            echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash -s scan               # Run scan"
            echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash -s status             # Check status"
            echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | sudo bash -s install       # Install binary"
            echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | sudo bash -s guard-install # Install guard protection"
            echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | sudo bash -s guard-uninstall # Uninstall guard protection"
            exit 1
            ;;
    esac
}

main "$@"

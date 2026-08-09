#!/bin/sh
# sbomlyze installer script
# Usage: curl -sSfL https://raw.githubusercontent.com/rezmoss/sbomlyze/main/install.sh | sh -s -- [options]
#
# Options:
#   -b <dir>    Install directory (default: ./bin)
#   -d          Enable debug output
#   -v <ver>    Install specific version (default: latest)
#
# Examples:
#   curl -sSfL https://raw.githubusercontent.com/rezmoss/sbomlyze/main/install.sh | sh
#   curl -sSfL https://raw.githubusercontent.com/rezmoss/sbomlyze/main/install.sh | sh -s -- -b /usr/local/bin
#   curl -sSfL https://raw.githubusercontent.com/rezmoss/sbomlyze/main/install.sh | sudo sh -s -- -b /usr/local/bin

set -e

GITHUB_REPO="rezmoss/sbomlyze"
BINARY_NAME="sbomlyze"
INSTALL_DIR="./bin"
VERSION=""
DEBUG=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
}

log_debug() {
    if [ "$DEBUG" -eq 1 ]; then
        printf "[DEBUG] %s\n" "$1" >&2
    fi
}

# Parse command line arguments
while getopts "b:dv:h" opt; do
    case $opt in
        b)
            INSTALL_DIR="$OPTARG"
            ;;
        d)
            DEBUG=1
            ;;
        v)
            VERSION="$OPTARG"
            ;;
        h)
            echo "sbomlyze installer"
            echo ""
            echo "Usage: curl -sSfL https://raw.githubusercontent.com/rezmoss/sbomlyze/main/install.sh | sh -s -- [options]"
            echo ""
            echo "Options:"
            echo "  -b <dir>    Install directory (default: ./bin)"
            echo "  -d          Enable debug output"
            echo "  -v <ver>    Install specific version (default: latest)"
            echo "  -h          Show this help message"
            echo ""
            echo "Examples:"
            echo "  # Install to ./bin"
            echo "  curl -sSfL https://raw.githubusercontent.com/rezmoss/sbomlyze/main/install.sh | sh"
            echo ""
            echo "  # Install to /usr/local/bin (requires sudo)"
            echo "  curl -sSfL https://raw.githubusercontent.com/rezmoss/sbomlyze/main/install.sh | sudo sh -s -- -b /usr/local/bin"
            echo ""
            echo "  # Install specific version"
            echo "  curl -sSfL https://raw.githubusercontent.com/rezmoss/sbomlyze/main/install.sh | sh -s -- -v 0.3.7"
            exit 0
            ;;
        \?)
            log_error "Invalid option: -$OPTARG"
            exit 1
            ;;
    esac
done

# Detect OS
detect_os() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$OS" in
        darwin)
            OS="Darwin"
            ;;
        linux)
            OS="Linux"
            ;;
        mingw*|msys*|cygwin*)
            OS="Windows"
            ;;
        *)
            log_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    log_debug "Detected OS: $OS"
    echo "$OS"
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        i386|i686)
            ARCH="i386"
            ;;
        armv6l)
            ARCH="armv6"
            ;;
        armv7l)
            ARCH="armv7"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    log_debug "Detected architecture: $ARCH"
    echo "$ARCH"
}

# Get latest version from GitHub
get_latest_version() {
    LATEST=$(curl -sSf "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$LATEST" ]; then
        log_error "Failed to fetch latest version"
        exit 1
    fi
    log_debug "Latest version: $LATEST"
    echo "$LATEST"
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    else
        log_error "No SHA256 tool found (tried sha256sum, shasum, and openssl)"
        return 1
    fi
}

verify_checksum() {
    ARCHIVE=$1
    CHECKSUMS=$2
    EXPECTED=$(awk -v file="$FILENAME" '$2 == file {print $1; exit}' "$CHECKSUMS")

    if [ -z "$EXPECTED" ]; then
        log_error "No checksum found for ${FILENAME}"
        return 1
    fi

    ACTUAL=$(sha256_file "$ARCHIVE")
    if [ "$ACTUAL" != "$EXPECTED" ]; then
        log_error "Checksum verification failed for ${FILENAME}"
        log_error "Expected: $EXPECTED"
        log_error "Actual:   $ACTUAL"
        return 1
    fi

    log_info "Checksum verified"
}

verify_provenance() {
    ARCHIVE=$1

    if ! command -v gh >/dev/null 2>&1; then
        log_warn "GitHub CLI not found; provenance verification skipped"
        log_warn "SHA256 verification succeeded. Install gh to verify release provenance."
        return 0
    fi

    if ! gh attestation verify --help >/dev/null 2>&1; then
        log_warn "Installed GitHub CLI does not support attestation verification"
        log_warn "SHA256 verification succeeded. Upgrade gh to verify release provenance."
        return 0
    fi

    log_info "Verifying GitHub build provenance..."
    if ! gh attestation verify "$ARCHIVE" \
        --repo "$GITHUB_REPO" \
        --signer-workflow "$GITHUB_REPO/.github/workflows/release.yml"; then
        log_error "Build provenance verification failed for ${FILENAME}"
        return 1
    fi
    log_info "Build provenance verified"
}

# Download and install
install() {
    OS=$(detect_os)
    ARCH=$(detect_arch)

    # Get version
    if [ -z "$VERSION" ]; then
        VERSION=$(get_latest_version)
    else
        # Ensure version starts with 'v'
        case "$VERSION" in
            v*) ;;
            *) VERSION="v$VERSION" ;;
        esac
    fi

    # Strip 'v' prefix for filename
    VERSION_NUM="${VERSION#v}"

    log_info "Installing sbomlyze ${VERSION} for ${OS}/${ARCH}"

    # Determine file extension
    EXT="tar.gz"
    if [ "$OS" = "Windows" ]; then
        EXT="zip"
    fi

    # Build download URL
    FILENAME="${BINARY_NAME}_${VERSION_NUM}_${OS}_${ARCH}.${EXT}"
    URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${FILENAME}"

    log_debug "Download URL: $URL"

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    log_info "Downloading ${FILENAME}..."

    # Download
    HTTP_CODE=$(curl -sSL -w "%{http_code}" -o "${TMP_DIR}/${FILENAME}" "$URL")
    if [ "$HTTP_CODE" != "200" ]; then
        log_error "Download failed (HTTP $HTTP_CODE)"
        log_error "URL: $URL"
        log_error ""
        log_error "Available releases: https://github.com/${GITHUB_REPO}/releases"
        exit 1
    fi

    CHECKSUMS_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/checksums.txt"
    log_info "Verifying SHA256 checksum..."
    curl -sSfL -o "${TMP_DIR}/checksums.txt" "$CHECKSUMS_URL"
    verify_checksum "${TMP_DIR}/${FILENAME}" "${TMP_DIR}/checksums.txt"

    verify_provenance "${TMP_DIR}/${FILENAME}"

    # Extract
    log_info "Extracting..."
    cd "$TMP_DIR"
    if [ "$EXT" = "zip" ]; then
        unzip -q "$FILENAME"
    else
        tar -xzf "$FILENAME"
    fi

    # Create install directory if needed
    mkdir -p "$INSTALL_DIR"

    # Install binary
    if [ "$OS" = "Windows" ]; then
        BINARY="${BINARY_NAME}.exe"
    else
        BINARY="$BINARY_NAME"
    fi

    log_info "Installing to ${INSTALL_DIR}/${BINARY}..."

    # Move binary
    mv "$BINARY" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/$BINARY"

    # Remove quarantine attribute on macOS
    if [ "$OS" = "Darwin" ]; then
        xattr -d com.apple.quarantine "$INSTALL_DIR/$BINARY" 2>/dev/null || true
    fi

    log_info "Successfully installed sbomlyze ${VERSION} to ${INSTALL_DIR}/${BINARY}"

    # Check if install dir is in PATH
    case ":$PATH:" in
        *":$INSTALL_DIR:"*)
            ;;
        *)
            log_warn "Installation directory is not in your PATH"
            log_warn "Add it with: export PATH=\"\$PATH:$INSTALL_DIR\""
            ;;
    esac

    # Verify installation
    if [ -x "$INSTALL_DIR/$BINARY" ]; then
        log_info "Verifying installation..."
        "$INSTALL_DIR/$BINARY" --version
    fi
}

# Run installation
install

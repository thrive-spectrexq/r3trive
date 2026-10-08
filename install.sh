#!/usr/bin/env bash
# R3TRIVE Installation Script
# https://github.com/thrive-spectrexq/r3trive

set -euo pipefail

REPO="thrive-spectrexq/r3trive"
INSTALL_DIR="/usr/local/bin"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Error: required command not found: $1" >&2
        exit 1
    }
}

require_command curl
require_command tar
require_command sha256sum || require_command shasum

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

case "$OS" in
    linux) OS="linux" ;;
    darwin) OS="darwin" ;;
    mingw*|msys*|cygwin*) OS="windows" ;;
    *) echo "Unsupported operating system: $OS" >&2; exit 1 ;;
esac

if [ "$OS" = "windows" ]; then
    require_command unzip
fi

echo "═══════════════════════════════════════════"
echo " R3TRIVE Installer"
echo " Maintained by https://github.com/thrive-spectrexq"
echo "═══════════════════════════════════════════"
echo "Detected OS: $OS ($ARCH)"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# Resolve a release tag rather than downloading from the mutable main branch.
if [ -n "${R3TRIVE_VERSION:-}" ]; then
    VERSION="$R3TRIVE_VERSION"
else
    VERSION="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" | sed 's#^.*/tag/##')"
fi

case "$VERSION" in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "Invalid release version: $VERSION" >&2; exit 1 ;;
esac

if [ "$OS" = "windows" ]; then
    ARCHIVE="r3trive_${VERSION}_${OS}_${ARCH}.zip"
    BINARY_NAME="r3trive.exe"
else
    ARCHIVE="r3trive_${VERSION}_${OS}_${ARCH}.tar.gz"
    BINARY_NAME="r3trive"
fi

BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
CHECKSUMS="${tmp_dir}/checksums.txt"
ARCHIVE_PATH="${tmp_dir}/${ARCHIVE}"

curl -fsSL -o "$CHECKSUMS" "${BASE_URL}/checksums.txt"
curl -fsSL -o "$ARCHIVE_PATH" "${BASE_URL}/${ARCHIVE}"

# Verify the downloaded artifact against the checksum published with the release.
CHECKSUM_LINE="$(grep -F "  ${ARCHIVE}" "$CHECKSUMS" || true)"
if [ -z "$CHECKSUM_LINE" ]; then
    echo "Error: no checksum found for ${ARCHIVE}" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' "$CHECKSUM_LINE" | sha256sum -c -
else
    EXPECTED="$(printf '%s\n' "$CHECKSUM_LINE" | awk '{print $1}')"
    ACTUAL="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
    [ "$EXPECTED" = "$ACTUAL" ] || {
        echo "Error: checksum verification failed for ${ARCHIVE}" >&2
        exit 1
    }
fi

mkdir -p "${tmp_dir}/extract"
if [ "$OS" = "windows" ]; then
    unzip -q "$ARCHIVE_PATH" -d "${tmp_dir}/extract"
else
    tar -xzf "$ARCHIVE_PATH" -C "${tmp_dir}/extract"
fi

BINARY_PATH="${tmp_dir}/extract/${BINARY_NAME}"
[ -f "$BINARY_PATH" ] || {
    echo "Error: release archive does not contain ${BINARY_NAME}" >&2
    exit 1
}

if [ "$OS" = "windows" ]; then
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
    install -m 0755 "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}"
else
    sudo install -m 0755 "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}"
fi

echo "✓ R3TRIVE ${VERSION} successfully installed to ${INSTALL_DIR}/${BINARY_NAME}"
echo ""
echo "Run 'r3trive --help' to get started."

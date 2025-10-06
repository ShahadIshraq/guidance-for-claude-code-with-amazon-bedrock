#!/bin/bash
set -e

VERSION=${1:-$(cargo metadata --format-version 1 2>/dev/null | jq -r '.packages[] | select(.name == "credential-provider") | .version' 2>/dev/null || echo "1.0.0")}
DIST_DIR="dist"

echo "Creating distribution for version $VERSION..."

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Build for current platform
cargo build --release

# Detect platform
OS=$(uname -s)
ARCH=$(uname -m)

if [ "$OS" = "Linux" ]; then
    PLATFORM="linux-${ARCH}"
elif [ "$OS" = "Darwin" ]; then
    PLATFORM="darwin-${ARCH}"
else
    PLATFORM="windows-${ARCH}"
fi

echo "Packaging for platform: $PLATFORM"

mkdir -p "$DIST_DIR/$PLATFORM"

# Copy binaries (handle both Unix and Windows executables)
if [ -f "target/release/credential-provider" ]; then
    cp target/release/credential-provider "$DIST_DIR/$PLATFORM/credential-process"
elif [ -f "target/release/credential-provider.exe" ]; then
    cp target/release/credential-provider.exe "$DIST_DIR/$PLATFORM/credential-process.exe"
fi

if [ -f "target/release/otel-helper" ]; then
    cp target/release/otel-helper "$DIST_DIR/$PLATFORM/otel-helper"
elif [ -f "target/release/otel-helper.exe" ]; then
    cp target/release/otel-helper.exe "$DIST_DIR/$PLATFORM/otel-helper.exe"
fi

# Create tarball
cd "$DIST_DIR"
tar czf "claude-code-rust-${PLATFORM}-${VERSION}.tar.gz" "$PLATFORM"
cd ..

echo ""
echo "Distribution package created:"
echo "  $DIST_DIR/claude-code-rust-${PLATFORM}-${VERSION}.tar.gz"
echo ""
echo "Contents:"
ls -lh "$DIST_DIR/$PLATFORM/"

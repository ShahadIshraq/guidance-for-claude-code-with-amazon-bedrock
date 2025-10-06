#!/bin/bash
set -e

echo "Building Rust binaries for current platform..."
cargo build --release

echo ""
echo "Running tests..."
cargo test --workspace

echo ""
echo "Build complete! Binaries located at:"
echo "  - target/release/credential-provider"
echo "  - target/release/otel-helper"
echo ""
echo "To install:"
echo "  cp target/release/credential-provider ~/claude-code-with-bedrock/credential-process"
echo "  cp target/release/otel-helper ~/claude-code-with-bedrock/otel-helper"

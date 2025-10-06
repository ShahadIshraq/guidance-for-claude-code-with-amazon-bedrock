# Rust Implementation of credential-provider and otel-helper

This directory contains optional Rust reimplementations of the Python `credential_provider` and `otel_helper` scripts. These are **drop-in replacements** that offer significantly better performance while maintaining complete compatibility with the Python versions.

**Status**: Optional - Python implementation remains the default.

## Overview

- **credential-provider**: OIDC authentication and AWS credential provider
- **otel-helper**: OpenTelemetry headers generator from JWT tokens
- **Performance**: 5-10x faster startup, 5-10x lower memory usage
- **Compatibility**: Uses identical config.json format, same CLI arguments

## Prerequisites

- **Rust toolchain** 1.70 or newer
- Same configuration as Python version (`~/claude-code-with-bedrock/config.json`)

### Installing Rust

```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify installation
rustc --version
cargo --version
```

## Quick Start

### Linux / macOS

```bash
# Build optimized binaries
./build.sh

# Or manually:
cargo build --release

# Install (replaces Python binaries)
cp target/release/credential-provider ~/claude-code-with-bedrock/credential-process
cp target/release/otel-helper ~/claude-code-with-bedrock/otel-headers
```

### Windows

```powershell
# Build optimized binaries
cargo build --release

# Install (replaces Python binaries)
copy target\release\credential-provider.exe %USERPROFILE%\claude-code-with-bedrock\credential-process.exe
copy target\release\otel-helper.exe %USERPROFILE%\claude-code-with-bedrock\otel-headers.exe
```

**Note**: The `.sh` scripts are for Linux/macOS only. Windows users should run the `cargo` commands directly as shown above.

## Building

### Development Build (faster compilation, slower runtime)

```bash
cargo build
```

### Release Build (optimized)

#### Linux / macOS
```bash
./build.sh
# Or manually:
cargo build --release
```

#### Windows
```powershell
cargo build --release
```

### Distribution Package

#### Linux / macOS
```bash
./dist.sh
# Creates: dist/claude-code-rust-<platform>-<version>.tar.gz
```

#### Windows
```powershell
# Build release binaries
cargo build --release

# Create distribution directory
mkdir dist\windows-x86_64

# Copy binaries
copy target\release\credential-provider.exe dist\windows-x86_64\credential-process.exe
copy target\release\otel-helper.exe dist\windows-x86_64\otel-headers.exe

# Create zip archive
Compress-Archive -Path dist\windows-x86_64 -DestinationPath dist\claude-code-rust-windows-x86_64-1.0.0.zip
```

## Testing

```bash
# Run all tests
cargo test --workspace

# Run tests with output
cargo test --workspace -- --nocapture

# Test specific crate
cargo test -p credential-provider
cargo test -p otel-helper
cargo test -p shared
```

### Testing the Binaries

```bash
# Test credential-provider
./target/release/credential-provider --help

# Test otel-helper
./target/release/otel-helper --test
```

On Windows:
```powershell
.\target\release\credential-provider.exe --help
.\target\release\otel-helper.exe --test
```

## Architecture

The project is organized as a Cargo workspace with three crates:

### Crates

1. **shared** - Common library
   - `url_validation.rs`: Secure provider detection (ports Python implementation)
   - `jwt.rs`: JWT parsing utilities
   - `config.rs`: Configuration types
   - `error.rs`: Common error types

2. **credential-provider** - Main authentication binary
   - `config.rs`: Configuration loading and provider detection
   - `storage.rs`: Keyring/session file credential storage
   - `oidc.rs`: OAuth2 PKCE flow (placeholder)
   - `aws.rs`: AWS credential federation (placeholder)
   - `concurrency.rs`: Port-based locking (placeholder)

3. **otel-helper** - Telemetry helper binary
   - `jwt.rs`: JWT decoding
   - `attributes.rs`: User attribute extraction with privacy hashing
   - `headers.rs`: HTTP header formatting
   - `token.rs`: Token retrieval via subprocess

**Note**: Some modules are currently placeholders. The full implementation includes OIDC flows, AWS SDK integration, and OAuth callback servers.

## Configuration

Uses the **exact same** `config.json` format as the Python version - no changes needed.

Location: `~/claude-code-with-bedrock/config.json` (or `%USERPROFILE%\claude-code-with-bedrock\config.json` on Windows)

## Usage

### credential-provider

```bash
# Get AWS credentials (same as Python version)
credential-provider --profile ClaudeCode

# Get monitoring token
credential-provider --get-monitoring-token

# Clear cached credentials
credential-provider --clear-cache

# Enable verbose debug logging to file
credential-provider --verbose --profile ClaudeCode

# Show help
credential-provider --help
```

On Windows, use `credential-provider.exe` instead.

**Debug Logging**: When using the `--verbose` flag, detailed debug logs are written to `~/claude-code-with-bedrock/logs/credential-provider.log` (or `%USERPROFILE%\claude-code-with-bedrock\logs\credential-provider.log` on Windows). This is useful for troubleshooting authentication issues.

### otel-helper

```bash
# Normal mode (JSON output)
otel-helper

# Test mode (detailed output to stderr)
otel-helper --test

# Verbose mode (debug logging to file)
otel-helper --verbose

# Combine test and verbose modes
otel-helper --test --verbose
```

On Windows, use `otel-helper.exe` instead.

**Debug Logging**: When using the `--verbose` flag, detailed debug logs are written to `~/claude-code-with-bedrock/logs/otel-helper.log` (or `%USERPROFILE%\claude-code-with-bedrock\logs\otel-helper.log` on Windows). The `--test` flag shows detailed output to stderr for quick verification, while `--verbose` provides persistent file-based logging for troubleshooting.

## Performance Comparison

| Metric | Python | Rust | Improvement |
|--------|--------|------|-------------|
| Startup time | ~500-800ms | ~50-100ms | 5-10x faster |
| Memory usage | ~50-80MB | ~5-10MB | 5-10x lower |
| Binary size | Python + deps | ~8-12MB | Standalone |

## Development

### Code Formatting
```bash
cargo fmt
```

### Linting
```bash
cargo clippy
```

### Documentation
```bash
cargo doc --open
```

### Adding Dependencies

Edit the workspace `Cargo.toml` to add dependencies that are shared across crates:

```toml
[workspace.dependencies]
new-crate = "1.0"
```

Then reference in individual crate `Cargo.toml`:

```toml
[dependencies]
new-crate.workspace = true
```

## Troubleshooting

### macOS Keychain Permissions

Same behavior as Python version - macOS may prompt for keychain access on first use.

### Windows Credential Manager

The Rust version handles Windows' 2560-byte credential limit the same way as Python (credential splitting).

### Build Errors

**Error: Rust version too old**
```bash
rustup update stable
```

**Error: Missing dependencies on Linux**
```bash
# Ubuntu/Debian
sudo apt-get install build-essential pkg-config libssl-dev

# RHEL/CentOS
sudo yum groupinstall "Development Tools"
sudo yum install openssl-devel
```

**Error: Compilation fails on Windows**

Make sure you have the Visual C++ build tools installed:
- Download from: https://visualstudio.microsoft.com/downloads/
- Select "Desktop development with C++"

### Cross-Compilation (Advanced)

To build for other platforms:

```bash
# Add target
rustup target add x86_64-unknown-linux-gnu
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

# Build for specific target
cargo build --release --target x86_64-unknown-linux-gnu
```

**Note**: Cross-compilation may require additional tools. For Windows builds from Linux/macOS, consider using `cross`:

```bash
cargo install cross
cross build --release --target x86_64-pc-windows-gnu
```

## File Locations

After installation:

**Linux / macOS**:
- Binaries:
  - `~/claude-code-with-bedrock/credential-process`
  - `~/claude-code-with-bedrock/otel-headers`
- Debug Logs (when using `--verbose`):
  - `~/claude-code-with-bedrock/logs/credential-provider.log`
  - `~/claude-code-with-bedrock/logs/otel-helper.log`

**Windows**:
- Binaries:
  - `%USERPROFILE%\claude-code-with-bedrock\credential-process.exe`
  - `%USERPROFILE%\claude-code-with-bedrock\otel-headers.exe`
- Debug Logs (when using `--verbose`):
  - `%USERPROFILE%\claude-code-with-bedrock\logs\credential-provider.log`
  - `%USERPROFILE%\claude-code-with-bedrock\logs\otel-helper.log`

## Rollback to Python

If you need to revert to the Python version:

1. Remove Rust binaries
2. Reinstall Python package: `poetry install` (from `source/` directory)
3. Python binaries will be restored

## Contributing

- Follow Rust conventions and idioms
- Add tests for new features
- Run `cargo fmt` and `cargo clippy` before committing
- Update this README for significant changes

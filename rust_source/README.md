# Rust Implementation of credential-provider and otel-helper

This directory contains optional Rust reimplementations of the Python `credential_provider` and `otel_helper` scripts. These are **drop-in replacements** that offer significantly better performance while maintaining complete compatibility with the Python versions.

**Status**: Optional - Python implementation remains the default.

## Overview

- **credential-provider**: OIDC authentication and AWS credential provider
- **otel-helper**: OpenTelemetry headers generator from JWT tokens
- **Performance**: Up to 321x faster execution, up to 91% less memory usage
- **Compatibility**: Uses identical config.json format, same CLI arguments

## Performance Benchmarks

Real-world benchmark results comparing Rust vs Python implementations. Benchmarks measured using macOS `/usr/bin/time -l` for execution time and peak RSS (Resident Set Size) memory usage, averaged over 5 iterations.

### credential-provider

| Metric | Python | Rust | Improvement |
|--------|--------|------|-------------|
| **Execution Time** | 1.2840s | 0.0040s | **321x faster** |
| **Memory Usage** | 53.79 MB | 4.76 MB | **91% reduction** |
| **Binary Size** | 29 MB | 20 MB | **31% smaller** |

### otel-helper

| Metric | Python | Rust | Improvement |
|--------|--------|------|-------------|
| **Execution Time** | 0.3720s | 0.0180s | **21x faster** |
| **Memory Usage** | 25.04 MB | 5.79 MB | **76% reduction** |
| **Binary Size** | 8.7 MB | 2.4 MB | **72% smaller** |

**Benchmark methodology**: Measured execution time via `/usr/bin/time -l`, capturing real time and maximum resident set size. Tests run `--version` flag for credential-provider and `--test` flag for otel-helper to ensure complete initialization without external dependencies.

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
cp target/release/otel-helper ~/claude-code-with-bedrock/otel-helper
```

### Windows

```powershell
# Build optimized binaries
cargo build --release

# Install (replaces Python binaries)
copy target\release\credential-provider.exe %USERPROFILE%\claude-code-with-bedrock\credential-process.exe
copy target\release\otel-helper.exe %USERPROFILE%\claude-code-with-bedrock\otel-helper.exe
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
copy target\release\otel-helper.exe dist\windows-x86_64\otel-helper.exe

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
   - `jwt.rs`: JWT parsing utilities
   - `config.rs`: Configuration types
   - `error.rs`: Common error types
   - `logging.rs`: Shared logging utilities

2. **credential-provider** - Main authentication binary
   - `config.rs`: Configuration loading and provider detection
   - `storage.rs`: Keyring/session file credential storage
   - `oidc.rs`: OAuth2 PKCE flow with callback server
   - `aws.rs`: AWS credential federation via Cognito Identity Pool
   - `concurrency.rs`: Port-based locking for safe concurrent authentication
   - `logging.rs`: File-based debug logging

3. **otel-helper** - Telemetry helper binary
   - `jwt.rs`: JWT decoding
   - `attributes.rs`: User attribute extraction with privacy hashing
   - `headers.rs`: HTTP header formatting
   - `token.rs`: Token retrieval via subprocess
   - `logging.rs`: File-based debug logging

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

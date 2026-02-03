# Snipher 🕵️‍♂️

**Snipher** is a high-performance Go-based security auditing tool designed to inspect, validate, and audit TLS configurations. It provides deep visibility into certificate trust chains, protocol support (from legacy SSLv2 to modern TLS 1.3), and security posture.

## Features

- **🛡️ Protocol Enumeration:** Parallel detection of TLS 1.0, 1.1, 1.2, and 1.3.
- **🕵️ Legacy Detection:** Manual packet construction to detect SSLv2 and SSLv3, bypassing modern library restrictions.
- **🔐 Cipher Suite Enumeration:**
  - **Strength-Based Sorting**: Ciphers displayed strongest-first (ECDHE+AES-256+GCM → RC4).
  - **Verbose Mode** (`--verbose`): Shows ALL possible ciphers with ✓/✗ status indicators.
  - **Weak Cipher Highlighting**: Automatically flags RC4, DES, 3DES, MD5, NULL ciphers.
  - **Comprehensive Coverage**: TLS 1.0-1.3 cipher discovery.
- **📜 Advanced Certificate Audit:**
  - Full **Chain of Trust** visualization.
  - **Trust Anchor** (Root CA) identification and highlighting.
  - **Serial Number** display for all certificates in the chain.
  - **Time-Agnostic Trust**: Identifies trusted roots even for expired certificates.
  - **SANs Inspection**: Toggleable Subject Alternative Names display.
- **📦 Private PKI Support:** Use the `--ca-bundle` flag to validate against custom root certificates.
- **🤖 Automation Ready:** Stable `--json` output for CI/CD pipelines.
- **🚦 Strict Exit Codes for CI/CD:** 
  - **Exit Code 0**: Scan completed successfully, no critical issues found.
  - **Exit Code 1**: Critical security issue detected (expired/untrusted certificates, SSLv2/SSLv3 enabled).
  - **Exit Code 2**: Operational error (DNS failure, connection timeout, invalid input).

## Installation & Building

Snipher is written in Go and builds into a single, statically linked binary.

### Prerequisites
- [Go 1.21+](https://go.dev/dl/)

### Build Instructions
```powershell
# Build the snipher binary
go build -o snipher.exe ./cmd/snipher
```

## Usage

```bash
# Standard scan (shows enabled ciphers sorted by strength)
./snipher google.com

# Verbose mode (shows ALL ciphers with ✓/✗ indicators)
./snipher google.com --verbose

# Scan with custom CA bundle and SANs visible
./snipher internal.local --ca-bundle ./root.pem --sans

# JSON output for pipelines
./snipher google.com --json

# Scan slow servers with adaptive timeouts
./snipher 3des.badssl.com --min-timeout 500ms --max-timeout 5s
```

### Flags
- `--port, -p`: Select target port (default: 443).
- `--verbose, -v`: Show all possible cipher suites for each enabled protocol with status indicators (✓ enabled, ✗ disabled).
- `--json`: Output strict JSON schema for automation.
- `--ca-bundle, --ca`: Path to custom CA PEM file for internal PKI validation.
- `--sans`: Show Subject Alternative Names in certificate details.
- `--min-timeout`: Initial timeout per cipher check (default: `2s`).
- `--max-timeout`: Maximum timeout for cipher check retries (default: `10s`).

## CI/CD Integration

Snipher is designed for seamless integration into CI/CD pipelines with **zero configuration required**.

### Automatic CI Detection

Snipher automatically detects CI/CD environments and adjusts its output accordingly. When running in CI mode, colors and interactive elements are disabled for clean log output.

**Supported CI Platforms:**
- GitHub Actions (`GITHUB_ACTIONS`)
- GitLab CI (`GITLAB_CI`)
- Jenkins (`JENKINS_HOME`)
- Travis CI (`TRAVIS`)
- CircleCI (`CIRCLECI`)
- Buildkite (`BUILDKITE`)
- Drone CI (`DRONE`)
- Azure Pipelines (`TF_BUILD`)
- Generic CI (`CI=true`)

### Output Modes

**Interactive Mode (Default):**
- Rich colors and styling
- Box-drawing characters for tables
- Visual indicators for warnings and errors

**CI Mode (Auto-detected):**
- Plain text output
- No ANSI color codes
- Simple ASCII borders
- Fully parseable logs

**JSON Mode (`--json` flag):**
- Structured JSON output
- Overrides CI detection
- Machine-readable format for automation

### Example CI Usage

```yaml
# GitHub Actions example
- name: Scan TLS Configuration
  run: |
    ./snipher production.example.com
    # Exit code 0 = success, 1 = critical issue, 2 = operational error
```

No special flags needed - Snipher detects the CI environment automatically!

## Testing & Verification

### Local Mock Server
Test detection logic locally without external dependencies using our mock TLS server:

1. **Start the Mock Server:**
   ```bash
   go run ./tools/tls-server/main.go --port 4433
   ```
2. **Scan the Mock:**
   ```bash
   ./snipher localhost --port 4433
   ```

## License
MIT

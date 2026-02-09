# Snipher 🕵️‍♂️

**Snipher** is a high-performance Go-based security auditing tool designed to inspect, validate, and audit TLS configurations. It provides deep visibility into certificate trust chains, protocol support (TLS 1.0 to TLS 1.3), and security posture.

> [!NOTE]
> **How do you say it?** 🗣️
> Whether you pronounce it **"sni-fur"** (like a sniper) or the literal **"sniff-er"**, we won't judge. Just please, for the love of all things holy, **don't call it "snip-her"**.


## Features

- **🛡️ Protocol Enumeration:** Parallel detection of TLS 1.0, 1.1, 1.2, and 1.3.
- **📚 Complete IANA Cipher Coverage:** Comprehensive scanning support for all IANA-registered cipher suites including legacy SSLv2/SSLv3 ciphers (for security auditing purposes).
- **🔐 Cipher Suite Enumeration:**
  - **Strength-Based Sorting**: Ciphers displayed strongest-first (ECDHE+AES-256+GCM → RC4).
  - **Verbose Mode** (`--verbose`): Shows ALL possible ciphers with status indicators (`✓` enabled, `✗` disabled).
  - **Reference Mode** (`list-ciphers`): View a standardized list of all supported ciphers by protocol.
  - **Security Icons**: Clear visual indicators for weak (`⚠`) and critically insecure (`⊘`) ciphers.
- **🔬 Deep Intel Vulnerability Reporting:**
  - **Standardized Ratings**: All vulnerabilities ranked on a `Low/Medium/High/Critical` scale.
  - **Colorful Visual Tags**: Instant visual recognition via severity-based background colors (Red = Critical, Orange = High, Magenta = Medium).
  - **Risk & Impact Details**: Explicit "Risk Detail" and "Impact Detail" fields for every report.
  - **Exploit Tracking**: Specific "Exploit Ref" links for vulnerabilities currently exploited in the wild.
  - **Recency Verification**: All vulnerability profiles include a "Verified" date for data recency.
- **⚖️ Policy-Based Auditing:**
  - **Compliance-as-Code**: Define corporate TLS standards in a YAML policy file.
  - **Automatic Enforcement**: Use `--policy path.yaml` to verify targets against allowed protocols and ciphers.
  - **Dual Naming Support**: Use either IANA or OpenSSL names in your policy files.
  - **Visual Violation Tracking**: Non-compliant configurations are explicitly tagged with `POLICY VIOLATION` (Cyan).
- **📜 Advanced Certificate Audit:**
  - Full **Chain of Trust** visualization.
  - **Trust Anchor** (Root CA) identification and highlighting.
  - **Serial Number** display for all certificates in the chain.
  - **Time-Agnostic Trust**: Identifies trusted roots even for expired certificates.
  - **SANs Inspection**: Toggleable Subject Alternative Names display.
- **📦 Private PKI Support:** Use the `--ca-bundle` flag to validate against custom root certificates.
- **📋 Comprehensive Cipher Database:**
  - **135+ Cipher Suites**: Complete IANA registry coverage from SSLv2 through TLS 1.3.
  - **Legacy Protocol Support**: SSLv2/SSLv3 cipher detection for comprehensive security audits.
  - **Security-First Categorization**: All legacy, NULL, and EXPORT ciphers clearly marked as HIGH RISK.
  - **Dual Naming**: Both IANA and OpenSSL naming conventions supported for all cipher suites.
- **🤖 Automation Ready:** Stable `--json` output for CI/CD pipelines.
- **🚦 Strict Exit Codes for CI/CD:** 
  - **Exit Code 0**: Scan completed successfully, no issues/violations found.
  - **Exit Code 1**: Critical security issue or Policy Violation detected.
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

# Verify against a corporate policy
./snipher production.internal --policy my-standard.yaml

# Combined naming format (IANA / OpenSSL) via naming flag
./snipher google.com --naming both

# Verbose mode with OpenSSL naming convention
./snipher google.com --verbose --naming openssl

# Scan with custom CA bundle and SANs visible
./snipher internal.local --ca-bundle ./root.pem --sans

# JSON output for pipelines
./snipher google.com --json

# Scan slow servers with adaptive timeouts
./snipher 3des.badssl.com --min-timeout 500ms --max-timeout 5s

# Display reference list of all supported ciphers
./snipher list-ciphers --naming both
```

### Flags
- `--port, -p`: Select target port (default: 443).
- `--verbose, -v`: Show all possible cipher suites for each enabled protocol with status indicators (✓ enabled, ✗ disabled).
- `--policy`: Path to a YAML policy file to verify against.
- `--naming`: Select cipher naming style: `iana` (default), `openssl`, or `both`.
- `--json`: Output strict JSON schema for automation.
- `--ca-bundle, --ca`: Path to custom CA PEM file for internal PKI validation.
- `--sans`: Show Subject Alternative Names in certificate details.
- `--min-timeout`: Initial timeout per cipher check (default: `2s`).
- `--max-timeout`: Maximum timeout for cipher check retries (default: `10s`).

### Commands
- `list-ciphers`: Display a reference list of all supported ciphers and exit.

## Policy-Based Auditing

Define a "Golden Standard" in YAML to automate security compliance.

### Example Policy (`standard.yaml`)
```yaml
name: "Corporate Standard v1.2"
protocols:
  - "TLS 1.2"
  - "TLS 1.3"
ciphers:
  - "TLS_AES_256_GCM_SHA384"
  - "ECDHE-RSA-AES256-GCM-SHA384" # OpenSSL names supported!
```

### Color Legend 🎨
When running in interactive mode (non-CI), Snipher uses background colors to help you prioritize:
- 🔴 **Red**: `Critical` Security Vulnerability
- 🟠 **Orange**: `High` Security Risk
- 🟣 **Magenta**: `Medium` Security Risk
- 🔵 **Blue**: `Low` Security Risk
- 🟢 **Cyan**: `Policy Violation` (Compliance failure)

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

## 🚀 Future Improvements

- **Complete Adversiary Code Review**: Complete an adverserial code review.
- **Automated Remediation Advice**: Contextual tips based on detected flaws.

## License
MIT


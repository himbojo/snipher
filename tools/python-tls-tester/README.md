# Python TLS Server & PKI Generator

This tool provides a Python-based TLS web server capable of supporting legacy and modern TLS protocols (SSLv2 - TLS1.3) and custom cipher suites. It also includes a script to generate a complete 3-tier PKI certificate chain.

## Prerequisites

- Python 3.6+
- `cryptography` library (`pip install cryptography`)
- OpenSSL (system library used by Python's `ssl` module)

## Quick Start

1.  **Generate Certificates**
    
    Run the generation script for your platform:
    ```powershell
    # Windows
    .\generate_pki.ps1
    ```
    ```bash
    # Linux / macOS
    ./generate_pki.sh
    ```
    This will create a `certs/` directory containing:
    -   `root_ca.pem`, `intermediate_ca.pem`, `issuing_ca.pem`
    -   `leaf_cert.pem`, `leaf_key.pem`
    -   `fullchain.pem` (Leaf -> Issuing -> Intermediate)

2.  **Start the Server**

    Run the server using default settings (Port 4443, all supported protocols):
    ```bash
    python server.py
    ```

    Navigate to `https://localhost:4443` in your browser (accept the self-signed certificate warning).

## Docker Usage (Recommended for Legacy Support)

If your local environment (like Windows 11 or modern Linux) does not support older protocols like SSLv2/SSLv3 or weak ciphers, use the provided Docker container. It compiles a custom OpenSSL 1.0.2u with all legacy features enabled.

1.  **Build the Image**
    ```bash
    docker build -t tls-test-server .
    ```

2.  **Run the Container**
    ```bash
    docker run -p 4443:4443 --rm -it tls-test-server
    ```
    To force a specific protocol or cipher:
    ```bash
    docker run -p 4443:4443 --rm -it tls-test-server --protocol SSLv3 --cipher ALL:eNULL:@SECLEVEL=0
    ```

## Usage

### Command Line Arguments

```bash
python server.py --help
usage: server.py [-h] [--port PORT] [--protocol {TLSv1.3,TLSv1.2,TLSv1.1,TLSv1.0,SSLv3,SSLv2,ALL}] [--cipher CIPHER]
```

-   `--port`: Port to listen on (default: 4443).
-   `--protocol`: Force a specific TLS/SSL version. Note that SSLv2/SSLv3 support depends on your system's OpenSSL configuration.
-   `--cipher`: Specify a cipher suite string. You can use standard OpenSSL names OR IANA names (e.g., `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`).

### Examples

**Force TLS 1.2 with a specific cipher:**
```bash
python server.py --protocol TLSv1.2 --cipher TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

**Force TLS 1.3:**
```bash
python server.py --protocol TLSv1.3
```

**Attempt SSLv3 (if supported):**
```bash
python server.py --protocol SSLv3 --cipher RC4-MD5
```

## Protocol Support Note

Modern operating systems and Python versions often disable SSLv2 and SSLv3 at compile time for security reasons. If you receive an error like `AttributeError: module 'ssl' has no attribute 'PROTOCOL_SSLv3'`, your environment does not support that protocol.

## IANA Cipher Mapping

The `iana_ciphers.py` module contains a mapping of IANA cipher suite names to their OpenSSL equivalents. This allows you to use the standard names in the `--cipher` argument.

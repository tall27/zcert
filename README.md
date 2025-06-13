# ZCERT - Zero Touch PKI Certificate Management CLI

[![Release](https://img.shields.io/github/v/release/your-org/zcert)](https://github.com/your-org/zcert/releases)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://github.com/your-org/zcert/workflows/Tests/badge.svg)](https://github.com/your-org/zcert/actions)

A production-ready command-line tool for managing digital certificates through CyberArk's Zero Touch PKI (ZTPKI) service. ZCERT provides secure, automated certificate lifecycle management with enterprise-grade security and cross-platform support.

## 🚀 Quick Start

### Installation

#### Binary Downloads
```bash
# Linux (x86_64)
curl -L https://github.com/your-org/zcert/releases/download/v1.1.0/zcert-1.1.0-linux-amd64.tar.gz | tar xz
sudo mv zcert /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/your-org/zcert/releases/download/v1.1.0/zcert-1.1.0-darwin-amd64.tar.gz | tar xz
sudo mv zcert /usr/local/bin/

# macOS (Apple Silicon)
curl -L https://github.com/your-org/zcert/releases/download/v1.1.0/zcert-1.1.0-darwin-arm64.tar.gz | tar xz
sudo mv zcert /usr/local/bin/
```

#### Verify Installation
```bash
zcert --version
```

### Basic Usage

```bash
# Set up environment
zcert env

# Search certificates
zcert search --filter "status:active"

# Enroll new certificate
zcert enroll --cn "server.example.com"

# Retrieve certificate
zcert retrieve --thumbprint abc123...
```

## 🔧 Features

### Certificate Operations
- **Certificate Enrollment** - Request new certificates with flexible RSA key sizes
- **Certificate Retrieval** - Download existing certificates in multiple formats
- **Certificate Search** - Advanced filtering and policy-based searching  
- **Certificate Revocation** - Secure certificate revocation with confirmation

### Security Features
- **HAWK Authentication** - Secure API authentication with proper nonce generation
- **RSA Key Support** - 2048, 3072, and 4096-bit RSA key generation
- **Secure Configuration** - Protected configuration files with restricted permissions
- **Input Validation** - Comprehensive sanitization and validation

### Platform Support
- **Linux** (x86_64) - Primary target platform
- **macOS** (Intel and Apple Silicon) - Full compatibility
- **Windows** (x86_64) - Complete Windows support
- **Cross-Platform Builds** - Automated release binaries

## 📖 Documentation

### Configuration

Create a configuration file with secure defaults:
```bash
zcert config --cnf
```

Example configuration:
```ini
[Default]
url = https://ztpki.venafi.com/api/v2
hawk-id = your-hawk-id
hawk-key = your-hawk-key
format = pem
policy = your-policy-id
key-size = 3072
key-type = rsa
validity = 90d
chain = true
```

### Environment Variables
```bash
export ZTPKI_HAWK_ID="your-hawk-id"
export ZTPKI_HAWK_SECRET="your-hawk-secret"
export ZTPKI_POLICY_ID="your-policy-id"
```

### Certificate Enrollment

```bash
# Basic enrollment
zcert enroll --cn "server.example.com"

# With Subject Alternative Names
zcert enroll --cn "api.example.com" \
  --san-dns "example.com" \
  --san-dns "www.example.com"

# Custom key size and validity
zcert enroll --cn "secure.example.com" \
  --key-size 4096 \
  --validity "1y"

# Using specific profile
zcert --profile production enroll --cn "prod.example.com"
```

### Certificate Search

```bash
# Search by status
zcert search --filter "status:active"

# Search by expiration
zcert search --filter "expires:<30days"

# Search by policy
zcert search --policy-id "PolicyName"

# List all policies
zcert search --policy-id
```

### Certificate Retrieval

```bash
# Retrieve by thumbprint
zcert retrieve --thumbprint abc123def456...

# Retrieve by serial number
zcert retrieve --serial 123456789

# Custom output files
zcert retrieve --thumbprint abc123... \
  --cert-file "server.crt" \
  --key-file "server.key"
```

## 🔒 Security

### Authentication
ZCERT uses HAWK authentication for secure API communication:
- Cryptographically secure nonce generation
- Request signing with HMAC-SHA256
- Automatic credential protection

### Key Generation
- Support for 2048, 3072, and 4096-bit RSA keys
- Secure random number generation
- Local CSR creation for enhanced security
- Private key protection with optional encryption

### Configuration Security
- Automatic file permission restrictions (0600)
- Environment variable support for sensitive data
- No credential exposure in logs or output

## 🛠 Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/your-org/zcert.git
cd zcert

# Install dependencies
go mod tidy

# Build
go build -o zcert main.go

# Run tests
go test ./...

# Cross-platform build
./build-cross-platform.sh
```

### Project Structure

```
zcert/
├── cmd/                 # Command implementations
├── internal/
│   ├── api/            # ZTPKI API client
│   ├── cert/           # Certificate operations
│   ├── config/         # Configuration management
│   └── policy/         # Policy management
├── main.go             # Application entry point
├── go.mod              # Go module definition
└── build*.sh           # Build scripts
```

### Testing

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./internal/cert -v

# Run with coverage
go test -cover ./...
```

## 📊 Examples

### Automated Certificate Management

```bash
#!/bin/bash
# Certificate renewal script

# Search for expiring certificates
EXPIRING=$(zcert search --filter "expires:<30days" --format json)

# Process each expiring certificate
echo "$EXPIRING" | jq -r '.certificates[].thumbprint' | while read thumbprint; do
    echo "Processing certificate: $thumbprint"
    
    # Retrieve certificate details
    CERT_INFO=$(zcert retrieve --thumbprint "$thumbprint" --format json)
    CN=$(echo "$CERT_INFO" | jq -r '.subject.common_name')
    
    # Enroll new certificate
    zcert enroll --cn "$CN" --cert-file "${CN}.crt" --key-file "${CN}.key"
    
    echo "New certificate enrolled for: $CN"
done
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Get SSL Certificate
  run: |
    zcert enroll \
      --cn "${{ env.DOMAIN_NAME }}" \
      --cert-file "ssl.crt" \
      --key-file "ssl.key" \
      --format pem
```

## 🔄 Changelog

### v1.1.0 (Latest)
- Enhanced RSA key size support (2048, 3072, 4096-bit)
- Improved configuration validation
- Added comprehensive test coverage
- Fixed profile selection priority
- Updated default key size to 3072-bit

### v1.0.0
- Initial production release
- Complete certificate lifecycle management
- HAWK authentication support
- Cross-platform compatibility
- Security hardening

## 🆘 Support

### Getting Help

```bash
# General help
zcert --help

# Command-specific help
zcert enroll --help

# Environment setup guidance
zcert env

# Verbose output for troubleshooting
zcert --verbose search --limit 1
```

### Common Issues

**Authentication Errors**
```bash
# Check environment setup
zcert env

# Verify configuration
zcert search --limit 1 --verbose
```

**Certificate Enrollment Issues**
```bash
# Check policy compatibility
zcert search --policy-id

# Verify key size support
zcert enroll --cn "test.example.com" --verbose
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Security

For security vulnerabilities, please email security@example.com instead of using the issue tracker.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- CyberArk for the Zero Touch PKI platform
- Go community for excellent tooling and libraries
- Contributors and early adopters for valuable feedback

---

**ZCERT v1.1.0** - Secure, automated certificate management for modern infrastructure.
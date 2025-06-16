# ZCERT - CyberArk Zero Touch PKI CLI Tool

A security-hardened command-line certificate management tool for CyberArk's Zero Touch PKI (ZTPKI) service, featuring comprehensive certificate lifecycle operations and advanced shell integration.

## 🔒 Security Features

**Production-Ready Security Hardening Completed:**
- **HAWK Authentication** - Secure API authentication with cryptographically strong nonce generation
- **Protected Configuration** - Automatic file permission hardening (0600) for sensitive data
- **Zero Sensitive Data Exposure** - No debug information leakage of authentication credentials
- **Input Validation** - Comprehensive sanitization and validation throughout
- **Secure File Handling** - Protected permissions on configuration files containing secrets

## Overview

zcert provides a comprehensive set of certificate lifecycle operations including enrollment, retrieval, revocation, and management through the ZTPKI REST API. The tool uses HAWK authentication and supports multiple output formats for maximum flexibility.

## ✨ Key Features

- **Certificate Enrollment**: Generate private keys, create CSRs, and request certificates
- **Certificate Retrieval**: Fetch existing certificates by ID, Common Name, or other criteria
- **Certificate Revocation**: Revoke certificates with confirmation prompts
- **Policy Management**: Interactive policy selection during enrollment
- **Multiple Output Formats**: PEM, PKCS#12, Java Keystore, and DER formats
- **HAWK Authentication**: Secure API communication using HAWK request signing
- **Configuration Management**: Support for config files and environment variables
- **Interactive and Scripted Usage**: Works both interactively and in automated workflows

## Installation

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/zcert.git
cd zcert

# Install dependencies
go mod tidy

# Build the executable
go build -o zcert main.go

# For Windows
go build -o zcert.exe main.go
```

### Prerequisites

- Go 1.19 or later
- Access to a CyberArk Zero Touch PKI instance
- HAWK authentication credentials

## Quick Start

### 1. Configuration

Create a configuration file at `~/.zcert.cnf`:

```ini
[Default]
base_url = https://your-ztpki-instance.com/api/v2
hawk_id = your-hawk-id-here
hawk_key = your-hawk-key-here
verbose = false
default_key_size = 2048
default_key_type = rsa
default_format = pem
```

Or generate a template configuration:
```bash
# Generate basic configuration template
zcert config --ini > zcert.cnf

# Generate YAML playbook template
zcert config --yaml > playbook.yaml
```

Or use environment variables:
```bash
export ZCERT_HAWK_ID="your-hawk-id"
export ZCERT_HAWK_KEY="your-hawk-key"
export ZCERT_BASE_URL="https://your-ztpki-instance.com/api/v2"
```

### 2. Basic Usage

#### Enroll a new certificate
```bash
# Interactive enrollment (will prompt for policy selection)
zcert enroll --cn example.com

# Non-interactive enrollment
zcert enroll --cn example.com --policy "Web Server Policy" --file mycert

# With Subject Alternative Names
zcert enroll --cn example.com --sans "www.example.com,api.example.com"
```

#### Retrieve an existing certificate
```bash
# By certificate ID
zcert retrieve --id "cert-12345"

# By Common Name
zcert retrieve --cn example.com

# Save to file
zcert retrieve --cn example.com --file retrieved-cert.pem
```

#### Search certificates
```bash
# List all certificates
zcert search

# Search by Common Name
zcert search --cn example.com

# Show certificates expiring in 30 days
zcert search --expiring 30

# Output as JSON
zcert search --format json
```

#### Revoke a certificate
```bash
# Interactive revocation (will prompt for confirmation)
zcert revoke --cn example.com

# Force revocation without confirmation
zcert revoke --id "cert-12345" --force --reason "keyCompromise"
```

## Commands

### `zcert config`
Generate configuration templates for setup and automation.

**Flags:**
- `--ini`: Generate INI configuration file template
- `--yaml`: Generate YAML playbook template
- `--comprehensive`: Include comprehensive examples and documentation

**Examples:**
```bash
# Generate basic INI configuration
zcert config --ini > zcert.cnf

# Generate YAML playbook template
zcert config --yaml > playbook.yaml

# Generate comprehensive playbook with examples
zcert config --yaml --comprehensive > full-playbook.yaml
```

### `zcert env`
Display environment variable setup instructions and test connectivity.

**Flags:**
- `--test`: Test API connectivity and authentication

**Examples:**
```bash
# Show environment setup instructions
zcert env

# Test API connectivity
zcert env --test
```

### `zcert run`
Execute YAML playbook for automated certificate operations.

**Flags:**
- `--file string`: Path to YAML playbook file
- `--force`: Force renewal of certificates even if not needed
- `--dry-run`: Show what would be executed without making changes

**Examples:**
```bash
# Execute playbook
zcert run --file playbook.yaml

# Force renewal of all certificates in playbook
zcert run --file playbook.yaml --force

# Preview operations without executing
zcert run --file playbook.yaml --dry-run
```

### `zcert enroll`
Request a new certificate from ZTPKI with complete workflow automation.

**Flags:**
- `--cn string`: Common Name for the certificate
- `--sans strings`: Subject Alternative Names (comma-separated)
- `--policy string`: Policy ID or name for certificate issuance
- `--key-size int`: RSA key size in bits (default: 2048)
- `--key-type string`: Key type - rsa or ecdsa (default: "rsa")
- `--format string`: Output format - pem, p12, jks, der (default: "pem")
- `--file string`: Output file path
- `--p12-password string`: Password for PKCS#12 format
- `--no-key-output`: Don't output private key to file

### `zcert retrieve`
Retrieve an existing certificate from ZTPKI.

**Flags:**
- `--id string`: Certificate ID or GUID
- `--cn string`: Common Name of the certificate
- `--serial string`: Certificate serial number
- `--policy string`: Policy ID or name to filter by
- `--format string`: Output format (default: "pem")
- `--file string`: Output file path
- `--chain`: Include certificate chain

### `zcert search`
Search and list certificates with various filters.

**Flags:**
- `--cn string`: Search by Common Name (supports wildcards)
- `--issuer string`: Search by certificate issuer
- `--serial string`: Search by serial number
- `--policy string`: Search by policy ID or name
- `--status string`: Search by status (active, revoked, expired)
- `--limit int`: Maximum number of results (default: 50)
- `--format string`: Output format - table, json, csv (default: "table")
- `--expired`: Show only expired certificates
- `--expiring int`: Show certificates expiring within N days

### `zcert revoke`
Revoke an existing certificate.

**Flags:**
- `--id string`: Certificate ID or GUID
- `--cn string`: Common Name of the certificate
- `--serial string`: Certificate serial number
- `--reason string`: Revocation reason (default: "unspecified")
- `--force`: Skip confirmation prompt

### `zcert renew`
Renew an existing certificate (planned feature - currently shows placeholder).

## Configuration

### Configuration File

The configuration file uses INI format and can be placed at:
- `~/.zcert.cnf` or `zcert.cnf` in current directory
- Specified with `--config` flag

Example configuration:

```ini
[Default]
base_url = https://your-ztpki-instance.com/api/v2
hawk_id = your-hawk-id-here
hawk_key = your-hawk-key-here
verbose = false

# Certificate defaults
default_key_size = 2048
default_key_type = rsa
default_format = pem

# Output settings
output_directory = ./certificates
include_chain = true
```

### Profile-based Configuration

Support multiple environments with profile sections:

```ini
[Default]
base_url = https://dev-ztpki.example.com/api/v2
hawk_id = dev-hawk-id
hawk_key = dev-hawk-key

[Production]
base_url = https://prod-ztpki.example.com/api/v2
hawk_id = prod-hawk-id
hawk_key = prod-hawk-key
verbose = false
```

Use profiles with the `--profile` flag:
```bash
zcert enroll --cn example.com --profile Production
```

### Playbook Configuration

Generate YAML playbook templates for automated certificate operations:

```bash
# Generate basic playbook template
zcert config --yaml > playbook.yaml

# Generate comprehensive playbook with examples
zcert config --yaml --comprehensive > comprehensive-playbook.yaml
```

Example playbook structure:
```yaml
# ZCert Playbook Configuration
version: "1.0"
name: "Certificate Management Playbook"

authentication:
  base_url: "https://your-ztpki-instance.com/api/v2"
  hawk_id: "{{ HAWK_ID }}"
  hawk_key: "{{ HAWK_KEY }}"

certificateTasks:
  - name: "Web Server Certificate"
    action: "enroll"
    common_name: "www.example.com"
    policy_id: "your-policy-id-here"
    subject_alternative_names:
      - "example.com"
      - "api.example.com"
    key_type: "rsa"
    key_size: 2048
    output_file: "webserver-cert"
    format: "pem"
```

### Environment Variables

All configuration options can be overridden with environment variables using the `ZCERT_` prefix:

- `ZCERT_BASE_URL`: API base URL
- `ZCERT_HAWK_ID`: HAWK authentication ID
- `ZCERT_HAWK_KEY`: HAWK authentication key
- `ZCERT_VERBOSE`: Enable verbose output

Alternative environment variable names:
- `HAWK_ID`: Alternative for HAWK ID
- `HAWK_KEY`: Alternative for HAWK key
- `ZTPKI_URL`: Alternative for base URL

## Authentication

zcert uses HAWK (HTTP Authentication Web Key) for secure API communication with ZTPKI. You need:

1. **HAWK ID**: Your authentication identifier
2. **HAWK Key**: Your secret key for request signing

### Obtaining Credentials

Contact your ZTPKI administrator to obtain your HAWK authentication credentials:

```bash
export ZCERT_HAWK_ID="your-hawk-id-here"
export ZCERT_HAWK_KEY="your-hawk-key-here"
```

**Note**: Use only your authorized credentials for your specific ZTPKI environment.

## Output Formats

### PEM Format (Default)
```bash
zcert enroll --cn example.com --format pem
```
Outputs certificate in PEM format, optionally with private key and chain files.

### PKCS#12 Format
```bash
zcert enroll --cn example.com --format p12 --p12-password mypassword
```
Creates PEM files and provides OpenSSL commands for PKCS#12 conversion.

### Java Keystore Format
```bash
zcert enroll --cn example.com --format jks
```
Creates PKCS#12 files and provides keytool commands for JKS conversion.

### DER Format
```bash
zcert retrieve --cn example.com --format der
```
Outputs certificate in binary DER format.

## Error Handling

zcert provides detailed error messages for common scenarios:

- **Authentication failures**: Check HAWK credentials
- **Policy not found**: Use `zcert search` to find available policies
- **Certificate not found**: Verify certificate identifier
- **Network issues**: Check connectivity to ZTPKI endpoint
- **Invalid parameters**: Review command-line flags and configuration

Use `--verbose` flag for detailed operation logs:
```bash
zcert enroll --cn example.com --verbose
```

## Examples

### Complete Certificate Enrollment Workflow
```bash
# Set up authentication
export ZCERT_HAWK_ID="your-hawk-id"
export ZCERT_HAWK_KEY="your-hawk-key"

# Enroll a certificate with interactive policy selection
zcert enroll --cn api.example.com --sans "www.example.com,example.com"

# Enroll with specific policy (non-interactive)
zcert enroll --cn secure.example.com --policy "High Assurance Policy" --file secure-cert

# Retrieve and save certificate
zcert retrieve --cn api.example.com --file api-cert.pem --chain

# Check certificate status
zcert search --cn api.example.com

# Revoke when needed
zcert revoke --cn api.example.com --reason "superseded"
```

### Automated Certificate Management
```bash
#!/bin/bash
# Script for automated certificate enrollment

# Configuration
CN="app.example.com"
POLICY="Standard SSL"
OUTPUT_DIR="./certs"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Enroll certificate
zcert enroll \
    --cn "$CN" \
    --policy "$POLICY" \
    --file "$OUTPUT_DIR/$CN" \
    --format pem \
    --verbose

# Verify enrollment
if [ $? -eq 0 ]; then
    echo "Certificate enrolled successfully for $CN"
    zcert search --cn "$CN"
else
    echo "Certificate enrollment failed for $CN"
    exit 1
fi
```

## Troubleshooting

### Common Issues

1. **"Authentication failed"**
   - Verify HAWK ID and Key are correct
   - Check that credentials have proper permissions
   - Ensure system time is synchronized

2. **"No policies available"**
   - Verify API endpoint is correct
   - Check that your account has access to certificate policies
   - Contact your ZTPKI administrator

3. **"Certificate not ready"**
   - Increase poll timeout with configuration
   - Check certificate request status in ZTPKI web interface
   - Verify policy allows automatic issuance

4. **"Failed to connect to API"**
   - Check network connectivity
   - Verify API endpoint URL
   - Check firewall/proxy settings

### Debug Mode

Enable verbose logging for troubleshooting:
```bash
zcert --verbose enroll --cn example.com
```

### Configuration Validation

Test your configuration:
```bash
# This will show any configuration issues
zcert search --limit 1 --verbose
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Commit your changes: `git commit -am 'Add feature'`
5. Push to the branch: `git push origin feature-name`
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Open an issue on GitHub
- Review the troubleshooting section
- Check the CyberArk Zero Touch PKI documentation

## Changelog

### Version 1.0.0
- Initial release
- Certificate enrollment, retrieval, revocation, and search
- HAWK authentication implementation
- Multiple output format support
- Interactive and non-interactive modes
- Configuration file and environment variable support

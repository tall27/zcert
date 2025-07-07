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

# Build the executable (outputs "zcert" on Linux/macOS, "zcert.exe" on Windows)
./build.sh

# Or build manually:
# Linux/macOS: go build -o zcert main.go
# Windows: go build -o zcert.exe main.go
```

### Prerequisites

- Go 1.19 or later
- Access to a CyberArk Zero Touch PKI instance
- HAWK authentication credentials

## Quick Start

### 1. Configuration

The easiest way to get started is by generating a configuration file. This file will store your ZTPKI connection details and default settings.

1.  **Generate the configuration file:**

    ```bash
    zcert config --cnf
    ```

    This will create a `zcert.cnf` file in your current directory.

2.  **Edit the `zcert.cnf` file:**

    Open the newly created `zcert.cnf` file and fill in your ZTPKI `base_url`, `hawk_id`, and `hawk_key`.

    ```ini
    [Default]
    base_url = https://your-ztpki-instance.com/api/v2
    hawk_id = your-hawk-id-here
    hawk_key = your-hawk-key-here
    # ... other settings
    ```

Alternatively, you can use environment variables, which will override any settings in the configuration file. The `env` command can help you with this:

1.  **See platform-specific examples:**

    ```bash
    zcert env --examples
    ```

    This will show you the correct commands to set up environment variables for your operating system (Windows, macOS, or Linux).

2.  **Test your configuration:**

    Once you have set your environment variables or created your `zcert.cnf` file, you can verify that your connection to the ZTPKI API is working correctly:

    ```bash
    zcert env --test
    ```

### 2. Basic Usage

#### Enroll a new certificate
```bash
# Interactive enrollment (will prompt for policy selection)
zcert enroll --cn example.com

# Non-interactive enrollment with specific output files
zcert enroll --cn example.com --policy "Web Server Policy" --cert-file mycert.pem --key-file mycert.key

# With multiple Subject Alternative Names
zcert enroll --cn example.com --san-dns www.example.com --san-dns api.example.com
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
# List all available policies for enrollment
zcert search --policies

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
Generate example configuration files.

**Flags:**
- `--cnf`: Generate profile-based configuration file (zcert.cnf).
- `--yaml`: Generate YAML playbook configuration file.
- `--output string`: Output filename (default: zcert.cnf or playbook.yaml).

### `zcert config completion`
Generate shell completion scripts.

**Flags:**
- `--shell string`: Shell type (bash, zsh, fish, powershell).
- `--setup`: Generate setup script for Replit environment.

### `zcert enroll`
Request a new certificate from ZTPKI.

**Flags:**
- `--cn string`: Common Name for the certificate (required).
- `--san-dns strings`: DNS Subject Alternative Names (repeatable).
- `--san-ip strings`: IP Subject Alternative Names (repeatable).
- `--san-email strings`: Email Subject Alternative Names (repeatable).
- `--policy string`: Policy ID or name for certificate issuance.
- `--validity string`: Certificate validity period (e.g., 30d, 6m, 1y).
- `--org strings`: Organization (O) (repeatable).
- `--ou strings`: Organizational Unit (OU) (repeatable).
- `--locality string`: Locality/City (L).
- `--province string`: State/Province (ST).
- `--country string`: Country (C).
- `--key-size int`: RSA key size (default 2048).
- `--key-type string`: Key type (rsa, ecdsa) (default "rsa").
- `--key-curve string`: ECDSA curve (p256, p384, p521) (default "p256").
- `--csr string`: CSR generation mode (local, file) (default "local").
- `--csr-file string`: Path to CSR file for `file` mode.
- `--cert-file string`: Certificate output file path.
- `--key-file string`: Private key output file path.
- `--chain-file string`: Certificate chain output file path.
- `--bundle-file string`: Combined certificate bundle file path.
- `--format string`: Output format (pem, p12) (default "pem").
- `--key-password string`: Password for private key encryption.
- `--p12-password string`: Password for PKCS#12 bundle.
- `--no-key-output`: Do not output the private key.
- `--chain`: Include the certificate chain.

### `zcert search`
Search and list certificates.

**Flags:**
- `--cn string`: Search by Common Name (substring matching).
- `--issuer string`: Search by certificate issuer.
- `--serial string`: Search by serial number.
- `--policy string`: Search by policy ID or name.
- `--status string`: Search by certificate status.
- `--limit int`: Maximum number of results (default 10).
- `--format string`: Output format (table, json, csv) (default "table").
- `--wide`: Show full column content without truncation.
- `--expired`: Show only expired certificates.
- `--expiring string`: Show certificates expiring within a period (e.g., 30d, 6m, 1y).
- `--recent int`: Show certificates issued within N days.
- `-p, --policies`: List all available policies.

### `zcert retrieve`
Retrieve an existing certificate from ZTPKI.

**Flags:**
- `--id string`: Certificate ID or GUID.
- `--cn string`: Common Name of the certificate.
- `--serial string`: Certificate serial number.
- `--policy string`: Policy ID or name to filter by.
- `--format string`: Output format (pem, p12) (default "pem").
- `--file string`: Output file path.
- `--p12-password string`: Password for PKCS#12 bundle.
- `--chain`: Include certificate chain.

### `zcert revoke`
Revoke an existing certificate.

**Flags:**
- `--id string`: Certificate ID or GUID.
- `--cn string`: Common Name of the certificate.
- `--serial string`: Certificate serial number.
- `--reason string`: Revocation reason (default "unspecified").
- `--force`: Skip confirmation prompt.

### `zcert renew`
Renew an existing certificate (Future Enhancement).

### `zcert pqc`
Generate and enroll Post-Quantum Cryptography certificates.

**Flags:**
- `--cn string`: Common Name for the certificate (required).
- `--pqc-algorithm string`: PQC algorithm (e.g., MLDSA44, Dilithium2).
- ... (and many other flags similar to `enroll`)

### `zcert env`
Show environment variable setup instructions and test connectivity.

**Flags:**
- `--examples`: Show platform-specific setup instructions.
- `--test`: Test ZTPKI API connectivity and authentication.

## Configuration

zcert uses a hierarchical system for configuration, allowing for flexible and powerful setup options. The order of precedence is as follows:

1.  **Command-line Flags:** Flags provided directly with a command (e.g., `zcert enroll --cn example.com`) always take the highest priority, overriding all other settings.
2.  **Configuration File (`zcert.cnf`):** Settings defined in a profile within your `zcert.cnf` file are used next. You can specify a profile with the `--profile` global flag.
3.  **Environment Variables:** If a setting is not provided via a flag or in the config file, the tool will look for environment variables (e.g., `ZCERT_HAWK_ID`). This is the last place the tool looks.

This hierarchy allows you to set up general defaults in environment variables, create specific profiles for different environments (like `dev` and `prod`) in your `zcert.cnf` file, and then override any setting on-the-fly for a specific command using flags.

### Configuration File

The configuration file uses INI format. `zcert` will automatically use a file named `zcert.cnf` if it finds one in the same directory where you run the command. You can also place the file in your home directory (`~/.zcert.cnf`) or specify a path to a configuration file using the global `--config` flag.

The locations are checked in the following order:
1. Path specified with `--config` flag.
2. `zcert.cnf` in the current directory.
3. `.zcert.cnf` in the current directory.
4. `~/.zcert.cnf` in the user's home directory.

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

### Environment Variables

All configuration options can be overridden with environment variables. The following variables are supported:

- `ZTPKI_URL`: The base URL for the ZTPKI API.
- `ZTPKI_HAWK_ID`: Your HAWK authentication ID.
- `ZTPKI_HAWK_SECRET`: Your HAWK authentication secret key.
- `ZTPKI_POLICY_ID`: The default policy ID to use for enrollment.

To see platform-specific examples for setting these variables, run `zcert env --examples`.

## Authentication

zcert uses HAWK (HTTP Authentication Web Key) for secure API communication with ZTPKI. You need:

1. **HAWK ID**: Your authentication identifier
2. **HAWK Key**: Your secret key for request signing

### Obtaining Credentials

Contact your ZTPKI administrator to obtain your HAWK authentication credentials. You can set them up using the `zcert env --examples` command.

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
Creates a password-protected PKCS#12 file containing the certificate and private key.

## Error Handling

zcert provides detailed error messages for common scenarios:

- **Authentication failures**: Check HAWK credentials
- **Policy not found**: Use `zcert search --policies` to find available policies
- **Certificate not found**: Verify certificate identifier
- **Network issues**: Check connectivity to ZTPKI endpoint
- **Invalid parameters**: Review command-line flags and configuration

Use `--verbose` flag for detailed operation logs:
```bash
zcert enroll --cn example.com -v
```

## Examples

### Complete Certificate Enrollment Workflow
```bash
# Set up authentication using environment variables
export ZTPKI_HAWK_ID="your-hawk-id"
export ZTPKI_HAWK_SECRET="your-hawk-key"
export ZTPKI_URL="https://your-ztpki-instance.com/api/v2"

# Enroll a certificate with interactive policy selection
zcert enroll --cn api.example.com --san-dns "www.example.com" --san-dns "example.com"

# Enroll with specific policy (non-interactive) and save to files
zcert enroll --cn secure.example.com --policy "High Assurance Policy" --cert-file secure-cert.pem --key-file secure-cert.key

# Retrieve and save certificate
zcert retrieve --cn api.example.com --file api-cert.pem --chain

# Check certificate status
zcert search --cn api.example.com

# Revoke when needed
zcert revoke --cn api.example.com --reason "superseded"
```
### PQC Certificate Enrollment
```bash
# Enroll a PQC certificate using the dilithium3 algorithm
zcert pqc --cn pqc.example.com --pqc-algorithm dilithium3
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
    --cert-file "$OUTPUT_DIR/$CN.crt" \
    --key-file "$OUTPUT_DIR/$CN.key" \
    --format pem \
    -v

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
   - Verify HAWK ID and Key are correct using `zcert env --test`.
   - Check that credentials have proper permissions.
   - Ensure system time is synchronized.

2. **"No policies available"**
   - Verify API endpoint is correct using `zcert env --test`.
   - Check that your account has access to certificate policies with `zcert search --policies`.
   - Contact your ZTPKI administrator.

3. **"Certificate not ready"**
   - Increase poll timeout with configuration.
   - Check certificate request status in ZTPKI web interface.
   - Verify policy allows automatic issuance.

4. **"Failed to connect to API"**
   - Check network connectivity.
   - Verify API endpoint URL with `zcert env --test`.
   - Check firewall/proxy settings.

### Debug Mode

Enable verbose logging for troubleshooting:
```bash
zcert -v enroll --cn example.com
```
For even more detail, including full API responses:
```bash
zcert -vv enroll --cn example.com
```

### Configuration Validation

Test your configuration and authentication:
```bash
zcert env --test
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

## Tips and Tricks

### Bulk Certificate Operations

#### Bulk Revocation
For bulk certificate revocation, you can use PowerShell or Bash to pipe search results to revocation commands:

```powershell
# PowerShell: Revoke all valid certificates with CN 1.1.1.1
.\zcert search --cn 1.1.1.1 --status valid --wide | Select-Object -Skip 2 | ForEach-Object { .\zcert revoke --id ($_ -split '\s+')[0] --reason 3 --force }
```

```bash
# Bash: Revoke all valid certificates with CN 1.1.1.1
./zcert search --cn 1.1.1.1 --status valid --wide | tail -n +3 | awk '{print $1}' | xargs -I {} ./zcert revoke --id {} --reason 3 --force
```

For more deployment guidance and security information, see [DEPLOYMENT.md](DEPLOYMENT.md).


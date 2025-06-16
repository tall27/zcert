# ZCERT Production Deployment Guide

## Overview
This guide covers deploying the security-hardened zcert CLI tool for production environments with CyberArk Zero Touch PKI integration.

## Security Hardening Completed

### Critical Vulnerabilities Fixed
✅ **HAWK Debug Information Exposure** - Removed sensitive authentication data from console output  
✅ **Weak Cryptographic Nonce Generation** - Upgraded to cryptographically secure random number generation  
✅ **Insecure File Permissions** - Implemented 0600 permissions for configuration files containing sensitive data  
✅ **Code Duplication Elimination** - Consolidated duplicate utilities into shared functions  

### Security Features
- HAWK authentication with secure nonce generation
- Protected configuration file handling (0600 permissions)
- No sensitive data exposure in logs or debug output
- Input validation and sanitization throughout

## Cross-Platform Builds

### Supported Platforms
- **Linux AMD64** - Primary production target
- **macOS AMD64** - Intel-based Mac support
- **macOS ARM64** - Apple Silicon support  
- **Windows AMD64** - Windows 10/11 support

### GitHub Actions Automation
The repository includes automated CI/CD pipeline that:
- Builds binaries for all supported platforms
- Runs security scans and code quality checks
- Creates release artifacts with proper versioning
- Executes comprehensive test suites

## Environment Configuration

### Required Environment Variables
```bash
# HAWK Authentication
export ZTPKI_HAWK_ID="your-hawk-id"
export ZTPKI_HAWK_SECRET="your-hawk-secret"

# Policy Configuration
export ZTPKI_POLICY_ID="your-policy-id"
```

### Platform-Specific Setup
Run `zcert env` for detailed environment setup instructions for your platform.

## Production Deployment Steps

### 1. Binary Installation

#### Linux/macOS
```bash
# Download the appropriate binary for your platform
wget https://github.com/your-org/zcert/releases/latest/download/zcert-1.2.0-linux-amd64.tar.gz

# Extract and install (binary is named "zcert")
tar -xzf zcert-1.2.0-linux-amd64.tar.gz
sudo mv zcert /usr/local/bin/
sudo chmod +x /usr/local/bin/zcert
```

#### Windows
```powershell
# Download and extract the Windows binary
# Binary is named "zcert.exe"
Invoke-WebRequest -Uri "https://github.com/your-org/zcert/releases/latest/download/zcert-1.2.0-windows-amd64.zip" -OutFile "zcert.zip"
Expand-Archive -Path "zcert.zip" -DestinationPath "."

# Add to PATH or run directly
.\zcert.exe --version
```

### 2. Configuration Setup
```bash
# Generate example configuration
zcert config

# Edit configuration file with your settings
vim zcert.cnf

# Secure configuration file permissions
chmod 600 zcert.cnf
```

### 3. Shell Completion Setup
```bash
# Install bash completion
sudo cp zcert-completion.bash /etc/bash_completion.d/zcert

# For other shells, see completion documentation
zcert completion --help
```

### 4. Verification
```bash
# Test basic functionality
zcert --version
zcert env
zcert search --help
```

## Production Security Checklist

- [ ] Environment variables configured securely
- [ ] Configuration files have 0600 permissions
- [ ] HAWK credentials are properly secured
- [ ] Network connectivity to CyberArk ZTPKI verified
- [ ] Shell completion installed for operational efficiency
- [ ] Logging configuration reviewed for sensitive data exposure
- [ ] Binary signature verification completed

## Operational Commands

### Certificate Operations
```bash
# Search for certificates
zcert search --filter "domain:example.com"

# Enroll new certificate
zcert enroll --cn "server.example.com" --profile production

# Retrieve existing certificate
zcert retrieve --thumbprint <thumbprint>

# Revoke certificate
zcert revoke --thumbprint <thumbprint> --reason superseded
```

### Administrative Tasks
```bash
# Environment validation
zcert env

# Configuration management
zcert config --profile production

# Help and documentation
zcert --help
zcert <command> --help
```

## Troubleshooting

### Common Issues
1. **HAWK Authentication Failures** - Verify ZTPKI_HAWK_ID and ZTPKI_HAWK_SECRET
2. **Network Connectivity** - Ensure access to CyberArk ZTPKI endpoints
3. **Permission Denied** - Check file permissions on configuration files
4. **Policy Validation** - Verify ZTPKI_POLICY_ID matches available policies

### Debug Mode
```bash
# Enable verbose output for troubleshooting
zcert --verbose search --filter "status:active"
```

## Support and Maintenance

### Version Information
```bash
zcert --version
```

### Log Analysis
- Configuration errors: Check file permissions and syntax
- Authentication issues: Verify HAWK credentials
- Network problems: Test connectivity to ZTPKI endpoints

For additional support, consult the CyberArk ZTPKI documentation and your organization's PKI administration team.
# ZCERT Production Deployment Guide

## Overview
This guide covers deploying the security-hardened zcert CLI tool for production environments with CyberArk Zero Touch PKI integration.

## Security Features
- HAWK authentication with secure nonce generation
- Protected configuration file handling (0600 permissions)
- No sensitive data exposure in logs or debug output
- Input validation and sanitization throughout

## Production Deployment Steps

### 1. Binary Installation

#### Linux/macOS
```bash
# Download the appropriate binary for your platform
wget https://github.com/your-org/zcert/releases/latest/download/zcert-linux-amd64.tar.gz

# Extract and install (binary is named "zcert")
tar -xzf zcert-linux-amd64.tar.gz
sudo mv zcert /usr/local/bin/
sudo chmod +x /usr/local/bin/zcert
```

#### Windows
```powershell
# Download and extract the Windows binary
# Binary is named "zcert.exe"
Invoke-WebRequest -Uri "https://github.com/your-org/zcert/releases/latest/download/zcert-windows-amd64.zip" -OutFile "zcert.zip"
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

### 3. Environment Configuration

#### Required Environment Variables
```bash
# HAWK Authentication
export ZTPKI_HAWK_ID="your-hawk-id"
export ZTPKI_HAWK_SECRET="your-hawk-secret"

# Policy Configuration
export ZTPKI_POLICY_ID="your-policy-id"
```

### 4. Shell Completion Setup
```bash
# Install bash completion
zcert completion --shell bash > zcert-completion.bash
sudo cp zcert-completion.bash /etc/bash_completion.d/zcert

# For other shells
zcert completion --help
```

### 5. Verification
```bash
# Test basic functionality
zcert --version
zcert env --test
zcert search --policies
```

## Production Security Checklist

- [ ] Environment variables configured securely
- [ ] Configuration files have 0600 permissions
- [ ] HAWK credentials are properly secured
- [ ] Network connectivity to CyberArk ZTPKI verified
- [ ] Shell completion installed for operational efficiency
- [ ] Logging configuration reviewed for sensitive data exposure

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

For additional support, consult the main README.md file and your organization's PKI administration team.
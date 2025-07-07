# ZCERT v1.0.0 - Release Notes

## Overview
ZCERT v1.0.0 is a production-ready, security-hardened CLI tool for CyberArk Zero Touch PKI certificate management.

## Security Enhancements
- HAWK Authentication with secure nonce generation
- Automatic 0600 permissions for configuration files containing secrets
- Zero sensitive data exposure in logs or console output
- Comprehensive input validation and sanitization

## New Features

### Certificate Operations
- Certificate Enrollment with policy selection and CSR generation
- Certificate Retrieval with flexible search capabilities
- Advanced Certificate Search with filtering options
- Certificate Revocation with confirmation prompts

### Environment Management
- Environment Setup Command (`zcert env`)
- Multi-Profile Support for different ZTPKI environments
- Automated configuration file generation

### Shell Integration
- Native bash, zsh, fish, and PowerShell completion
- Interactive user prompts for certificate operations
- Detailed operational logging for troubleshooting

## Platform Support
- Linux AMD64
- macOS Intel (AMD64)
- macOS Apple Silicon (ARM64)
- Windows AMD64

## Configuration

### Environment Variables
```bash
export ZTPKI_HAWK_ID="your-hawk-id"
export ZTPKI_HAWK_SECRET="your-hawk-secret"
export ZTPKI_POLICY_ID="your-policy-id"
```

### Configuration File
```bash
# Generate secure configuration
zcert config --cnf
```

## Known Issues
- ARM64 Linux builds require manual compilation
- Certificate renewal depends on ZTPKI policy configuration
- Large certificate searches may timeout (use --limit flag)

## Upcoming Features
- Certificate renewal automation
- Enhanced bulk certificate operations
- Policy template management
- Integration with CI/CD pipelines

## Support
- See [README.md](README.md) for usage examples
- See [DEPLOYMENT.md](DEPLOYMENT.md) for deployment instructions
- Use `zcert --verbose` for detailed logging and troubleshooting

---

**ZCERT v1.0.0** - Production-ready certificate management for CyberArk Zero Touch PKI.
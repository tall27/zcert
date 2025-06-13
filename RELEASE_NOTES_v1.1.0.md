# ZCERT v1.1.0 - Enhanced Key Size Support Release

## Release Overview

ZCERT v1.1.0 introduces enhanced RSA key size support, improved configuration validation, and comprehensive testing enhancements. This release builds upon the solid foundation of v1.0.0 with additional cryptographic flexibility and robustness.

## 🔒 Security Enhancements

### Enhanced Cryptographic Support
- **3072-bit RSA Key Support**: Full support for 3072-bit RSA keys in addition to existing 2048 and 4096-bit support
- **Improved Key Size Validation**: Comprehensive validation ensures only secure key sizes (2048, 3072, 4096) are accepted
- **Configuration Security**: Enhanced profile-based key size management with secure defaults

## ✨ New Features

### Enhanced Certificate Generation
- **Flexible Key Sizes**: Support for 2048, 3072, and 4096-bit RSA keys
- **Configuration-Driven Key Selection**: Key size automatically inherited from profile configuration
- **Command-Line Override**: Ability to override profile key size via --key-size flag
- **Comprehensive Validation**: Real-time validation of key generation parameters

### Improved Configuration Management
- **Profile-Based Key Configuration**: Set key-size in configuration profiles
- **Automatic Profile Selection**: Intelligent default profile selection when none specified
- **Enhanced Configuration Validation**: Comprehensive testing of all configuration options
- **Backward Compatibility**: Full compatibility with existing v1.0.0 configurations

### Testing Infrastructure
- **Enhanced Test Suite**: Added 3072-bit RSA key generation tests
- **Configuration Validation Tests**: Comprehensive testing of all 44 configuration options
- **Key Size Validation Tests**: Automated testing of all supported RSA key sizes
- **Cross-Platform Test Coverage**: Verified functionality across all supported platforms

## 🚀 Technical Improvements

### Certificate Operations
- **CSR Generation Enhancement**: Improved certificate signing request generation with flexible key sizes
- **Private Key Management**: Enhanced private key generation with size validation
- **API Integration**: Seamless integration with ZTPKI API for all supported key sizes

### Code Quality
- **Test Coverage**: Comprehensive test coverage for new features
- **Error Handling**: Improved error messages for key size validation
- **Performance**: Optimized key generation performance for larger key sizes
- **Documentation**: Updated help text and examples for new key size options

## 📦 Configuration Updates

### Default Configuration Changes
```ini
[Default]
# Enhanced security with 3072-bit RSA keys
key-size = 3072
key-type = rsa
# ... other settings remain unchanged
```

### Command-Line Examples
```bash
# Use 3072-bit keys from configuration
zcert enroll --cn "server.example.com"

# Override with 4096-bit keys
zcert enroll --cn "secure.example.com" --key-size 4096

# Profile-specific key sizes
zcert --profile production enroll --cn "prod.example.com"
```

## 🔧 Migration Guide

### From v1.0.0
1. **Automatic Migration**: No action required - all v1.0.0 configurations remain compatible
2. **Optional Enhancement**: Update configuration files to specify preferred key sizes
3. **Testing**: Verify operations with `zcert --version` and basic certificate operations

### Configuration Updates
```bash
# Update existing configuration to use 3072-bit keys
# Edit zcert.cnf and set: key-size = 3072

# Or generate new configuration with enhanced defaults
zcert config --cnf
```

## 📋 Validation Results

### Test Suite Status
- ✅ All 6 test files passing
- ✅ 44/44 configuration options validated
- ✅ 3072-bit RSA key generation tested and verified
- ✅ Cross-platform compatibility confirmed
- ✅ API integration tests successful

### Supported Key Sizes
- ✅ RSA 2048-bit: Standard security, faster generation
- ✅ RSA 3072-bit: Enhanced security, balanced performance (new default)
- ✅ RSA 4096-bit: Maximum security, slower generation

## 🛠 Installation

### Binary Downloads
```bash
# Download v1.1.0 binaries (replace URLs with actual GitHub release URLs)
wget https://github.com/your-org/zcert/releases/download/v1.1.0/zcert-1.1.0-linux-amd64.tar.gz
tar -xzf zcert-1.1.0-linux-amd64.tar.gz
sudo mv zcert /usr/local/bin/
```

### Upgrade from v1.0.0
```bash
# Simple binary replacement - no configuration changes required
sudo wget -O /usr/local/bin/zcert https://github.com/your-org/zcert/releases/download/v1.1.0/zcert-1.1.0-linux-amd64
sudo chmod +x /usr/local/bin/zcert
zcert --version  # Verify upgrade
```

## 🔮 Future Enhancements

### Planned for v1.2.0
- ECDSA key support (P-256, P-384, P-521)
- Certificate renewal automation
- Bulk certificate operations
- Enhanced search filtering

### Long-term Roadmap
- Hardware Security Module (HSM) integration
- Certificate lifecycle automation
- Policy template management
- CI/CD pipeline integration

## 🐛 Bug Fixes

### Resolved Issues
- Fixed profile selection to prioritize "Default" profile correctly
- Improved configuration file parsing for key-size parameters
- Enhanced error messages for invalid key size specifications
- Corrected help text alignment for flag descriptions

## 📖 Documentation Updates

### Updated Examples
- Added 3072-bit key generation examples
- Updated configuration file templates
- Enhanced command-line usage documentation
- Improved troubleshooting guides

## 🆘 Support

### Getting Help
```bash
# Check version and build info
zcert --version

# Comprehensive help
zcert --help

# Command-specific help
zcert enroll --help

# Environment setup guidance
zcert env
```

### Troubleshooting
- Use `zcert --verbose` for detailed operation logging
- Verify key size configuration with `zcert config --show`
- Check connectivity with `zcert search --limit 1`

## 🙏 Acknowledgments

This release incorporates valuable feedback from security teams requiring enhanced RSA key size flexibility while maintaining the robust security and usability of the original v1.0.0 release.

---

**ZCERT v1.1.0** - Enhanced security through flexible RSA key size support for enterprise certificate management.
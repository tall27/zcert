# Windows PQC Setup Guide

This guide helps you set up Post-Quantum Cryptography (PQC) support for zcert on Windows.

## Prerequisites

### 1. OpenSSL 3.5+ with PQC Support

**Option A: Pre-compiled Binaries (Recommended)**
```bash
# Download from https://wiki.openssl.org/index.php/Binaries
# Install to: C:\Program Files\OpenSSL-Win64\
```

**Option B: Build from Source**
```bash
# Requires Visual Studio Build Tools
git clone https://github.com/openssl/openssl.git
cd openssl
git checkout openssl-3.5
perl Configure VC-WIN64A
nmake
nmake install
```

### 2. Post-Quantum Cryptography Provider (oqsprovider)

**Download oqsprovider.dll**
```bash
# From: https://github.com/open-quantum-safe/oqs-provider/releases
# Place in: C:\Program Files\OpenSSL-Win64\lib\ossl-modules\
```

**Required DLLs:**
- `oqsprovider.dll` - Main PQC provider
- `liboqs.dll` - OQS library (may be bundled)

### 3. Visual C++ Redistributable

Install Microsoft Visual C++ Redistributable (x64) from:
https://aka.ms/vs/17/release/vc_redist.x64.exe

## Environment Setup

### 1. Add OpenSSL to PATH

**Option A: System Environment Variables**
```cmd
# Add to System PATH:
C:\Program Files\OpenSSL-Win64\bin
```

**Option B: PowerShell Session**
```powershell
$env:PATH += ";C:\Program Files\OpenSSL-Win64\bin"
```

### 2. Set OpenSSL Module Path

```cmd
# Command Prompt
set OPENSSL_MODULES=C:\Program Files\OpenSSL-Win64\lib\ossl-modules

# PowerShell
$env:OPENSSL_MODULES = "C:\Program Files\OpenSSL-Win64\lib\ossl-modules"
```

### 3. Verify Installation

```bash
# Test OpenSSL
openssl version -a

# Test PQC provider
openssl list -providers

# Should show 'oqsprovider' in the output
```

## zcert Configuration

### 1. Create Windows PQC Profile

Create `zcert.cnf`:
```ini
[Default]
url = https://your-ztpki-instance.com/api/v2
hawk-id = your-hawk-id
hawk-api = your-hawk-secret
policy = your-policy-id

[pqc]
url = https://your-ztpki-instance.com/api/v2
hawk-id = your-hawk-id
hawk-api = your-hawk-secret
policy = your-policy-id
pqc-algorithm = MLDSA44
openssl-path = C:\Program Files\OpenSSL-Win64\bin\openssl.exe
temp-dir = C:\temp\zcert-pqc
cleanup = false
verbose = true
```

### 2. Test PQC Command

```bash
# Basic test
zcert pqc --cn test.local

# Verbose test
zcert pqc --cn test.local --verbose

# Manual credentials test
zcert pqc --cn test.local --url https://ztpki-staging.venafi.com/api/v2 --hawk-id your-id --hawk-key your-key --policy your-policy
```

## Troubleshooting

### Common Issues

#### 1. "OpenSSL not found"
```bash
# Check PATH
echo $env:PATH | Select-String "OpenSSL"

# Test direct path
"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" version
```

#### 2. "Provider not available"
```bash
# Check provider path
dir "C:\Program Files\OpenSSL-Win64\lib\ossl-modules\"

# Test provider loading
openssl list -providers -provider oqsprovider
```

#### 3. "DLL load failed"
```bash
# Install Visual C++ Redistributable
# Check DLL dependencies with Dependency Walker
```

#### 4. "Access denied" / Permission errors
```bash
# Run PowerShell as Administrator
# Or use user-writable temp directory
```

### Diagnostic Command

```bash
# Get detailed Windows diagnostics
zcert pqc --help

# Manual diagnostic (if implemented)
zcert diagnose --pqc --windows
```

### Manual Provider Test

```bash
# Create test config
echo 'openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module_path = C:/Program Files/OpenSSL-Win64/lib/ossl-modules/oqsprovider.dll' > test-openssl.conf

# Test PQC key generation
openssl genpkey -config test-openssl.conf -algorithm dilithium2 -out test.key

# Test CSR creation
openssl req -new -config test-openssl.conf -key test.key -out test.csr -subj "/CN=test"
```

## Performance Notes

- PQC operations are computationally intensive
- Key generation may take 5-30 seconds
- Certificate requests may take 30-60 seconds
- Use `--verbose` to monitor progress

## Security Considerations

- Store private keys securely
- Use key passwords for sensitive certificates
- Clean up temporary files (or use `--cleanup` flag)
- Validate certificate chains properly

## Alternative Algorithms

Supported PQC algorithms:
- `MLDSA44` (Default, fastest)
- `MLDSA65` (Medium security)
- `MLDSA87` (Highest security)
- `Dilithium2` (Legacy name for MLDSA44)
- `Dilithium3` (Legacy name for MLDSA65)
- `Dilithium5` (Legacy name for MLDSA87)

Example:
```bash
zcert pqc --cn test.local --pqc-algorithm MLDSA65
```

## Support

For Windows-specific issues:
1. Check this setup guide
2. Verify OpenSSL and provider installation
3. Test with manual OpenSSL commands
4. Report issues with diagnostic output
5. Include Windows version and architecture
# Windows PQC Troubleshooting Guide

This guide addresses common issues when running `zcert pqc --cn cert.local` on Windows after compilation.

## Quick Diagnosis

Run this command to get detailed Windows diagnostics:
```bash
zcert pqc --cn test.local --verbose
```

## Common Issues and Solutions

### 1. "OpenSSL not found" or "openssl: command not found"

**Symptoms:**
- Command fails immediately
- Error about missing OpenSSL executable

**Solutions:**

**Option A: Install OpenSSL with PQC Support**
```bash
# Download from: https://wiki.openssl.org/index.php/Binaries
# Install to: C:\Program Files\OpenSSL-Win64\
# Add to PATH: C:\Program Files\OpenSSL-Win64\bin
```

**Option B: Use Portable OpenSSL**
```bash
# Download portable version
# Extract to: C:\tools\openssl\
# Use with --openssl-path flag:
zcert pqc --cn cert.local --openssl-path "C:\tools\openssl\bin\openssl.exe"
```

**Option C: Manual PATH Setup**
```cmd
# Command Prompt
set PATH=%PATH%;C:\Program Files\OpenSSL-Win64\bin

# PowerShell
$env:PATH += ";C:\Program Files\OpenSSL-Win64\bin"
```

### 2. "Provider not available" or PQC Algorithm Errors

**Symptoms:**
- OpenSSL found but PQC algorithms fail
- "unknown algorithm" errors
- Key generation fails

**Root Cause:** Missing oqsprovider.dll

**Solutions:**

**Step 1: Download oqsprovider.dll**
```bash
# From: https://github.com/open-quantum-safe/oqs-provider/releases
# Download: oqsprovider-x.x.x-Windows.zip
```

**Step 2: Install Provider**
```bash
# Copy to OpenSSL modules directory:
copy oqsprovider.dll "C:\Program Files\OpenSSL-Win64\lib\ossl-modules\"
copy liboqs.dll "C:\Program Files\OpenSSL-Win64\lib\ossl-modules\"
```

**Step 3: Set Environment Variable**
```cmd
# Command Prompt
set OPENSSL_MODULES=C:\Program Files\OpenSSL-Win64\lib\ossl-modules

# PowerShell
$env:OPENSSL_MODULES = "C:\Program Files\OpenSSL-Win64\lib\ossl-modules"
```

**Step 4: Test Provider**
```bash
openssl list -providers
# Should show 'oqsprovider' in output
```

### 3. "DLL load failed" or "The specified module could not be found"

**Symptoms:**
- OpenSSL and provider files exist
- DLL loading errors at runtime

**Root Cause:** Missing Visual C++ Runtime

**Solution:**
```bash
# Install Microsoft Visual C++ Redistributable (x64)
# Download from: https://aka.ms/vs/17/release/vc_redist.x64.exe
# Run installer as Administrator
```

### 4. "Access denied" or Permission Errors

**Symptoms:**
- Temporary file creation fails
- Cannot write to default temp directory

**Solutions:**

**Option A: Run as Administrator**
```bash
# Right-click Command Prompt/PowerShell
# Select "Run as Administrator"
```

**Option B: Use Custom Temp Directory**
```bash
zcert pqc --cn cert.local --temp-dir "C:\temp\zcert"
```

**Option C: Create User Temp Directory**
```bash
mkdir %USERPROFILE%\zcert-temp
zcert pqc --cn cert.local --temp-dir "%USERPROFILE%\zcert-temp"
```

### 5. Certificate Issuance Fails (Backend Errors)

**Symptoms:**
- CSR submitted successfully
- Certificate issuance returns "FAILED"

**Diagnosis:**
```bash
# Test with verbose output to see full backend response
zcert pqc --cn cert.local --url https://your-ztpki.com/api/v2 --hawk-id your-id --hawk-key your-key --policy your-policy -vv
```

**Common Causes:**
- Invalid policy ID for PQC certificates
- Backend doesn't support PQC algorithms
- Authentication credentials expired
- Certificate subject conflicts with policy restrictions

**Solutions:**
- Verify policy supports PQC algorithms
- Test with different credentials/environment
- Contact ZTPKI administrator for policy configuration

## Environment Verification Checklist

### ✅ OpenSSL Installation
```bash
# Test OpenSSL version (should be 3.5+)
openssl version -a

# Test algorithm availability
openssl list -signature-algorithms | findstr -i dilithium
openssl list -signature-algorithms | findstr -i mldsa
```

### ✅ Provider Installation  
```bash
# Check provider files exist
dir "C:\Program Files\OpenSSL-Win64\lib\ossl-modules\oqsprovider.dll"
dir "C:\Program Files\OpenSSL-Win64\lib\ossl-modules\liboqs.dll"

# Test provider loading
openssl list -providers -provider oqsprovider
```

### ✅ Environment Variables
```bash
# Check PATH includes OpenSSL
echo %PATH% | findstr -i openssl

# Check modules path (optional)
echo %OPENSSL_MODULES%
```

### ✅ File Permissions
```bash
# Test temp directory access
echo test > %TEMP%\zcert-test.tmp
del %TEMP%\zcert-test.tmp
```

## Manual PQC Test

If zcert still fails, test OpenSSL directly:

```bash
# Create test OpenSSL config
echo openssl_conf = openssl_init > test.conf
echo. >> test.conf
echo [openssl_init] >> test.conf
echo providers = provider_sect >> test.conf
echo. >> test.conf
echo [provider_sect] >> test.conf
echo default = default_sect >> test.conf
echo oqsprovider = oqsprovider_sect >> test.conf
echo. >> test.conf
echo [default_sect] >> test.conf
echo activate = 1 >> test.conf
echo. >> test.conf
echo [oqsprovider_sect] >> test.conf
echo activate = 1 >> test.conf

# Test key generation
openssl genpkey -config test.conf -algorithm dilithium2 -out test.key

# Test CSR creation
openssl req -new -config test.conf -key test.key -out test.csr -subj "/CN=test"

# If these work, the issue is with zcert configuration
```

## Performance Considerations

- **Key Generation Time:** 5-30 seconds (normal for PQC)
- **CSR Creation Time:** 10-60 seconds
- **Certificate Request:** Depends on backend processing

Use `--verbose` to monitor progress during long operations.

## Alternative Solutions

### Use Different Algorithm
```bash
# Try faster algorithm
zcert pqc --cn cert.local --pqc-algorithm MLDSA44

# Try legacy name
zcert pqc --cn cert.local --pqc-algorithm Dilithium2
```

### Use Pre-built Environment
```bash
# Use Docker with pre-configured OpenSSL
docker run -it --rm ubuntu:22.04 bash
apt update && apt install -y openssl libssl3 wget
# Install zcert and run commands inside container
```

### Use WSL (Windows Subsystem for Linux)
```bash
# Install WSL with Ubuntu
wsl --install Ubuntu

# In WSL, install OpenSSL and zcert Linux version
sudo apt update
sudo apt install -y openssl
# Use zcert Linux binary instead of Windows compilation
```

## Advanced Troubleshooting

### Enable OpenSSL Debug Logging
```bash
set OPENSSL_TRACE=all
zcert pqc --cn cert.local --verbose
```

### Check DLL Dependencies
Use Dependency Walker (depends.exe) to verify all required DLLs are available.

### Provider Configuration File
Create custom provider configuration:
```bash
# Create custom openssl.cnf
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module_path = C:/Program Files/OpenSSL-Win64/lib/ossl-modules/oqsprovider.dll

# Use with:
set OPENSSL_CONF=C:\path\to\openssl.cnf
```

## Getting Help

1. **Check Windows Setup Guide:** `WINDOWS_PQC_SETUP.md`
2. **Run Diagnostics:** `zcert pqc --cn test.local --verbose`
3. **Test Manual OpenSSL:** Follow manual test steps above
4. **Report Issues:** Include diagnostic output and system information

## System Information Template

When reporting issues, include:

```bash
# Windows version
ver

# OpenSSL version
openssl version -a

# Provider status
openssl list -providers

# zcert version
zcert version

# Environment variables
echo %PATH%
echo %OPENSSL_MODULES%
echo %TEMP%

# File existence
dir "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
dir "C:\Program Files\OpenSSL-Win64\lib\ossl-modules\oqsprovider.dll"
```
# zcert - Zero Touch PKI Certificate Management CLI

A command-line certificate management tool for Venafi's Zero Touch PKI (ZTPKI) service, designed to mirror the functionality and user experience of vcert but tailored specifically for the ZTPKI platform.

## Overview

zcert provides a comprehensive set of certificate lifecycle operations including enrollment, retrieval, revocation, and management through the ZTPKI REST API. The tool uses HAWK authentication and supports multiple output formats for maximum flexibility.

## Features

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
git clone <repository-url>
cd zcert

# Build the executable
go build -o zcert main.go

# For Windows
go build -o zcert.exe main.go

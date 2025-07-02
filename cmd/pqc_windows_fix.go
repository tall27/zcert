package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// WindowsPQCConfig holds Windows-specific PQC configuration
type WindowsPQCConfig struct {
	OpenSSLPath     string
	ProviderPath    string
	TempDir         string
	UseSystemPath   bool
	RequiredDLLs    []string
}

// ValidateWindowsOpenSSLPath validates an explicitly provided OpenSSL path
func ValidateWindowsOpenSSLPath(opensslPath string) error {
	if runtime.GOOS != "windows" {
		return nil // Skip validation on non-Windows systems
	}

	// On Windows, OpenSSL path MUST be explicitly provided via CLI or config file
	if opensslPath == "" || opensslPath == "openssl" {
		return fmt.Errorf(`OpenSSL path must be explicitly specified on Windows.

Use one of these options:
1. CLI flag: --openssl-path "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
2. Config file: Set openssl-path in your zcert.cnf profile

Example:
  zcert pqc --cn cert.local --openssl-path "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

For setup instructions, see: WINDOWS_PQC_SETUP.md`)
	}

	// Validate the executable exists and is accessible
	if _, err := os.Stat(opensslPath); err != nil {
		return fmt.Errorf("OpenSSL executable not found at specified path: %s\n\nVerify the path is correct and the file exists.", opensslPath)
	}

	return nil
}

// ValidateWindowsPQCEnvironment checks if all required components are available
func ValidateWindowsPQCEnvironment(config *WindowsPQCConfig) []string {
	var issues []string

	// Check OpenSSL executable
	if config.OpenSSLPath == "" {
		issues = append(issues, "OpenSSL executable not found")
	} else {
		if _, err := os.Stat(config.OpenSSLPath); err != nil {
			issues = append(issues, fmt.Sprintf("OpenSSL executable not accessible: %s", config.OpenSSLPath))
		}
	}

	// Check for PQC provider DLLs if provider path is known
	if config.ProviderPath != "" {
		for _, dll := range config.RequiredDLLs {
			dllPath := filepath.Join(config.ProviderPath, dll)
			if _, err := os.Stat(dllPath); err != nil {
				issues = append(issues, fmt.Sprintf("Required DLL not found: %s", dllPath))
			}
		}
	}

	// Check temporary directory permissions
	testFile := filepath.Join(config.TempDir, "test.tmp")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		issues = append(issues, fmt.Sprintf("Cannot write to temporary directory: %s", config.TempDir))
	} else {
		os.Remove(testFile) // Clean up
	}

	return issues
}

// GetWindowsPQCDiagnostics provides detailed Windows PQC diagnostic information
func GetWindowsPQCDiagnostics() string {
	if runtime.GOOS != "windows" {
		return "Not running on Windows"
	}

	var diagnostics strings.Builder
	
	diagnostics.WriteString("=== Windows PQC Diagnostics ===\n")
	diagnostics.WriteString(fmt.Sprintf("OS: %s\n", runtime.GOOS))
	diagnostics.WriteString(fmt.Sprintf("Arch: %s\n", runtime.GOARCH))
	
	diagnostics.WriteString("\nRequired Configuration:\n")
	diagnostics.WriteString("- OpenSSL path must be specified via --openssl-path flag or config file\n")
	diagnostics.WriteString("- Example: --openssl-path \"C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe\"\n")
	
	diagnostics.WriteString("\nRecommended Installation:\n")
	diagnostics.WriteString("1. Install OpenSSL 3.5+ from https://wiki.openssl.org/index.php/Binaries\n")
	diagnostics.WriteString("2. Install oqsprovider.dll in OpenSSL modules directory\n")
	diagnostics.WriteString("3. Install Visual C++ Redistributable (x64)\n")
	diagnostics.WriteString("4. Specify explicit OpenSSL path in zcert configuration\n")
	
	// Environment variables
	diagnostics.WriteString("\nEnvironment Variables:\n")
	envVars := []string{"PATH", "OPENSSL_MODULES", "OPENSSL_CONF"}
	for _, envVar := range envVars {
		value := os.Getenv(envVar)
		if value != "" {
			diagnostics.WriteString(fmt.Sprintf("%s: %s\n", envVar, value))
		} else {
			diagnostics.WriteString(fmt.Sprintf("%s: (not set)\n", envVar))
		}
	}
	
	return diagnostics.String()
}

// NormalizeWindowsPath converts Windows paths to use forward slashes for OpenSSL
func NormalizeWindowsPath(path string) string {
	if runtime.GOOS == "windows" {
		// OpenSSL on Windows can handle forward slashes better in config files
		return strings.ReplaceAll(path, "\\", "/")
	}
	return path
}

// CreateWindowsOpenSSLConfig generates Windows-compatible OpenSSL configuration
func CreateWindowsOpenSSLConfig(tempDir, providerPath string) string {
	config := fmt.Sprintf(`# OpenSSL Configuration for Windows PQC
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
%s

[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
`, func() string {
		if providerPath != "" {
			normalizedPath := NormalizeWindowsPath(providerPath)
			return fmt.Sprintf("module_path = %s/oqsprovider.dll", normalizedPath)
		}
		return "# Provider path auto-detected"
	}())

	return config
}

// WindowsPQCPreflightCheck performs basic Windows PQC environment validation
func WindowsPQCPreflightCheck(opensslPath string, verbose bool) error {
	if runtime.GOOS != "windows" {
		return nil // Skip on non-Windows systems
	}

	if verbose {
		fmt.Print(GetWindowsPQCDiagnostics())
	}

	// Only validate explicitly provided OpenSSL path
	if err := ValidateWindowsOpenSSLPath(opensslPath); err != nil {
		return fmt.Errorf("Windows PQC preflight check failed: %w\n\nFor Windows setup instructions, see: WINDOWS_PQC_SETUP.md", err)
	}

	return nil
}
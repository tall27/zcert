package cert

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// A map of supported legacy PQC algorithms for case-insensitive lookup.
// The key is the uppercase name, and the value is the canonical lowercase name for OpenSSL.
var supportedLegacyAlgorithms = map[string]string{
	"DILITHIUM2": "dilithium2",
	"DILITHIUM3": "dilithium3",
	"DILITHIUM5": "dilithium5",
	"MLDSA44":    "mldsa44", // ML-DSA-44 (NIST OID 2.16.840.1.101.3.4.3.17)
	"MLDSA65":    "mldsa65", // ML-DSA-65 (NIST OID 2.16.840.1.101.3.4.3.18)
	"MLDSA87":    "mldsa87", // ML-DSA-87 (NIST OID 2.16.840.1.101.3.4.3.19)
	"FALCON512":  "falcon512",
	"FALCON1024": "falcon1024",
	"SLHDSA128F": "sphincssha2128fsimple",
	"SLHDSA192F": "sphincssha2192fsimple",
}

// A map of supported modern PQC algorithms for case-insensitive lookup.
var supportedModernAlgorithms = map[string]bool{
	"MLDSA44":    true,
	"MLDSA65":    true,
	"MLDSA87":    true,
	"SLHDSA128F": true,
	"SLHDSA192F": true,
}

// PQCAlgorithm represents a supported PQC algorithm
type PQCAlgorithm string

const (
	// ML-DSA variants
	MLDSA44  PQCAlgorithm = "MLDSA44"
	MLDSA65  PQCAlgorithm = "MLDSA65"
	MLDSA87  PQCAlgorithm = "MLDSA87"
	// SLH-DSA variants
	SLHDSA128F PQCAlgorithm = "SLHDSA128F"
	SLHDSA192F PQCAlgorithm = "SLHDSA192F"
	// Kyber variants
	Kyber512 PQCAlgorithm = "Kyber512"
	Kyber768 PQCAlgorithm = "Kyber768"
	Kyber1024 PQCAlgorithm = "Kyber1024"
	// Falcon variants
	Falcon512 PQCAlgorithm = "Falcon512"
	Falcon1024 PQCAlgorithm = "Falcon1024"
	// Dilithium variants (legacy names)
	Dilithium2 PQCAlgorithm = "Dilithium2"
	Dilithium3 PQCAlgorithm = "Dilithium3"
	Dilithium5 PQCAlgorithm = "Dilithium5"
)

// PQCGenerator handles PQC certificate generation
type PQCGenerator struct {
	OpenSSLPath    string
	TempDir        string
	Verbose        bool
	NoCleanup      bool
	LegacyAlgNames bool
	LegacyPQCAlgorithm string
	ExtKeyUsage    []string
	CertPolicy     []string
	GeneratedFiles []string // Track files created by OpenSSL
	OpenSSLCleanup bool     // Controls cleanup of openssl.cnf file
}

// NewPQCGenerator creates a new PQC generator instance
func NewPQCGenerator(openSSLPath, tempDir string, verbose, noCleanup, legacyAlgNames bool, legacyPQCAlgorithm string) *PQCGenerator {
	return &PQCGenerator{
		OpenSSLPath:    openSSLPath,
		TempDir:        tempDir,
		Verbose:        verbose,
		NoCleanup:      noCleanup,
		LegacyAlgNames: legacyAlgNames,
		LegacyPQCAlgorithm: legacyPQCAlgorithm,
		GeneratedFiles: []string{},
		OpenSSLCleanup: true, // Default to true
	}
}

// SetOpenSSLCleanup sets the OpenSSL config file cleanup behavior
func (g *PQCGenerator) SetOpenSSLCleanup(cleanup bool) {
	g.OpenSSLCleanup = cleanup
}

// ValidateAlgorithm checks if the provided algorithm is supported
func (g *PQCGenerator) ValidateAlgorithm(alg string) error {
	upperAlg := strings.ToUpper(alg)
	if g.LegacyAlgNames {
		if _, ok := supportedLegacyAlgorithms[upperAlg]; ok {
			return nil
		}
	} else {
		if _, ok := supportedModernAlgorithms[upperAlg]; ok {
			return nil
		}
	}
	return fmt.Errorf("unsupported PQC algorithm: %s", alg)
}

// convertToLegacyAlgorithm converts a PQC algorithm name to its legacy OpenSSL name if legacy mode is enabled
func (g *PQCGenerator) convertToLegacyAlgorithm(algorithm string) string {
	if !g.LegacyAlgNames {
		if g.Verbose {
			fmt.Fprintf(os.Stderr, "DEBUG: Legacy algorithm names disabled, using original algorithm: %s\n", algorithm)
		}
		return algorithm
	}

	// Check if there's a specific legacy algorithm override
	if g.LegacyPQCAlgorithm != "" {
		if g.Verbose {
			fmt.Fprintf(os.Stderr, "DEBUG: Using legacy algorithm override: %s -> %s\n", algorithm, g.LegacyPQCAlgorithm)
		}
		return g.LegacyPQCAlgorithm
	}

	// Convert to uppercase for case-insensitive lookup
	upperAlg := strings.ToUpper(algorithm)

	// Look up in the supported legacy algorithms map
	if legacyAlg, exists := supportedLegacyAlgorithms[upperAlg]; exists {
		if g.Verbose {
			fmt.Fprintf(os.Stderr, "DEBUG: Found legacy algorithm mapping: %s -> %s\n", algorithm, legacyAlg)
		}
		return legacyAlg
	}

	// If not found, return the original algorithm (converted to lowercase for OpenSSL)
	lowerAlg := strings.ToLower(algorithm)
	if g.Verbose {
		fmt.Fprintf(os.Stderr, "DEBUG: No legacy mapping found, using lowercase: %s -> %s\n", algorithm, lowerAlg)
	}
	return lowerAlg
}

// Helper to determine if an algorithm is MLDSA (NIST standardized)
func isMLDSA(algorithm string) bool {
	switch strings.ToLower(algorithm) {
	case "mldsa44", "mldsa65", "mldsa87":
		return true
	default:
		return false
	}
}

// getMaskedArgs creates a copy of command arguments and masks any passwords.
func getMaskedArgs(args []string) []string {
	maskedArgs := make([]string, len(args))
	copy(maskedArgs, args)
	for i, arg := range maskedArgs {
		if (arg == "-passout" || arg == "-passin") && i+1 < len(maskedArgs) {
			if strings.HasPrefix(maskedArgs[i+1], "pass:") {
				maskedArgs[i+1] = "pass:*****"
			}
		}
	}
	return maskedArgs
}

// GenerateKey generates a PQC private key using OpenSSL
func (g *PQCGenerator) GenerateKey(algorithm string) (string, error) {
	if err := g.ValidateAlgorithm(algorithm); err != nil {
		return "", err
	}

	// Convert to legacy algorithm name if needed
	legacyAlgorithm := g.convertToLegacyAlgorithm(algorithm)
	keyFile := filepath.Join(g.TempDir, fmt.Sprintf("%s.key", strings.ToLower(algorithm)))

	var cmd *exec.Cmd

	// Provider selection based on algorithm
	if isMLDSA(legacyAlgorithm) {
		// Use only default provider for MLDSA
		args := []string{"genpkey",
			"-algorithm", legacyAlgorithm,
			"-provider", "default",
			"-provider-path", g.TempDir,
			"-out", keyFile}
		cmd = exec.Command(g.OpenSSLPath, args...)
	} else {
		// Use oqsprovider and default for all other PQC algorithms
		args := []string{"genpkey",
			"-algorithm", legacyAlgorithm,
			"-provider", "default",
			"-provider", "oqsprovider",
			"-provider-path", g.TempDir,
			"-out", keyFile}
		cmd = exec.Command(g.OpenSSLPath, args...)
	}

	// Set OPENSSL_MODULES environment variable to help OpenSSL find oqsprovider.dll
	cmd.Env = append(os.Environ(), "OPENSSL_MODULES="+g.TempDir)

	if g.Verbose {
		fmt.Printf("[zcert] OpenSSL command: %s\n", strings.Join(getMaskedArgs(cmd.Args), " "))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to generate PQC key: %w", err)
	}

	// Track the generated key file
	g.GeneratedFiles = append(g.GeneratedFiles, keyFile)

	return keyFile, nil
}

// GenerateCSR generates a CSR using the provided key and subject information
func (g *PQCGenerator) GenerateCSR(keyFile string, subject Subject, sans []string, password string) (string, error) {
	// Generate OpenSSL config
	configFile := filepath.Join(g.TempDir, "openssl.cnf")
	if err := g.generateOpenSSLConfig(configFile, subject, sans); err != nil {
		return "", err
	}

	csrFile := filepath.Join(g.TempDir, filepath.Base(keyFile[:len(keyFile)-4])+".csr")

	var cmd *exec.Cmd

	// Determine algorithm from key file name
	algo := strings.TrimSuffix(filepath.Base(keyFile), ".key")
	if isMLDSA(algo) {
		// Use only default provider for MLDSA
		args := []string{"req",
			"-new",
			"-key", keyFile,
			"-out", csrFile,
			"-config", configFile,
			"-provider", "default",
			"-provider-path", g.TempDir}
		if password != "" {
			args = append(args, "-passin", "pass:"+password)
		}
		cmd = exec.Command(g.OpenSSLPath, args...)
	} else {
		// Use oqsprovider and default for all other PQC algorithms
		args := []string{"req",
			"-new",
			"-key", keyFile,
			"-out", csrFile,
			"-config", configFile,
			"-provider", "default",
			"-provider", "oqsprovider",
			"-provider-path", g.TempDir}
		if password != "" {
			args = append(args, "-passin", "pass:"+password)
		}
		cmd = exec.Command(g.OpenSSLPath, args...)
	}

	// Set OPENSSL_MODULES environment variable to help OpenSSL find oqsprovider.dll
	cmd.Env = append(os.Environ(), "OPENSSL_MODULES="+g.TempDir)

	if g.Verbose {
		fmt.Printf("[zcert] OpenSSL command: %s\n", strings.Join(getMaskedArgs(cmd.Args), " "))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Track the generated CSR file
	g.GeneratedFiles = append(g.GeneratedFiles, csrFile)
	
	// Track the config file for cleanup if enabled
	if g.OpenSSLCleanup {
		g.GeneratedFiles = append(g.GeneratedFiles, configFile)
	}

	return csrFile, nil
}

// generateOpenSSLConfig generates the OpenSSL configuration file
func (g *PQCGenerator) generateOpenSSLConfig(configFile string, subject Subject, sans []string) error {
	// Determine if we have any SANs
	hasSANs := len(sans) > 0

	// Define the base config template
	baseConfig := `[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = %s
ST = %s
L = %s
O = %s
OU = %s
CN = %s

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation`

	// Add subjectAltName if SANs are present
	if hasSANs {
		baseConfig += "\nsubjectAltName = @alt_names"
	}

	// Add extendedKeyUsage if provided
	if g.ExtKeyUsage != nil && len(g.ExtKeyUsage) > 0 {
		baseConfig += "\nextendedKeyUsage = " + strings.Join(g.ExtKeyUsage, ", ")
	}

	// Add certificatePolicies if provided
	if g.CertPolicy != nil && len(g.CertPolicy) > 0 {
		baseConfig += "\ncertificatePolicies = " + strings.Join(g.CertPolicy, ", ")
	}

	// Format SAN entries if present
	var sanEntries []string
	if hasSANs {
		dnsCount := 1
		ipCount := 1
		emailCount := 1
		for _, san := range sans {
			if strings.Contains(san, "@") {
				sanEntries = append(sanEntries, fmt.Sprintf("email.%d = %s", emailCount, san))
				emailCount++
			} else if isIPAddress(san) {
				sanEntries = append(sanEntries, fmt.Sprintf("IP.%d = %s", ipCount, san))
				ipCount++
			} else {
				sanEntries = append(sanEntries, fmt.Sprintf("DNS.%d = %s", dnsCount, san))
				dnsCount++
			}
		}
	}

	// Build the final config content
	var configContent string
	if hasSANs {
		configContent = fmt.Sprintf(baseConfig+"\n\n[alt_names]\n%s",
			subject.Country,
			subject.Province,
			subject.Locality,
			subject.Organization,
			subject.OrganizationalUnit,
			subject.CommonName,
			strings.Join(sanEntries, "\n"),
		)
	} else {
		configContent = fmt.Sprintf(baseConfig,
			subject.Country,
			subject.Province,
			subject.Locality,
			subject.Organization,
			subject.OrganizationalUnit,
			subject.CommonName,
		)
	}

	return os.WriteFile(configFile, []byte(configContent), 0644)
}

// Cleanup removes temporary files unless NoCleanup is true
func (g *PQCGenerator) Cleanup(files ...string) {
	if g.NoCleanup {
		return
	}

	// Only remove files tracked as generated by OpenSSL
	for _, file := range g.GeneratedFiles {
		if file != "" {
			os.Remove(file)
		}
	}
}

// EncryptKey encrypts a PQC private key using OpenSSL pkcs8
func (g *PQCGenerator) EncryptKey(keyFile, password, outputFile string) error {
	args := []string{"pkcs8", 
		"-in", keyFile,
		"-topk8",
		"-out", outputFile,
		"-passout", "pass:"+password,
		"-provider-path", g.TempDir,
		"-provider", "default",
		"-provider", "oqsprovider"}
	
	cmd := exec.Command(g.OpenSSLPath, args...)

	// Set OPENSSL_MODULES environment variable to help OpenSSL find oqsprovider.dll
	cmd.Env = append(os.Environ(), "OPENSSL_MODULES="+g.TempDir)

	if g.Verbose {
		fmt.Printf("[zcert] OpenSSL encryption command: %s\n", strings.Join(getMaskedArgs(cmd.Args), " "))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to encrypt PQC key: %w", err)
	}

	return nil
}

// isIPAddress checks if a string is a valid IP address (IPv4 or IPv6)
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
} 
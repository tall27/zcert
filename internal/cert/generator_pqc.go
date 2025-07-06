package cert

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// AlgorithmInfo contains both the OpenSSL algorithm name and the appropriate OID
type AlgorithmInfo struct {
	OpenSSLName string
	OID         string
}

// A comprehensive map of supported PQC algorithms with both legacy and modern OIDs
var algorithmMappings = map[string]map[bool]AlgorithmInfo{
	// ML-DSA variants (NIST standardized)
	"MLDSA44": {
		true:  {OpenSSLName: "dilithium2", OID: "1.3.6.1.4.1.2.267.7.4.4"}, // Legacy OID for Dilithium2
		false: {OpenSSLName: "mldsa44", OID: "2.16.840.1.101.3.4.3.17"},    // NIST OID for ML-DSA-44
	},
	"MLDSA65": {
		true:  {OpenSSLName: "dilithium3", OID: "1.3.6.1.4.1.2.267.7.6.4"}, // Legacy OID for Dilithium3
		false: {OpenSSLName: "mldsa65", OID: "2.16.840.1.101.3.4.3.18"},    // NIST OID for ML-DSA-65
	},
	"MLDSA87": {
		true:  {OpenSSLName: "dilithium5", OID: "1.3.6.1.4.1.2.267.7.8.4"}, // Legacy OID for Dilithium5
		false: {OpenSSLName: "mldsa87", OID: "2.16.840.1.101.3.4.3.19"},    // NIST OID for ML-DSA-87
	},
	// Dilithium variants (legacy names)
	"DILITHIUM2": {
		true:  {OpenSSLName: "dilithium2", OID: "1.3.6.1.4.1.2.267.7.4.4"},
		false: {OpenSSLName: "dilithium2", OID: "1.3.6.1.4.1.2.267.7.4.4"}, // Same for legacy names
	},
	"DILITHIUM3": {
		true:  {OpenSSLName: "dilithium3", OID: "1.3.6.1.4.1.2.267.7.6.4"},
		false: {OpenSSLName: "dilithium3", OID: "1.3.6.1.4.1.2.267.7.6.4"}, // Same for legacy names
	},
	"DILITHIUM5": {
		true:  {OpenSSLName: "dilithium5", OID: "1.3.6.1.4.1.2.267.7.8.4"},
		false: {OpenSSLName: "dilithium5", OID: "1.3.6.1.4.1.2.267.7.8.4"}, // Same for legacy names
	},
	// SLH-DSA variants
	"SLHDSA128F": {
		true:  {OpenSSLName: "sphincssha2128fsimple", OID: "1.3.9999.6.4.13"}, // Legacy OID
		false: {OpenSSLName: "slhdsa128f", OID: "2.16.840.1.101.3.4.3.20"},    // NIST OID
	},
	"SLHDSA192F": {
		true:  {OpenSSLName: "sphincssha2192fsimple", OID: "1.3.9999.6.4.14"}, // Legacy OID
		false: {OpenSSLName: "slhdsa192f", OID: "2.16.840.1.101.3.4.3.21"},    // NIST OID
	},
	// Falcon variants
	"FALCON512": {
		true:  {OpenSSLName: "falcon512", OID: "1.3.9999.6.4.1"},
		false: {OpenSSLName: "falcon512", OID: "1.3.9999.6.4.1"}, // Same for Falcon
	},
	"FALCON1024": {
		true:  {OpenSSLName: "falcon1024", OID: "1.3.9999.6.4.2"},
		false: {OpenSSLName: "falcon1024", OID: "1.3.9999.6.4.2"}, // Same for Falcon
	},
}

// A map of supported legacy PQC algorithms for case-insensitive lookup.
// The key is the uppercase name, and the value is the canonical lowercase name for OpenSSL.
var supportedLegacyAlgorithms = map[string]string{
	"DILITHIUM2": "dilithium2",
	"DILITHIUM3": "dilithium3",
	"DILITHIUM5": "dilithium5",
	"MLDSA44":    "dilithium2", // ML-DSA-44 maps to Dilithium2 (legacy name)
	"MLDSA65":    "dilithium3", // ML-DSA-65 maps to Dilithium3 (legacy name)
	"MLDSA87":    "dilithium5", // ML-DSA-87 maps to Dilithium5 (legacy name)
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
	MLDSA44 PQCAlgorithm = "MLDSA44"
	MLDSA65 PQCAlgorithm = "MLDSA65"
	MLDSA87 PQCAlgorithm = "MLDSA87"
	// SLH-DSA variants
	SLHDSA128F PQCAlgorithm = "SLHDSA128F"
	SLHDSA192F PQCAlgorithm = "SLHDSA192F"
	// Kyber variants
	Kyber512  PQCAlgorithm = "Kyber512"
	Kyber768  PQCAlgorithm = "Kyber768"
	Kyber1024 PQCAlgorithm = "Kyber1024"
	// Falcon variants
	Falcon512  PQCAlgorithm = "Falcon512"
	Falcon1024 PQCAlgorithm = "Falcon1024"
	// Dilithium variants (legacy names)
	Dilithium2 PQCAlgorithm = "Dilithium2"
	Dilithium3 PQCAlgorithm = "Dilithium3"
	Dilithium5 PQCAlgorithm = "Dilithium5"
)

// PQCGenerator handles PQC certificate generation
type PQCGenerator struct {
	OpenSSLPath        string
	TempDir            string
	Verbose            bool
	NoCleanup          bool
	LegacyAlgNames     bool
	LegacyPQCAlgorithm string
	ExtKeyUsage        []string
	CertPolicy         []string
	GeneratedFiles     []string // Track files created by OpenSSL
	OpenSSLCleanup     bool     // Controls cleanup of openssl.cnf file
	ProviderPath       string   // Path to OpenSSL providers (for -provider-path)
}

// NewPQCGenerator creates a new PQC generator instance
func NewPQCGenerator(openSSLPath, tempDir string, verbose, noCleanup, legacyAlgNames bool, legacyPQCAlgorithm, providerPath string) *PQCGenerator {
	return &PQCGenerator{
		OpenSSLPath:        openSSLPath,
		TempDir:            tempDir,
		Verbose:            verbose,
		NoCleanup:          noCleanup,
		LegacyAlgNames:     legacyAlgNames,
		LegacyPQCAlgorithm: legacyPQCAlgorithm,
		GeneratedFiles:     []string{},
		OpenSSLCleanup:     true, // Default to true
		ProviderPath:       providerPath,
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

// getAlgorithmInfo returns the OpenSSL algorithm name and OID based on legacy setting
func (g *PQCGenerator) getAlgorithmInfo(algorithm string) AlgorithmInfo {
	upperAlg := strings.ToUpper(algorithm)

	// Check if there's a specific legacy algorithm override
	if g.LegacyPQCAlgorithm != "" {
		if g.Verbose {
			fmt.Fprintf(os.Stderr, "DEBUG: Using legacy algorithm override: %s -> %s\n", algorithm, g.LegacyPQCAlgorithm)
		}
		// For override, use the same OID as the original algorithm but with override name
		if info, exists := algorithmMappings[upperAlg]; exists {
			legacyInfo := info[g.LegacyAlgNames]
			return AlgorithmInfo{OpenSSLName: g.LegacyPQCAlgorithm, OID: legacyInfo.OID}
		}
		return AlgorithmInfo{OpenSSLName: g.LegacyPQCAlgorithm, OID: ""}
	}

	// Use comprehensive mapping
	if info, exists := algorithmMappings[upperAlg]; exists {
		algorithmInfo := info[g.LegacyAlgNames]
		if g.Verbose {
			fmt.Fprintf(os.Stderr, "DEBUG: Found algorithm mapping: %s -> %s (OID: %s, Legacy: %t)\n",
				algorithm, algorithmInfo.OpenSSLName, algorithmInfo.OID, g.LegacyAlgNames)
		}
		return algorithmInfo
	}

	// Fallback for backward compatibility
	if g.LegacyAlgNames {
		if legacyName, ok := supportedLegacyAlgorithms[upperAlg]; ok {
			return AlgorithmInfo{OpenSSLName: legacyName, OID: ""}
		}
	}

	// If not found, return the original algorithm (converted to lowercase for OpenSSL)
	lowerAlg := strings.ToLower(algorithm)
	if g.Verbose {
		fmt.Fprintf(os.Stderr, "DEBUG: No mapping found, using lowercase: %s -> %s\n", algorithm, lowerAlg)
	}
	return AlgorithmInfo{OpenSSLName: lowerAlg, OID: ""}
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

// Helper to determine if an algorithm is MLDSA (NIST standardized) - only the original names, not legacy dilithium names
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
	csrFile := filepath.Join(g.TempDir, filepath.Base(keyFile[:len(keyFile)-4])+".csr")

	// Generate OpenSSL config file in TempDir for proper cleanup
	configFile := filepath.Join(g.TempDir, "openssl.cnf")
	err := g.generateOpenSSLConfig(configFile, subject, sans)
	if err != nil {
		return "", fmt.Errorf("failed to generate OpenSSL config: %w", err)
	}

	var cmd *exec.Cmd

	// Determine algorithm from key file name (for backward compatibility)
	algo := strings.TrimSuffix(filepath.Base(keyFile), ".key")

	// If we have a legacy algorithm mapping, use the mapped algorithm for provider selection
	if g.LegacyAlgNames {
		if mappedAlgo := g.convertToLegacyAlgorithm(algo); mappedAlgo != algo {
			algo = mappedAlgo
		}
	}

	if isMLDSA(algo) {
		// Use only default provider for MLDSA
		args := []string{"req",
			"-new",
			"-key", keyFile,
			"-out", csrFile,
			"-config", configFile,
			"-reqexts", "v3_req",
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
			"-reqexts", "v3_req",
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

	return csrFile, nil
}

// Cleanup removes temporary files unless NoCleanup is true
func (g *PQCGenerator) Cleanup(files ...string) {
	if g.NoCleanup {
		return
	}

	fmt.Println("[zcert] DEBUG: Cleanup called. Files to delete:")
	for _, file := range g.GeneratedFiles {
		fmt.Printf("  - %s\n", file)
	}

	// Only remove files tracked as generated by OpenSSL
	for _, file := range g.GeneratedFiles {
		if file != "" {
			// Check if file exists before trying to delete
			if _, err := os.Stat(file); os.IsNotExist(err) {
				fmt.Printf("[zcert] DEBUG: File %s does not exist\n", file)
				continue
			}

			err := os.Remove(file)
			if err != nil {
				fmt.Printf("[zcert] DEBUG: Failed to delete %s: %v\n", file, err)
				// Try to get more details about the error
				if pathErr, ok := err.(*os.PathError); ok {
					fmt.Printf("[zcert] DEBUG: Path error details - Op: %s, Path: %s, Err: %v\n", pathErr.Op, pathErr.Path, pathErr.Err)
				}
			} else {
				fmt.Printf("[zcert] DEBUG: Successfully deleted %s\n", file)
			}
		}
	}
}

// EncryptKey encrypts a PQC private key using OpenSSL pkcs8
func (g *PQCGenerator) EncryptKey(keyFile, password, outputFile string) error {
	args := []string{"pkcs8",
		"-in", keyFile,
		"-topk8",
		"-out", outputFile,
		"-passout", "pass:" + password,
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

// generateOpenSSLConfig generates an OpenSSL configuration file for CSR generation
func (g *PQCGenerator) generateOpenSSLConfig(configFile string, subject Subject, sans []string) error {
	// Create the OpenSSL config content
	configContent := fmt.Sprintf(`[req]
default_bits = 2048
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = %s
`, subject.CommonName)

	// Add optional subject fields
	if subject.Country != "" {
		configContent += fmt.Sprintf("C = %s\n", subject.Country)
	}
	if subject.Province != "" {
		configContent += fmt.Sprintf("ST = %s\n", subject.Province)
	}
	if subject.Locality != "" {
		configContent += fmt.Sprintf("L = %s\n", subject.Locality)
	}
	if subject.Organization != "" {
		configContent += fmt.Sprintf("O = %s\n", subject.Organization)
	}
	if subject.OrganizationalUnit != "" {
		configContent += fmt.Sprintf("OU = %s\n", subject.OrganizationalUnit)
	}

	// Add v3_req section with SANs
	configContent += "\n[v3_req]\n"
	configContent += "basicConstraints = CA:FALSE\n"
	configContent += "keyUsage = nonRepudiation, digitalSignature, keyEncipherment\n"

	// Add extended key usage if specified
	if len(g.ExtKeyUsage) > 0 {
		configContent += fmt.Sprintf("extendedKeyUsage = %s\n", strings.Join(g.ExtKeyUsage, ", "))
	}

	// Add certificate policies if specified
	if len(g.CertPolicy) > 0 {
		configContent += fmt.Sprintf("certificatePolicies = %s\n", strings.Join(g.CertPolicy, ", "))
	}

	// Add SANs if provided
	if len(sans) > 0 {
		configContent += "subjectAltName = @alt_names\n\n"
		configContent += "[alt_names]\n"

		dnsCount := 1
		ipCount := 1
		emailCount := 1

		for _, san := range sans {
			if isIPAddress(san) {
				configContent += fmt.Sprintf("IP.%d = %s\n", ipCount, san)
				ipCount++
			} else if strings.Contains(san, "@") {
				configContent += fmt.Sprintf("email.%d = %s\n", emailCount, san)
				emailCount++
			} else {
				configContent += fmt.Sprintf("DNS.%d = %s\n", dnsCount, san)
				dnsCount++
			}
		}
	}

	// Write the config file
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write OpenSSL config file: %w", err)
	}

	// Always track the config file for cleanup since it's a temporary file
	g.GeneratedFiles = append(g.GeneratedFiles, configFile)

	return nil
}

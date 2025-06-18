package cert

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

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
	SLHDSA256F PQCAlgorithm = "SLHDSA256F"
)

// PQCGenerator handles PQC certificate generation
type PQCGenerator struct {
	OpenSSLPath    string
	TempDir        string
	Verbose        bool
	NoClean        bool
	ExtKeyUsage    []string
	CertPolicy     []string
	GeneratedFiles []string // Track files created by OpenSSL
}

// NewPQCGenerator creates a new PQC generator instance
func NewPQCGenerator(openSSLPath, tempDir string, verbose, noClean bool) *PQCGenerator {
	return &PQCGenerator{
		OpenSSLPath:    openSSLPath,
		TempDir:        tempDir,
		Verbose:        verbose,
		NoClean:        noClean,
		GeneratedFiles: []string{},
	}
}

// ValidateAlgorithm checks if the provided algorithm is supported
func (g *PQCGenerator) ValidateAlgorithm(alg string) error {
	alg = strings.ToUpper(alg)
	switch PQCAlgorithm(alg) {
	case MLDSA44, MLDSA65, MLDSA87, SLHDSA128F, SLHDSA192F, SLHDSA256F:
		return nil
	default:
		return fmt.Errorf("unsupported PQC algorithm: %s", alg)
	}
}

// GenerateKey generates a PQC private key using OpenSSL
func (g *PQCGenerator) GenerateKey(algorithm string) (string, error) {
	if err := g.ValidateAlgorithm(algorithm); err != nil {
		return "", err
	}

	keyFile := filepath.Join(g.TempDir, fmt.Sprintf("%s.key", strings.ToLower(algorithm)))
	cmd := exec.Command(g.OpenSSLPath, "genpkey",
		"-algorithm", algorithm,
		"-out", keyFile)

	if g.Verbose {
		fmt.Printf("[zcert] OpenSSL command: %s\n", strings.Join(cmd.Args, " "))
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
func (g *PQCGenerator) GenerateCSR(keyFile string, subject Subject, sans []string) (string, error) {
	// Generate OpenSSL config
	configFile := filepath.Join(g.TempDir, "openssl.cnf")
	if err := g.generateOpenSSLConfig(configFile, subject, sans); err != nil {
		return "", err
	}

	// Generate CSR
	csrFile := filepath.Join(g.TempDir, filepath.Base(keyFile[:len(keyFile)-4])+".csr")
	cmd := exec.Command(g.OpenSSLPath, "req",
		"-config", configFile,
		"-new",
		"-key", keyFile,
		"-out", csrFile,
		"-subj", subject.String())

	if g.Verbose {
		fmt.Printf("[zcert] OpenSSL command: %s\n", strings.Join(cmd.Args, " "))
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
		for _, san := range sans {
			if strings.Contains(san, ":") {
				sanEntries = append(sanEntries, fmt.Sprintf("IP.%d = %s", len(sanEntries)+1, san))
			} else if strings.Contains(san, "@") {
				sanEntries = append(sanEntries, fmt.Sprintf("email.%d = %s", len(sanEntries)+1, san))
			} else {
				sanEntries = append(sanEntries, fmt.Sprintf("DNS.%d = %s", len(sanEntries)+1, san))
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

// Cleanup removes temporary files unless NoClean is true
func (g *PQCGenerator) Cleanup(files ...string) {
	if g.NoClean {
		return
	}

	// Only remove files tracked as generated by OpenSSL
	for _, file := range g.GeneratedFiles {
		if file != "" {
			os.Remove(file)
		}
	}
} 
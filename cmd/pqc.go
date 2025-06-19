package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"strings"
	"time"
	"zcert/internal/api"
	"zcert/internal/cert"
	"zcert/internal/config"
)

var pqcCmd = &cobra.Command{
	Use:   "pqc",
	Short: "Generate and enroll Post-Quantum Cryptography certificates",
	Long: `Generate and enroll Post-Quantum Cryptography certificates using OpenSSL 3.5+.
Supports FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) algorithms.`,
	RunE: runPQC,
}

func init() {
	rootCmd.AddCommand(pqcCmd)

	// Required flags
	pqcCmd.Flags().String("cn", "", "Common Name for certificate (required)")
	pqcCmd.MarkFlagRequired("cn")
	pqcCmd.Flags().String("pqc-algorithm", "", "PQC algorithm (MLDSA44, MLDSA65, MLDSA87, SLHDSA128F, SLHDSA192F, SLHDSA256F)")

	// Authentication & Configuration
	pqcCmd.Flags().String("config", "", "Configuration file path")
	pqcCmd.Flags().String("profile", "", "Profile name from configuration")
	pqcCmd.Flags().String("url", "", "ZTPKI API base URL")
	pqcCmd.Flags().String("hawk-id", "", "HAWK authentication ID")
	pqcCmd.Flags().String("hawk-key", "", "HAWK authentication key")
	pqcCmd.Flags().String("policy", "", "Policy ID for certificate issuance")

	// Subject Information
	pqcCmd.Flags().String("country", "", "Country (C)")
	pqcCmd.Flags().String("province", "", "State/Province (ST)")
	pqcCmd.Flags().String("locality", "", "Locality/City (L)")
	pqcCmd.Flags().StringArray("org", []string{}, "Organization (O)")
	pqcCmd.Flags().StringArray("ou", []string{}, "Organizational Unit (OU)")
	pqcCmd.Flags().StringArray("san-dns", []string{}, "DNS Subject Alternative Names")
	pqcCmd.Flags().StringArray("san-ip", []string{}, "IP Subject Alternative Names")
	pqcCmd.Flags().StringArray("san-email", []string{}, "Email Subject Alternative Names")

	// Output Options
	pqcCmd.Flags().String("cert-file", "", "Certificate output file path")
	pqcCmd.Flags().String("key-file", "", "Private key output file path")
	pqcCmd.Flags().String("chain-file", "", "Certificate chain output file path")
	pqcCmd.Flags().String("bundle-file", "", "Combined certificate bundle file path")
	pqcCmd.Flags().String("format", "pem", "Output format (pem, p12)")
	pqcCmd.Flags().String("key-password", "", "Password for private key encryption")
	pqcCmd.Flags().String("p12-password", "", "Password for PKCS#12 bundle")
	pqcCmd.Flags().Bool("no-key-output", false, "Don't output private key to file")

	// Operational Flags
	pqcCmd.Flags().String("validity", "", "Certificate validity period (30d, 6m, 1y, etc.)")
}

func runPQC(cmd *cobra.Command, args []string) error {
	cfg, err := loadPQCConfig(cmd)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Get global verbose level
	verboseLevel := GetVerboseLevel()
	cfg.Verbose = verboseLevel > 0

	// Ensure key file is set
	if cfg.KeyFile == "" {
		cfg.KeyFile = "mldsa44.key"
	}

	// Create PQC generator with correct signature
	generator := cert.NewPQCGenerator(cfg.OpenSSLPath, cfg.TempDir, cfg.Verbose, cfg.NoClean)

	// Generate PQC key
	keyFile, err := generator.GenerateKey(cfg.Algorithm)
	if err != nil {
		return fmt.Errorf("failed to generate PQC key: %w", err)
	}
	if !cfg.NoClean {
		defer generator.Cleanup(keyFile)
	}

	// If user specified --key-file and it's different from the generated key file, copy it
	if cfg.KeyFile != "" && cfg.KeyFile != keyFile {
		err = copyFile(keyFile, cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to copy key to --key-file: %w", err)
		}
	}

	// Create subject information
	subject := cert.Subject{
		CommonName:         cfg.CommonName,
		Country:            cfg.Country,
		Province:           cfg.Province,
		Locality:           cfg.Locality,
		Organization:       "",
		OrganizationalUnit: "",
	}
	if len(cfg.Organizations) > 0 {
		subject.Organization = cfg.Organizations[0]
	}
	if len(cfg.OrganizationalUnits) > 0 {
		subject.OrganizationalUnit = cfg.OrganizationalUnits[0]
	}

	// Collect SANs
	var sans []string
	sans = append(sans, cfg.SANDNS...)
	sans = append(sans, cfg.SANIP...)
	sans = append(sans, cfg.SANEmail...)

	// Generate CSR
	csrFile, err := generator.GenerateCSR(keyFile, subject, sans)
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}
	if !cfg.NoClean {
		defer generator.Cleanup(csrFile)
	}

	// Output CSR file path
	fmt.Printf("CSR file generated: %s\n", csrFile)

	// Step 5: Direct certificate enrollment (no subprocess)
	fmt.Println("[zcert] Submitting CSR for enrollment...")
	
	// Create API client using the same approach as enroll command
	apiConfig := &config.Config{
		BaseURL: cfg.URL,
		HawkID:  cfg.HawkID,
		HawkKey: cfg.HawkKey,
	}
	
	client, err := api.NewClientWithVerbose(apiConfig, verboseLevel)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	
	// Read CSR content
	csrPEM, err := os.ReadFile(csrFile)
	if err != nil {
		return fmt.Errorf("failed to read CSR file: %w", err)
	}
	
	// Create certificate task using the same structure as enroll command
	certTask := &config.CertificateTask{
		Request: config.CertificateRequest{
			Subject: config.CertificateSubject{
				CommonName:   cfg.CommonName,
				Country:      cfg.Country,
				State:        cfg.Province,
				Locality:     cfg.Locality,
				Organization: strings.Join(cfg.Organizations, ","),
				OrgUnits:     cfg.OrganizationalUnits,
			},
			Policy: cfg.Policy,
			SANs: &config.FlexibleSANs{
				SubjectAltNames: &config.SubjectAltNames{
					DNS:   cfg.SANDNS,
					IP:    cfg.SANIP,
					Email: cfg.SANEmail,
				},
			},
		},
	}
	
	// Submit CSR to ZTPKI
	requestID, err := client.SubmitCSRWithFullPayload(string(csrPEM), certTask, verboseLevel)
	if err != nil {
		return fmt.Errorf("failed to submit CSR: %w", err)
	}
	
	if verboseLevel > 0 {
		fmt.Fprintf(os.Stderr, "CSR submitted successfully. Request ID: %s\n", requestID)
	}
	
	// Wait for certificate to be issued
	if verboseLevel > 0 {
		fmt.Fprintf(os.Stderr, "Waiting for certificate issuance...\n")
	}
	
	// Poll for certificate completion
	var certificate *api.Certificate
	attemptCount := 0
	maxAttempts := 600 // 10 minutes with 1-second intervals
	for attemptCount < maxAttempts {
		attemptCount++
		time.Sleep(1 * time.Second)
		
		// Check certificate request status first
		request, err := client.GetCertificateRequest(requestID)
		if err != nil {
			if verboseLevel > 0 && attemptCount%20 == 1 { // Log every 20 seconds
				fmt.Fprintf(os.Stderr, "Attempt %d: Certificate not ready yet...\n", attemptCount)
			}
			continue
		}
		
		if request.IssuanceStatus == "COMPLETE" || request.IssuanceStatus == "VALID" || request.IssuanceStatus == "ISSUED" {
			if verboseLevel > 0 {
				fmt.Fprintf(os.Stderr, "Certificate issued successfully!\n")
			}
			// Now get the actual certificate using the certificate ID
			certificate, err = client.GetCertificate(request.CertificateID)
			if err != nil {
				return fmt.Errorf("failed to retrieve certificate after issuance: %w", err)
			}
			break
		} else if request.IssuanceStatus == "FAILED" {
			errorMsg := fmt.Sprintf("certificate issuance failed: %s", request.IssuanceStatus)
			if request.Status != "" {
				errorMsg += fmt.Sprintf(" (Status: %s)", request.Status)
			}
			return fmt.Errorf(errorMsg)
		} else if verboseLevel > 0 {
			fmt.Fprintf(os.Stderr, "Certificate status: %s\n", request.IssuanceStatus)
		}
	}
	
	if certificate == nil {
		return fmt.Errorf("certificate issuance timed out after %d attempts", maxAttempts)
	}
	
	// Retrieve certificate
	certPEM, err := client.GetCertificatePEM(certificate.ID, cfg.Chain)
	if err != nil {
		return fmt.Errorf("failed to retrieve certificate: %w", err)
	}
	
	// Write certificate and chain to files as per pqc's output options
	if cfg.CertFile != "" {
		if err := os.WriteFile(cfg.CertFile, []byte(certPEM.Certificate), 0644); err != nil {
			return fmt.Errorf("failed to write certificate file: %w", err)
		}
		if verboseLevel > 0 {
			fmt.Fprintf(os.Stderr, "Certificate written to: %s\n", cfg.CertFile)
		}
	}
	
	if cfg.ChainFile != "" && certPEM.Chain != "" {
		if err := os.WriteFile(cfg.ChainFile, []byte(certPEM.Chain), 0644); err != nil {
			return fmt.Errorf("failed to write chain file: %w", err)
		}
		if verboseLevel > 0 {
			fmt.Fprintf(os.Stderr, "Certificate chain written to: %s\n", cfg.ChainFile)
		}
	}
	
	if cfg.BundleFile != "" {
		bundle := certPEM.Certificate
		if certPEM.Chain != "" {
			bundle += "\n" + certPEM.Chain
		}
		if err := os.WriteFile(cfg.BundleFile, []byte(bundle), 0644); err != nil {
			return fmt.Errorf("failed to write bundle file: %w", err)
		}
		if verboseLevel > 0 {
			fmt.Fprintf(os.Stderr, "Certificate bundle written to: %s\n", cfg.BundleFile)
		}
	}
	
	// Always write the private key
	if cfg.KeyFile != "" && keyFile != "" {
		copyFile(keyFile, cfg.KeyFile)
		if verboseLevel > 0 {
			fmt.Fprintf(os.Stderr, "Private key written to: %s\n", cfg.KeyFile)
		}
	}
	
	return nil
}

type PQCConfig struct {
	// OpenSSL configuration
	OpenSSLPath string
	TempDir     string
	Algorithm   string
	Verbose     bool
	NoClean     bool

	// Certificate configuration
	CommonName           string
	Country             string
	Province            string
	Locality            string
	Organizations       []string
	OrganizationalUnits []string
	SANDNS              []string
	SANIP               []string
	SANEmail            []string

	// Output configuration
	CertFile    string
	KeyFile     string
	ChainFile   string
	BundleFile  string
	Format      string
	KeyPassword string
	P12Password string
	NoKeyOutput bool
	Chain       bool

	// ZTPKI configuration
	ConfigFile string
	Profile    string
	URL        string
	HawkID     string
	HawkKey    string
	Policy     string
	Validity   string
}

func loadPQCConfig(cmd *cobra.Command) (*PQCConfig, error) {
	// Initialize config with defaults
	cfg := &PQCConfig{
		OpenSSLPath: "openssl",
		TempDir:     os.TempDir(),
		Verbose:     false, // Will be set by global verbose level
		NoClean:     false,
	}

	// Load configuration file
	configFile, _ := cmd.Flags().GetString("config")
	if configFile == "" {
		configFile = "zcert.cnf"
	}

	// Load profile
	profile, _ := cmd.Flags().GetString("profile")

	// Load configuration
	profileConfig, err := config.LoadProfileConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load profile config: %w", err)
	}

	if profile == "" {
		// If pqc profile exists, use it; otherwise, use Default
		if pqcProfile := profileConfig.GetProfile("pqc"); pqcProfile != nil {
			profile = pqcProfile.Name
		} else {
			profile = "Default"
		}
	}

	// Get the profile section
	profileSection := profileConfig.Profiles[profile]
	if profileSection == nil {
		return nil, fmt.Errorf("profile not found: %s", profile)
	}

	// Map profile config to PQCConfig
	if profileSection.OpenSSLPath != "" {
		cfg.OpenSSLPath = profileSection.OpenSSLPath
	} else {
		cfg.OpenSSLPath = "./openssl.exe"
	}
	if profileSection.TempDir != "" {
		cfg.TempDir = profileSection.TempDir
	} else {
		cfg.TempDir = "."
	}
	
	// Get algorithm from CLI flag or profile
	cfg.Algorithm, _ = cmd.Flags().GetString("pqc-algorithm")
	if cfg.Algorithm == "" {
		// Try to get from profile section
		cfg.Algorithm = profileSection.PQCAlgorithm
	}
	if cfg.Algorithm == "" {
		return nil, fmt.Errorf("pqc-algorithm must be specified either via --pqc-algorithm flag or in the selected profile of the config file (profile: %s)", profile)
	}
	
	cfg.NoClean = profileSection.NoClean // Read NoClean from the profile section

	// Map certificate configuration
	cfg.CommonName, _ = cmd.Flags().GetString("cn")
	cfg.Country, _ = cmd.Flags().GetString("country")
	cfg.Province, _ = cmd.Flags().GetString("province")
	cfg.Locality, _ = cmd.Flags().GetString("locality")
	cfg.Organizations, _ = cmd.Flags().GetStringArray("org")
	cfg.OrganizationalUnits, _ = cmd.Flags().GetStringArray("ou")
	cfg.SANDNS, _ = cmd.Flags().GetStringArray("san-dns")
	cfg.SANIP, _ = cmd.Flags().GetStringArray("san-ip")
	cfg.SANEmail, _ = cmd.Flags().GetStringArray("san-email")

	// Map output configuration
	cfg.CertFile, _ = cmd.Flags().GetString("cert-file")
	cfg.KeyFile, _ = cmd.Flags().GetString("key-file")
	cfg.ChainFile, _ = cmd.Flags().GetString("chain-file")
	cfg.BundleFile, _ = cmd.Flags().GetString("bundle-file")
	cfg.Format, _ = cmd.Flags().GetString("format")
	cfg.KeyPassword, _ = cmd.Flags().GetString("key-password")
	cfg.P12Password, _ = cmd.Flags().GetString("p12-password")
	cfg.NoKeyOutput, _ = cmd.Flags().GetBool("no-key-output")
	// Chain: use CLI flag if set, else profile value
	chainFlag := cmd.Flags().Changed("chain")
	if chainFlag {
		cfg.Chain, _ = cmd.Flags().GetBool("chain")
	} else {
		cfg.Chain = profileSection.Chain
	}

	// Map ZTPKI configuration
	cfg.ConfigFile = configFile
	cfg.Profile = profile
	cfg.URL = profileSection.URL
	cfg.HawkID = profileSection.KeyID
	cfg.HawkKey = profileSection.Secret
	cfg.Policy = profileSection.PolicyID
	cfg.Validity = fmt.Sprintf("%d", profileSection.Validity)

	return cfg, nil
} 
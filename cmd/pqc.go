package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
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
	pqcCmd.Flags().String("pqc-algorithm", "", "PQC algorithm (MLDSA44, MLDSA65, MLDSA87, Dilithium2, Dilithium3, Dilithium5)")

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
	pqcCmd.Flags().Bool("chain", false, "Include certificate chain")

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
	cfg.Verbose = verboseLevel > 1

	// Print variable hierarchy only if verbose level is explicitly set
	if verboseLevel > 0 {
		printVariableHierarchyPQC(cmd, cfg)
	}

	// Create PQC generator with correct signature
	generator := cert.NewPQCGenerator(cfg.OpenSSLPath, cfg.TempDir, cfg.Verbose, cfg.NoCleanup, cfg.LegacyAlgNames, cfg.LegacyPQCAlgorithm)

	// Always generate PQC key unencrypted
	keyFile, err := generator.GenerateKey(cfg.Algorithm)
	if err != nil {
		return fmt.Errorf("failed to generate PQC key: %w", err)
	}
	if !cfg.NoCleanup {
		defer generator.Cleanup(keyFile)
	}

	finalKeyFile := keyFile
	// If key encryption is requested, encrypt the key using OpenSSL pkcs8
	if cfg.KeyPassword != "" {
		encryptedKeyFile := keyFile + ".enc"
		err = generator.EncryptKey(keyFile, cfg.KeyPassword, encryptedKeyFile)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}
		finalKeyFile = encryptedKeyFile
	}

	// Handle private key output
	if !cfg.NoKeyOutput && finalKeyFile != "" {
		keyOutputFile := cfg.KeyFile
		if keyOutputFile == "" {
			keyOutputFile = cfg.CommonName + ".key"
		}
		err = copyFile(finalKeyFile, keyOutputFile)
		if err != nil {
			return fmt.Errorf("failed to copy private key to output location: %w", err)
		}
		if verboseLevel > 1 {
			fmt.Fprintf(os.Stderr, "Private key written to: %s\n", keyOutputFile)
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
	csrFile, err := generator.GenerateCSR(finalKeyFile, subject, sans, cfg.KeyPassword)
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}
	if !cfg.NoCleanup {
		defer generator.Cleanup(csrFile)
	}

	// Output CSR file path only if verbose
	if verboseLevel > 1 {
		fmt.Printf("CSR file generated: %s\n", csrFile)
	}

	// Step 5: Direct certificate enrollment (no subprocess)
	if verboseLevel > 1 {
		fmt.Println("[zcert] Submitting CSR for enrollment...")
	}

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

	if verboseLevel > 1 {
		fmt.Fprintf(os.Stderr, "CSR submitted successfully. Request ID: %s\n", requestID)
	}

	// Wait for certificate to be issued
	if verboseLevel > 1 {
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
			if verboseLevel > 1 && attemptCount%20 == 1 { // Log every 20 seconds
				fmt.Fprintf(os.Stderr, "Attempt %d: Certificate not ready yet...\n", attemptCount)
			}
			continue
		}

		if request.IssuanceStatus == "COMPLETE" || request.IssuanceStatus == "VALID" || request.IssuanceStatus == "ISSUED" {
			if verboseLevel > 1 {
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
		} else if verboseLevel > 1 {
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

	// Output certificate
	certOutputFile := cfg.CertFile
	if certOutputFile == "" {
		certOutputFile = cfg.CommonName + ".crt"
	}
	err = os.WriteFile(certOutputFile, []byte(certPEM.Certificate), 0644)
	if err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}
	if verboseLevel > 1 {
		fmt.Fprintf(os.Stderr, "Certificate written to: %s\n", certOutputFile)
	}

	// Output private key content to terminal first if not disabled
	if !cfg.NoKeyOutput {
		keyOutputFile := cfg.KeyFile
		if keyOutputFile == "" {
			keyOutputFile = cfg.CommonName + ".key"
		}
		keyContent, err := os.ReadFile(keyOutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not read private key file for terminal output: %v\n", err)
		} else {
			// Print private key content without additional line breaks
			fmt.Print(string(keyContent))
		}
	}

	// Output certificate content to terminal next with exactly one empty line
	fmt.Println("")
	fmt.Println(certPEM.Certificate)

	// Output chain certificates if available and requested with one empty line
	if cfg.Chain && certPEM.Chain != "" {
		fmt.Println("")
		fmt.Println(certPEM.Chain)
	}

	return nil
}

type PQCConfig struct {
	// OpenSSL configuration
	OpenSSLPath string
	TempDir     string
	Algorithm   string
	Verbose     bool
	NoCleanup   bool
	LegacyAlgNames bool
	LegacyPQCAlgorithm string

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
		NoCleanup:   false,
	}

	// Get verbose level
	verboseLevel := GetVerboseLevel()

	// Use the global currentProfile that was set by the root command, or select profile here
	var selectedProfile *config.Profile

	// Ensure profileConfig is loaded
	pc := profileConfig
	if pc == nil {
		// Try to get config file from flag or default
		cfgFileFlag, _ := cmd.Flags().GetString("config")
		cfgFile := cfgFileFlag
		if cfgFile == "" {
			cfgFile = "zcert.cnf"
		}
		var err error
		pc, err = config.LoadProfileConfig(cfgFile, true) // preferPQC=true
		if err != nil {
			return nil, err
		}
	}

	// Check if --profile flag is set
	profileFlag, _ := cmd.Flags().GetString("profile")
	if profileFlag != "" {
		selectedProfile = pc.GetProfile(profileFlag)
		if verboseLevel > 1 {
			fmt.Fprintf(os.Stderr, "DEBUG: Using profile from flag: '%s'\n", profileFlag)
		}
	} else {
		// List available profiles for debugging
		profiles := pc.ListProfiles()
		if verboseLevel > 1 {
			fmt.Fprintf(os.Stderr, "DEBUG: profileName from flag: ''\n")
			fmt.Fprintf(os.Stderr, "DEBUG: Available profiles: %v\n", profiles)
		}
		
		// Explicitly prioritize 'pqc' profile for pqc command if it exists
		selectedProfile = pc.GetProfile("pqc")
		if selectedProfile != nil {
			if verboseLevel > 1 {
				fmt.Fprintf(os.Stderr, "DEBUG: Using 'pqc' profile by default for pqc command\n")
			}
		} else {
			// Fallback to 'Default' profile if 'pqc' doesn't exist
			selectedProfile = pc.GetProfile("Default")
			if selectedProfile != nil {
				if verboseLevel > 1 {
					fmt.Fprintf(os.Stderr, "DEBUG: 'pqc' profile not found, falling back to 'Default'\n")
				}
			} else if len(profiles) > 0 {
				// Fallback: use the first available profile if neither 'pqc' nor 'Default' exist
				selectedProfile = pc.GetProfile(profiles[0])
				if verboseLevel > 1 {
					fmt.Fprintf(os.Stderr, "DEBUG: Neither 'pqc' nor 'Default' profiles found, using first available: '%s'\n", profiles[0])
				}
			}
		}
	}

	if selectedProfile == nil {
		return nil, fmt.Errorf("no valid profile found (tried --profile, 'pqc', and 'Default')")
	}

	// Debug information about profile and settings only if verbose level is set
	if verboseLevel > 1 {
		fmt.Fprintf(os.Stderr, "DEBUG: Using profile: %s\n", selectedProfile.Name)
		fmt.Fprintf(os.Stderr, "DEBUG: PQC Algorithm: %s\n", selectedProfile.PQCAlgorithm)
		fmt.Fprintf(os.Stderr, "DEBUG: LegacyAlgNames: %t\n", selectedProfile.LegacyAlgNames)
		fmt.Fprintf(os.Stderr, "DEBUG: LegacyPQCAlgorithm: %s\n", selectedProfile.LegacyPQCAlgorithm)
	}

	// Map profile config to PQCConfig
	if selectedProfile.OpenSSLPath != "" {
		cfg.OpenSSLPath = selectedProfile.OpenSSLPath
	} else {
		cfg.OpenSSLPath = "./openssl.exe"
	}
	if selectedProfile.TempDir != "" {
		cfg.TempDir = selectedProfile.TempDir
	}
	cfg.Verbose = verboseLevel > 0 // Use global verbose level
	cfg.NoCleanup = selectedProfile.NoCleanup
	cfg.LegacyAlgNames = selectedProfile.LegacyAlgNames
	cfg.LegacyPQCAlgorithm = selectedProfile.LegacyPQCAlgorithm

	// Algorithm selection: CLI flag takes precedence over profile
	algoFlag, _ := cmd.Flags().GetString("pqc-algorithm")
	if algoFlag != "" {
		cfg.Algorithm = algoFlag
	} else {
		cfg.Algorithm = selectedProfile.PQCAlgorithm
	}

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
		cfg.Chain = selectedProfile.Chain
	}

	// Map ZTPKI configuration (CLI flags will override profile settings via Viper)
	cfg.ConfigFile = "" // Not needed since we're using global profile
	cfg.Profile = selectedProfile.Name
	cfg.URL = selectedProfile.URL
	cfg.HawkID = selectedProfile.KeyID
	cfg.HawkKey = selectedProfile.Secret
	cfg.Policy = selectedProfile.PolicyID
	cfg.Validity = fmt.Sprintf("%d", selectedProfile.Validity)

	// Override with command-line flags
	if cmd.Flags().Changed("url") {
		cfg.URL, _ = cmd.Flags().GetString("url")
	}
	if cmd.Flags().Changed("hawk-id") {
		cfg.HawkID, _ = cmd.Flags().GetString("hawk-id")
	}
	if cmd.Flags().Changed("hawk-key") {
		cfg.HawkKey, _ = cmd.Flags().GetString("hawk-key")
	}
	if cmd.Flags().Changed("policy") {
		cfg.Policy, _ = cmd.Flags().GetString("policy")
	}
	if cmd.Flags().Changed("validity") {
		cfg.Validity, _ = cmd.Flags().GetString("validity")
	}

	return cfg, nil
}

func printVariableHierarchyPQC(cmd *cobra.Command, cfg *PQCConfig) {
	fmt.Printf("\n=== Variable Hierarchy (CLI > Config > Environment) ===\n")

	// Helper to determine the source of a string value
	getSource := func(flagName, profileValue, envName string) (string, string) {
		if cmd.Flags().Changed(flagName) {
			val, _ := cmd.Flags().GetString(flagName)
			return "CLI", val
		}
		if profileValue != "" {
			return "Config", profileValue
		}
		if os.Getenv(envName) != "" {
			return "ENV", os.Getenv(envName)
		}
		return "Default", profileValue // Fallback to profile value if nothing else is set
	}

	// URL
	urlSource, urlValue := getSource("url", cfg.URL, "ZTPKI_URL")
	fmt.Printf("ZTPKI_URL - %s - %s\n", urlSource, urlValue)

	// HAWK ID
	hawkIDSource, hawkIDValue := getSource("hawk-id", cfg.HawkID, "ZTPKI_HAWK_ID")
	fmt.Printf("ZTPKI_HAWK_ID - %s - %s\n", hawkIDSource, hawkIDValue)

	// HAWK Key
	hawkKeySource, hawkKeyValue := getSource("hawk-key", cfg.HawkKey, "ZTPKI_HAWK_SECRET")
	fmt.Printf("ZTPKI_HAWK_SECRET - %s - %s\n", hawkKeySource, maskSecret(hawkKeyValue))

	// Policy
	policySource, policyValue := getSource("policy", cfg.Policy, "ZTPKI_POLICY_ID")
	fmt.Printf("ZTPKI_POLICY_ID - %s - %s\n", policySource, policyValue)

	fmt.Printf("===============================================\n\n")
}

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"zcert/internal/cert"
	"zcert/internal/config"
	"zcert/internal/utils"
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
	cfg, selectedProfile, err := loadPQCConfig(cmd)
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
	generator.SetOpenSSLCleanup(cfg.OpenSSLCleanup)

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

	// Set default output file names if not specified
	if cfg.CertFile == "" {
		cfg.CertFile = cfg.CommonName + ".crt"
	}
	if cfg.KeyFile == "" && !cfg.NoKeyOutput {
		cfg.KeyFile = cfg.CommonName + ".key"
	}

	// Create subject information - use profile defaults if CLI values not provided
	subject := cert.Subject{
		CommonName:         cfg.CommonName,
		Country:            getSubjectValue(cfg.Country, selectedProfile.SubjectCountry),
		Province:           getSubjectValue(cfg.Province, selectedProfile.SubjectProvince),
		Locality:           getSubjectValue(cfg.Locality, selectedProfile.SubjectLocality),
		Organization:       "",
		OrganizationalUnit: "",
	}
	if len(cfg.Organizations) > 0 {
		subject.Organization = cfg.Organizations[0]
	} else if selectedProfile.SubjectOrganization != "" {
		subject.Organization = selectedProfile.SubjectOrganization
	}
	if len(cfg.OrganizationalUnits) > 0 {
		subject.OrganizationalUnit = cfg.OrganizationalUnits[0]
	} else if selectedProfile.SubjectOrganizationalUnit != "" {
		subject.OrganizationalUnit = selectedProfile.SubjectOrganizationalUnit
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

	// Create API client using the utility function
	profile := &config.Profile{
		URL:    cfg.URL,
		KeyID:  cfg.HawkID,
		Secret: cfg.HawkKey,
	}

	client, err := CreateAPIClientFromProfile(profile, verboseLevel)
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

	// Use the enrollment workflow function
	certificate, err := client.EnrollmentWorkflow(string(csrPEM), certTask)
	if err != nil {
		return err
	}

	// Retrieve certificate using standardized chain handling
	chainOpts := &utils.ChainRetrievalOptions{
		IncludeChain: cfg.Chain,
		FallbackMode: true,
		VerboseLevel: 0, // PQC command doesn't expose verbose flag
	}
	
	result, err := utils.RetrieveCertificateWithChainResult(client, certificate.ID, chainOpts)
	if err != nil {
		return err
	}
	
	certificate = result.Certificate
	certPEM := result.PEMResponse

	// Read private key for output
	var keyPEM []byte
	if !cfg.NoKeyOutput {
		keyContent, err := os.ReadFile(finalKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read private key for output: %w", err)
		}
		keyPEM = keyContent
	}

	// Write to files first
	err = OutputCertificateWithFiles(certPEM, keyPEM, OutputCertificateOptions{
		CertFile:     cfg.CertFile,
		KeyFile:      cfg.KeyFile, 
		ChainFile:    cfg.ChainFile,
		BundleFile:   cfg.BundleFile,
		KeyPassword:  cfg.KeyPassword,
		NoKeyOutput:  cfg.NoKeyOutput,
		IncludeChain: cfg.Chain,
		VerboseLevel: verboseLevel,
	})
	if err != nil {
		return fmt.Errorf("failed to output certificate: %w", err)
	}

	// Always display certificate and private key on terminal (regardless of file output)
	if !cfg.NoKeyOutput && keyPEM != nil {
		fmt.Print(string(keyPEM))
		fmt.Println("") // Add blank line between key and certificate
	}
	fmt.Print(certPEM.Certificate)
	
	// Output chain certificates if available and requested
	if cfg.Chain && certPEM.Chain != "" {
		fmt.Print(certPEM.Chain)
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
	OpenSSLCleanup bool // Controls cleanup of openssl.cnf file

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

func loadPQCConfig(cmd *cobra.Command) (*PQCConfig, *config.Profile, error) {
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
	var configFileError error
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
			configFileError = err
			// If config file loading fails, create an empty profile config to allow environment variables and CLI flags
			if verboseLevel > 1 {
				fmt.Fprintf(os.Stderr, "DEBUG: Config file '%s' not found: %v\n", cfgFile, err)
				fmt.Fprintf(os.Stderr, "DEBUG: Will try environment variables and CLI flags\n")
			}
			pc = &config.ProfileConfig{} // Create empty config to continue with env vars and CLI flags
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
		// If no profile found, create one from environment variables
		if verboseLevel > 1 {
			fmt.Fprintf(os.Stderr, "DEBUG: No profile found, checking environment variables\n")
		}
		selectedProfile = &config.Profile{
			Name:   "Environment",
			URL:    os.Getenv("ZTPKI_URL"),
			KeyID:  os.Getenv("ZTPKI_HAWK_ID"),
			Secret: os.Getenv("ZTPKI_HAWK_SECRET"),
			PolicyID: os.Getenv("ZTPKI_POLICY_ID"),
			PQCAlgorithm: "MLDSA44", // Default PQC algorithm
		}
		
		// Check if CLI flags provide the necessary authentication before returning error
		hasURLFlag := cmd.Flags().Changed("url")
		hasHawkIDFlag := cmd.Flags().Changed("hawk-id")
		hasHawkKeyFlag := cmd.Flags().Changed("hawk-key")
		
		// If no environment variables are set and no CLI flags provided, return error
		if selectedProfile.URL == "" && selectedProfile.KeyID == "" && selectedProfile.Secret == "" &&
		   !hasURLFlag && !hasHawkIDFlag && !hasHawkKeyFlag {
			var errorMsg string
			if configFileError != nil {
				errorMsg = fmt.Sprintf("no valid configuration found:\n  - Config file error: %v\n  - No environment variables set (ZTPKI_URL, ZTPKI_HAWK_ID, ZTPKI_HAWK_SECRET)\n  - Use --url, --hawk-id, --hawk-key flags as alternative", configFileError)
			} else {
				errorMsg = "no valid profile found and no environment variables set (tried --profile, 'pqc', 'Default' profiles and ZTPKI_URL/ZTPKI_HAWK_ID/ZTPKI_HAWK_SECRET environment variables)"
			}
			return nil, nil, fmt.Errorf(errorMsg)
		}
		
		// If CLI flags are provided, update the environment profile with CLI values
		if hasURLFlag {
			selectedProfile.URL, _ = cmd.Flags().GetString("url")
		}
		if hasHawkIDFlag {
			selectedProfile.KeyID, _ = cmd.Flags().GetString("hawk-id")
		}
		if hasHawkKeyFlag {
			selectedProfile.Secret, _ = cmd.Flags().GetString("hawk-key")
		}
	}

	// Debug information about profile and settings only if verbose level is set
	if verboseLevel > 1 {
		fmt.Fprintf(os.Stderr, "DEBUG: Using profile: %s\n", selectedProfile.Name)
		fmt.Fprintf(os.Stderr, "DEBUG: PQC Algorithm: %s\n", selectedProfile.PQCAlgorithm)
		fmt.Fprintf(os.Stderr, "DEBUG: LegacyAlgNames: %t\n", selectedProfile.LegacyAlgNames)
		fmt.Fprintf(os.Stderr, "DEBUG: LegacyPQCAlgorithm: %s\n", selectedProfile.LegacyPQCAlgorithm)
		fmt.Fprintf(os.Stderr, "DEBUG: Cleanup: %t\n", selectedProfile.Cleanup)
		fmt.Fprintf(os.Stderr, "DEBUG: Subject Country: %s\n", selectedProfile.SubjectCountry)
		fmt.Fprintf(os.Stderr, "DEBUG: Subject Province: %s\n", selectedProfile.SubjectProvince)
		fmt.Fprintf(os.Stderr, "DEBUG: Subject Locality: %s\n", selectedProfile.SubjectLocality)
		fmt.Fprintf(os.Stderr, "DEBUG: Subject Organization: %s\n", selectedProfile.SubjectOrganization)
		fmt.Fprintf(os.Stderr, "DEBUG: Subject OU: %s\n", selectedProfile.SubjectOrganizationalUnit)
	}

	// Map profile config to PQCConfig
	if selectedProfile.OpenSSLPath != "" {
		cfg.OpenSSLPath = selectedProfile.OpenSSLPath
	} else {
		cfg.OpenSSLPath = "openssl"
	}
	if selectedProfile.TempDir != "" {
		cfg.TempDir = selectedProfile.TempDir
	}
	cfg.Verbose = verboseLevel > 0 // Use global verbose level
	cfg.NoCleanup = selectedProfile.NoCleanup
	cfg.LegacyAlgNames = selectedProfile.LegacyAlgNames
	cfg.LegacyPQCAlgorithm = selectedProfile.LegacyPQCAlgorithm
	cfg.OpenSSLCleanup = selectedProfile.Cleanup

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

	// Override with command-line flags (must happen before validation)
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

	// Also check CLI flags when building the environment profile
	if selectedProfile.Name == "Environment" {
		// Override environment profile with CLI flags if provided
		if cmd.Flags().Changed("url") {
			cfg.URL, _ = cmd.Flags().GetString("url")
		}
		if cmd.Flags().Changed("hawk-id") {
			cfg.HawkID, _ = cmd.Flags().GetString("hawk-id")
		}
		if cmd.Flags().Changed("hawk-key") {
			cfg.HawkKey, _ = cmd.Flags().GetString("hawk-key")
		}
	}

	return cfg, selectedProfile, nil
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

// getSubjectValue returns the CLI value if not empty, otherwise returns the profile default
func getSubjectValue(cliValue, profileValue string) string {
	if cliValue != "" {
		return cliValue
	}
	return profileValue
}

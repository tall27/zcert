package cmd

import (
	"fmt"
	"os"
	"strings"

	"zcert/internal/api"
	"zcert/internal/cert"
	"zcert/internal/config"
	validitypkg "zcert/internal/validity"

	"github.com/spf13/cobra"
)

var pqcCmd = &cobra.Command{
	Use:   "pqc",
	Short: "Generate and enroll Post-Quantum Cryptography certificates",
	Long: `Generate and enroll Post-Quantum Cryptography certificates using OpenSSL 3.5+.
Supports FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) algorithms.

The pqc command generates Post-Quantum Cryptography keys and CSRs using OpenSSL with OQS provider,
then enrolls them with the Zero Touch PKI service. It handles the complete workflow from key 
generation to certificate retrieval and output formatting.

Examples:
  # Using profile configuration (recommended)
  zcert pqc --cn "example.com" --pqc-algorithm "dilithium2"
  
  # Command-line authentication with PQC algorithm
  zcert pqc --cn "pqc.example.com" --pqc-algorithm "dilithium3" --url "https://your-ztpki-instance.com/api/v2" --hawk-id "your-id" --hawk-key "your-key"
  
  # With multiple SANs and custom validity
  zcert pqc --cn "api.example.com" --pqc-algorithm "mldsa44" --san-dns "example.com" --san-dns "www.example.com" --validity "90d"
  
  # With custom file outputs and encryption
  zcert pqc --cn "secure.example.com" --pqc-algorithm "dilithium5" --cert-file "./secure.crt" --key-file "./secure.key" --key-password "secret123"`,
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
	pqcCmd.Flags().String("p12-password", "", "Password for PKCS#12 bundle")
	pqcCmd.Flags().Bool("no-key-output", false, "Don't output private key to file")
	pqcCmd.Flags().Bool("chain", false, "Include certificate chain")
	pqcCmd.Flags().Bool("display", false, "Display private key and certificate on screen")

	// Operational Flags
	pqcCmd.Flags().String("validity", "", "Certificate validity period (30d, 6m, 1y, etc.)")

	// Set custom help and usage functions to group flags consistently
	pqcCmd.SetHelpFunc(getPQCCustomHelpFunc())
	pqcCmd.SetUsageFunc(getPQCUsageFunc())
}

func runPQC(cmd *cobra.Command, args []string) error {
	var (
		cfg          *PQCConfig
		keyFile      string
		csrFile      string
		csrContent   []byte
		client       *api.Client
		certTask     *config.CertificateTask
		requestID    string
		certificate  *api.Certificate
		certPEM      *api.CertificatePEMResponse
		keyPEM       []byte
		verboseLevel int
		finalKeyFile string
		vp           *validitypkg.ValidityPeriod
		vErr         error
	)

	cfg, err := loadPQCConfig(cmd)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	verboseLevel = GetVerboseLevel()
	cfg.Verbose = verboseLevel > 0

	if verboseLevel > 0 {
		printVariableHierarchyPQC(cmd, cfg)
	}

	generator := cert.NewPQCGenerator(cfg.OpenSSLPath, cfg.TempDir, cfg.Verbose, !cfg.KeepTempFiles, cfg.LegacyAlgNames, cfg.LegacyPQCAlgorithm, "")

	if verboseLevel > 0 {
		fmt.Fprintf(os.Stderr, "DEBUG: Algorithm: %s\n", cfg.Algorithm)
		fmt.Fprintf(os.Stderr, "DEBUG: LegacyAlgNames: %v\n", cfg.LegacyAlgNames)
		fmt.Fprintf(os.Stderr, "DEBUG: LegacyPQCAlgorithm: %s\n", cfg.LegacyPQCAlgorithm)
	}

	keyFile, err = generator.GenerateKey(cfg.Algorithm)
	if err != nil {
		return fmt.Errorf("failed to generate PQC key: %w", err)
	}
	finalKeyFile = keyFile

	// Clean up key file if keep-temp-files is false
	if !cfg.KeepTempFiles {
		defer os.Remove(keyFile)
	}

	csrFile, err = generator.GenerateCSR(finalKeyFile, cfg.Subject, cfg.SANDNS, "")
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Clean up CSR file if keep-temp-files is false
	if !cfg.KeepTempFiles {
		defer os.Remove(csrFile)
	}

	csrContent, err = os.ReadFile(csrFile)
	if err != nil {
		return fmt.Errorf("failed to read CSR file: %w", err)
	}

	apiConfig := &config.Config{
		BaseURL: cfg.URL,
		HawkID:  cfg.HawkID,
		HawkKey: cfg.HawkKey,
	}
	client, err = api.NewClientWithVerbose(apiConfig, verboseLevel)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	certTask = &config.CertificateTask{
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

	if cfg.Validity != "" {
		vp, vErr = validitypkg.ParseValidityPeriod(cfg.Validity)
		if vErr != nil {
			return fmt.Errorf("failed to parse validity '%s': %w", cfg.Validity, vErr)
		}
		certTask.Request.Validity = &config.ValidityConfig{
			Years:  vp.Years,
			Months: vp.Months,
			Days:   vp.Days,
		}
	}

	requestID, err = client.SubmitCSRWithFullPayload(string(csrContent), certTask, verboseLevel)
	if err != nil {
		return fmt.Errorf("failed to submit CSR: %w", err)
	}

	fmt.Fprintf(os.Stderr, "CSR submitted successfully. Request ID: %s\n", requestID)
	fmt.Fprintf(os.Stderr, "Waiting for certificate issuance...\n")

	certificate, err = client.PollForCertificateCompletion(requestID, 600)
	if err != nil {
		return fmt.Errorf("failed to wait for certificate: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Certificate issued successfully!\n")

	certPEM, err = client.GetCertificatePEM(certificate.ID, cfg.Chain)
	if err != nil {
		return fmt.Errorf("failed to retrieve certificate: %w", err)
	}

	keyPEM, err = os.ReadFile(finalKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	err = OutputCertificateWithFiles(certPEM, keyPEM, OutputCertificateOptions{
		CertFile:     cfg.CertFile,
		KeyFile:      cfg.KeyFile,
		ChainFile:    cfg.ChainFile,
		BundleFile:   cfg.BundleFile,
		NoKeyOutput:  cfg.NoKeyOutput,
		IncludeChain: cfg.Chain,
		VerboseLevel: verboseLevel,
	})
	if err != nil {
		return fmt.Errorf("failed to output certificate: %w", err)
	}

	return nil
}

type PQCConfig struct {
	// OpenSSL configuration
	OpenSSLPath        string
	TempDir            string
	Algorithm          string
	Verbose            bool
	KeepTempFiles      bool
	LegacyAlgNames     bool
	LegacyPQCAlgorithm string

	// Certificate configuration
	CommonName          string
	Country             string
	Province            string
	Locality            string
	Organizations       []string
	OrganizationalUnits []string
	SANDNS              []string
	SANIP               []string
	SANEmail            []string
	Subject             cert.Subject // Added Subject field

	// Output configuration
	CertFile    string
	KeyFile     string
	ChainFile   string
	BundleFile  string
	Format      string
	P12Password string
	NoKeyOutput bool
	Chain       bool
	Display     bool

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
		OpenSSLPath:   "openssl",
		TempDir:       "C:\\dev\\tmp",
		Verbose:       false, // Will be set by global verbose level
		KeepTempFiles: false,
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
	} else if pqcProfile := pc.GetProfile("pqc"); pqcProfile != nil {
		selectedProfile = pqcProfile
	} else if pc.GetProfile("") != nil {
		selectedProfile = pc.GetProfile("") // Default
	} else {
		// Fallback: use the first available profile
		profiles := pc.ListProfiles()
		if len(profiles) > 0 {
			selectedProfile = pc.GetProfile(profiles[0])
		}
	}

	if selectedProfile == nil {
		return nil, fmt.Errorf("no valid profile found (tried --profile, 'pqc', and 'Default')")
	}

	if verboseLevel > 0 {
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
	cfg.KeepTempFiles = selectedProfile.KeepTempFiles
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

	// Use the local selectedProfile variable for subject merging
	getSubjectValue := func(cliVal, profileVal string) string {
		if cliVal != "" {
			return cliVal
		}
		return profileVal
	}
	cfg.Subject = cert.Subject{
		CommonName:         getSubjectValue(cfg.CommonName, selectedProfile.SubjectCommonName),
		Country:            getSubjectValue(cfg.Country, selectedProfile.SubjectCountry),
		Province:           getSubjectValue(cfg.Province, selectedProfile.SubjectProvince),
		Locality:           getSubjectValue(cfg.Locality, selectedProfile.SubjectLocality),
		Organization:       "",
		OrganizationalUnit: "",
	}
	if len(cfg.Organizations) > 0 {
		cfg.Subject.Organization = cfg.Organizations[0]
	} else if selectedProfile.SubjectOrganization != "" {
		cfg.Subject.Organization = selectedProfile.SubjectOrganization
	}
	if len(cfg.OrganizationalUnits) > 0 {
		cfg.Subject.OrganizationalUnit = cfg.OrganizationalUnits[0]
	} else if selectedProfile.SubjectOrganizationalUnit != "" {
		cfg.Subject.OrganizationalUnit = selectedProfile.SubjectOrganizationalUnit
	}

	// Map output configuration
	cfg.CertFile, _ = cmd.Flags().GetString("cert-file")
	cfg.KeyFile, _ = cmd.Flags().GetString("key-file")
	cfg.ChainFile, _ = cmd.Flags().GetString("chain-file")
	cfg.BundleFile, _ = cmd.Flags().GetString("bundle-file")
	cfg.Format, _ = cmd.Flags().GetString("format")
	cfg.P12Password, _ = cmd.Flags().GetString("p12-password")
	cfg.NoKeyOutput, _ = cmd.Flags().GetBool("no-key-output")
	cfg.Display, _ = cmd.Flags().GetBool("display")
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

// Help and Usage Functions

func getPQCCustomHelpFunc() func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		fmt.Print(`Generate and enroll Post-Quantum Cryptography certificates using OpenSSL 3.5+.
Supports FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) algorithms.

The pqc command generates Post-Quantum Cryptography keys and CSRs using OpenSSL with OQS provider,
then enrolls them with the Zero Touch PKI service. It handles the complete workflow from key 
generation to certificate retrieval and output formatting.

Examples:
  # Using profile configuration (recommended)
  zcert pqc --cn "example.com" --pqc-algorithm "dilithium2"
  
  # Command-line authentication with PQC algorithm
  zcert pqc --cn "pqc.example.com" --pqc-algorithm "dilithium3" --url "https://your-ztpki-instance.com/api/v2" --hawk-id "your-id" --hawk-key "your-key"
  
  # With multiple SANs and custom validity
  zcert pqc --cn "api.example.com" --pqc-algorithm "mldsa44" --san-dns "example.com" --san-dns "www.example.com" --validity "90d"
  
  # With custom file outputs
  zcert pqc --cn "secure.example.com" --pqc-algorithm "dilithium5" --cert-file "./secure.crt" --key-file "./secure.key"

Usage:
  zcert pqc [flags]

Server & Authentication:
      --hawk-id string    HAWK authentication ID
      --hawk-key string   HAWK authentication key
      --url string        ZTPKI API base URL (e.g., https://ztpki.venafi.com/api/v2)

Certificate Request:
      --cn string                Common Name for the certificate (required)
      --policy string            Policy ID or name for certificate issuance (optional - will show selection if not specified)
      --pqc-algorithm string     PQC algorithm (MLDSA44, MLDSA65, MLDSA87, Dilithium2, Dilithium3, Dilithium5)
      --san-dns strings          DNS Subject Alternative Name (repeatable: --san-dns example.com --san-dns *.example.com)
      --san-email strings        Email Subject Alternative Name (repeatable)
      --san-ip strings           IP Subject Alternative Name (repeatable: --san-ip 10.0.1.1 --san-ip 10.0.0.1)
      --validity string          Certificate validity period (formats: 30d, 6m, 1y or plain number for days)

Certificate Subject (Distinguished Name):
      --country string           Country (C)
      --locality string          Locality/City (L)
      --org strings              Organization (O) (repeatable)
      --ou strings               Organizational Unit (OU) (repeatable: --ou "IT Dep" --ou "Security Team")
      --province string          State/Province (ST)

Output Files:
      --bundle-file string       Combined certificate bundle file path (cert + chain)
      --cert-file string         Certificate output file path
      --chain-file string        Certificate chain output file path
      --key-file string          Private key output file path

Output Format & Security:
      --format string            Output format (pem, p12) (default "pem")
      --no-key-output            Don't output private key to file
      --p12-password string      Password for PKCS#12 bundle format
      --display                  Display private key and certificate on screen
      --chain                    Include certificate chain

Global Flags:
      --config string    profile config file (e.g., zcert.cnf)
  -h, --help             help for pqc
      --profile string   profile name from config file (default: Default)
  -v, --verbose          verbose output (-v for requests and variables, -vv for responses too)
`)
	}
}

func getPQCUsageFunc() func(*cobra.Command) error {
	return func(cmd *cobra.Command) error {
		fmt.Printf("Usage: %s\n", cmd.UseLine())
		fmt.Printf("Run '%s --help' for more information.\n", cmd.CommandPath())
		return nil
	}
}

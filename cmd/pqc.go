package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
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
	pqcCmd.Flags().Bool("verbose", false, "Enable detailed logging")
	pqcCmd.Flags().String("validity", "", "Certificate validity period (30d, 6m, 1y, etc.)")
}

func runPQC(cmd *cobra.Command, args []string) error {
	cfg, err := loadPQCConfig(cmd)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

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

	// Step 5: Automate certificate enrollment
	fmt.Println("[zcert] Submitting CSR for enrollment...")
	enrollArgs := []string{
		"enroll",
		"--config", cfg.ConfigFile,
		"--profile", cfg.Profile,
		"--csr", "file",
		"--csr-file", csrFile,
	}
	// Add output file flags if specified
	if cfg.CertFile != "" {
		enrollArgs = append(enrollArgs, "--cert-file", cfg.CertFile)
	}
	if cfg.KeyFile != "" {
		enrollArgs = append(enrollArgs, "--key-file", cfg.KeyFile)
	}
	if cfg.ChainFile != "" {
		enrollArgs = append(enrollArgs, "--chain-file", cfg.ChainFile)
	}
	if cfg.BundleFile != "" {
		enrollArgs = append(enrollArgs, "--bundle-file", cfg.BundleFile)
	}
	if cfg.Format != "" {
		enrollArgs = append(enrollArgs, "--format", cfg.Format)
	}
	if cfg.Verbose {
		enrollArgs = append(enrollArgs, "--verbose")
	}

	// Add subject fields if specified
	if cfg.CommonName != "" {
		enrollArgs = append(enrollArgs, "--cn", cfg.CommonName)
	}
	if cfg.Country != "" {
		enrollArgs = append(enrollArgs, "--country", cfg.Country)
	}
	if cfg.Province != "" {
		enrollArgs = append(enrollArgs, "--province", cfg.Province)
	}
	if cfg.Locality != "" {
		enrollArgs = append(enrollArgs, "--locality", cfg.Locality)
	}
	for _, org := range cfg.Organizations {
		enrollArgs = append(enrollArgs, "--org", org)
	}
	for _, ou := range cfg.OrganizationalUnits {
		enrollArgs = append(enrollArgs, "--ou", ou)
	}
	for _, san := range cfg.SANDNS {
		enrollArgs = append(enrollArgs, "--san-dns", san)
	}
	for _, san := range cfg.SANIP {
		enrollArgs = append(enrollArgs, "--san-ip", san)
	}
	for _, san := range cfg.SANEmail {
		enrollArgs = append(enrollArgs, "--san-email", san)
	}

	if cfg.Chain {
		enrollArgs = append(enrollArgs, "--chain")
	}

	cmdEnroll := exec.Command(os.Args[0], enrollArgs...)
	cmdEnroll.Stdout = os.Stdout
	cmdEnroll.Stderr = os.Stderr
	if err := cmdEnroll.Run(); err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
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
	cfg := &PQCConfig{}

	// Load configuration file
	configFile, _ := cmd.Flags().GetString("config")
	if configFile == "" {
		configFile = "zcert.cnf"
	}

	// Load profile
	profile, _ := cmd.Flags().GetString("profile")
	if profile == "" {
		profile = "pqc"
	}

	// Load configuration
	profileConfig, err := config.LoadProfileConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load profile config: %w", err)
	}

	// Get the profile section
	profileSection := profileConfig.Profiles[profile]
	if profileSection == nil {
		return nil, fmt.Errorf("profile not found: %s", profile)
	}

	// Map profile config to PQCConfig
	cfg.OpenSSLPath = "./openssl.exe" // Default, can be extended to read from profileSection if needed
	cfg.TempDir = "." // Default, can be extended to read from profileSection if needed
	
	// Get algorithm from CLI flag or profile
	cfg.Algorithm, _ = cmd.Flags().GetString("pqc-algorithm")
	if cfg.Algorithm == "" {
		// Try to get from profile section
		cfg.Algorithm = profileSection.PQCAlgorithm
	}
	if cfg.Algorithm == "" {
		return nil, fmt.Errorf("pqc-algorithm must be specified either via --pqc-algorithm flag or in the selected profile of the config file (profile: %s)", profile)
	}
	
	cfg.Verbose, _ = cmd.Flags().GetBool("verbose")
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
package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"zcert/internal/api"
	"zcert/internal/config"
	"zcert/internal/utils"
)

var (
	// Certificate Request
	enrollCN        string
	enrollSANsDNS   []string
	enrollSANsIP    []string
	enrollSANsEmail []string
	enrollPolicy    string
	enrollValidity  string

	// Certificate Subject (DN Components)
	enrollOrg      []string
	enrollOrgUnit  []string
	enrollLocality string
	enrollProvince string
	enrollCountry  string

	// Key Generation
	enrollKeySize  int
	enrollKeyType  string
	enrollKeyCurve string
	enrollCSRMode  string
	enrollCSRFile  string

	// ZTPKI Authentication
	enrollURL     string
	enrollHawkID  string
	enrollHawkKey string

	// Output Files
	enrollCertFile   string
	enrollKeyFile    string
	enrollChainFile  string
	enrollBundleFile string

	// Output Format & Security
	enrollFormat  string
	enrollKeyPass string
	enrollP12Pass string
	enrollNoKey   bool
	enrollChain   bool
)

// enrollCmd represents the enroll command
var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Request a new certificate from ZTPKI",
	Long: `The enroll command requests a new certificate from the Zero Touch PKI service.
It handles the complete workflow from key generation and CSR creation to certificate 
retrieval and output formatting.

Examples:
  # Using profile configuration (recommended)
  zcert enroll --config zcert.cnf --cn "example.com"
  
  # Command-line authentication
  zcert enroll --cn "example.com" --url "https://your-ztpki-instance.com/api/v2" --hawk-id "your-id" --hawk-key "your-key"
  
  # With multiple SANs and OUs
  zcert enroll --cn "api.example.com" --san-dns "example.com" --san-dns "www.example.com" --ou "IT" --ou "Security" --validity "90d"
  
  # With custom file outputs and encryption
  zcert enroll --cn "secure.example.com" --cert-file "./secure.crt" --key-file "./secure.key" --key-password "secret123"`,
	RunE: runEnroll,
}

func init() {
	rootCmd.AddCommand(enrollCmd)

	// Server & Authentication
	enrollCmd.Flags().StringVar(&enrollURL, "url", "", "ZTPKI API base URL (e.g., https://your-ztpki-instance.com/api/v2)")
	enrollCmd.Flags().StringVar(&enrollHawkID, "hawk-id", "", "HAWK authentication ID")
	enrollCmd.Flags().StringVar(&enrollHawkKey, "hawk-key", "", "HAWK authentication key")

	// Certificate Request
	enrollCmd.Flags().StringVar(&enrollCN, "cn", "", "Common Name for the certificate (required)")
	enrollCmd.Flags().StringSliceVar(&enrollSANsDNS, "san-dns", []string{}, "DNS Subject Alternative Name (repeatable: --san-dns example.com --san-dns *.example.com)")
	enrollCmd.Flags().StringSliceVar(&enrollSANsIP, "san-ip", []string{}, "IP Subject Alternative Name (repeatable: --san-ip 192.168.1.1 --san-ip 10.0.0.1)")
	enrollCmd.Flags().StringSliceVar(&enrollSANsEmail, "san-email", []string{}, "Email Subject Alternative Name (repeatable)")
	enrollCmd.Flags().StringVar(&enrollPolicy, "policy", "", "Policy ID or name for certificate issuance (optional - will show selection if not specified)")
	enrollCmd.Flags().StringVar(&enrollValidity, "validity", "", "Certificate validity period (formats: 30d, 6m, 1y, 30d6m, 1y6m, or plain number for days)")

	// Certificate Subject (Distinguished Name)
	enrollCmd.Flags().StringSliceVar(&enrollOrg, "org", []string{"OmniCorp"}, "Organization (O) (repeatable)")
	enrollCmd.Flags().StringSliceVar(&enrollOrgUnit, "ou", []string{"Cybernetics"}, "Organizational Unit (OU) (repeatable: --ou \"IT Department\" --ou \"Security Team\")")
	enrollCmd.Flags().StringVar(&enrollLocality, "locality", "Detroit", "Locality/City (L)")
	enrollCmd.Flags().StringVar(&enrollProvince, "province", "Michigan", "State/Province (ST)")
	enrollCmd.Flags().StringVar(&enrollCountry, "country", "US", "Country (C)")

	// Key Generation
	enrollCmd.Flags().IntVar(&enrollKeySize, "key-size", 2048, "RSA key size in bits")
	enrollCmd.Flags().StringVar(&enrollKeyType, "key-type", "rsa", "Key type (rsa, ecdsa)")
	enrollCmd.Flags().StringVar(&enrollKeyCurve, "key-curve", "p256", "ECDSA curve (p256, p384, p521)")
	enrollCmd.Flags().StringVar(&enrollCSRMode, "csr", "local", "CSR generation mode (local, file)")
	enrollCmd.Flags().StringVar(&enrollCSRFile, "csr-file", "", "Path to CSR file when using --csr file mode")

	// Output Files
	enrollCmd.Flags().StringVar(&enrollCertFile, "cert-file", "", "Certificate output file path")
	enrollCmd.Flags().StringVar(&enrollKeyFile, "key-file", "", "Private key output file path")
	enrollCmd.Flags().StringVar(&enrollChainFile, "chain-file", "", "Certificate chain output file path")
	enrollCmd.Flags().StringVar(&enrollBundleFile, "bundle-file", "", "Combined certificate bundle file path (cert + chain)")

	// Output Format & Security
	enrollCmd.Flags().StringVar(&enrollFormat, "format", "pem", "Output format (pem, p12)")
	enrollCmd.Flags().StringVar(&enrollKeyPass, "key-password", "", "Password for private key encryption (PEM format)")
	enrollCmd.Flags().StringVar(&enrollP12Pass, "p12-password", "", "Password for PKCS#12 bundle format")
	enrollCmd.Flags().BoolVar(&enrollNoKey, "no-key-output", false, "Don't output private key to file")
	enrollCmd.Flags().BoolVar(&enrollChain, "chain", false, "Include certificate chain")

	// Set custom help and usage functions to group flags consistently
	enrollCmd.SetHelpFunc(getCustomHelpFunc())
	enrollCmd.SetUsageFunc(getEnrollUsageFunc())

	// Bind flags to viper for config file support
	_ = viper.BindPFlag("enroll.cn", enrollCmd.Flags().Lookup("cn"))
	_ = viper.BindPFlag("enroll.policy", enrollCmd.Flags().Lookup("policy"))
	_ = viper.BindPFlag("enroll.key_size", enrollCmd.Flags().Lookup("key-size"))
	_ = viper.BindPFlag("enroll.key_type", enrollCmd.Flags().Lookup("key-type"))
	_ = viper.BindPFlag("enroll.format", enrollCmd.Flags().Lookup("format"))

	// Bind authentication flags
	viper.BindPFlag("ztpki.url", enrollCmd.Flags().Lookup("url"))
	viper.BindPFlag("ztpki.hawk_id", enrollCmd.Flags().Lookup("hawk-id"))
	viper.BindPFlag("ztpki.hawk_key", enrollCmd.Flags().Lookup("hawk-key"))
}

func runEnroll(cmd *cobra.Command, args []string) error {
	// Get global verbose level
	verboseLevel := GetVerboseLevel()

	// Use profile configuration if available
	profile := GetCurrentProfile()

	// Create final configuration following hierarchy: CLI > Config > Environment
	finalProfile := &config.Profile{
		Algo:   "sha256",
		Format: "pem", // default format
	}

	// Step 1: Start with environment variables as base
	if url := os.Getenv("ZTPKI_URL"); url != "" {
		finalProfile.URL = url
	}
	if hawkID := os.Getenv("ZTPKI_HAWK_ID"); hawkID != "" {
		finalProfile.KeyID = hawkID
	}
	if hawkKey := os.Getenv("ZTPKI_HAWK_SECRET"); hawkKey != "" {
		finalProfile.Secret = hawkKey
	}
	if policy := os.Getenv("ZTPKI_POLICY_ID"); policy != "" {
		finalProfile.PolicyID = policy
	}

	// Step 2: Override with config file values if available
	if profile != nil {
		if profile.URL != "" {
			finalProfile.URL = profile.URL
		}
		if profile.KeyID != "" {
			finalProfile.KeyID = profile.KeyID
		}
		if profile.Secret != "" {
			finalProfile.Secret = profile.Secret
		}
		if profile.PolicyID != "" {
			finalProfile.PolicyID = profile.PolicyID
		}
		if profile.Format != "" {
			finalProfile.Format = profile.Format
		}
		if profile.P12Pass != "" {
			finalProfile.P12Pass = profile.P12Pass
		}
		if profile.KeySize > 0 {
			finalProfile.KeySize = profile.KeySize
		} else {
			finalProfile.KeySize = 2048 // default
		}
		if profile.KeyType != "" {
			finalProfile.KeyType = profile.KeyType
		} else {
			finalProfile.KeyType = "rsa" // default
		}
		if profile.Validity > 0 {
			finalProfile.Validity = profile.Validity
		}
		if profile.ValidityString != "" {
			finalProfile.ValidityString = profile.ValidityString
		}
		finalProfile.Chain = profile.Chain
	} else {
		// Set defaults when no profile
		finalProfile.KeySize = 2048
		finalProfile.KeyType = "rsa"
	}

	// Step 3: Override with CLI flags (highest priority)
	if enrollURL != "" {
		finalProfile.URL = enrollURL
	}
	if enrollHawkID != "" {
		finalProfile.KeyID = enrollHawkID
	}
	if enrollHawkKey != "" {
		finalProfile.Secret = enrollHawkKey
	}
	if enrollPolicy != "" {
		finalProfile.PolicyID = enrollPolicy
	}
	if enrollFormat != "" {
		finalProfile.Format = enrollFormat
	}
	if enrollP12Pass != "" {
		finalProfile.P12Pass = enrollP12Pass
	}
	if enrollValidity != "" {
		finalProfile.ValidityString = enrollValidity
	}
	if cmd.Flags().Changed("key-size") {
		finalProfile.KeySize = enrollKeySize
	}
	if cmd.Flags().Changed("key-type") {
		finalProfile.KeyType = enrollKeyType
	}

	// Handle chain flag
	var chainValue bool
	if cmd.Flags().Changed("chain") {
		chainValue, _ = cmd.Flags().GetBool("chain")
	} else {
		chainValue = finalProfile.Chain
	}

	// Validate required authentication parameters
	if finalProfile.URL == "" {
		return fmt.Errorf("ZTPKI URL is required (use --url flag, config file, or ZTPKI_URL environment variable)")
	}
	if finalProfile.KeyID == "" {
		return fmt.Errorf("HAWK ID is required (use --hawk-id flag, config file, or ZTPKI_HAWK_ID environment variable)")
	}
	if finalProfile.Secret == "" {
		return fmt.Errorf("HAWK key is required (use --hawk-key flag, config file, or ZTPKI_HAWK_SECRET environment variable)")
	}

	// Create API client using the utility function
	client, err := CreateAPIClientFromProfile(finalProfile, verboseLevel)
	if err != nil {
		return err
	}

	// Show variable hierarchy in verbose mode (both -v and -vv)
	if verboseLevel > 0 {
		fmt.Printf("\n=== Variable Hierarchy (CLI > Config > Environment) ===\n")

		// ZTPKI URL
		var urlSource string
		if enrollURL != "" {
			urlSource = "CLI"
		} else if profile != nil && profile.URL != "" {
			urlSource = "Config"
		} else if os.Getenv("ZTPKI_URL") != "" {
			urlSource = "Environment"
		} else {
			urlSource = "Not set"
		}
		fmt.Printf("ZTPKI_URL: %s (%s)\n", finalProfile.URL, urlSource)

		// HAWK ID
		var hawkIDSource string
		if enrollHawkID != "" {
			hawkIDSource = "CLI"
		} else if profile != nil && profile.KeyID != "" {
			hawkIDSource = "Config"
		} else if os.Getenv("ZTPKI_HAWK_ID") != "" {
			hawkIDSource = "Environment"
		} else {
			hawkIDSource = "Not set"
		}
		fmt.Printf("ZTPKI_HAWK_ID: %s (%s)\n", finalProfile.KeyID, hawkIDSource)

		// HAWK Secret
		var hawkSecretSource string
		if enrollHawkKey != "" {
			hawkSecretSource = "CLI"
		} else if profile != nil && profile.Secret != "" {
			hawkSecretSource = "Config"
		} else if os.Getenv("ZTPKI_HAWK_SECRET") != "" {
			hawkSecretSource = "Environment"
		} else {
			hawkSecretSource = "Not set"
		}
		fmt.Printf("ZTPKI_HAWK_SECRET: %s (%s)\n", maskSecret(finalProfile.Secret), hawkSecretSource)

		// Policy ID
		var policySource string
		if enrollPolicy != "" {
			policySource = "CLI"
		} else if profile != nil && profile.PolicyID != "" {
			policySource = "Config"
		} else if os.Getenv("ZTPKI_POLICY_ID") != "" {
			policySource = "Environment"
		} else {
			policySource = "Not set"
		}
		fmt.Printf("ZTPKI_POLICY_ID: %s (%s)\n", finalProfile.PolicyID, policySource)
		fmt.Printf("===============================================\n\n")
	}

	// Step 4: Handle policy selection if no policy is specified
	if finalProfile.PolicyID == "" {
		fmt.Println("No policy specified. Fetching available policies...")
		policies, err := client.GetPolicies()
		if err != nil {
			return fmt.Errorf("failed to fetch policies: %w", err)
		}

		if len(policies) == 0 {
			return fmt.Errorf("no policies available")
		}

		fmt.Println("\nAvailable Policies:")
		for i, policy := range policies {
			fmt.Printf("%d. %s (ID: %s)\n", i+1, policy.Name, policy.ID)
		}

		fmt.Print("\nSelect a policy by number (1-", len(policies), "): ")
		var selection int
		_, err = fmt.Scanf("%d", &selection)
		if err != nil || selection < 1 || selection > len(policies) {
			return fmt.Errorf("invalid selection")
		}

		finalProfile.PolicyID = policies[selection-1].ID
		fmt.Printf("Selected policy: %s (ID: %s)\n\n", policies[selection-1].Name, finalProfile.PolicyID)
	}

	// Get configuration values (CLI flags override config/profile)
	cn := enrollCN
	if cn == "" && profile != nil {
		// Could add default CN from profile if needed
	}

	policyID := finalProfile.PolicyID
	keySize := finalProfile.KeySize
	keyType := finalProfile.KeyType
	format := finalProfile.Format

	// Use validity from profile if not provided via CLI flag
	validity := enrollValidity
	if validity == "" {
		if finalProfile.ValidityString != "" {
			validity = finalProfile.ValidityString
		} else if finalProfile.Validity > 0 {
			validity = fmt.Sprintf("%dd", finalProfile.Validity)
		}
	}

	// Handle CSR generation mode first to determine if CN is needed
	csrMode := cmd.Flag("csr").Value.String()

	// Validate required CN parameter (only for local CSR generation)
	if csrMode == "local" && cn == "" {
		return fmt.Errorf("Common Name (CN) is required for local CSR generation (use --cn flag or config file)")
	}

	// Validate key generation parameters
	if keyType == "rsa" {
		if keySize < 2048 {
			return fmt.Errorf("RSA key size must be at least 2048 bits for security")
		}
		if keySize != 2048 && keySize != 3072 && keySize != 4096 {
			return fmt.Errorf("RSA key size must be 2048, 3072, or 4096 bits")
		}
	} else if keyType == "ecdsa" {
		return fmt.Errorf("ECDSA key type is not yet supported")
	} else if keyType != "rsa" {
		return fmt.Errorf("unsupported key type: %s (supported: rsa)", keyType)
	}

	// Validate output format
	if format != "pem" && format != "p12" && format != "jks" {
		return fmt.Errorf("unsupported output format: %s (supported: pem, p12, jks)", format)
	}

	// Parse validity period if provided, otherwise use template maximum
	var validityPeriod *api.ValidityPeriod
	if validity != "" {
		validityPeriod, err = utils.ParseValidityPeriod(validity)
		if err != nil {
			return fmt.Errorf("invalid validity format: %w", err)
		}
	}

	// Create certificate task for API submission
	certTask := &config.CertificateTask{
		Request: config.CertificateRequest{
			Subject: config.CertificateSubject{
				CommonName:   cn,
				Country:      enrollCountry,
				State:        enrollProvince,
				Locality:     enrollLocality,
				Organization: strings.Join(enrollOrg, ","),
				OrgUnits:     enrollOrgUnit,
			},
			Policy: policyID,
			SANs: &config.FlexibleSANs{
				SubjectAltNames: &config.SubjectAltNames{
					DNS:   enrollSANsDNS,
					IP:    enrollSANsIP,
					Email: enrollSANsEmail,
				},
			},
		},
	}

	// Add validity period if specified
	if validityPeriod != nil {
		certTask.Request.Validity = &config.ValidityConfig{
			Years:  validityPeriod.Years,
			Months: validityPeriod.Months,
			Days:   validityPeriod.Days,
		}
	}

	// Handle CSR generation mode
	if csrMode == "local" {
		// Generate CSR locally
		if verboseLevel > 0 {
			fmt.Fprintf(os.Stderr, "Generating CSR locally for CN: %s\n", cn)
		}

		// Generate private key
		keyFile, err := generatePrivateKey(keyType, keySize, enrollKeyCurve, enrollKeyPass)
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}
		defer os.Remove(keyFile) // Clean up temporary key file

		// Generate CSR
		csrFile, err := generateCSR(keyFile, certTask, enrollKeyPass)
		if err != nil {
			return fmt.Errorf("failed to generate CSR: %w", err)
		}
		defer os.Remove(csrFile) // Clean up temporary CSR file

		// Read CSR content
		csrPEM, err := os.ReadFile(csrFile)
		if err != nil {
			return fmt.Errorf("failed to read CSR file: %w", err)
		}

		if verboseLevel > 0 {
			fmt.Fprintf(os.Stderr, "CSR generated successfully: %s\n", csrFile)
		}

		// Use the enrollment workflow function
		certificate, err := client.EnrollmentWorkflow(string(csrPEM), certTask)
		if err != nil {
			return err
		}

		// Retrieve certificate using standardized chain handling
		chainOpts := &utils.ChainRetrievalOptions{
			IncludeChain: chainValue,
			FallbackMode: true,
			VerboseLevel: verboseLevel,
		}

		result, err := utils.RetrieveCertificateWithChainResult(client, certificate.ID, chainOpts)
		if err != nil {
			return err
		}

		certificate = result.Certificate
		certPEM := result.PEMResponse

		if verboseLevel > 0 {
			if result.ChainRetrieved {
				fmt.Fprintf(os.Stderr, "Certificate retrieved with chain\n")
			} else if chainValue && result.FallbackUsed {
				fmt.Fprintf(os.Stderr, "Certificate retrieved without chain (fallback used)\n")
			}
		}

		// Read private key for output
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}

		// Output private key and certificate
		if format == "p12" {
			// Create PKCS#12 bundle
			if enrollP12Pass == "" {
				return fmt.Errorf("p12-password is required when using --format p12")
			}

			// Generate filename based on CN
			p12Filename := cn + ".p12"

			// Create PKCS#12 bundle
			p12Data, err := utils.CreatePKCS12Bundle(keyPEM, []byte(certPEM.Certificate), enrollP12Pass)
			if err != nil {
				return fmt.Errorf("failed to create PKCS#12 bundle: %w", err)
			}

			// Write PKCS#12 file
			if err := os.WriteFile(p12Filename, p12Data, 0600); err != nil {
				return fmt.Errorf("failed to write PKCS#12 file: %w", err)
			}

			if verboseLevel > 0 {
				fmt.Fprintf(os.Stderr, "PKCS#12 bundle written to: %s\n", p12Filename)
			}

		} else {
			// PEM format output - use shared output function
			err = OutputCertificateWithFiles(certPEM, keyPEM, OutputCertificateOptions{
				CertFile:     enrollCertFile,
				KeyFile:      enrollKeyFile,
				ChainFile:    enrollChainFile,
				BundleFile:   enrollBundleFile,
				KeyPassword:  enrollKeyPass,
				NoKeyOutput:  enrollNoKey,
				IncludeChain: chainValue,
				VerboseLevel: verboseLevel,
			})
			if err != nil {
				return fmt.Errorf("failed to output certificate: %w", err)
			}
		}

	} else if csrMode == "file" {
		// Submit existing CSR file
		if enrollCSRFile == "" {
			return fmt.Errorf("--csr-file is required when using --csr file mode")
		}

		csrPEM, err := os.ReadFile(enrollCSRFile)
		if err != nil {
			return fmt.Errorf("failed to read CSR file: %w", err)
		}

		// Use the enrollment workflow function for file mode too
		_, err = client.EnrollmentWorkflow(string(csrPEM), certTask)
		if err != nil {
			return err
		}

		if verboseLevel > 0 {
			fmt.Fprintf(os.Stderr, "Certificate enrollment completed successfully\n")
		}
	} else {
		return fmt.Errorf("unsupported CSR mode: %s (supported: local, file)", csrMode)
	}

	return nil
}

// Help and Usage Functions

func getCustomHelpFunc() func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		fmt.Print(`Request a new certificate from ZTPKI

The enroll command requests a new certificate from the Zero Touch PKI service.
It handles the complete workflow from key generation and CSR creation to certificate 
retrieval and output formatting.

Examples:
  # Using profile configuration (recommended)
  zcert -config zcert.cnf --cn "example.com"
  
  # Command-line authentication
  zcert enroll --cn "example.com" --url "https://your-ztpki-instance.com/api/v2" --hawk-id "your-id" --hawk-key "your-key"
  
  # With multiple SANs and OUs
  zcert enroll --cn "api.example.com" --san-dns "example.com" --san-dns "www.example.com" --ou "IT" --ou "Security" --validity "90d"
  
  # With custom file outputs and encryption
  zcert enroll --cn "secure.example.com" --cert-file "./secure.crt" --key-file "./secure.key" --key-password "secret123"

Usage:
  zcert enroll [flags]

Server & Authentication:
      --hawk-id string    HAWK authentication ID
      --hawk-key string   HAWK authentication key
      --url string        ZTPKI API base URL (e.g., https://ztpki.venafi.com/api/v2)

Certificate Request:
      --cn string                Common Name for the certificate (required)
      --policy string            Policy ID or name for certificate issuance (optional - will show selection if not specified)
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

Key Generation:
      --csr string               CSR generation mode (local, file) (default "local")
      --csr-file string          Path to CSR file when using --csr file mode
      --key-curve string         ECDSA curve (p256, p384, p521) (default "p256")
      --key-size int             RSA key size in bits (default 2048)
      --key-type string          Key type (rsa, ecdsa) (default "rsa")

Output Files:
      --bundle-file string       Combined certificate bundle file path (cert + chain)
      --cert-file string         Certificate output file path
      --chain-file string        Certificate chain output file path
      --key-file string          Private key output file path

Output Format & Security:
      --format string            Output format (pem, p12) (default "pem")
      --key-password string      Password for private key encryption (PEM format)
      --no-key-output            Don't output private key to file
      --p12-password string      Password for PKCS#12 bundle format

Global Flags:
      --config string    profile config file (e.g., zcert.cnf)
  -h, --help             help for enroll
      --profile string   profile name from config file (default: Default)
  -v, --verbose          verbose output (-v for requests and variables, -vv for responses too)

Use "zcert enroll [command] --help" for more information about a command.
`)
	}
}

func getEnrollUsageFunc() func(*cobra.Command) error {
	return func(cmd *cobra.Command) error {
		fmt.Printf("Usage:\n  %s\n\n", cmd.UseLine())
		// ... (rest of the usage function)
		return nil
	}
}

// generatePrivateKey generates a private key and saves it to a temporary file
func generatePrivateKey(keyType string, keySize int, keyCurve, keyPass string) (string, error) {
	var privKey *rsa.PrivateKey
	var err error

	if keyType == "rsa" {
		privKey, err = rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return "", err
		}
	} else {
		// Placeholder for ECDSA key generation
		return "", fmt.Errorf("ECDSA key generation not yet supported")
	}

	keyFile, err := os.CreateTemp("", "zcert-key-*.pem")
	if err != nil {
		return "", err
	}
	defer keyFile.Close()

	var pemBlock *pem.Block
	pemBlock = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}

	if keyPass != "" {
		pemBlock, err = x509.EncryptPEMBlock(rand.Reader, pemBlock.Type, pemBlock.Bytes, []byte(keyPass), x509.PEMCipherAES256)
		if err != nil {
			return "", err
		}
	}

	if err := pem.Encode(keyFile, pemBlock); err != nil {
		return "", err
	}

	return keyFile.Name(), nil
}

// generateCSR generates a CSR from a private key and saves it to a temporary file
func generateCSR(keyFile string, certTask *config.CertificateTask, keyPass string) (string, error) {
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block containing private key")
	}

	var privKey *rsa.PrivateKey
	if x509.IsEncryptedPEMBlock(block) {
		decrypted, err := x509.DecryptPEMBlock(block, []byte(keyPass))
		if err != nil {
			return "", err
		}
		privKey, err = x509.ParsePKCS1PrivateKey(decrypted)
		if err != nil {
			return "", err
		}
	} else {
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
	}

	// Create CSR template
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         certTask.Request.Subject.CommonName,
			Country:            []string{certTask.Request.Subject.Country},
			Province:           []string{certTask.Request.Subject.State},
			Locality:           []string{certTask.Request.Subject.Locality},
			Organization:       []string{certTask.Request.Subject.Organization},
			OrganizationalUnit: certTask.Request.Subject.OrgUnits,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Add SANs
	for _, san := range certTask.Request.SANs.SubjectAltNames.DNS {
		template.DNSNames = append(template.DNSNames, san)
	}
	for _, san := range certTask.Request.SANs.SubjectAltNames.IP {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(san))
	}
	for _, san := range certTask.Request.SANs.SubjectAltNames.Email {
		template.EmailAddresses = append(template.EmailAddresses, san)
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		return "", err
	}

	csrFile, err := os.CreateTemp("", "zcert-csr-*.pem")
	if err != nil {
		return "", err
	}
	defer csrFile.Close()

	if err := pem.Encode(csrFile, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}); err != nil {
		return "", err
	}

	return csrFile.Name(), nil
}

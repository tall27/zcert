package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"zcert/internal/api"
	"zcert/internal/cert"
	"zcert/internal/config"
	policyselect "zcert/internal/policy"
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

	// Set custom help and usage functions to group flags consistently
	enrollCmd.SetHelpFunc(getCustomHelpFunc())
	enrollCmd.SetUsageFunc(getEnrollUsageFunc())

	// Bind flags to viper for config file support
	viper.BindPFlag("enroll.cn", enrollCmd.Flags().Lookup("cn"))
	viper.BindPFlag("enroll.policy", enrollCmd.Flags().Lookup("policy"))
	viper.BindPFlag("enroll.key_size", enrollCmd.Flags().Lookup("key-size"))
	viper.BindPFlag("enroll.key_type", enrollCmd.Flags().Lookup("key-type"))
	viper.BindPFlag("enroll.format", enrollCmd.Flags().Lookup("format"))

	// Bind authentication flags
	viper.BindPFlag("ztpki.url", enrollCmd.Flags().Lookup("url"))
	viper.BindPFlag("ztpki.hawk_id", enrollCmd.Flags().Lookup("hawk-id"))
	viper.BindPFlag("ztpki.hawk_key", enrollCmd.Flags().Lookup("hawk-key"))
}

func runEnroll(cmd *cobra.Command, args []string) error {
	// Use profile configuration if available
	profile := GetCurrentProfile()
	var finalProfile *config.Profile

	if profile != nil {
		// Merge profile with command-line flags (flags take precedence)
		finalProfile = config.MergeProfileWithFlags(
			profile,
			enrollURL, enrollHawkID, enrollHawkKey,
			enrollFormat, enrollPolicy, enrollP12Pass,
			enrollKeySize, enrollKeyType,
		)
	} else {
		// No profile config, use command-line flags or defaults
		finalProfile = &config.Profile{
			URL:      enrollURL,
			KeyID:    enrollHawkID,
			Secret:   enrollHawkKey,
			Algo:     "sha256", // Default algorithm
			Format:   enrollFormat,
			PolicyID: enrollPolicy,
			P12Pass:  enrollP12Pass,
			KeySize:  enrollKeySize,
			KeyType:  enrollKeyType,
		}

		// Set defaults if not provided
		if finalProfile.Format == "" {
			finalProfile.Format = "pem"
		}
		if finalProfile.KeySize == 0 {
			finalProfile.KeySize = 2048
		}
		if finalProfile.KeyType == "" {
			finalProfile.KeyType = "rsa"
		}
	}

	// Validate required authentication parameters
	if finalProfile.URL == "" {
		return fmt.Errorf("ZTPKI URL is required (use --url flag or config file)")
	}
	if finalProfile.KeyID == "" {
		return fmt.Errorf("HAWK ID is required (use --hawk-id flag or config file)")
	}
	if finalProfile.Secret == "" {
		return fmt.Errorf("HAWK key is required (use --hawk-key flag or config file)")
	}

	// Create API client with profile settings
	cfg := &config.Config{
		BaseURL: finalProfile.URL,
		HawkID:  finalProfile.KeyID,
		HawkKey: finalProfile.Secret,
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize API client: %w", err)
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
	if enrollValidity != "" {
		validityPeriod, err = utils.ParseValidityPeriod(enrollValidity)
		if err != nil {
			return fmt.Errorf("invalid validity format: %w", err)
		}
	}
	// If validityPeriod is nil, the API will use template maximum validity

	// Convert validity period to policy type for compatibility checking
	var policyValidityPeriod *policyselect.ValidityPeriod
	if validityPeriod != nil {
		policyValidityPeriod = &policyselect.ValidityPeriod{
			Days:   validityPeriod.Days,
			Months: validityPeriod.Months,
			Years:  validityPeriod.Years,
		}
	}

	// Create user arguments for policy compatibility checking
	userArgs := &policyselect.UserArgs{
		CN:           cn,
		SANsDNS:      enrollSANsDNS,
		SANsIP:       enrollSANsIP,
		SANsEmail:    enrollSANsEmail,
		Validity:     policyValidityPeriod,
		Organization: enrollOrg,
		OrgUnit:      enrollOrgUnit,
		Locality:     enrollLocality,
		Province:     enrollProvince,
		Country:      enrollCountry,
		KeyType:      keyType,
		KeySize:      keySize,
		KeyCurve:     enrollKeyCurve,
	}

	policySelector := policyselect.NewPolicySelector(client)

	// Get or select policy with compatibility checking
	if policyID == "" {
		policyID, err = policySelector.SelectCompatiblePolicy(userArgs)
		if err != nil {
			return fmt.Errorf("failed to select policy: %w", err)
		}
	} else {
		// Validate compatibility when policy is pre-specified
		err = policySelector.ValidatePolicyCompatibility(policyID, userArgs)
		if err != nil {
			return fmt.Errorf("policy %s is incompatible with your certificate requirements: %w", policyID, err)
		}
	}

	if viper.GetBool("verbose") {
		fmt.Fprintf(os.Stderr, "Enrolling certificate with CN: %s, Policy: %s\n", cn, policyID)
	}

	var csrPEM []byte
	var privateKey interface{}

	// Handle CSR generation based on mode determined above

	if csrMode == "local" {
		// Generate private key locally
		if viper.GetBool("verbose") {
			fmt.Fprintln(os.Stderr, "Generating private key...")
		}

		if keyType == "rsa" {
			privateKey, err = rsa.GenerateKey(rand.Reader, keySize)
			if err != nil {
				return fmt.Errorf("failed to generate RSA private key: %w", err)
			}
		} else {
			return fmt.Errorf("unsupported key type: %s", keyType)
		}

		// Create CSR
		if viper.GetBool("verbose") {
			fmt.Fprintln(os.Stderr, "Creating Certificate Signing Request...")
		}

		// Prepare SAN values - combine all DNS SANs
		var dnsNames []string
		dnsNames = append(dnsNames, enrollSANsDNS...)

		// Prepare IP addresses
		var ipAddresses []net.IP
		for _, ipStr := range enrollSANsIP {
			if ip := net.ParseIP(ipStr); ip != nil {
				ipAddresses = append(ipAddresses, ip)
			}
		}

		// Prepare email addresses
		var emailAddresses []string
		emailAddresses = append(emailAddresses, enrollSANsEmail...)

		template := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:         cn,
				Organization:       enrollOrg,
				OrganizationalUnit: enrollOrgUnit,
				Locality:           []string{enrollLocality},
				Province:           []string{enrollProvince},
				Country:            []string{enrollCountry},
			},
			DNSNames:       dnsNames,
			IPAddresses:    ipAddresses,
			EmailAddresses: emailAddresses,
		}

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
		if err != nil {
			return fmt.Errorf("failed to create CSR: %w", err)
		}

		csrPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		})
	} else if csrMode == "file" {
		// Read CSR from file
		if enrollCSRFile == "" {
			return fmt.Errorf("CSR file path required when using --csr file mode. Use --csr-file flag")
		}

		if viper.GetBool("verbose") {
			fmt.Fprintf(os.Stderr, "Reading CSR from file: %s\n", enrollCSRFile)
		}

		csrPEM, err = os.ReadFile(enrollCSRFile)
		if err != nil {
			return fmt.Errorf("failed to read CSR file: %w", err)
		}

		// Validate CSR format
		block, _ := pem.Decode(csrPEM)
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			return fmt.Errorf("invalid CSR file format. Expected PEM-encoded CERTIFICATE REQUEST")
		}
	} else {
		return fmt.Errorf("invalid CSR mode: %s. Use 'local' or 'file'", csrMode)
	}

	// Submit CSR to ZTPKI
	if viper.GetBool("verbose") {
		fmt.Fprintln(os.Stderr, "Submitting CSR to ZTPKI...")
	}

	requestID, err := client.SubmitCSR(string(csrPEM), policyID, validityPeriod)
	if err != nil {
		return fmt.Errorf("failed to submit CSR: %w", err)
	}

	if viper.GetBool("verbose") {
		fmt.Fprintf(os.Stderr, "CSR submitted successfully. Request ID: %s\n", requestID)
		fmt.Fprintln(os.Stderr, "Polling for certificate issuance...")
	}

	// Poll for certificate request completion
	var certificate *api.Certificate

	// Immediate polling with 2-second timeout
	if viper.GetBool("verbose") {
		fmt.Fprintln(os.Stderr, "Starting immediate certificate polling with 2-second timeout...")
	}

	// Create context with 2-second timeout for the entire operation
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Continuous polling until timeout or success
	ticker := time.NewTicker(50 * time.Millisecond) // Poll every 50ms for faster response
	defer ticker.Stop()

	attemptCount := 0
	for {
		select {
		case <-ctx.Done():
			if viper.GetBool("verbose") {
				fmt.Fprintf(os.Stderr, "Certificate polling timed out after 2 seconds (attempted %d times)\n", attemptCount)
			}
			goto timeout_reached
		case <-ticker.C:
			attemptCount++
			if viper.GetBool("verbose") && attemptCount%20 == 1 { // Log every second (20 * 50ms)
				fmt.Fprintf(os.Stderr, "Polling attempt %d...\n", attemptCount)
			}

			// First, check the request status to get certificate ID
			request, err := client.GetCertificateRequest(requestID)
			if err != nil {
				if viper.GetBool("verbose") {
					fmt.Fprintf(os.Stderr, "Error checking request status (attempt %d): %v\n", attemptCount, err)
				}
				continue
			}

			if request != nil && request.CertificateID != "" {
				if viper.GetBool("verbose") {
					fmt.Fprintf(os.Stderr, "Request status: %s, Certificate ID: %s (attempt %d)\n", request.Status, request.CertificateID, attemptCount)
				}

				// Request completed, now get the actual certificate
				certificate, err = client.GetCertificate(request.CertificateID)
				if err == nil && certificate != nil && certificate.Certificate != "" {
					if viper.GetBool("verbose") {
						fmt.Fprintf(os.Stderr, "Certificate retrieved successfully after %d attempts! Certificate ID: %s\n", attemptCount, request.CertificateID)
					}
					goto certificate_ready
				} else if err != nil {
					if viper.GetBool("verbose") {
						fmt.Fprintf(os.Stderr, "Error retrieving certificate (attempt %d): %v\n", attemptCount, err)
					}
				}
			}
		}
	}

timeout_reached:
certificate_ready:

	if certificate == nil {
		// Fallback: Try to get certificate directly by request ID (some APIs use this pattern)
		if viper.GetBool("verbose") {
			fmt.Fprintf(os.Stderr, "Trying fallback approach: getting certificate directly by request ID...\n")
		}
		certificate, err := client.GetCertificate(requestID)
		if err == nil && certificate != nil && certificate.Certificate != "" {
			if viper.GetBool("verbose") {
				fmt.Fprintf(os.Stderr, "Certificate retrieved via fallback method!\n")
			}
		} else {
			return fmt.Errorf("certificate was not issued within the expected time frame (40 seconds). The certificate may still be processing on the server")
		}
	}

	if viper.GetBool("verbose") {
		fmt.Fprintln(os.Stderr, "Certificate issued successfully!")
	}

	// Output certificate with enhanced options
	outputter := cert.NewOutputter(format, "", enrollP12Pass)

	// Set custom file paths if provided
	if enrollCertFile != "" || enrollKeyFile != "" || enrollChainFile != "" || enrollBundleFile != "" {
		return outputter.OutputCertificateToFiles(certificate, privateKey, !enrollNoKey, cert.OutputOptions{
			CertFile:    enrollCertFile,
			KeyFile:     enrollKeyFile,
			ChainFile:   enrollChainFile,
			BundleFile:  enrollBundleFile,
			KeyPassword: enrollKeyPass,
		})
	}

	// Standard output behavior
	return outputter.OutputCertificate(certificate, privateKey, !enrollNoKey)
}

// Helper functions to get configuration values with precedence: CLI flag > config file > default
func getStringValue(configKey, flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return viper.GetString(configKey)
}

func getIntValue(configKey string, flagValue int) int {
	if cmd, _, _ := rootCmd.Find(os.Args[1:]); cmd != nil {
		if flag := cmd.Flags().Lookup(strings.Split(configKey, ".")[1]); flag != nil && flag.Changed {
			return flagValue
		}
	}
	if viper.IsSet(configKey) {
		return viper.GetInt(configKey)
	}
	return flagValue
}

// getCustomHelpFunc returns a custom help function that groups flags
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
      --country string     Country (C) 
      --locality string    Locality/City (L) 
      --org strings        Organization (O) (repeatable) 
      --ou strings         Organizational Unit (OU) (repeatable: --ou "IT Department" --ou "Security Team")
      --province string    State/Province (ST) 

Key Generation:
      --csr string         CSR generation mode (local, file) (default "local")
      --csr-file string    Path to CSR file when using --csr file mode
      --key-curve string   ECDSA curve (p256, p384, p521) (default "p256")
      --key-size int       RSA key size in bits (default 2048)
      --key-type string    Key type (rsa, ecdsa) (default "rsa")

Output Files:
      --bundle-file string   Combined certificate bundle file path (cert + chain)
      --cert-file string     Certificate output file path
      --chain-file string    Certificate chain output file path
      --key-file string      Private key output file path

Output Format & Security:
      --format string        Output format (pem, p12) (default "pem")
      --key-password string  Password for private key encryption (PEM format)
      --no-key-output        Don't output private key to file
      --p12-password string  Password for PKCS#12 bundle format

Global Flags:
      --config string    profile config file (e.g., zcert.cnf)
  -h, --help             help for enroll
      --profile string   profile name from config file (default: Default)
      --verbose          verbose output

Use "zcert enroll [command] --help" for more information about a command.
`)
	}
}

// getEnrollUsageFunc returns a custom usage function that groups flags
func getEnrollUsageFunc() func(*cobra.Command) error {
	return func(cmd *cobra.Command) error {
		fmt.Printf("Usage:\n  %s\n\nServer & Authentication:\n", cmd.UseLine())
		fmt.Printf("      --hawk-id string    HAWK authentication ID\n")
		fmt.Printf("      --hawk-key string   HAWK authentication key\n")
		fmt.Printf("      --url string        ZTPKI API base URL (e.g., https://your-ztpki-instance.com/api/v2)\n\n")

		fmt.Printf("Certificate Request:\n")
		fmt.Printf("      --cn string                Common Name for the certificate (required)\n")
		fmt.Printf("      --policy string            Policy ID or name for certificate issuance (optional)\n")
		fmt.Printf("      --san-dns strings          DNS Subject Alternative Name \n")
		fmt.Printf("      --san-email strings        Email Subject Alternative Name \n")
		fmt.Printf("      --san-ip strings           IP Subject Alternative Name \n")
		fmt.Printf("      --validity string          Certificate validity period \n\n")

		fmt.Printf("Certificate Subject (Distinguished Name):\n")
		fmt.Printf("      --country string     Country (C) (default \"US\")\n")
		fmt.Printf("      --locality string    Locality/City (L) (default \"Chicago\")\n")
		fmt.Printf("      --org strings        Organization (O) (default [OmniCorp])\n")
		fmt.Printf("      --ou strings         Organizational Unit (OU) (default [Cybernetics])\n")
		fmt.Printf("      --province string    State/Province (ST) (default \"Illinois\")\n\n")

		fmt.Printf("Key Generation:\n")
		fmt.Printf("      --csr string         CSR generation mode (local, file) (default \"local\")\n")
		fmt.Printf("      --csr-file string    Path to CSR file when using --csr file mode\n")
		fmt.Printf("      --key-curve string   ECDSA curve (p256, p384, p521) (default \"p256\")\n")
		fmt.Printf("      --key-size int       RSA key size in bits (default 2048)\n")
		fmt.Printf("      --key-type string    Key type (rsa, ecdsa) (default \"rsa\")\n\n")

		fmt.Printf("Output Files:\n")
		fmt.Printf("      --bundle-file string   Combined certificate bundle file path (cert + chain)\n")
		fmt.Printf("      --cert-file string     Certificate output file path\n")
		fmt.Printf("      --chain-file string    Certificate chain output file path\n")
		fmt.Printf("      --key-file string      Private key output file path\n\n")

		fmt.Printf("Output Format & Security:\n")
		fmt.Printf("      --format string        Output format (pem, p12) (default \"pem\")\n")
		fmt.Printf("      --key-password string  Password for private key encryption (PEM format)\n")
		fmt.Printf("      --p12-password string  Password for PKCS#12 bundle format\n\n")

		fmt.Printf("Global Flags:\n")
		fmt.Printf("      --config string    profile config file (e.g., zcert.cnf)\n")
		fmt.Printf("      --profile string   profile name from config file (default: Default)\n")
		fmt.Printf("  -h, --help             help for enroll\n")
		fmt.Printf("      --verbose          verbose output\n")

		return nil
	}
}

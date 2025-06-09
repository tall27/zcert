package cmd

import (
        "crypto/rand"
        "crypto/rsa"
        "crypto/x509"
        "crypto/x509/pkix"
        "encoding/pem"
        "fmt"
        "os"
        "strings"
        "time"

        "github.com/spf13/cobra"
        "github.com/spf13/viper"
        "zcert/internal/api"
        "zcert/internal/cert"
        "zcert/internal/config"
        policyselect "zcert/internal/policy"
)

var (
        enrollCN       string
        enrollSANs     []string
        enrollPolicy   string
        enrollKeySize  int
        enrollKeyType  string
        enrollFormat   string
        enrollOutfile  string
        enrollP12Pass  string
        enrollNoKey    bool
        enrollCSRMode  string
        // ZTPKI Authentication
        enrollURL      string
        enrollKeyID    string
        enrollSecret   string
        enrollAlgo     string
)

// enrollCmd represents the enroll command
var enrollCmd = &cobra.Command{
        Use:   "enroll",
        Short: "Request a new certificate from ZTPKI",
        Long: `The enroll command requests a new certificate from the Zero Touch PKI service.
It handles the complete workflow from key generation and CSR creation to certificate 
retrieval and output formatting.

The tool can generate a private key and Certificate Signing Request (CSR) locally,
submit it to ZTPKI, poll for certificate issuance, and output the certificate in
various formats including PEM, PKCS#12, and Java Keystore.

Authentication to ZTPKI requires HAWK credentials:
  --url        ZTPKI API base URL (e.g., https://ztpki-dev.venafi.com/api/v2)
  --key-id     Your HAWK authentication key ID
  --secret     Your HAWK authentication secret
  --algo       HAWK algorithm (default: sha256)

Examples:
  # Using profile configuration (recommended)
  zcert -config zcert.cnf --cn "example.com"
  zcert -config zcert.cnf -profile p12 --cn "example.com"
  zcert -config zcert.cnf -profile prod --cn "prod.example.com"
  
  # Command-line authentication (all parameters required)
  zcert enroll --cn "example.com" --url "https://ztpki-dev.venafi.com/api/v2" --key-id "your-key-id" --secret "your-secret"
  
  # Generate example configuration file
  zcert config --example
  
  # Mixed mode: profile for auth, command-line for specific options
  zcert -config zcert.cnf --cn "app.company.com" --format "p12" --p12-password "secret123"`,
        RunE: runEnroll,
}

func init() {
        rootCmd.AddCommand(enrollCmd)

        // Certificate subject flags
        enrollCmd.Flags().StringVar(&enrollCN, "cn", "", "Common Name for the certificate")
        enrollCmd.Flags().StringSliceVar(&enrollSANs, "sans", []string{}, "Subject Alternative Names (comma-separated)")
        
        // Policy and authentication
        enrollCmd.Flags().StringVar(&enrollPolicy, "policy", "", "Policy ID or name for certificate issuance")
        
        // ZTPKI Authentication flags
        enrollCmd.Flags().StringVar(&enrollURL, "url", "", "ZTPKI API base URL (e.g., https://ztpki-dev.venafi.com/api/v2)")
        enrollCmd.Flags().StringVar(&enrollKeyID, "key-id", "", "HAWK authentication key ID")
        enrollCmd.Flags().StringVar(&enrollKeyID, "hawk-id", "", "HAWK authentication ID (alias for key-id)")
        enrollCmd.Flags().StringVar(&enrollSecret, "secret", "", "HAWK authentication secret")
        enrollCmd.Flags().StringVar(&enrollSecret, "hawk-key", "", "HAWK authentication key (alias for secret)")
        enrollCmd.Flags().StringVar(&enrollAlgo, "algo", "sha256", "HAWK algorithm (sha1, sha256)")
        
        // Key generation options
        enrollCmd.Flags().IntVar(&enrollKeySize, "key-size", 2048, "RSA key size in bits")
        enrollCmd.Flags().StringVar(&enrollKeyType, "key-type", "rsa", "Key type (rsa, ecdsa)")
        enrollCmd.Flags().StringVar(&enrollCSRMode, "csr", "local", "CSR generation mode (local, file)")
        enrollCmd.Flags().String("csr-file", "", "Path to CSR file when using --csr file mode")
        
        // Output options
        enrollCmd.Flags().StringVar(&enrollFormat, "format", "pem", "Output format (pem, p12, jks)")
        enrollCmd.Flags().StringVar(&enrollOutfile, "file", "", "Output file path")
        enrollCmd.Flags().StringVar(&enrollP12Pass, "p12-password", "", "Password for PKCS#12 format")
        enrollCmd.Flags().BoolVar(&enrollNoKey, "no-key-output", false, "Don't output private key to file")

        // Bind flags to viper for config file support
        viper.BindPFlag("enroll.cn", enrollCmd.Flags().Lookup("cn"))
        viper.BindPFlag("enroll.policy", enrollCmd.Flags().Lookup("policy"))
        viper.BindPFlag("enroll.key_size", enrollCmd.Flags().Lookup("key-size"))
        viper.BindPFlag("enroll.key_type", enrollCmd.Flags().Lookup("key-type"))
        viper.BindPFlag("enroll.format", enrollCmd.Flags().Lookup("format"))
        
        // Bind authentication flags
        viper.BindPFlag("ztpki.url", enrollCmd.Flags().Lookup("url"))
        viper.BindPFlag("ztpki.key_id", enrollCmd.Flags().Lookup("key-id"))
        viper.BindPFlag("ztpki.secret", enrollCmd.Flags().Lookup("secret"))
        viper.BindPFlag("ztpki.algo", enrollCmd.Flags().Lookup("algo"))
}

func runEnroll(cmd *cobra.Command, args []string) error {
        // Use profile configuration if available
        profile := GetCurrentProfile()
        var finalProfile *config.Profile
        
        if profile != nil {
                // Merge profile with command-line flags (flags take precedence)
                finalProfile = config.MergeProfileWithFlags(
                        profile,
                        enrollURL, enrollKeyID, enrollSecret, enrollAlgo,
                        enrollFormat, enrollPolicy, enrollP12Pass,
                        enrollKeySize, enrollKeyType,
                )
        } else {
                // No profile config, use command-line flags or defaults
                finalProfile = &config.Profile{
                        URL:      enrollURL,
                        KeyID:    enrollKeyID,
                        Secret:   enrollSecret,
                        Algo:     enrollAlgo,
                        Format:   enrollFormat,
                        PolicyID: enrollPolicy,
                        P12Pass:  enrollP12Pass,
                        KeySize:  enrollKeySize,
                        KeyType:  enrollKeyType,
                }
                
                // Set defaults if not provided
                if finalProfile.Algo == "" {
                        finalProfile.Algo = "sha256"
                }
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
                return fmt.Errorf("HAWK key ID is required (use --key-id flag or config file)")
        }
        if finalProfile.Secret == "" {
                return fmt.Errorf("HAWK secret is required (use --secret flag or config file)")
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

        // Get or select policy
        if policyID == "" {
                fmt.Println("No policy specified. Please select a policy from the available options:")
                policySelector := policyselect.NewPolicySelector(client)
                policyID, err = policySelector.SelectPolicy()
                if err != nil {
                        return fmt.Errorf("failed to select policy: %w", err)
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

                template := x509.CertificateRequest{
                        Subject: pkix.Name{
                                CommonName:         cn,
                                Organization:       []string{"OmniCorp"},
                                OrganizationalUnit: []string{"Cybernetics"},
                                Locality:           []string{"Detroit"},
                                Province:           []string{"Michigan"},
                                Country:            []string{"US"},
                        },
                        DNSNames: enrollSANs,
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
                csrFile := cmd.Flag("csr-file").Value.String()
                if csrFile == "" {
                        return fmt.Errorf("CSR file path required when using --csr file mode. Use --csr-file flag")
                }

                if viper.GetBool("verbose") {
                        fmt.Fprintf(os.Stderr, "Reading CSR from file: %s\n", csrFile)
                }

                csrPEM, err = os.ReadFile(csrFile)
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

        requestID, err := client.SubmitCSR(string(csrPEM), policyID)
        if err != nil {
                return fmt.Errorf("failed to submit CSR: %w", err)
        }

        if viper.GetBool("verbose") {
                fmt.Fprintf(os.Stderr, "CSR submitted successfully. Request ID: %s\n", requestID)
                fmt.Fprintln(os.Stderr, "Polling for certificate issuance...")
        }

        // Poll for certificate
        var certificate *api.Certificate
        maxAttempts := 30
        pollInterval := 2 * time.Second

        for i := 0; i < maxAttempts; i++ {
                certificate, err = client.GetCertificate(requestID)
                if err == nil && certificate != nil {
                        break
                }

                if i < maxAttempts-1 {
                        if viper.GetBool("verbose") {
                                fmt.Fprintf(os.Stderr, "Certificate not ready yet, waiting %v...\n", pollInterval)
                        }
                        time.Sleep(pollInterval)
                }
        }

        if certificate == nil {
                return fmt.Errorf("certificate was not issued within the expected time frame")
        }

        if viper.GetBool("verbose") {
                fmt.Fprintln(os.Stderr, "Certificate issued successfully!")
        }

        // Output certificate
        outputter := cert.NewOutputter(format, enrollOutfile, enrollP12Pass)
        
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

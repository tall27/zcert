package cmd

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
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
	cfg.Verbose = verboseLevel > 0

	// Ensure key file is set
	if cfg.KeyFile == "" {
		cfg.KeyFile = "mldsa44.key"
	}

	// Create PQC generator with correct signature
	generator := cert.NewPQCGenerator(cfg.OpenSSLPath, cfg.TempDir, cfg.Verbose, cfg.NoCleanup, cfg.LegacyAlgNames, cfg.LegacyPQCAlgorithm)

	// Generate PQC key
	keyFile, err := generator.GenerateKey(cfg.Algorithm)
	if err != nil {
		return fmt.Errorf("failed to generate PQC key: %w", err)
	}
	if !cfg.NoCleanup {
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
	if !cfg.NoCleanup {
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
	
	// Validate format
	format := cfg.Format
	if format != "pem" && format != "p12" {
		return fmt.Errorf("unsupported output format: %s (supported: pem, p12)", format)
	}
	
	// Handle PKCS#12 format
	if format == "p12" {
		if cfg.P12Password == "" {
			return fmt.Errorf("p12-password is required when using --format p12")
		}
		
		// Read private key for PKCS#12 bundle
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read private key for PKCS#12 bundle: %w", err)
		}
		
		// Create PKCS#12 filename
		p12Filename := cfg.CertFile
		if p12Filename == "" {
			p12Filename = cfg.CommonName + ".p12"
		}
		
		// Create PKCS#12 bundle
		p12Data, err := createPKCS12Bundle(keyPEM, []byte(certPEM.Certificate), cfg.P12Password)
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
		
		// Don't output individual files when using PKCS#12 format
		return nil
	}
	
	// PEM format output
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
	
	// Handle private key output
	if !cfg.NoKeyOutput && keyFile != "" {
		// Read the generated private key
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}
		
		// Determine key output filename
		keyOutputFile := cfg.KeyFile
		if keyOutputFile == "" {
			keyOutputFile = cfg.CommonName + ".key"
		}
		
		// Handle key encryption if password is provided
		if cfg.KeyPassword != "" {
			// Parse the private key
			keyBlock, _ := pem.Decode(keyPEM)
			if keyBlock == nil {
				return fmt.Errorf("failed to decode private key PEM")
			}
			
			// Decrypt if already encrypted, then re-encrypt with new password
			var privateKey interface{}
			if x509.IsEncryptedPEMBlock(keyBlock) {
				privateKey, err = decryptPrivateKey(keyBlock, "")
				if err != nil {
					return fmt.Errorf("failed to decrypt existing private key: %w", err)
				}
			} else {
				// Parse unencrypted key
				privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse private key: %w", err)
				}
			}
			
			// Encrypt with new password
			encryptedKey, err := encryptPrivateKey(privateKey.(*rsa.PrivateKey), cfg.KeyPassword)
			if err != nil {
				return fmt.Errorf("failed to encrypt private key: %w", err)
			}
			
			// Write encrypted key
			if err := os.WriteFile(keyOutputFile, encryptedKey, 0600); err != nil {
				return fmt.Errorf("failed to write encrypted private key: %w", err)
			}
		} else {
			// Write unencrypted key
			if err := os.WriteFile(keyOutputFile, keyPEM, 0600); err != nil {
				return fmt.Errorf("failed to write private key: %w", err)
			}
		}
		
		if verboseLevel > 0 {
			fmt.Fprintf(os.Stderr, "Private key written to: %s\n", keyOutputFile)
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
	
	cfg.NoCleanup = profileSection.NoCleanup // Read NoCleanup from the profile section
	cfg.LegacyAlgNames = profileSection.LegacyAlgNames
	cfg.LegacyPQCAlgorithm = profileSection.LegacyPQCAlgorithm

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

// encryptPrivateKey encrypts a private key with a password using DES-EDE3-CBC
func encryptPrivateKey(key *rsa.PrivateKey, password string) ([]byte, error) {
	// Generate random salt
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	
	// Derive key from password and salt using MD5
	keyBytes := deriveKey(password, salt)
	
	// Create DES-EDE3-CBC cipher
	block, err := des.NewTripleDESCipher(keyBytes[:24])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	
	// Encrypt the private key
	keyData := x509.MarshalPKCS1PrivateKey(key)
	paddedData := pkcs7Pad(keyData, block.BlockSize())
	
	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, keyBytes[:8])
	mode.CryptBlocks(ciphertext, paddedData)
	
	// Create PEM block with encryption info
	blockType := "RSA PRIVATE KEY"
	headers := map[string]string{
		"Proc-Type": "4,ENCRYPTED",
		"DEK-Info":  fmt.Sprintf("DES-EDE3-CBC,%s", hex.EncodeToString(salt)),
	}
	
	pemBlock := &pem.Block{
		Type:    blockType,
		Headers: headers,
		Bytes:   ciphertext,
	}
	
	return pem.EncodeToMemory(pemBlock), nil
}

// deriveKey derives a 24-byte key from password and salt using OpenSSL's method
func deriveKey(password string, salt []byte) []byte {
	// OpenSSL's EVP_BytesToKey with MD5: iteratively hash password+salt to get 24 bytes
	key := make([]byte, 24)
	hash := md5.New()
	
	// First iteration: hash password + salt
	hash.Write([]byte(password))
	hash.Write(salt)
	copy(key[:16], hash.Sum(nil))
	
	// Second iteration: hash previous result + password + salt
	hash.Reset()
	hash.Write(key[:16])
	hash.Write([]byte(password))
	hash.Write(salt)
	copy(key[16:], hash.Sum(nil)[:8])
	
	return key
}

// pkcs7Pad adds PKCS#7 padding to data
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// decryptPrivateKey decrypts a private key with a password using DES-EDE3-CBC
func decryptPrivateKey(block *pem.Block, password string) (interface{}, error) {
	if !x509.IsEncryptedPEMBlock(block) {
		return nil, fmt.Errorf("PEM block is not encrypted")
	}
	
	// Extract salt from DEK-Info header
	dekInfo := block.Headers["DEK-Info"]
	if dekInfo == "" {
		return nil, fmt.Errorf("missing DEK-Info header in encrypted private key")
	}
	
	parts := strings.Split(dekInfo, ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid DEK-Info format")
	}
	
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid salt in DEK-Info: %w", err)
	}
	
	// Derive key from password and salt using MD5
	keyBytes := deriveKey(password, salt)
	
	// Create DES-EDE3-CBC cipher
	cipherBlock, err := des.NewTripleDESCipher(keyBytes[:24])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	
	// Decrypt the private key
	plaintext := make([]byte, len(block.Bytes))
	mode := cipher.NewCBCDecrypter(cipherBlock, keyBytes[:8])
	mode.CryptBlocks(plaintext, block.Bytes)
	
	// Remove PKCS#7 padding
	plaintext = pkcs7Unpad(plaintext)
	
	// Parse the private key
	privateKey, err := x509.ParsePKCS1PrivateKey(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted private key: %w", err)
	}
	
	return privateKey, nil
}

// pkcs7Unpad removes PKCS#7 padding from data
func pkcs7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding > len(data) {
		return data
	}
	return data[:len(data)-padding]
}

// createPKCS12Bundle creates a PKCS#12 bundle with the certificate and private key
func createPKCS12Bundle(keyPEM, certPEM []byte, password string) ([]byte, error) {
	// Parse the private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}
	
	var privateKey interface{}
	var err error
	
	if x509.IsEncryptedPEMBlock(keyBlock) {
		// Decrypt the private key
		privateKey, err = decryptPrivateKey(keyBlock, password)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
	} else {
		// Parse unencrypted private key
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}
	
	// Parse the certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	
	// Create PKCS#12 bundle
	p12Data, err := pkcs12.Encode(rand.Reader, privateKey, cert, nil, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create PKCS#12 bundle: %w", err)
	}
	
	return p12Data, nil
} 
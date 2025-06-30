package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"zcert/internal/api"
	"zcert/internal/config"
	"zcert/internal/utils"
)

// getStringValue gets a string value from Viper, falling back to a default if not set.
func getStringValue(key, defaultValue string) string {
	if viper.IsSet(key) {
		return viper.GetString(key)
	}
	return defaultValue
}

// getIntValue gets an int value from Viper, falling back to a default if not set.
func getIntValue(key string, defaultValue int) int {
	if viper.IsSet(key) {
		return viper.GetInt(key)
	}
	return defaultValue
}

// flagChanged is a helper to check if a flag was explicitly set by the user.
func flagChanged(cmd *cobra.Command, name string) bool {
	return cmd.Flags().Changed(name)
}

func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode())
}

// CreateAPIClientFromProfile creates an API client from a profile with standardized error handling
// This consolidates the common pattern used across all commands
func CreateAPIClientFromProfile(profile *config.Profile, verboseLevel int) (*api.Client, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile cannot be nil")
	}

	// Validate required authentication parameters
	if profile.URL == "" {
		return nil, fmt.Errorf("ZTPKI URL is required (use --url flag, config file, or ZTPKI_URL environment variable)")
	}
	if profile.KeyID == "" {
		return nil, fmt.Errorf("HAWK ID is required (use --hawk-id flag, config file, or ZTPKI_HAWK_ID environment variable)")
	}
	if profile.Secret == "" {
		return nil, fmt.Errorf("HAWK key is required (use --hawk-key flag, config file, or ZTPKI_HAWK_SECRET environment variable)")
	}

	// Create API client configuration
	cfg := &config.Config{
		BaseURL: profile.URL,
		HawkID:  profile.KeyID,
		HawkKey: profile.Secret,
	}

	// Create and return the API client
	client, err := api.NewClientWithVerbose(cfg, verboseLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize API client: %w", err)
	}

	return client, nil
}

// convertPEMResponseToCertificate converts API CertificatePEMResponse to Certificate format for output
func convertPEMResponseToCertificate(pemResp *api.CertificatePEMResponse, cert *api.Certificate) *api.Certificate {
	if pemResp == nil {
		return cert
	}

	// Create a new certificate object with PEM format and chain
	result := &api.Certificate{
		ID:          cert.ID,
		CommonName:  cert.CommonName,
		Certificate: pemResp.Certificate,
		Status:      cert.Status,
		CreatedDate: cert.CreatedDate,
		ExpiryDate:  cert.ExpiryDate,
	}

	// Add chain if available
	if pemResp.Chain != "" {
		// Split the chain into individual certificates if needed
		result.Chain = []string{pemResp.Chain}
	}

	return result
}

// OutputCertificateOptions provides options for certificate output
type OutputCertificateOptions struct {
	CertFile     string // Certificate output file path
	KeyFile      string // Private key output file path
	ChainFile    string // Certificate chain output file path
	BundleFile   string // Combined certificate bundle file path (cert + chain)
	KeyPassword  string // Password for private key encryption
	NoKeyOutput  bool   // Don't output private key
	IncludeChain bool   // Whether to include chain in stdout output
	VerboseLevel int    // Verbose level for feedback
}

// OutputCertificateWithFiles outputs certificate and private key to files and/or stdout
// This is the shared function used by both enroll and PQC commands
func OutputCertificateWithFiles(certPEM *api.CertificatePEMResponse, keyPEM []byte, options OutputCertificateOptions) error {
	// Handle private key output
	if !options.NoKeyOutput && keyPEM != nil {
		if options.KeyFile != "" {
			// Write key to file
			var keyToWrite []byte
			var err error
			
			if options.KeyPassword != "" {
				// Encrypt the key if password is provided
				keyToWrite, err = utils.EncryptPEMBlock(keyPEM, options.KeyPassword)
				if err != nil {
					return fmt.Errorf("failed to encrypt private key: %w", err)
				}
			} else {
				keyToWrite = keyPEM
			}
			
			if err := os.WriteFile(options.KeyFile, keyToWrite, 0600); err != nil {
				return fmt.Errorf("failed to write private key file: %w", err)
			}
			if options.VerboseLevel > 0 {
				fmt.Fprintf(os.Stderr, "Private key written to: %s\n", options.KeyFile)
			}
		} else {
			// Output key to stdout
			fmt.Print(string(keyPEM))
		}
	}

	// Write certificate file if specified
	if options.CertFile != "" {
		if err := os.WriteFile(options.CertFile, []byte(certPEM.Certificate), 0644); err != nil {
			return fmt.Errorf("failed to write certificate file: %w", err)
		}
		if options.VerboseLevel > 0 {
			fmt.Fprintf(os.Stderr, "Certificate written to: %s\n", options.CertFile)
		}
	}

	// Write chain file if specified and chain is available
	if options.ChainFile != "" && certPEM.Chain != "" {
		if err := os.WriteFile(options.ChainFile, []byte(certPEM.Chain), 0644); err != nil {
			return fmt.Errorf("failed to write chain file: %w", err)
		}
		if options.VerboseLevel > 0 {
			fmt.Fprintf(os.Stderr, "Certificate chain written to: %s\n", options.ChainFile)
		}
	}

	// Write bundle file if specified (cert + chain)
	if options.BundleFile != "" {
		bundleContent := certPEM.Certificate
		if certPEM.Chain != "" {
			bundleContent += certPEM.Chain
		}
		if err := os.WriteFile(options.BundleFile, []byte(bundleContent), 0644); err != nil {
			return fmt.Errorf("failed to write bundle file: %w", err)
		}
		if options.VerboseLevel > 0 {
			fmt.Fprintf(os.Stderr, "Certificate bundle written to: %s\n", options.BundleFile)
		}
	}

	// Output certificate to stdout if no cert file specified
	if options.CertFile == "" {
		// Add empty line before certificate if key was output to stdout
		if !options.NoKeyOutput && keyPEM != nil && options.KeyFile == "" {
			fmt.Println("")
		}
		fmt.Println(certPEM.Certificate)
	}

	// Output chain certificates if available and requested
	if options.IncludeChain && certPEM.Chain != "" {
		fmt.Println(certPEM.Chain)
	}

	return nil
}
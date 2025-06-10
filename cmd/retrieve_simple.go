package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"zcert/internal/api"
	"zcert/internal/config"
)

var (
	retrieveSimpleID     string
	retrieveSimpleURL    string
	retrieveSimpleKeyID  string
	retrieveSimpleSecret string
	retrieveSimpleFormat string
	retrieveSimpleFile   string
)

// retrieveSimpleCmd represents a simplified retrieve command for ZTPKI
var retrieveSimpleCmd = &cobra.Command{
	Use:   "retrieve-simple",
	Short: "Retrieve an issued certificate from ZTPKI by request ID",
	Long: `Retrieve an issued certificate from ZTPKI using the CSR request ID.
This command fetches certificates that have been successfully issued by the ZTPKI service.

Example:
  zcert retrieve-simple --id b7a0c295-d875-4d32-a30d-8a825fb4dfaa --url https://ztpki-dev.venafi.com/api/v2 --key-id YOUR_HAWK_ID --secret YOUR_HAWK_SECRET`,
	RunE: runRetrieveSimple,
}

func init() {
	rootCmd.AddCommand(retrieveSimpleCmd)

	// Required flags
	retrieveSimpleCmd.Flags().StringVar(&retrieveSimpleID, "id", "", "Certificate request ID (required)")
	retrieveSimpleCmd.Flags().StringVar(&retrieveSimpleURL, "url", "", "ZTPKI API base URL")
	retrieveSimpleCmd.Flags().StringVar(&retrieveSimpleKeyID, "key-id", "", "HAWK authentication key ID")
	retrieveSimpleCmd.Flags().StringVar(&retrieveSimpleSecret, "secret", "", "HAWK authentication secret")
	
	// Optional flags
	retrieveSimpleCmd.Flags().StringVar(&retrieveSimpleFormat, "format", "pem", "Output format (pem)")
	retrieveSimpleCmd.Flags().StringVar(&retrieveSimpleFile, "file", "", "Output file path (default: stdout)")
	
	// Mark required flags
	retrieveSimpleCmd.MarkFlagRequired("id")
}

func runRetrieveSimple(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg := config.GetConfig()
	
	// Override with command-line flags
	if retrieveSimpleURL != "" {
		cfg.BaseURL = retrieveSimpleURL
	}
	if retrieveSimpleKeyID != "" {
		cfg.HawkID = retrieveSimpleKeyID
	}
	if retrieveSimpleSecret != "" {
		cfg.HawkKey = retrieveSimpleSecret
	}
	
	// Validate required parameters
	if cfg.BaseURL == "" {
		return fmt.Errorf("ZTPKI URL is required (use --url or config file)")
	}
	if cfg.HawkID == "" {
		return fmt.Errorf("HAWK ID is required (use --key-id or config file)")
	}
	if cfg.HawkKey == "" {
		return fmt.Errorf("HAWK secret is required (use --secret or config file)")
	}
	
	// Initialize API client
	client, err := api.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize API client: %w", err)
	}
	
	if viper.GetBool("verbose") {
		fmt.Fprintf(os.Stderr, "Retrieving certificate for request ID: %s\n", retrieveSimpleID)
	}
	
	// Check certificate status first
	status, err := client.GetCSRStatus(retrieveSimpleID)
	if err != nil {
		return fmt.Errorf("failed to check certificate status: %w", err)
	}
	
	if viper.GetBool("verbose") {
		fmt.Fprintf(os.Stderr, "Certificate status: %s\n", status.IssuanceStatus)
	}
	
	if status.IssuanceStatus != "ISSUED" {
		return fmt.Errorf("certificate not yet issued, current status: %s", status.IssuanceStatus)
	}
	
	// Retrieve the certificate
	certificate, err := client.GetCertificate(retrieveSimpleID)
	if err != nil {
		return fmt.Errorf("failed to retrieve certificate: %w", err)
	}
	
	if viper.GetBool("verbose") {
		fmt.Fprintf(os.Stderr, "Certificate retrieved successfully:\n")
		fmt.Fprintf(os.Stderr, "  ID: %s\n", certificate.ID)
		fmt.Fprintf(os.Stderr, "  CN: %s\n", certificate.CommonName)
		fmt.Fprintf(os.Stderr, "  Serial: %s\n", certificate.Serial)
		fmt.Fprintf(os.Stderr, "  Expires: %s\n", certificate.NotAfter.Format("2006-01-02 15:04:05"))
	}
	
	// Output certificate
	if retrieveSimpleFile != "" {
		// Write to file
		err := os.WriteFile(retrieveSimpleFile, []byte(certificate.Certificate), 0644)
		if err != nil {
			return fmt.Errorf("failed to write certificate to file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Certificate written to: %s\n", retrieveSimpleFile)
	} else {
		// Write to stdout
		fmt.Print(certificate.Certificate)
	}
	
	return nil
}
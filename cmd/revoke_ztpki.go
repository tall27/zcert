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
	revokeZTPKIID     string
	revokeZTPKIURL    string
	revokeZTPKIKeyID  string
	revokeZTPKISecret string
	revokeZTPKIReason string
	revokeZTPKIForce  bool
)

// revokeZTPKICmd represents the ZTPKI certificate revocation command
var revokeZTPKICmd = &cobra.Command{
	Use:   "revoke-ztpki",
	Short: "Revoke a certificate in ZTPKI",
	Long: `Revoke an active certificate in ZTPKI by certificate ID.
This command will mark the certificate as revoked and provide a revocation reason.

Example:
  zcert revoke-ztpki --id CERT_ID --reason cessationOfOperation --url https://ztpki-dev.venafi.com/api/v2 --key-id YOUR_HAWK_ID --secret YOUR_HAWK_SECRET`,
	RunE: runRevokeZTPKI,
}

func init() {
	rootCmd.AddCommand(revokeZTPKICmd)

	// Required flags
	revokeZTPKICmd.Flags().StringVar(&revokeZTPKIID, "id", "", "Certificate ID to revoke (required)")
	revokeZTPKICmd.Flags().StringVar(&revokeZTPKIURL, "url", "", "ZTPKI API base URL")
	revokeZTPKICmd.Flags().StringVar(&revokeZTPKIKeyID, "key-id", "", "HAWK authentication key ID")
	revokeZTPKICmd.Flags().StringVar(&revokeZTPKISecret, "secret", "", "HAWK authentication secret")
	
	// Revocation options
	revokeZTPKICmd.Flags().StringVar(&revokeZTPKIReason, "reason", "cessationOfOperation", "Revocation reason")
	revokeZTPKICmd.Flags().BoolVar(&revokeZTPKIForce, "force", false, "Skip confirmation prompt")
	
	// Mark required flags
	revokeZTPKICmd.MarkFlagRequired("id")
}

func runRevokeZTPKI(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg := config.GetConfig()
	
	// Override with command-line flags
	if revokeZTPKIURL != "" {
		cfg.BaseURL = revokeZTPKIURL
	}
	if revokeZTPKIKeyID != "" {
		cfg.HawkID = revokeZTPKIKeyID
	}
	if revokeZTPKISecret != "" {
		cfg.HawkKey = revokeZTPKISecret
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
		fmt.Fprintf(os.Stderr, "Revoking certificate: %s\n", revokeZTPKIID)
		fmt.Fprintf(os.Stderr, "Revocation reason: %s\n", revokeZTPKIReason)
	}
	
	// Get certificate information before revocation
	certificate, err := client.GetCertificateInfo(revokeZTPKIID)
	if err != nil {
		return fmt.Errorf("failed to retrieve certificate information: %w", err)
	}
	
	// Check if certificate is already revoked
	if certificate.RevocationStatus != "VALID" {
		return fmt.Errorf("certificate is already in revocation status: %s", certificate.RevocationStatus)
	}
	
	// Display certificate information
	fmt.Fprintf(os.Stderr, "Certificate to revoke:\n")
	fmt.Fprintf(os.Stderr, "  ID: %s\n", certificate.ID)
	fmt.Fprintf(os.Stderr, "  Common Name: %s\n", certificate.CommonName)
	fmt.Fprintf(os.Stderr, "  Serial Number: %s\n", certificate.Serial)
	fmt.Fprintf(os.Stderr, "  Issuer: %s\n", certificate.IssuerDN)
	fmt.Fprintf(os.Stderr, "  Expires: %s\n", certificate.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(os.Stderr, "  Current Status: %s\n", certificate.RevocationStatus)
	
	// Confirmation prompt unless --force is used
	if !revokeZTPKIForce {
		fmt.Fprintf(os.Stderr, "\nAre you sure you want to revoke this certificate? (y/N): ")
		var response string
		fmt.Scanln(&response)
		
		if response != "y" && response != "Y" && response != "yes" && response != "YES" {
			fmt.Println("Certificate revocation cancelled.")
			return nil
		}
	}
	
	// Perform revocation
	if viper.GetBool("verbose") {
		fmt.Fprintf(os.Stderr, "Submitting revocation request to ZTPKI...\n")
	}
	
	err = client.RevokeCertificate(revokeZTPKIID, revokeZTPKIReason)
	if err != nil {
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}
	
	// Success message
	fmt.Printf("Certificate revocation initiated successfully:\n")
	fmt.Printf("  Certificate ID: %s\n", certificate.ID)
	fmt.Printf("  Common Name: %s\n", certificate.CommonName)
	fmt.Printf("  Serial Number: %s\n", certificate.Serial)
	fmt.Printf("  Revocation Reason: %s\n", revokeZTPKIReason)
	fmt.Printf("  Status: PENDING (revocation in progress)\n")
	
	if viper.GetBool("verbose") {
		fmt.Fprintf(os.Stderr, "Revocation request completed successfully.\n")
		fmt.Fprintf(os.Stderr, "Note: Revocation may take some time to propagate through the PKI infrastructure.\n")
	}
	
	return nil
}
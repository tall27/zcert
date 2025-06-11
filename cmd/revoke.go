package cmd

import (
        "fmt"
        "os"

        "github.com/spf13/cobra"
        "github.com/spf13/viper"
        "zcert/internal/api"
        "zcert/internal/config"
        "zcert/internal/utils"
)

var (
        revokeID       string
        revokeCN       string
        revokeSerial   string
        revokeReason   string
        revokeForce    bool
        // ZTPKI Authentication
        revokeURL      string
        revokeKeyID    string
        revokeSecret   string
        revokeAlgo     string
)

// revokeCmd represents the revoke command
var revokeCmd = &cobra.Command{
        Use:   "revoke",
        Short: "Revoke an existing certificate",
        Long: `The revoke command revokes an issued certificate through the ZTPKI API.
This operation is typically irreversible and will immediately invalidate the certificate.

You can identify the certificate to revoke by its ID, Common Name, or serial number.
A confirmation prompt will be displayed unless the --force flag is used.`,
        RunE: runRevoke,
}

func init() {
        rootCmd.AddCommand(revokeCmd)

        // Certificate identification flags
        revokeCmd.Flags().StringVar(&revokeID, "id", "", "Certificate ID or GUID")
        revokeCmd.Flags().StringVar(&revokeCN, "cn", "", "Common Name of the certificate")
        revokeCmd.Flags().StringVar(&revokeSerial, "serial", "", "Certificate serial number")
        
        // ZTPKI Authentication flags
        revokeCmd.Flags().StringVar(&revokeURL, "url", "", "ZTPKI API base URL (e.g., https://api.ztpki.venafi.com)")
        revokeCmd.Flags().StringVar(&revokeKeyID, "key-id", "", "HAWK authentication key ID")
        revokeCmd.Flags().StringVar(&revokeSecret, "secret", "", "HAWK authentication secret")
        revokeCmd.Flags().StringVar(&revokeAlgo, "algo", "sha256", "HAWK algorithm (sha1, sha256)")
        
        // Revocation options
        revokeCmd.Flags().StringVar(&revokeReason, "reason", "unspecified", "Revocation reason")
        revokeCmd.Flags().BoolVar(&revokeForce, "force", false, "Skip confirmation prompt")
}

func runRevoke(cmd *cobra.Command, args []string) error {
        cfg := config.GetConfig()
        
        // Initialize API client
        client, err := api.NewClient(cfg)
        if err != nil {
                return fmt.Errorf("failed to initialize API client: %w", err)
        }

        // Validate that at least one identifier is provided
        if revokeID == "" && revokeCN == "" && revokeSerial == "" {
                return fmt.Errorf("must specify at least one certificate identifier (--id, --cn, or --serial)")
        }

        if viper.GetBool("verbose") {
                fmt.Fprintln(os.Stderr, "Looking up certificate for revocation...")
        }

        var certificate *api.Certificate

        // Find the certificate to revoke
        if revokeID != "" {
                if viper.GetBool("verbose") {
                        fmt.Fprintf(os.Stderr, "Looking up certificate by ID: %s\n", revokeID)
                }
                certificate, err = client.GetCertificate(revokeID)
                if err != nil {
                        return fmt.Errorf("failed to find certificate by ID: %w", err)
                }
        } else {
                // Search for certificate by other criteria
                searchParams := api.CertificateSearchParams{
                        CommonName: revokeCN,
                        Serial:     revokeSerial,
                }

                if viper.GetBool("verbose") {
                        fmt.Fprintf(os.Stderr, "Searching for certificate with criteria: CN=%s, Serial=%s\n", 
                                revokeCN, revokeSerial)
                }

                certificates, err := client.SearchCertificates(searchParams)
                if err != nil {
                        return fmt.Errorf("failed to search for certificates: %w", err)
                }

                if len(certificates) == 0 {
                        return fmt.Errorf("no certificates found matching the specified criteria")
                }

                if len(certificates) > 1 {
                        fmt.Fprintf(os.Stderr, "Error: Multiple certificates found (%d):\n", len(certificates))
                        for i, cert := range certificates {
                                fmt.Fprintf(os.Stderr, "  [%d] ID: %s, CN: %s, Serial: %s\n", 
                                        i+1, cert.ID, cert.CommonName, cert.Serial)
                        }
                        return fmt.Errorf("multiple certificates found, use --id to specify which one to revoke")
                }

                certificate = &certificates[0]
        }

        if certificate == nil {
                return fmt.Errorf("certificate not found")
        }

        // Display certificate information
        fmt.Fprintf(os.Stderr, "Certificate to revoke:\n")
        fmt.Fprintf(os.Stderr, "  ID: %s\n", certificate.ID)
        fmt.Fprintf(os.Stderr, "  Common Name: %s\n", certificate.CommonName)
        fmt.Fprintf(os.Stderr, "  Serial Number: %s\n", certificate.Serial)
        fmt.Fprintf(os.Stderr, "  Issuer: %s\n", certificate.IssuerDN)
        fmt.Fprintf(os.Stderr, "  Expires: %s\n", certificate.NotAfter)

        // Confirmation prompt unless --force is used
        if !revokeForce {
                confirmed, err := utils.PromptConfirm(
                        fmt.Sprintf("Are you sure you want to revoke certificate CN=%s?", certificate.CommonName),
                        false)
                if err != nil {
                        return fmt.Errorf("failed to get confirmation: %w", err)
                }
                
                if !confirmed {
                        fmt.Fprintln(os.Stderr, "Revocation cancelled.")
                        return nil
                }
        }

        if viper.GetBool("verbose") {
                fmt.Fprintf(os.Stderr, "Revoking certificate %s with reason: %s\n", certificate.ID, revokeReason)
        }

        // Perform revocation
        err = client.RevokeCertificate(certificate.ID, revokeReason)
        if err != nil {
                return fmt.Errorf("failed to revoke certificate: %w", err)
        }

        fmt.Printf("Certificate successfully revoked:\n")
        fmt.Printf("  ID: %s\n", certificate.ID)
        fmt.Printf("  Common Name: %s\n", certificate.CommonName)
        fmt.Printf("  Serial Number: %s\n", certificate.Serial)
        fmt.Printf("  Revocation Reason: %s\n", revokeReason)

        if viper.GetBool("verbose") {
                fmt.Fprintln(os.Stderr, "Revocation completed successfully.")
        }

        return nil
}

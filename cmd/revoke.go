package cmd

import (
        "fmt"
        "os"

        "github.com/spf13/cobra"
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
        revokeFirst    bool
        revokeWide     bool
        // ZTPKI Authentication
        revokeURL      string
        revokeHawkID   string
        revokeHawkKey  string

)

// promptRevocationReason displays an interactive menu for selecting revocation reason
func promptRevocationReason() (string, error) {
        fmt.Fprintf(os.Stderr, "\nSelect revocation reason:\n")
        fmt.Fprintf(os.Stderr, "0. Unspecified\n")
        fmt.Fprintf(os.Stderr, "1. Key Compromise\n")
        fmt.Fprintf(os.Stderr, "3. Affiliation Changed\n")
        fmt.Fprintf(os.Stderr, "4. Superseded\n")
        fmt.Fprintf(os.Stderr, "5. Cessation Of Operation\n")
        fmt.Fprintf(os.Stderr, "Enter your choice (0-5): ")
        
        var choice string
        _, err := fmt.Scanln(&choice)
        if err != nil {
                return "", fmt.Errorf("failed to read input: %w", err)
        }
        
        switch choice {
        case "0":
                return "unspecified", nil
        case "1":
                return "keyCompromise", nil
        case "2":
                fmt.Fprintf(os.Stderr, "Option 2 not valid, selecting 3 (affiliationChanged)\n")
                return "affiliationChanged", nil
        case "3":
                return "affiliationChanged", nil
        case "4":
                return "superseded", nil
        case "5":
                return "cessationOfOperation", nil
        default:
                fmt.Fprintf(os.Stderr, "Invalid choice '%s', using 'unspecified'\n", choice)
                return "unspecified", nil
        }
}

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
        revokeCmd.Flags().StringVar(&revokeURL, "url", "", "ZTPKI API base URL (e.g., https://your-ztpki-instance.com/api/v2)")
        revokeCmd.Flags().StringVar(&revokeHawkID, "hawk-id", "", "HAWK authentication ID")
        revokeCmd.Flags().StringVar(&revokeHawkKey, "hawk-key", "", "HAWK authentication key")

        
        // Revocation options
        revokeCmd.Flags().StringVar(&revokeReason, "reason", "unspecified", "Revocation reason (unspecified, keyCompromise, affiliationChanged, superseded, cessationOfOperation)")
        revokeCmd.Flags().BoolVar(&revokeForce, "force", false, "Skip confirmation prompt")
        revokeCmd.Flags().BoolVar(&revokeFirst, "first", false, "Automatically select the first certificate when multiple matches found")
        revokeCmd.Flags().BoolVar(&revokeWide, "wide", false, "Show full column content without truncation")

        // Set custom help and usage functions to group flags consistently
        revokeCmd.SetHelpFunc(getRevokeHelpFunc())
        revokeCmd.SetUsageFunc(getRevokeUsageFunc())
}

func runRevoke(cmd *cobra.Command, args []string) error {
        // Get global verbose level
        verboseLevel := GetVerboseLevel()

        // Use profile configuration if available
        profile := GetCurrentProfile()
        var finalProfile *config.Profile
        
        if profile != nil {
                finalProfile = config.MergeProfileWithFlags(
                        profile,
                        revokeURL, revokeHawkID, revokeHawkKey,
                        "", "", "", // format, policy, p12password not needed for revoke
                        0, "", // keysize, keytype not needed for revoke
                )
        } else {
                // Fallback to environment variables if CLI flags are not set
                url := revokeURL
                if url == "" {
                        url = os.Getenv("ZTPKI_URL")
                }
                hawkID := revokeHawkID
                if hawkID == "" {
                        hawkID = os.Getenv("ZTPKI_HAWK_ID")
                }
                hawkKey := revokeHawkKey
                if hawkKey == "" {
                        hawkKey = os.Getenv("ZTPKI_HAWK_SECRET")
                }
                finalProfile = &config.Profile{
                        URL:    url,
                        KeyID:  hawkID,
                        Secret: hawkKey,
                        Algo:   "sha256",
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

        client, err := api.NewClientWithVerbose(cfg, verboseLevel)
        if err != nil {
                return fmt.Errorf("failed to initialize API client: %w", err)
        }

        // Show variable hierarchy in verbose mode (both -v and -vv)
        if verboseLevel > 0 {
                fmt.Printf("\n=== Variable Hierarchy (CLI > Config > Environment) ===\n")
                
                // ZTPKI URL
                var urlSource string
                if revokeURL != "" {
                        urlSource = "CLI"
                } else if profile != nil && profile.URL != "" {
                        urlSource = "Config"
                } else if os.Getenv("ZTPKI_URL") != "" {
                        urlSource = "ENV Variable"
                } else {
                        urlSource = "Not set"
                }
                fmt.Printf("ZTPKI_URL - %s - %s\n", urlSource, finalProfile.URL)

                // HAWK ID
                var hawkIDSource string
                if revokeHawkID != "" {
                        hawkIDSource = "CLI"
                } else if profile != nil && profile.KeyID != "" {
                        hawkIDSource = "Config"
                } else if os.Getenv("ZTPKI_HAWK_ID") != "" {
                        hawkIDSource = "ENV Variable"
                } else {
                        hawkIDSource = "Not set"
                }
                fmt.Printf("ZTPKI_HAWK_ID - %s - %s\n", hawkIDSource, finalProfile.KeyID)

                // HAWK Secret
                var hawkSecretSource string
                if revokeHawkKey != "" {
                        hawkSecretSource = "CLI"
                } else if profile != nil && profile.Secret != "" {
                        hawkSecretSource = "Config"
                } else if os.Getenv("ZTPKI_HAWK_SECRET") != "" {
                        hawkSecretSource = "ENV Variable"
                } else {
                        hawkSecretSource = "Not set"
                }
                fmt.Printf("ZTPKI_HAWK_SECRET - %s - %s\n", hawkSecretSource, maskSecret(finalProfile.Secret))
                fmt.Printf("===============================================\n\n")
        }

        // Validate that at least one identifier is provided
        if revokeID == "" && revokeCN == "" && revokeSerial == "" {
                return fmt.Errorf("must specify at least one certificate identifier (--id, --cn, or --serial)")
        }

        if verboseLevel > 0 {
                fmt.Fprintln(os.Stderr, "Looking up certificate for revocation...")
        }

        var certificate *api.Certificate

        // Find the certificate to revoke
        if revokeID != "" {
                if verboseLevel > 0 {
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

                if verboseLevel > 0 {
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
                        if revokeFirst {
                                // Use first certificate when --first flag is specified
                                fmt.Fprintf(os.Stderr, "Multiple certificates found (%d), using the first one (--first flag specified):\n", len(certificates))
                                fmt.Fprintf(os.Stderr, "  Selected: ID: %s, CN: %s, Serial: %s\n", 
                                        certificates[0].ID, certificates[0].CommonName, certificates[0].SerialNumber)
                                certificate = &certificates[0]
                        } else {
                                // Use interactive selection if multiple certificates found
                                selectedCert, err := utils.SelectCertificate(certificates, "Multiple certificates found", revokeWide)
                                if err != nil {
                                        return fmt.Errorf("certificate selection failed: %w", err)
                                }
                                certificate = selectedCert
                        }
                } else {
                        certificate = &certificates[0]
                }
        }

        if certificate == nil {
                return fmt.Errorf("certificate not found")
        }

        // Display certificate information
        fmt.Fprintf(os.Stderr, "Certificate to revoke:\n")
        fmt.Fprintf(os.Stderr, "  ID: %s\n", certificate.ID)
        fmt.Fprintf(os.Stderr, "  Common Name: %s\n", certificate.CommonName)
        fmt.Fprintf(os.Stderr, "  Serial Number: %s\n", certificate.SerialNumber)
        fmt.Fprintf(os.Stderr, "  Issuer: %s\n", certificate.Issuer)
        fmt.Fprintf(os.Stderr, "  Expires: %s\n", certificate.ExpiryDate)

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
                
                // After confirmation, prompt for revocation reason if not specified
                if revokeReason == "unspecified" {
                        selectedReason, err := promptRevocationReason()
                        if err != nil {
                                return fmt.Errorf("failed to get revocation reason: %w", err)
                        }
                        revokeReason = selectedReason
                }
        }

        if verboseLevel > 0 {
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
        fmt.Printf("  Serial Number: %s\n", certificate.SerialNumber)
        fmt.Printf("  Revocation Reason: %s\n", revokeReason)

        if verboseLevel > 0 {
                fmt.Fprintln(os.Stderr, "Revocation completed successfully.")
        }

        return nil
}

// getRevokeUsageFunc returns a custom usage function that groups flags
func getRevokeUsageFunc() func(*cobra.Command) error {
        return func(cmd *cobra.Command) error {
                fmt.Printf("Usage:\n  %s\n\nServer & Authentication:\n", cmd.UseLine())
                fmt.Printf("      --url string        ZTPKI API base URL (e.g., https://your-ztpki-instance.com/api/v2)\n")
                fmt.Printf("      --hawk-id string    HAWK authentication ID\n")
                fmt.Printf("      --hawk-key string   HAWK authentication key\n\n")
                
                fmt.Printf("Certificate Identification:\n")
                fmt.Printf("      --id string         Certificate ID or GUID\n")
                fmt.Printf("      --cn string         Common Name of the certificate\n")
                fmt.Printf("      --serial string     Certificate serial number\n\n")
                
                fmt.Printf("Revocation Options:\n")
                fmt.Printf("      --reason string     Revocation reason (default \"unspecified\")\n")
                fmt.Printf("      --force             Skip confirmation prompt\n")
                fmt.Printf("      --first             Automatically select first certificate when multiple found\n")
                fmt.Printf("      --wide              Show full column content without truncation\n\n")
                
                fmt.Printf("Global Flags:\n")
                fmt.Printf("      --config string     profile config file (e.g., zcert.cnf)\n")
                fmt.Printf("      --profile string    profile name from config file (default: Default)\n")
                fmt.Printf("  -h, --help              help for revoke\n")
                fmt.Printf("  -v, --verbose           verbose output (-v for requests and variables, -vv for responses too)\n")
                
                return nil
        }
}

// getRevokeHelpFunc returns a custom help function that groups flags
func getRevokeHelpFunc() func(*cobra.Command, []string) {
        return func(cmd *cobra.Command, args []string) {
                fmt.Print(`The revoke command revokes an issued certificate through the ZTPKI API.
This operation is typically irreversible and will immediately invalidate the certificate.

You can identify the certificate to revoke by its ID, Common Name, or serial number.
A confirmation prompt will be displayed unless the --force flag is used.

Examples:
  zcert revoke --id "12345"
  zcert revoke --cn "example.com" --reason "key-compromise"
  zcert revoke --serial "ABC123" --force

Usage:
  zcert revoke [flags]

Server & Authentication:
      --url string        ZTPKI API base URL (e.g., https://your-ztpki-instance.com/api/v2)
      --hawk-id string    HAWK authentication ID
      --hawk-key string   HAWK authentication key

Certificate Identification:
      --id string         Certificate ID or GUID
      --cn string         Common Name of the certificate
      --serial string     Certificate serial number

Revocation Options:
      --reason string     Revocation reason (default "unspecified")
      --force             Skip confirmation prompt
      --first             Automatically select first certificate when multiple found
      --wide              Show full column content without truncation

Global Flags:
      --config string     profile config file (e.g., zcert.cnf)
      --profile string    profile name from config file (default: Default)
  -h, --help              help for revoke
  -v, --verbose           verbose output (-v for requests and variables, -vv for responses too)

Use "zcert revoke [command] --help" for more information about a command.
`)
        }
}

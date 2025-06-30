package cmd

import (
        "fmt"
        "os"

        "github.com/spf13/cobra"
        "github.com/spf13/viper"
        "zcert/internal/api"
        "zcert/internal/cert"
        "zcert/internal/config"
        "zcert/internal/utils"
)

var (
        retrieveID       string
        retrieveCN       string
        retrieveSerial   string
        retrievePolicy   string
        retrieveFormat   string
        retrieveOutfile  string
        retrieveP12Pass  string
        retrieveChain    bool
        retrieveFirst    bool
        retrieveWide     bool
        // ZTPKI Authentication
        retrieveURL      string
        retrieveHawkID   string
        retrieveHawkKey  string

)

// retrieveCmd represents the retrieve command
var retrieveCmd = &cobra.Command{
        Use:   "retrieve",
        Short: "Retrieve an existing certificate from ZTPKI",
        Long: `The retrieve command fetches an existing certificate from the Zero Touch PKI system.
You can retrieve a certificate by specifying its ID, Common Name, serial number, or other
identifying information.

The certificate can be output in various formats including PEM, PKCS#12, and Java Keystore.
If a certificate chain is available, it can also be included in the output.`,
        RunE: runRetrieve,
}

func init() {
        rootCmd.AddCommand(retrieveCmd)

        // Certificate identification flags
        retrieveCmd.Flags().StringVar(&retrieveID, "id", "", "Certificate ID or GUID")
        retrieveCmd.Flags().StringVar(&retrieveCN, "cn", "", "Common Name of the certificate")
        retrieveCmd.Flags().StringVar(&retrieveSerial, "serial", "", "Certificate serial number")
        retrieveCmd.Flags().StringVar(&retrievePolicy, "policy", "", "Policy ID or name to filter by")
        
        // ZTPKI Authentication flags
        retrieveCmd.Flags().StringVar(&retrieveURL, "url", "", "ZTPKI API base URL (e.g., https://your-ztpki-instance.com/api/v2)")
        retrieveCmd.Flags().StringVar(&retrieveHawkID, "hawk-id", "", "HAWK authentication ID")
        retrieveCmd.Flags().StringVar(&retrieveHawkKey, "hawk-key", "", "HAWK authentication key")

        
        // Output options
        retrieveCmd.Flags().StringVar(&retrieveFormat, "format", "pem", "Output format (pem, p12, jks)")
        retrieveCmd.Flags().StringVar(&retrieveOutfile, "file", "", "Output file path")
        retrieveCmd.Flags().StringVar(&retrieveP12Pass, "p12-password", "", "Password for PKCS#12 format")
        retrieveCmd.Flags().BoolVar(&retrieveChain, "chain", false, "Include certificate chain")
        retrieveCmd.Flags().BoolVar(&retrieveFirst, "first", false, "Automatically select the first certificate when multiple matches found")
        retrieveCmd.Flags().BoolVar(&retrieveWide, "wide", false, "Show full column content without truncation")

        // Set custom help and usage functions to group flags consistently
        retrieveCmd.SetHelpFunc(getRetrieveHelpFunc())
        retrieveCmd.SetUsageFunc(getRetrieveUsageFunc())

        // Bind flags to viper
        viper.BindPFlag("retrieve.format", retrieveCmd.Flags().Lookup("format"))
        viper.BindPFlag("retrieve.chain", retrieveCmd.Flags().Lookup("chain"))
}

func runRetrieve(cmd *cobra.Command, args []string) error {
        // Get global verbose level
        verboseLevel := GetVerboseLevel()

        // Use profile configuration if available
        profile := GetCurrentProfile()
        var finalProfile *config.Profile
        
        if profile != nil {
                finalProfile = config.MergeProfileWithFlags(
                        profile,
                        retrieveURL, retrieveHawkID, retrieveHawkKey,
                        retrieveFormat, "", retrieveP12Pass,
                        0, "", // keysize, keytype not needed for retrieve
                )
        } else {
                // Fallback to environment variables if CLI flags are not set
                url := retrieveURL
                if url == "" {
                        url = os.Getenv("ZTPKI_URL")
                }
                hawkID := retrieveHawkID
                if hawkID == "" {
                        hawkID = os.Getenv("ZTPKI_HAWK_ID")
                }
                hawkKey := retrieveHawkKey
                if hawkKey == "" {
                        hawkKey = os.Getenv("ZTPKI_HAWK_SECRET")
                }
                format := retrieveFormat
                if format == "" {
                        format = "pem"
                }
                finalProfile = &config.Profile{
                        URL:    url,
                        KeyID:  hawkID,
                        Secret: hawkKey,
                        Algo:   "sha256",
                        Format: format,
                }
        }

        // Validate required authentication parameters
        if finalProfile.URL == "" {
                return utils.NewAuthURLError()
        }
        if finalProfile.KeyID == "" {
                return utils.NewAuthHawkIDError()
        }
        if finalProfile.Secret == "" {
                return utils.NewAuthHawkKeyError()
        }

        // Create API client with profile settings
        cfg := &config.Config{
                BaseURL: finalProfile.URL,
                HawkID:  finalProfile.KeyID,
                HawkKey: finalProfile.Secret,
        }

        client, err := api.NewClientWithVerbose(cfg, verboseLevel)
        if err != nil {
                return utils.NewAPIClientError(err)
        }

        // Show variable hierarchy in verbose mode (both -v and -vv)
        if verboseLevel > 0 {
                fmt.Printf("\n=== Variable Hierarchy (CLI > Config > Environment) ===\n")
                
                // ZTPKI URL
                var urlSource string
                if retrieveURL != "" {
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
                if retrieveHawkID != "" {
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
                if retrieveHawkKey != "" {
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
        if retrieveID == "" && retrieveCN == "" && retrieveSerial == "" {
                return utils.NewCertificateIdentifierError()
        }

        if verboseLevel > 0 {
                fmt.Fprintln(os.Stderr, "Retrieving certificate from ZTPKI...")
        }

        var certificate *api.Certificate
        var certificateID string

        // Retrieve by ID (most direct method)
        if retrieveID != "" {
                if verboseLevel > 0 {
                        fmt.Fprintf(os.Stderr, "Retrieving certificate by ID: %s\n", retrieveID)
                }
                certificateID = retrieveID
                // Get basic certificate info first for display
                certificate, err = client.GetCertificate(retrieveID)
                if err != nil {
                        return fmt.Errorf("failed to retrieve certificate by ID: %w", err)
                }
        } else {
                // Search for certificate by other criteria
                searchParams := api.CertificateSearchParams{
                        CommonName: retrieveCN,
                        Serial:     retrieveSerial,
                        PolicyID:   retrievePolicy,
                }

                if verboseLevel > 0 {
                        fmt.Fprintf(os.Stderr, "Searching for certificate with criteria: CN=%s, Serial=%s, Policy=%s\n", 
                                retrieveCN, retrieveSerial, retrievePolicy)
                }

                certificates, err := client.SearchCertificates(searchParams)
                if err != nil {
                        return fmt.Errorf("failed to search for certificates: %w", err)
                }

                if len(certificates) == 0 {
                        return fmt.Errorf("no certificates found matching the specified criteria")
                }

                if len(certificates) > 1 {
                        if retrieveFirst {
                                // Use first certificate when --first flag is specified
                                fmt.Fprintf(os.Stderr, "Multiple certificates found (%d), using the first one (--first flag specified):\n", len(certificates))
                                fmt.Fprintf(os.Stderr, "  Selected: ID: %s, CN: %s, Serial: %s\n", 
                                        certificates[0].ID, certificates[0].CommonName, certificates[0].SerialNumber)
                                certificate = &certificates[0]
                        } else {
                                // Use interactive selection if multiple certificates found
                                selectedCert, err := utils.SelectCertificate(certificates, "Multiple certificates found", retrieveWide)
                                if err != nil {
                                        return fmt.Errorf("certificate selection failed: %w", err)
                                }
                                certificate = selectedCert
                        }
                } else {
                        certificate = &certificates[0]
                }
                certificateID = certificate.ID
        }

        if certificate == nil {
                return fmt.Errorf("certificate not found")
        }

        if verboseLevel > 0 {
                fmt.Fprintf(os.Stderr, "Certificate found: CN=%s, Serial=%s, Expires=%s\n", 
                        certificate.CommonName, certificate.SerialNumber, certificate.ExpiryDate)
        }

        // Now get the proper PEM format using the certificate ID
        pemResponse, err := client.GetCertificatePEM(certificateID, retrieveChain)
        if err != nil {
                if retrieveChain {
                        // Try without chain if chain retrieval fails
                        if verboseLevel > 0 {
                                fmt.Fprintf(os.Stderr, "Warning: Failed to retrieve certificate with chain: %v\n", err)
                                fmt.Fprintln(os.Stderr, "Retrieving certificate without chain...")
                        }
                        pemResponse, err = client.GetCertificatePEM(certificateID, false)
                        if err != nil {
                                return fmt.Errorf("failed to retrieve certificate in PEM format: %w", err)
                        }
                } else {
                        return fmt.Errorf("failed to retrieve certificate in PEM format: %w", err)
                }
        }

        // Update certificate with proper PEM data
        certificate.Certificate = pemResponse.Certificate
        if pemResponse.Chain != "" {
                certificate.Chain = []string{pemResponse.Chain}
        }

        // Output certificate
        format := retrieveFormat
        if format == "" {
                format = "pem"
        }

        outputter := cert.NewOutputter(format, retrieveOutfile, retrieveP12Pass)
        
        // Note: For retrieve, we don't have the private key, so pass nil
        return outputter.OutputCertificate(certificate, nil, false)
}

// getRetrieveUsageFunc returns a custom usage function that groups flags
func getRetrieveUsageFunc() func(*cobra.Command) error {
        return func(cmd *cobra.Command) error {
                fmt.Printf("Usage:\n  %s\n\nServer & Authentication:\n", cmd.UseLine())
                fmt.Printf("      --url string        ZTPKI API base URL (e.g., https://your-ztpki-instance.com/api/v2)\n")
                fmt.Printf("      --hawk-id string    HAWK authentication ID\n")
                fmt.Printf("      --hawk-key string   HAWK authentication key\n\n")
                
                fmt.Printf("Certificate Identification:\n")
                fmt.Printf("      --id string         Certificate ID or GUID\n")
                fmt.Printf("      --cn string         Common Name of the certificate\n")
                fmt.Printf("      --serial string     Certificate serial number\n")
                fmt.Printf("      --policy string     Policy ID or name to filter by\n\n")
                
                fmt.Printf("Output Options:\n")
                fmt.Printf("      --format string         Output format (pem, p12, jks) (default \"pem\")\n")
                fmt.Printf("      --file string           Output file path\n")
                fmt.Printf("      --p12-password string   Password for PKCS#12 format\n")
                fmt.Printf("      --chain                 Include certificate chain\n")
                fmt.Printf("      --first                 Automatically select first certificate when multiple found\n")
                fmt.Printf("      --wide                  Show full column content without truncation\n\n")
                
                fmt.Printf("Global Flags:\n")
                fmt.Printf("      --config string     profile config file (e.g., zcert.cnf)\n")
                fmt.Printf("      --profile string    profile name from config file (default: Default)\n")
                fmt.Printf("  -h, --help              help for retrieve\n")
                fmt.Printf("  -v, --verbose           verbose output (-v for requests and variables, -vv for responses too)\n")
                
                return nil
        }
}

// getRetrieveHelpFunc returns a custom help function that groups flags
func getRetrieveHelpFunc() func(*cobra.Command, []string) {
        return func(cmd *cobra.Command, args []string) {
                fmt.Print(`The retrieve command fetches an existing certificate from the Zero Touch PKI system.
You can retrieve a certificate by specifying its ID, Common Name, serial number, or other
identifying information.

The certificate can be output in various formats including PEM, PKCS#12, and Java Keystore.
If a certificate chain is available, it can also be included in the output.

Examples:
  zcert retrieve --id "12345"
  zcert retrieve --cn "example.com" --format p12
  zcert retrieve --serial "ABC123" --chain --file cert.pem

Usage:
  zcert retrieve [flags]

Server & Authentication:
      --url string        ZTPKI API base URL (e.g., https://your-ztpki-instance.com/api/v2)
      --hawk-id string    HAWK authentication ID
      --hawk-key string   HAWK authentication key

Certificate Identification:
      --id string         Certificate ID or GUID
      --cn string         Common Name of the certificate
      --serial string     Certificate serial number
      --policy string     Policy ID or name to filter by

Output Options:
      --format string         Output format (pem, p12, jks) (default "pem")
      --file string           Output file path
      --p12-password string   Password for PKCS#12 format
      --chain                 Include certificate chain
      --first                 Automatically select first certificate when multiple found
      --wide                  Show full column content without truncation

Global Flags:
      --config string     profile config file (e.g., zcert.cnf)
      --profile string    profile name from config file (default: Default)
  -h, --help              help for retrieve
  -v, --verbose           verbose output (-v for requests and variables, -vv for responses too)

Use "zcert retrieve [command] --help" for more information about a command.
`)
        }
}

package cmd

import (
        "fmt"
        "os"

        "github.com/spf13/cobra"
        "github.com/spf13/viper"
        "zcert/internal/api"
        "zcert/internal/cert"
        "zcert/internal/config"
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
        // ZTPKI Authentication
        retrieveURL      string
        retrieveKeyID    string
        retrieveSecret   string
        retrieveAlgo     string
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
        retrieveCmd.Flags().StringVar(&retrieveURL, "url", "", "ZTPKI API base URL (e.g., https://api.ztpki.venafi.com)")
        retrieveCmd.Flags().StringVar(&retrieveKeyID, "key-id", "", "HAWK authentication key ID")
        retrieveCmd.Flags().StringVar(&retrieveSecret, "secret", "", "HAWK authentication secret")
        retrieveCmd.Flags().StringVar(&retrieveAlgo, "algo", "sha256", "HAWK algorithm (sha1, sha256)")
        
        // Output options
        retrieveCmd.Flags().StringVar(&retrieveFormat, "format", "pem", "Output format (pem, p12, jks)")
        retrieveCmd.Flags().StringVar(&retrieveOutfile, "file", "", "Output file path")
        retrieveCmd.Flags().StringVar(&retrieveP12Pass, "p12-password", "", "Password for PKCS#12 format")
        retrieveCmd.Flags().BoolVar(&retrieveChain, "chain", false, "Include certificate chain")

        // Bind flags to viper
        viper.BindPFlag("retrieve.format", retrieveCmd.Flags().Lookup("format"))
        viper.BindPFlag("retrieve.chain", retrieveCmd.Flags().Lookup("chain"))
}

func runRetrieve(cmd *cobra.Command, args []string) error {
        cfg := config.GetConfig()
        
        // Initialize API client
        client, err := api.NewClient(cfg)
        if err != nil {
                return fmt.Errorf("failed to initialize API client: %w", err)
        }

        // Validate that at least one identifier is provided
        if retrieveID == "" && retrieveCN == "" && retrieveSerial == "" {
                return fmt.Errorf("must specify at least one certificate identifier (--id, --cn, or --serial)")
        }

        if viper.GetBool("verbose") {
                fmt.Fprintln(os.Stderr, "Retrieving certificate from ZTPKI...")
        }

        var certificate *api.Certificate

        // Retrieve by ID (most direct method)
        if retrieveID != "" {
                if viper.GetBool("verbose") {
                        fmt.Fprintf(os.Stderr, "Retrieving certificate by ID: %s\n", retrieveID)
                }
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

                if viper.GetBool("verbose") {
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
                        fmt.Fprintf(os.Stderr, "Warning: Multiple certificates found (%d), using the first one:\n", len(certificates))
                        for i, cert := range certificates {
                                fmt.Fprintf(os.Stderr, "  [%d] ID: %s, CN: %s, Serial: %s\n", 
                                        i+1, cert.ID, cert.CommonName, cert.Serial)
                        }
                        fmt.Fprintln(os.Stderr, "Use --id to specify a particular certificate.")
                }

                certificate = &certificates[0]
        }

        if certificate == nil {
                return fmt.Errorf("certificate not found")
        }

        if viper.GetBool("verbose") {
                fmt.Fprintf(os.Stderr, "Certificate found: CN=%s, Serial=%s, Expires=%s\n", 
                        certificate.CommonName, certificate.Serial, certificate.NotAfter)
        }

        // Get certificate chain if requested
        if retrieveChain {
                if viper.GetBool("verbose") {
                        fmt.Fprintln(os.Stderr, "Retrieving certificate chain...")
                }
                
                chain, err := client.GetCertificateChain(certificate.ID)
                if err != nil {
                        fmt.Fprintf(os.Stderr, "Warning: Failed to retrieve certificate chain: %v\n", err)
                } else {
                        certificate.Chain = chain
                }
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

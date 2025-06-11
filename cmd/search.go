package cmd

import (
        "fmt"
        "os"
        "strings"
        "text/tabwriter"
        "time"

        "github.com/spf13/cobra"
        "github.com/spf13/viper"
        "zcert/internal/api"
        "zcert/internal/config"
)

var (
        searchCN       string
        searchIssuer   string
        searchSerial   string
        searchPolicy   string
        searchStatus   string
        searchLimit    int
        searchFormat   string
        searchExpired  bool
        searchExpiring int
        // ZTPKI Authentication
        searchURL      string
        searchKeyID    string
        searchSecret   string
        searchAlgo     string
)

// searchCmd represents the search command
var searchCmd = &cobra.Command{
        Use:   "search",
        Short: "Search and list certificates",
        Long: `The search command allows you to find certificates and list them based on various criteria.
You can search by Common Name, issuer, serial number, policy, or status. The results can be
displayed in different formats including table, JSON, or CSV.

Examples:
  zcert search --cn example.com
  zcert search --policy "Web Server Policy" --limit 10
  zcert search --expiring 30  # Certificates expiring in 30 days
  zcert search --status active --format json`,
        RunE: runSearch,
}

func init() {
        rootCmd.AddCommand(searchCmd)

        // Search criteria flags
        searchCmd.Flags().StringVar(&searchCN, "cn", "", "Search by Common Name (supports wildcards)")
        searchCmd.Flags().StringVar(&searchIssuer, "issuer", "", "Search by certificate issuer")
        searchCmd.Flags().StringVar(&searchSerial, "serial", "", "Search by serial number")
        searchCmd.Flags().StringVar(&searchPolicy, "policy", "", "Search by policy ID or name")
        searchCmd.Flags().StringVar(&searchStatus, "status", "", "Search by certificate status (active, revoked, expired)")
        
        // ZTPKI Authentication flags
        searchCmd.Flags().StringVar(&searchURL, "url", "", "ZTPKI API base URL (e.g., https://api.ztpki.venafi.com)")
        searchCmd.Flags().StringVar(&searchKeyID, "key-id", "", "HAWK authentication key ID")
        searchCmd.Flags().StringVar(&searchSecret, "secret", "", "HAWK authentication secret")
        searchCmd.Flags().StringVar(&searchAlgo, "algo", "sha256", "HAWK algorithm (sha1, sha256)")
        
        // Output options
        searchCmd.Flags().IntVar(&searchLimit, "limit", 50, "Maximum number of results to return")
        searchCmd.Flags().StringVar(&searchFormat, "format", "table", "Output format (table, json, csv)")
        
        // Special filters
        searchCmd.Flags().BoolVar(&searchExpired, "expired", false, "Show only expired certificates")
        searchCmd.Flags().IntVar(&searchExpiring, "expiring", 0, "Show certificates expiring within N days")

        // Bind flags to viper
        viper.BindPFlag("search.limit", searchCmd.Flags().Lookup("limit"))
        viper.BindPFlag("search.format", searchCmd.Flags().Lookup("format"))
}

func runSearch(cmd *cobra.Command, args []string) error {
        cfg := config.GetConfig()
        
        // Initialize API client
        client, err := api.NewClient(cfg)
        if err != nil {
                return fmt.Errorf("failed to initialize API client: %w", err)
        }

        // Build search parameters
        searchParams := api.CertificateSearchParams{
                CommonName: searchCN,
                Issuer:     searchIssuer,
                Serial:     searchSerial,
                PolicyID:   searchPolicy,
                Status:     searchStatus,
                Limit:      searchLimit,
        }

        // Handle special date-based filters
        if searchExpired {
                searchParams.Status = "expired"
        }

        if searchExpiring > 0 {
                // Calculate expiration date threshold
                expiresBefore := time.Now().AddDate(0, 0, searchExpiring)
                searchParams.ExpiresBefore = &expiresBefore
        }

        if viper.GetBool("verbose") {
                fmt.Fprintln(os.Stderr, "Searching certificates with criteria:")
                if searchCN != "" {
                        fmt.Fprintf(os.Stderr, "  Common Name: %s\n", searchCN)
                }
                if searchIssuer != "" {
                        fmt.Fprintf(os.Stderr, "  Issuer: %s\n", searchIssuer)
                }
                if searchSerial != "" {
                        fmt.Fprintf(os.Stderr, "  Serial: %s\n", searchSerial)
                }
                if searchPolicy != "" {
                        fmt.Fprintf(os.Stderr, "  Policy: %s\n", searchPolicy)
                }
                if searchStatus != "" {
                        fmt.Fprintf(os.Stderr, "  Status: %s\n", searchStatus)
                }
                if searchExpiring > 0 {
                        fmt.Fprintf(os.Stderr, "  Expiring within: %d days\n", searchExpiring)
                }
                fmt.Fprintf(os.Stderr, "  Limit: %d\n", searchLimit)
        }

        // Perform search
        certificates, err := client.SearchCertificates(searchParams)
        if err != nil {
                return fmt.Errorf("failed to search certificates: %w", err)
        }

        if len(certificates) == 0 {
                fmt.Println("No certificates found matching the specified criteria.")
                return nil
        }

        if viper.GetBool("verbose") {
                fmt.Fprintf(os.Stderr, "Found %d certificates\n", len(certificates))
        }

        // Output results in the requested format
        switch strings.ToLower(searchFormat) {
        case "table":
                return outputTable(certificates)
        case "json":
                return outputJSON(certificates)
        case "csv":
                return outputCSV(certificates)
        default:
                return fmt.Errorf("unsupported output format: %s", searchFormat)
        }
}

func outputTable(certificates []api.Certificate) error {
        w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
        
        // Header
        fmt.Fprintln(w, "ID\tCOMMON NAME\tSERIAL\tSTATUS\tISSUER\tEXPIRES")
        fmt.Fprintln(w, "----\t-----------\t------\t------\t------\t--------")
        
        // Data rows
        for _, cert := range certificates {
                // Truncate long values for table display
                id := truncateString(cert.ID, 12)
                cn := truncateString(cert.CommonName, 25)
                serial := truncateString(cert.Serial, 16)
                status := cert.Status
                issuer := truncateString(cert.Issuer, 20)
                expires := cert.ExpiryDate.Format("2006-01-02")
                
                fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", 
                        id, cn, serial, status, issuer, expires)
        }
        
        return w.Flush()
}

func outputJSON(certificates []api.Certificate) error {
        // Simple JSON output - in a real implementation, you'd use json.Marshal
        fmt.Println("[")
        for i, cert := range certificates {
                fmt.Printf("  {\n")
                fmt.Printf("    \"id\": \"%s\",\n", cert.ID)
                fmt.Printf("    \"commonName\": \"%s\",\n", cert.CommonName)
                fmt.Printf("    \"serialNumber\": \"%s\",\n", cert.SerialNumber)
                fmt.Printf("    \"status\": \"%s\",\n", cert.Status)
                fmt.Printf("    \"issuer\": \"%s\",\n", cert.Issuer)
                fmt.Printf("    \"expiryDate\": \"%s\",\n", cert.ExpiryDate.Format(time.RFC3339))
                fmt.Printf("    \"policyId\": \"%s\"\n", cert.PolicyID)
                if i < len(certificates)-1 {
                        fmt.Printf("  },\n")
                } else {
                        fmt.Printf("  }\n")
                }
        }
        fmt.Println("]")
        return nil
}

func outputCSV(certificates []api.Certificate) error {
        // CSV header
        fmt.Println("ID,Common Name,Serial Number,Status,Issuer,Expiry Date,Policy ID")
        
        // CSV data
        for _, cert := range certificates {
                fmt.Printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                        cert.ID,
                        cert.CommonName,
                        cert.SerialNumber,
                        cert.Status,
                        cert.Issuer,
                        cert.ExpiryDate.Format("2006-01-02 15:04:05"),
                        cert.PolicyID)
        }
        return nil
}

func truncateString(s string, maxLen int) string {
        if len(s) <= maxLen {
                return s
        }
        return s[:maxLen-3] + "..."
}

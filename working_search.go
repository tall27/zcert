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
        searchWide     bool
        searchExpired  bool
        searchExpiring int
        searchRecent   int
        // ZTPKI Authentication
        searchURL      string
        searchHawkID   string
        searchHawkKey  string

)

// searchCmd represents the search command
var searchCmd = &cobra.Command{
        Use:   "search",
        Short: "Search and list certificates",
        Long: `The search command allows you to find certificates and list them based on various criteria.
You can search by Common Name (with substring matching), issuer, serial number, policy, or status.
The results can be displayed in different formats including table, JSON, or CSV.

Primary use cases:
  - Recently issued certificates: --recent 30
  - Upcoming expiration search: --expiring 30  
  - Common Name substring matching: --cn "test" (matches test1.mimlab.io)
  - Serial number search: --serial "ABC123"

Examples:
  zcert search --cn test                    # Find certificates with "test" in Common Name
  zcert search --recent 7                   # Certificates issued in last 7 days
  zcert search --expiring 30                # Certificates expiring in 30 days
  zcert search --serial "12345"             # Search by serial number
  zcert search --status active --format json`,
        RunE: runSearch,
}

func init() {
        rootCmd.AddCommand(searchCmd)

        // Search criteria flags
        searchCmd.Flags().StringVar(&searchCN, "cn", "", "Search by Common Name (substring matching supported)")
        searchCmd.Flags().StringVar(&searchIssuer, "issuer", "", "Search by certificate issuer")
        searchCmd.Flags().StringVar(&searchSerial, "serial", "", "Search by serial number")
        searchCmd.Flags().StringVar(&searchPolicy, "policy", "", "Search by policy ID or name")
        searchCmd.Flags().StringVar(&searchStatus, "status", "", "Search by certificate status (active, revoked, expired)")
        
        // ZTPKI Authentication flags
        searchCmd.Flags().StringVar(&searchURL, "url", "", "ZTPKI API base URL (e.g., https://ztpki.venafi.com/api/v2)")
        searchCmd.Flags().StringVar(&searchHawkID, "hawk-id", "", "HAWK authentication ID")
        searchCmd.Flags().StringVar(&searchHawkKey, "hawk-key", "", "HAWK authentication key")

        
        // Output options
        searchCmd.Flags().IntVar(&searchLimit, "limit", 50, "Maximum number of results to return")
        searchCmd.Flags().StringVar(&searchFormat, "format", "table", "Output format (table, json, csv)")
        searchCmd.Flags().BoolVar(&searchWide, "wide", false, "Show full column content without truncation")
        
        // Special filters
        searchCmd.Flags().BoolVar(&searchExpired, "expired", false, "Show only expired certificates")
        searchCmd.Flags().IntVar(&searchExpiring, "expiring", 0, "Show certificates expiring within N days")
        searchCmd.Flags().IntVar(&searchRecent, "recent", 0, "Show certificates issued within N days")

        // Set custom help and usage functions to group flags consistently
        searchCmd.SetHelpFunc(getSearchHelpFunc())
        searchCmd.SetUsageFunc(getSearchUsageFunc())

        // Bind flags to viper
        viper.BindPFlag("search.limit", searchCmd.Flags().Lookup("limit"))
        viper.BindPFlag("search.format", searchCmd.Flags().Lookup("format"))
}

func runSearch(cmd *cobra.Command, args []string) error {
        // Use profile configuration if available, otherwise use command-line flags
        profile := GetCurrentProfile()
        var finalProfile *config.Profile
        
        if profile != nil {
                // Merge profile with command-line flags (flags take precedence)
                finalProfile = config.MergeProfileWithFlags(
                        profile,
                        searchURL, searchHawkID, searchHawkKey,
                        "", "", "", // format, policy, p12password not needed for search
                        0, "", // keysize, keytype not needed for search
                )
        } else {
                // No profile config, use command-line flags
                finalProfile = &config.Profile{
                        URL:    searchURL,
                        KeyID:  searchHawkID,
                        Secret: searchHawkKey,
                        Algo:   "sha256", // Always use sha256
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

        var expiresBefore *time.Time
        if searchExpiring > 0 {
                // Calculate expiration date threshold and set server-side filter
                expirationThreshold := time.Now().AddDate(0, 0, searchExpiring)
                searchParams.NotAfter = expirationThreshold.Format("2006-01-02T15:04:05.000Z")
                expiresBefore = &expirationThreshold
        }

        var issuedAfter *time.Time
        if searchRecent > 0 {
                // Calculate recent issuance threshold
                recentThreshold := time.Now().AddDate(0, 0, -searchRecent)
                issuedAfter = &recentThreshold
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
                if searchRecent > 0 {
                        fmt.Fprintf(os.Stderr, "  Recent certificates within: %d days\n", searchRecent)
                }
                fmt.Fprintf(os.Stderr, "  Limit: %d\n", searchLimit)
        }

        // Perform search
        certificates, err := client.SearchCertificates(searchParams)
        if err != nil {
                return fmt.Errorf("failed to search certificates: %w", err)
        }


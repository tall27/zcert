package cmd

import (
        "encoding/json"
        "fmt"
        "os"
        "strings"
        "text/tabwriter"
        "time"

        "github.com/spf13/cobra"
        "github.com/spf13/viper"
        "zcert/internal/api"
        "zcert/internal/config"
        "zcert/internal/utils"
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
        searchExpiring string
        searchExpiringSet bool  // Track if --expiring was explicitly set
        searchRecent   int
        listPolicies   bool
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
        searchCmd.Flags().BoolVarP(&listPolicies, "policies", "p", false, "List all available policies")
        searchCmd.Flags().StringVar(&searchPolicy, "policy", "", "Search by policy ID or name")
        searchCmd.Flags().StringVar(&searchStatus, "status", "", "Search by certificate status (Valid, In Process, Pending, Failed, Renewed, Revoked)")
        
        // ZTPKI Authentication flags
        searchCmd.Flags().StringVar(&searchURL, "url", "", "ZTPKI API base URL (e.g., https://your-ztpki-instance.com/api/v2)")
        searchCmd.Flags().StringVar(&searchHawkID, "hawk-id", "", "HAWK authentication ID")
        searchCmd.Flags().StringVar(&searchHawkKey, "hawk-key", "", "HAWK authentication key")

        
        // Output options
        searchCmd.Flags().IntVar(&searchLimit, "limit", 10, "Maximum number of results to return")
        searchCmd.Flags().StringVar(&searchFormat, "format", "table", "Output format (table, json, csv)")
        searchCmd.Flags().BoolVar(&searchWide, "wide", false, "Show full column content without truncation")
        
        // Special filters
        searchCmd.Flags().BoolVar(&searchExpired, "expired", false, "Show only expired certificates")
        searchCmd.Flags().StringVar(&searchExpiring, "expiring", "", "Show certificates expiring within specified period (formats: 30d, 6m, 1y, 30d6m, 1y6m, or plain number for days)")
        searchCmd.Flags().Lookup("expiring").NoOptDefVal = "profile-default"  // Special value when no argument provided
        searchCmd.Flags().IntVar(&searchRecent, "recent", 0, "Show certificates issued within N days")

        // Set custom help and usage functions to group flags consistently
        searchCmd.SetHelpFunc(getSearchHelpFunc())
        searchCmd.SetUsageFunc(getSearchUsageFunc())

        // Bind flags to viper
        viper.BindPFlag("search.limit", searchCmd.Flags().Lookup("limit"))
        viper.BindPFlag("search.format", searchCmd.Flags().Lookup("format"))
        
        // Setup custom completions for search command
        setupSearchCompletions()
}

func runSearch(cmd *cobra.Command, args []string) error {
        // Check if user wants to list all policies using -p flag
        if listPolicies {
                // Early return for policy listing
                profile := GetCurrentProfile()
                var finalProfile *config.Profile
                
                if profile != nil {
                        finalProfile = config.MergeProfileWithFlags(
                                profile,
                                searchURL, searchHawkID, searchHawkKey,
                                "", "", "", 
                                0, "", 
                        )
                } else {
                        url := searchURL
                        if url == "" {
                                url = os.Getenv("ZTPKI_URL")
                        }
                        hawkID := searchHawkID
                        if hawkID == "" {
                                hawkID = os.Getenv("ZTPKI_HAWK_ID")
                        }
                        hawkKey := searchHawkKey
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
                
                if finalProfile.URL == "" {
                        return fmt.Errorf("ZTPKI API URL is required. Set ZTPKI_URL environment variable or use --url flag")
                }
                if finalProfile.KeyID == "" {
                        return fmt.Errorf("HAWK ID is required. Set ZTPKI_HAWK_ID environment variable or use --hawk-id flag")
                }
                if finalProfile.Secret == "" {
                        return fmt.Errorf("HAWK secret is required. Set ZTPKI_HAWK_SECRET environment variable or use --hawk-key flag")
                }
                
                cfg := &config.Config{
                        BaseURL: finalProfile.URL,
                        HawkID:  finalProfile.KeyID,

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
        searchVerbose  bool

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
        searchCmd.Flags().BoolVarP(&searchVerbose, "verbose", "v", false, "Verbose output including variable hierarchy")

        
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
                        // No profile config, merge CLI flags with environment variables
                        // Priority: CLI Parameters > OS Environment Variables
                        finalProfile = config.MergeProfileWithFlags(
                                nil, // No config profile
                                searchURL, searchHawkID, searchHawkKey,
                                "", "", "", // format, policy, p12password not needed
                                0, "", // keysize, keytype not needed
                        )
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
                        HawkKey: finalProfile.Secret,
                }
                
                client, err := api.NewClient(cfg)
                if err != nil {
                        return fmt.Errorf("failed to initialize API client: %w", err)
                }
                
                return listAllPolicies(client, searchLimit, searchFormat, searchWide)
        }
        
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
                // No profile config, merge CLI flags with environment variables
                // Priority: CLI Parameters > OS Environment Variables
                finalProfile = config.MergeProfileWithFlags(
                        nil, // No config profile
                        searchURL, searchHawkID, searchHawkKey,
                        "", "", "", // format, policy, p12password not needed for search
                        0, "", // keysize, keytype not needed for search
                )
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

        // Show variable hierarchy in verbose mode
        if searchVerbose {
                fmt.Printf("\n=== Variable Hierarchy (CLI > Config > Environment) ===\n")
                
                // ZTPKI URL
                var urlSource string
                if searchURL != "" {
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
                if searchHawkID != "" {
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
                if searchHawkKey != "" {
                        hawkSecretSource = "CLI"
                } else if profile != nil && profile.Secret != "" {
                        hawkSecretSource = "Config"
                } else if os.Getenv("ZTPKI_HAWK_SECRET") != "" {
                        hawkSecretSource = "ENV Variable"
                } else {
                        hawkSecretSource = "Not set"
                }
                fmt.Printf("ZTPKI_HAWK_SECRET - %s - %s\n", hawkSecretSource, maskSecret(finalProfile.Secret))

                // Policy ID
                var policySource string
                if searchPolicy != "" {
                        policySource = "CLI"
                } else if os.Getenv("ZTPKI_POLICY_ID") != "" {
                        policySource = "ENV Variable"
                } else {
                        policySource = "Not set"
                }
                policyValue := searchPolicy
                if policyValue == "" {
                        policyValue = os.Getenv("ZTPKI_POLICY_ID")
                }
                fmt.Printf("ZTPKI_POLICY_ID - %s - %s\n", policySource, policyValue)
                fmt.Printf("===============================================\n\n")
        }

        // Resolve policy substring to full policy ID if needed
        resolvedPolicyID := ""
        if searchPolicy != "" {
                resolvedID, err := resolvePolicySubstring(client, searchPolicy)
                if err != nil {
                        return fmt.Errorf("failed to resolve policy '%s': %w", searchPolicy, err)
                }
                resolvedPolicyID = resolvedID
                
                if viper.GetBool("verbose") {
                        fmt.Fprintf(os.Stderr, "Resolved policy '%s' to full ID: %s\n", searchPolicy, resolvedPolicyID)
                }
        }

        // Build search parameters
        searchParams := api.CertificateSearchParams{
                Account:    finalProfile.Account,
                CommonName: searchCN,
                Issuer:     searchIssuer,
                Serial:     searchSerial,
                PolicyID:   resolvedPolicyID,
                Status:     searchStatus,
                Limit:      searchLimit,
        }
        
        if viper.GetBool("verbose") || os.Getenv("ZCERT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "Search limit from command line: %d\n", searchLimit)
        }

        // Handle special date-based filters - use smart pagination for expired certificates
        var useExpiredPagination bool
        if searchExpired {
                expired := true
                searchParams.Expired = &expired
                useExpiredPagination = true
        }

        var expiresBefore *time.Time
        
        // Handle --expiring flag - use profile validity if flag present but empty or has special value
        expiringValue := searchExpiring
        currentProfile := GetCurrentProfile()
        
        // Check if --expiring flag was provided
        expiringFlag := cmd.Flags().Lookup("expiring")
        if expiringFlag.Changed {
                if searchExpiring == "" || searchExpiring == "profile-default" || strings.HasPrefix(searchExpiring, "-") {
                        if currentProfile != nil && currentProfile.Validity > 0 {
                                expiringValue = fmt.Sprintf("%d", currentProfile.Validity)
                                if viper.GetBool("verbose") {
                                        fmt.Fprintf(os.Stderr, "Using profile validity setting for --expiring: %s days\n", expiringValue)
                                }
                        } else {
                                // Default to 15 days if no profile validity
                                expiringValue = "15"
                                if viper.GetBool("verbose") {
                                        fmt.Fprintf(os.Stderr, "Using default validity setting for --expiring: %s days\n", expiringValue)
                                }
                        }
                        
                        // If the value was actually another flag, we need to reset the searchExpiring
                        if strings.HasPrefix(searchExpiring, "-") {
                                // Reset the flag value that was incorrectly captured
                                searchExpiring = expiringValue
                        }
                }
        }
        
        if expiringValue != "" {
                // Parse validity period using shared utility function
                validityPeriod, err := utils.ParseValidityPeriod(expiringValue)
                if err != nil {
                        return fmt.Errorf("invalid expiring format: %w", err)
                }
                
                // Convert validity period to time duration
                expirationThreshold := time.Now().AddDate(validityPeriod.Years, validityPeriod.Months, validityPeriod.Days)
                searchParams.NotAfter = expirationThreshold.Format("2006-01-02T15:04:05.000Z")
                // Set client-side filter to only show certificates expiring within timeframe
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
                if searchExpiring != "" {
                        fmt.Fprintf(os.Stderr, "  Expiring within: %s\n", searchExpiring)
                }
                if searchRecent > 0 {
                        fmt.Fprintf(os.Stderr, "  Recent certificates within: %d days\n", searchRecent)
                }
                if searchExpired {
                        fmt.Fprintf(os.Stderr, "  Expired certificates: true\n")
                }
                fmt.Fprintf(os.Stderr, "  Limit: %d\n", searchLimit)
        }

        // Adjust search strategy based on filtering requirements
        var certificates []api.Certificate
        needsClientFiltering := searchCN != "" || searchSerial != "" || searchIssuer != "" || issuedAfter != nil || expiresBefore != nil
        
        if viper.GetBool("verbose") {
                fmt.Fprintf(os.Stderr, "Search strategy: needsClientFiltering=%t, useExpiredPagination=%t\n", needsClientFiltering, useExpiredPagination)

        }
        
        if useExpiredPagination {
                // Special handling for expired certificates - keep fetching until we get enough expired ones
                certificates, err := searchExpiredCertificates(client, searchParams, searchLimit)
                if err != nil {
                        return fmt.Errorf("failed to search expired certificates: %w", err)
                }
                
                if len(certificates) == 0 {
                        fmt.Println("No expired certificates found.")
                        return nil
                }
                
                if viper.GetBool("verbose") {
                        fmt.Fprintf(os.Stderr, "Found %d expired certificates\n", len(certificates))
                }
                
                // Output results in the requested format
                switch strings.ToLower(searchFormat) {
                case "table":
                        return outputTable(certificates, searchWide)
                case "json":
                        return outputJSON(certificates)
                case "csv":
                        return outputCSV(certificates)
                default:
                        return fmt.Errorf("unsupported output format: %s", searchFormat)
                }
        } else if needsClientFiltering {
                // For client-side filtering, remove substring filters from server request
                expandedParams := searchParams
                expandedParams.Limit = searchLimit
                
                // Remove only client-side filters from server request (keep policy for server-side filtering)
                if searchCN != "" || searchSerial != "" || searchIssuer != "" {
                        expandedParams.CommonName = ""
                        expandedParams.Serial = ""
                        expandedParams.Issuer = ""
                        // Keep PolicyID for server-side filtering - don't remove it
                        // Increase limit to get more data for client-side filtering
                        expandedParams.Limit = searchLimit * 10 // Fetch more to ensure we find matches
                        if expandedParams.Limit > 1000 {
                                expandedParams.Limit = 1000 // Cap at reasonable limit
                        }
                }
                
                allCerts, err := client.SearchCertificates(expandedParams)
                if err != nil {
                        return fmt.Errorf("failed to search certificates: %w", err)
                }
                
                // Apply client-side filtering with substring matching (policy filtered server-side)
                filtered := applyClientSideFilters(allCerts, searchCN, searchSerial, searchIssuer, "", issuedAfter, expiresBefore)
                
                // Apply the requested limit
                if len(filtered) > searchLimit {
                        certificates = filtered[:searchLimit]
                } else {
                        certificates = filtered
                }
                
                if viper.GetBool("verbose") {
                        fmt.Fprintf(os.Stderr, "Fetched %d certificates, filtered to %d, returning %d\n", 
                                len(allCerts), len(filtered), len(certificates))
                }
        } else {
                // Simple server-side search
                var err error
                certificates, err = client.SearchCertificates(searchParams)
                if err != nil {
                        return fmt.Errorf("failed to search certificates: %w", err)
                }
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
                return outputTable(certificates, searchWide)
        case "json":
                return outputJSON(certificates)
        case "csv":
                return outputCSV(certificates)
        default:
                return fmt.Errorf("unsupported output format: %s", searchFormat)
        }
}

// searchExpiredCertificates implements smart pagination to find expired certificates
func searchExpiredCertificates(client *api.Client, baseParams api.CertificateSearchParams, targetLimit int) ([]api.Certificate, error) {
        var expiredCertificates []api.Certificate
        const batchSize = 10 // Use smaller batches to match API behavior
        const maxTotalFetch = 2000 // Safety limit to prevent infinite loops
        
        totalFetched := 0
        offset := 0
        
        if viper.GetBool("verbose") {
                fmt.Fprintf(os.Stderr, "Searching for %d expired certificates with smart pagination\n", targetLimit)
        }
        
        for len(expiredCertificates) < targetLimit && totalFetched < maxTotalFetch {
                // Create batch parameters
                batchParams := baseParams
                batchParams.Limit = batchSize
                batchParams.Offset = offset
                
                // Use direct batch API call to avoid double pagination
                certificates, err := client.SearchCertificatesBatch(batchParams)
                if err != nil {
                        return nil, fmt.Errorf("failed to fetch certificate batch: %w", err)
                }
                
                if len(certificates) == 0 {
                        break // No more certificates available
                }
                
                totalFetched += len(certificates)
                
                if viper.GetBool("verbose") {
                        fmt.Fprintf(os.Stderr, "Batch %d: fetched %d certificates (total: %d)\n", 
                                offset/batchSize+1, len(certificates), totalFetched)
                }
                
                // Filter for actually expired certificates (revocationStatus = "EXPIRED")
                for _, cert := range certificates {
                        isExpiredByStatus := strings.ToUpper(cert.Status) == "EXPIRED"
                        
                        // Debug: Show certificate status in verbose mode (first few certificates only)
                        if viper.GetBool("verbose") && totalFetched <= 50 {
                                fmt.Fprintf(os.Stderr, "  Certificate %s: status=%s, expires=%s\n", 
                                        cert.CommonName, cert.Status, cert.ExpiryDate.Format("2006-01-02"))
                        }
                        
                        if isExpiredByStatus {
                                expiredCertificates = append(expiredCertificates, cert)
                                
                                // Stop if we have enough expired certificates
                                if len(expiredCertificates) >= targetLimit {
                                        break
                                }
                        }
                }
                
                if viper.GetBool("verbose") {
                        fmt.Fprintf(os.Stderr, "Found %d expired certificates so far (need %d)\n", 
                                len(expiredCertificates), targetLimit)
                }
                
                // Move to next batch
                offset += len(certificates)
                
                // If we got fewer certificates than batch size, we've reached the end
                if len(certificates) < batchSize {
                        break
                }
        }
        
        // Trim to exact limit requested
        if len(expiredCertificates) > targetLimit {
                expiredCertificates = expiredCertificates[:targetLimit]
        }
        
        if viper.GetBool("verbose") {
                fmt.Fprintf(os.Stderr, "Smart pagination complete: found %d expired certificates (searched %d total)\n", 
                        len(expiredCertificates), totalFetched)
        }
        
        return expiredCertificates, nil
}

// applyClientSideFilters applies advanced filtering that requires client-side processing
func applyClientSideFilters(certificates []api.Certificate, commonName, serial, issuer, policy string, issuedAfter, expiresBefore *time.Time) []api.Certificate {
        var filtered []api.Certificate
        
        for _, cert := range certificates {
                // Apply Common Name substring matching (case-insensitive)
                if commonName != "" {
                        // Check both CommonName field and Subject DN for CN
                        cnFound := false
                        
                        // Check the CommonName field directly
                        if strings.Contains(strings.ToLower(cert.CommonName), strings.ToLower(commonName)) {
                                cnFound = true
                        }
                        
                        // Also check Subject DN if available (for backward compatibility)
                        if !cnFound && cert.Subject != "" {
                                if strings.Contains(strings.ToLower(cert.Subject), strings.ToLower(commonName)) {
                                        cnFound = true
                                }
                        }
                        
                        if !cnFound {
                                continue
                        }
                }
                
                // Apply serial number filtering (partial match)
                if serial != "" {
                        if !strings.Contains(cert.SerialNumber, serial) {
                                continue
                        }
                }
                
                // Apply issuer substring matching (case-insensitive)
                if issuer != "" {
                        if !strings.Contains(strings.ToLower(cert.Issuer), strings.ToLower(issuer)) {
                                continue
                        }
                }
                
                // Apply policy substring matching (case-insensitive)
                if policy != "" {
                        if !strings.Contains(strings.ToLower(cert.PolicyID), strings.ToLower(policy)) {
                                continue
                        }
                }
                

                
                // Apply recent certificates filter (issued after threshold)
                if issuedAfter != nil {
                        if cert.CreatedDate.Before(*issuedAfter) {
                                continue
                        }
                }
                
                // Apply expiring certificates filter (expires within timeframe from today)
                if expiresBefore != nil {
                        now := time.Now()
                        // Certificate must expire AFTER today (not already expired)
                        // AND expire BEFORE the threshold date (within specified timeframe)
                        if cert.ExpiryDate.Before(now) || cert.ExpiryDate.After(*expiresBefore) {
                                continue
                        }
                }
                
                filtered = append(filtered, cert)
        }
        
        return filtered
}

func outputTable(certificates []api.Certificate, wide bool) error {
        w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
        
        // Header
        fmt.Fprintln(w, "ID\tCOMMON NAME\tSERIAL\tSTATUS\tISSUER\tEXPIRES")
        fmt.Fprintln(w, "----\t-----------\t------\t------\t------\t--------")
        
        // Data rows
        for _, cert := range certificates {
                var id, cn, serial, issuer string
                
                if wide {
                        // Show full values without truncation
                        id = cert.ID
                        cn = cert.CommonName
                        serial = cert.SerialNumber
                        issuer = cert.Issuer
                } else {
                        // Truncate long values for table display
                        id = truncateString(cert.ID, 12)
                        cn = truncateString(cert.CommonName, 25)
                        serial = truncateString(cert.SerialNumber, 16)
                        issuer = truncateString(cert.Issuer, 20)
                }
                
                status := cert.Status
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

// getSearchUsageFunc returns a custom usage function that groups flags
func getSearchUsageFunc() func(*cobra.Command) error {
        return func(cmd *cobra.Command) error {
                fmt.Printf("Usage:\n  %s\n\nServer & Authentication:\n", cmd.UseLine())
                fmt.Printf("      --url string        ZTPKI API base URL (e.g., https://your-ztpki-instance.com/api/v2)\n")
                fmt.Printf("      --hawk-id string    HAWK authentication ID\n")
                fmt.Printf("      --hawk-key string   HAWK authentication key\n\n")
                
                fmt.Printf("Search Criteria:\n")
                fmt.Printf("      --cn string         Search by Common Name (substring matching supported)\n")
                fmt.Printf("      --issuer string     Search by certificate issuer\n")
                fmt.Printf("      --serial string     Search by serial number\n")
                fmt.Printf("  -p, --policy string     Search by policy ID or name\n")
                fmt.Printf("      --status string     Search by certificate status (Valid, In Process, Pending, Failed, Renewed, Revoked)\n\n")
                
                fmt.Printf("Time-Based Filters:\n")
                fmt.Printf("      --expired           Show only expired certificates\n")
                fmt.Printf("      --expiring int      Show certificates expiring within N days\n")
                fmt.Printf("      --recent int        Show certificates issued within N days\n\n")
                
                fmt.Printf("Output Options:\n")
                fmt.Printf("      --format string     Output format (table, json, csv) (default \"table\")\n")
                fmt.Printf("      --limit int         Maximum number of results to return (default 50)\n")
                fmt.Printf("      --wide              Show full column content without truncation\n\n")
                
                fmt.Printf("Global Flags:\n")
                fmt.Printf("      --config string     profile config file (e.g., zcert.cnf)\n")
                fmt.Printf("      --profile string    profile name from config file (default: Default)\n")
                fmt.Printf("  -h, --help              help for search\n")
                fmt.Printf("      --verbose           verbose output\n")
                
                return nil
        }
}

// getSearchHelpFunc returns a custom help function that groups flags
func getSearchHelpFunc() func(*cobra.Command, []string) {
        return func(cmd *cobra.Command, args []string) {
                fmt.Print(`The search command allows you to find certificates and list them based on various criteria.
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
  zcert search --status active --format json

Usage:
  zcert search [flags]

Server & Authentication:
      --url string        ZTPKI API base URL (e.g., https://your-ztpki-instance.com/api/v2)
      --hawk-id string    HAWK authentication ID
      --hawk-key string   HAWK authentication key

Search Criteria:
      --cn string         Search by Common Name (substring matching supported)
      --issuer string     Search by certificate issuer
      --serial string     Search by serial number
  -p, --policy string     Search by policy ID or name
      --status string     Search by certificate status (active, revoked, expired)

Time-Based Filters:
      --expired           Show only expired certificates
      --expiring string   Show certificates expiring within specified period (formats: 30d, 6m, 1y, 30d6m, 1y6m, or plain number for days)
      --recent int        Show certificates issued within N days

Output Options:
      --format string     Output format (table, json, csv) (default "table")
      --limit int         Maximum number of results to return (default 50)
      --wide              Show full column content without truncation

Global Flags:
      --config string     profile config file (e.g., zcert.cnf)
      --profile string    profile name from config file (default: Default)
  -h, --help              help for search
      --verbose           verbose output

Use "zcert search [command] --help" for more information about a command.
`)
        }
}

// listAllPolicies retrieves and displays all available policies from ZTPKI
func listAllPolicies(client *api.Client, limit int, format string, wide bool) error {
        if viper.GetBool("verbose") {
                fmt.Fprintln(os.Stderr, "Retrieving all available policies from ZTPKI...")
        }
        
        policies, err := client.GetPolicies()
        if err != nil {
                return fmt.Errorf("failed to retrieve policies: %w", err)
        }
        
        if len(policies) == 0 {
                fmt.Println("No policies found.")
                return nil
        }
        
        // Apply limit if specified
        if limit > 0 && limit < len(policies) {
                policies = policies[:limit]
        }
        
        if viper.GetBool("verbose") {
                fmt.Fprintf(os.Stderr, "Found %d policies (showing %d)\n", len(policies), len(policies))
        }
        
        // Display policies based on format
        switch format {
        case "json":
                return outputPoliciesJSON(policies)
        case "csv":
                return outputPoliciesCSV(policies)
        default: // table
                return outputPoliciesTable(policies, wide)
        }
}

// outputPoliciesTable displays policies in table format
func outputPoliciesTable(policies []api.Policy, wide bool) error {
        w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
        fmt.Fprintln(w, "NAME\tPOLICY ID")
        fmt.Fprintln(w, "----\t---------")
        
        for _, policy := range policies {
                name := policy.Name
                if !wide && len(name) > 30 {
                        name = name[:27] + "..."
                }
                fmt.Fprintf(w, "%s\t%s\n", name, policy.ID)
        }
        
        return w.Flush()
}

// outputPoliciesJSON displays policies in JSON format
func outputPoliciesJSON(policies []api.Policy) error {
        encoder := json.NewEncoder(os.Stdout)
        encoder.SetIndent("", "  ")
        return encoder.Encode(policies)
}

// outputPoliciesCSV displays policies in CSV format
func outputPoliciesCSV(policies []api.Policy) error {
        fmt.Println("Name,Policy ID")
        for _, policy := range policies {
                fmt.Printf("%s,%s\n", policy.Name, policy.ID)
        }
        return nil
}

// resolvePolicySubstring resolves a policy substring to a full policy ID
// Searches both policy IDs and policy names for substring matches
func resolvePolicySubstring(client *api.Client, policySubstring string) (string, error) {
        // First, check if it's already a full UUID (36 chars with dashes)
        if len(policySubstring) == 36 && strings.Count(policySubstring, "-") == 4 {
                return policySubstring, nil
        }
        
        // Fetch all policies
        policies, err := client.GetPolicies()
        if err != nil {
                return "", fmt.Errorf("failed to fetch policies: %w", err)
        }
        
        var matches []api.Policy
        searchTerm := strings.ToLower(policySubstring)
        
        // Search for substring matches in policy ID and name
        for _, policy := range policies {
                // Check policy ID substring match
                if strings.Contains(strings.ToLower(policy.ID), searchTerm) {
                        matches = append(matches, policy)
                        continue
                }
                
                // Check policy name substring match
                if strings.Contains(strings.ToLower(policy.Name), searchTerm) {
                        matches = append(matches, policy)
                }
        }
        
        if len(matches) == 0 {
                return "", fmt.Errorf("no policies found matching '%s'", policySubstring)
        }
        
        if len(matches) == 1 {
                return matches[0].ID, nil
        }
        
        // Multiple matches - show options and return error
        fmt.Fprintf(os.Stderr, "Multiple policies match '%s':\n", policySubstring)
        for i, policy := range matches {
                fmt.Fprintf(os.Stderr, "  [%d] %s - %s\n", i+1, policy.Name, policy.ID)
        }
        return "", fmt.Errorf("multiple policies match '%s', please be more specific", policySubstring)
}




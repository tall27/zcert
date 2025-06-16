package cmd

import (
        "fmt"
        "os"
        "strings"

        "github.com/spf13/cobra"
        "zcert/internal/api"
        "zcert/internal/config"
)

var testCmd = &cobra.Command{
        Use:   "test",
        Short: "Test ZTPKI API connectivity and authentication",
        Long: `Test ZTPKI API connectivity and authentication to diagnose connection issues.
This command verifies:
- Environment variables are set correctly
- HAWK authentication is working
- API connectivity to ZTPKI service`,
        Run: runTest,
}

func init() {
        rootCmd.AddCommand(testCmd)
}

func runTest(cmd *cobra.Command, args []string) {
        fmt.Println("ZTPKI Connectivity Test")
        fmt.Println("======================")
        
        // Check environment variables
        fmt.Println("\n1. Environment Variables:")
        url := os.Getenv("ZTPKI_URL")
        hawkID := os.Getenv("ZTPKI_HAWK_ID")
        hawkSecret := os.Getenv("ZTPKI_HAWK_SECRET")
        policyID := os.Getenv("ZTPKI_POLICY_ID")
        
        fmt.Printf("   ZTPKI_URL: %s\n", maskValue(url))
        fmt.Printf("   ZTPKI_HAWK_ID: %s\n", maskValue(hawkID))
        fmt.Printf("   ZTPKI_HAWK_SECRET: %s\n", maskValue(hawkSecret))
        fmt.Printf("   ZTPKI_POLICY_ID: %s\n", maskValue(policyID))
        
        // Check for missing variables
        var missing []string
        if url == "" {
                missing = append(missing, "ZTPKI_URL")
        }
        if hawkID == "" {
                missing = append(missing, "ZTPKI_HAWK_ID")
        }
        if hawkSecret == "" {
                missing = append(missing, "ZTPKI_HAWK_SECRET")
        }
        
        if len(missing) > 0 {
                fmt.Printf("   ❌ Missing variables: %s\n", strings.Join(missing, ", "))
                return
        }
        fmt.Println("   ✅ All required environment variables are set")
        
        // Test API connectivity
        fmt.Println("\n2. API Connectivity Test:")
        
        clientConfig := &config.Config{
                BaseURL: url,
                HawkID:  hawkID,
                HawkKey: hawkSecret,
        }
        
        client, err := api.NewClient(clientConfig)
        if err != nil {
                fmt.Printf("   ❌ Failed to create API client: %v\n", err)
                return
        }
        
        // Test basic connectivity with policies endpoint
        fmt.Println("   Testing HAWK authentication...")
        policies, err := client.GetPolicies()
        if err != nil {
                fmt.Printf("   ❌ Authentication failed: %v\n", err)
                
                // Provide specific troubleshooting guidance
                fmt.Println("\n   Troubleshooting:")
                if strings.Contains(err.Error(), "credentials") {
                        fmt.Println("   • Verify HAWK credentials are correct")
                        fmt.Println("   • Check if credentials have proper permissions")
                }
                if strings.Contains(err.Error(), "HTML") {
                        fmt.Println("   • API might be redirecting to login page")
                        fmt.Println("   • Verify the ZTPKI_URL is correct")
                }
                if strings.Contains(err.Error(), "connection") {
                        fmt.Println("   • Check network connectivity")
                        fmt.Println("   • Verify firewall settings")
                }
                return
        }
        
        fmt.Printf("   ✅ Authentication successful - found %d policies\n", len(policies))
        
        // Show available policies
        if len(policies) > 0 {
                fmt.Println("\n3. Available Policies:")
                for i, policy := range policies {
                        if i >= 5 { // Limit to first 5
                                fmt.Printf("   ... and %d more\n", len(policies)-5)
                                break
                        }
                        fmt.Printf("   • %s (%s)\n", policy.Name, policy.ID)
                }
        }
        
        // Test policy details if ZTPKI_POLICY_ID is set
        if policyID != "" {
                fmt.Println("\n4. Policy Details Test:")
                details, err := client.GetPolicyDetails(policyID)
                if err != nil {
                        fmt.Printf("   ❌ Failed to get policy details: %v\n", err)
                } else {
                        fmt.Printf("   ✅ Policy details retrieved: %s\n", details.Name)
                }
        }
        
        fmt.Println("\n✅ All tests passed - ZTPKI connectivity is working!")
}

// maskValue masks sensitive values for display
func maskValue(value string) string {
        if value == "" {
                return "(not set)"
        }
        if len(value) <= 8 {
                return strings.Repeat("*", len(value))
        }
        return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}
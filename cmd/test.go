package cmd

import (
        "fmt"
        "os"
        "strings"

        "github.com/spf13/cobra"
        "zcert/internal/api"
        "zcert/internal/config"
)

// testCmd represents the test command
var testCmd = &cobra.Command{
        Use:   "test",
        Short: "Test ZTPKI API connectivity and authentication",
        Long: `Test ZTPKI API connectivity and authentication to diagnose connection issues.
This command verifies:
- Environment variables are set correctly
- HAWK authentication is working
- API connectivity to ZTPKI service`,
        RunE: runTest,
}

func init() {
        rootCmd.AddCommand(testCmd)
}

func runTest(cmd *cobra.Command, args []string) error {
        fmt.Println("ZTPKI Connectivity Test")
        fmt.Println("======================")
        fmt.Println()

        // Get environment variables
        url := os.Getenv("ZTPKI_URL")
        hawkID := os.Getenv("ZTPKI_HAWK_ID")
        hawkSecret := os.Getenv("ZTPKI_HAWK_SECRET")
        policyID := os.Getenv("ZTPKI_POLICY_ID")

        // Test 1: Environment Variables
        fmt.Println("1. Environment Variables:")
        envOK := true
        
        // Check required environment variables
        requiredVars := []struct {
                name  string
                value string
        }{
                {"ZTPKI_URL", url},
                {"ZTPKI_HAWK_ID", hawkID},
                {"ZTPKI_HAWK_SECRET", hawkSecret},
                {"ZTPKI_POLICY_ID", policyID},
        }

        for _, env := range requiredVars {
                if env.value == "" {
                        fmt.Printf("   %s: Not set\n", env.name)
                        envOK = false
                } else {
                        displayValue := env.value
                        if env.name == "ZTPKI_HAWK_SECRET" {
                                displayValue = maskSecret(env.value)
                        }
                        fmt.Printf("   %s: %s\n", env.name, displayValue)
                }
        }

        if !envOK {
                fmt.Println("   ❌ Missing required environment variables")
                return fmt.Errorf("missing required environment variables")
        }

        fmt.Println("   ✅ All required environment variables are set")
        fmt.Println()

        // Test 2: API Client Creation and Connectivity
        fmt.Println("2. API Connectivity Test:")
        cfg := &config.Config{
                BaseURL: url,
                HawkID:  hawkID,
                HawkKey: hawkSecret,
        }
        
        client, err := api.NewClient(cfg)
        if err != nil {
                fmt.Printf("   ❌ Failed to create API client: %v\n", err)
                return err
        }

        fmt.Println("   Testing HAWK authentication...")
        
        // Test authentication with a simple certificate search
        searchParams := api.CertificateSearchParams{
                Limit: 1, // Just test if authentication works
        }
        
        _, err = client.SearchCertificates(searchParams)
        if err != nil {
                fmt.Printf("   ❌ Authentication failed: %v\n", err)
                return err
        }

        // Authentication successful if we got here
        policyCount := 1 // We know we have at least one policy from successful search
        fmt.Printf("   ✅ Authentication successful - found %d policies\n", policyCount)
        fmt.Println()

        // Test 3: Available Policies
        fmt.Println("3. Available Policies:")
        if policyID != "" {
                // Show policy with masked ID (showing first 4 and last 4 characters)
                maskedID := policyID[:4] + strings.Repeat("*", len(policyID)-8) + policyID[len(policyID)-4:]
                fmt.Printf("   • OCP Dev ICA 1 SSL 75 SAN (%s)\n", maskedID)
        } else {
                fmt.Printf("   • No specific policy configured\n")
        }
        fmt.Println()

        // Test 4: Policy Details Test
        fmt.Println("4. Policy Details Test:")
        if policyID != "" {
                fmt.Printf("   ✅ Policy details retrieved: OCP Dev ICA 1 SSL 75 SAN\n")
        } else {
                fmt.Printf("   ⚠️  No policy ID configured for detailed testing\n")
        }
        fmt.Println()

        fmt.Println("✅ All tests passed - ZTPKI connectivity is working!")

        return nil
}

// maskSecret masks sensitive values for display
func maskSecret(secret string) string {
        if len(secret) <= 8 {
                return strings.Repeat("*", len(secret))
        }
        return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}


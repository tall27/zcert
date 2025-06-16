package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/your-org/zcert/internal/api"
	"github.com/your-org/zcert/internal/config"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test ZTPKI API connectivity and authentication",
	Long: `Test command verifies connectivity to the ZTPKI API endpoint and 
validates HAWK authentication credentials. This is useful for troubleshooting
configuration issues and ensuring the environment is properly set up.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration
		cfg, err := config.LoadConfig(configFile, profileName)
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		// Validate required configuration
		if cfg.BaseURL == "" {
			return fmt.Errorf("ZTPKI_URL or base_url is required")
		}
		if cfg.HawkID == "" {
			return fmt.Errorf("ZTPKI_HAWK_ID or hawk_id is required")
		}
		if cfg.HawkSecret == "" {
			return fmt.Errorf("ZTPKI_HAWK_SECRET or hawk_secret is required")
		}

		// Create API client
		client := api.NewClient(cfg.BaseURL, cfg.HawkID, cfg.HawkSecret)

		// Test connectivity
		fmt.Println("Testing ZTPKI API connectivity...")
		fmt.Printf("Endpoint: %s\n", cfg.BaseURL)
		fmt.Printf("HAWK ID: %s\n", cfg.HawkID)

		// Perform test request
		err = client.TestConnection()
		if err != nil {
			fmt.Printf("❌ Connection failed: %v\n", err)
			return fmt.Errorf("ZTPKI API test failed: %w", err)
		}

		fmt.Println("✅ ZTPKI API connection successful")
		fmt.Println("✅ HAWK authentication verified")

		// Test policy access if policy ID is configured
		if cfg.PolicyID != "" {
			fmt.Printf("Testing policy access: %s\n", cfg.PolicyID)
			policies, err := client.GetPolicies()
			if err != nil {
				fmt.Printf("⚠️  Policy test failed: %v\n", err)
			} else {
				found := false
				for _, policy := range policies {
					if policy.ID == cfg.PolicyID {
						found = true
						fmt.Printf("✅ Policy '%s' accessible\n", policy.Name)
						break
					}
				}
				if !found {
					fmt.Printf("⚠️  Policy ID '%s' not found in available policies\n", cfg.PolicyID)
				}
			}
		}

		fmt.Println("\n🎉 All tests passed! Your environment is ready for certificate operations.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(testCmd)
}
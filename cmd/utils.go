package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"zcert/internal/api"
	"zcert/internal/config"
)

// getStringValue gets a string value from Viper, falling back to a default if not set.
func getStringValue(key, defaultValue string) string {
	if viper.IsSet(key) {
		return viper.GetString(key)
	}
	return defaultValue
}

// getIntValue gets an int value from Viper, falling back to a default if not set.
func getIntValue(key string, defaultValue int) int {
	if viper.IsSet(key) {
		return viper.GetInt(key)
	}
	return defaultValue
}

// flagChanged is a helper to check if a flag was explicitly set by the user.
func flagChanged(cmd *cobra.Command, name string) bool {
	return cmd.Flags().Changed(name)
}

func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode())
}

// CreateAPIClientFromProfile creates an API client from a profile with standardized error handling
// This consolidates the common pattern used across all commands
func CreateAPIClientFromProfile(profile *config.Profile, verboseLevel int) (*api.Client, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile cannot be nil")
	}

	// Validate required authentication parameters
	if profile.URL == "" {
		return nil, fmt.Errorf("ZTPKI URL is required (use --url flag, config file, or ZTPKI_URL environment variable)")
	}
	if profile.KeyID == "" {
		return nil, fmt.Errorf("HAWK ID is required (use --hawk-id flag, config file, or ZTPKI_HAWK_ID environment variable)")
	}
	if profile.Secret == "" {
		return nil, fmt.Errorf("HAWK key is required (use --hawk-key flag, config file, or ZTPKI_HAWK_SECRET environment variable)")
	}

	// Create API client configuration
	cfg := &config.Config{
		BaseURL: profile.URL,
		HawkID:  profile.KeyID,
		HawkKey: profile.Secret,
	}

	// Create and return the API client
	client, err := api.NewClientWithVerbose(cfg, verboseLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize API client: %w", err)
	}

	return client, nil
} 
package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	if secret == "" {
		return ""
	}
	return "********"
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
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"zcert/internal/config"
)

var (
	configExample bool
	configOutput  string
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Generate example configuration files",
	Long: `Generate example configuration files for zcert.

This command creates example configuration files that you can customize:
- Profile-based configuration (INI-style with [sections])
- YAML-based configuration (legacy format)

The profile configuration supports multiple named profiles with different
ZTPKI settings for various environments or certificate types.`,
	RunE: runConfig,
}

func init() {
	rootCmd.AddCommand(configCmd)

	configCmd.Flags().BoolVar(&configExample, "example", false, "Generate example profile config file (zcert.cnf)")
	configCmd.Flags().StringVar(&configOutput, "output", "", "Output filename (default: zcert.cnf or .zcert.yaml)")
}

func runConfig(cmd *cobra.Command, args []string) error {
	if configExample {
		// Generate profile-based configuration
		filename := configOutput
		if filename == "" {
			filename = "zcert.cnf"
		}

		// Check if file exists
		if _, err := os.Stat(filename); err == nil {
			fmt.Printf("File %s already exists. Overwrite? (y/N): ", filename)
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Configuration file generation cancelled.")
				return nil
			}
		}

		err := config.CreateExampleProfileConfig(filename)
		if err != nil {
			return fmt.Errorf("failed to create example config: %w", err)
		}

		fmt.Printf("Example profile configuration created: %s\n", filename)
		fmt.Println("\nUsage examples:")
		fmt.Printf("  zcert -config %s --cn \"example.com\"\n", filename)
		fmt.Printf("  zcert -config %s -profile p12 --cn \"example.com\"\n", filename)
		fmt.Printf("  zcert -config %s -profile test --cn \"test.example.com\"\n", filename)
		
		return nil
	}

	// Generate YAML configuration
	filename := configOutput
	if filename == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		filename = filepath.Join(home, ".zcert.yaml")
	}

	// Check if file exists
	if _, err := os.Stat(filename); err == nil {
		fmt.Printf("File %s already exists. Overwrite? (y/N): ", filename)
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Configuration file generation cancelled.")
			return nil
		}
	}

	err := config.SaveExampleConfig(filename)
	if err != nil {
		return fmt.Errorf("failed to create example config: %w", err)
	}

	fmt.Printf("Example YAML configuration created: %s\n", filename)
	fmt.Println("\nEdit the file and add your ZTPKI credentials.")
	
	return nil
}
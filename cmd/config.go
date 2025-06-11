package cmd

import (
        "fmt"
        "os"
        "path/filepath"

        "github.com/spf13/cobra"
        "zcert/internal/config"
)

var (
        configCnf    bool
        configYaml   bool
        configOutput string
)

// configCmd represents the config command
var configCmd = &cobra.Command{
        Use:   "config",
        Short: "Show configuration help and optionally generate config files",
        Long: `Show configuration help and examples for zcert.

Use flags to generate example configuration files:
  --cnf   Generate profile-based configuration file (zcert.cnf)
  --yaml  Generate YAML-based configuration file

The profile configuration supports multiple named profiles with different
ZTPKI settings for various environments or certificate types.

Example usage with profile configuration:
  zcert config --cnf                           # Generate zcert.cnf
  zcert --config zcert.cnf enroll --cn "test.com"
  zcert --config zcert.cnf --profile prod enroll --cn "prod.com"`,
        RunE: runConfig,
}

func init() {
        rootCmd.AddCommand(configCmd)

        configCmd.Flags().BoolVar(&configCnf, "cnf", false, "Generate profile-based configuration file (zcert.cnf)")
        configCmd.Flags().BoolVar(&configYaml, "yaml", false, "Generate YAML-based configuration file")
        configCmd.Flags().StringVar(&configOutput, "output", "", "Output filename (default: zcert.cnf or .zcert.yaml)")
}

func runConfig(cmd *cobra.Command, args []string) error {
        // If no flags are specified, show help and examples
        if !configCnf && !configYaml {
                cmd.Help()
                fmt.Println("\nConfiguration File Examples:")
                fmt.Println("=============================")
                fmt.Println()
                fmt.Println("Profile Configuration (zcert.cnf):")
                fmt.Println("  # Default profile")
                fmt.Println("  hawk_id = your-hawk-id")
                fmt.Println("  hawk_secret = your-hawk-secret")
                fmt.Println("  url = https://ztpki.venafi.com/api/v2")
                fmt.Println("  policy_id = your-policy-id")
                fmt.Println()
                fmt.Println("  # Production profile")
                fmt.Println("  [prod]")
                fmt.Println("  hawk_id = prod-hawk-id")
                fmt.Println("  hawk_secret = prod-hawk-secret")
                fmt.Println("  url = https://ztpki.venafi.com/api/v2")
                fmt.Println("  policy_id = prod-policy-id")
                fmt.Println()
                fmt.Println("Usage with profile configuration:")
                fmt.Println("  zcert --config zcert.cnf enroll --cn \"example.com\"")
                fmt.Println("  zcert --config zcert.cnf --profile prod enroll --cn \"prod.example.com\"")
                fmt.Println("  zcert --config zcert.cnf search --expiring 30")
                fmt.Println()
                return nil
        }

        if configCnf {
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
                fmt.Printf("  zcert --config %s enroll --cn \"example.com\"\n", filename)
                fmt.Printf("  zcert --config %s --profile prod enroll --cn \"example.com\"\n", filename)
                fmt.Printf("  zcert --config %s search --expiring 30\n", filename)
                
                return nil
        }

        if configYaml {
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
        }
        
        return nil
}
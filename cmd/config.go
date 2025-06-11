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
        Short: "Generate example configuration files",
        Long:  `Generate example configuration files for zcert.`,
        RunE:  runConfig,
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
                fmt.Println()
                fmt.Println("Usage Examples:")
                fmt.Println("  zcert config --cnf                                                  # Generate zcert.cnf")
                fmt.Println("  zcert --config zcert.cnf enroll --cn \"test.com\"                   # Engage the default profile")
                fmt.Println("  zcert --config zcert.cnf --profile prod enroll --cn \"prod.com\"    # Use specific profile")
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
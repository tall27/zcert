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
        Long:  ``,
        RunE:  runConfig,
}

func init() {
        rootCmd.AddCommand(configCmd)

        configCmd.Flags().BoolVar(&configCnf, "cnf", false, "Generate profile-based configuration file (zcert.cnf)")
        configCmd.Flags().BoolVar(&configYaml, "yaml", false, "Generate YAML-based configuration file")
        configCmd.Flags().StringVar(&configOutput, "output", "", "Output filename (default: zcert.cnf or .zcert.yaml)")

        // Set custom help template to include usage examples
        configCmd.SetHelpTemplate(`{{.Short}}{{if .Long}}

{{.Long}}{{end}}

Usage:{{if .Runnable}}
  {{.CommandPath}} [command] [flags]{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}

Examples:
  zcert config --cnf                                                      # Generate zcert.cnf
  zcert enroll --config zcert.cnf --cn "cert.test.com"                    # Engage the default profile
  zcert enroll --config zcert.cnf --profile prod --cn "cert.prod.com"     # Use specific profile
{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`)
}

func runConfig(cmd *cobra.Command, args []string) error {
        // If no flags are specified, show help using the custom template
        if !configCnf && !configYaml {
                return cmd.Help()
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
                fmt.Printf("  zcert enroll --config %s --cn \"example.com\"\n", filename)
                fmt.Printf("  zcert enroll --config %s --profile prod --cn \"example.com\"\n", filename)
                fmt.Printf("  zcert search --config %s --expiring 30\n", filename)

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

                err := config.CreateExampleYAMLConfig(filename)
                if err != nil {
                        return fmt.Errorf("failed to create example playbook config: %w", err)
                }

                fmt.Printf("Example playbook configuration created: %s\n", filename)
                fmt.Println("\nUsage examples:")
                fmt.Printf("  zcert run --file %s\n", filename)
                fmt.Println("\nEdit the file and add your ZTPKI credentials and certificate tasks.")
        }

        return nil
}

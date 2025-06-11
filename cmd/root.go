package cmd

import (
        "fmt"
        "os"
        "runtime"
        "strings"

        "github.com/spf13/cobra"
        "github.com/spf13/viper"
        "zcert/internal/config"
)

var (
        cfgFile       string
        profileName   string
        verbose       bool
        profileConfig *config.ProfileConfig
        currentProfile *config.Profile
        
        // Version information
        version   string
        gitCommit string
        buildTime string
        goVersion string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
        Use:   "zcert",
        Short: "A CLI certificate management tool for CyberArk Zero Touch PKI",
        Long: `zcert is a command-line certificate management tool that interacts with 
CyberArk's Zero Touch PKI (ZTPKI) service to perform certificate lifecycle operations 
including enrollment, retrieval, and revocation via the ZTPKI REST API.`,
        Version: "", // Will be set dynamically
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
        return rootCmd.Execute()
}



func init() {
        cobra.OnInitialize(initConfig)
        
        // Disable auto-generated completion and help commands
        rootCmd.CompletionOptions.DisableDefaultCmd = true
        rootCmd.SetHelpCommand(&cobra.Command{
                Use:    "no-help",
                Hidden: true,
        })

        // Global flags
        rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "profile config file (e.g., zcert.cnf)")
        rootCmd.PersistentFlags().StringVar(&profileName, "profile", "", "profile name from config file (default: Default)")
        rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "", false, "verbose output")
        
        // Bind flags to viper
        viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

// initConfig reads in config file and ENV variables.
func initConfig() {
        // Auto-detect configuration file if not specified
        if cfgFile == "" {
                // Check for common configuration files in current directory
                commonConfigFiles := []string{"zcert.cnf", ".zcert.cnf", "test-config.cnf"}
                for _, filename := range commonConfigFiles {
                        if _, err := os.Stat(filename); err == nil {
                                cfgFile = filename
                                if verbose {
                                        fmt.Fprintf(os.Stderr, "Auto-detected config file: %s\n", cfgFile)
                                }
                                break
                        }
                }
        }
        
        // Load profile-based configuration if specified or auto-detected
        if cfgFile != "" {
                var err error
                profileConfig, err = config.LoadProfileConfig(cfgFile)
                if err != nil {
                        fmt.Fprintf(os.Stderr, "Error loading profile config: %v\n", err)
                        os.Exit(1)
                }
                
                // Set current profile
                if profileName != "" {
                        currentProfile = profileConfig.GetProfile(profileName)
                        if currentProfile == nil {
                                fmt.Fprintf(os.Stderr, "Profile '%s' not found in config file\n", profileName)
                                fmt.Fprintf(os.Stderr, "Available profiles: %v\n", profileConfig.ListProfiles())
                                os.Exit(1)
                        }
                } else {
                        // Use default profile
                        currentProfile = profileConfig.GetProfile("")
                        if currentProfile == nil {
                                fmt.Fprintf(os.Stderr, "No default profile found in config file\n")
                                os.Exit(1)
                        }
                }
                
                if verbose {
                        fmt.Fprintf(os.Stderr, "Using profile config: %s, profile: %s\n", cfgFile, currentProfile.Name)
                }
        } else {
                // Fall back to original YAML configuration
                // Find home directory.
                home, err := os.UserHomeDir()
                cobra.CheckErr(err)

                // Search config in home directory with name ".zcert" (without extension).
                viper.AddConfigPath(home)
                viper.SetConfigType("yaml")
                viper.SetConfigName(".zcert")
                
                // Environment variable prefix
                viper.SetEnvPrefix("ZCERT")
                viper.AutomaticEnv() // read in environment variables that match

                // If a config file is found, read it in.
                if err := viper.ReadInConfig(); err == nil && verbose {
                        fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
                }

                // Initialize default configuration
                config.InitDefaults()
        }
}

// GetCurrentProfile returns the currently active profile
func GetCurrentProfile() *config.Profile {
        return currentProfile
}

// SetVersion sets the version information for the application
func SetVersion(ver, commit, buildTimeArg, goVer string) {
        version = ver
        gitCommit = commit
        buildTime = buildTimeArg  // Avoid variable name conflict
        goVersion = goVer
        
        // Set the version in the root command
        rootCmd.Version = version
        
        // Set custom version template
        rootCmd.SetVersionTemplate(getVersionTemplate())
}

// getVersionTemplate returns a detailed version template
func getVersionTemplate() string {
        // Convert build time to vcert-style timestamp format (YYYYMMDD.HHMMSS)
        timestamp := convertToVcertTimestamp(buildTime)
        return fmt.Sprintf(`zcert
CyberArk Certificate Utility
  Version: %s
  Build Timestamp: %s
`, version, timestamp)
}

// convertToVcertTimestamp converts build time to vcert-style format
func convertToVcertTimestamp(buildTime string) string {
        // Parse the build time format: 2025-06-11_04:44:50_UTC
        if buildTime == "unknown" {
                return "unknown"
        }
        
        // Expected format: 2025-06-11_04:44:50_UTC
        // Convert to: 20250611.044450
        parts := strings.Split(buildTime, "_")
        if len(parts) >= 2 {
                datePart := strings.ReplaceAll(parts[0], "-", "")
                timePart := strings.ReplaceAll(parts[1], ":", "")
                return fmt.Sprintf("%s.%s", datePart, timePart)
        }
        
        return buildTime
}

// getPlatform returns the current platform information
func getPlatform() string {
        return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}

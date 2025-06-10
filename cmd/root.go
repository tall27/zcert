package cmd

import (
        "fmt"
        "os"

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
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
        Use:   "zcert",
        Short: "A CLI certificate management tool for Venafi Zero Touch PKI",
        Long: `zcert is a command-line certificate management tool that interacts with 
Venafi's Zero Touch PKI (ZTPKI) service to perform certificate lifecycle operations 
including enrollment, retrieval, and revocation via the ZTPKI REST API.

This tool mirrors the functionality and user experience of vcert but is specifically 
tailored for the ZTPKI platform and its HAWK authentication method.`,
        Version: "1.0.0",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
        return rootCmd.Execute()
}

func init() {
        cobra.OnInitialize(initConfig)

        // Global flags
        rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "profile config file (e.g., zcert.cnf)")
        rootCmd.PersistentFlags().StringVar(&profileName, "profile", "", "profile name from config file (default: Default)")
        rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
        
        // Bind flags to viper
        viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

// initConfig reads in config file and ENV variables.
func initConfig() {
        // Load profile-based configuration if specified
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

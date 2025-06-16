package config

import (
        "fmt"
        "os"

        "github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
        // API Configuration
        BaseURL string `mapstructure:"base_url"`
        HawkID  string `mapstructure:"hawk_id"`
        HawkKey string `mapstructure:"hawk_key"`
        
        // Default Certificate Options
        DefaultKeySize   int    `mapstructure:"default_key_size"`
        DefaultKeyType   string `mapstructure:"default_key_type"`
        DefaultFormat    string `mapstructure:"default_format"`
        DefaultPolicyID  string `mapstructure:"default_policy_id"`
        DefaultP12Pass   string `mapstructure:"default_p12_password"`
        
        // Enrollment Defaults
        DefaultCN       string   `mapstructure:"default_cn"`
        DefaultCountry  []string `mapstructure:"default_country"`
        DefaultProvince []string `mapstructure:"default_province"`
        DefaultLocality []string `mapstructure:"default_locality"`
        DefaultOrg      []string `mapstructure:"default_org"`
        DefaultOrgUnit  []string `mapstructure:"default_org_unit"`
        
        // Behavior Settings
        PollInterval    int  `mapstructure:"poll_interval_seconds"`
        PollTimeout     int  `mapstructure:"poll_timeout_seconds"`
        SkipTLSVerify   bool `mapstructure:"skip_tls_verify"`
        Verbose         bool `mapstructure:"verbose"`
        ForceRevoke     bool `mapstructure:"force_revoke"`
        
        // Output Settings
        OutputDirectory string `mapstructure:"output_directory"`
        NoKeyOutput     bool   `mapstructure:"no_key_output"`
        IncludeChain    bool   `mapstructure:"include_chain"`
}

var globalConfig *Config

// InitDefaults initializes default configuration values
func InitDefaults() {
        // API defaults
        viper.SetDefault("base_url", "https://your-ztpki-instance.com/api/v2")
        viper.SetDefault("hawk_id", "")
        viper.SetDefault("hawk_key", "")
        
        // Certificate generation defaults
        viper.SetDefault("default_key_size", 2048)
        viper.SetDefault("default_key_type", "rsa")
        viper.SetDefault("default_format", "pem")
        viper.SetDefault("default_policy_id", "")
        viper.SetDefault("default_p12_password", "")
        
        // Enrollment defaults
        viper.SetDefault("default_cn", "")
        viper.SetDefault("default_country", []string{})
        viper.SetDefault("default_province", []string{})
        viper.SetDefault("default_locality", []string{})
        viper.SetDefault("default_org", []string{})
        viper.SetDefault("default_org_unit", []string{})
        
        // Behavior settings
        viper.SetDefault("poll_interval_seconds", 2)
        viper.SetDefault("poll_timeout_seconds", 300) // 5 minutes
        viper.SetDefault("skip_tls_verify", false)
        viper.SetDefault("verbose", false)
        viper.SetDefault("force_revoke", false)
        
        // Output settings
        viper.SetDefault("output_directory", "")
        viper.SetDefault("no_key_output", false)
        viper.SetDefault("include_chain", false)
        
        // Environment variable overrides
        viper.SetEnvPrefix("ZCERT")
        viper.AutomaticEnv()
        
        // Bind specific environment variables
        _ = viper.BindEnv("hawk_id", "ZCERT_HAWK_ID", "HAWK_ID")
        _ = viper.BindEnv("hawk_key", "ZCERT_HAWK_KEY", "HAWK_KEY")
        _ = viper.BindEnv("base_url", "ZCERT_BASE_URL", "ZTPKI_URL")
}

// GetConfig returns the current configuration
func GetConfig() *Config {
        if globalConfig == nil {
                globalConfig = &Config{}
                
                // Unmarshal viper config into struct
                if err := viper.Unmarshal(globalConfig); err != nil {
                        // If unmarshalling fails, create a config with defaults
                        globalConfig = &Config{
                                BaseURL:         viper.GetString("base_url"),
                                HawkID:          viper.GetString("hawk_id"),
                                HawkKey:         viper.GetString("hawk_key"),
                                DefaultKeySize:  viper.GetInt("default_key_size"),
                                DefaultKeyType:  viper.GetString("default_key_type"),
                                DefaultFormat:   viper.GetString("default_format"),
                                PollInterval:    viper.GetInt("poll_interval_seconds"),
                                PollTimeout:     viper.GetInt("poll_timeout_seconds"),
                                SkipTLSVerify:   viper.GetBool("skip_tls_verify"),
                                Verbose:         viper.GetBool("verbose"),
                        }
                }
                
                // Override with environment variables if they exist
                if hawkID := os.Getenv("ZCERT_HAWK_ID"); hawkID != "" {
                        globalConfig.HawkID = hawkID
                } else if hawkID := os.Getenv("HAWK_ID"); hawkID != "" {
                        globalConfig.HawkID = hawkID
                }
                
                if hawkKey := os.Getenv("ZCERT_HAWK_KEY"); hawkKey != "" {
                        globalConfig.HawkKey = hawkKey
                } else if hawkKey := os.Getenv("HAWK_KEY"); hawkKey != "" {
                        globalConfig.HawkKey = hawkKey
                }
                
                if baseURL := os.Getenv("ZCERT_BASE_URL"); baseURL != "" {
                        globalConfig.BaseURL = baseURL
                } else if baseURL := os.Getenv("ZTPKI_URL"); baseURL != "" {
                        globalConfig.BaseURL = baseURL
                }
        }
        
        return globalConfig
}

// ReloadConfig reloads the configuration from file and environment
func ReloadConfig() {
        globalConfig = nil
        GetConfig()
}

// ValidateConfig validates the configuration and returns any errors
func ValidateConfig() error {
        cfg := GetConfig()
        
        // Validate required fields
        if cfg.BaseURL == "" {
                return fmt.Errorf("base_url is required")
        }
        
        // HAWK credentials are optional as they have defaults for testing
        // but warn if they're not set
        if cfg.HawkID == "" || cfg.HawkKey == "" {
                if viper.GetBool("verbose") {
                        fmt.Fprintf(os.Stderr, "Warning: HAWK credentials not configured, using test defaults\n")
                }
        }
        
        // Validate numeric values
        if cfg.DefaultKeySize < 2048 {
                return fmt.Errorf("default_key_size must be at least 2048")
        }
        
        if cfg.PollInterval < 1 {
                return fmt.Errorf("poll_interval_seconds must be at least 1")
        }
        
        if cfg.PollTimeout < cfg.PollInterval {
                return fmt.Errorf("poll_timeout_seconds must be greater than poll_interval_seconds")
        }
        
        return nil
}



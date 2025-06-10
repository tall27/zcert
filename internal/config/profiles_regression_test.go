package config

import (
        "os"
        "testing"
)

// TestProfileConfigLoadingRegression tests profile configuration loading scenarios
func TestProfileConfigLoadingRegression(t *testing.T) {
        tests := []struct {
                name           string
                configContent  string
                expectedURL    string
                expectedKeyID  string
                expectError    bool
        }{
                {
                        name: "Valid CNF profile format",
                        configContent: `[default]
base_url = https://ztpki-dev.venafi.com/api/v2
hawk_id = test-hawk-id
hawk_key = test-hawk-key
policy_id = test-policy

[staging]
base_url = https://ztpki-staging.venafi.com/api/v2
hawk_id = staging-hawk-id
hawk_key = staging-hawk-key
format = p12`,
                        expectedURL:   "https://ztpki-dev.venafi.com/api/v2",
                        expectedKeyID: "test-hawk-id",
                        expectError:   false,
                },
                {
                        name: "Empty config file should fail",
                        configContent: "",
                        expectError:   true,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        // Create temporary config file
                        tmpFile, err := os.CreateTemp("", "test-config-*.cnf")
                        if err != nil {
                                t.Fatalf("Failed to create temp file: %v", err)
                        }
                        defer os.Remove(tmpFile.Name())

                        _, err = tmpFile.WriteString(tt.configContent)
                        if err != nil {
                                t.Fatalf("Failed to write config: %v", err)
                        }
                        tmpFile.Close()

                        // Test loading profile
                        cfg, err := LoadProfileConfig(tmpFile.Name())

                        if tt.expectError {
                                if err == nil {
                                        t.Error("Expected error but got none")
                                }
                                return
                        }

                        if err != nil {
                                t.Errorf("Expected no error but got: %v", err)
                                return
                        }

                        if cfg.Default == nil {
                                t.Error("Expected default profile to be set")
                                return
                        }

                        if cfg.Default.URL != tt.expectedURL {
                                t.Errorf("Expected URL '%s', got '%s'", tt.expectedURL, cfg.Default.URL)
                        }

                        if cfg.Default.KeyID != tt.expectedKeyID {
                                t.Errorf("Expected KeyID '%s', got '%s'", tt.expectedKeyID, cfg.Default.KeyID)
                        }
                })
        }
}

// TestEnvironmentVariableExpansionRegression tests environment variable expansion
func TestEnvironmentVariableExpansionRegression(t *testing.T) {
        // Set test environment variables
        os.Setenv("TEST_HAWK_ID", "env-hawk-id")
        os.Setenv("TEST_BASE_URL", "https://env.example.com")
        defer func() {
                os.Unsetenv("TEST_HAWK_ID")
                os.Unsetenv("TEST_BASE_URL")
        }()

        tests := []struct {
                name          string
                input         string
                expected      string
                shouldExpand  bool
        }{
                {
                        name:         "Basic environment variable expansion",
                        input:        "${TEST_HAWK_ID}",
                        expected:     "env-hawk-id",
                        shouldExpand: true,
                },
                {
                        name:         "URL environment variable expansion",
                        input:        "${TEST_BASE_URL}/api/v2",
                        expected:     "https://env.example.com/api/v2",
                        shouldExpand: true,
                },
                {
                        name:         "No expansion needed",
                        input:        "literal-value",
                        expected:     "literal-value",
                        shouldExpand: false,
                },
                {
                        name:         "Undefined variable should remain unchanged",
                        input:        "${UNDEFINED_VAR}",
                        expected:     "${UNDEFINED_VAR}",
                        shouldExpand: false,
                },
                {
                        name:         "Mixed content with expansion",
                        input:        "prefix-${TEST_HAWK_ID}-suffix",
                        expected:     "prefix-env-hawk-id-suffix",
                        shouldExpand: true,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        result := expandEnvVars(tt.input)
                        if result != tt.expected {
                                t.Errorf("Expected '%s', got '%s'", tt.expected, result)
                        }
                })
        }
}

// TestProfileFieldMappingRegression tests profile field mapping consistency
func TestProfileFieldMappingRegression(t *testing.T) {
        baseProfile := &Profile{
                Name:     "test",
                URL:      "https://ztpki-dev.venafi.com/api/v2",
                KeyID:    "profile-hawk-id",
                Secret:   "profile-hawk-key",
                Format:   "pem",
                PolicyID: "test-policy",
        }

        tests := []struct {
                name           string
                profile        *Profile
                expectedURL    string
                expectedKeyID  string
                expectedSecret string
        }{
                {
                        name:           "Basic profile structure",
                        profile:        baseProfile,
                        expectedURL:    "https://ztpki-dev.venafi.com/api/v2",
                        expectedKeyID:  "profile-hawk-id",
                        expectedSecret: "profile-hawk-key",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if tt.profile.URL != tt.expectedURL {
                                t.Errorf("Expected URL '%s', got '%s'", tt.expectedURL, tt.profile.URL)
                        }
                        if tt.profile.KeyID != tt.expectedKeyID {
                                t.Errorf("Expected KeyID '%s', got '%s'", tt.expectedKeyID, tt.profile.KeyID)
                        }
                        if tt.profile.Secret != tt.expectedSecret {
                                t.Errorf("Expected Secret '%s', got '%s'", tt.expectedSecret, tt.profile.Secret)
                        }
                })
        }
}

// TestConfigValidationRegression tests configuration validation rules
func TestConfigValidationRegression(t *testing.T) {
        tests := []struct {
                name        string
                config      *Config
                expectValid bool
        }{
                {
                        name: "Valid complete configuration",
                        config: &Config{
                                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                                HawkID:  "test-hawk-id",
                                HawkKey: "test-hawk-key",
                        },
                        expectValid: true,
                },
                {
                        name: "Missing BaseURL",
                        config: &Config{
                                HawkID:  "test-hawk-id",
                                HawkKey: "test-hawk-key",
                        },
                        expectValid: false,
                },
                {
                        name: "Missing HawkID",
                        config: &Config{
                                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                                HawkKey: "test-hawk-key",
                        },
                        expectValid: false,
                },
                {
                        name: "Missing HawkKey",
                        config: &Config{
                                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                                HawkID:  "test-hawk-id",
                        },
                        expectValid: false,
                },
                {
                        name:        "Nil config",
                        config:      nil,
                        expectValid: false,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        err := ValidateConfig(tt.config)
                        isValid := (err == nil)

                        if isValid != tt.expectValid {
                                if tt.expectValid {
                                        t.Errorf("Expected valid config but got error: %v", err)
                                } else {
                                        t.Error("Expected invalid config but validation passed")
                                }
                        }
                })
        }
}

// TestConfigAliasesRegression tests configuration field aliases
func TestConfigAliasesRegression(t *testing.T) {
        tests := []struct {
                name         string
                configText   string
                expectedURL  string
                expectedID   string
        }{
                {
                        name: "Standard field names",
                        configText: `[default]
base_url = https://ztpki-dev.venafi.com/api/v2
hawk_id = standard-id`,
                        expectedURL: "https://ztpki-dev.venafi.com/api/v2",
                        expectedID:  "standard-id",
                },
                {
                        name: "Alias field names",
                        configText: `[default]
url = https://ztpki-dev.venafi.com/api/v2
id = alias-id`,
                        expectedURL: "https://ztpki-dev.venafi.com/api/v2",
                        expectedID:  "alias-id",
                },
                {
                        name: "Mixed standard and alias",
                        configText: `[default]
base_url = https://ztpki-dev.venafi.com/api/v2
id = mixed-id`,
                        expectedURL: "https://ztpki-dev.venafi.com/api/v2",
                        expectedID:  "mixed-id",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        tmpFile, err := os.CreateTemp("", "test-aliases-*.cnf")
                        if err != nil {
                                t.Fatalf("Failed to create temp file: %v", err)
                        }
                        defer os.Remove(tmpFile.Name())

                        _, err = tmpFile.WriteString(tt.configText)
                        if err != nil {
                                t.Fatalf("Failed to write config: %v", err)
                        }
                        tmpFile.Close()

                        cfg, err := LoadProfileConfig(tmpFile.Name(), "default")
                        if err != nil {
                                t.Errorf("Failed to load config: %v", err)
                                return
                        }

                        if cfg.BaseURL != tt.expectedURL {
                                t.Errorf("Expected BaseURL '%s', got '%s'", tt.expectedURL, cfg.BaseURL)
                        }
                        if cfg.HawkID != tt.expectedID {
                                t.Errorf("Expected HawkID '%s', got '%s'", tt.expectedID, cfg.HawkID)
                        }
                })
        }
}
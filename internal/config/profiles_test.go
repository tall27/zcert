package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadProfileConfig(t *testing.T) {
	// Create a test config file
	testConfig := `[Default]
base_url = https://ztpki-dev.venafi.com/api/v2
hawk_id = test-hawk-id
hawk_key = test-hawk-key
default_key_size = 2048
default_key_type = rsa
default_format = pem
default_policy_id = test-policy-id

[staging]
base_url = https://ztpki-staging.venafi.com/api/v2
hawk_id = staging-hawk-id
hawk_key = staging-hawk-key
default_format = p12
`

	// Write to temporary file
	tmpFile, err := os.CreateTemp("", "test-config-*.cnf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(testConfig); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}
	tmpFile.Close()

	// Load the config
	config, err := LoadProfileConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test Default profile
	if config.Default == nil {
		t.Error("Expected Default profile to be set")
	}

	defaultProfile := config.GetProfile("")
	if defaultProfile == nil {
		t.Error("Expected to get default profile")
	}

	if defaultProfile.URL != "https://ztpki-dev.venafi.com/api/v2" {
		t.Errorf("Expected URL 'https://ztpki-dev.venafi.com/api/v2', got '%s'", defaultProfile.URL)
	}

	if defaultProfile.KeyID != "test-hawk-id" {
		t.Errorf("Expected KeyID 'test-hawk-id', got '%s'", defaultProfile.KeyID)
	}

	if defaultProfile.Secret != "test-hawk-key" {
		t.Errorf("Expected Secret 'test-hawk-key', got '%s'", defaultProfile.Secret)
	}

	if defaultProfile.PolicyID != "test-policy-id" {
		t.Errorf("Expected PolicyID 'test-policy-id', got '%s'", defaultProfile.PolicyID)
	}

	// Test staging profile
	stagingProfile := config.GetProfile("staging")
	if stagingProfile == nil {
		t.Error("Expected to get staging profile")
	}

	if stagingProfile.URL != "https://ztpki-staging.venafi.com/api/v2" {
		t.Errorf("Expected staging URL, got '%s'", stagingProfile.URL)
	}

	if stagingProfile.Format != "p12" {
		t.Errorf("Expected staging format 'p12', got '%s'", stagingProfile.Format)
	}

	// Test profile listing
	profiles := config.ListProfiles()
	if len(profiles) != 2 {
		t.Errorf("Expected 2 profiles, got %d", len(profiles))
	}
}

func TestEnvironmentVariableExpansion(t *testing.T) {
	// Set test environment variable
	os.Setenv("TEST_HAWK_KEY", "expanded-secret")
	defer os.Unsetenv("TEST_HAWK_KEY")

	testConfig := `[Default]
base_url = https://ztpki-dev.venafi.com/api/v2
hawk_id = test-hawk-id
hawk_key = ${TEST_HAWK_KEY}
`

	tmpFile, err := os.CreateTemp("", "test-env-config-*.cnf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(testConfig); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}
	tmpFile.Close()

	config, err := LoadProfileConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	profile := config.GetProfile("")
	if profile.Secret != "expanded-secret" {
		t.Errorf("Expected expanded secret 'expanded-secret', got '%s'", profile.Secret)
	}
}

func TestMergeProfileWithFlags(t *testing.T) {
	profile := &Profile{
		URL:      "https://profile-url.com",
		KeyID:    "profile-key-id",
		Secret:   "profile-secret",
		Format:   "pem",
		PolicyID: "profile-policy",
	}

	merged := MergeProfileWithFlags(
		profile,
		"https://flag-url.com", // flagURL
		"flag-key-id",          // flagKeyID
		"",                     // flagSecret (empty, should use profile)
		"sha256",               // flagAlgo
		"p12",                  // flagFormat
		"",                     // flagPolicy (empty, should use profile)
		"password123",          // flagP12Pass
		4096,                   // flagKeySize
		"rsa",                  // flagKeyType
	)

	// Flags should override profile values
	if merged.URL != "https://flag-url.com" {
		t.Errorf("Expected flag URL to override, got '%s'", merged.URL)
	}

	if merged.KeyID != "flag-key-id" {
		t.Errorf("Expected flag KeyID to override, got '%s'", merged.KeyID)
	}

	// Profile values should be used when flags are empty
	if merged.Secret != "profile-secret" {
		t.Errorf("Expected profile secret when flag is empty, got '%s'", merged.Secret)
	}

	if merged.PolicyID != "profile-policy" {
		t.Errorf("Expected profile policy when flag is empty, got '%s'", merged.PolicyID)
	}

	// Flag values should override profile
	if merged.Format != "p12" {
		t.Errorf("Expected flag format to override, got '%s'", merged.Format)
	}
}

func TestCreateExampleProfileConfig(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-example-*.cnf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	err = CreateExampleProfileConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create example config: %v", err)
	}

	// Read and verify the created file
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read created file: %v", err)
	}

	contentStr := string(content)

	// Check for required sections
	requiredSections := []string{"[Default]", "[p12]", "[test]", "[prod]"}
	for _, section := range requiredSections {
		if !strings.Contains(contentStr, section) {
			t.Errorf("Expected section '%s' in example config", section)
		}
	}

	// Check for required fields
	requiredFields := []string{"url", "key-id", "secret", "format", "policy"}
	for _, field := range requiredFields {
		if !strings.Contains(contentStr, field) {
			t.Errorf("Expected field '%s' in example config", field)
		}
	}
}

func TestConfigAliases(t *testing.T) {
	testConfig := `[Default]
base_url = https://ztpki-dev.venafi.com/api/v2
hawk_id = test-id-alias
hawk-key = test-key-alias
key_size = 4096
`

	tmpFile, err := os.CreateTemp("", "test-alias-*.cnf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(testConfig); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}
	tmpFile.Close()

	config, err := LoadProfileConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	profile := config.GetProfile("")
	
	// Test hawk_id alias
	if profile.KeyID != "test-id-alias" {
		t.Errorf("Expected hawk_id alias to work, got '%s'", profile.KeyID)
	}

	// Test hawk-key alias  
	if profile.Secret != "test-key-alias" {
		t.Errorf("Expected hawk-key alias to work, got '%s'", profile.Secret)
	}

	// Test key_size parsing
	if profile.KeySize != 4096 {
		t.Errorf("Expected key_size 4096, got %d", profile.KeySize)
	}
}
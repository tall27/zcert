package config

import (
	"os"
	"strings"
	"testing"
)

func TestProfileSelection(t *testing.T) {
	// Create a test config file
	testConfig := `[Default]
url = https://default-url.com
hawk-id = default-id
hawk-api = default-api

[test]
url = https://test-url.com
hawk-id = test-id
hawk-api = test-api

[prod]
url = https://prod-url.com
hawk-id = prod-id
hawk-api = prod-api`

	// Write test config to temporary file
	tmpFile, err := os.CreateTemp("", "test-config-*.cnf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(testConfig); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}
	tmpFile.Close()

	// Load the profile config
	profileConfig, err := LoadProfileConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load profile config: %v", err)
	}

	// Test 1: No profile specified - should use Default
	defaultProfile := profileConfig.GetProfile("")
	if defaultProfile == nil {
		t.Fatal("Expected default profile, got nil")
	}
	if defaultProfile.Name != "Default" {
		t.Errorf("Expected default profile name 'Default', got '%s'", defaultProfile.Name)
	}
	if defaultProfile.URL != "https://default-url.com" {
		t.Errorf("Expected default URL 'https://default-url.com', got '%s'", defaultProfile.URL)
	}

	// Test 2: Explicit profile specified
	testProfile := profileConfig.GetProfile("test")
	if testProfile == nil {
		t.Fatal("Expected test profile, got nil")
	}
	if testProfile.Name != "test" {
		t.Errorf("Expected test profile name 'test', got '%s'", testProfile.Name)
	}
	if testProfile.URL != "https://test-url.com" {
		t.Errorf("Expected test URL 'https://test-url.com', got '%s'", testProfile.URL)
	}

	// Test 3: List all profiles
	profiles := profileConfig.ListProfiles()
	expectedProfiles := []string{"Default", "test", "prod"}
	for _, expected := range expectedProfiles {
		found := false
		for _, profile := range profiles {
			if profile == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected profile '%s' not found in list: %v", expected, profiles)
		}
	}
}

func TestProfileSelectionWithoutDefault(t *testing.T) {
	// Create a test config file without [Default] section
	testConfig := `[prod]
url = https://prod-url.com
hawk-id = prod-id
hawk-api = prod-api

[test]
url = https://test-url.com
hawk-id = test-id
hawk-api = test-api`

	// Write test config to temporary file
	tmpFile, err := os.CreateTemp("", "test-config-no-default-*.cnf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(testConfig); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}
	tmpFile.Close()

	// Load the profile config
	profileConfig, err := LoadProfileConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load profile config: %v", err)
	}

	// Test: No profile specified - should use first alphabetically (prod < test)
	defaultProfile := profileConfig.GetProfile("")
	if defaultProfile == nil {
		t.Fatal("Expected default profile, got nil")
	}
	if defaultProfile.Name != "prod" {
		t.Errorf("Expected default profile name 'prod' (alphabetically first), got '%s'", defaultProfile.Name)
	}
}

func TestCaseInsensitiveDefault(t *testing.T) {
	// Create a test config file with lowercase default
	testConfig := `[default]
url = https://default-url.com
hawk-id = default-id
hawk-api = default-api

[test]
url = https://test-url.com
hawk-id = test-id
hawk-api = test-api`

	// Write test config to temporary file
	tmpFile, err := os.CreateTemp("", "test-config-lowercase-*.cnf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(testConfig); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}
	tmpFile.Close()

	// Load the profile config
	profileConfig, err := LoadProfileConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load profile config: %v", err)
	}

	// Test: No profile specified - should use lowercase "default" as Default
	defaultProfile := profileConfig.GetProfile("")
	if defaultProfile == nil {
		t.Fatal("Expected default profile, got nil")
	}
	if !strings.EqualFold(defaultProfile.Name, "default") {
		t.Errorf("Expected default profile name (case-insensitive), got '%s'", defaultProfile.Name)
	}
}
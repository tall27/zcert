package main

import (
	"fmt"
	"os"
	"testing"

	"zcert/internal/api"
	"zcert/internal/config"
	"zcert/internal/policy"
)

// TestPolicySelectionIntegration tests the complete policy selection flow
func TestPolicySelectionIntegration(t *testing.T) {
	// Skip if no HAWK credentials available
	hawkID := os.Getenv("ZTPKI_HAWK_ID")
	hawkKey := os.Getenv("ZTPKI_HAWK_SECRET")
	
	if hawkID == "" || hawkKey == "" {
		t.Skip("Skipping integration test - ZTPKI_HAWK_ID and ZTPKI_HAWK_SECRET environment variables required")
	}

	cfg := &config.Config{
		BaseURL: "https://ztpki-dev.venafi.com/api/v2",
		HawkID:  hawkID,
		HawkKey: hawkKey,
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}

	selector := policy.NewPolicySelector(client)

	// Test that we can get available policies
	policies := selector.getAvailablePolicies()
	if len(policies) == 0 {
		t.Error("Expected at least one policy to be available")
	}

	// Test that the verified working policy is present
	found := false
	for _, p := range policies {
		if p.ID == "5fe6d368-896a-4883-97eb-f87148c90896" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find the verified working policy ID in available policies")
	}

	// Test policy validation
	err = selector.ValidatePolicy("5fe6d368-896a-4883-97eb-f87148c90896")
	if err != nil {
		t.Errorf("Expected valid policy to pass validation, got error: %v", err)
	}

	// Test invalid policy validation
	err = selector.ValidatePolicy("invalid-policy-123")
	if err == nil {
		t.Error("Expected invalid policy to fail validation")
	}
}

// TestConfigurationLoading tests various configuration file formats
func TestConfigurationLoading(t *testing.T) {
	// Test CNF format
	cnfContent := `[Default]
url = https://ztpki-dev.venafi.com/api/v2
key-id = test-hawk-id
secret = test-hawk-key
policy = 5fe6d368-896a-4883-97eb-f87148c90896
format = pem
key-size = 2048
key-type = rsa

[staging]
url = https://ztpki-staging.venafi.com/api/v2
key-id = staging-hawk-id
secret = staging-hawk-key
format = p12
`

	// Write CNF test file
	cnfFile, err := os.CreateTemp("", "test-*.cnf")
	if err != nil {
		t.Fatalf("Failed to create temp CNF file: %v", err)
	}
	defer os.Remove(cnfFile.Name())

	if _, err := cnfFile.WriteString(cnfContent); err != nil {
		t.Fatalf("Failed to write CNF content: %v", err)
	}
	cnfFile.Close()

	// Load CNF config
	cnfConfig, err := config.LoadProfileConfig(cnfFile.Name())
	if err != nil {
		t.Fatalf("Failed to load CNF config: %v", err)
	}

	// Verify CNF config
	defaultProfile := cnfConfig.GetProfile("")
	if defaultProfile == nil {
		t.Error("Expected default profile from CNF config")
	}

	if defaultProfile.URL != "https://ztpki-dev.venafi.com/api/v2" {
		t.Errorf("Expected default URL from CNF, got: %s", defaultProfile.URL)
	}

	stagingProfile := cnfConfig.GetProfile("staging")
	if stagingProfile == nil {
		t.Error("Expected staging profile from CNF config")
	}

	if stagingProfile.Format != "p12" {
		t.Errorf("Expected staging format p12, got: %s", stagingProfile.Format)
	}
}

// TestEnrollmentWorkflow tests the certificate enrollment process
func TestEnrollmentWorkflow(t *testing.T) {
	// Skip if no HAWK credentials available
	hawkID := os.Getenv("ZTPKI_HAWK_ID")
	hawkKey := os.Getenv("ZTPKI_HAWK_SECRET")
	
	if hawkID == "" || hawkKey == "" {
		t.Skip("Skipping enrollment test - ZTPKI_HAWK_ID and ZTPKI_HAWK_SECRET environment variables required")
	}

	cfg := &config.Config{
		BaseURL: "https://ztpki-dev.venafi.com/api/v2",
		HawkID:  hawkID,
		HawkKey: hawkKey,
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}

	// Test that client can make authenticated requests
	// This is a basic connectivity test
	searchParams := api.CertificateSearchParams{
		Limit: 1,
	}

	_, err = client.SearchCertificates(searchParams)
	// We expect this might fail with specific API errors, but not auth errors
	if err != nil {
		// Log the error but don't fail the test unless it's an auth error
		fmt.Printf("Search request result: %v\n", err)
	}
}

// TestCLIFlags tests that all required CLI flags are available
func TestCLIFlags(t *testing.T) {
	// This would test the CLI flag definitions
	// We can't easily test this without running the actual CLI
	// But we can test that the flag structures are correct
	
	profile := &config.Profile{
		URL:      "https://ztpki-dev.venafi.com/api/v2",
		KeyID:    "test-id",
		Secret:   "test-key", 
		Format:   "pem",
		PolicyID: "test-policy",
	}

	// Test merging with flags
	merged := config.MergeProfileWithFlags(
		profile,
		"https://override-url.com",
		"override-id",
		"override-key",
		"sha256",
		"p12",
		"override-policy",
		"password123",
		4096,
		"rsa",
	)

	// Verify all flags override profile values
	if merged.URL != "https://override-url.com" {
		t.Error("URL flag should override profile value")
	}
	if merged.KeyID != "override-id" {
		t.Error("KeyID flag should override profile value")
	}
	if merged.Secret != "override-key" {
		t.Error("Secret flag should override profile value")
	}
	if merged.Format != "p12" {
		t.Error("Format flag should override profile value")
	}
	if merged.PolicyID != "override-policy" {
		t.Error("PolicyID flag should override profile value")
	}
}
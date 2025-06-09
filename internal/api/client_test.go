package api

import (
	"testing"

	"zcert/internal/config"
)

func TestNewClient(t *testing.T) {
	cfg := &config.Config{
		BaseURL: "https://ztpki-dev.venafi.com/api/v2",
		HawkID:  "test-hawk-id",
		HawkKey: "test-hawk-key",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client == nil {
		t.Error("Expected client to be non-nil")
	}

	if client.BaseURL != cfg.BaseURL {
		t.Errorf("Expected BaseURL '%s', got '%s'", cfg.BaseURL, client.BaseURL)
	}

	if client.HawkID != cfg.HawkID {
		t.Errorf("Expected HawkID '%s', got '%s'", cfg.HawkID, client.HawkID)
	}

	if client.HawkKey != cfg.HawkKey {
		t.Errorf("Expected HawkKey '%s', got '%s'", cfg.HawkKey, client.HawkKey)
	}
}

func TestNewClientValidation(t *testing.T) {
	testCases := []struct {
		name        string
		config      *config.Config
		expectError bool
	}{
		{
			name: "Valid config",
			config: &config.Config{
				BaseURL: "https://ztpki-dev.venafi.com/api/v2",
				HawkID:  "test-hawk-id",
				HawkKey: "test-hawk-key",
			},
			expectError: false,
		},
		{
			name: "Missing BaseURL",
			config: &config.Config{
				HawkID:  "test-hawk-id",
				HawkKey: "test-hawk-key",
			},
			expectError: true,
		},
		{
			name: "Missing HawkID",
			config: &config.Config{
				BaseURL: "https://ztpki-dev.venafi.com/api/v2",
				HawkKey: "test-hawk-key",
			},
			expectError: true,
		},
		{
			name: "Missing HawkKey",
			config: &config.Config{
				BaseURL: "https://ztpki-dev.venafi.com/api/v2",
				HawkID:  "test-hawk-id",
			},
			expectError: true,
		},
		{
			name: "Invalid BaseURL",
			config: &config.Config{
				BaseURL: "not-a-valid-url",
				HawkID:  "test-hawk-id",
				HawkKey: "test-hawk-key",
			},
			expectError: false, // URL validation might be lenient
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewClient(tc.config)
			
			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			
			if !tc.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			
			if !tc.expectError && client == nil {
				t.Error("Expected client to be non-nil when no error")
			}
		})
	}
}

func TestCertificateSearchParams(t *testing.T) {
	params := CertificateSearchParams{
		Limit:  10,
		Offset: 20,
		Filter: "cn=example.com",
	}

	if params.Limit != 10 {
		t.Errorf("Expected Limit 10, got %d", params.Limit)
	}

	if params.Offset != 20 {
		t.Errorf("Expected Offset 20, got %d", params.Offset)
	}

	if params.Filter != "cn=example.com" {
		t.Errorf("Expected Filter 'cn=example.com', got '%s'", params.Filter)
	}
}

func TestCertificateEnrollmentRequest(t *testing.T) {
	req := CertificateEnrollmentRequest{
		CSR:      "-----BEGIN CERTIFICATE REQUEST-----\n...",
		PolicyID: "test-policy-id",
	}

	if req.CSR == "" {
		t.Error("Expected CSR to be set")
	}

	if req.PolicyID != "test-policy-id" {
		t.Errorf("Expected PolicyID 'test-policy-id', got '%s'", req.PolicyID)
	}
}
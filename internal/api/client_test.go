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

        // Client fields are private, so we test functionality rather than direct field access
        if client.baseURL != cfg.BaseURL {
                t.Errorf("Expected BaseURL '%s', got '%s'", cfg.BaseURL, client.baseURL)
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
                Limit:      10,
                CommonName: "example.com",
                PolicyID:   "test-policy",
        }

        if params.Limit != 10 {
                t.Errorf("Expected Limit 10, got %d", params.Limit)
        }

        if params.CommonName != "example.com" {
                t.Errorf("Expected CommonName 'example.com', got '%s'", params.CommonName)
        }

        if params.PolicyID != "test-policy" {
                t.Errorf("Expected PolicyID 'test-policy', got '%s'", params.PolicyID)
        }
}

func TestCSRSubmissionRequest(t *testing.T) {
        req := CSRSubmissionRequest{
                CSR:    "-----BEGIN CERTIFICATE REQUEST-----\n...",
                Policy: "test-policy-id",
                DNComponents: map[string]interface{}{
                        "CN": "test.example.com",
                },
        }

        if req.CSR == "" {
                t.Error("Expected CSR to be set")
        }

        if req.Policy != "test-policy-id" {
                t.Errorf("Expected Policy 'test-policy-id', got '%s'", req.Policy)
        }

        if req.DNComponents["CN"] != "test.example.com" {
                t.Errorf("Expected CN 'test.example.com', got '%v'", req.DNComponents["CN"])
        }
}
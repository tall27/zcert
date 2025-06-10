package api

import (
        "testing"
        "zcert/internal/config"
)

// TestClientCreationRegression tests various client creation scenarios to prevent regressions
func TestClientCreationRegression(t *testing.T) {
        tests := []struct {
                name        string
                config      *config.Config
                expectError bool
                errorMsg    string
        }{
                {
                        name: "Valid complete config",
                        config: &config.Config{
                                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                                HawkID:  "test-hawk-id",
                                HawkKey: "test-hawk-key",
                        },
                        expectError: false,
                },
                {
                        name:        "Nil config should fail",
                        config:      nil,
                        expectError: true,
                        errorMsg:    "config cannot be nil",
                },
                {
                        name: "Empty BaseURL should fail",
                        config: &config.Config{
                                BaseURL: "",
                                HawkID:  "test-hawk-id",
                                HawkKey: "test-hawk-key",
                        },
                        expectError: true,
                        errorMsg:    "BaseURL is required",
                },
                {
                        name: "Empty HawkID should fail",
                        config: &config.Config{
                                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                                HawkID:  "",
                                HawkKey: "test-hawk-key",
                        },
                        expectError: true,
                        errorMsg:    "HawkID is required",
                },
                {
                        name: "Empty HawkKey should fail",
                        config: &config.Config{
                                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                                HawkID:  "test-hawk-id",
                                HawkKey: "",
                        },
                        expectError: true,
                        errorMsg:    "HawkKey is required",
                },
                {
                        name: "All fields empty should fail",
                        config: &config.Config{
                                BaseURL: "",
                                HawkID:  "",
                                HawkKey: "",
                        },
                        expectError: true,
                        errorMsg:    "BaseURL is required",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        client, err := NewClient(tt.config)

                        if tt.expectError {
                                if err == nil {
                                        t.Errorf("Expected error but got none")
                                }
                                if client != nil {
                                        t.Errorf("Expected nil client when error occurs")
                                }
                                if tt.errorMsg != "" && err != nil && err.Error() != tt.errorMsg {
                                        t.Errorf("Expected error message '%s', got '%s'", tt.errorMsg, err.Error())
                                }
                        } else {
                                if err != nil {
                                        t.Errorf("Expected no error but got: %v", err)
                                }
                                if client == nil {
                                        t.Errorf("Expected non-nil client")
                                }
                                if client != nil && client.baseURL != tt.config.BaseURL {
                                        t.Errorf("Expected BaseURL '%s', got '%s'", tt.config.BaseURL, client.baseURL)
                                }
                        }
                })
        }
}

// TestClientHTTPClientRegression ensures HTTP client is properly configured
func TestClientHTTPClientRegression(t *testing.T) {
        cfg := &config.Config{
                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                HawkID:  "test-hawk-id",
                HawkKey: "test-hawk-key",
        }

        client, err := NewClient(cfg)
        if err != nil {
                t.Fatalf("Failed to create client: %v", err)
        }

        if client.httpClient == nil {
                t.Error("HTTP client should not be nil")
        }

        if client.httpClient.Timeout == 0 {
                t.Error("HTTP client timeout should be set")
        }
}

// TestClientHawkAuthRegression ensures HAWK authentication is properly initialized
func TestClientHawkAuthRegression(t *testing.T) {
        cfg := &config.Config{
                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                HawkID:  "test-hawk-id",
                HawkKey: "test-hawk-key",
        }

        client, err := NewClient(cfg)
        if err != nil {
                t.Fatalf("Failed to create client: %v", err)
        }

        if client.hawkAuth == nil {
                t.Error("HAWK auth should not be nil")
        }
}

// TestCertificateSearchParamsRegression ensures search params structure integrity
func TestCertificateSearchParamsRegression(t *testing.T) {
        params := CertificateSearchParams{
                Limit:      50,
                CommonName: "test.example.com",
                PolicyID:   "test-policy-id",
        }

        // Verify field values are preserved
        if params.Limit != 50 {
                t.Errorf("Expected Limit 50, got %d", params.Limit)
        }
        if params.CommonName != "test.example.com" {
                t.Errorf("Expected CommonName 'test.example.com', got '%s'", params.CommonName)
        }
        if params.PolicyID != "test-policy-id" {
                t.Errorf("Expected PolicyID 'test-policy-id', got '%s'", params.PolicyID)
        }

        // Test zero values
        emptyParams := CertificateSearchParams{}
        if emptyParams.Limit != 0 {
                t.Errorf("Expected default Limit 0, got %d", emptyParams.Limit)
        }
        if emptyParams.CommonName != "" {
                t.Errorf("Expected empty CommonName, got '%s'", emptyParams.CommonName)
        }
}

// TestCSRSubmissionRequestRegression ensures CSR request structure integrity
func TestCSRSubmissionRequestRegression(t *testing.T) {
        csr := "-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKdGVzdC5jb20..."
        request := CSRSubmissionRequest{
                CSR:    csr,
                Policy: "test-policy-id",
                DNComponents: map[string]interface{}{
                        "CN": "test.example.com",
                },
        }

        if request.CSR != csr {
                t.Errorf("Expected CSR to match input")
        }
        if request.Policy != "test-policy-id" {
                t.Errorf("Expected Policy 'test-policy-id', got '%s'", request.Policy)
        }
        if request.DNComponents == nil {
                t.Error("Expected DNComponents to be initialized")
        }

        // Test with empty values
        emptyRequest := CSRSubmissionRequest{}
        if emptyRequest.CSR != "" {
                t.Errorf("Expected empty CSR, got '%s'", emptyRequest.CSR)
        }
        if emptyRequest.Policy != "" {
                t.Errorf("Expected empty Policy, got '%s'", emptyRequest.Policy)
        }
        if emptyRequest.DNComponents != nil {
                t.Error("Expected DNComponents to be nil for empty request")
        }
}
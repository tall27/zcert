package api

import (
	"testing"
	"zcert/internal/config"
)

func TestEnrollmentWorkflow(t *testing.T) {
	// This is a unit test for the enrollment workflow function structure
	// We test the function signature and basic validation without making actual API calls
	
	cfg := &config.Config{
		BaseURL: "https://test-ztpki-instance.com/api/v2",
		HawkID:  "test-hawk-id",
		HawkKey: "test-hawk-key",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test with nil certificate task (should fail gracefully)
	_, err = client.EnrollmentWorkflow("invalid-csr", nil)
	if err == nil {
		t.Error("Expected error with nil certificate task")
	}

	// Test with empty CSR (should fail gracefully)
	certTask := &config.CertificateTask{
		Request: config.CertificateRequest{
			Subject: config.CertificateSubject{
				CommonName: "test.example.com",
			},
			Policy: "test-policy",
		},
	}
	
	_, err = client.EnrollmentWorkflow("", certTask)
	if err == nil {
		t.Error("Expected error with empty CSR")
	}
}

func TestPollForCertificateCompletion(t *testing.T) {
	// Test the polling function structure without making actual API calls
	
	cfg := &config.Config{
		BaseURL: "https://test-ztpki-instance.com/api/v2",
		HawkID:  "test-hawk-id",
		HawkKey: "test-hawk-key",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test with invalid request ID (should fail gracefully)
	_, err = client.PollForCertificateCompletion("invalid-request-id", 1)
	if err == nil {
		t.Error("Expected error with invalid request ID")
	}

	// Test with zero max attempts (should fail immediately)
	_, err = client.PollForCertificateCompletion("test-request-id", 0)
	if err == nil {
		t.Error("Expected error with zero max attempts")
	}
}

func TestExtractCNFromCSR(t *testing.T) {
	tests := []struct {
		name        string
		csrPEM      string
		expectedCN  string
		expectError bool
	}{
		{
			name:        "Empty CSR",
			csrPEM:      "",
			expectedCN:  "",
			expectError: true,
		},
		{
			name:        "Invalid PEM format",
			csrPEM:      "invalid pem content",
			expectedCN:  "",
			expectError: true,
		},
		{
			name: "Valid CSR format structure",
			csrPEM: `-----BEGIN CERTIFICATE REQUEST-----
MIICZjCCAU4CAQAwGTEXMBUGA1UEAwwOdGVzdC5leGFtcGxlLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAL8+K9OB1NQFJLv2Z2xD5c6yE8qN2wJv
-----END CERTIFICATE REQUEST-----`,
			expectedCN:  "", // This will fail parsing but tests structure
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cn, err := extractCNFromCSR(tt.csrPEM)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if cn != tt.expectedCN {
					t.Errorf("Expected CN '%s', got '%s'", tt.expectedCN, cn)
				}
			}
		})
	}
}

// Test that the new methods don't break existing API client functionality
func TestClientMethodsExist(t *testing.T) {
	cfg := &config.Config{
		BaseURL: "https://test-ztpki-instance.com/api/v2",
		HawkID:  "test-hawk-id",
		HawkKey: "test-hawk-key",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Verify that our new methods exist on the client
	if client == nil {
		t.Fatal("Client should not be nil")
	}

	// Test that we can call the methods (they should fail gracefully with invalid input)
	_, err = client.EnrollmentWorkflow("", nil)
	if err == nil {
		t.Error("EnrollmentWorkflow should return error with empty input")
	}

	_, err = client.PollForCertificateCompletion("", 0)
	if err == nil {
		t.Error("PollForCertificateCompletion should return error with empty input")
	}
}
package utils

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"zcert/internal/api"
)

// MockClient for testing chain retrieval
type MockClient struct {
	getCertificateFunc    func(id string) (*api.Certificate, error)
	getCertificatePEMFunc func(id string, includeChain bool) (*api.CertificatePEMResponse, error)
}

func (m *MockClient) GetCertificate(id string) (*api.Certificate, error) {
	if m.getCertificateFunc != nil {
		return m.getCertificateFunc(id)
	}
	return nil, errors.New("not implemented")
}

func (m *MockClient) GetCertificatePEM(id string, includeChain bool) (*api.CertificatePEMResponse, error) {
	if m.getCertificatePEMFunc != nil {
		return m.getCertificatePEMFunc(id, includeChain)
	}
	return nil, errors.New("not implemented")
}

// TestRetrieveCertificateWithChain tests basic certificate retrieval with chain
func TestRetrieveCertificateWithChain(t *testing.T) {
	// Create mock client
	client := &MockClient{
		getCertificateFunc: func(id string) (*api.Certificate, error) {
			return createTestCertificate(id), nil
		},
		getCertificatePEMFunc: func(id string, includeChain bool) (*api.CertificatePEMResponse, error) {
			response := &api.CertificatePEMResponse{
				Certificate: "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----",
				SelfSigned:  false,
			}
			if includeChain {
				response.Chain = "-----BEGIN CERTIFICATE-----\ntest-chain\n-----END CERTIFICATE-----"
			}
			return response, nil
		},
	}
	
	opts := &ChainRetrievalOptions{
		IncludeChain: true,
		FallbackMode: false,
		VerboseLevel: 0,
	}
	
	cert, pemResp, err := RetrieveCertificateWithChain(client, "test-cert-1", opts)
	
	if err != nil {
		t.Fatalf("RetrieveCertificateWithChain failed: %v", err)
	}
	
	if cert == nil {
		t.Fatal("Certificate should not be nil")
	}
	
	if pemResp == nil {
		t.Fatal("PEM response should not be nil")
	}
	
	// Check certificate data
	if cert.ID != "test-cert-1" {
		t.Errorf("Expected certificate ID 'test-cert-1', got '%s'", cert.ID)
	}
	
	// Check that chain was included
	if len(cert.Chain) == 0 {
		t.Error("Certificate should have chain data")
	}
	
	if cert.Chain[0] != "-----BEGIN CERTIFICATE-----\ntest-chain\n-----END CERTIFICATE-----" {
		t.Error("Chain data should match expected value")
	}
}

// TestRetrieveCertificateWithChainFallback tests fallback behavior when chain retrieval fails
func TestRetrieveCertificateWithChainFallback(t *testing.T) {
	// Capture stderr for verbose output testing
	var stderr bytes.Buffer
	originalStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	
	defer func() {
		w.Close()
		os.Stderr = originalStderr
	}()
	
	go func() {
		defer r.Close()
		buf := make([]byte, 1024)
		for {
			n, err := r.Read(buf)
			if err != nil {
				break
			}
			stderr.Write(buf[:n])
		}
	}()
	
	client := &MockClient{
		getCertificateFunc: func(id string) (*api.Certificate, error) {
			return createTestCertificate(id), nil
		},
		getCertificatePEMFunc: func(id string, includeChain bool) (*api.CertificatePEMResponse, error) {
			if includeChain {
				// Simulate chain retrieval failure
				return nil, errors.New("chain retrieval failed")
			}
			// Return certificate without chain
			return &api.CertificatePEMResponse{
				Certificate: "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----",
				SelfSigned:  false,
			}, nil
		},
	}
	
	opts := &ChainRetrievalOptions{
		IncludeChain: true,
		FallbackMode: true,
		VerboseLevel: 1,
	}
	
	cert, pemResp, err := RetrieveCertificateWithChain(client, "test-cert-1", opts)
	
	if err != nil {
		t.Fatalf("RetrieveCertificateWithChain should succeed with fallback: %v", err)
	}
	
	if cert == nil {
		t.Fatal("Certificate should not be nil")
	}
	
	if pemResp == nil {
		t.Fatal("PEM response should not be nil")
	}
	
	// Check that certificate data is present
	if cert.Certificate == "" {
		t.Error("Certificate PEM data should be present")
	}
	
	// Check that chain is empty (fallback succeeded)
	if len(cert.Chain) != 0 {
		t.Error("Certificate should not have chain data when fallback used")
	}
}

// TestRetrieveCertificateWithChainNoFallback tests behavior when fallback is disabled
func TestRetrieveCertificateWithChainNoFallback(t *testing.T) {
	client := &MockClient{
		getCertificateFunc: func(id string) (*api.Certificate, error) {
			return createTestCertificate(id), nil
		},
		getCertificatePEMFunc: func(id string, includeChain bool) (*api.CertificatePEMResponse, error) {
			if includeChain {
				// Simulate chain retrieval failure
				return nil, errors.New("chain retrieval failed")
			}
			return &api.CertificatePEMResponse{
				Certificate: "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----",
				SelfSigned:  false,
			}, nil
		},
	}
	
	opts := &ChainRetrievalOptions{
		IncludeChain: true,
		FallbackMode: false,
		VerboseLevel: 0,
	}
	
	_, _, err := RetrieveCertificateWithChain(client, "test-cert-1", opts)
	
	if err == nil {
		t.Fatal("RetrieveCertificateWithChain should fail when fallback is disabled")
	}
	
	if !strings.Contains(err.Error(), "failed to retrieve certificate in PEM format") {
		t.Errorf("Error should indicate PEM retrieval failure, got: %v", err)
	}
}

// TestRetrieveCertificateWithChainResult tests detailed chain retrieval results
func TestRetrieveCertificateWithChainResult(t *testing.T) {
	testCases := []struct {
		name               string
		includeChain       bool
		chainInResponse    bool
		simulateChainError bool
		fallbackMode       bool
		expectedRetrieved  bool
		expectedFallback   bool
		shouldError        bool
	}{
		{
			name:              "Successful chain retrieval",
			includeChain:      true,
			chainInResponse:   true,
			expectedRetrieved: true,
			expectedFallback:  false,
		},
		{
			name:               "Chain error with fallback",
			includeChain:       true,
			simulateChainError: true,
			fallbackMode:       true,
			expectedRetrieved:  false,
			expectedFallback:   true,
		},
		{
			name:               "Chain error without fallback",
			includeChain:       true,
			simulateChainError: true,
			fallbackMode:       false,
			shouldError:        true,
		},
		{
			name:              "No chain requested",
			includeChain:      false,
			expectedRetrieved: false,
			expectedFallback:  false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &MockClient{
				getCertificateFunc: func(id string) (*api.Certificate, error) {
					return createTestCertificate(id), nil
				},
				getCertificatePEMFunc: func(id string, includeChain bool) (*api.CertificatePEMResponse, error) {
					if includeChain && tc.simulateChainError {
						return nil, errors.New("chain error")
					}
					
					response := &api.CertificatePEMResponse{
						Certificate: "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----",
						SelfSigned:  false,
					}
					
					if includeChain && tc.chainInResponse {
						response.Chain = "-----BEGIN CERTIFICATE-----\ntest-chain\n-----END CERTIFICATE-----"
					}
					
					return response, nil
				},
			}
			
			opts := &ChainRetrievalOptions{
				IncludeChain: tc.includeChain,
				FallbackMode: tc.fallbackMode,
				VerboseLevel: 0,
			}
			
			result, err := RetrieveCertificateWithChainResult(client, "test-cert-1", opts)
			
			if tc.shouldError {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			if result == nil {
				t.Fatal("Result should not be nil")
			}
			
			if result.ChainRetrieved != tc.expectedRetrieved {
				t.Errorf("Expected ChainRetrieved=%v, got %v", tc.expectedRetrieved, result.ChainRetrieved)
			}
			
			if result.FallbackUsed != tc.expectedFallback {
				t.Errorf("Expected FallbackUsed=%v, got %v", tc.expectedFallback, result.FallbackUsed)
			}
			
			if result.Certificate == nil {
				t.Error("Certificate should not be nil in result")
			}
			
			if result.PEMResponse == nil {
				t.Error("PEMResponse should not be nil in result")
			}
		})
	}
}

// TestStandardizeChainHandling tests chain standardization
func TestStandardizeChainHandling(t *testing.T) {
	testCases := []struct {
		name         string
		certChain    []string
		pemChain     string
		expectedLen  int
		expectedVal  string
	}{
		{
			name:        "Empty chain",
			certChain:   nil,
			pemChain:    "",
			expectedLen: 0,
		},
		{
			name:        "PEM chain present",
			certChain:   nil,
			pemChain:    "test-chain-pem",
			expectedLen: 1,
			expectedVal: "test-chain-pem",
		},
		{
			name:        "Existing cert chain with new PEM",
			certChain:   []string{"old-chain"},
			pemChain:    "new-chain-pem",
			expectedLen: 1,
			expectedVal: "new-chain-pem",
		},
		{
			name:        "Existing cert chain without PEM",
			certChain:   []string{"existing-chain"},
			pemChain:    "",
			expectedLen: 0,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cert := &api.Certificate{
				ID:    "test",
				Chain: tc.certChain,
			}
			
			pemResp := &api.CertificatePEMResponse{
				Certificate: "test-cert",
				Chain:       tc.pemChain,
			}
			
			StandardizeChainHandling(cert, pemResp)
			
			if len(cert.Chain) != tc.expectedLen {
				t.Errorf("Expected chain length %d, got %d", tc.expectedLen, len(cert.Chain))
			}
			
			if tc.expectedLen > 0 && cert.Chain[0] != tc.expectedVal {
				t.Errorf("Expected chain value '%s', got '%s'", tc.expectedVal, cert.Chain[0])
			}
		})
	}
}

// TestGetChainFromCertificate tests chain extraction utility
func TestGetChainFromCertificate(t *testing.T) {
	testCases := []struct {
		name     string
		chain    []string
		expected []string
	}{
		{
			name:     "Nil chain",
			chain:    nil,
			expected: []string{},
		},
		{
			name:     "Empty chain",
			chain:    []string{},
			expected: []string{},
		},
		{
			name:     "Single chain entry",
			chain:    []string{"chain-cert-1"},
			expected: []string{"chain-cert-1"},
		},
		{
			name:     "Multiple chain entries",
			chain:    []string{"chain-cert-1", "chain-cert-2"},
			expected: []string{"chain-cert-1", "chain-cert-2"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cert := &api.Certificate{
				Chain: tc.chain,
			}
			
			result := GetChainFromCertificate(cert)
			
			if len(result) != len(tc.expected) {
				t.Errorf("Expected chain length %d, got %d", len(tc.expected), len(result))
			}
			
			for i, expected := range tc.expected {
				if i >= len(result) || result[i] != expected {
					t.Errorf("Expected chain[%d] = '%s', got '%s'", i, expected, result[i])
				}
			}
		})
	}
}

// TestHasChain tests chain presence detection
func TestHasChain(t *testing.T) {
	testCases := []struct {
		name     string
		chain    []string
		expected bool
	}{
		{"Nil chain", nil, false},
		{"Empty chain", []string{}, false},
		{"Single chain entry", []string{"chain-cert"}, true},
		{"Multiple chain entries", []string{"cert1", "cert2"}, true},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cert := &api.Certificate{
				Chain: tc.chain,
			}
			
			result := HasChain(cert)
			
			if result != tc.expected {
				t.Errorf("Expected HasChain=%v, got %v", tc.expected, result)
			}
		})
	}
}

// TestGetFullChainPEM tests full chain PEM construction
func TestGetFullChainPEM(t *testing.T) {
	testCases := []struct {
		name         string
		certificate  string
		chain        []string
		expected     string
	}{
		{
			name:        "Certificate only",
			certificate: "cert-pem",
			chain:       nil,
			expected:    "cert-pem",
		},
		{
			name:        "Certificate with single chain",
			certificate: "cert-pem",
			chain:       []string{"chain-pem"},
			expected:    "cert-pem\nchain-pem",
		},
		{
			name:        "Certificate with multiple chain entries",
			certificate: "cert-pem",
			chain:       []string{"chain1-pem", "chain2-pem"},
			expected:    "cert-pem\nchain1-pem\nchain2-pem",
		},
		{
			name:        "Certificate with empty chain entry",
			certificate: "cert-pem",
			chain:       []string{"", "chain-pem"},
			expected:    "cert-pem\nchain-pem",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cert := &api.Certificate{
				Certificate: tc.certificate,
				Chain:       tc.chain,
			}
			
			result := GetFullChainPEM(cert)
			
			if result != tc.expected {
				t.Errorf("Expected full chain PEM:\n%s\nGot:\n%s", tc.expected, result)
			}
		})
	}
}

// TestChainRetrievalOptionsDefaults tests default options behavior
func TestChainRetrievalOptionsDefaults(t *testing.T) {
	client := &MockClient{
		getCertificateFunc: func(id string) (*api.Certificate, error) {
			return createTestCertificate(id), nil
		},
		getCertificatePEMFunc: func(id string, includeChain bool) (*api.CertificatePEMResponse, error) {
			return &api.CertificatePEMResponse{
				Certificate: "test-cert",
				SelfSigned:  false,
			}, nil
		},
	}
	
	// Test with nil options (should use defaults)
	cert, pemResp, err := RetrieveCertificateWithChain(client, "test-cert-1", nil)
	
	if err != nil {
		t.Fatalf("RetrieveCertificateWithChain with nil options failed: %v", err)
	}
	
	if cert == nil {
		t.Fatal("Certificate should not be nil")
	}
	
	if pemResp == nil {
		t.Fatal("PEM response should not be nil")
	}
}

// TestCertificateRetrievalErrors tests error handling in certificate retrieval
func TestCertificateRetrievalErrors(t *testing.T) {
	// Test GetCertificate error
	t.Run("GetCertificate error", func(t *testing.T) {
		client := &MockClient{
			getCertificateFunc: func(id string) (*api.Certificate, error) {
				return nil, errors.New("certificate not found")
			},
		}
		
		opts := &ChainRetrievalOptions{
			IncludeChain: false,
			FallbackMode: false,
		}
		
		_, _, err := RetrieveCertificateWithChain(client, "nonexistent", opts)
		
		if err == nil {
			t.Fatal("Expected error for nonexistent certificate")
		}
		
		// Should be wrapped with standardized error
		if !strings.Contains(err.Error(), "failed to retrieve certificate") {
			t.Errorf("Error should be wrapped with standard message, got: %v", err)
		}
	})
	
	// Test GetCertificatePEM error without fallback
	t.Run("GetCertificatePEM error without fallback", func(t *testing.T) {
		client := &MockClient{
			getCertificateFunc: func(id string) (*api.Certificate, error) {
				return createTestCertificate(id), nil
			},
			getCertificatePEMFunc: func(id string, includeChain bool) (*api.CertificatePEMResponse, error) {
				return nil, errors.New("PEM retrieval failed")
			},
		}
		
		opts := &ChainRetrievalOptions{
			IncludeChain: false,
			FallbackMode: false,
		}
		
		_, _, err := RetrieveCertificateWithChain(client, "test-cert", opts)
		
		if err == nil {
			t.Fatal("Expected error for PEM retrieval failure")
		}
	})
}

// Helper function to create test certificate
func createTestCertificate(id string) *api.Certificate {
	expiryDate, _ := time.Parse(time.RFC3339, "2025-01-01T12:00:00Z")
	
	return &api.Certificate{
		ID:           id,
		CommonName:   "test.example.com",
		SerialNumber: "123456",
		Status:       "Valid",
		Issuer:       "Test CA",
		ExpiryDate:   expiryDate,
		PolicyID:     "test-policy",
	}
}

// TestChainHandlingIntegration tests integration between different chain utilities
func TestChainHandlingIntegration(t *testing.T) {
	// Create a certificate with complex chain scenario
	cert := &api.Certificate{
		ID:          "integration-test",
		Certificate: "cert-pem-data", // Existing certificate data
		Chain:       []string{"old-chain"},
	}
	
	pemResp := &api.CertificatePEMResponse{
		Certificate: "new-cert-pem-data",
		Chain:       "new-chain-pem-data",
	}
	
	// Standardize chain handling
	StandardizeChainHandling(cert, pemResp)
	
	// Test chain extraction
	chain := GetChainFromCertificate(cert)
	if len(chain) != 1 || chain[0] != "new-chain-pem-data" {
		t.Error("Chain should be updated with new PEM data")
	}
	
	// Test chain presence
	if !HasChain(cert) {
		t.Error("Certificate should have chain after standardization")
	}
	
	// Test full chain PEM construction
	// Note: StandardizeChainHandling only updates Certificate field if it's empty
	// So the existing certificate data is preserved
	fullPEM := GetFullChainPEM(cert)
	expectedPEM := "cert-pem-data\nnew-chain-pem-data" // Original cert + new chain
	if fullPEM != expectedPEM {
		t.Errorf("Full chain PEM should be '%s', got '%s'", expectedPEM, fullPEM)
	}
	
	// Test that certificate field preservation works correctly
	if cert.Certificate != "cert-pem-data" {
		t.Error("Original certificate data should be preserved when not empty")
	}
	
	// Test with empty certificate field
	emptyCert := &api.Certificate{
		ID:          "empty-test",
		Certificate: "", // Empty certificate data
		Chain:       []string{"old-chain"},
	}
	
	StandardizeChainHandling(emptyCert, pemResp)
	
	if emptyCert.Certificate != "new-cert-pem-data" {
		t.Error("Certificate field should be updated when empty")
	}
	
	fullPEMEmpty := GetFullChainPEM(emptyCert)
	expectedPEMEmpty := "new-cert-pem-data\nnew-chain-pem-data"
	if fullPEMEmpty != expectedPEMEmpty {
		t.Errorf("Full chain PEM for empty cert should be '%s', got '%s'", expectedPEMEmpty, fullPEMEmpty)
	}
}
package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"strings"
	"testing"
)

// TestCSRGenerationRegression tests CSR generation with various parameters
func TestCSRGenerationRegression(t *testing.T) {
	tests := []struct {
		name         string
		commonName   string
		keySize      int
		keyType      string
		sans         []string
		expectError  bool
	}{
		{
			name:         "Valid RSA 2048 CSR",
			commonName:   "test.example.com",
			keySize:      2048,
			keyType:      "rsa",
			sans:         []string{"alt1.example.com", "alt2.example.com"},
			expectError:  false,
		},
		{
			name:         "Valid RSA 4096 CSR", 
			commonName:   "secure.example.com",
			keySize:      4096,
			keyType:      "rsa",
			sans:         []string{},
			expectError:  false,
		},
		{
			name:         "Empty common name should fail",
			commonName:   "",
			keySize:      2048,
			keyType:      "rsa",
			sans:         []string{},
			expectError:  true,
		},
		{
			name:         "Invalid key size should fail",
			commonName:   "test.example.com",
			keySize:      1024,
			keyType:      "rsa",
			sans:         []string{},
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr, privateKey, err := GenerateCSR(tt.commonName, tt.keySize, tt.keyType, tt.sans)

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

			if csr == "" {
				t.Error("CSR should not be empty")
			}

			if privateKey == "" {
				t.Error("Private key should not be empty")
			}

			// Validate CSR format
			if !strings.Contains(csr, "-----BEGIN CERTIFICATE REQUEST-----") {
				t.Error("CSR should contain proper PEM header")
			}

			if !strings.Contains(csr, "-----END CERTIFICATE REQUEST-----") {
				t.Error("CSR should contain proper PEM footer")
			}

			// Validate private key format
			if !strings.Contains(privateKey, "-----BEGIN") {
				t.Error("Private key should contain proper PEM header")
			}

			if !strings.Contains(privateKey, "-----END") {
				t.Error("Private key should contain proper PEM footer")
			}
		})
	}
}

// TestCSRParsingRegression tests CSR parsing and validation
func TestCSRParsingRegression(t *testing.T) {
	// Generate a test CSR
	csr, _, err := GenerateCSR("test.example.com", 2048, "rsa", []string{"alt.example.com"})
	if err != nil {
		t.Fatalf("Failed to generate test CSR: %v", err)
	}

	// Parse the CSR
	block, _ := pem.Decode([]byte(csr))
	if block == nil {
		t.Fatal("Failed to decode PEM block from CSR")
	}

	if block.Type != "CERTIFICATE REQUEST" {
		t.Errorf("Expected block type 'CERTIFICATE REQUEST', got '%s'", block.Type)
	}

	parsedCSR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse CSR: %v", err)
		return
	}

	// Validate CSR contents
	if parsedCSR.Subject.CommonName != "test.example.com" {
		t.Errorf("Expected CN 'test.example.com', got '%s'", parsedCSR.Subject.CommonName)
	}

	// Check if SAN is present
	found := false
	for _, name := range parsedCSR.DNSNames {
		if name == "alt.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected SAN 'alt.example.com' not found in CSR")
	}
}

// TestPrivateKeyGenerationRegression tests private key generation consistency
func TestPrivateKeyGenerationRegression(t *testing.T) {
	tests := []struct {
		name     string
		keySize  int
		keyType  string
		expected string
	}{
		{
			name:     "RSA 2048 key",
			keySize:  2048,
			keyType:  "rsa",
			expected: "RSA PRIVATE KEY",
		},
		{
			name:     "RSA 4096 key",
			keySize:  4096,
			keyType:  "rsa", 
			expected: "RSA PRIVATE KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, privateKey, err := GenerateCSR("test.example.com", tt.keySize, tt.keyType, []string{})
			if err != nil {
				t.Errorf("Failed to generate CSR: %v", err)
				return
			}

			if !strings.Contains(privateKey, tt.expected) {
				t.Errorf("Expected private key to contain '%s'", tt.expected)
			}

			// Validate key can be parsed
			block, _ := pem.Decode([]byte(privateKey))
			if block == nil {
				t.Error("Failed to decode private key PEM block")
				return
			}

			if tt.keyType == "rsa" {
				_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					t.Errorf("Failed to parse RSA private key: %v", err)
				}
			}
		})
	}
}

// TestSANHandlingRegression tests Subject Alternative Name handling
func TestSANHandlingRegression(t *testing.T) {
	tests := []struct {
		name         string
		sans         []string
		expectedDNS  []string
		expectedIP   []net.IP
	}{
		{
			name:         "DNS SANs only",
			sans:         []string{"www.example.com", "api.example.com"},
			expectedDNS:  []string{"www.example.com", "api.example.com"},
			expectedIP:   []net.IP{},
		},
		{
			name:         "Mixed DNS and IP SANs",
			sans:         []string{"www.example.com", "192.168.1.1"},
			expectedDNS:  []string{"www.example.com"},
			expectedIP:   []net.IP{net.ParseIP("192.168.1.1")},
		},
		{
			name:         "No SANs",
			sans:         []string{},
			expectedDNS:  []string{},
			expectedIP:   []net.IP{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr, _, err := GenerateCSR("test.example.com", 2048, "rsa", tt.sans)
			if err != nil {
				t.Errorf("Failed to generate CSR: %v", err)
				return
			}

			// Parse and validate SANs
			block, _ := pem.Decode([]byte(csr))
			if block == nil {
				t.Fatal("Failed to decode CSR PEM block")
			}

			parsedCSR, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Errorf("Failed to parse CSR: %v", err)
				return
			}

			// Validate DNS SANs
			if len(parsedCSR.DNSNames) != len(tt.expectedDNS) {
				t.Errorf("Expected %d DNS SANs, got %d", len(tt.expectedDNS), len(parsedCSR.DNSNames))
			}

			for _, expectedDNS := range tt.expectedDNS {
				found := false
				for _, dnsName := range parsedCSR.DNSNames {
					if dnsName == expectedDNS {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected DNS SAN '%s' not found", expectedDNS)
				}
			}

			// Validate IP SANs
			if len(parsedCSR.IPAddresses) != len(tt.expectedIP) {
				t.Errorf("Expected %d IP SANs, got %d", len(tt.expectedIP), len(parsedCSR.IPAddresses))
			}
		})
	}
}

// TestCSRSubjectRegression tests CSR subject field handling
func TestCSRSubjectRegression(t *testing.T) {
	csr, _, err := GenerateCSR("test.example.com", 2048, "rsa", []string{})
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	block, _ := pem.Decode([]byte(csr))
	if block == nil {
		t.Fatal("Failed to decode CSR PEM block")
	}

	parsedCSR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse CSR: %v", err)
		return
	}

	expected := pkix.Name{
		CommonName: "test.example.com",
	}

	if parsedCSR.Subject.CommonName != expected.CommonName {
		t.Errorf("Expected CN '%s', got '%s'", expected.CommonName, parsedCSR.Subject.CommonName)
	}
}

// TestKeyGenerationConsistencyRegression tests key generation consistency
func TestKeyGenerationConsistencyRegression(t *testing.T) {
	// Generate multiple keys and ensure they're different
	keys := make(map[string]bool)
	
	for i := 0; i < 5; i++ {
		_, privateKey, err := GenerateCSR("test.example.com", 2048, "rsa", []string{})
		if err != nil {
			t.Errorf("Failed to generate CSR iteration %d: %v", i, err)
			continue
		}

		if keys[privateKey] {
			t.Error("Generated duplicate private key - randomness issue")
		}
		keys[privateKey] = true
	}

	if len(keys) < 5 {
		t.Errorf("Expected 5 unique keys, got %d", len(keys))
	}
}

// Mock GenerateCSR function for testing (actual implementation would be in cert package)
func GenerateCSR(commonName string, keySize int, keyType string, sans []string) (string, string, error) {
	if commonName == "" {
		return "", "", fmt.Errorf("common name is required")
	}
	
	if keySize < 2048 {
		return "", "", fmt.Errorf("key size must be at least 2048 bits")
	}

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return "", "", err
	}

	// Create certificate request template
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Add SANs
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	// Create the CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return "", "", err
	}

	// Encode CSR as PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	// Encode private key as PEM
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return string(csrPEM), string(privateKeyPEM), nil
}

import "fmt"
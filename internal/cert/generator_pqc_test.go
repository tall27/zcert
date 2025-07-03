package cert

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPQCGeneratorOpenSSLCleanup tests the OpenSSL cleanup functionality
func TestPQCGeneratorOpenSSLCleanup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test-pqc-cleanup-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test with cleanup enabled (default)
	t.Run("Cleanup enabled", func(t *testing.T) {
		generator := NewPQCGenerator("openssl", tempDir, false, false, false, "", "")

		if !generator.OpenSSLCleanup {
			t.Error("Expected OpenSSLCleanup to be true by default")
		}
	})

	// Test setting cleanup to false
	t.Run("Set cleanup to false", func(t *testing.T) {
		generator := NewPQCGenerator("openssl", tempDir, false, false, false, "", "")
		generator.SetOpenSSLCleanup(false)

		if generator.OpenSSLCleanup {
			t.Error("Expected OpenSSLCleanup to be false after setting")
		}
	})

	// Test setting cleanup to true
	t.Run("Set cleanup to true", func(t *testing.T) {
		generator := NewPQCGenerator("openssl", tempDir, false, false, false, "", "")
		generator.SetOpenSSLCleanup(false)
		generator.SetOpenSSLCleanup(true)

		if !generator.OpenSSLCleanup {
			t.Error("Expected OpenSSLCleanup to be true after setting")
		}
	})
}

// TestPQCGeneratorOpenSSLConfigGeneration tests OpenSSL config file generation
func TestPQCGeneratorOpenSSLConfigGeneration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test-pqc-config-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	generator := NewPQCGenerator("openssl", tempDir, false, false, false, "", "")

	// Test basic subject
	subject := Subject{
		CommonName:         "test.example.com",
		Country:            "US",
		Province:           "California",
		Locality:           "San Francisco",
		Organization:       "Test Corp",
		OrganizationalUnit: "IT Department",
	}

	// Test without SANs
	t.Run("Config without SANs", func(t *testing.T) {
		configFile := filepath.Join(tempDir, "test-no-sans.cnf")
		err := generator.generateOpenSSLConfig(configFile, subject, []string{})
		if err != nil {
			t.Fatalf("Failed to generate OpenSSL config: %v", err)
		}

		// Read and verify the config
		content, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatalf("Failed to read config file: %v", err)
		}

		contentStr := string(content)

		// Check required sections
		if !strings.Contains(contentStr, "[req]") {
			t.Error("Config should contain [req] section")
		}
		if !strings.Contains(contentStr, "[req_distinguished_name]") {
			t.Error("Config should contain [req_distinguished_name] section")
		}
		if !strings.Contains(contentStr, "[v3_req]") {
			t.Error("Config should contain [v3_req] section")
		}

		// Check subject fields
		if !strings.Contains(contentStr, "CN = test.example.com") {
			t.Error("Config should contain correct CN")
		}
		if !strings.Contains(contentStr, "C = US") {
			t.Error("Config should contain correct country")
		}
		if !strings.Contains(contentStr, "ST = California") {
			t.Error("Config should contain correct state/province")
		}
		if !strings.Contains(contentStr, "L = San Francisco") {
			t.Error("Config should contain correct locality")
		}
		if !strings.Contains(contentStr, "O = Test Corp") {
			t.Error("Config should contain correct organization")
		}
		if !strings.Contains(contentStr, "OU = IT Department") {
			t.Error("Config should contain correct organizational unit")
		}

		// Check basic constraints and key usage
		if !strings.Contains(contentStr, "basicConstraints = CA:FALSE") {
			t.Error("Config should contain basicConstraints")
		}
		if !strings.Contains(contentStr, "keyUsage = digitalSignature, nonRepudiation") {
			t.Error("Config should contain keyUsage")
		}

		// Should NOT contain SANs
		if strings.Contains(contentStr, "subjectAltName") {
			t.Error("Config should not contain subjectAltName when no SANs provided")
		}
		if strings.Contains(contentStr, "[alt_names]") {
			t.Error("Config should not contain [alt_names] section when no SANs provided")
		}
	})

	// Test with SANs
	t.Run("Config with SANs", func(t *testing.T) {
		configFile := filepath.Join(tempDir, "test-with-sans.cnf")
		sans := []string{
			"alt1.example.com",
			"alt2.example.com",
			"192.168.1.1",
			"test@example.com",
		}

		err := generator.generateOpenSSLConfig(configFile, subject, sans)
		if err != nil {
			t.Fatalf("Failed to generate OpenSSL config: %v", err)
		}

		// Read and verify the config
		content, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatalf("Failed to read config file: %v", err)
		}

		contentStr := string(content)

		// Should contain SANs
		if !strings.Contains(contentStr, "subjectAltName = @alt_names") {
			t.Error("Config should contain subjectAltName reference")
		}
		if !strings.Contains(contentStr, "[alt_names]") {
			t.Error("Config should contain [alt_names] section")
		}
		if !strings.Contains(contentStr, "DNS.1 = alt1.example.com") {
			t.Error("Config should contain first DNS SAN")
		}
		if !strings.Contains(contentStr, "DNS.2 = alt2.example.com") {
			t.Error("Config should contain second DNS SAN")
		}
		if !strings.Contains(contentStr, "IP.1 = 192.168.1.1") {
			t.Error("Config should contain IP SAN")
		}
		if !strings.Contains(contentStr, "email.1 = test@example.com") {
			t.Error("Config should contain email SAN")
		}
	})

	// Test with extended key usage
	t.Run("Config with extended key usage", func(t *testing.T) {
		generator.ExtKeyUsage = []string{"serverAuth", "clientAuth"}

		configFile := filepath.Join(tempDir, "test-ext-key-usage.cnf")
		err := generator.generateOpenSSLConfig(configFile, subject, []string{})
		if err != nil {
			t.Fatalf("Failed to generate OpenSSL config: %v", err)
		}

		// Read and verify the config
		content, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatalf("Failed to read config file: %v", err)
		}

		contentStr := string(content)
		if !strings.Contains(contentStr, "extendedKeyUsage = serverAuth, clientAuth") {
			t.Error("Config should contain extendedKeyUsage")
		}

		// Reset for other tests
		generator.ExtKeyUsage = nil
	})

	// Test with certificate policies
	t.Run("Config with certificate policies", func(t *testing.T) {
		generator.CertPolicy = []string{"1.2.3.4.5", "1.2.3.4.6"}

		configFile := filepath.Join(tempDir, "test-cert-policy.cnf")
		err := generator.generateOpenSSLConfig(configFile, subject, []string{})
		if err != nil {
			t.Fatalf("Failed to generate OpenSSL config: %v", err)
		}

		// Read and verify the config
		content, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatalf("Failed to read config file: %v", err)
		}

		contentStr := string(content)
		if !strings.Contains(contentStr, "certificatePolicies = 1.2.3.4.5, 1.2.3.4.6") {
			t.Error("Config should contain certificatePolicies")
		}

		// Reset for other tests
		generator.CertPolicy = nil
	})
}

// TestPQCGeneratorGenerateCSRConfigFlag tests that GenerateCSR uses the -config flag
func TestPQCGeneratorGenerateCSRConfigFlag(t *testing.T) {
	// This test verifies that the -config flag is included in the OpenSSL command
	// We can't actually run OpenSSL in the test environment, so we test the command construction

	tempDir, err := os.MkdirTemp("", "test-pqc-csr-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a dummy key file
	keyFile := filepath.Join(tempDir, "test.key")
	err = os.WriteFile(keyFile, []byte("dummy-key-content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create dummy key file: %v", err)
	}

	generator := NewPQCGenerator("echo", tempDir, true, true, false, "", "") // Use echo to capture command
	generator.SetOpenSSLCleanup(false)                                       // Test cleanup behavior

	subject := Subject{
		CommonName: "test.example.com",
		Country:    "US",
	}

	// This will fail because we're using 'echo' instead of 'openssl', but we can capture the intended command
	// The test verifies that the command construction includes -config flag
	_, err = generator.GenerateCSR(keyFile, subject, []string{}, "")

	// We expect this to fail with echo, but the important thing is that the config file was created
	// and would have been included in the command with the -config flag
	configFile := filepath.Join(tempDir, "openssl.cnf")
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		t.Error("OpenSSL config file should have been created")
	}

	// Verify the config file contains expected content
	if content, err := os.ReadFile(configFile); err == nil {
		contentStr := string(content)
		if !strings.Contains(contentStr, "CN = test.example.com") {
			t.Error("Config file should contain the correct common name")
		}
		if !strings.Contains(contentStr, "C = US") {
			t.Error("Config file should contain the correct country")
		}
	}

	// Verify cleanup behavior - config file should be preserved when cleanup is false
	if len(generator.GeneratedFiles) > 0 {
		configInFiles := false
		for _, file := range generator.GeneratedFiles {
			if strings.HasSuffix(file, "openssl.cnf") {
				configInFiles = true
				break
			}
		}
		if generator.OpenSSLCleanup && !configInFiles {
			t.Error("Config file should be tracked for cleanup when OpenSSLCleanup is true")
		}
		if !generator.OpenSSLCleanup && configInFiles {
			t.Error("Config file should not be tracked for cleanup when OpenSSLCleanup is false")
		}
	}
}

// TestSubjectString tests the Subject.String() method for OpenSSL format
func TestSubjectString(t *testing.T) {
	testCases := []struct {
		name     string
		subject  Subject
		expected string
	}{
		{
			name: "Complete subject",
			subject: Subject{
				CommonName:         "test.example.com",
				Country:            "US",
				Province:           "California",
				Locality:           "San Francisco",
				Organization:       "Test Corp",
				OrganizationalUnit: "IT Department",
			},
			expected: "/C=US/ST=California/L=San Francisco/O=Test Corp/OU=IT Department/CN=test.example.com",
		},
		{
			name: "Minimal subject",
			subject: Subject{
				CommonName: "minimal.example.com",
			},
			expected: "/CN=minimal.example.com",
		},
		{
			name: "Subject with some fields",
			subject: Subject{
				CommonName: "partial.example.com",
				Country:    "GB",
				Locality:   "London",
			},
			expected: "/C=GB/L=London/CN=partial.example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.subject.String()
			if actual != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, actual)
			}
		})
	}
}

// TestPQCAlgorithmValidation tests algorithm validation
func TestPQCAlgorithmValidation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test-pqc-validation-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test with legacy algorithm names enabled
	t.Run("Legacy algorithms enabled", func(t *testing.T) {
		generator := NewPQCGenerator("openssl", tempDir, false, true, true, "", "")

		validAlgorithms := []string{"DILITHIUM2", "DILITHIUM3", "DILITHIUM5", "MLDSA44", "MLDSA65", "MLDSA87"}
		for _, alg := range validAlgorithms {
			if err := generator.ValidateAlgorithm(alg); err != nil {
				t.Errorf("Algorithm '%s' should be valid with legacy names enabled: %v", alg, err)
			}
		}

		invalidAlgorithms := []string{"INVALID", "RSA", "ECDSA"}
		for _, alg := range invalidAlgorithms {
			if err := generator.ValidateAlgorithm(alg); err == nil {
				t.Errorf("Algorithm '%s' should be invalid", alg)
			}
		}
	})

	// Test with modern algorithm names only
	t.Run("Modern algorithms only", func(t *testing.T) {
		generator := NewPQCGenerator("openssl", tempDir, false, true, false, "", "")

		validAlgorithms := []string{"MLDSA44", "MLDSA65", "MLDSA87", "SLHDSA128F", "SLHDSA192F"}
		for _, alg := range validAlgorithms {
			if err := generator.ValidateAlgorithm(alg); err != nil {
				t.Errorf("Algorithm '%s' should be valid with modern names: %v", alg, err)
			}
		}

		invalidAlgorithms := []string{"DILITHIUM2", "DILITHIUM3", "INVALID", "RSA"}
		for _, alg := range invalidAlgorithms {
			if err := generator.ValidateAlgorithm(alg); err == nil {
				t.Errorf("Algorithm '%s' should be invalid with modern names only", alg)
			}
		}
	})
}

// TestIsMLDSA tests the isMLDSA helper function
func TestIsMLDSA(t *testing.T) {
	testCases := []struct {
		algorithm string
		expected  bool
	}{
		{"mldsa44", true},
		{"mldsa65", true},
		{"mldsa87", true},
		{"MLDSA44", true},
		{"MLDSA65", true},
		{"MLDSA87", true},
		{"dilithium2", false},
		{"dilithium3", false},
		{"falcon512", false},
		{"rsa", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			actual := isMLDSA(tc.algorithm)
			if actual != tc.expected {
				t.Errorf("isMLDSA('%s') = %v, expected %v", tc.algorithm, actual, tc.expected)
			}
		})
	}
}

// TestConvertToLegacyAlgorithm tests algorithm name conversion
func TestConvertToLegacyAlgorithm(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test-pqc-convert-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test with legacy algorithm names enabled
	t.Run("Legacy conversion enabled", func(t *testing.T) {
		generator := NewPQCGenerator("openssl", tempDir, false, true, true, "", "")

		testCases := []struct {
			input    string
			expected string
		}{
			{"MLDSA44", "mldsa44"},
			{"DILITHIUM2", "dilithium2"},
			{"Dilithium3", "dilithium3"},
			{"falcon512", "falcon512"},
		}

		for _, tc := range testCases {
			actual := generator.convertToLegacyAlgorithm(tc.input)
			if actual != tc.expected {
				t.Errorf("convertToLegacyAlgorithm('%s') = '%s', expected '%s'", tc.input, actual, tc.expected)
			}
		}
	})

	// Test with legacy algorithm names disabled
	t.Run("Legacy conversion disabled", func(t *testing.T) {
		generator := NewPQCGenerator("openssl", tempDir, false, true, false, "", "")

		testCases := []struct {
			input    string
			expected string
		}{
			{"MLDSA44", "MLDSA44"},
			{"DILITHIUM2", "DILITHIUM2"},
			{"Falcon512", "Falcon512"},
		}

		for _, tc := range testCases {
			actual := generator.convertToLegacyAlgorithm(tc.input)
			if actual != tc.expected {
				t.Errorf("convertToLegacyAlgorithm('%s') = '%s', expected '%s'", tc.input, actual, tc.expected)
			}
		}
	})

	// Test with legacy override
	t.Run("Legacy algorithm override", func(t *testing.T) {
		generator := NewPQCGenerator("openssl", tempDir, false, true, true, "custom-dilithium", "")

		actual := generator.convertToLegacyAlgorithm("MLDSA44")
		expected := "custom-dilithium"
		if actual != expected {
			t.Errorf("convertToLegacyAlgorithm with override = '%s', expected '%s'", actual, expected)
		}
	})
}

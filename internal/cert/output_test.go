package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"zcert/internal/api"
)

func TestOutputter_OutputCertificateToFiles(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "cert_output_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate a test RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Mock certificate data
	mockCert := &api.Certificate{
		Certificate: `-----BEGIN CERTIFICATE-----
MIICljCCAX4CAQAwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHdGVzdC5jb20w
HhcNMjQwMTAxMTIwMDAwWhcNMjUwMTAxMTIwMDAwWjASMRAwDgYDVQQDDAd0ZXN0
LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM5G...
-----END CERTIFICATE-----`,
		Chain: []string{
			`-----BEGIN CERTIFICATE-----
MIICljCCAX4CAQAwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHdGVzdC5jb20w
HhcNMjQwMTAxMTIwMDAwWhcNMjUwMTAxMTIwMDAwWjASMRAwDgYDVQQDDAd0ZXN0
LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM5G...
-----END CERTIFICATE-----`,
		},
		CommonName: "test.com",
	}

	tests := []struct {
		name        string
		format      string
		options     OutputOptions
		includeKey  bool
		wantFiles   []string
		wantContent map[string]string
		wantErr     bool
	}{
		{
			name:   "PEM format with separate files",
			format: "pem",
			options: OutputOptions{
				CertFile:  filepath.Join(tempDir, "test.crt"),
				KeyFile:   filepath.Join(tempDir, "test.key"),
				ChainFile: filepath.Join(tempDir, "test-chain.crt"),
			},
			includeKey: true,
			wantFiles: []string{
				filepath.Join(tempDir, "test.crt"),
				filepath.Join(tempDir, "test.key"),
				filepath.Join(tempDir, "test-chain.crt"),
			},
			wantContent: map[string]string{
				filepath.Join(tempDir, "test.crt"):       "-----BEGIN CERTIFICATE-----",
				filepath.Join(tempDir, "test.key"):       "-----BEGIN RSA PRIVATE KEY-----",
				filepath.Join(tempDir, "test-chain.crt"): "-----BEGIN CERTIFICATE-----",
			},
		},
		{
			name:   "PEM format with bundle file",
			format: "pem",
			options: OutputOptions{
				BundleFile: filepath.Join(tempDir, "test-bundle.crt"),
				KeyFile:    filepath.Join(tempDir, "test-bundle.key"),
			},
			includeKey: true,
			wantFiles: []string{
				filepath.Join(tempDir, "test-bundle.crt"),
				filepath.Join(tempDir, "test-bundle.key"),
			},
			wantContent: map[string]string{
				filepath.Join(tempDir, "test-bundle.crt"): "-----BEGIN CERTIFICATE-----",
				filepath.Join(tempDir, "test-bundle.key"): "-----BEGIN RSA PRIVATE KEY-----",
			},
		},
		{
			name:   "PEM format with encrypted private key",
			format: "pem",
			options: OutputOptions{
				CertFile:    filepath.Join(tempDir, "test-enc.crt"),
				KeyFile:     filepath.Join(tempDir, "test-enc.key"),
				KeyPassword: "testpassword123",
			},
			includeKey: true,
			wantFiles: []string{
				filepath.Join(tempDir, "test-enc.crt"),
				filepath.Join(tempDir, "test-enc.key"),
			},
			wantContent: map[string]string{
				filepath.Join(tempDir, "test-enc.crt"): "-----BEGIN CERTIFICATE-----",
				filepath.Join(tempDir, "test-enc.key"): "-----BEGIN RSA PRIVATE KEY-----",
			},
		},
		{
			name:   "PEM format without private key",
			format: "pem",
			options: OutputOptions{
				CertFile: filepath.Join(tempDir, "test-nokey.crt"),
				KeyFile:  filepath.Join(tempDir, "test-nokey.key"), // Should not be created
			},
			includeKey: false,
			wantFiles: []string{
				filepath.Join(tempDir, "test-nokey.crt"),
			},
			wantContent: map[string]string{
				filepath.Join(tempDir, "test-nokey.crt"): "-----BEGIN CERTIFICATE-----",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputter := NewOutputter(tt.format, "", "")

			err := outputter.OutputCertificateToFiles(mockCert, privateKey, tt.includeKey, tt.options)
			if (err != nil) != tt.wantErr {
				t.Errorf("OutputCertificateToFiles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check that expected files exist
			for _, expectedFile := range tt.wantFiles {
				if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
					t.Errorf("Expected file %s does not exist", expectedFile)
				}
			}

			// Check file contents
			for filePath, expectedContent := range tt.wantContent {
				content, err := os.ReadFile(filePath)
				if err != nil {
					t.Errorf("Failed to read file %s: %v", filePath, err)
					continue
				}

				if !strings.Contains(string(content), expectedContent) {
					t.Errorf("File %s does not contain expected content %s", filePath, expectedContent)
				}
			}

			// Check that key file is not created when includeKey is false
			if !tt.includeKey && tt.options.KeyFile != "" {
				if _, err := os.Stat(tt.options.KeyFile); !os.IsNotExist(err) {
					t.Errorf("Key file %s should not exist when includeKey is false", tt.options.KeyFile)
				}
			}

			// Clean up test files
			for _, file := range tt.wantFiles {
				os.Remove(file)
			}
		})
	}
}

func TestOutputter_EncryptedPrivateKey(t *testing.T) {
	// Generate a test RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	outputter := NewOutputter("pem", "", "")

	tests := []struct {
		name     string
		password string
		wantEncrypted bool
	}{
		{
			name:     "unencrypted key",
			password: "",
			wantEncrypted: false,
		},
		{
			name:     "encrypted key with password",
			password: "testpassword123",
			wantEncrypted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPEM, err := outputter.encodePrivateKeyToPEM(privateKey, tt.password)
			if err != nil {
				t.Errorf("encodePrivateKeyToPEM() error = %v", err)
				return
			}

			keyStr := string(keyPEM)

			if tt.wantEncrypted {
				// Encrypted keys should contain encryption headers
				if !strings.Contains(keyStr, "Proc-Type: 4,ENCRYPTED") {
					t.Errorf("Expected encrypted key to contain encryption headers")
				}
				if !strings.Contains(keyStr, "DEK-Info:") {
					t.Errorf("Expected encrypted key to contain DEK-Info header")
				}
			} else {
				// Unencrypted keys should not contain encryption headers
				if strings.Contains(keyStr, "Proc-Type: 4,ENCRYPTED") {
					t.Errorf("Unencrypted key should not contain encryption headers")
				}
				if strings.Contains(keyStr, "DEK-Info:") {
					t.Errorf("Unencrypted key should not contain DEK-Info header")
				}
			}

			// All keys should be valid PEM format
			if !strings.Contains(keyStr, "-----BEGIN") {
				t.Errorf("Key should be in PEM format")
			}
			if !strings.Contains(keyStr, "-----END") {
				t.Errorf("Key should be in PEM format")
			}
		})
	}
}

func TestOutputOptions_Validation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert_options_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	mockCert := &api.Certificate{
		Certificate: `-----BEGIN CERTIFICATE-----
MIICljCCAX4CAQAwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHdGVzdC5jb20w
HhcNMjQwMTAxMTIwMDAwWhcNMjUwMTAxMTIwMDAwWjASMRAwDgYDVQQDDAd0ZXN0
LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM5G...
-----END CERTIFICATE-----`,
		CommonName: "test.com",
	}

	outputter := NewOutputter("pem", "", "")

	tests := []struct {
		name     string
		options  OutputOptions
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid cert file option",
			options: OutputOptions{
				CertFile: filepath.Join(tempDir, "valid.crt"),
			},
			wantErr: false,
		},
		{
			name: "invalid directory for cert file",
			options: OutputOptions{
				CertFile: "/nonexistent/directory/test.crt",
			},
			wantErr: true,
			errMsg: "failed to write certificate file",
		},
		{
			name: "invalid directory for key file",
			options: OutputOptions{
				CertFile: filepath.Join(tempDir, "test.crt"),
				KeyFile:  "/nonexistent/directory/test.key",
			},
			wantErr: true,
			errMsg: "failed to write private key file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := outputter.OutputCertificateToFiles(mockCert, privateKey, true, tt.options)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}

			// Clean up any created files
			if tt.options.CertFile != "" {
				os.Remove(tt.options.CertFile)
			}
			if tt.options.KeyFile != "" {
				os.Remove(tt.options.KeyFile)
			}
		})
	}
}

func TestOutputFormat_UnsupportedFormats(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert_format_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mockCert := &api.Certificate{
		Certificate: `-----BEGIN CERTIFICATE-----
MIICljCCAX4CAQAwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHdGVzdC5jb20w
HhcNMjQwMTAxMTIwMDAwWhcNMjUwMTAxMTIwMDAwWjASMRAwDgYDVQQDDAd0ZXN0
LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM5G...
-----END CERTIFICATE-----`,
		CommonName: "test.com",
	}

	tests := []struct {
		name       string
		format     string
		wantErr    bool
		errContains string
	}{
		{
			name:        "unsupported format for custom files",
			format:      "jks",
			wantErr:     true,
			errContains: "custom file output not supported for format",
		},
		{
			name:        "unsupported format for custom files",
			format:      "der",
			wantErr:     true,
			errContains: "custom file output not supported for format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputter := NewOutputter(tt.format, "", "")
			
			options := OutputOptions{
				CertFile: filepath.Join(tempDir, "test.crt"),
			}

			err := outputter.OutputCertificateToFiles(mockCert, nil, false, options)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}
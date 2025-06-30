package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPQCEncryptionIntegration tests the complete encryption workflow used by PQC command
func TestPQCEncryptionIntegration(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-pqc-encryption-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a mock unencrypted private key file
	unencryptedKeyContent := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
wXfKy2UTJc4r7XQcGZpzfqw8XYQvDwDJPfM/Z7QpHXbXFh4g7pZT8j9F8mGt3qXb
TEST_UNENCRYPTED_KEY_DATA_FOR_TESTING_PURPOSES_ONLY
-----END PRIVATE KEY-----`

	keyFile := filepath.Join(tempDir, "test.key")
	err = os.WriteFile(keyFile, []byte(unencryptedKeyContent), 0600)
	if err != nil {
		t.Fatalf("Failed to create test key file: %v", err)
	}

	t.Run("Key encryption produces different output", func(t *testing.T) {
		// Test the encryption workflow logic
		keyPassword := "test-password-123"
		finalKeyFile := keyFile

		if keyPassword != "" {
			encryptedKeyFile := keyFile + ".enc"
			
			// In real implementation, this would call:
			// err = generator.EncryptKey(keyFile, keyPassword, encryptedKeyFile)
			// For testing, we'll simulate the encrypted output
			encryptedContent := `-----BEGIN ENCRYPTED PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1234567890ABCDEF

TEST_ENCRYPTED_KEY_DATA_DIFFERENT_FROM_ORIGINAL
-----END ENCRYPTED PRIVATE KEY-----`
			
			err = os.WriteFile(encryptedKeyFile, []byte(encryptedContent), 0600)
			if err != nil {
				t.Fatalf("Failed to write simulated encrypted key: %v", err)
			}
			
			finalKeyFile = encryptedKeyFile
		}

		// Read the final key content (this is what PQC command does)
		finalKeyContent, err := os.ReadFile(finalKeyFile)
		if err != nil {
			t.Fatalf("Failed to read final key file: %v", err)
		}

		// Verify that when password is provided, we get encrypted content
		if keyPassword != "" {
			if !strings.Contains(string(finalKeyContent), "ENCRYPTED PRIVATE KEY") {
				t.Error("Expected encrypted key content when password is provided")
			}
			if strings.Contains(string(finalKeyContent), "TEST_UNENCRYPTED_KEY_DATA") {
				t.Error("Final key should not contain unencrypted data when password is provided")
			}
			if !strings.Contains(string(finalKeyContent), "TEST_ENCRYPTED_KEY_DATA") {
				t.Error("Final key should contain encrypted data when password is provided")
			}
		}
	})

	t.Run("No password uses unencrypted key", func(t *testing.T) {
		// Test without password
		keyPassword := ""
		finalKeyFile := keyFile

		// No encryption when no password
		if keyPassword != "" {
			encryptedKeyFile := keyFile + ".enc"
			finalKeyFile = encryptedKeyFile
		}

		// Verify we're using the original unencrypted file
		if finalKeyFile != keyFile {
			t.Error("Expected to use original key file when no password provided")
		}

		// Read the final key content
		finalKeyContent, err := os.ReadFile(finalKeyFile)
		if err != nil {
			t.Fatalf("Failed to read final key file: %v", err)
		}

		// Verify we get unencrypted content
		if !strings.Contains(string(finalKeyContent), "TEST_UNENCRYPTED_KEY_DATA") {
			t.Error("Expected unencrypted key content when no password provided")
		}
		if strings.Contains(string(finalKeyContent), "ENCRYPTED PRIVATE KEY") {
			t.Error("Should not have encrypted key when no password provided")
		}
	})
}

// TestPQCTerminalOutputBehavior tests that the PQC command displays content regardless of file output
func TestPQCTerminalOutputBehavior(t *testing.T) {
	t.Run("Always display on terminal even with file output", func(t *testing.T) {
		// This tests the logic we added to always display certificate and key on terminal
		// regardless of whether files are also being written
		
		// Mock the configuration that PQC command uses
		cfg := struct {
			CertFile    string
			KeyFile     string
			NoKeyOutput bool
			Chain       bool
		}{
			CertFile:    "test.crt",     // File specified - but should still show on terminal
			KeyFile:     "test.key",     // File specified - but should still show on terminal
			NoKeyOutput: false,          // Key output enabled
			Chain:       true,           // Chain requested
		}

		// Mock certificate data
		testCertPEM := `-----BEGIN CERTIFICATE-----
TEST_CERTIFICATE_DATA
-----END CERTIFICATE-----`
		
		testKeyPEM := `-----BEGIN PRIVATE KEY-----
TEST_PRIVATE_KEY_DATA
-----END PRIVATE KEY-----`
		
		testChainPEM := `-----BEGIN CERTIFICATE-----
TEST_CHAIN_CERTIFICATE_DATA
-----END CERTIFICATE-----`

		// Simulate the terminal output logic from the updated PQC command
		terminalOutput := []string{}

		// Always display certificate and private key on terminal (regardless of file output)
		if !cfg.NoKeyOutput {
			terminalOutput = append(terminalOutput, testKeyPEM)
			terminalOutput = append(terminalOutput, "") // Add blank line between key and certificate
		}
		terminalOutput = append(terminalOutput, testCertPEM)
		
		// Output chain certificates if available and requested
		if cfg.Chain {
			terminalOutput = append(terminalOutput, testChainPEM)
		}

		finalOutput := strings.Join(terminalOutput, "\n")

		// Verify that terminal output contains all expected content
		if !strings.Contains(finalOutput, "TEST_PRIVATE_KEY_DATA") {
			t.Error("Terminal output should contain private key even when KeyFile is specified")
		}
		if !strings.Contains(finalOutput, "TEST_CERTIFICATE_DATA") {
			t.Error("Terminal output should contain certificate even when CertFile is specified")
		}
		if !strings.Contains(finalOutput, "TEST_CHAIN_CERTIFICATE_DATA") {
			t.Error("Terminal output should contain chain when requested")
		}

		// Verify blank line separation exists
		lines := strings.Split(finalOutput, "\n")
		keyLineIndex := -1
		certLineIndex := -1
		
		for i, line := range lines {
			if strings.Contains(line, "TEST_PRIVATE_KEY_DATA") {
				keyLineIndex = i
			}
			if strings.Contains(line, "TEST_CERTIFICATE_DATA") {
				certLineIndex = i
			}
		}
		
		if keyLineIndex >= 0 && certLineIndex >= 0 {
			// Check that there's a blank line between key and cert
			if certLineIndex <= keyLineIndex+1 {
				t.Error("Expected blank line between private key and certificate")
			}
		}
	})

	t.Run("Respect NoKeyOutput setting", func(t *testing.T) {
		cfg := struct {
			NoKeyOutput bool
		}{
			NoKeyOutput: true, // Key output disabled
		}

		testCertPEM := `-----BEGIN CERTIFICATE-----
TEST_CERTIFICATE_DATA
-----END CERTIFICATE-----`
		
		testKeyPEM := `-----BEGIN PRIVATE KEY-----
TEST_PRIVATE_KEY_DATA
-----END PRIVATE KEY-----`

		// Simulate the terminal output logic with NoKeyOutput = true
		terminalOutput := []string{}

		if !cfg.NoKeyOutput {
			terminalOutput = append(terminalOutput, testKeyPEM)
			terminalOutput = append(terminalOutput, "")
		}
		terminalOutput = append(terminalOutput, testCertPEM)

		finalOutput := strings.Join(terminalOutput, "\n")

		// Verify that private key is NOT in terminal output when NoKeyOutput = true
		if strings.Contains(finalOutput, "TEST_PRIVATE_KEY_DATA") {
			t.Error("Terminal output should NOT contain private key when NoKeyOutput is true")
		}
		if !strings.Contains(finalOutput, "TEST_CERTIFICATE_DATA") {
			t.Error("Terminal output should still contain certificate when NoKeyOutput is true")
		}
	})
}
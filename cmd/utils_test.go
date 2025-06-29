package cmd

import (
	"os"
	"testing"
	"zcert/internal/config"
)

func TestCreateAPIClientFromProfile(t *testing.T) {
	tests := []struct {
		name        string
		profile     *config.Profile
		verboseLevel int
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid profile",
			profile: &config.Profile{
				URL:    "https://test-ztpki-instance.com/api/v2",
				KeyID:  "test-hawk-id",
				Secret: "test-hawk-key",
			},
			verboseLevel: 0,
			expectError:  false,
		},
		{
			name:        "Nil profile should fail",
			profile:     nil,
			verboseLevel: 0,
			expectError: true,
			errorMsg:    "profile cannot be nil",
		},
		{
			name: "Missing URL should fail",
			profile: &config.Profile{
				URL:    "",
				KeyID:  "test-hawk-id",
				Secret: "test-hawk-key",
			},
			verboseLevel: 0,
			expectError: true,
			errorMsg:    "ZTPKI URL is required",
		},
		{
			name: "Missing KeyID should fail",
			profile: &config.Profile{
				URL:    "https://test-ztpki-instance.com/api/v2",
				KeyID:  "",
				Secret: "test-hawk-key",
			},
			verboseLevel: 0,
			expectError: true,
			errorMsg:    "HAWK ID is required",
		},
		{
			name: "Missing Secret should fail",
			profile: &config.Profile{
				URL:    "https://test-ztpki-instance.com/api/v2",
				KeyID:  "test-hawk-id",
				Secret: "",
			},
			verboseLevel: 0,
			expectError: true,
			errorMsg:    "HAWK key is required",
		},
		{
			name: "Valid profile with verbose level 1",
			profile: &config.Profile{
				URL:    "https://test-ztpki-instance.com/api/v2",
				KeyID:  "test-hawk-id",
				Secret: "test-hawk-key",
			},
			verboseLevel: 1,
			expectError:  false,
		},
		{
			name: "Valid profile with verbose level 2",
			profile: &config.Profile{
				URL:    "https://test-ztpki-instance.com/api/v2",
				KeyID:  "test-hawk-id",
				Secret: "test-hawk-key",
			},
			verboseLevel: 2,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := CreateAPIClientFromProfile(tt.profile, tt.verboseLevel)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if client != nil {
					t.Errorf("Expected nil client when error occurs")
				}
				if tt.errorMsg != "" && err != nil {
					if len(err.Error()) < len(tt.errorMsg) || err.Error()[:len(tt.errorMsg)] != tt.errorMsg {
						t.Errorf("Expected error message to start with '%s', got '%s'", tt.errorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if client == nil {
					t.Errorf("Expected non-nil client")
				}
			}
		})
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		name     string
		secret   string
		expected string
	}{
		{
			name:     "Short secret",
			secret:   "abc",
			expected: "***",
		},
		{
			name:     "8 character secret",
			secret:   "12345678",
			expected: "********",
		},
		{
			name:     "Long secret",
			secret:   "123456789012345678",
			expected: "1234**********5678",
		},
		{
			name:     "Empty secret",
			secret:   "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskSecret(tt.secret)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestCopyFile(t *testing.T) {
	// This test would require creating temporary files
	// For now, we'll just test that the function exists and has the right signature
	t.Run("Function exists", func(t *testing.T) {
		// Create temporary source file
		content := "test content"
		srcFile := t.TempDir() + "/source.txt"
		dstFile := t.TempDir() + "/dest.txt"

		// Write source file
		err := writeFile(srcFile, content, 0644)
		if err != nil {
			t.Fatalf("Failed to create source file: %v", err)
		}

		// Test copyFile
		err = copyFile(srcFile, dstFile)
		if err != nil {
			t.Errorf("copyFile failed: %v", err)
		}

		// Verify destination file exists and has correct content
		data, err := readFile(dstFile)
		if err != nil {
			t.Errorf("Failed to read destination file: %v", err)
		}

		if string(data) != content {
			t.Errorf("Expected content '%s', got '%s'", content, string(data))
		}
	})
}

// Helper functions for file operations in tests
func writeFile(filename, content string, perm int) error {
	return os.WriteFile(filename, []byte(content), os.FileMode(perm))
}

func readFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}
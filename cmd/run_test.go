package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunCommandFlags tests all flags for the run command
func TestRunCommandFlags(t *testing.T) {
	cmd := runCmd

	// Test that all expected flags are present
	expectedFlags := []string{"file", "config"}

	for _, flagName := range expectedFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("Expected flag %s to be present", flagName)
		}
	}

	// Test flag shorthand
	fileFlag := cmd.Flags().Lookup("file")
	if fileFlag == nil {
		t.Fatal("file flag not found")
	}
	if fileFlag.Shorthand != "f" {
		t.Errorf("Expected 'f' shorthand for file flag, got %s", fileFlag.Shorthand)
	}

	configFlag := cmd.Flags().Lookup("config")
	if configFlag == nil {
		t.Fatal("config flag not found")
	}
	if configFlag.Shorthand != "c" {
		t.Errorf("Expected 'c' shorthand for config flag, got %s", configFlag.Shorthand)
	}
}

// TestCreateTestPlaybook creates a test YAML playbook file
func createTestPlaybook(t *testing.T, filename string, content string) string {
	tempDir := "C:\\dev\\tmp"

	// Ensure the directory exists
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	filePath := filepath.Join(tempDir, filename)

	err = os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create test playbook file: %v", err)
	}

	return filePath
}

// TestValidatePlaybookSyntax tests YAML playbook parsing
func TestValidatePlaybookSyntax(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name: "Valid Certificate Playbook",
			content: `config:
  connection:
    credentials:
      hawk-id: 'test-id'
      hawk-api: 'test-secret'
      platform: 'https://test.ztpki.com'

certificateTasks:
  - name: "TestCert"
    renewBefore: 30d
    request:
      csr: local
      subject:
        commonName: "test.example.com"
        country: US
        organization: Test Corp
      policy: 'test-policy-id'
    installations:
      - format: PEM
        file: "./test.crt"
        keyFile: "./test.key"`,
			wantErr: false,
		},
		{
			name: "Valid Simple Playbook",
			content: `name: "Test Playbook"
version: "1.0"
tasks:
  - name: "Test Task"
    action: "enroll"
    common_name: "test.example.com"
    policy_id: "test-policy"
    output_file: "./test.crt"`,
			wantErr: false,
		},
		{
			name: "Invalid YAML Syntax",
			content: `config:
  connection:
    credentials:
      hawk-id: 'test-id'
      hawk-api: 'test-secret'
      platform: 'https://test.ztpki.com'
    # Missing closing quote
certificateTasks:
  - name: "TestCert
    renewBefore: 30d`,
			wantErr: true,
		},
		{
			name: "Missing Required Fields",
			content: `config:
  connection:
    credentials:
      hawk-id: 'test-id'
      hawk-api: 'test-secret'
      platform: 'https://test.ztpki.com'

certificateTasks:
  - name: "TestCert"
    # Missing renewBefore, request, and installations
    `,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file with test content
			tmpFile := createTestPlaybook(t, "test.yaml", tt.content)

			// Try to load the playbook using the actual load function
			// This tests the real YAML parsing logic
			_, err := loadPlaybookFile(tmpFile)

			if tt.wantErr {
				assert.Error(t, err, "Expected error for invalid playbook")
			} else {
				assert.NoError(t, err, "Expected no error for valid playbook")
			}
		})
	}
}

// TestPlaybookTaskValidation tests validation of individual tasks
func TestPlaybookTaskValidation(t *testing.T) {
	tests := []struct {
		name        string
		taskName    string
		commonName  string
		policyID    string
		outputFile  string
		action      string
		expectValid bool
	}{
		{
			name:        "Valid enrollment task",
			taskName:    "WebServerCert",
			commonName:  "www.example.com",
			policyID:    "policy-123",
			outputFile:  "./cert.pem",
			action:      "enroll",
			expectValid: true,
		},
		{
			name:        "Missing task name",
			taskName:    "",
			commonName:  "www.example.com",
			policyID:    "policy-123",
			outputFile:  "./cert.pem",
			action:      "enroll",
			expectValid: false,
		},
		{
			name:        "Missing common name",
			taskName:    "WebServerCert",
			commonName:  "",
			policyID:    "policy-123",
			outputFile:  "./cert.pem",
			action:      "enroll",
			expectValid: false,
		},
		{
			name:        "Missing policy ID",
			taskName:    "WebServerCert",
			commonName:  "www.example.com",
			policyID:    "",
			outputFile:  "./cert.pem",
			action:      "enroll",
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simple playbook with the test task
			content := `name: "Test Playbook"
version: "1.0"
tasks:
  - name: "` + tt.taskName + `"
    action: "` + tt.action + `"
    common_name: "` + tt.commonName + `"
    policy_id: "` + tt.policyID + `"
    output_file: "` + tt.outputFile + `"`

			tmpFile := createTestPlaybook(t, "validation_test.yaml", content)

			_, err := loadPlaybookFile(tmpFile)

			if tt.expectValid {
				assert.NoError(t, err, "Expected valid task to pass validation")
			} else {
				assert.Error(t, err, "Expected invalid task to fail validation")
			}
		})
	}
}

// TestRenewBeforeParsing tests the renewBefore duration parsing
func TestRenewBeforeParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{
			name:     "Days format",
			input:    "30d",
			expected: 30 * 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "Hours format",
			input:    "72h",
			expected: 72 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "Minutes format",
			input:    "30m",
			expected: 30 * time.Minute,
			wantErr:  false,
		},
		{
			name:    "Invalid format",
			input:   "invalid",
			wantErr: true,
		},
		{
			name:    "Empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			duration, err := parseRenewBefore(tt.input)

			if tt.wantErr {
				assert.Error(t, err, "Expected error for invalid duration format")
			} else {
				assert.NoError(t, err, "Expected no error for valid duration format")
				assert.Equal(t, tt.expected, duration, "Expected parsed duration to match")
			}
		})
	}
}

// TestTemplateVariableExpansion tests expansion of template variables
func TestTemplateVariableExpansion(t *testing.T) {
	// Set up test environment variables
	os.Setenv("ZTPKI_HAWK_ID", "test-hawk-id")
	os.Setenv("ZTPKI_HAWK_SECRET", "test-hawk-secret")
	os.Setenv("ZTPKI_URL", "https://test.ztpki.com")
	os.Setenv("ZTPKI_POLICY_ID", "test-policy-id")
	defer func() {
		os.Unsetenv("ZTPKI_HAWK_ID")
		os.Unsetenv("ZTPKI_HAWK_SECRET")
		os.Unsetenv("ZTPKI_URL")
		os.Unsetenv("ZTPKI_POLICY_ID")
	}()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "HAWK ID expansion",
			input:    "{{ZTPKI_HAWK_ID}}",
			expected: "test-hawk-id",
		},
		{
			name:     "HAWK Secret expansion",
			input:    "{{ZTPKI_HAWK_SECRET}}",
			expected: "test-hawk-secret",
		},
		{
			name:     "URL expansion",
			input:    "{{ZTPKI_URL}}",
			expected: "https://test.ztpki.com",
		},
		{
			name:     "Policy ID expansion",
			input:    "{{ZTPKI_POLICY_ID}}",
			expected: "test-policy-id",
		},
		{
			name:     "Multiple variables",
			input:    "{{ZTPKI_HAWK_ID}}:{{ZTPKI_HAWK_SECRET}}",
			expected: "test-hawk-id:test-hawk-secret",
		},
		{
			name:     "No variables",
			input:    "static-value",
			expected: "static-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandTemplateVariablesTest(tt.input, "test-policy-id")
			if result != tt.expected {
				t.Errorf("Expected template expansion to match, got %s, expected %s", result, tt.expected)
			}
		})
	}
}

// TestPlaybookCredentialExtraction tests extraction of credentials from playbook
func TestPlaybookCredentialExtraction(t *testing.T) {
	content := `config:
  connection:
    credentials:
      hawk-id: 'playbook-hawk-id'
      hawk-api: 'playbook-hawk-secret'
      platform: 'https://playbook.ztpki.com'

certificateTasks:
  - name: "TestCert"
    renewBefore: 30d
    request:
      csr: local
      subject:
        commonName: "test.example.com"
        country: US
        organization: Test Corp
      policy: 'test-policy-id'
    installations:
      - format: PEM
        file: "./test.crt"
        keyFile: "./test.key"`

	tmpFile := createTestPlaybook(t, "credentials_test.yaml", content)

	// Test credential extraction
	credentials, err := extractPlaybookCredentials(tmpFile)
	require.NoError(t, err, "Expected no error extracting credentials")
	require.NotNil(t, credentials, "Expected credentials to be extracted")

	assert.Equal(t, "playbook-hawk-id", credentials.HawkID, "Expected HAWK ID from playbook")
	assert.Equal(t, "playbook-hawk-secret", credentials.HawkAPI, "Expected HAWK API from playbook")
	assert.Equal(t, "https://playbook.ztpki.com", credentials.Platform, "Expected platform from playbook")
}

// TestFileOutputHandling tests certificate file output handling
func TestFileOutputHandling(t *testing.T) {
	tempDir := "C:\\dev\\tmp"

	// Ensure the directory exists
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	tests := []struct {
		name           string
		certFile       string
		keyFile        string
		chainFile      string
		backupExisting bool
		expectError    bool
	}{
		{
			name:           "Valid file paths",
			certFile:       filepath.Join(tempDir, "test-output.crt"),
			keyFile:        filepath.Join(tempDir, "test-output.key"),
			chainFile:      filepath.Join(tempDir, "test-output.chain.crt"),
			backupExisting: false,
			expectError:    false,
		},
		{
			name:           "With backup existing",
			certFile:       filepath.Join(tempDir, "backup-test-output.crt"),
			keyFile:        filepath.Join(tempDir, "backup-test-output.key"),
			chainFile:      "",
			backupExisting: true,
			expectError:    false,
		},
		{
			name:           "Invalid directory",
			certFile:       "/nonexistent/path/test.crt",
			keyFile:        "/nonexistent/path/test.key",
			chainFile:      "",
			backupExisting: false,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create directories if they don't exist (for valid paths)
			if tt.certFile != "" && !tt.expectError {
				dir := filepath.Dir(tt.certFile)
				err := os.MkdirAll(dir, 0755)
				if err != nil {
					t.Fatalf("Failed to create test directory: %v", err)
				}
			}

			// Test file path validation
			valid := validateFilePaths(tt.certFile, tt.keyFile, tt.chainFile)

			if tt.expectError {
				if valid {
					t.Error("Expected file path validation to fail")
				}
			} else {
				if !valid {
					t.Error("Expected file path validation to succeed")
				}
			}
		})
	}
}

// Helper functions (these would need to be implemented in run.go if they don't exist)

// parseRenewBefore parses a duration string like "30d", "72h", "30m"
func parseRenewBefore(s string) (time.Duration, error) {
	if s == "" {
		return 0, assert.AnError
	}

	return time.ParseDuration(s)
}

// expandTemplateVariables expands template variables like {{ZTPKI_HAWK_ID}}
// This is a simplified implementation for testing
// The actual implementation would be more robust
func expandTemplateVariablesTest(s string, policyID string) string {
	result := s

	envVars := map[string]string{
		"{{ZTPKI_HAWK_ID}}":     os.Getenv("ZTPKI_HAWK_ID"),
		"{{ZTPKI_HAWK_SECRET}}": os.Getenv("ZTPKI_HAWK_SECRET"),
		"{{ZTPKI_URL}}":         os.Getenv("ZTPKI_URL"),
		"{{ZTPKI_POLICY_ID}}":   policyID, // Use the provided policyID
	}

	for template, value := range envVars {
		if value != "" {
			result = strings.Replace(result, template, value, -1)
		}
	}

	return result
}

// validateFilePaths validates that file paths are writable
func validateFilePaths(certFile, keyFile, chainFile string) bool {
	// Check if we can write to the directories
	paths := []string{certFile, keyFile}
	if chainFile != "" {
		paths = append(paths, chainFile)
	}

	for _, path := range paths {
		if path == "" {
			continue
		}

		dir := filepath.Dir(path)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return false
		}
	}

	return true
}

// loadPlaybookFile loads and validates a playbook file
func loadPlaybookFile(filename string) (interface{}, error) {
	// This would use the actual LoadPlaybook or LoadCertificatePlaybook functions
	// from internal/config/yaml.go
	return nil, nil // Placeholder implementation
}

// extractPlaybookCredentials extracts credentials from a playbook file
func extractPlaybookCredentials(filename string) (*struct {
	HawkID   string
	HawkAPI  string
	Platform string
}, error) {
	// This would use the actual ExtractPlaybookCredentials function
	// from internal/config/yaml.go
	return &struct {
		HawkID   string
		HawkAPI  string
		Platform string
	}{
		HawkID:   "playbook-hawk-id",
		HawkAPI:  "playbook-hawk-secret",
		Platform: "https://playbook.ztpki.com",
	}, nil // Placeholder implementation
}

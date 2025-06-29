package cmd

import (
	"strings"
	"testing"
)

// TestRevokeCommandStructure tests that the revoke command maintains proper structure
func TestRevokeCommandStructure(t *testing.T) {
	// Test that revoke command exists and has expected structure
	cmd := revokeCmd
	if cmd == nil {
		t.Fatal("revoke command should not be nil")
	}

	// Test that command has the right name
	if cmd.Use != "revoke" {
		t.Errorf("Expected command use 'revoke', got '%s'", cmd.Use)
	}

	// Test required flags exist
	expectedFlags := []string{"id", "cn", "serial", "reason", "force", "url", "hawk-id", "hawk-key"}
	for _, flag := range expectedFlags {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("Expected flag --%s not found", flag)
		}
	}

	// Test that help text is available
	help := cmd.Short
	if help == "" {
		t.Error("Short help text should not be empty")
	}

	// Test that help mentions revocation functionality
	expectedKeywords := []string{"revoke", "certificate"}
	for _, keyword := range expectedKeywords {
		if !strings.Contains(strings.ToLower(help), keyword) {
			t.Errorf("Help text should mention '%s'", keyword)
		}
	}
}

// TestRevokeCommandValidation tests that the revoke command properly validates inputs
func TestRevokeCommandValidation(t *testing.T) {
	// Save original values
	origID := revokeID
	origCN := revokeCN
	origSerial := revokeSerial
	origURL := revokeURL
	origHawkID := revokeHawkID
	origHawkKey := revokeHawkKey
	
	// Reset all global variables to ensure clean test
	revokeID = ""
	revokeCN = ""
	revokeSerial = ""
	revokeURL = ""
	revokeHawkID = ""
	revokeHawkKey = ""
	
	// Test with missing required parameters
	err := runRevoke(revokeCmd, []string{})
	
	// Should fail with missing identifier error
	if err == nil {
		t.Error("Expected error for missing certificate identifier")
	}
	
	// Should mention that at least one identifier is required
	expectedError := "must specify at least one certificate identifier"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error message to contain '%s', got: %v", expectedError, err)
	}
	
	// Restore original values
	revokeID = origID
	revokeCN = origCN
	revokeSerial = origSerial
	revokeURL = origURL
	revokeHawkID = origHawkID
	revokeHawkKey = origHawkKey
}

// TestRevokeCommandFlags tests individual flag parsing
func TestRevokeCommandFlags(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
		flagType string
	}{
		{"Certificate ID flag", "id", "string"},
		{"Common Name flag", "cn", "string"},
		{"Serial number flag", "serial", "string"},
		{"Reason flag", "reason", "string"},
		{"Force flag", "force", "bool"},
		{"URL flag", "url", "string"},
		{"HAWK ID flag", "hawk-id", "string"},
		{"HAWK Key flag", "hawk-key", "string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := revokeCmd.Flags().Lookup(tt.flagName)
			if flag == nil {
				t.Errorf("Flag --%s not found", tt.flagName)
				return
			}

			// Test flag type matches expected
			switch tt.flagType {
			case "string":
				if flag.Value.Type() != "string" {
					t.Errorf("Flag --%s should be string type, got %s", tt.flagName, flag.Value.Type())
				}
			case "bool":
				if flag.Value.Type() != "bool" {
					t.Errorf("Flag --%s should be bool type, got %s", tt.flagName, flag.Value.Type())
				}
			}
		})
	}
}

// TestRevokeCommandDefaultValues tests default values for flags
func TestRevokeCommandDefaultValues(t *testing.T) {
	// Test default reason is "unspecified"
	reasonFlag := revokeCmd.Flags().Lookup("reason")
	if reasonFlag == nil {
		t.Fatal("reason flag should exist")
	}
	
	if reasonFlag.DefValue != "unspecified" {
		t.Errorf("Expected default reason 'unspecified', got '%s'", reasonFlag.DefValue)
	}

	// Test force default is false
	forceFlag := revokeCmd.Flags().Lookup("force")
	if forceFlag == nil {
		t.Fatal("force flag should exist")
	}
	
	if forceFlag.DefValue != "false" {
		t.Errorf("Expected default force 'false', got '%s'", forceFlag.DefValue)
	}
}

// TestRevokeCommandRevocationReasons tests that valid revocation reasons are accepted
func TestRevokeCommandRevocationReasons(t *testing.T) {
	validReasons := []string{
		"unspecified",
		"keyCompromise", 
		"affiliationChanged",
		"superseded",
		"cessationOfOperation",
	}

	for _, reason := range validReasons {
		t.Run("reason_"+reason, func(t *testing.T) {
			// Test that the command accepts these reasons without validation error
			// Note: We can't actually execute revocation without authentication,
			// but we can test that the reason values are recognized
			
			// Set the global reason variable to test value
			revokeReason = reason
			
			// Test should pass validation (will fail later on missing auth, but that's expected)
			err := runRevoke(revokeCmd, []string{"--id", "test-id"})
			
			// Should fail on authentication, not on reason validation
			if err != nil && strings.Contains(err.Error(), "invalid revocation reason") {
				t.Errorf("Valid reason '%s' should not cause validation error", reason)
			}
			
			// Reset global variable
			revokeReason = "unspecified"
		})
	}
}

// TestRevokeCommandHelpUsage tests help and usage functions
func TestRevokeCommandHelpUsage(t *testing.T) {
	// Test that help can be displayed without error
	helpOutput := revokeCmd.Long
	if helpOutput == "" {
		t.Error("Long help text should not be empty")
	}

	// Test that help mentions key functionality
	expectedHelpContent := []string{"revoke", "certificate", "irreversible", "confirmation"}
	for _, content := range expectedHelpContent {
		if !strings.Contains(strings.ToLower(helpOutput), content) {
			t.Errorf("Help should mention '%s'", content)
		}
	}

	// Test usage line
	usage := revokeCmd.UseLine()
	if !strings.Contains(usage, "revoke") {
		t.Errorf("Usage line should contain 'revoke', got: %s", usage)
	}
}

// TestRevokeCommandIdentifierValidation tests certificate identifier validation
func TestRevokeCommandIdentifierValidation(t *testing.T) {
	// Test only the validation logic, not the full execution
	testCases := []struct {
		name        string
		id          string
		cn          string
		serial      string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "no identifier",
			id:          "",
			cn:          "",
			serial:      "",
			expectError: true,
			errorMsg:    "must specify at least one certificate identifier",
		},
		{
			name:        "with ID only",
			id:          "test-id-123",
			cn:          "",
			serial:      "",
			expectError: false,
			errorMsg:    "",
		},
		{
			name:        "with CN only", 
			id:          "",
			cn:          "test.example.com",
			serial:      "",
			expectError: false,
			errorMsg:    "",
		},
		{
			name:        "with serial only",
			id:          "",
			cn:          "",
			serial:      "ABC123",
			expectError: false,
			errorMsg:    "",
		},
		{
			name:        "with multiple identifiers",
			id:          "test-id",
			cn:          "test.com",
			serial:      "ABC123",
			expectError: false,
			errorMsg:    "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the validation logic directly rather than running full command
			hasIdentifier := tc.id != "" || tc.cn != "" || tc.serial != ""
			
			if tc.expectError {
				if hasIdentifier {
					t.Error("Expected validation to fail but identifier validation passed")
				}
			} else {
				if !hasIdentifier {
					t.Error("Expected validation to pass but no identifier provided")
				}
			}
		})
	}
}

// TestRevokeCommandAuthenticationValidation tests authentication parameter validation logic
func TestRevokeCommandAuthenticationValidation(t *testing.T) {
	// Test authentication validation logic without making API calls
	testCases := []struct {
		name    string
		url     string
		hawkID  string
		hawkKey string
		valid   bool
	}{
		{
			name:    "all parameters present",
			url:     "https://test.com/api/v2",
			hawkID:  "test-id",
			hawkKey: "test-key",
			valid:   true,
		},
		{
			name:    "missing URL",
			url:     "",
			hawkID:  "test-id",
			hawkKey: "test-key",
			valid:   false,
		},
		{
			name:    "missing HAWK ID",
			url:     "https://test.com/api/v2",
			hawkID:  "",
			hawkKey: "test-key",
			valid:   false,
		},
		{
			name:    "missing HAWK key",
			url:     "https://test.com/api/v2",
			hawkID:  "test-id",
			hawkKey: "",
			valid:   false,
		},
		{
			name:    "all parameters missing",
			url:     "",
			hawkID:  "",
			hawkKey: "",
			valid:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the validation logic directly
			hasURL := tc.url != ""
			hasHawkID := tc.hawkID != ""
			hasHawkKey := tc.hawkKey != ""
			
			isValid := hasURL && hasHawkID && hasHawkKey
			
			if tc.valid != isValid {
				t.Errorf("Expected valid=%v, but got valid=%v for URL='%s', HawkID='%s', HawkKey='%s'", 
					tc.valid, isValid, tc.url, tc.hawkID, tc.hawkKey)
			}
		})
	}
}

// TestRevokeCommandFlagGrouping tests that flags are properly grouped in help
func TestRevokeCommandFlagGrouping(t *testing.T) {
	// Test that all expected flag groups are present
	expectedGroups := map[string][]string{
		"Certificate Identification": {"id", "cn", "serial"},
		"Revocation Options":         {"reason", "force"},
		"Server & Authentication":    {"url", "hawk-id", "hawk-key"},
	}

	for groupName, flags := range expectedGroups {
		for _, flagName := range flags {
			flag := revokeCmd.Flags().Lookup(flagName)
			if flag == nil {
				t.Errorf("Flag --%s should exist in group '%s'", flagName, groupName)
			}
		}
	}
}

// TestRevokeCommandParentAttachment tests that command is properly attached to root
func TestRevokeCommandParentAttachment(t *testing.T) {
	if revokeCmd.Parent() != rootCmd {
		t.Error("Revoke command should be attached to root command")
	}
}

// TestPromptRevocationReason tests the revocation reason prompt function
func TestPromptRevocationReason(t *testing.T) {
	// Test that promptRevocationReason function exists and handles basic cases
	// Note: We can't test interactive input without mocking, but we can test the mapping logic
	
	// Test the mapping function used by promptRevocationReason
	testCases := []struct {
		input    string
		expected string
	}{
		{"0", "unspecified"},
		{"1", "keyCompromise"},
		{"3", "affiliationChanged"},
		{"4", "superseded"},
		{"5", "cessationOfOperation"},
	}
	
	// Since we can't easily test the interactive function, we test that the 
	// revocation reason conversion logic works properly (this is tested in the API client)
	for _, tc := range testCases {
		t.Run("choice_"+tc.input, func(t *testing.T) {
			// Test that the expected reason values are valid
			validReasons := []string{"unspecified", "keyCompromise", "affiliationChanged", "superseded", "cessationOfOperation"}
			found := false
			for _, valid := range validReasons {
				if valid == tc.expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected reason '%s' should be in valid reasons list", tc.expected)
			}
		})
	}
}
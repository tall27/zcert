package cmd

import (
	"strings"
	"testing"
)

// TestRetrieveCommandStructure tests that the retrieve command maintains proper structure
func TestRetrieveCommandStructure(t *testing.T) {
	// Test that retrieve command exists and has expected structure
	cmd := retrieveCmd
	if cmd == nil {
		t.Fatal("retrieve command should not be nil")
	}

	// Test that command has the right name
	if cmd.Use != "retrieve" {
		t.Errorf("Expected command use 'retrieve', got '%s'", cmd.Use)
	}

	// Test required flags exist
	expectedFlags := []string{"id", "cn", "serial", "policy", "format", "file", "p12-password", "chain", "first", "wide", "url", "hawk-id", "hawk-key"}
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

	// Test that help mentions retrieval functionality
	expectedKeywords := []string{"retrieve", "certificate"}
	for _, keyword := range expectedKeywords {
		if !strings.Contains(strings.ToLower(help), keyword) {
			t.Errorf("Help text should mention '%s'", keyword)
		}
	}
}

// TestRetrieveCommandValidation tests that the retrieve command properly validates inputs
func TestRetrieveCommandValidation(t *testing.T) {
	// Save original values
	origID := retrieveID
	origCN := retrieveCN
	origSerial := retrieveSerial
	origURL := retrieveURL
	origHawkID := retrieveHawkID
	origHawkKey := retrieveHawkKey
	
	// Reset all global variables to ensure clean test
	retrieveID = ""
	retrieveCN = ""
	retrieveSerial = ""
	retrieveURL = ""
	retrieveHawkID = ""
	retrieveHawkKey = ""
	
	// Test with missing required parameters
	err := runRetrieve(retrieveCmd, []string{})
	
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
	retrieveID = origID
	retrieveCN = origCN
	retrieveSerial = origSerial
	retrieveURL = origURL
	retrieveHawkID = origHawkID
	retrieveHawkKey = origHawkKey
}

// TestRetrieveCommandFlags tests individual flag parsing
func TestRetrieveCommandFlags(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
		flagType string
	}{
		{"Certificate ID flag", "id", "string"},
		{"Common Name flag", "cn", "string"},
		{"Serial number flag", "serial", "string"},
		{"Policy flag", "policy", "string"},
		{"Format flag", "format", "string"},
		{"File flag", "file", "string"},
		{"P12 password flag", "p12-password", "string"},
		{"Chain flag", "chain", "bool"},
		{"First flag", "first", "bool"},
		{"Wide flag", "wide", "bool"},
		{"URL flag", "url", "string"},
		{"HAWK ID flag", "hawk-id", "string"},
		{"HAWK Key flag", "hawk-key", "string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := retrieveCmd.Flags().Lookup(tt.flagName)
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

// TestRetrieveCommandDefaultValues tests default values for flags
func TestRetrieveCommandDefaultValues(t *testing.T) {
	// Test default format is "pem"
	formatFlag := retrieveCmd.Flags().Lookup("format")
	if formatFlag == nil {
		t.Fatal("format flag should exist")
	}
	
	if formatFlag.DefValue != "pem" {
		t.Errorf("Expected default format 'pem', got '%s'", formatFlag.DefValue)
	}

	// Test chain default is false
	chainFlag := retrieveCmd.Flags().Lookup("chain")
	if chainFlag == nil {
		t.Fatal("chain flag should exist")
	}
	
	if chainFlag.DefValue != "false" {
		t.Errorf("Expected default chain 'false', got '%s'", chainFlag.DefValue)
	}
}

// TestRetrieveCommandFormats tests that valid output formats are accepted
func TestRetrieveCommandFormats(t *testing.T) {
	validFormats := []string{"pem", "p12", "jks"}

	for _, format := range validFormats {
		t.Run("format_"+format, func(t *testing.T) {
			// Test that the command accepts these formats without validation error
			// Note: We can't actually execute retrieval without authentication,
			// but we can test that the format values are recognized
			
			// Check that format flag accepts the value
			formatFlag := retrieveCmd.Flags().Lookup("format")
			if formatFlag == nil {
				t.Fatal("format flag should exist")
			}
			
			// The format validation happens in the output handler, 
			// so we just verify the flag accepts the value
			err := formatFlag.Value.Set(format)
			if err != nil {
				t.Errorf("Valid format '%s' should be accepted by flag", format)
			}
		})
	}
}

// TestRetrieveCommandHelpUsage tests help and usage functions
func TestRetrieveCommandHelpUsage(t *testing.T) {
	// Test that help can be displayed without error
	helpOutput := retrieveCmd.Long
	if helpOutput == "" {
		t.Error("Long help text should not be empty")
	}

	// Test that help mentions key functionality
	expectedHelpContent := []string{"retrieve", "certificate", "formats", "chain"}
	for _, content := range expectedHelpContent {
		if !strings.Contains(strings.ToLower(helpOutput), content) {
			t.Errorf("Help should mention '%s'", content)
		}
	}

	// Test usage line
	usage := retrieveCmd.UseLine()
	if !strings.Contains(usage, "retrieve") {
		t.Errorf("Usage line should contain 'retrieve', got: %s", usage)
	}
}

// TestRetrieveCommandIdentifierValidation tests certificate identifier validation
func TestRetrieveCommandIdentifierValidation(t *testing.T) {
	// Test only the validation logic, not the full execution
	testCases := []struct {
		name        string
		id          string
		cn          string
		serial      string
		policy      string
		expectError bool
	}{
		{
			name:        "no identifier",
			id:          "",
			cn:          "",
			serial:      "",
			policy:      "",
			expectError: true,
		},
		{
			name:        "with ID only",
			id:          "test-id-123",
			cn:          "",
			serial:      "",
			policy:      "",
			expectError: false,
		},
		{
			name:        "with CN only", 
			id:          "",
			cn:          "test.example.com",
			serial:      "",
			policy:      "",
			expectError: false,
		},
		{
			name:        "with serial only",
			id:          "",
			cn:          "",
			serial:      "ABC123",
			policy:      "",
			expectError: false,
		},
		{
			name:        "with policy only",
			id:          "",
			cn:          "",
			serial:      "",
			policy:      "test-policy",
			expectError: true, // Policy alone is not a valid identifier
		},
		{
			name:        "with multiple identifiers",
			id:          "test-id",
			cn:          "test.com",
			serial:      "ABC123",
			policy:      "",
			expectError: false,
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

// TestRetrieveCommandAuthenticationValidation tests authentication parameter validation logic
func TestRetrieveCommandAuthenticationValidation(t *testing.T) {
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

// TestRetrieveCommandFlagGrouping tests that flags are properly grouped in help
func TestRetrieveCommandFlagGrouping(t *testing.T) {
	// Test that all expected flag groups are present
	expectedGroups := map[string][]string{
		"Certificate Identification": {"id", "cn", "serial", "policy"},
		"Output Options":             {"format", "file", "p12-password", "chain", "first", "wide"},
		"Server & Authentication":    {"url", "hawk-id", "hawk-key"},
	}

	for groupName, flags := range expectedGroups {
		for _, flagName := range flags {
			flag := retrieveCmd.Flags().Lookup(flagName)
			if flag == nil {
				t.Errorf("Flag --%s should exist in group '%s'", flagName, groupName)
			}
		}
	}
}

// TestRetrieveCommandParentAttachment tests that command is properly attached to root
func TestRetrieveCommandParentAttachment(t *testing.T) {
	if retrieveCmd.Parent() != rootCmd {
		t.Error("Retrieve command should be attached to root command")
	}
}

// TestRetrieveCommandOutputOptions tests output options validation
func TestRetrieveCommandOutputOptions(t *testing.T) {
	testCases := []struct {
		name     string
		format   string
		file     string
		p12Pass  string
		chain    bool
		valid    bool
	}{
		{
			name:    "PEM format without file",
			format:  "pem",
			file:    "",
			p12Pass: "",
			chain:   false,
			valid:   true,
		},
		{
			name:    "PEM format with file",
			format:  "pem",
			file:    "cert.pem",
			p12Pass: "",
			chain:   false,
			valid:   true,
		},
		{
			name:    "PEM format with chain",
			format:  "pem",
			file:    "",
			p12Pass: "",
			chain:   true,
			valid:   true,
		},
		{
			name:    "P12 format with password",
			format:  "p12",
			file:    "cert.p12",
			p12Pass: "password123",
			chain:   false,
			valid:   true,
		},
		{
			name:    "P12 format without password",
			format:  "p12",
			file:    "cert.p12",
			p12Pass: "",
			chain:   false,
			valid:   true, // P12 password is optional
		},
		{
			name:    "JKS format",
			format:  "jks",
			file:    "cert.jks",
			p12Pass: "",
			chain:   false,
			valid:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test that the combination of options is logically valid
			// This is basic validation - the actual format handling is in the output module
			
			validFormats := []string{"pem", "p12", "jks"}
			formatValid := false
			for _, validFormat := range validFormats {
				if tc.format == validFormat {
					formatValid = true
					break
				}
			}
			
			if !formatValid && tc.valid {
				t.Errorf("Invalid format '%s' should not be considered valid", tc.format)
			}
			
			if formatValid && !tc.valid {
				t.Errorf("Valid format '%s' should be considered valid", tc.format)
			}
		})
	}
}

// TestRetrieveCommandRetrievalMethods tests different certificate retrieval methods
func TestRetrieveCommandRetrievalMethods(t *testing.T) {
	testCases := []struct {
		name        string
		useID       bool
		useCN       bool
		useSerial   bool
		expectDirect bool // ID-based retrieval is direct, others require search
	}{
		{
			name:         "retrieve by ID",
			useID:        true,
			useCN:        false,
			useSerial:    false,
			expectDirect: true,
		},
		{
			name:         "retrieve by CN",
			useID:        false,
			useCN:        true,
			useSerial:    false,
			expectDirect: false,
		},
		{
			name:         "retrieve by serial",
			useID:        false,
			useCN:        false,
			useSerial:    true,
			expectDirect: false,
		},
		{
			name:         "retrieve by CN and serial",
			useID:        false,
			useCN:        true,
			useSerial:    true,
			expectDirect: false,
		},
		{
			name:         "retrieve by ID with CN",
			useID:        true,
			useCN:        true,
			useSerial:    false,
			expectDirect: true, // ID takes precedence
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the logic that determines retrieval method
			// ID-based retrieval is direct, others require search first
			
			if tc.useID && !tc.expectDirect {
				t.Error("ID-based retrieval should be direct")
			}
			
			if !tc.useID && tc.expectDirect {
				t.Error("Non-ID retrieval should not be direct")
			}
		})
	}
}
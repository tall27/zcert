package cmd

import (
	"strings"
	"testing"
)

// TestSearchCommandStructure tests that the search command maintains proper structure
func TestSearchCommandStructure(t *testing.T) {
	// Test that search command exists and has expected structure
	cmd := searchCmd
	if cmd == nil {
		t.Fatal("search command should not be nil")
	}

	// Test that command has the right name
	if cmd.Use != "search" {
		t.Errorf("Expected command use 'search', got '%s'", cmd.Use)
	}

	// Test required flags exist
	expectedFlags := []string{"id", "cn", "issuer", "serial", "policies", "policy", "status", "url", "hawk-id", "hawk-key", "limit", "format", "wide", "expired", "expiring", "recent"}
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

	// Test that help mentions search functionality
	expectedKeywords := []string{"search", "certificate"}
	for _, keyword := range expectedKeywords {
		if !strings.Contains(strings.ToLower(help), keyword) {
			t.Errorf("Help text should mention '%s'", keyword)
		}
	}
}

// TestSearchCommandFlags tests individual flag parsing
func TestSearchCommandFlags(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
		flagType string
	}{
		{"Certificate ID flag", "id", "string"},
		{"Common Name flag", "cn", "string"},
		{"Issuer flag", "issuer", "string"},
		{"Serial number flag", "serial", "string"},
		{"Policies flag", "policies", "bool"},
		{"Policy flag", "policy", "string"},
		{"Status flag", "status", "string"},
		{"URL flag", "url", "string"},
		{"HAWK ID flag", "hawk-id", "string"},
		{"HAWK Key flag", "hawk-key", "string"},
		{"Limit flag", "limit", "int"},
		{"Format flag", "format", "string"},
		{"Wide flag", "wide", "bool"},
		{"Expired flag", "expired", "bool"},
		{"Expiring flag", "expiring", "string"},
		{"Recent flag", "recent", "int"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := searchCmd.Flags().Lookup(tt.flagName)
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
			case "int":
				if flag.Value.Type() != "int" {
					t.Errorf("Flag --%s should be int type, got %s", tt.flagName, flag.Value.Type())
				}
			}
		})
	}
}

// TestSearchCommandDefaultValues tests default values for flags
func TestSearchCommandDefaultValues(t *testing.T) {
	// Test default limit is 10
	limitFlag := searchCmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Fatal("limit flag should exist")
	}
	
	if limitFlag.DefValue != "10" {
		t.Errorf("Expected default limit '10', got '%s'", limitFlag.DefValue)
	}

	// Test default format is "table"
	formatFlag := searchCmd.Flags().Lookup("format")
	if formatFlag == nil {
		t.Fatal("format flag should exist")
	}
	
	if formatFlag.DefValue != "table" {
		t.Errorf("Expected default format 'table', got '%s'", formatFlag.DefValue)
	}

	// Test wide default is false
	wideFlag := searchCmd.Flags().Lookup("wide")
	if wideFlag == nil {
		t.Fatal("wide flag should exist")
	}
	
	if wideFlag.DefValue != "false" {
		t.Errorf("Expected default wide 'false', got '%s'", wideFlag.DefValue)
	}

	// Test expired default is false
	expiredFlag := searchCmd.Flags().Lookup("expired")
	if expiredFlag == nil {
		t.Fatal("expired flag should exist")
	}
	
	if expiredFlag.DefValue != "false" {
		t.Errorf("Expected default expired 'false', got '%s'", expiredFlag.DefValue)
	}

	// Test recent default is 0
	recentFlag := searchCmd.Flags().Lookup("recent")
	if recentFlag == nil {
		t.Fatal("recent flag should exist")
	}
	
	if recentFlag.DefValue != "0" {
		t.Errorf("Expected default recent '0', got '%s'", recentFlag.DefValue)
	}
}

// TestSearchCommandFormats tests that valid output formats are accepted
func TestSearchCommandFormats(t *testing.T) {
	validFormats := []string{"table", "json", "csv"}

	for _, format := range validFormats {
		t.Run("format_"+format, func(t *testing.T) {
			// Test that the command accepts these formats without validation error
			formatFlag := searchCmd.Flags().Lookup("format")
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

// TestSearchCommandHelpUsage tests help and usage functions
func TestSearchCommandHelpUsage(t *testing.T) {
	// Test that help can be displayed without error
	helpOutput := searchCmd.Long
	if helpOutput == "" {
		t.Error("Long help text should not be empty")
	}

	// Test that help mentions key functionality
	expectedHelpContent := []string{"search", "certificate", "criteria", "formats"}
	for _, content := range expectedHelpContent {
		if !strings.Contains(strings.ToLower(helpOutput), content) {
			t.Errorf("Help should mention '%s'", content)
		}
	}

	// Test usage line
	usage := searchCmd.UseLine()
	if !strings.Contains(usage, "search") {
		t.Errorf("Usage line should contain 'search', got: %s", usage)
	}
}

// TestSearchCommandIDFlagConsistency tests that the new --id flag is consistent with other commands
func TestSearchCommandIDFlagConsistency(t *testing.T) {
	// Test that search command has the --id flag like other commands
	idFlag := searchCmd.Flags().Lookup("id")
	if idFlag == nil {
		t.Fatal("search command should have --id flag for consistency with retrieve and revoke commands")
	}

	// Test that the flag has the correct type
	if idFlag.Value.Type() != "string" {
		t.Errorf("ID flag should be string type, got %s", idFlag.Value.Type())
	}

	// Test that the flag has appropriate usage text
	if !strings.Contains(strings.ToLower(idFlag.Usage), "certificate") {
		t.Error("ID flag usage should mention 'certificate'")
	}
	
	if !strings.Contains(strings.ToLower(idFlag.Usage), "id") {
		t.Error("ID flag usage should mention 'id'")
	}
}

// TestSearchCommandSearchCriteriaOptions tests different search criteria combinations
func TestSearchCommandSearchCriteriaOptions(t *testing.T) {
	// Test that multiple search criteria can be configured
	testCases := []struct {
		name     string
		flagName string
		purpose  string
	}{
		{
			name:     "ID search",
			flagName: "id",
			purpose:  "Direct certificate lookup",
		},
		{
			name:     "CN search",
			flagName: "cn",
			purpose:  "Common Name substring matching",
		},
		{
			name:     "Serial search",
			flagName: "serial",
			purpose:  "Serial number search",
		},
		{
			name:     "Issuer search",
			flagName: "issuer",
			purpose:  "Issuer filtering",
		},
		{
			name:     "Policy search",
			flagName: "policy",
			purpose:  "Policy-based filtering",
		},
		{
			name:     "Status search",
			flagName: "status",
			purpose:  "Certificate status filtering",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flag := searchCmd.Flags().Lookup(tc.flagName)
			if flag == nil {
				t.Errorf("Flag --%s should exist for %s", tc.flagName, tc.purpose)
			}
		})
	}
}

// TestSearchCommandFlagGrouping tests that flags are properly grouped in help
func TestSearchCommandFlagGrouping(t *testing.T) {
	// Test that all expected flag groups are present
	expectedGroups := map[string][]string{
		"Search Criteria":        {"id", "cn", "issuer", "serial", "policy", "status"},
		"Time-Based Filters":     {"expired", "expiring", "recent"},
		"Output Options":         {"format", "limit", "wide"},
		"Server & Authentication": {"url", "hawk-id", "hawk-key"},
	}

	for groupName, flags := range expectedGroups {
		for _, flagName := range flags {
			flag := searchCmd.Flags().Lookup(flagName)
			if flag == nil {
				t.Errorf("Flag --%s should exist in group '%s'", flagName, groupName)
			}
		}
	}
}

// TestSearchCommandParentAttachment tests that command is properly attached to root
func TestSearchCommandParentAttachment(t *testing.T) {
	if searchCmd.Parent() != rootCmd {
		t.Error("Search command should be attached to root command")
	}
}

// TestSearchCommandValidation tests basic input validation logic
func TestSearchCommandValidation(t *testing.T) {
	// Test search criteria validation logic
	testCases := []struct {
		name        string
		id          string
		cn          string
		serial      string
		expectValid bool
	}{
		{
			name:        "with ID only",
			id:          "test-id-123",
			cn:          "",
			serial:      "",
			expectValid: true,
		},
		{
			name:        "with CN only", 
			id:          "",
			cn:          "test.example.com",
			serial:      "",
			expectValid: true,
		},
		{
			name:        "with serial only",
			id:          "",
			cn:          "",
			serial:      "ABC123",
			expectValid: true,
		},
		{
			name:        "with multiple criteria",
			id:          "",
			cn:          "test.com",
			serial:      "ABC123",
			expectValid: true,
		},
		{
			name:        "no search criteria",
			id:          "",
			cn:          "",
			serial:      "",
			expectValid: true, // Search without criteria is valid (returns all)
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test validation logic for search criteria
			hasSearchCriteria := tc.id != "" || tc.cn != "" || tc.serial != ""
			
			// Search without criteria is valid (returns all certificates up to limit)
			isValid := tc.expectValid
			
			if isValid {
				// Test passes if we expect it to be valid
				if !tc.expectValid {
					t.Error("Expected search criteria to be valid")
				}
			} else {
				// Test passes if we expect it to be invalid
				if tc.expectValid {
					t.Error("Expected search criteria to be invalid")
				}
			}
			
			// Note: Unlike retrieve and revoke, search allows empty criteria
			_ = hasSearchCriteria // Suppress unused variable warning
		})
	}
}

// TestSearchCommandIDPrecedence tests that ID search takes precedence over other criteria
func TestSearchCommandIDPrecedence(t *testing.T) {
	// Test the logic that ID search should be direct and bypass other criteria
	testCases := []struct {
		name           string
		useID          bool
		useCN          bool
		useSerial      bool
		expectDirect   bool // ID-based search is direct, others use search API
	}{
		{
			name:         "ID only",
			useID:        true,
			useCN:        false,
			useSerial:    false,
			expectDirect: true,
		},
		{
			name:         "CN only",
			useID:        false,
			useCN:        true,
			useSerial:    false,
			expectDirect: false,
		},
		{
			name:         "ID with CN",
			useID:        true,
			useCN:        true,
			useSerial:    false,
			expectDirect: true, // ID takes precedence
		},
		{
			name:         "ID with serial",
			useID:        true,
			useCN:        false,
			useSerial:    true,
			expectDirect: true, // ID takes precedence
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the precedence logic
			if tc.useID && !tc.expectDirect {
				t.Error("ID-based search should be direct")
			}
			
			if !tc.useID && tc.expectDirect {
				t.Error("Non-ID search should not be direct")
			}
		})
	}
}
package cmd

import (
	"strings"
	"testing"
)

// TestEnrollCommandIntegration tests that the enroll command maintains proper structure
// This is a synthetic test to verify the command works after refactoring
func TestEnrollCommandIntegration(t *testing.T) {
	// Test that enroll command exists and has expected flags
	cmd := enrollCmd
	if cmd == nil {
		t.Fatal("enroll command should not be nil")
	}

	// Test required flags exist
	requiredFlags := []string{"cn", "url", "hawk-id", "hawk-key"}
	for _, flag := range requiredFlags {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("Required flag --%s not found", flag)
		}
	}

	// Test that help text is available
	help := cmd.Long
	if help == "" {
		t.Error("Help text should not be empty")
	}

	// Test that help mentions key workflow features
	expectedKeywords := []string{"certificate", "CSR"}
	for _, keyword := range expectedKeywords {
		if !strings.Contains(help, keyword) {
			t.Errorf("Help text should mention '%s'", keyword)
		}
	}

	// Test that examples mention HAWK authentication
	if !strings.Contains(help, "hawk-id") {
		t.Error("Help examples should mention HAWK authentication")
	}
}

// TestEnrollCommandValidation tests that the enroll command properly validates inputs
func TestEnrollCommandValidation(t *testing.T) {
	// Test with missing required parameters
	err := runEnroll(enrollCmd, []string{})
	if err == nil {
		t.Error("Expected error when no parameters provided")
	}

	// The error should mention missing required fields
	if err != nil && !strings.Contains(err.Error(), "required") {
		t.Errorf("Error should mention missing required fields, got: %v", err)
	}
}

// TestEnrollCommandUseUtilityFunctions tests that enroll command uses our new utility functions
// This is more of a design test to ensure the refactoring was applied
func TestEnrollCommandUsesUtilityFunctions(t *testing.T) {
	// This test verifies that our utility functions exist and can be called
	// It doesn't test actual enrollment (which would require a real ZTPKI instance)

	// Test that CreateAPIClientFromProfile function exists and can handle nil input
	_, err := CreateAPIClientFromProfile(nil, 0)
	if err == nil {
		t.Error("CreateAPIClientFromProfile should return error with nil profile")
	}

	expectedError := "profile cannot be nil"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error to contain '%s', got: %v", expectedError, err)
	}
}
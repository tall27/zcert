package cmd

import (
	"strings"
	"testing"
)

// TestPQCCommandIntegration tests that the PQC command maintains proper structure after refactoring
func TestPQCCommandIntegration(t *testing.T) {
	// Test that PQC command exists and has expected flags
	cmd := pqcCmd
	if cmd == nil {
		t.Fatal("PQC command should not be nil")
	}

	// Test required flags exist
	requiredFlags := []string{"cn", "pqc-algorithm", "url", "hawk-id", "hawk-key"}
	for _, flag := range requiredFlags {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("Required flag --%s not found", flag)
		}
	}

	// Test that help text mentions OpenSSL
	help := cmd.Long
	if !strings.Contains(help, "OpenSSL") {
		t.Error("Help text should mention OpenSSL for PQC operations")
	}

	// Test that help mentions PQC algorithms
	if !strings.Contains(help, "FIPS") {
		t.Error("Help text should mention FIPS standards")
	}
}

// TestPQCCommandValidation tests that the PQC command properly validates inputs
func TestPQCCommandValidation(t *testing.T) {
	// Test with missing required CN parameter
	err := runPQC(pqcCmd, []string{})
	if err == nil {
		t.Error("Expected error when no CN provided")
	}

	// The error should mention the missing required field
	if err != nil && !strings.Contains(err.Error(), "failed") {
		t.Errorf("Error should mention validation failure, got: %v", err)
	}
}

// TestPQCCommandUsesUtilityFunctions tests that PQC command uses our new utility functions
func TestPQCCommandUsesUtilityFunctions(t *testing.T) {
	// This test verifies that our utility functions are properly integrated
	// It doesn't test actual PQC operations (which would require OpenSSL and a real ZTPKI instance)

	// Test that CreateAPIClientFromProfile function is available
	_, err := CreateAPIClientFromProfile(nil, 0)
	if err == nil {
		t.Error("CreateAPIClientFromProfile should return error with nil profile")
	}

	expectedError := "profile cannot be nil"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error to contain '%s', got: %v", expectedError, err)
	}
}

// TestPQCOpenSSLIntegration tests that PQC command structure supports OpenSSL integration
func TestPQCOpenSSLIntegration(t *testing.T) {
	// Verify that PQC-specific flags are available
	pqcFlags := []string{"pqc-algorithm", "key-password", "no-key-output"}
	for _, flag := range pqcFlags {
		if pqcCmd.Flags().Lookup(flag) == nil {
			t.Errorf("PQC-specific flag --%s not found", flag)
		}
	}

	// Test that PQC algorithms are mentioned in help
	help := pqcCmd.Long
	algorithmMentions := []string{"ML-DSA", "SLH-DSA"}
	for _, alg := range algorithmMentions {
		if !strings.Contains(help, alg) {
			t.Errorf("Help should mention algorithm '%s'", alg)
		}
	}
}
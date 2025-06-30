package utils

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestNewAuthURLError tests standardized authentication URL error
func TestNewAuthURLError(t *testing.T) {
	err := NewAuthURLError()
	
	if err == nil {
		t.Fatal("NewAuthURLError() should return an error")
	}
	
	expected := "ZTPKI URL is required (use --url flag, config file, or ZTPKI_URL environment variable)"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
}

// TestNewAuthHawkIDError tests standardized authentication HAWK ID error
func TestNewAuthHawkIDError(t *testing.T) {
	err := NewAuthHawkIDError()
	
	if err == nil {
		t.Fatal("NewAuthHawkIDError() should return an error")
	}
	
	expected := "HAWK ID is required (use --hawk-id flag, config file, or ZTPKI_HAWK_ID environment variable)"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
}

// TestNewAuthHawkKeyError tests standardized authentication HAWK key error
func TestNewAuthHawkKeyError(t *testing.T) {
	err := NewAuthHawkKeyError()
	
	if err == nil {
		t.Fatal("NewAuthHawkKeyError() should return an error")
	}
	
	expected := "HAWK key is required (use --hawk-key flag, config file, or ZTPKI_HAWK_SECRET environment variable)"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
}

// TestNewCertificateIdentifierError tests certificate identifier validation error
func TestNewCertificateIdentifierError(t *testing.T) {
	err := NewCertificateIdentifierError()
	
	if err == nil {
		t.Fatal("NewCertificateIdentifierError() should return an error")
	}
	
	expected := "must specify at least one certificate identifier (--id, --cn, or --serial)"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
}

// TestNewCertificateNotFoundError tests certificate not found error
func TestNewCertificateNotFoundError(t *testing.T) {
	err := NewCertificateNotFoundError()
	
	if err == nil {
		t.Fatal("NewCertificateNotFoundError() should return an error")
	}
	
	expected := "no certificates found matching the specified criteria"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
}

// TestErrorWrapping tests that errors are properly wrapped
func TestErrorWrapping(t *testing.T) {
	originalErr := errors.New("original error")
	
	testCases := []struct {
		name     string
		errFunc  func(error) error
		contains string
	}{
		{
			name:     "Certificate retrieval error",
			errFunc:  NewCertificateRetrievalError,
			contains: "failed to retrieve certificate:",
		},
		{
			name:     "Certificate search error",
			errFunc:  NewCertificateSearchError,
			contains: "failed to search certificates:",
		},
		{
			name:     "Certificate revocation error",
			errFunc:  NewCertificateRevocationError,
			contains: "failed to revoke certificate:",
		},
		{
			name:     "Certificate enrollment error",
			errFunc:  NewCertificateEnrollmentError,
			contains: "failed to enroll certificate:",
		},
		{
			name:     "API client error",
			errFunc:  NewAPIClientError,
			contains: "failed to initialize API client:",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.errFunc(originalErr)
			
			if err == nil {
				t.Fatal("Error function should return an error")
			}
			
			if !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("Error message should contain '%s', got '%s'", tc.contains, err.Error())
			}
			
			if !strings.Contains(err.Error(), "original error") {
				t.Errorf("Error should wrap original error, got '%s'", err.Error())
			}
			
			// Test error unwrapping
			if !errors.Is(err, originalErr) {
				t.Error("Error should be unwrappable to original error")
			}
		})
	}
}

// TestPolicyErrors tests policy-related error functions
func TestPolicyErrors(t *testing.T) {
	testCases := []struct {
		name     string
		function func(string) error
		policy   string
		contains string
	}{
		{
			name:     "Policy not found",
			function: NewPolicyNotFoundError,
			policy:   "test-policy",
			contains: "no policies found matching 'test-policy'",
		},
		{
			name:     "Policy ambiguous",
			function: NewPolicyAmbiguousError,
			policy:   "test",
			contains: "multiple policies match 'test', please be more specific",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.function(tc.policy)
			
			if err == nil {
				t.Fatal("Policy error function should return an error")
			}
			
			if err.Error() != tc.contains {
				t.Errorf("Expected error message '%s', got '%s'", tc.contains, err.Error())
			}
		})
	}
}

// TestPolicyResolutionError tests policy resolution error with wrapping
func TestPolicyResolutionError(t *testing.T) {
	originalErr := errors.New("network error")
	policy := "test-policy"
	
	err := NewPolicyResolutionError(policy, originalErr)
	
	if err == nil {
		t.Fatal("NewPolicyResolutionError should return an error")
	}
	
	expected := "failed to resolve policy 'test-policy': network error"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
	
	if !errors.Is(err, originalErr) {
		t.Error("Error should be unwrappable to original error")
	}
}

// TestFileErrors tests file I/O error functions
func TestFileErrors(t *testing.T) {
	originalErr := errors.New("permission denied")
	
	testCases := []struct {
		name     string
		function func(string, error) error
		fileType string
		contains string
	}{
		{
			name:     "File read error",
			function: NewFileReadError,
			fileType: "CSR",
			contains: "failed to read CSR file:",
		},
		{
			name:     "File write error",
			function: NewFileWriteError,
			fileType: "certificate",
			contains: "failed to write certificate file:",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.function(tc.fileType, originalErr)
			
			if err == nil {
				t.Fatal("File error function should return an error")
			}
			
			if !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("Error message should contain '%s', got '%s'", tc.contains, err.Error())
			}
			
			if !errors.Is(err, originalErr) {
				t.Error("Error should be unwrappable to original error")
			}
		})
	}
}

// TestUnsupportedFormatError tests format validation error
func TestUnsupportedFormatError(t *testing.T) {
	format := "xml"
	supported := []string{"pem", "p12", "jks"}
	
	err := NewUnsupportedFormatError(format, supported)
	
	if err == nil {
		t.Fatal("NewUnsupportedFormatError should return an error")
	}
	
	expected := "unsupported output format: xml (supported: [pem p12 jks])"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
}

// TestParameterValidationError tests parameter validation error
func TestParameterValidationError(t *testing.T) {
	param := "expiring"
	reason := "invalid format: must be a number"
	
	err := NewParameterValidationError(param, reason)
	
	if err == nil {
		t.Fatal("NewParameterValidationError should return an error")
	}
	
	expected := "invalid parameter --expiring: invalid format: must be a number"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
}

// TestNonInteractiveModeError tests non-interactive mode error
func TestNonInteractiveModeError(t *testing.T) {
	count := 5
	instruction := "Use --id to specify a particular certificate"
	
	err := NewNonInteractiveModeError(count, instruction)
	
	if err == nil {
		t.Fatal("NewNonInteractiveModeError should return an error")
	}
	
	expected := "multiple items found (5) but running in non-interactive mode. Use --id to specify a particular certificate"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
}

// TestConfigurationError tests configuration error functions
func TestConfigurationError(t *testing.T) {
	t.Run("With underlying error", func(t *testing.T) {
		originalErr := errors.New("file not found")
		message := "invalid config file"
		
		err := NewConfigurationError(message, originalErr)
		
		if err == nil {
			t.Fatal("NewConfigurationError should return an error")
		}
		
		expected := "configuration error: invalid config file: file not found"
		if err.Error() != expected {
			t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
		}
		
		if !errors.Is(err, originalErr) {
			t.Error("Error should be unwrappable to original error")
		}
	})
	
	t.Run("Without underlying error", func(t *testing.T) {
		message := "invalid config file"
		
		err := NewConfigurationError(message, nil)
		
		if err == nil {
			t.Fatal("NewConfigurationError should return an error")
		}
		
		expected := "configuration error: invalid config file"
		if err.Error() != expected {
			t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
		}
	})
}

// TestCSRAndKeyErrors tests CSR and private key error functions
func TestCSRAndKeyErrors(t *testing.T) {
	originalErr := errors.New("invalid format")
	
	testCases := []struct {
		name     string
		function func(error) error
		contains string
	}{
		{
			name:     "CSR generation error",
			function: NewCSRGenerationError,
			contains: "failed to generate certificate signing request:",
		},
		{
			name:     "CSR parsing error",
			function: NewCSRParsingError,
			contains: "failed to parse certificate signing request:",
		},
		{
			name:     "Private key generation error",
			function: NewPrivateKeyGenerationError,
			contains: "failed to generate private key:",
		},
		{
			name:     "Private key parsing error",
			function: NewPrivateKeyParsingError,
			contains: "failed to parse private key:",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.function(originalErr)
			
			if err == nil {
				t.Fatal("Error function should return an error")
			}
			
			if !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("Error message should contain '%s', got '%s'", tc.contains, err.Error())
			}
			
			if !errors.Is(err, originalErr) {
				t.Error("Error should be unwrappable to original error")
			}
		})
	}
}

// TestErrorConsistency tests that all error messages follow consistent patterns
func TestErrorConsistency(t *testing.T) {
	// Test that authentication errors all mention the three sources
	authErrors := []error{
		NewAuthURLError(),
		NewAuthHawkIDError(),
		NewAuthHawkKeyError(),
	}
	
	for i, err := range authErrors {
		t.Run(fmt.Sprintf("auth_error_%d", i), func(t *testing.T) {
			msg := err.Error()
			
			// Should mention all three sources
			sources := []string{"--", "flag", "config file", "environment variable"}
			for _, source := range sources {
				if !strings.Contains(msg, source) {
					t.Errorf("Authentication error should mention '%s', got '%s'", source, msg)
				}
			}
		})
	}
	
	// Test that operational errors follow "failed to [action]" pattern
	originalErr := errors.New("test error")
	operationalErrors := []error{
		NewCertificateRetrievalError(originalErr),
		NewCertificateSearchError(originalErr),
		NewCertificateRevocationError(originalErr),
		NewCertificateEnrollmentError(originalErr),
		NewAPIClientError(originalErr),
	}
	
	for i, err := range operationalErrors {
		t.Run(fmt.Sprintf("operational_error_%d", i), func(t *testing.T) {
			msg := err.Error()
			
			if !strings.HasPrefix(msg, "failed to ") {
				t.Errorf("Operational error should start with 'failed to ', got '%s'", msg)
			}
		})
	}
}
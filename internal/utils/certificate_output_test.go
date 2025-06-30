package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"zcert/internal/api"
)

// TestDefaultCertificateOutputOptions tests default options creation
func TestDefaultCertificateOutputOptions(t *testing.T) {
	opts := DefaultCertificateOutputOptions()
	
	if opts == nil {
		t.Fatal("DefaultCertificateOutputOptions() should not return nil")
	}
	
	if opts.Format != "table" {
		t.Errorf("Expected default format 'table', got '%s'", opts.Format)
	}
	
	if opts.Wide != false {
		t.Errorf("Expected default wide false, got %v", opts.Wide)
	}
	
	if opts.Writer == nil {
		t.Error("Expected default writer to be set")
	}
}

// TestOutputCertificatesTable tests table format output
func TestOutputCertificatesTable(t *testing.T) {
	certificates := createTestCertificates()
	
	var buf bytes.Buffer
	opts := &CertificateOutputOptions{
		Format: "table",
		Wide:   false,
		Writer: &buf,
	}
	
	err := OutputCertificates(certificates, opts)
	if err != nil {
		t.Fatalf("OutputCertificates failed: %v", err)
	}
	
	output := buf.String()
	
	// Check table headers (check each column)
	if !strings.Contains(output, "ID") || !strings.Contains(output, "COMMON NAME") || !strings.Contains(output, "SERIAL") {
		t.Errorf("Table output should contain headers, got: %s", output)
	}
	
	// Check table separator (look for dashes)
	if !strings.Contains(output, "----") {
		t.Errorf("Table output should contain separator line, got: %s", output)
	}
	
	// Check certificate data
	if !strings.Contains(output, "test1.com") {
		t.Error("Table output should contain certificate data")
	}
}

// TestOutputCertificatesTableWithIndex tests table format with index numbers
func TestOutputCertificatesTableWithIndex(t *testing.T) {
	certificates := createTestCertificates()
	
	var buf bytes.Buffer
	opts := &CertificateOutputOptions{
		Format:    "table",
		Wide:      false,
		Writer:    &buf,
		ShowIndex: true,
		Title:     "Test Certificates",
	}
	
	err := OutputCertificates(certificates, opts)
	if err != nil {
		t.Fatalf("OutputCertificates failed: %v", err)
	}
	
	output := buf.String()
	
	// Check title
	if !strings.Contains(output, "Test Certificates (2 found)") {
		t.Error("Table output should contain title with count")
	}
	
	// Check index headers
	if !strings.Contains(output, "#") || !strings.Contains(output, "ID") {
		t.Errorf("Table output should contain index column header, got: %s", output)
	}
	
	// Check index numbers
	if !strings.Contains(output, "1") {
		t.Errorf("Table output should contain index numbers, got: %s", output)
	}
}

// TestOutputCertificatesTableWide tests wide table format
func TestOutputCertificatesTableWide(t *testing.T) {
	certificates := createTestCertificatesWithLongFields()
	
	var buf bytes.Buffer
	opts := &CertificateOutputOptions{
		Format: "table",
		Wide:   true,
		Writer: &buf,
	}
	
	err := OutputCertificates(certificates, opts)
	if err != nil {
		t.Fatalf("OutputCertificates failed: %v", err)
	}
	
	output := buf.String()
	
	// In wide mode, long fields should not be truncated
	if !strings.Contains(output, "very-long-certificate-id-that-should-not-be-truncated") {
		t.Error("Wide table output should not truncate long fields")
	}
}

// TestOutputCertificatesTableNonWide tests non-wide table format with truncation
func TestOutputCertificatesTableNonWide(t *testing.T) {
	certificates := createTestCertificatesWithLongFields()
	
	var buf bytes.Buffer
	opts := &CertificateOutputOptions{
		Format: "table",
		Wide:   false,
		Writer: &buf,
	}
	
	err := OutputCertificates(certificates, opts)
	if err != nil {
		t.Fatalf("OutputCertificates failed: %v", err)
	}
	
	output := buf.String()
	
	// In non-wide mode, long fields should be truncated with "..."
	if !strings.Contains(output, "very-long...") {
		t.Error("Non-wide table output should truncate long fields with '...'")
	}
}

// TestOutputCertificatesJSON tests JSON format output
func TestOutputCertificatesJSON(t *testing.T) {
	certificates := createTestCertificates()
	
	var buf bytes.Buffer
	opts := &CertificateOutputOptions{
		Format: "json",
		Writer: &buf,
	}
	
	err := OutputCertificates(certificates, opts)
	if err != nil {
		t.Fatalf("OutputCertificates failed: %v", err)
	}
	
	output := buf.String()
	
	// Parse JSON to verify it's valid
	var result []api.Certificate
	err = json.Unmarshal([]byte(strings.TrimSpace(output)), &result)
	if err != nil {
		t.Fatalf("JSON output should be valid JSON: %v", err)
	}
	
	if len(result) != len(certificates) {
		t.Errorf("Expected %d certificates in JSON, got %d", len(certificates), len(result))
	}
	
	// Verify certificate data
	if result[0].CommonName != "test1.com" {
		t.Errorf("Expected first certificate CN 'test1.com', got '%s'", result[0].CommonName)
	}
}

// TestOutputCertificatesCSV tests CSV format output
func TestOutputCertificatesCSV(t *testing.T) {
	certificates := createTestCertificates()
	
	var buf bytes.Buffer
	opts := &CertificateOutputOptions{
		Format: "csv",
		Writer: &buf,
	}
	
	err := OutputCertificates(certificates, opts)
	if err != nil {
		t.Fatalf("OutputCertificates failed: %v", err)
	}
	
	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	
	// Check header
	expectedHeader := "ID,Common Name,Serial Number,Status,Issuer,Expiry Date,Policy ID"
	if lines[0] != expectedHeader {
		t.Errorf("Expected CSV header '%s', got '%s'", expectedHeader, lines[0])
	}
	
	// Check data rows
	if len(lines) != len(certificates)+1 { // +1 for header
		t.Errorf("Expected %d lines in CSV (including header), got %d", len(certificates)+1, len(lines))
	}
	
	// Check CSV data contains quoted values
	if !strings.Contains(lines[1], "\"test1.com\"") {
		t.Error("CSV output should contain quoted certificate data")
	}
}

// TestOutputCertificatesCSVWithIndex tests CSV format with index numbers
func TestOutputCertificatesCSVWithIndex(t *testing.T) {
	certificates := createTestCertificates()
	
	var buf bytes.Buffer
	opts := &CertificateOutputOptions{
		Format:    "csv",
		Writer:    &buf,
		ShowIndex: true,
	}
	
	err := OutputCertificates(certificates, opts)
	if err != nil {
		t.Fatalf("OutputCertificates failed: %v", err)
	}
	
	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	
	// Check header with index
	if !strings.HasPrefix(lines[0], "#,ID,") {
		t.Error("CSV output with index should start with '#,ID,'")
	}
	
	// Check data rows start with index numbers
	if !strings.HasPrefix(lines[1], "1,") {
		t.Error("CSV data rows should start with index numbers")
	}
}

// TestOutputCertificatesUnsupportedFormat tests error handling for unsupported formats
func TestOutputCertificatesUnsupportedFormat(t *testing.T) {
	certificates := createTestCertificates()
	
	var buf bytes.Buffer
	opts := &CertificateOutputOptions{
		Format: "xml",
		Writer: &buf,
	}
	
	err := OutputCertificates(certificates, opts)
	if err == nil {
		t.Fatal("OutputCertificates should fail for unsupported format")
	}
	
	expectedError := "unsupported output format: xml (supported: [table json csv])"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestTruncateString tests string truncation utility
func TestTruncateString(t *testing.T) {
	testCases := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10c", 10, "exactly10c"},
		{"this is a very long string", 10, "this is..."},
		{"medium length", 15, "medium length"},
		{"", 5, ""},
		{"a", 5, "a"},
		{"very long string that needs truncation", 15, "very long st..."},
	}
	
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := TruncateString(tc.input, tc.maxLen)
			if result != tc.expected {
				t.Errorf("TruncateString(%q, %d) = %q, expected %q", tc.input, tc.maxLen, result, tc.expected)
			}
		})
	}
}

// TestFormatCertificateList tests certificate list formatting for error messages
func TestFormatCertificateList(t *testing.T) {
	certificates := createTestCertificates()
	
	result := FormatCertificateList(certificates)
	
	// Check format
	lines := strings.Split(strings.TrimSpace(result), "\n")
	if len(lines) != len(certificates) {
		t.Errorf("Expected %d lines, got %d", len(certificates), len(lines))
	}
	
	// Check content (without leading spaces as implemented)
	if !strings.Contains(lines[0], "ID: cert-1") || !strings.Contains(lines[0], "CN: test1.com") {
		t.Errorf("Expected line to contain certificate data, got '%s'", lines[0])
	}
}

// TestDisplayCertificatesForSelection tests certificate selection display
func TestDisplayCertificatesForSelection(t *testing.T) {
	certificates := createTestCertificates()
	
	var buf bytes.Buffer
	opts := &CertificateSelectionOptions{
		Wide:   false,
		Prompt: "Select a certificate",
		Writer: &buf,
	}
	
	err := DisplayCertificatesForSelection(certificates, opts)
	if err != nil {
		t.Fatalf("DisplayCertificatesForSelection failed: %v", err)
	}
	
	output := buf.String()
	
	// Should contain prompt with count
	if !strings.Contains(output, "Select a certificate (2 found)") {
		t.Error("Selection display should contain prompt with count")
	}
	
	// Should contain index column
	if !strings.Contains(output, "#") || !strings.Contains(output, "ID") {
		t.Errorf("Selection display should contain index column, got: %s", output)
	}
}

// TestDisplayCertificatesForSelectionNilOptions tests with nil options
func TestDisplayCertificatesForSelectionNilOptions(t *testing.T) {
	certificates := createTestCertificates()
	
	// Should work with nil options (using defaults)
	err := DisplayCertificatesForSelection(certificates, nil)
	if err != nil {
		t.Fatalf("DisplayCertificatesForSelection with nil options failed: %v", err)
	}
}

// TestOutputSingleCertificate tests single certificate information display
func TestOutputSingleCertificate(t *testing.T) {
	certificate := &createTestCertificates()[0]
	
	var buf bytes.Buffer
	OutputSingleCertificate(certificate, &buf)
	
	output := buf.String()
	
	// Check required fields
	expectedFields := []string{
		"Certificate information:",
		"ID: cert-1",
		"Common Name: test1.com",
		"Serial Number: 12345",
		"Issuer: Test CA",
		"Status: Valid",
		"Expires:",
	}
	
	for _, field := range expectedFields {
		if !strings.Contains(output, field) {
			t.Errorf("Single certificate output should contain '%s'", field)
		}
	}
}

// TestEscapeCsvValue tests CSV value escaping
func TestEscapeCsvValue(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with spaces", "with spaces"},
		{"with\"quotes", "with\\\"quotes"},
		{"with,comma", "with,comma"},
		{"with\nnewline", "with\\nnewline"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := escapeCsvValue(tc.input)
			if result != tc.expected {
				t.Errorf("escapeCsvValue(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

// Helper functions for creating test data

func createTestCertificates() []api.Certificate {
	expiryDate, _ := time.Parse(time.RFC3339, "2025-01-01T12:00:00Z")
	
	return []api.Certificate{
		{
			ID:           "cert-1",
			CommonName:   "test1.com",
			SerialNumber: "12345",
			Status:       "Valid",
			Issuer:       "Test CA",
			ExpiryDate:   expiryDate,
			PolicyID:     "policy-1",
		},
		{
			ID:           "cert-2",
			CommonName:   "test2.com",
			SerialNumber: "67890",
			Status:       "Valid",
			Issuer:       "Test CA",
			ExpiryDate:   expiryDate,
			PolicyID:     "policy-2",
		},
	}
}

func createTestCertificatesWithLongFields() []api.Certificate {
	expiryDate, _ := time.Parse(time.RFC3339, "2025-01-01T12:00:00Z")
	
	return []api.Certificate{
		{
			ID:           "very-long-certificate-id-that-should-not-be-truncated-in-wide-mode",
			CommonName:   "very-long-common-name-that-exceeds-normal-display-width.example.com",
			SerialNumber: "very-long-serial-number-123456789012345678901234567890",
			Status:       "Valid",
			Issuer:       "Very Long Certificate Authority Name That Exceeds Display Width",
			ExpiryDate:   expiryDate,
			PolicyID:     "very-long-policy-id-that-should-be-truncated",
		},
	}
}

// TestOutputCertificatesConsistency tests consistency across different formats
func TestOutputCertificatesConsistency(t *testing.T) {
	certificates := createTestCertificates()
	
	formats := []string{"table", "json", "csv"}
	
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			opts := &CertificateOutputOptions{
				Format: format,
				Writer: &buf,
			}
			
			err := OutputCertificates(certificates, opts)
			if err != nil {
				t.Fatalf("OutputCertificates failed for format %s: %v", format, err)
			}
			
			output := buf.String()
			
			// All formats should contain certificate data
			if !strings.Contains(output, "test1.com") {
				t.Errorf("Format %s should contain certificate data", format)
			}
			
			// Output should not be empty
			if len(strings.TrimSpace(output)) == 0 {
				t.Errorf("Format %s should produce non-empty output", format)
			}
		})
	}
}

// TestCertificateOutputIntegration tests integration between different utilities
func TestCertificateOutputIntegration(t *testing.T) {
	certificates := createTestCertificates()
	
	// Test that FormatCertificateList produces consistent format
	listOutput := FormatCertificateList(certificates)
	lines := strings.Split(strings.TrimSpace(listOutput), "\n")
	
	if len(lines) != len(certificates) {
		t.Errorf("FormatCertificateList should produce one line per certificate")
	}
	
	// Test that DisplayCertificatesForSelection works with various options
	testOpts := []*CertificateSelectionOptions{
		{Wide: false, Prompt: "Test", Writer: &bytes.Buffer{}},
		{Wide: true, Prompt: "Test Wide", Writer: &bytes.Buffer{}},
		nil, // Should use defaults
	}
	
	for i, opts := range testOpts {
		t.Run(fmt.Sprintf("selection_opts_%d", i), func(t *testing.T) {
			err := DisplayCertificatesForSelection(certificates, opts)
			if err != nil {
				t.Errorf("DisplayCertificatesForSelection failed with options %v: %v", opts, err)
			}
		})
	}
}
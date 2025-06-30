package config

import (
	"os"
	"strings"
	"testing"
)

// TestPQCProfileSubjectParsing tests that PQC profile subject fields are parsed correctly
func TestPQCProfileSubjectParsing(t *testing.T) {
	// Create a temporary config file with PQC profile
	configContent := `[pqc]
url = https://ztpki-staging.venafi.com/api/v2
hawk-id = test-hawk-id
hawk-api = test-hawk-secret
policy = test-policy-id
pqc-algorithm = MLDSA44
legacy-alg-names = true
openssl-path = ./openssl
temp-dir = .
cleanup = false
subject = {
    common_name = Test PQC Certificate
    country = US
    state = California
    locality = San Francisco
    organization = Test Corp
    organizational_unit = IT Department
}
`

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "test-pqc-*.cnf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	// Load the profile config
	pc, err := LoadProfileConfig(tmpFile.Name(), true)
	if err != nil {
		t.Fatalf("Failed to load profile config: %v", err)
	}

	// Get the PQC profile
	profile := pc.GetProfile("pqc")
	if profile == nil {
		t.Fatal("PQC profile should not be nil")
	}

	// Test subject fields
	if profile.SubjectCommonName != "Test PQC Certificate" {
		t.Errorf("Expected SubjectCommonName 'Test PQC Certificate', got '%s'", profile.SubjectCommonName)
	}
	if profile.SubjectCountry != "US" {
		t.Errorf("Expected SubjectCountry 'US', got '%s'", profile.SubjectCountry)
	}
	if profile.SubjectProvince != "California" {
		t.Errorf("Expected SubjectProvince 'California', got '%s'", profile.SubjectProvince)
	}
	if profile.SubjectLocality != "San Francisco" {
		t.Errorf("Expected SubjectLocality 'San Francisco', got '%s'", profile.SubjectLocality)
	}
	if profile.SubjectOrganization != "Test Corp" {
		t.Errorf("Expected SubjectOrganization 'Test Corp', got '%s'", profile.SubjectOrganization)
	}
	if profile.SubjectOrganizationalUnit != "IT Department" {
		t.Errorf("Expected SubjectOrganizationalUnit 'IT Department', got '%s'", profile.SubjectOrganizationalUnit)
	}

	// Test PQC-specific settings
	if !profile.LegacyAlgNames {
		t.Error("Expected LegacyAlgNames to be true")
	}
	if profile.PQCAlgorithm != "MLDSA44" {
		t.Errorf("Expected PQCAlgorithm 'MLDSA44', got '%s'", profile.PQCAlgorithm)
	}
	if profile.Cleanup {
		t.Error("Expected Cleanup to be false")
	}
	if profile.OpenSSLPath != "./openssl" {
		t.Errorf("Expected OpenSSLPath './openssl', got '%s'", profile.OpenSSLPath)
	}
	if profile.TempDir != "." {
		t.Errorf("Expected TempDir '.', got '%s'", profile.TempDir)
	}
}

// TestPQCProfileSubjectParsingInlineFormat tests parsing subject in inline format
func TestPQCProfileSubjectParsingInlineFormat(t *testing.T) {
	configContent := `[pqc]
url = https://ztpki-staging.venafi.com/api/v2
hawk-id = test-hawk-id
hawk-api = test-hawk-secret
policy = test-policy-id
subject = CN=Inline Test,C=US,ST=TX,L=Austin,O=Inline Corp,OU=Dev Team
`

	tmpFile, err := os.CreateTemp("", "test-inline-*.cnf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	pc, err := LoadProfileConfig(tmpFile.Name(), true)
	if err != nil {
		t.Fatalf("Failed to load profile config: %v", err)
	}

	profile := pc.GetProfile("pqc")
	if profile == nil {
		t.Fatal("PQC profile should not be nil")
	}

	// Test inline parsing
	if profile.SubjectCommonName != "Inline Test" {
		t.Errorf("Expected SubjectCommonName 'Inline Test', got '%s'", profile.SubjectCommonName)
	}
	if profile.SubjectCountry != "US" {
		t.Errorf("Expected SubjectCountry 'US', got '%s'", profile.SubjectCountry)
	}
	if profile.SubjectProvince != "TX" {
		t.Errorf("Expected SubjectProvince 'TX', got '%s'", profile.SubjectProvince)
	}
	if profile.SubjectLocality != "Austin" {
		t.Errorf("Expected SubjectLocality 'Austin', got '%s'", profile.SubjectLocality)
	}
	if profile.SubjectOrganization != "Inline Corp" {
		t.Errorf("Expected SubjectOrganization 'Inline Corp', got '%s'", profile.SubjectOrganization)
	}
	if profile.SubjectOrganizationalUnit != "Dev Team" {
		t.Errorf("Expected SubjectOrganizationalUnit 'Dev Team', got '%s'", profile.SubjectOrganizationalUnit)
	}
}

// TestPQCProfileSubjectParsingIndividualFields tests parsing individual subject fields
func TestPQCProfileSubjectParsingIndividualFields(t *testing.T) {
	configContent := `[pqc]
url = https://ztpki-staging.venafi.com/api/v2
hawk-id = test-hawk-id
hawk-api = test-hawk-secret
policy = test-policy-id
subject-country = DE
subject-province = Bavaria
subject-locality = Munich
subject-organization = Individual Corp
subject-organizational-unit = Security
subject-common-name = Individual Test
`

	tmpFile, err := os.CreateTemp("", "test-individual-*.cnf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	pc, err := LoadProfileConfig(tmpFile.Name(), true)
	if err != nil {
		t.Fatalf("Failed to load profile config: %v", err)
	}

	profile := pc.GetProfile("pqc")
	if profile == nil {
		t.Fatal("PQC profile should not be nil")
	}

	// Test individual field parsing
	if profile.SubjectCommonName != "Individual Test" {
		t.Errorf("Expected SubjectCommonName 'Individual Test', got '%s'", profile.SubjectCommonName)
	}
	if profile.SubjectCountry != "DE" {
		t.Errorf("Expected SubjectCountry 'DE', got '%s'", profile.SubjectCountry)
	}
	if profile.SubjectProvince != "Bavaria" {
		t.Errorf("Expected SubjectProvince 'Bavaria', got '%s'", profile.SubjectProvince)
	}
	if profile.SubjectLocality != "Munich" {
		t.Errorf("Expected SubjectLocality 'Munich', got '%s'", profile.SubjectLocality)
	}
	if profile.SubjectOrganization != "Individual Corp" {
		t.Errorf("Expected SubjectOrganization 'Individual Corp', got '%s'", profile.SubjectOrganization)
	}
	if profile.SubjectOrganizationalUnit != "Security" {
		t.Errorf("Expected SubjectOrganizationalUnit 'Security', got '%s'", profile.SubjectOrganizationalUnit)
	}
}

// TestPQCProfileDefaults tests that PQC profile has correct defaults
func TestPQCProfileDefaults(t *testing.T) {
	configContent := `[pqc]
url = https://ztpki-staging.venafi.com/api/v2
hawk-id = test-hawk-id
hawk-api = test-hawk-secret
policy = test-policy-id
`

	tmpFile, err := os.CreateTemp("", "test-defaults-*.cnf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	pc, err := LoadProfileConfig(tmpFile.Name(), true)
	if err != nil {
		t.Fatalf("Failed to load profile config: %v", err)
	}

	profile := pc.GetProfile("pqc")
	if profile == nil {
		t.Fatal("PQC profile should not be nil")
	}

	// Test defaults
	if !profile.Cleanup {
		t.Error("Expected Cleanup default to be true")
	}
	if profile.SubjectCountry != "" {
		t.Errorf("Expected SubjectCountry to be empty by default, got '%s'", profile.SubjectCountry)
	}
	if profile.SubjectProvince != "" {
		t.Errorf("Expected SubjectProvince to be empty by default, got '%s'", profile.SubjectProvince)
	}
	if profile.SubjectLocality != "" {
		t.Errorf("Expected SubjectLocality to be empty by default, got '%s'", profile.SubjectLocality)
	}
	if profile.SubjectOrganization != "" {
		t.Errorf("Expected SubjectOrganization to be empty by default, got '%s'", profile.SubjectOrganization)
	}
	if profile.SubjectOrganizationalUnit != "" {
		t.Errorf("Expected SubjectOrganizationalUnit to be empty by default, got '%s'", profile.SubjectOrganizationalUnit)
	}
	if profile.SubjectCommonName != "" {
		t.Errorf("Expected SubjectCommonName to be empty by default, got '%s'", profile.SubjectCommonName)
	}
}

// TestCreateExampleProfileConfigPQC tests that the example config includes PQC settings
func TestCreateExampleProfileConfigPQC(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-example-*.cnf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Create example config
	err = CreateExampleProfileConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create example config: %v", err)
	}

	// Read the generated file
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read example config: %v", err)
	}

	contentStr := string(content)

	// Test that PQC section exists
	if !strings.Contains(contentStr, "[pqc]") {
		t.Error("Example config should contain [pqc] section")
	}

	// Test PQC-specific settings
	requiredPQCSettings := []string{
		"pqc-algorithm = MLDSA44",
		"legacy-alg-names = true",
		"openssl-path = ./openssl",
		"temp-dir = .",
		"cleanup = false",
		"subject = {",
		"common_name = PQC Certificate",
		"country = US",
		"state = Michigan",
		"locality = Detroit",
		"organization = OmniCorp",
		"organizational_unit = Cybernetics",
	}

	for _, setting := range requiredPQCSettings {
		if !strings.Contains(contentStr, setting) {
			t.Errorf("Example config should contain '%s'", setting)
		}
	}
}

// TestSetSubjectField tests the setSubjectField function
func TestSetSubjectField(t *testing.T) {
	profile := &Profile{}

	testCases := []struct {
		key      string
		value    string
		expected func(*Profile) string
	}{
		{"cn", "Test CN", func(p *Profile) string { return p.SubjectCommonName }},
		{"common_name", "Test Common Name", func(p *Profile) string { return p.SubjectCommonName }},
		{"c", "US", func(p *Profile) string { return p.SubjectCountry }},
		{"country", "Germany", func(p *Profile) string { return p.SubjectCountry }},
		{"st", "Texas", func(p *Profile) string { return p.SubjectProvince }},
		{"state", "California", func(p *Profile) string { return p.SubjectProvince }},
		{"province", "Ontario", func(p *Profile) string { return p.SubjectProvince }},
		{"l", "Austin", func(p *Profile) string { return p.SubjectLocality }},
		{"locality", "San Francisco", func(p *Profile) string { return p.SubjectLocality }},
		{"o", "Test Org", func(p *Profile) string { return p.SubjectOrganization }},
		{"organization", "Test Corporation", func(p *Profile) string { return p.SubjectOrganization }},
		{"ou", "Test OU", func(p *Profile) string { return p.SubjectOrganizationalUnit }},
		{"organizational_unit", "Test Department", func(p *Profile) string { return p.SubjectOrganizationalUnit }},
	}

	for _, tc := range testCases {
		t.Run(tc.key+"_"+tc.value, func(t *testing.T) {
			setSubjectField(profile, tc.key, tc.value)
			if actual := tc.expected(profile); actual != tc.value {
				t.Errorf("Expected '%s', got '%s'", tc.value, actual)
			}
		})
	}
}

// TestParseSubjectContent tests the parseSubjectContent function
func TestParseSubjectContent(t *testing.T) {
	profile := &Profile{}

	testCases := []struct {
		name     string
		content  string
		expected map[string]string
	}{
		{
			name: "Multi-line format",
			content: `{
    common_name = Multi Test
    country = FR
    state = Ile-de-France
    locality = Paris
    organization = Multi Corp
    organizational_unit = Engineering
}`,
			expected: map[string]string{
				"common_name":         "Multi Test",
				"country":             "FR",
				"state":               "Ile-de-France",
				"locality":            "Paris",
				"organization":        "Multi Corp",
				"organizational_unit": "Engineering",
			},
		},
		{
			name:    "Single line format",
			content: "{common_name = Single Test, country = UK}",
			expected: map[string]string{
				"common_name": "Single Test",
				"country":     "UK",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset profile
			profile = &Profile{}
			
			parseSubjectContent(profile, tc.content)

			// Check expected values
			for key, expectedValue := range tc.expected {
				var actualValue string
				switch key {
				case "common_name":
					actualValue = profile.SubjectCommonName
				case "country":
					actualValue = profile.SubjectCountry
				case "state":
					actualValue = profile.SubjectProvince
				case "locality":
					actualValue = profile.SubjectLocality
				case "organization":
					actualValue = profile.SubjectOrganization
				case "organizational_unit":
					actualValue = profile.SubjectOrganizationalUnit
				}

				if actualValue != expectedValue {
					t.Errorf("Expected %s='%s', got '%s'", key, expectedValue, actualValue)
				}
			}
		})
	}
}
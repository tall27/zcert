package config

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"zcert/internal/validity"
)

// ValidityPeriod represents a parsed validity period
type ValidityPeriod struct {
	Years  int
	Months int
	Days   int
}

// Profile represents a configuration profile
type Profile struct {
	Name               string
	URL                string
	KeyID              string
	Secret             string
	Account            string
	Algo               string
	Format             string
	PolicyID           string
	P12Pass            string
	KeySize            int
	KeyType            string
	Validity           int
	ValidityString     string // Store original validity string from config
	OutDir             string
	NoKeyOut           bool
	Chain              bool
	NoCleanup          bool
	PQCAlgorithm       string
	LegacyAlgNames     bool
	LegacyPQCAlgorithm string
	OpenSSLPath        string
	TempDir            string
	ProviderPath       string // Path to OpenSSL providers (for -provider-path)
	// PQC-specific settings
	Cleanup bool // Controls cleanup of openssl.cnf file (default: true)
	// Subject defaults for OpenSSL config generation
	SubjectCountry            string
	SubjectProvince           string
	SubjectLocality           string
	SubjectOrganization       string
	SubjectOrganizationalUnit string
	SubjectCommonName         string
}

// ProfileConfig manages multiple profiles
type ProfileConfig struct {
	Profiles map[string]*Profile
	Default  *Profile
}

// LoadProfileConfig loads profiles from an INI-style configuration file
func LoadProfileConfig(filename string, preferPQC bool) (*ProfileConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file %s: %w", filename, err)
	}
	defer file.Close()

	config := &ProfileConfig{
		Profiles: make(map[string]*Profile),
	}

	scanner := bufio.NewScanner(file)
	var currentProfile *Profile
	var currentSection string
	var inSubjectSection bool
	var subjectContent strings.Builder

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments (but not when in subject section)
		if !inSubjectSection && (line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";")) {
			continue
		}

		// Handle multi-line subject section
		if inSubjectSection {
			subjectContent.WriteString(line + "\n")
			if strings.Contains(line, "}") {
				// End of subject section
				parseSubjectContent(currentProfile, subjectContent.String())
				inSubjectSection = false
				subjectContent.Reset()
			}
			continue
		}

		// Check for section headers [ProfileName]
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.TrimSpace(line[1 : len(line)-1])

			// Create new profile
			currentProfile = &Profile{
				Name:    currentSection,
				Algo:    "sha256", // Default algorithm
				Format:  "pem",    // Default format
				KeySize: 2048,     // Default key size
				KeyType: "rsa",    // Default key type
				Cleanup: true,     // Default cleanup for openssl.cnf
			}

			config.Profiles[currentSection] = currentProfile

			// Set as default if it's the Default section
			if strings.ToLower(currentSection) == "default" {
				config.Default = currentProfile
			}
			continue
		}

		// Parse key=value pairs
		if currentProfile != nil && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// Remove comments (everything after #)
			if commentIndex := strings.Index(value, "#"); commentIndex != -1 {
				value = strings.TrimSpace(value[:commentIndex])
			}

			// Remove quotes if present
			if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
				(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
				value = value[1 : len(value)-1]
			}

			// Expand environment variables in ${VAR} format
			value = expandEnvVars(value)

			// Parse configuration values
			switch strings.ToLower(key) {
			case "url", "base-url":
				currentProfile.URL = value
			case "key-id", "hawk-id":
				currentProfile.KeyID = value
			case "secret", "hawk-key", "hawk-api":
				currentProfile.Secret = value
			case "account", "account-id":
				currentProfile.Account = value
			case "format":
				currentProfile.Format = value
			case "policy", "policy-id":
				currentProfile.PolicyID = value
			case "p12-password", "p12-pass":
				currentProfile.P12Pass = value
			case "key-size":
				if size, err := strconv.Atoi(value); err == nil {
					currentProfile.KeySize = size
				}
			case "key-type":
				currentProfile.KeyType = value
			case "validity":
				// Store the original validity string for consistent parsing later
				currentProfile.ValidityString = value
				if days, err := strconv.Atoi(value); err == nil {
					currentProfile.Validity = days
				} else {
					if vp, err := validity.ParseValidityPeriod(value); err == nil {
						totalDays := vp.ToTotalDays()
						currentProfile.Validity = totalDays
					} else {
						// Silently ignore invalid validity in config - will be handled later
					}
				}
			case "output-dir":
				currentProfile.OutDir = value
			case "no-key-output":
				currentProfile.NoKeyOut = strings.ToLower(value) == "true"
			case "chain":
				currentProfile.Chain = strings.ToLower(value) == "true"
			case "no-cleanup":
				currentProfile.NoCleanup = strings.ToLower(value) == "true"
			case "pqc-algorithm":
				currentProfile.PQCAlgorithm = value
			case "legacy-alg-names":
				currentProfile.LegacyAlgNames = strings.ToLower(value) == "true"
			case "legacy-pqc-algorithm":
				currentProfile.LegacyPQCAlgorithm = value
			case "openssl-path":
				currentProfile.OpenSSLPath = value
			case "temp-dir":
				currentProfile.TempDir = value
			case "cleanup":
				currentProfile.Cleanup = strings.ToLower(value) == "true"
			case "subject-country", "country":
				currentProfile.SubjectCountry = value
			case "subject-province", "province", "state":
				currentProfile.SubjectProvince = value
			case "subject-locality", "locality":
				currentProfile.SubjectLocality = value
			case "subject-organization", "organization":
				currentProfile.SubjectOrganization = value
			case "subject-organizational-unit", "organizational-unit", "ou":
				currentProfile.SubjectOrganizationalUnit = value
			case "subject-common-name", "common-name":
				currentProfile.SubjectCommonName = value
			case "subject":
				// Check if this is a multi-line subject section starting with {
				if strings.Contains(value, "{") {
					inSubjectSection = true
					subjectContent.WriteString(value + "\n")
					if strings.Contains(value, "}") {
						// Single line subject section
						parseSubjectContent(currentProfile, value)
						inSubjectSection = false
						subjectContent.Reset()
					}
				} else {
					// Parse single-line subject format
					parseSubjectSection(currentProfile, value)
				}
			case "provider-path":
				currentProfile.ProviderPath = value
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Prefer [pqc] as default if requested and it exists
	if preferPQC {
		if pqc, ok := config.Profiles["pqc"]; ok {
			config.Default = pqc
		}
	}

	// Ensure we have a default profile
	if config.Default == nil && len(config.Profiles) > 0 {
		// Use the first profile as default if no [Default] section exists
		for _, profile := range config.Profiles {
			config.Default = profile
			break
		}
	}

	return config, nil
}

// expandEnvVars expands environment variables in ${VAR} format
func expandEnvVars(value string) string {
	re := regexp.MustCompile(`\$\{([^}]+)\}`)
	return re.ReplaceAllStringFunc(value, func(match string) string {
		// Extract variable name from ${VAR}
		varName := match[2 : len(match)-1]
		if envValue := os.Getenv(varName); envValue != "" {
			return envValue
		}
		return match // Return original if no env var found
	})
}

// parseSubjectSection parses subject configuration from various formats
func parseSubjectSection(profile *Profile, value string) {
	// Handle multi-line JSON-like format
	if strings.Contains(value, "{") {
		// This will be handled by the multi-line parser
		return
	}

	// Handle inline format: "CN=test,C=US,ST=CA,L=SF,O=Corp,OU=IT"
	if strings.Contains(value, "=") {
		pairs := strings.Split(value, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) == 2 {
				key := strings.ToLower(strings.TrimSpace(kv[0]))
				val := strings.TrimSpace(kv[1])
				setSubjectField(profile, key, val)
			}
		}
	}
}

// setSubjectField sets a subject field on the profile
func setSubjectField(profile *Profile, key, value string) {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "cn", "common_name":
		profile.SubjectCommonName = value
	case "c", "country":
		profile.SubjectCountry = value
	case "st", "state", "province":
		profile.SubjectProvince = value
	case "l", "locality":
		profile.SubjectLocality = value
	case "o", "organization":
		profile.SubjectOrganization = value
	case "ou", "organizational_unit":
		profile.SubjectOrganizationalUnit = value
	}
}

// parseSubjectContent parses the multi-line JSON-like subject content
func parseSubjectContent(profile *Profile, content string) {
	// Remove braces and clean up the content
	content = strings.ReplaceAll(content, "{", "")
	content = strings.ReplaceAll(content, "}", "")

	// Determine if this is single-line (comma-separated) or multi-line format
	var entries []string
	if strings.Contains(content, "\n") {
		// Multi-line format: split by newlines
		entries = strings.Split(content, "\n")
	} else {
		// Single-line format: split by commas
		entries = strings.Split(content, ",")
	}

	// Parse each key-value pair
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// Parse key = value format
		if strings.Contains(entry, "=") {
			kv := strings.SplitN(entry, "=", 2)
			if len(kv) == 2 {
				key := strings.TrimSpace(kv[0])
				value := strings.TrimSpace(kv[1])
				setSubjectField(profile, key, value)
			}
		}
	}
}

// GetProfile returns a specific profile by name
func (pc *ProfileConfig) GetProfile(name string) *Profile {
	if name == "" && pc.Default != nil {
		return pc.Default
	}

	if profile, exists := pc.Profiles[name]; exists {
		return profile
	}

	// Case-insensitive lookup
	for profileName, profile := range pc.Profiles {
		if strings.EqualFold(profileName, name) {
			return profile
		}
	}

	return nil
}

// ListProfiles returns all available profile names
func (pc *ProfileConfig) ListProfiles() []string {
	profiles := make([]string, 0, len(pc.Profiles))
	for name := range pc.Profiles {
		profiles = append(profiles, name)
	}
	return profiles
}

// CreateExampleProfileConfig creates an example profile configuration file
func CreateExampleProfileConfig(filename string) error {
	content := `# zcert Profile Configuration File
# This file supports multiple profiles with different ZTPKI settings
# Use: zcert enroll --config zcert.cnf --cn "mycert.com" 
#   or zcert search --config zcert.cnf --profile test --cn "mycert.com"

[Default]
# Default profile used when no --profile is specified
url = https://ztpki.venafi.com/api/v2
hawk-id = your-default-hawk-id
hawk-api = your-default-hawk-api
account = your-account-id
format = pem
policy = PolicyID
key-size = 2048
key-type = rsa
validity = 365  # Days (can use 365, 30d, 6m, 1y, etc.)
chain = true

[test]
# Profile for testing environment
url = https://ztpki.venafi.com/api/v2
hawk-id = test-hawk-id
hawk-api = test-hawk-api
format = pem
policy = PolicyID
key-size = 2048
key-type = rsa
validity = 90  # Days (can use 90, 90d, 3m, etc.)
chain = false
extendedKeyUsage = serverAuth, clientAuth
certificatePolicies = 1.2.3.4.5, 1.2.3.4.6

[prod]
# Profile for production environment
url = https://ztpki.venafi.com/api/v2
hawk-id = prod-hawk-id
hawk-api = prod-hawk-api
format = pem
policy = PolicyID
key-size = 4096
key-type = rsa
validity = 365  # Days (can use 365, 365d, 1y, etc.)
chain = true

[pqc]
url = https://ztpki-staging.venafi.com/api/v2
hawk-id = your-hawk-id
hawk-api = your-hawk-secret
policy = policy-id
validity = 15
chain = true 
pqc-algorithm = MLDSA44
legacy-alg-names = true
# Specify only the directory, not the file name:
openssl-path = ./   # Directory containing OpenSSL executable (optional)
provider-path = ./   # Directory containing oqsprovider library (optional)
temp-dir = .
cleanup = false
# Following are pqc specific settings
subject = {
    common_name = PQC Certificate
    country = US
    state = Michigan
    locality = Detroit
    organization = OmniCorp
    organizational_unit = Cybernetics
}
`
	return os.WriteFile(filename, []byte(content), 0600) // Restrict to owner only
}

// Restore MergeProfileWithFlags for compatibility with other commands
func MergeProfileWithFlags(profile *Profile, flagURL, flagKeyID, flagSecret, flagFormat, flagPolicy, flagP12Pass string, flagKeySize int, flagKeyType string) *Profile {
	// Start with environment variables as base (lowest priority)
	envProfile := &Profile{
		Algo:    "sha256",
		Format:  "pem",
		KeySize: 2048,
		KeyType: "rsa",
	}

	// Apply environment variables
	if envURL := os.Getenv("ZTPKI_URL"); envURL != "" {
		envProfile.URL = envURL
	}
	if envKeyID := os.Getenv("ZTPKI_HAWK_ID"); envKeyID != "" {
		envProfile.KeyID = envKeyID
	}
	if envSecret := os.Getenv("ZTPKI_HAWK_SECRET"); envSecret != "" {
		envProfile.Secret = envSecret
	}
	// Don't apply ZTPKI_POLICY_ID here - handle it with proper priority later

	// Override with configuration file values (medium priority)
	merged := *envProfile
	if profile != nil {
		if profile.URL != "" {
			merged.URL = profile.URL
		}
		if profile.KeyID != "" {
			merged.KeyID = profile.KeyID
		}
		if profile.Secret != "" {
			merged.Secret = profile.Secret
		}
		if profile.PolicyID != "" {
			merged.PolicyID = profile.PolicyID
		}
		if profile.Format != "" {
			merged.Format = profile.Format
		}
		if profile.P12Pass != "" {
			merged.P12Pass = profile.P12Pass
		}
		if profile.KeySize > 0 {
			merged.KeySize = profile.KeySize
		}
		if profile.KeyType != "" {
			merged.KeyType = profile.KeyType
		}
		if profile.OutDir != "" {
			merged.OutDir = profile.OutDir
		}
		merged.NoKeyOut = profile.NoKeyOut
		merged.Chain = profile.Chain
		if profile.Validity > 0 {
			merged.Validity = profile.Validity
		}
		if profile.ValidityString != "" {
			merged.ValidityString = profile.ValidityString
		}
		merged.NoCleanup = profile.NoCleanup
	}

	// Override with command-line flags (highest priority)
	if flagURL != "" {
		merged.URL = flagURL
	}
	if flagKeyID != "" {
		merged.KeyID = flagKeyID
	}
	if flagSecret != "" {
		merged.Secret = flagSecret
	}
	if flagPolicy != "" {
		merged.PolicyID = flagPolicy
	}
	if flagFormat != "" {
		merged.Format = flagFormat
	}
	if flagP12Pass != "" {
		merged.P12Pass = flagP12Pass
	}
	if flagKeySize > 0 {
		merged.KeySize = flagKeySize
	}
	if flagKeyType != "" {
		merged.KeyType = flagKeyType
	}

	// Always ensure sha256 is used
	merged.Algo = "sha256"

	return &merged
}

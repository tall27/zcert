package config

import (
        "bufio"
        "fmt"
        "os"
        "regexp"
        "strconv"
        "strings"
)

// ValidityPeriod represents a parsed validity period
type ValidityPeriod struct {
        Years  int
        Months int
        Days   int
}

// parseValidityPeriodSimple parses validity period strings like "5d", "30", "1y6m"
func parseValidityPeriodSimple(input string) (*ValidityPeriod, error) {
        if input == "" {
                return nil, fmt.Errorf("empty validity period")
        }

        // If it's just a number, treat as days
        if days, err := strconv.Atoi(input); err == nil {
                return &ValidityPeriod{Days: days}, nil
        }

        // Parse with suffixes
        result := &ValidityPeriod{}
        
        // Regular expressions for different components
        yearRegex := regexp.MustCompile(`(\d+)y`)
        monthRegex := regexp.MustCompile(`(\d+)m`)
        dayRegex := regexp.MustCompile(`(\d+)d`)

        // Extract years
        if yearMatch := yearRegex.FindStringSubmatch(input); yearMatch != nil {
                if years, err := strconv.Atoi(yearMatch[1]); err == nil {
                        result.Years = years
                }
        }

        // Extract months
        if monthMatch := monthRegex.FindStringSubmatch(input); monthMatch != nil {
                if months, err := strconv.Atoi(monthMatch[1]); err == nil {
                        result.Months = months
                }
        }

        // Extract days
        if dayMatch := dayRegex.FindStringSubmatch(input); dayMatch != nil {
                if days, err := strconv.Atoi(dayMatch[1]); err == nil {
                        result.Days = days
                }
        }

        // Validate that we found at least one component
        if result.Years == 0 && result.Months == 0 && result.Days == 0 {
                return nil, fmt.Errorf("invalid validity format: %s (expected formats: 30d, 6m, 1y, 30d6m, 1y6m, or plain number for days)", input)
        }

        return result, nil
}

// Profile represents a configuration profile
type Profile struct {
        Name      string
        URL       string
        KeyID     string
        Secret    string
        Account   string
        Algo      string
        Format    string
        PolicyID  string
        P12Pass   string
        KeySize   int
        KeyType   string
        Validity  int
        OutDir    string
        NoKeyOut  bool
        Chain     bool
        NoCleanup   bool
        PQCAlgorithm string
        LegacyAlgNames bool
        LegacyPQCAlgorithm string
        OpenSSLPath string
        TempDir    string
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

        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                
                // Skip empty lines and comments
                if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
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
                                if days, err := strconv.Atoi(value); err == nil {
                                        currentProfile.Validity = days
                                } else {
                                        if validityPeriod, err := parseValidityPeriodSimple(value); err == nil {
                                                totalDays := validityPeriod.Years*365 + validityPeriod.Months*30 + validityPeriod.Days
                                                currentProfile.Validity = totalDays
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
default_key_type = MLDSA44
openssl_path = "./openssl.exe"
temp_dir = "."
cleanonsuccess = false
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

// MergeProfileWithFlags merges profile settings with command-line flags and environment variables
// Priority: CLI Parameters > Configuration File Variables > OS Environment Variables
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

// LoadConfig loads configuration from either YAML or CNF format based on file extension
func LoadConfig(filename string) (*ProfileConfig, error) {
        if filename == "" {
                return nil, fmt.Errorf("no configuration file specified")
        }

        // Load CNF/INI format configuration files only
        // YAML playbook files are handled separately in yaml.go
        return LoadProfileConfig(filename, false)
}
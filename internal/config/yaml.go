package config

import (
        "fmt"
        "os"
        "path/filepath"
        "gopkg.in/yaml.v3"
)

// YAMLConfig represents the YAML configuration structure
type YAMLConfig struct {
        Profiles map[string]YAMLProfile `yaml:"profiles"`
}

// YAMLProfile represents a single profile in YAML format
type YAMLProfile struct {
        BaseURL           string `yaml:"base_url"`
        HawkID            string `yaml:"hawk_id"`
        HawkKey           string `yaml:"hawk_key"`
        DefaultKeySize    int    `yaml:"default_key_size"`
        DefaultKeyType    string `yaml:"default_key_type"`
        DefaultFormat     string `yaml:"default_format"`
        DefaultPolicyID   string `yaml:"default_policy_id"`
        DefaultAlgorithm  string `yaml:"default_algorithm"`
        P12Password       string `yaml:"p12_password"`
        OutputDirectory   string `yaml:"output_directory"`
        NoKeyOutput       bool   `yaml:"no_key_output"`
        IncludeChain      bool   `yaml:"include_chain"`
        
        // Subject defaults
        DefaultCountry    []string `yaml:"default_country"`
        DefaultProvince   []string `yaml:"default_province"`
        DefaultLocality   []string `yaml:"default_locality"`
        DefaultOrg        []string `yaml:"default_org"`
        DefaultOrgUnit    []string `yaml:"default_org_unit"`
        
        // Behavior settings
        PollIntervalSeconds int  `yaml:"poll_interval_seconds"`
        PollTimeoutSeconds  int  `yaml:"poll_timeout_seconds"`
        Verbose             bool `yaml:"verbose"`
        ForceRevoke         bool `yaml:"force_revoke"`
}

// LoadYAMLConfig loads configuration from a YAML file
func LoadYAMLConfig(filename string) (*ProfileConfig, error) {
        file, err := os.Open(filename)
        if err != nil {
                return nil, fmt.Errorf("failed to open YAML config file %s: %w", filename, err)
        }
        defer file.Close()

        var yamlConfig YAMLConfig
        decoder := yaml.NewDecoder(file)
        if err := decoder.Decode(&yamlConfig); err != nil {
                return nil, fmt.Errorf("failed to parse YAML config: %w", err)
        }

        // Convert YAML config to ProfileConfig
        config := &ProfileConfig{
                Profiles: make(map[string]*Profile),
        }

        for name, yamlProfile := range yamlConfig.Profiles {
                profile := &Profile{
                        Name:     name,
                        URL:      yamlProfile.BaseURL,
                        KeyID:    yamlProfile.HawkID,
                        Secret:   yamlProfile.HawkKey,
                        Algo:     yamlProfile.DefaultAlgorithm,
                        Format:   yamlProfile.DefaultFormat,
                        PolicyID: yamlProfile.DefaultPolicyID,
                        P12Pass:  yamlProfile.P12Password,
                        KeySize:  yamlProfile.DefaultKeySize,
                        KeyType:  yamlProfile.DefaultKeyType,
                        OutDir:   yamlProfile.OutputDirectory,
                        NoKeyOut: yamlProfile.NoKeyOutput,
                        Chain:    yamlProfile.IncludeChain,
                }

                // Set defaults if not specified
                if profile.Algo == "" {
                        profile.Algo = "sha256"
                }
                if profile.Format == "" {
                        profile.Format = "pem"
                }
                if profile.KeySize == 0 {
                        profile.KeySize = 2048
                }
                if profile.KeyType == "" {
                        profile.KeyType = "rsa"
                }

                config.Profiles[name] = profile

                // Set as default if it's the Default profile
                if name == "Default" || name == "default" {
                        config.Default = profile
                }
        }

        // Ensure we have a default profile
        if config.Default == nil && len(config.Profiles) > 0 {
                for _, profile := range config.Profiles {
                        config.Default = profile
                        break
                }
        }

        return config, nil
}

// Playbook represents a YAML playbook configuration
type Playbook struct {
        Name    string          `yaml:"name"`
        Version string          `yaml:"version"`
        Tasks   []PlaybookTask  `yaml:"tasks"`
}

// PlaybookTask represents a single task in a playbook
type PlaybookTask struct {
        Name            string       `yaml:"name"`
        Action          string       `yaml:"action"`
        CommonName      string       `yaml:"common_name"`
        PolicyID        string       `yaml:"policy_id"`
        CertificateID   string       `yaml:"certificate_id"`
        OutputFile      string       `yaml:"output_file"`
        KeySize         int          `yaml:"key_size"`
        KeyType         string       `yaml:"key_type"`
        Subject         *SubjectInfo `yaml:"subject"`
        Limit           int          `yaml:"limit"`
        ContinueOnError bool         `yaml:"continue_on_error"`
}

// SubjectInfo represents certificate subject information
type SubjectInfo struct {
        Country      []string `yaml:"country"`
        Province     []string `yaml:"province"`
        Locality     []string `yaml:"locality"`
        Organization []string `yaml:"organization"`
        OrgUnit      []string `yaml:"organizational_unit"`
}

// LoadPlaybook loads a YAML playbook from file
func LoadPlaybook(filename string) (*Playbook, error) {
        file, err := os.Open(filename)
        if err != nil {
                return nil, fmt.Errorf("failed to open playbook file %s: %w", filename, err)
        }
        defer file.Close()

        var playbook Playbook
        decoder := yaml.NewDecoder(file)
        if err := decoder.Decode(&playbook); err != nil {
                return nil, fmt.Errorf("failed to parse playbook YAML: %w", err)
        }

        // Validate playbook
        if playbook.Name == "" {
                playbook.Name = filepath.Base(filename)
        }
        
        if len(playbook.Tasks) == 0 {
                return nil, fmt.Errorf("playbook must contain at least one task")
        }

        // Validate each task
        for i, task := range playbook.Tasks {
                if task.Name == "" {
                        return nil, fmt.Errorf("task %d must have a name", i+1)
                }
                if task.Action == "" {
                        return nil, fmt.Errorf("task %d (%s) must have an action", i+1, task.Name)
                }
        }

        return &playbook, nil
}

// CreateExampleYAMLConfig creates an example YAML configuration file
func CreateExampleYAMLConfig(filename string) error {
        content := `# zcert YAML Configuration File
# This file supports multiple profiles with different ZTPKI settings
# Usage: zcert --config zcert.yaml --profile <profile_name> enroll --cn example.com

profiles:
  Default:
    base_url: "https://your-ztpki-instance.com/api/v2"
    hawk_id: "your-hawk-id-here"
    hawk_key: "your-hawk-key-here"
    default_key_size: 2048
    default_key_type: "rsa"
    default_format: "pem"
    default_policy_id: ""
    default_algorithm: "sha256"
    output_directory: "./certificates"
    no_key_output: false
    include_chain: true
    
    # Default Subject Information
    default_country: ["US"]
    default_province: ["CA"]
    default_locality: ["San Francisco"]
    default_org: ["Your Organization"]
    default_org_unit: ["IT Department"]
    
    # Behavior Settings
    poll_interval_seconds: 2
    poll_timeout_seconds: 300
    verbose: false
    force_revoke: false

  staging:
    base_url: "https://your-ztpki-staging.com/api/v2"
    hawk_id: "your-staging-hawk-id"
    hawk_key: "your-staging-hawk-key"
    default_key_size: 2048
    default_key_type: "rsa"
    default_format: "pem"
    default_policy_id: ""
    default_algorithm: "sha256"
    output_directory: "./certificates"
    include_chain: true

  production:
    base_url: "https://your-ztpki-production.com/api/v2"
    hawk_id: "your-prod-hawk-id"
    hawk_key: "your-prod-hawk-key"
    default_key_size: 4096
    default_key_type: "rsa"
    default_format: "pem"
    default_policy_id: ""
    default_algorithm: "sha256"
    output_directory: "./certificates"
    include_chain: true

  p12:
    base_url: "https://your-ztpki-instance.com/api/v2"
    hawk_id: "your-hawk-id-here"
    hawk_key: "your-hawk-key-here"
    default_key_size: 2048
    default_key_type: "rsa"
    default_format: "p12"
    default_policy_id: ""
    p12_password: "changeme"
    output_directory: "./certificates"
    include_chain: true
`

        return os.WriteFile(filename, []byte(content), 0600) // Restrict to owner only
}

// CreateExamplePlaybookConfig creates an example playbook YAML configuration file
func CreateExamplePlaybookConfig(filename string) error {
        content := `# zcert Playbook Configuration File
# This file defines a series of certificate operations to be executed
# Usage: zcert run --file playbook.yaml

name: "Certificate Management Playbook"
version: "1.0"

tasks:
  # Task 1: Enroll a new web server certificate
  - name: "Enroll Web Server Certificate"
    action: "enroll"
    common_name: "web.example.com"
    policy_id: "WebServerPolicy"
    key_size: 2048
    key_type: "rsa"
    output_file: "./certs/web-server"
    subject:
      country: ["US"]
      province: ["CA"]
      locality: ["San Francisco"]
      organization: ["Example Corp"]
      organizational_unit: ["IT Department"]
    continue_on_error: false

  # Task 2: Search for existing certificates
  - name: "Search Existing Certificates"
    action: "search"
    common_name: "*.example.com"
    limit: 10
    output_file: "./reports/cert-search-results.txt"
    continue_on_error: true

  # Task 3: Retrieve a specific certificate by ID
  - name: "Retrieve Production Certificate"
    action: "retrieve"
    certificate_id: "cert-12345-abcdef"
    output_file: "./certs/production-cert.pem"
    continue_on_error: false

  # Task 4: Enroll API server certificate
  - name: "Enroll API Certificate"
    action: "enroll"
    common_name: "api.example.com"
    policy_id: "APIServerPolicy"
    key_size: 4096
    key_type: "rsa"
    output_file: "./certs/api-server"
    subject:
      country: ["US"]
      province: ["CA"]
      locality: ["San Francisco"]
      organization: ["Example Corp"]
      organizational_unit: ["API Team"]
    continue_on_error: true

# Configuration Notes:
# - Set environment variables before running:
#   export ZTPKI_URL="https://your-ztpki-instance.com/api/v2"
#   export ZTPKI_HAWK_ID="your-hawk-id"
#   export ZTPKI_HAWK_SECRET="your-hawk-secret"
#
# - Available actions: enroll, retrieve, search, revoke
# - Use --dry-run flag to preview operations without executing
# - Set continue_on_error: true to continue playbook execution if a task fails
`

        return os.WriteFile(filename, []byte(content), 0600) // Restrict to owner only
}


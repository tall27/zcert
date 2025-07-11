package config

import (
        "fmt"
        "os"
        "path/filepath"
        "gopkg.in/yaml.v3"
)

// YAML playbook structures and functions only
// Profile configuration loading is handled in profiles.go

// Playbook represents a YAML playbook configuration
type Playbook struct {
        Name    string          `yaml:"name"`
        Version string          `yaml:"version"`
        Tasks   []PlaybookTask  `yaml:"tasks"`
}

// CertificatePlaybook represents a certificate management playbook
type CertificatePlaybook struct {
        Config           PlaybookConfig      `yaml:"config"`
        CertificateTasks []CertificateTask   `yaml:"certificateTasks"`
}

// PlaybookConfig represents the configuration section
type PlaybookConfig struct {
        Connection ConnectionConfig `yaml:"connection"`
}

// ConnectionConfig represents connection credentials
type ConnectionConfig struct {
        Credentials CredentialsConfig `yaml:"credentials"`
}

// CredentialsConfig represents authentication credentials
type CredentialsConfig struct {
        HawkID   string `yaml:"hawk-id"`
        HawkAPI  string `yaml:"hawk-api"`
        Platform string `yaml:"platform"`
}

// CertificateTask represents a certificate management task
type CertificateTask struct {
        Name                string                 `yaml:"name"`
        RenewBefore         string                 `yaml:"renewBefore"`
        CertificateLocation string                 `yaml:"certificateLocation,omitempty"`
        Request             CertificateRequest     `yaml:"request"`
        Installations       []CertificateInstall   `yaml:"installations"`
}

// CertificateRequest represents certificate request details
type CertificateRequest struct {
        CSR               string                 `yaml:"csr"`
        Subject           CertificateSubject     `yaml:"subject"`
        Policy            string                 `yaml:"policy"`
        SANs              *FlexibleSANs          `yaml:"sans,omitempty"`
        Validity          *ValidityConfig        `yaml:"validity,omitempty"`
        CustomFields      map[string]string      `yaml:"customFields,omitempty"`
        CustomExtensions  map[string]string      `yaml:"customExtensions,omitempty"`
        Comment           string                 `yaml:"comment,omitempty"`
        ExpiryEmails      []string               `yaml:"expiryEmails,omitempty"`
        ClearRemindersID  string                 `yaml:"clearRemindersCertificateId,omitempty"`
}

// CertificateSubject represents certificate subject information
type CertificateSubject struct {
        CommonName       string   `yaml:"commonName"`
        Country          string   `yaml:"country"`
        State            string   `yaml:"state"`
        Locality         string   `yaml:"locality"`
        Organization     string   `yaml:"organization"`
        OrgUnits         []string `yaml:"orgUnits"`
        DomainComponents []string `yaml:"domainComponents,omitempty"`
        Email            string   `yaml:"email,omitempty"`
}

// SubjectAltNames represents subject alternative names
type SubjectAltNames struct {
        DNS   []string `yaml:"dns,omitempty"`
        IP    []string `yaml:"ip,omitempty"`
        Email []string `yaml:"email,omitempty"`
        UPN   []string `yaml:"upn,omitempty"`
        URI   []string `yaml:"uri,omitempty"`
}

// FlexibleSANs handles both simple array and structured SAN formats
type FlexibleSANs struct {
        *SubjectAltNames
        SimpleList []string
}

// UnmarshalYAML implements custom unmarshaling for flexible SAN formats
func (f *FlexibleSANs) UnmarshalYAML(value *yaml.Node) error {
        // Try to unmarshal as a simple array first
        var simpleList []string
        if err := value.Decode(&simpleList); err == nil {
                f.SimpleList = simpleList
                f.SubjectAltNames = &SubjectAltNames{
                        DNS: simpleList, // Assume all entries are DNS names by default
                }
                return nil
        }
        
        // Fall back to structured format
        var sans SubjectAltNames
        if err := value.Decode(&sans); err != nil {
                return err
        }
        f.SubjectAltNames = &sans
        return nil
}

// ValidityConfig represents certificate validity period
type ValidityConfig struct {
        Years  int `yaml:"years"`
        Months int `yaml:"months"`
        Days   int `yaml:"days"`
}

// CertificateInstall represents certificate installation configuration
type CertificateInstall struct {
        Format            string `yaml:"format"`
        File              string `yaml:"file"`
        ChainFile         string `yaml:"chainFile,omitempty"`
        KeyFile           string `yaml:"keyFile,omitempty"`
        Password          string `yaml:"password,omitempty"`
        BackupExisting    bool   `yaml:"backupExisting,omitempty"`
        AfterInstallAction string `yaml:"afterInstallAction,omitempty"`
}

// PlaybookTask represents a single task in a playbook
type PlaybookTask struct {
        Name               string       `yaml:"name"`
        Action             string       `yaml:"action"`
        CommonName         string       `yaml:"common_name"`
        PolicyID           string       `yaml:"policy_id"`
        CertificateID      string       `yaml:"certificate_id"`
        OutputFile         string       `yaml:"output_file"`
        CertificateLocation string      `yaml:"certificate_location"`
        KeySize            int          `yaml:"key_size"`
        KeyType            string       `yaml:"key_type"`
        Subject            *SubjectInfo `yaml:"subject"`
        RenewBefore        string       `yaml:"renew_before"`
        BackupExisting     bool         `yaml:"backup_existing"`
        Limit              int          `yaml:"limit"`
        ContinueOnError    bool         `yaml:"continue_on_error"`
}

// SubjectInfo represents certificate subject information
type SubjectInfo struct {
        Country      []string `yaml:"country"`
        Province     []string `yaml:"province"`
        Locality     []string `yaml:"locality"`
        Organization []string `yaml:"organization"`
        OrgUnit      []string `yaml:"organizational_unit"`
}

// LoadPlaybook loads a YAML playbook from file and supports both formats
func LoadPlaybook(filename string) (*Playbook, error) {
        file, err := os.Open(filename)
        if err != nil {
                return nil, fmt.Errorf("failed to open playbook file %s: %w", filename, err)
        }
        defer file.Close()

        // First, try to load as certificate playbook format
        _, _ = file.Seek(0, 0)
        var certPlaybook CertificatePlaybook
        decoder := yaml.NewDecoder(file)
        if err := decoder.Decode(&certPlaybook); err == nil && len(certPlaybook.CertificateTasks) > 0 {
                // Convert certificate tasks to simple tasks for compatibility
                return convertCertificatePlaybook(&certPlaybook, filename)
        }

        // Fall back to simple playbook format
        _, _ = file.Seek(0, 0)
        var playbook Playbook
        decoder = yaml.NewDecoder(file)
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

// convertCertificatePlaybook converts a certificate playbook to a simple playbook format
func convertCertificatePlaybook(certPlaybook *CertificatePlaybook, filename string) (*Playbook, error) {
        playbook := &Playbook{
                Name:    "Certificate Management Playbook",
                Version: "1.0",
                Tasks:   make([]PlaybookTask, 0, len(certPlaybook.CertificateTasks)),
        }

        for i, certTask := range certPlaybook.CertificateTasks {
                // Convert certificate task to simple enrollment task
                task := PlaybookTask{
                        Name:        certTask.Name,
                        Action:      "enroll",
                        CommonName:  certTask.Request.Subject.CommonName,
                        PolicyID:    certTask.Request.Policy,
                        KeySize:     2048, // Default
                        KeyType:     "rsa", // Default
                        RenewBefore: certTask.RenewBefore,
                        Subject: &SubjectInfo{
                                Country:      []string{certTask.Request.Subject.Country},
                                Province:     []string{certTask.Request.Subject.State},
                                Locality:     []string{certTask.Request.Subject.Locality},
                                Organization: []string{certTask.Request.Subject.Organization},
                                OrgUnit:      certTask.Request.Subject.OrgUnits,
                        },
                        ContinueOnError: false,
                }

                // Set output file and backup settings from installations if available
                if len(certTask.Installations) > 0 {
                        task.OutputFile = certTask.Installations[0].File
                        task.BackupExisting = certTask.Installations[0].BackupExisting
                }
                
                // Set certificate location from task or use output file as default
                if certTask.CertificateLocation != "" {
                        task.CertificateLocation = certTask.CertificateLocation
                } else {
                        task.CertificateLocation = task.OutputFile
                }

                // Validate required fields
                if task.Name == "" {
                        return nil, fmt.Errorf("certificate task %d must have a name", i+1)
                }
                if task.CommonName == "" {
                        return nil, fmt.Errorf("certificate task %d (%s) must have a commonName", i+1, task.Name)
                }

                playbook.Tasks = append(playbook.Tasks, task)
        }

        if len(playbook.Tasks) == 0 {
                return nil, fmt.Errorf("playbook must contain at least one certificate task")
        }

        return playbook, nil
}



// CreateExamplePlaybookYAML creates an example playbook YAML file
func CreateExamplePlaybookYAML(filename string) error {
        content := `# zcert Playbook Configuration File
# This file defines certificate management workflows with automated deployment
# Usage: zcert run --file playbook.yaml

config:
  connection:
    credentials:
      hawk-id: '{{ZTPKI_HAWK_ID}}'
      hawk-api: '{{ZTPKI_HAWK_SECRET}}'
      platform: '{{ZTPKI_URL}}'

certificateTasks:
  - name: "WebServerCert"
    renewBefore: 30d
    request:
      csr: local
      subject:
        commonName: "www.example.com"
        country: US
        state: California
        locality: San Francisco
        organization: Example Corp
        # Additional optional fields:
        # orgUnits: ["IT Department"]
        # email: "admin@example.com"
      policy: '{{ZTPKI_POLICY_ID}}'
      # Subject Alternative Names (SAN)
      sans:
        dns:
          - "example.com"
          - "api.example.com"
          - "mail.example.com"
        # Optional: IP and email SANs
        # ip:
        #   - "192.168.1.100"
        # email:
        #   - "webmaster@example.com"
    installations:
      - format: PEM
        file: "./certs/webserver.crt"
        chainFile: "./certs/webserver.chain.crt"
        keyFile: "./certs/webserver.key"
        backupExisting: true
        # Optional: Run command after certificate installation
        # afterInstallAction: "systemctl reload nginx"

  # Example 2: Simple API Certificate (minimal configuration)
  - name: "APICert"
    renewBefore: 15d
    request:
      csr: local
      subject:
        commonName: "api.example.com"
        country: US
        organization: Example Corp
      policy: '{{ZTPKI_POLICY_ID}}'
    installations:
      - format: PEM
        file: "./certs/api.crt"
        keyFile: "./certs/api.key"

  # Example 3: Database Certificate with IP SAN
  - name: "DatabaseCert"
    renewBefore: 45d
    request:
      csr: local
      subject:
        commonName: "db.example.com"
        country: US
        state: California
        locality: San Francisco
        organization: Example Corp
        orgUnits: ["Database Team"]
      policy: '{{ZTPKI_POLICY_ID}}'
      sans:
        dns:
          - "db.example.com"
          - "db-primary.example.com"
        ip:
          - "10.0.1.100"
          - "10.0.1.101"
    installations:
      - format: PEM
        file: "./certs/database.crt"
        chainFile: "./certs/database.chain.crt"
        keyFile: "./certs/database.key"
        password: "db-cert-password"
        backupExisting: true
        afterInstallAction: "systemctl restart postgresql"

# Notes:
# - Replace {{ZTPKI_HAWK_ID}}, {{ZTPKI_HAWK_SECRET}}, {{ZTPKI_URL}}, and {{ZTPKI_POLICY_ID}} with your values
# - Or set environment variables: ZTPKI_HAWK_ID, ZTPKI_HAWK_SECRET, ZTPKI_URL, ZTPKI_POLICY_ID
# - Create directory: mkdir -p ./certs
# - Run: zcert run --file playbook.yaml
`

        return os.WriteFile(filename, []byte(content), 0600) // Restrict to owner only
}

// ExtractPlaybookCredentials attempts to extract credentials from a playbook file
func ExtractPlaybookCredentials(filename string) (*CredentialsConfig, error) {
        file, err := os.Open(filename)
        if err != nil {
                return nil, fmt.Errorf("failed to open playbook file: %w", err)
        }
        defer file.Close()

        // Try to parse as certificate playbook format
        var certPlaybook CertificatePlaybook
        decoder := yaml.NewDecoder(file)
        if err := decoder.Decode(&certPlaybook); err == nil {
                if certPlaybook.Config.Connection.Credentials.Platform != "" ||
                   certPlaybook.Config.Connection.Credentials.HawkID != "" ||
                   certPlaybook.Config.Connection.Credentials.HawkAPI != "" {
                        return &certPlaybook.Config.Connection.Credentials, nil
                }
        }

        return nil, nil // No credentials found, not an error
}

// LoadCertificatePlaybook loads a certificate playbook from a YAML file
func LoadCertificatePlaybook(filename string) (*CertificatePlaybook, error) {
        file, err := os.Open(filename)
        if err != nil {
                return nil, fmt.Errorf("failed to open file: %w", err)
        }
        defer file.Close()

        var playbook CertificatePlaybook
        decoder := yaml.NewDecoder(file)
        if err := decoder.Decode(&playbook); err != nil {
                return nil, fmt.Errorf("failed to parse YAML: %w", err)
        }

        // Validate the playbook
        if len(playbook.CertificateTasks) == 0 {
                return nil, nil // Not a certificate playbook format
        }

        // Validate each certificate task
        for i, task := range playbook.CertificateTasks {
                if task.Name == "" {
                        return nil, fmt.Errorf("certificate task %d must have a name", i+1)
                }
                if task.Request.Subject.CommonName == "" {
                        return nil, fmt.Errorf("certificate task %d (%s) must have a common name", i+1, task.Name)
                }
                if task.Request.Policy == "" {
                        return nil, fmt.Errorf("certificate task %d (%s) must have a policy", i+1, task.Name)
                }
        }

        return &playbook, nil
}


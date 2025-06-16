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
        Name         string                 `yaml:"name"`
        RenewBefore  string                 `yaml:"renewBefore"`
        Request      CertificateRequest     `yaml:"request"`
        Installations []CertificateInstall  `yaml:"installations"`
}

// CertificateRequest represents certificate request details
type CertificateRequest struct {
        CSR               string                 `yaml:"csr"`
        Subject           CertificateSubject     `yaml:"subject"`
        Policy            string                 `yaml:"policy"`
        SANs              *SubjectAltNames       `yaml:"sans,omitempty"`
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

// LoadPlaybook loads a YAML playbook from file and supports both formats
func LoadPlaybook(filename string) (*Playbook, error) {
        file, err := os.Open(filename)
        if err != nil {
                return nil, fmt.Errorf("failed to open playbook file %s: %w", filename, err)
        }
        defer file.Close()

        // First, try to load as certificate playbook format
        file.Seek(0, 0)
        var certPlaybook CertificatePlaybook
        decoder := yaml.NewDecoder(file)
        if err := decoder.Decode(&certPlaybook); err == nil && len(certPlaybook.CertificateTasks) > 0 {
                // Convert certificate tasks to simple tasks for compatibility
                return convertCertificatePlaybook(&certPlaybook, filename)
        }

        // Fall back to simple playbook format
        file.Seek(0, 0)
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
                        Name:       certTask.Name,
                        Action:     "enroll",
                        CommonName: certTask.Request.Subject.CommonName,
                        PolicyID:   certTask.Request.Policy,
                        KeySize:    2048, // Default
                        KeyType:    "rsa", // Default
                        Subject: &SubjectInfo{
                                Country:      []string{certTask.Request.Subject.Country},
                                Province:     []string{certTask.Request.Subject.State},
                                Locality:     []string{certTask.Request.Subject.Locality},
                                Organization: []string{certTask.Request.Subject.Organization},
                                OrgUnit:      certTask.Request.Subject.OrgUnits,
                        },
                        ContinueOnError: false,
                }

                // Set output file from installations if available
                if len(certTask.Installations) > 0 {
                        task.OutputFile = certTask.Installations[0].File
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



// CreateExamplePlaybookConfig creates an example playbook YAML configuration file
func CreateExamplePlaybookConfig(filename string) error {
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
        commonName: "abc.example.com"
        country: US
        state: Utah
        locality: Salt Lake City
        organization: Example Corp
        orgUnits: ["IT Ops"]
        # Additional DN components supported by ZTPKI:
        domainComponents: ["example", "com"]  # DC fields
        email: "admin@example.com"           # EMAIL field
      policy: '5fe6d368-896a-4883-97eb-f87148c90896'
      # Enhanced SAN support matching ZTPKI schema
      sans:
        dns:
          - "www.example.com"
          - "api.example.com"
          - "mail.example.com"
        ip:
          - "192.168.1.100"
          - "10.0.0.50"
        email:
          - "webmaster@example.com"
          - "support@example.com"
        upn:
          - "service@example.com"
        uri:
          - "https://api.example.com"
      # Validity period (optional)
      validity:
        years: 1
        months: 0
        days: 0
      # Custom fields (optional)
      customFields:
        department: "IT"
        costCenter: "12345"
      # Custom extensions (optional)
      customExtensions:
        "1.3.6.1.4.1.311.21.7": "302f06272b060104018237150884f09f0881fe9c1b85fd973886edbb1581edd1228149828fe83b86f9ea32020164020102"
        "1.3.6.1.4.1.311.21.10": "3018300a06082b06010505070301300a06082b06010505070302"
        "1.3.6.1.4.1.311.25.2": ""
      # Additional metadata
      comment: "Web server certificate for production environment"
      expiryEmails:
        - "admin@example.com"
        - "security@example.com"
      # Certificate reminder management
      clearRemindersCertificateId: ""  # If replacing existing cert
    installations:
      - format: PEM
        file: "./certs/example.crt"
        chainFile: "./certs/example.chain.crt"
        keyFile: "./certs/example.key"
        backupExisting: true
        afterInstallAction: "echo 'Certificate installed successfully'"
        # windows example: combine cert and chain files
        # afterInstallAction: ('', (gc .\certs\example.crt -Raw)) | ac .\certs\example.chain.crt
      
      # Additional installation formats
      - format: PKCS12
        file: "./certs/example.p12"
        password: "secure123"
        afterInstallAction: "systemctl restart apache2"

  # Example with minimal configuration
  - name: "APIServerCert"
    renewBefore: 15d
    request:
      csr: local
      subject:
        commonName: "api.example.com"
      policy: '5fe6d368-896a-4883-97eb-f87148c90896'
      sans:
        dns:
          - "api-v2.example.com"
    installations:
      - format: PEM
        file: "./certs/api.crt"
        keyFile: "./certs/api.key"
`

        return os.WriteFile(filename, []byte(content), 0600) // Restrict to owner only
}


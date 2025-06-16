package cmd

import (
        "context"
        "crypto/rand"
        "crypto/rsa"
        "crypto/x509"
        "crypto/x509/pkix"
        "encoding/pem"
        "fmt"
        "os"
        "strings"
        "time"

        "github.com/spf13/cobra"
        "zcert/internal/api"
        "zcert/internal/config"
)

var (
        runFile string
        runForceRenew bool
        runDryRun bool
)

// runCmd represents the run command
var runCmd = &cobra.Command{
        Use:   "run [--file PLAYBOOK] [--force-renew]",
        Short: "Execute a YAML playbook for automated certificate operations",
        Long: `Execute a YAML playbook that defines a series of certificate operations.
The playbook contains connection settings and one or more certificate tasks to
automate end-to-end certificate enrollment and deployment.

Example usage:
  zcert run                              # Execute playbook.yaml
  zcert run --file myplaybook.yaml       # Execute specific playbook
  zcert run --force-renew                # Force renewal of all certificates`,
        Args: cobra.NoArgs,
        RunE: runPlaybook,
}

func init() {
        rootCmd.AddCommand(runCmd)
        
        runCmd.Flags().StringVarP(&runFile, "file", "f", "playbook.yaml", "Playbook YAML file to execute (default \"playbook.yaml\")")
        runCmd.Flags().BoolVar(&runForceRenew, "force-renew", false, "Force renew certificates regardless of current expiration")
        runCmd.Flags().BoolVar(&runDryRun, "dry-run", false, "Show what would be executed without running")
}

func runPlaybook(cmd *cobra.Command, args []string) error {
        // Use default file if not specified
        playbookFile := runFile

        // Check if file exists
        if _, err := os.Stat(playbookFile); os.IsNotExist(err) {
                return fmt.Errorf("playbook file does not exist: %s", playbookFile)
        }

        fmt.Printf("Executing playbook: %s\n", playbookFile)
        if runDryRun {
                fmt.Println("DRY RUN MODE - No actual operations will be performed")
        }
        fmt.Println()

        // Load and parse the YAML playbook
        playbook, err := config.LoadPlaybook(playbookFile)
        if err != nil {
                return fmt.Errorf("failed to load playbook: %w", err)
        }

        fmt.Printf("Loaded playbook with %d tasks\n", len(playbook.Tasks))
        fmt.Println()

        // Create API client using global configuration
        cfg := config.GetConfig()
        
        // Try to extract credentials from the playbook file directly
        playbookCredentials, err := config.ExtractPlaybookCredentials(playbookFile)
        if err == nil && playbookCredentials != nil {
                if playbookCredentials.Platform != "" {
                        cfg.BaseURL = os.ExpandEnv(playbookCredentials.Platform)
                }
                if playbookCredentials.HawkID != "" {
                        cfg.HawkID = os.ExpandEnv(playbookCredentials.HawkID)
                }
                if playbookCredentials.HawkAPI != "" {
                        cfg.HawkKey = os.ExpandEnv(playbookCredentials.HawkAPI)
                }
        }
        
        // Override with environment variables if available (highest priority)
        if url := os.Getenv("ZTPKI_URL"); url != "" {
                cfg.BaseURL = url
        }
        if hawkID := os.Getenv("ZTPKI_HAWK_ID"); hawkID != "" {
                cfg.HawkID = hawkID
        }
        if hawkKey := os.Getenv("ZTPKI_HAWK_SECRET"); hawkKey != "" {
                cfg.HawkKey = hawkKey
        }

        // Validate required credentials before proceeding
        if cfg.BaseURL == "" {
                return fmt.Errorf("ZTPKI URL is required (set ZTPKI_URL environment variable or use --config with profile)")
        }
        if cfg.HawkID == "" {
                return fmt.Errorf("HAWK ID is required (set ZTPKI_HAWK_ID environment variable or use --config with profile)")
        }
        if cfg.HawkKey == "" {
                return fmt.Errorf("HAWK key is required (set ZTPKI_HAWK_SECRET environment variable or use --config with profile)")
        }

        client, err := api.NewClient(cfg)
        if err != nil {
                return fmt.Errorf("failed to create API client: %w", err)
        }

        // Execute each task in the playbook
        for i, task := range playbook.Tasks {
                fmt.Printf("Task %d: %s\n", i+1, task.Name)
                
                if runDryRun {
                        fmt.Printf("  Action: %s\n", task.Action)
                        if task.CommonName != "" {
                                fmt.Printf("  CN: %s\n", task.CommonName)
                        }
                        if task.PolicyID != "" {
                                fmt.Printf("  Policy: %s\n", task.PolicyID)
                        }
                        if task.OutputFile != "" {
                                fmt.Printf("  Output: %s\n", task.OutputFile)
                        }
                        fmt.Println("  [DRY RUN - would execute here]")
                } else {
                        err := executeTask(client, &task)
                        if err != nil {
                                fmt.Printf("  ❌ Task failed: %v\n", err)
                                if !task.ContinueOnError {
                                        return fmt.Errorf("task %d failed: %w", i+1, err)
                                }
                                fmt.Println("  ⚠️  Continuing despite error...")
                        } else {
                                fmt.Printf("  ✅ Task completed successfully\n")
                        }
                }
                fmt.Println()
        }

        if runDryRun {
                fmt.Println("DRY RUN completed - no actual operations performed")
        } else {
                fmt.Printf("Playbook execution completed: %d tasks processed\n", len(playbook.Tasks))
        }

        return nil
}

func executeTask(client *api.Client, task *config.PlaybookTask) error {
        switch strings.ToLower(task.Action) {
        case "enroll":
                return executeEnrollTask(client, task)
        case "retrieve":
                return executeRetrieveTask(client, task)
        case "search":
                return executeSearchTask(client, task)
        case "revoke":
                return executeRevokeTask(client, task)
        default:
                return fmt.Errorf("unknown task action: %s", task.Action)
        }
}

func executeEnrollTask(client *api.Client, task *config.PlaybookTask) error {
        fmt.Printf("    Enrolling certificate for CN: %s\n", task.CommonName)

        // Validate required fields
        if task.CommonName == "" {
                return fmt.Errorf("common name is required for enrollment")
        }
        if task.PolicyID == "" {
                return fmt.Errorf("policy ID is required for enrollment")
        }

        // Generate key pair and CSR
        keySize := task.KeySize
        if keySize == 0 {
                keySize = 2048 // Default key size
        }

        keyType := task.KeyType
        if keyType == "" {
                keyType = "rsa" // Default key type
        }

        // Create certificate request
        csr, privateKeyPEM, err := generateCSR(task.CommonName, keySize, keyType, task.Subject)
        if err != nil {
                return fmt.Errorf("failed to generate CSR: %w", err)
        }

        // Submit CSR to ZTPKI
        requestID, err := client.SubmitCSR(csr, task.PolicyID, nil)
        if err != nil {
                return fmt.Errorf("failed to submit CSR: %w", err)
        }

        fmt.Printf("    CSR submitted, request ID: %s\n", requestID)

        // Poll for certificate
        certificate, err := pollForCertificate(client, requestID)
        if err != nil {
                return fmt.Errorf("failed to retrieve certificate: %w", err)
        }

        // Save certificate and key if output file specified
        if task.OutputFile != "" {
                err := saveCertificateAndKey(task.OutputFile, certificate.Certificate, privateKeyPEM)
                if err != nil {
                        return fmt.Errorf("failed to save certificate: %w", err)
                }
                fmt.Printf("    Certificate saved to: %s\n", task.OutputFile)
        }

        return nil
}

func executeRetrieveTask(client *api.Client, task *config.PlaybookTask) error {
        fmt.Printf("    Retrieving certificate ID: %s\n", task.CertificateID)

        if task.CertificateID == "" {
                return fmt.Errorf("certificate ID is required for retrieval")
        }

        certificate, err := client.GetCertificate(task.CertificateID)
        if err != nil {
                return fmt.Errorf("failed to retrieve certificate: %w", err)
        }

        if task.OutputFile != "" {
                err := os.WriteFile(task.OutputFile, []byte(certificate.Certificate), 0644)
                if err != nil {
                        return fmt.Errorf("failed to save certificate: %w", err)
                }
                fmt.Printf("    Certificate saved to: %s\n", task.OutputFile)
        }

        return nil
}

func executeSearchTask(client *api.Client, task *config.PlaybookTask) error {
        fmt.Printf("    Searching certificates with criteria\n")

        searchParams := api.CertificateSearchParams{
                CommonName: task.CommonName,
                PolicyID:   task.PolicyID,
                Limit:      task.Limit,
        }

        if searchParams.Limit == 0 {
                searchParams.Limit = 10 // Default limit
        }

        certificates, err := client.SearchCertificates(searchParams)
        if err != nil {
                return fmt.Errorf("failed to search certificates: %w", err)
        }

        fmt.Printf("    Found %d certificates\n", len(certificates))

        // Save search results if output file specified
        if task.OutputFile != "" {
                err := saveSearchResults(task.OutputFile, certificates)
                if err != nil {
                        return fmt.Errorf("failed to save search results: %w", err)
                }
        }

        return nil
}

func executeRevokeTask(client *api.Client, task *config.PlaybookTask) error {
        fmt.Printf("    Revoking certificate ID: %s\n", task.CertificateID)

        if task.CertificateID == "" {
                return fmt.Errorf("certificate ID is required for revocation")
        }

        // Note: Implement revocation API call when available
        return fmt.Errorf("revocation not yet implemented in API client")
}

// generateCSR creates a Certificate Signing Request with the given parameters
func generateCSR(commonName string, keySize int, keyType string, subject *config.SubjectInfo) (string, string, error) {
        // Generate private key
        var privateKey interface{}
        var err error
        
        if keyType == "rsa" {
                privateKey, err = rsa.GenerateKey(rand.Reader, keySize)
                if err != nil {
                        return "", "", fmt.Errorf("failed to generate RSA private key: %w", err)
                }
        } else {
                return "", "", fmt.Errorf("unsupported key type: %s", keyType)
        }

        // Prepare subject information
        var country, province, locality, organization []string
        var orgUnit []string
        
        if subject != nil {
                country = subject.Country
                province = subject.Province  
                locality = subject.Locality
                organization = subject.Organization
                orgUnit = subject.OrgUnit
        }
        
        // Create certificate request template
        template := x509.CertificateRequest{
                Subject: pkix.Name{
                        CommonName:         commonName,
                        Country:            country,
                        Province:           province,
                        Locality:           locality,
                        Organization:       organization,
                        OrganizationalUnit: orgUnit,
                },
        }

        // Create the CSR
        csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
        if err != nil {
                return "", "", fmt.Errorf("failed to create CSR: %w", err)
        }

        // Encode CSR to PEM format
        csrPEM := pem.EncodeToMemory(&pem.Block{
                Type:  "CERTIFICATE REQUEST",
                Bytes: csrBytes,
        })

        // Encode private key to PEM format
        var privateKeyPEM []byte
        if rsaKey, ok := privateKey.(*rsa.PrivateKey); ok {
                privateKeyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
                privateKeyPEM = pem.EncodeToMemory(&pem.Block{
                        Type:  "RSA PRIVATE KEY",
                        Bytes: privateKeyBytes,
                })
        }

        return string(csrPEM), string(privateKeyPEM), nil
}

// Helper functions

func pollForCertificate(client *api.Client, requestID string) (*api.Certificate, error) {
        // Use the proven polling logic from enroll command
        var certificate *api.Certificate

        // Create context with 2-second timeout for immediate polling
        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
        defer cancel()

        // Continuous polling until timeout or success
        ticker := time.NewTicker(50 * time.Millisecond) // Poll every 50ms for faster response
        defer ticker.Stop()

        attemptCount := 0
        for {
                select {
                case <-ctx.Done():
                        goto timeout_reached
                case <-ticker.C:
                        attemptCount++

                        // First, check the request status to get certificate ID
                        request, err := client.GetCertificateRequest(requestID)
                        if err != nil {
                                continue
                        }

                        if request != nil && request.CertificateID != "" {
                                // Request completed, now get the actual certificate
                                certificate, err = client.GetCertificate(request.CertificateID)
                                if err == nil && certificate != nil && certificate.Certificate != "" {
                                        return certificate, nil
                                }
                        }
                }
        }

timeout_reached:
        if certificate == nil {
                // Fallback: Try to get certificate directly by request ID
                certificate, err := client.GetCertificate(requestID)
                if err == nil && certificate != nil && certificate.Certificate != "" {
                        return certificate, nil
                }
                return nil, fmt.Errorf("certificate was not issued within the expected time frame. The certificate may still be processing on the server")
        }

        return certificate, nil
}

func saveCertificateAndKey(outputFile, certificate, privateKey string) error {
        // Create directory if it doesn't exist
        dir := strings.Replace(outputFile, "\\", "/", -1) // Handle Windows paths
        if lastSlash := strings.LastIndex(dir, "/"); lastSlash != -1 {
                dir = dir[:lastSlash]
                err := os.MkdirAll(dir, 0755)
                if err != nil {
                        return fmt.Errorf("failed to create directory %s: %w", dir, err)
                }
        }

        // Save certificate to the specified output file
        err := os.WriteFile(outputFile, []byte(certificate), 0644)
        if err != nil {
                return fmt.Errorf("failed to write certificate file: %w", err)
        }

        // Save private key with .key extension
        keyFile := strings.TrimSuffix(outputFile, ".crt") + ".key"
        err = os.WriteFile(keyFile, []byte(privateKey), 0600) // More restrictive permissions for private key
        if err != nil {
                return fmt.Errorf("failed to write private key file: %w", err)
        }

        return nil
}

func saveSearchResults(outputFile string, certificates []api.Certificate) error {
        var results strings.Builder
        
        for _, cert := range certificates {
                results.WriteString(fmt.Sprintf("ID: %s\n", cert.ID))
                results.WriteString(fmt.Sprintf("CN: %s\n", cert.Subject))
                results.WriteString(fmt.Sprintf("Status: %s\n", cert.Status))
                results.WriteString("---\n")
        }

        return os.WriteFile(outputFile, []byte(results.String()), 0644)
}
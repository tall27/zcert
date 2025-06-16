package cmd

import (
        "fmt"
        "os"
        "strings"

        "github.com/spf13/cobra"
        "zcert/internal/api"
        "zcert/internal/config"
)

var (
        runFile string
        runDryRun bool
        runVerbose bool
)

// runCmd represents the run command
var runCmd = &cobra.Command{
        Use:   "run [playbook.yaml]",
        Short: "Execute a YAML playbook for automated certificate operations",
        Long: `Execute a YAML playbook that defines a series of certificate operations.
The playbook can include multiple tasks for enrollment, retrieval, and management
of certificates with different configurations.

Example usage:
  zcert run playbook.yaml
  zcert run --dry-run playbook.yaml
  zcert run --file playbook.yaml --verbose`,
        Args: cobra.MaximumNArgs(1),
        RunE: runPlaybook,
}

func init() {
        rootCmd.AddCommand(runCmd)
        
        runCmd.Flags().StringVarP(&runFile, "file", "f", "", "YAML playbook file to execute")
        runCmd.Flags().BoolVar(&runDryRun, "dry-run", false, "Show what would be executed without running")
        runCmd.Flags().BoolVar(&runVerbose, "verbose", false, "Verbose output during execution")
}

func runPlaybook(cmd *cobra.Command, args []string) error {
        // Determine playbook file
        var playbookFile string
        if len(args) > 0 {
                playbookFile = args[0]
        } else if runFile != "" {
                playbookFile = runFile
        } else {
                return fmt.Errorf("playbook file is required")
        }

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

        if runVerbose {
                fmt.Printf("Loaded playbook with %d tasks\n", len(playbook.Tasks))
                fmt.Println()
        }

        // Create API client using global configuration
        cfg := config.GetConfig()
        
        // Override with environment variables if available
        if url := os.Getenv("ZTPKI_URL"); url != "" {
                cfg.BaseURL = url
        }
        if hawkID := os.Getenv("ZTPKI_HAWK_ID"); hawkID != "" {
                cfg.HawkID = hawkID
        }
        if hawkKey := os.Getenv("ZTPKI_HAWK_SECRET"); hawkKey != "" {
                cfg.HawkKey = hawkKey
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
                        err := executeTask(client, &task, runVerbose)
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

func executeTask(client *api.Client, task *config.PlaybookTask, verbose bool) error {
        switch strings.ToLower(task.Action) {
        case "enroll":
                return executeEnrollTask(client, task, verbose)
        case "retrieve":
                return executeRetrieveTask(client, task, verbose)
        case "search":
                return executeSearchTask(client, task, verbose)
        case "revoke":
                return executeRevokeTask(client, task, verbose)
        default:
                return fmt.Errorf("unknown task action: %s", task.Action)
        }
}

func executeEnrollTask(client *api.Client, task *config.PlaybookTask, verbose bool) error {
        if verbose {
                fmt.Printf("    Enrolling certificate for CN: %s\n", task.CommonName)
        }

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
        csr, privateKey, err := generateCSR(task.CommonName, keySize, keyType, task.Subject)
        if err != nil {
                return fmt.Errorf("failed to generate CSR: %w", err)
        }

        // Submit CSR to ZTPKI
        requestID, err := client.SubmitCSR(csr, task.PolicyID, nil)
        if err != nil {
                return fmt.Errorf("failed to submit CSR: %w", err)
        }

        if verbose {
                fmt.Printf("    CSR submitted, request ID: %s\n", requestID)
        }

        // Poll for certificate
        certificate, err := pollForCertificate(client, requestID, verbose)
        if err != nil {
                return fmt.Errorf("failed to retrieve certificate: %w", err)
        }

        // Save certificate and key if output file specified
        if task.OutputFile != "" {
                err := saveCertificateAndKey(task.OutputFile, certificate.Certificate, privateKey)
                if err != nil {
                        return fmt.Errorf("failed to save certificate: %w", err)
                }
                if verbose {
                        fmt.Printf("    Certificate saved to: %s\n", task.OutputFile)
                }
        }

        return nil
}

func executeRetrieveTask(client *api.Client, task *config.PlaybookTask, verbose bool) error {
        if verbose {
                fmt.Printf("    Retrieving certificate ID: %s\n", task.CertificateID)
        }

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
                if verbose {
                        fmt.Printf("    Certificate saved to: %s\n", task.OutputFile)
                }
        }

        return nil
}

func executeSearchTask(client *api.Client, task *config.PlaybookTask, verbose bool) error {
        if verbose {
                fmt.Printf("    Searching certificates with criteria\n")
        }

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

        if verbose {
                fmt.Printf("    Found %d certificates\n", len(certificates))
        }

        // Save search results if output file specified
        if task.OutputFile != "" {
                err := saveSearchResults(task.OutputFile, certificates)
                if err != nil {
                        return fmt.Errorf("failed to save search results: %w", err)
                }
        }

        return nil
}

func executeRevokeTask(client *api.Client, task *config.PlaybookTask, verbose bool) error {
        if verbose {
                fmt.Printf("    Revoking certificate ID: %s\n", task.CertificateID)
        }

        if task.CertificateID == "" {
                return fmt.Errorf("certificate ID is required for revocation")
        }

        // Note: Implement revocation API call when available
        return fmt.Errorf("revocation not yet implemented in API client")
}

// Helper functions

func generateCSR(commonName string, keySize int, keyType string, subject *config.SubjectInfo) (string, string, error) {
        // This would use the existing CSR generation logic from the enroll command
        // For now, return an error indicating this needs to be implemented
        return "", "", fmt.Errorf("CSR generation not yet implemented in run command")
}

func pollForCertificate(client *api.Client, requestID string, verbose bool) (*api.Certificate, error) {
        // This would poll the certificate request status until ready
        // For now, return an error indicating this needs to be implemented
        return nil, fmt.Errorf("certificate polling not yet implemented in run command")
}

func saveCertificateAndKey(outputFile, certificate, privateKey string) error {
        // Save certificate
        certFile := outputFile
        if !strings.HasSuffix(certFile, ".pem") {
                certFile += ".pem"
        }
        
        err := os.WriteFile(certFile, []byte(certificate), 0644)
        if err != nil {
                return err
        }

        // Save private key
        keyFile := strings.TrimSuffix(certFile, ".pem") + ".key"
        err = os.WriteFile(keyFile, []byte(privateKey), 0600)
        if err != nil {
                return err
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
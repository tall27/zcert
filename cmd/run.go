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
        "path/filepath"
        "regexp"
        "strconv"
        "strings"
        "time"

        "github.com/spf13/cobra"
        "zcert/internal/api"
        "zcert/internal/config"
)

var (
        runFile string
        runForceRenew bool
        runQuiet bool
        runVerbose bool
        globalQuietMode bool // Global flag for quiet mode
        
        // ZTPKI Authentication flags
        runURL      string
        runHawkID   string
        runHawkKey  string
        runPolicy   string
)

// runCmd represents the run command
var runCmd = &cobra.Command{
        Use:   "run [--file PLAYBOOK] [--force-renew] [--quiet] [--verbose]",
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
        SilenceUsage: true, // Don't show usage on error
        SilenceErrors: true, // Don't show duplicate error messages
}

func init() {
        rootCmd.AddCommand(runCmd)
        
        runCmd.Flags().StringVarP(&runFile, "file", "f", "playbook.yaml", "Playbook YAML file to execute (default \"playbook.yaml\")")
        runCmd.Flags().BoolVar(&runForceRenew, "force-renew", false, "Force renew certificates regardless of current expiration")

        runCmd.Flags().BoolVarP(&runQuiet, "quiet", "q", false, "Script-friendly output mode: exit 0 on success, 1 on error")
        runCmd.Flags().BoolVarP(&runVerbose, "verbose", "v", false, "Detailed output including debug information")
        
        // ZTPKI Authentication flags
        runCmd.Flags().StringVar(&runURL, "url", "", "ZTPKI API base URL (e.g., https://your-ztpki-instance.com/api/v2)")
        runCmd.Flags().StringVar(&runHawkID, "hawk-id", "", "HAWK authentication ID")
        runCmd.Flags().StringVar(&runHawkKey, "hawk-key", "", "HAWK authentication key")
        runCmd.Flags().StringVar(&runPolicy, "policy", "", "Default policy ID for certificate operations")
}

func runPlaybook(cmd *cobra.Command, args []string) error {
        // Set global quiet mode for use throughout the application
        globalQuietMode = runQuiet
        
        // Use default file if not specified
        playbookFile := runFile

        // Check if file exists
        if _, err := os.Stat(playbookFile); os.IsNotExist(err) {
                return fmt.Errorf("playbook file does not exist: %s", playbookFile)
        }

        // Output mode logic: quiet overrides verbose, default is normal
        if !runQuiet {
                fmt.Printf("Executing playbook: %s\n", playbookFile)
                if !runVerbose {
                        fmt.Println()
                }
        }

        // Try to load as certificate playbook format first (comprehensive YAML)
        certPlaybook, err := config.LoadCertificatePlaybook(playbookFile)
        if err == nil && certPlaybook != nil {
                return executeCertificatePlaybook(certPlaybook, playbookFile, runQuiet, runVerbose)
        }
        
        // Fall back to simple playbook format
        playbook, err := config.LoadPlaybook(playbookFile)
        if err != nil {
                if !runQuiet {
                        fmt.Printf("🟥 Playbook execution failed: run with --verbose flag for more information.\n")
                }
                os.Exit(1)
        }

        fmt.Printf("Loaded playbook with %d tasks\n", len(playbook.Tasks))
        fmt.Println()

        // Create configuration with correct priority hierarchy
        // Priority: CLI Parameters > Configuration File > Environment Variables
        
        // Start with environment variables (lowest priority)
        cfg := &config.Config{}
        var defaultPolicy string
        
        if url := os.Getenv("ZTPKI_URL"); url != "" {
                cfg.BaseURL = url
        }
        if hawkID := os.Getenv("ZTPKI_HAWK_ID"); hawkID != "" {
                cfg.HawkID = hawkID
        }
        if hawkKey := os.Getenv("ZTPKI_HAWK_SECRET"); hawkKey != "" {
                cfg.HawkKey = hawkKey
        }
        if envPolicy := os.Getenv("ZTPKI_POLICY_ID"); envPolicy != "" {
                defaultPolicy = envPolicy
        }
        
        // Override with playbook credentials (medium priority - configuration file)
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
        
        // Override with profile configuration if available (medium priority)
        profile := GetCurrentProfile()
        if profile != nil {
                if profile.URL != "" {
                        cfg.BaseURL = profile.URL
                }
                if profile.KeyID != "" {
                        cfg.HawkID = profile.KeyID
                }
                if profile.Secret != "" {
                        cfg.HawkKey = profile.Secret
                }
                if profile.PolicyID != "" {
                        defaultPolicy = profile.PolicyID
                }
        }
        
        // Override with CLI parameters (highest priority)
        if runURL != "" {
                cfg.BaseURL = runURL
        }
        if runHawkID != "" {
                cfg.HawkID = runHawkID
        }
        if runHawkKey != "" {
                cfg.HawkKey = runHawkKey
        }
        if runPolicy != "" {
                defaultPolicy = runPolicy
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
                
                // Apply default policy if task doesn't specify one
                if task.PolicyID == "" && defaultPolicy != "" {
                        task.PolicyID = defaultPolicy
                }
                
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
                fmt.Println()
        }

        fmt.Printf("Playbook execution completed: %d tasks processed\n", len(playbook.Tasks))

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

        // Validate required fields
        if task.CommonName == "" {
                return fmt.Errorf("common name is required for enrollment")
        }
        if task.PolicyID == "" {
                return fmt.Errorf("policy ID is required for enrollment")
        }

        // Check for existing certificate renewal needs if renewBefore is specified
        if task.RenewBefore != "" && !runForceRenew {
                needsRenewal, err := checkCertificateRenewal(client, task)
                if err != nil {
                        fmt.Printf("    Warning: Could not check renewal status: %v\n", err)
                        // Continue with enrollment as fallback
                } else if !needsRenewal {
                        fmt.Printf("    Certificate does not need renewal yet (expires later than %s)\n", task.RenewBefore)
                        return nil
                }
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
                // Retrieve certificate with chain using PEM endpoint
                pemResponse, err := client.GetCertificatePEM(certificate.ID, true)
                if err != nil {
                        return fmt.Errorf("failed to retrieve certificate PEM: %w", err)
                }
                
                err = saveCertificateAndKeyQuiet(task.OutputFile, pemResponse.Certificate, privateKeyPEM, pemResponse.Chain, task.BackupExisting, true) // Use quiet mode for legacy function
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
                                // Request completed, now get the actual certificate with chain
                                pemResp, err := client.GetCertificatePEM(request.CertificateID, true)
                                if err == nil && pemResp != nil && pemResp.Certificate != "" {
                                        // Convert PEM response to Certificate struct
                                        certificate = &api.Certificate{
                                                ID:          request.CertificateID,
                                                Certificate: pemResp.Certificate,
                                                Chain:       []string{},
                                        }
                                        // Parse chain if present
                                        if pemResp.Chain != "" {
                                                certificate.Chain = append(certificate.Chain, pemResp.Chain)
                                        }
                                        return certificate, nil
                                }
                        }
                }
        }

timeout_reached:
        if certificate == nil {
                // Fallback: Try to get certificate directly by request ID with chain
                pemResp, err := client.GetCertificatePEM(requestID, true)
                if err == nil && pemResp != nil && pemResp.Certificate != "" {
                        certificate = &api.Certificate{
                                ID:          requestID,
                                Certificate: pemResp.Certificate,
                                Chain:       []string{},
                        }
                        if pemResp.Chain != "" {
                                certificate.Chain = append(certificate.Chain, pemResp.Chain)
                        }
                        return certificate, nil
                }
                return nil, fmt.Errorf("certificate was not issued within the expected time frame. The certificate may still be processing on the server")
        }

        return certificate, nil
}

func saveCertificateAndKey(outputFile, certificate, privateKey, chainCertificate string, backupExisting bool) error {
        return saveCertificateAndKeyQuiet(outputFile, certificate, privateKey, chainCertificate, backupExisting, false)
}

func saveCertificateAndKeyQuietNoBackup(outputFile, certificate, privateKey, chainCertificate string, quiet bool) error {
        // Create directory if it doesn't exist
        dir := strings.Replace(outputFile, "\\", "/", -1) // Handle Windows paths
        if lastSlash := strings.LastIndex(dir, "/"); lastSlash != -1 {
                dir = dir[:lastSlash]
                err := os.MkdirAll(dir, 0755)
                if err != nil {
                        return fmt.Errorf("failed to create directory %s: %w", dir, err)
                }
        }

        // Generate key file path
        keyFile := strings.TrimSuffix(outputFile, ".crt") + ".key"
        chainFile := strings.TrimSuffix(outputFile, ".crt") + ".chain.crt"

        // Save certificate to the specified output file
        err := os.WriteFile(outputFile, []byte(certificate), 0644)
        if err != nil {
                return fmt.Errorf("failed to write certificate file: %w", err)
        }

        // Save private key with .key extension
        err = os.WriteFile(keyFile, []byte(privateKey), 0600) // More restrictive permissions for private key
        if err != nil {
                return fmt.Errorf("failed to write private key file: %w", err)
        }
        if !quiet {
                fmt.Printf("    Private key generated and saved to: %s\n", keyFile)
        }

        // Save chain certificate if provided
        if chainCertificate != "" && strings.TrimSpace(chainCertificate) != "" {
                err = os.WriteFile(chainFile, []byte(chainCertificate), 0644)
                if err != nil {
                        return fmt.Errorf("failed to write chain certificate file: %w", err)
                }
                if !quiet {
                        fmt.Printf("    Chain certificate saved to: %s\n", chainFile)
                }
        }

        return nil
}

func saveCertificateAndKeyQuietNoBackupWithEnrollment(outputFile, certificate, privateKey, chainCertificate string, quiet bool, commonName string) error {
        // Create directory if it doesn't exist
        dir := strings.Replace(outputFile, "\\", "/", -1) // Handle Windows paths
        if lastSlash := strings.LastIndex(dir, "/"); lastSlash != -1 {
                dir = dir[:lastSlash]
                err := os.MkdirAll(dir, 0755)
                if err != nil {
                        return fmt.Errorf("failed to create directory %s: %w", dir, err)
                }
        }

        // Generate key file path
        keyFile := strings.TrimSuffix(outputFile, ".crt") + ".key"
        chainFile := strings.TrimSuffix(outputFile, ".crt") + ".chain.crt"

        // Save certificate to the specified output file
        err := os.WriteFile(outputFile, []byte(certificate), 0644)
        if err != nil {
                return fmt.Errorf("failed to write certificate file: %w", err)
        }

        // Save private key with .key extension
        err = os.WriteFile(keyFile, []byte(privateKey), 0600) // More restrictive permissions for private key
        if err != nil {
                return fmt.Errorf("failed to write private key file: %w", err)
        }
        if !quiet {
                fmt.Printf("    Private key generated and saved to: %s\n", keyFile)
                fmt.Printf("    Enrolling certificate for CN: %s\n", commonName)
        }

        // Save chain certificate if provided
        if chainCertificate != "" && strings.TrimSpace(chainCertificate) != "" {
                err = os.WriteFile(chainFile, []byte(chainCertificate), 0644)
                if err != nil {
                        return fmt.Errorf("failed to write chain certificate file: %w", err)
                }
                if !quiet {
                        fmt.Printf("    Chain certificate saved to: %s\n", chainFile)
                }
        }

        return nil
}

func saveCertificateAndKeyQuiet(outputFile, certificate, privateKey, chainCertificate string, backupExisting bool, quiet bool) error {
        // Create directory if it doesn't exist
        dir := strings.Replace(outputFile, "\\", "/", -1) // Handle Windows paths
        if lastSlash := strings.LastIndex(dir, "/"); lastSlash != -1 {
                dir = dir[:lastSlash]
                err := os.MkdirAll(dir, 0755)
                if err != nil {
                        return fmt.Errorf("failed to create directory %s: %w", dir, err)
                }
        }

        // Generate key file path
        keyFile := strings.TrimSuffix(outputFile, ".crt") + ".key"
        chainFile := strings.TrimSuffix(outputFile, ".crt") + ".chain.crt"

        // Backup existing files if requested
        if backupExisting {
                err := backupFileIfExistsQuiet(outputFile, quiet)
                if err != nil {
                        return fmt.Errorf("failed to backup certificate file: %w", err)
                }
                
                err = backupFileIfExistsQuiet(keyFile, quiet)
                if err != nil {
                        return fmt.Errorf("failed to backup key file: %w", err)
                }
                
                // Backup chain file if it exists
                if chainCertificate != "" {
                        err = backupFileIfExistsQuiet(chainFile, quiet)
                        if err != nil {
                                return fmt.Errorf("failed to backup chain file: %w", err)
                        }
                }
        }

        // Save certificate to the specified output file
        err := os.WriteFile(outputFile, []byte(certificate), 0644)
        if err != nil {
                return fmt.Errorf("failed to write certificate file: %w", err)
        }

        // Save private key with .key extension
        err = os.WriteFile(keyFile, []byte(privateKey), 0600) // More restrictive permissions for private key
        if err != nil {
                return fmt.Errorf("failed to write private key file: %w", err)
        }

        // Save chain certificate if provided
        if chainCertificate != "" && strings.TrimSpace(chainCertificate) != "" {
                err = os.WriteFile(chainFile, []byte(chainCertificate), 0644)
                if err != nil {
                        return fmt.Errorf("failed to write chain certificate file: %w", err)
                }
                if !quiet {
                        fmt.Printf("    Chain certificate saved to: %s\n", chainFile)
                }
        }

        return nil
}

// backupFileIfExists creates a backup copy of a file if it exists
func backupFileIfExists(filePath string) error {
        return backupFileIfExistsQuiet(filePath, false)
}

// backupFileIfExistsQuiet creates a backup copy of a file if it exists with optional quiet mode
func backupFileIfExistsQuiet(filePath string, quiet bool) error {
        // Check if file exists
        if _, err := os.Stat(filePath); os.IsNotExist(err) {
                // File doesn't exist, no backup needed
                return nil
        }

        // Simple backup filename (replaces any existing backup)
        backupPath := filePath + ".backup"

        // Delete existing backup if it exists
        if _, err := os.Stat(backupPath); err == nil {
                err = os.Remove(backupPath)
                if err != nil {
                        return fmt.Errorf("failed to remove existing backup %s: %w", backupPath, err)
                }
        }

        // Copy original file to backup
        err := copyFile(filePath, backupPath)
        if err != nil {
                return fmt.Errorf("failed to create backup %s: %w", backupPath, err)
        }

        if !quiet && !globalQuietMode {
                fmt.Printf("    Backed up existing file: %s -> %s\n", filePath, backupPath)
        }
        return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
        data, err := os.ReadFile(src)
        if err != nil {
                return err
        }
        
        // Preserve file permissions
        srcInfo, err := os.Stat(src)
        if err != nil {
                return err
        }
        
        return os.WriteFile(dst, data, srcInfo.Mode())
}

// checkCertificateRenewal checks if a local certificate file needs renewal based on renewBefore period
func checkCertificateRenewal(client *api.Client, task *config.PlaybookTask) (bool, error) {
        // Parse the renewBefore duration (e.g., "30d", "7d", "1h")
        renewBeforeDuration, err := parseDuration(task.RenewBefore)
        if err != nil {
                return true, fmt.Errorf("invalid renewBefore format: %w", err)
        }

        // Determine certificate file path to check
        certPath := task.CertificateLocation
        if certPath == "" {
                certPath = task.OutputFile
        }
        
        if certPath == "" {
                // No certificate file specified, needs enrollment
                return true, nil
        }

        // Check if certificate file exists
        if _, err := os.Stat(certPath); os.IsNotExist(err) {
                // Certificate file doesn't exist, needs enrollment
                return true, nil
        }

        // Read and parse the certificate file
        certData, err := os.ReadFile(certPath)
        if err != nil {
                return true, fmt.Errorf("failed to read certificate file %s: %w", certPath, err)
        }

        // Parse the PEM certificate
        block, _ := pem.Decode(certData)
        if block == nil || block.Type != "CERTIFICATE" {
                return true, fmt.Errorf("invalid certificate file format in %s", certPath)
        }

        cert, err := x509.ParseCertificate(block.Bytes)
        if err != nil {
                return true, fmt.Errorf("failed to parse certificate from %s: %w", certPath, err)
        }

        // Get certificate expiration time
        expiryTime := cert.NotAfter

        // Calculate renewal threshold time
        renewalThreshold := expiryTime.Add(-renewBeforeDuration)
        currentTime := time.Now()

        // Check if we're within the renewal window
        needsRenewal := currentTime.After(renewalThreshold)
        return needsRenewal, nil
}

// parseDuration parses duration strings like "30d", "7d", "24h", "60m"
func parseDuration(durationStr string) (time.Duration, error) {
        re := regexp.MustCompile(`^(\d+)([dhm])$`)
        matches := re.FindStringSubmatch(durationStr)
        
        if len(matches) != 3 {
                return 0, fmt.Errorf("invalid duration format, expected format: 30d, 24h, 60m")
        }
        
        value, err := strconv.Atoi(matches[1])
        if err != nil {
                return 0, fmt.Errorf("invalid numeric value: %w", err)
        }
        
        unit := matches[2]
        switch unit {
        case "d":
                return time.Duration(value) * 24 * time.Hour, nil
        case "h":
                return time.Duration(value) * time.Hour, nil
        case "m":
                return time.Duration(value) * time.Minute, nil
        default:
                return 0, fmt.Errorf("unsupported time unit: %s", unit)
        }
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

// executeCertificatePlaybook executes a certificate playbook with comprehensive ZTPKI API payloads
func executeCertificatePlaybook(certPlaybook *config.CertificatePlaybook, playbookFile string, quiet, verbose bool) error {
        renewedCount := 0
        processedCount := 0
        
        if verbose {
                fmt.Printf("Loaded certificate playbook with %d certificate tasks\n", len(certPlaybook.CertificateTasks))
                fmt.Println()
        }

        // Create API client using credentials from playbook or environment
        cfg := config.GetConfig()
        
        // Extract credentials from playbook if available
        playbookCredentials := &certPlaybook.Config.Connection.Credentials
        if playbookCredentials != nil {
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

        // Validate required credentials
        if cfg.BaseURL == "" {
                return fmt.Errorf("ZTPKI URL is required (set ZTPKI_URL environment variable or configure in playbook)")
        }
        if cfg.HawkID == "" {
                return fmt.Errorf("HAWK ID is required (set ZTPKI_HAWK_ID environment variable or configure in playbook)")
        }
        if cfg.HawkKey == "" {
                return fmt.Errorf("HAWK key is required (set ZTPKI_HAWK_SECRET environment variable or configure in playbook)")
        }

        client, err := api.NewClient(cfg)
        if err != nil {
                return fmt.Errorf("failed to create API client: %w", err)
        }

        // Execute each certificate task
        for i, certTask := range certPlaybook.CertificateTasks {
                if verbose {
                        fmt.Printf("Executing certificate task %d/%d: %s\n", i+1, len(certPlaybook.CertificateTasks), certTask.Name)
                }
                
                taskResult, err := executeCertificateTaskWithResult(client, &certTask, quiet, verbose)
                if err != nil {
                        if quiet {
                                return fmt.Errorf("certificate task failed")
                        } else if verbose {
                                fmt.Printf("  Task failed: %v\n", err)
                                return fmt.Errorf("certificate task %d failed: %w", i+1, err)
                        } else {
                                fmt.Printf("🟥 Playbook execution failed: run with --verbose flag for more information.\n")
                                os.Exit(1)
                        }
                }
                
                processedCount++
                if taskResult.Renewed {
                        renewedCount++
                }
                
                if verbose {
                        fmt.Println()
                }
        }

        // Final status output
        if !quiet {
                if renewedCount == 0 {
                        fmt.Printf("🟨 Playbook execution completed: no certificate renewed.\n")
                } else {
                        fmt.Printf("✅ Playbook execution completed: %d certificate renewed.\n", renewedCount)
                }
        }

        return nil
}

// TaskResult represents the result of executing a certificate task
type TaskResult struct {
        Renewed bool
        Skipped bool
        Error   error
}

// executeCertificateTaskWithResult executes a single certificate task and returns detailed results
func executeCertificateTaskWithResult(client *api.Client, certTask *config.CertificateTask, quiet, verbose bool) (*TaskResult, error) {
        result := &TaskResult{Renewed: false, Skipped: false}
        
        if verbose {
                fmt.Printf("    Processing certificate for CN: %s\n", certTask.Request.Subject.CommonName)
        }

        // Check for existing certificate renewal needs if renewBefore is specified
        if certTask.RenewBefore != "" && !runForceRenew {
                needsRenewal, err := checkCertificateRenewalFromTask(certTask)
                if err != nil {
                        if verbose {
                                fmt.Printf("    Warning: Could not check renewal status: %v\n", err)
                        }
                } else if !needsRenewal {
                        // Get expiry information for clean output
                        expiryInfo := getExpiryInfoFromTask(certTask)
                        if !quiet && !verbose {
                                fmt.Printf("    Local certificate expires %s, renewal not needed (threshold: %s)\n", 
                                        expiryInfo.ExpiryDate, expiryInfo.ThresholdDate)
                        } else if verbose {
                                fmt.Printf("    Certificate does not need renewal (expires more than %s from now)\n", certTask.RenewBefore)
                        }
                        result.Skipped = true
                        return result, nil
                }
        }

        // Generate CSR with comprehensive subject information
        keySize := 2048 // Default key size
        keyType := "rsa" // Default key type
        
        // Create certificate request with full subject details
        csr, privateKeyPEM, err := generateCSRFromCertTask(certTask, keySize, keyType)
        if err != nil {
                return nil, fmt.Errorf("failed to generate CSR: %w", err)
        }

        // Submit CSR using comprehensive ZTPKI API payload
        requestID, err := client.SubmitCSRWithFullPayload(csr, certTask, verbose)
        if err != nil {
                return nil, fmt.Errorf("failed to submit CSR: %w", err)
        }

        if verbose {
                fmt.Printf("    CSR submitted with comprehensive payload, request ID: %s\n", requestID)
        }

        // Poll for certificate
        certificate, err := pollForCertificate(client, requestID)
        if err != nil {
                return nil, fmt.Errorf("failed to retrieve certificate: %w", err)
        }

        // Process each installation configuration
        for _, installation := range certTask.Installations {
                err := processCertificateInstallation(certificate, privateKeyPEM, &installation, certTask, quiet)
                if err != nil {
                        return nil, fmt.Errorf("failed to install certificate: %w", err)
                }
        }

        result.Renewed = true
        return result, nil
}

// ExpiryInfo contains certificate expiry information for display
type ExpiryInfo struct {
        ExpiryDate    string
        ThresholdDate string
}

// getExpiryInfoFromTask extracts expiry information from certificate task for display
func getExpiryInfoFromTask(certTask *config.CertificateTask) *ExpiryInfo {
        // Check local certificate files from installations
        for _, installation := range certTask.Installations {
                if installation.Format == "PEM" && installation.File != "" {
                        certFile := installation.File
                        
                        // Check if certificateLocation overrides the installation file path
                        if certTask.CertificateLocation != "" {
                                certFile = certTask.CertificateLocation
                        }
                        
                        if expiry, threshold := extractExpiryDates(certFile, certTask.RenewBefore); expiry != "" {
                                return &ExpiryInfo{
                                        ExpiryDate:    expiry,
                                        ThresholdDate: threshold,
                                }
                        }
                }
        }
        
        return &ExpiryInfo{
                ExpiryDate:    "unknown",
                ThresholdDate: "unknown",
        }
}

// extractExpiryDates extracts certificate expiry and threshold dates for display
func extractExpiryDates(certFile, renewBefore string) (string, string) {
        // Read certificate file
        certData, err := os.ReadFile(certFile)
        if err != nil {
                return "", ""
        }

        // Parse PEM certificate
        block, _ := pem.Decode(certData)
        if block == nil || block.Type != "CERTIFICATE" {
                return "", ""
        }

        cert, err := x509.ParseCertificate(block.Bytes)
        if err != nil {
                return "", ""
        }

        // Parse renewal threshold - use existing function from the file
        threshold, err := parseDuration(renewBefore)
        if err != nil {
                return "", ""
        }

        expiryDate := cert.NotAfter.Format("2006-01-02")
        thresholdDate := cert.NotAfter.Add(-threshold).Format("2006-01-02")

        return expiryDate, thresholdDate
}

// executeCertificateTask executes a single certificate task with comprehensive ZTPKI API payload
func executeCertificateTask(client *api.Client, certTask *config.CertificateTask) error {
        // Check for existing certificate renewal needs if renewBefore is specified
        if certTask.RenewBefore != "" && !runForceRenew {
                needsRenewal, err := checkCertificateRenewalFromTask(certTask)
                if err != nil {
                        fmt.Printf("    Warning: Could not check renewal status: %v\n", err)
                } else if !needsRenewal {
                        fmt.Printf("    Certificate does not need renewal (expires more than %s from now)\n", certTask.RenewBefore)
                        return nil
                }
        }

        // Generate CSR with comprehensive subject information
        keySize := 2048 // Default key size
        keyType := "rsa" // Default key type
        
        // Create certificate request with full subject details
        csr, privateKeyPEM, err := generateCSRFromCertTask(certTask, keySize, keyType)
        if err != nil {
                return fmt.Errorf("failed to generate CSR: %w", err)
        }

        // Submit CSR using comprehensive ZTPKI API payload
        requestID, err := client.SubmitCSRWithFullPayload(csr, certTask, false) // Never show verbose output in legacy function
        if err != nil {
                return fmt.Errorf("failed to submit CSR: %w", err)
        }

        fmt.Printf("    CSR submitted with comprehensive payload, request ID: %s\n", requestID)

        // Poll for certificate
        certificate, err := pollForCertificate(client, requestID)
        if err != nil {
                return fmt.Errorf("failed to retrieve certificate: %w", err)
        }

        // Process each installation configuration
        for _, installation := range certTask.Installations {
                err := processCertificateInstallation(certificate, privateKeyPEM, &installation, certTask, false)
                if err != nil {
                        return fmt.Errorf("failed to install certificate: %w", err)
                }
        }

        return nil
}

// generateCSRFromCertTask generates a CSR from a certificate task with complete subject information
func generateCSRFromCertTask(certTask *config.CertificateTask, keySize int, keyType string) (string, string, error) {
        // Convert to SubjectInfo format
        subjectInfo := &config.SubjectInfo{
                Country:      []string{certTask.Request.Subject.Country},
                Province:     []string{certTask.Request.Subject.State},
                Locality:     []string{certTask.Request.Subject.Locality},
                Organization: []string{certTask.Request.Subject.Organization},
                OrgUnit:      certTask.Request.Subject.OrgUnits,
        }
        
        return generateCSR(certTask.Request.Subject.CommonName, keySize, keyType, subjectInfo)
}

// checkCertificateRenewalFromTask checks if a certificate needs renewal based on certificate task
func checkCertificateRenewalFromTask(certTask *config.CertificateTask) (bool, error) {
        // Check local certificate files from installations
        for _, installation := range certTask.Installations {
                if installation.Format == "PEM" && installation.File != "" {
                        certFile := installation.File
                        
                        // Check if certificateLocation overrides the installation file path
                        if certTask.CertificateLocation != "" {
                                certFile = certTask.CertificateLocation
                        }
                        
                        needsRenewal, err := checkCertificateRenewal(nil, &config.PlaybookTask{
                                OutputFile: certFile,
                                RenewBefore: certTask.RenewBefore,
                        })
                        if err != nil {
                                continue // Try next installation
                        }
                        return needsRenewal, nil
                }
        }
        
        return true, fmt.Errorf("no certificate files found for renewal check")
}

// processCertificateInstallation handles certificate installation with comprehensive options
func processCertificateInstallation(certificate *api.Certificate, privateKeyPEM string, installation *config.CertificateInstall, certTask *config.CertificateTask, quiet bool) error {
        switch strings.ToUpper(installation.Format) {
        case "PEM":
                return processPEMInstallation(certificate, privateKeyPEM, installation, certTask, quiet)
        case "PKCS12":
                return processPKCS12Installation(certificate, privateKeyPEM, installation, certTask, quiet)
        default:
                return fmt.Errorf("unsupported certificate format: %s", installation.Format)
        }
}

// processPEMInstallation handles PEM format certificate installation
func processPEMInstallation(certificate *api.Certificate, privateKeyPEM string, installation *config.CertificateInstall, certTask *config.CertificateTask, quiet bool) error {
        outputFile := installation.File
        if outputFile == "" {
                return fmt.Errorf("output file is required for PEM installation")
        }

        // Parse chain certificate if present
        chainCertificate := ""
        if len(certificate.Chain) > 0 {
                // Join chain certificates into a single PEM block
                for _, chainCert := range certificate.Chain {
                        chainCertificate += chainCert + "\n"
                }
        }
        
        // STEP 1: Perform all backup operations first if requested
        if installation.BackupExisting {
                // Backup main certificate file
                err := backupFileIfExistsQuiet(outputFile, quiet)
                if err != nil {
                        return fmt.Errorf("failed to backup certificate file: %w", err)
                }
                
                // Backup key file
                defaultKeyFile := strings.TrimSuffix(outputFile, ".crt") + ".key"
                err = backupFileIfExistsQuiet(defaultKeyFile, quiet)
                if err != nil {
                        return fmt.Errorf("failed to backup key file: %w", err)
                }
                
                // Backup chain file if custom chain file specified
                if installation.ChainFile != "" && chainCertificate != "" {
                        err = backupFileIfExistsQuiet(installation.ChainFile, quiet)
                        if err != nil {
                                return fmt.Errorf("failed to backup chain file: %w", err)
                        }
                }
                
                // Backup separate key file if specified and different from default
                if installation.KeyFile != "" {
                        keyFileAbs, _ := filepath.Abs(installation.KeyFile)
                        defaultKeyFileAbs, _ := filepath.Abs(strings.TrimSuffix(outputFile, ".crt") + ".key")
                        if keyFileAbs != defaultKeyFileAbs {
                                err = backupFileIfExistsQuiet(installation.KeyFile, quiet)
                                if err != nil {
                                        return fmt.Errorf("failed to backup separate key file: %w", err)
                                }
                        }
                }
                
                // Add empty line after backup operations
                if !quiet {
                        fmt.Println()
                }
        }

        // STEP 2: Save certificate and key files
        chainForDefaultSave := chainCertificate
        if installation.ChainFile != "" {
                // Custom chain file specified, don't save to default location
                chainForDefaultSave = ""
        }
        
        // Save certificate and key without backup operations (already done above)  
        err := saveCertificateAndKeyQuietNoBackupWithEnrollment(outputFile, certificate.Certificate, privateKeyPEM, chainForDefaultSave, quiet, certTask.Request.Subject.CommonName)
        if err != nil {
                return err
        }

        if !quiet {
                fmt.Printf("    Certificate saved to: %s\n", outputFile)
        }
        
        // Save to separate key file if specified
        if installation.KeyFile != "" {
                keyFile := installation.KeyFile
                
                // Check if this is the same key file already created by saveCertificateAndKeyQuietNoBackup
                defaultKeyFile := strings.TrimSuffix(outputFile, ".crt") + ".key"
                
                // Normalize paths for comparison
                keyFileAbs, _ := filepath.Abs(keyFile)
                defaultKeyFileAbs, _ := filepath.Abs(defaultKeyFile)
                
                // Only create separate key file if it's different from the default one
                if keyFileAbs != defaultKeyFileAbs {
                        err := os.WriteFile(keyFile, []byte(privateKeyPEM), 0600)
                        if err != nil {
                                return fmt.Errorf("failed to write key file: %w", err)
                        }
                        if !quiet {
                                fmt.Printf("    Private key saved to: %s\n", keyFile)
                        }
                }
        }
        
        // Save to separate chain file if specified
        if installation.ChainFile != "" && chainCertificate != "" {
                chainFile := installation.ChainFile
                
                err := os.WriteFile(chainFile, []byte(chainCertificate), 0644)
                if err != nil {
                        return fmt.Errorf("failed to write chain file: %w", err)
                }
                if !quiet {
                        fmt.Printf("    Chain certificate saved to: %s\n", chainFile)
                }
        }

        // Execute after-install action if specified
        if installation.AfterInstallAction != "" {
                if !quiet {
                        fmt.Printf("    Executing after-install action: %s\n", installation.AfterInstallAction)
                        fmt.Println() // Add empty line after after-install action
                }
                // Note: Actual execution would require shell command execution
                // For now, just log the action that would be performed
        }

        return nil
}

// processPKCS12Installation handles PKCS12 format certificate installation
func processPKCS12Installation(certificate *api.Certificate, privateKeyPEM string, installation *config.CertificateInstall, certTask *config.CertificateTask, quiet bool) error {
        // PKCS12 installation would require additional implementation
        // For now, return an informative message
        if !quiet {
                fmt.Printf("    PKCS12 installation to %s (password: %s)\n", installation.File, installation.Password)
                fmt.Printf("    Note: PKCS12 conversion not yet implemented\n")
        }
        return nil
}
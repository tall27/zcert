package cmd

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"zcert/internal/api"
	"zcert/internal/config"
)

// CertificateInfo represents a certificate from the list
type CertificateInfo struct {
	ID     string
	CN     string
	Serial string
}

// parseCertificateList parses the certificate list format
func parseCertificateList(input string) ([]CertificateInfo, error) {
	var certificates []CertificateInfo

	// Regular expression to match the certificate list format
	// Format: [1] ID: 62a64e89-f697-4ba1-847b-75ad0a7df71a, CN: 1.1.1.1, Serial: 3109D7AB32CAB1C33A79BE322135C292903706B8
	re := regexp.MustCompile(`\[\d+\]\s+ID:\s+([a-f0-9-]+),\s+CN:\s+([^,]+),\s+Serial:\s+([A-F0-9]+)`)

	matches := re.FindAllStringSubmatch(input, -1)
	for _, match := range matches {
		if len(match) == 4 {
			cert := CertificateInfo{
				ID:     match[1],
				CN:     strings.TrimSpace(match[2]),
				Serial: match[3],
			}
			certificates = append(certificates, cert)
		}
	}

	return certificates, nil
}

// bulkRevokeCertificates revokes multiple certificates
func bulkRevokeCertificates(certificates []CertificateInfo, reason string, force bool, dryRun bool) error {
	// Get profile configuration
	profile := GetCurrentProfile()
	if profile == nil {
		return fmt.Errorf("no profile configuration found")
	}

	// Create API client
	cfg := &config.Config{
		BaseURL: profile.URL,
		HawkID:  profile.KeyID,
		HawkKey: profile.Secret,
	}

	client, err := api.NewClientWithVerbose(cfg, GetVerboseLevel())
	if err != nil {
		return fmt.Errorf("failed to initialize API client: %w", err)
	}

	fmt.Printf("Found %d certificates to process\n", len(certificates))

	if dryRun {
		fmt.Println("DRY RUN MODE - No certificates will be revoked")
	}

	// Confirmation prompt unless --force is used
	if !force && !dryRun {
		fmt.Printf("\nAbout to revoke %d certificates with reason: %s\n", len(certificates), reason)
		fmt.Print("Are you sure you want to continue? (y/N): ")

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" && response != "yes" {
			fmt.Println("Bulk revocation cancelled.")
			return nil
		}
	}

	// Process each certificate
	successCount := 0
	failedCount := 0
	var failedCerts []string

	for i, cert := range certificates {
		fmt.Printf("[%d/%d] Processing certificate ID: %s, CN: %s, Serial: %s\n",
			i+1, len(certificates), cert.ID, cert.CN, cert.Serial)

		if dryRun {
			fmt.Printf("  [DRY RUN] Would revoke certificate %s\n", cert.ID)
			successCount++
			continue
		}

		// Attempt to revoke the certificate
		err := client.RevokeCertificate(cert.ID, reason)
		if err != nil {
			fmt.Printf("  [ERROR] Failed to revoke certificate %s: %v\n", cert.ID, err)
			failedCount++
			failedCerts = append(failedCerts, fmt.Sprintf("%s (%s)", cert.ID, err.Error()))
		} else {
			fmt.Printf("  [SUCCESS] Certificate %s revoked successfully\n", cert.ID)
			successCount++
		}

		// Add a small delay between requests to avoid overwhelming the API
		if i < len(certificates)-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Summary
	fmt.Printf("\n=== BULK REVOCATION SUMMARY ===\n")
	fmt.Printf("Total certificates processed: %d\n", len(certificates))
	fmt.Printf("Successfully revoked: %d\n", successCount)
	fmt.Printf("Failed to revoke: %d\n", failedCount)

	if failedCount > 0 {
		fmt.Printf("\nFailed certificates:\n")
		for _, failed := range failedCerts {
			fmt.Printf("  - %s\n", failed)
		}
	}

	return nil
}

// runBulkRevoke handles bulk revocation of certificates
func runBulkRevoke(certList string, reason string, force bool, dryRun bool) error {
	// Parse the certificate list
	certificates, err := parseCertificateList(certList)
	if err != nil {
		return fmt.Errorf("failed to parse certificate list: %w", err)
	}

	if len(certificates) == 0 {
		return fmt.Errorf("no certificates found in the provided list")
	}

	// Perform bulk revocation
	return bulkRevokeCertificates(certificates, reason, force, dryRun)
}

// TestBulkRevoke tests the bulk revocation functionality
func TestBulkRevoke() {
	// Example certificate list (you can replace this with your actual list)
	certList := `[1] ID: 62a64e89-f697-4ba1-847b-75ad0a7df71a, CN: 1.1.1.1, Serial: 3109D7AB32CAB1C33A79BE322135C292903706B8
[2] ID: b4a08532-d408-4881-b74d-72f3726974e7, CN: 1.1.1.1, Serial: 3F67DC33123761D4488AC273A3C809A2656EC789
[3] ID: cb70cdde-e8a3-4e98-80cd-c90743237659, CN: 1.1.1.1, Serial: 7356C20EA6CCE7FEE8A6EF5F5700B6FD994EB866`

	fmt.Println("Testing bulk revocation functionality...")

	// Test with dry run first
	err := runBulkRevoke(certList, "superseded", false, true)
	if err != nil {
		fmt.Printf("Error during bulk revocation test: %v\n", err)
		return
	}

	fmt.Println("Bulk revocation test completed successfully!")
}

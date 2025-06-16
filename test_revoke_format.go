package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// convertRevocationReason converts string reason to numeric code expected by ZTPKI
func convertRevocationReason(reason string) int {
	switch reason {
	case "unspecified":
		return 0
	case "keyCompromise":
		return 1
	case "caCompromise":
		return 2
	case "affiliationChanged":
		return 3
	case "superseded":
		return 4
	case "cessationOfOperation":
		return 5
	case "certificateHold":
		return 6
	case "removeFromCRL":
		return 8
	case "privilegeWithdrawn":
		return 9
	case "aaCompromise":
		return 10
	default:
		return 0 // Default to unspecified
	}
}

func main() {
	// Test with the actual certificate ID from your error
	certificateID := "eb3e4ef0-efce-4253-bca3-8c3c44cc3661"
	reason := "unspecified"
	
	// Convert reason string to numeric code
	reasonCode := convertRevocationReason(reason)
	
	// Current time in ISO format for revocationDate
	revocationDate := time.Now().UTC().Format(time.RFC3339)
	
	// ZTPKI revocation request format
	requestBody := map[string]interface{}{
		"revocationReason": reasonCode,
		"revocationDate":   revocationDate,
	}
	
	// Show the exact request format
	fmt.Printf("=== Fixed ZTPKI Revocation API Request ===\n")
	fmt.Printf("PATCH /certificates/%s\n", certificateID)
	
	if payload, err := json.MarshalIndent(requestBody, "", "  "); err == nil {
		fmt.Printf("%s\n", string(payload))
	}
	fmt.Printf("========================================\n")
	
	// Show different reason codes
	fmt.Printf("\nSupported revocation reasons:\n")
	reasons := []string{"unspecified", "keyCompromise", "caCompromise", "superseded"}
	for _, r := range reasons {
		fmt.Printf("  %s -> %d\n", r, convertRevocationReason(r))
	}
}
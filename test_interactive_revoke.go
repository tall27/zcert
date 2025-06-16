package main

import (
	"encoding/json"
	"fmt"
	"time"
)

func main() {
	fmt.Println("=== Interactive Revocation Demo ===")
	fmt.Println("After user confirms revocation, they see:")
	fmt.Println()
	fmt.Println("Select revocation reason:")
	fmt.Println("0. Unspecified")
	fmt.Println("1. Key Compromise") 
	fmt.Println("3. Affiliation Changed")
	fmt.Println("4. Superseded")
	fmt.Println("5. Cessation Of Operation")
	fmt.Println("Enter your choice (0-5): 1")
	fmt.Println()
	
	// Show the API request that would be generated
	requestBody := map[string]interface{}{
		"revocationReason": 1, // Key Compromise
		"revocationDate":   time.Now().UTC().Format(time.RFC3339),
		"reason":           1, // Fallback field name
	}
	
	fmt.Println("=== ZTPKI Revoke API Request ===")
	fmt.Println("PATCH /certificates/{certificate-id}")
	
	if payload, err := json.MarshalIndent(requestBody, "", "  "); err == nil {
		fmt.Printf("%s\n", string(payload))
	}
	fmt.Println("================================")
	fmt.Println()
	fmt.Println("This request includes both 'revocationReason' and 'reason' fields")
	fmt.Println("to ensure compatibility with different ZTPKI API versions.")
}
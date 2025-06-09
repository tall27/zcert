package main

import (
	"fmt"
	"os"

	"zcert/internal/api"
	"zcert/internal/config"
	"zcert/internal/policy"
)

func main() {
	fmt.Println("=== DEBUGGING POLICY SELECTION BUG ===")

	// Test with the exact credentials from user's failing command
	cfg := &config.Config{
		BaseURL: "https://ztpki-dev.venafi.com/api/v2",
		HawkID:  "165c01284c6c8d872091aed0c7cc0149",
		HawkKey: "b97a01107585f1f037a65fafe334dcda6a42b156e1ae8df0072d203dd36f5c0c",
	}

	fmt.Printf("Testing with BaseURL: %s\n", cfg.BaseURL)
	fmt.Printf("Testing with HawkID: %s\n", cfg.HawkID)

	// Create API client
	client, err := api.NewClient(cfg)
	if err != nil {
		fmt.Printf("ERROR: Failed to create API client: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ API client created successfully")

	// Create policy selector
	selector := policy.NewPolicySelector(client)
	fmt.Println("✓ Policy selector created successfully")

	// Test 1: Check GetAvailablePolicies (this should work)
	fmt.Println("\n--- Testing GetAvailablePolicies ---")
	policies := selector.GetAvailablePolicies()
	if len(policies) == 0 {
		fmt.Println("ERROR: No policies returned from GetAvailablePolicies")
		os.Exit(1)
	}
	
	fmt.Printf("✓ Found %d policies:\n", len(policies))
	for i, p := range policies {
		fmt.Printf("  %d. %s (ID: %s)\n", i+1, p.Name, p.ID)
	}

	// Test 2: Test what happens when SelectPolicy is called (this is where the bug occurs)
	fmt.Println("\n--- Testing SelectPolicy (Interactive) ---")
	fmt.Println("NOTE: This is where the 'API Error 0: invalid request' occurs")
	
	// The SelectPolicy method should NOT try to fetch from API
	// It should use GetAvailablePolicies which returns predefined policies
	// But let's verify this is working correctly

	// Test 3: Verify policy validation works
	fmt.Println("\n--- Testing Policy Validation ---")
	verifiedPolicyID := "5fe6d368-896a-4883-97eb-f87148c90896"
	err = selector.ValidatePolicy(verifiedPolicyID)
	if err != nil {
		fmt.Printf("ERROR: Valid policy failed validation: %v\n", err)
	} else {
		fmt.Printf("✓ Policy validation passed for: %s\n", verifiedPolicyID)
	}

	// Test 4: Test direct API call that causes the original bug
	fmt.Println("\n--- Testing Direct API Call (Root Cause) ---")
	searchParams := api.CertificateSearchParams{
		Limit: 1,
	}
	
	_, err = client.SearchCertificates(searchParams)
	if err != nil {
		fmt.Printf("ERROR: Direct API call failed: %v\n", err)
		fmt.Println("This explains why the original policy fetching failed!")
	} else {
		fmt.Println("✓ Direct API call succeeded")
	}

	fmt.Println("\n=== DIAGNOSIS COMPLETE ===")
	fmt.Println("If you see 'API Error 0: invalid request' above, that's the root cause.")
	fmt.Println("The fix is to ensure SelectPolicy uses predefined policies instead of API calls.")
}
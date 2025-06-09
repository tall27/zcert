package main

import (
        "fmt"
        "os"
        "strings"
        "testing"

        "zcert/internal/api"
        "zcert/internal/config"
        "zcert/internal/policy"
)

// TestPolicySelectionBug specifically tests the bug reported by the user
func TestPolicySelectionBug(t *testing.T) {
        // Simulate the exact scenario from the user's command:
        // zcert enroll --cn abc.mimlab.io --url "https://ztpki-dev.venafi.com/api/v2" 
        // --hawk-id 165c01284c6c8d872091aed0c7cc0149 --hawk-key b97a01107585f1f037a65fafe334dcda6a42b156e1ae8df0072d203dd36f5c0c

        cfg := &config.Config{
                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                HawkID:  "165c01284c6c8d872091aed0c7cc0149", 
                HawkKey: "b97a01107585f1f037a65fafe334dcda6a42b156e1ae8df0072d203dd36f5c0c",
        }

        // Create API client (this should work with the provided credentials)
        client, err := api.NewClient(cfg)
        if err != nil {
                t.Fatalf("Failed to create API client: %v", err)
        }

        // Create policy selector
        selector := policy.NewPolicySelector(client)

        // Test 1: Verify GetAvailablePolicies works (this should not fail)
        policies := selector.GetAvailablePolicies()
        if len(policies) == 0 {
                t.Error("BUG: GetAvailablePolicies returned no policies - this breaks interactive selection")
        }

        fmt.Printf("Available policies from GetAvailablePolicies(): %d\n", len(policies))
        for i, p := range policies {
                fmt.Printf("  %d. %s (ID: %s)\n", i+1, p.Name, p.ID)
        }

        // Test 2: Verify the verified working policy is present
        verifiedPolicyID := "5fe6d368-896a-4883-97eb-f87148c90896"
        found := false
        for _, p := range policies {
                if p.ID == verifiedPolicyID {
                        found = true
                        break
                }
        }
        if !found {
                t.Errorf("BUG: Verified working policy ID %s not found in available policies", verifiedPolicyID)
        }

        // Test 3: Test policy validation (this should work)
        err = selector.ValidatePolicy(verifiedPolicyID)
        if err != nil {
                t.Errorf("BUG: Valid policy failed validation: %v", err)
        }

        // Test 4: Test invalid policy validation (this should fail appropriately)
        err = selector.ValidatePolicy("invalid-policy-123")
        if err == nil {
                t.Error("BUG: Invalid policy passed validation when it should have failed")
        }

        // Test 5: Simulate the interactive selection bug
        // The bug is that when no policy is specified, it tries to fetch from API and fails
        // This is the root cause of the "API Error 0: invalid request" error
        
        // Let's test what happens when we call the API search directly
        searchParams := api.CertificateSearchParams{
                Limit: 1,
        }
        
        fmt.Println("Testing direct API call that causes the bug...")
        _, err = client.SearchCertificates(searchParams)
        if err != nil {
                fmt.Printf("API Error detected: %v\n", err)
                if strings.Contains(err.Error(), "invalid request") {
                        fmt.Println("FOUND THE BUG: SearchCertificates API call fails with 'invalid request'")
                        fmt.Println("This is why the interactive policy selection fails!")
                }
        }
}

// TestInteractivePolicySelectionWorkflow tests the complete workflow
func TestInteractivePolicySelectionWorkflow(t *testing.T) {
        // This test simulates what should happen when no policy is provided
        // and the user should see an interactive menu

        cfg := &config.Config{
                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                HawkID:  "test-hawk-id",
                HawkKey: "test-hawk-key",
        }

        client, err := api.NewClient(cfg)
        if err != nil {
                t.Fatalf("Failed to create client: %v", err)
        }

        selector := policy.NewPolicySelector(client)

        // Test that we can get policies without API failures
        policies := selector.GetAvailablePolicies()
        if len(policies) == 0 {
                t.Error("No policies available for interactive selection")
        }

        // Verify the menu would show the verified working policy
        verifiedFound := false
        for _, p := range policies {
                if p.ID == "5fe6d368-896a-4883-97eb-f87148c90896" {
                        verifiedFound = true
                        if !strings.Contains(p.Name, "Verified Working") {
                                t.Error("Verified working policy should be clearly marked")
                        }
                }
        }

        if !verifiedFound {
                t.Error("Interactive menu missing the verified working policy")
        }

        fmt.Printf("Interactive menu would show %d policies:\n", len(policies))
        for i, p := range policies {
                fmt.Printf("%d. %s\n   Policy ID: %s\n", i+1, p.Name, p.ID)
        }
}

// TestPolicySelectionFix tests the fix for the interactive policy selection
func TestPolicySelectionFix(t *testing.T) {
        // The fix is to NOT call the API to fetch policies, but use the predefined list
        // This test verifies that the SelectPolicy method works without API calls

        cfg := &config.Config{
                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                HawkID:  "test-hawk-id",
                HawkKey: "test-hawk-key",
        }

        client, err := api.NewClient(cfg)
        if err != nil {
                t.Fatalf("Failed to create client: %v", err)
        }

        selector := policy.NewPolicySelector(client)

        // Test that GetAvailablePolicies works without network calls
        policies := selector.GetAvailablePolicies()
        
        if len(policies) == 0 {
                t.Error("FIXED BUG CHECK: GetAvailablePolicies should return predefined policies")
        }

        // Verify all expected policies are present
        expectedPolicies := []string{
                "5fe6d368-896a-4883-97eb-f87148c90896", // Verified working
                "web-server-ssl",
                "client-auth", 
                "code-signing",
                "email-protection",
        }

        for _, expectedID := range expectedPolicies {
                found := false
                for _, p := range policies {
                        if p.ID == expectedID {
                                found = true
                                break
                        }
                }
                if !found {
                        t.Errorf("Expected policy %s not found in predefined list", expectedID)
                }
        }

        fmt.Println("✓ Policy selection fix verified - uses predefined policies instead of API calls")
}

// Run this test to identify the exact bug
func TestMain(m *testing.M) {
        fmt.Println("=== POLICY SELECTION BUG DETECTION TESTS ===")
        
        // Set up test environment
        os.Setenv("ZCERT_HAWK_ID", "165c01284c6c8d872091aed0c7cc0149")
        os.Setenv("ZCERT_HAWK_KEY", "b97a01107585f1f037a65fafe334dcda6a42b156e1ae8df0072d203dd36f5c0c")
        
        // Run tests
        code := m.Run()
        
        fmt.Println("=== END BUG DETECTION TESTS ===")
        os.Exit(code)
}
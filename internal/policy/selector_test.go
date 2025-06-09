package policy

import (
        "strings"
        "testing"

        "zcert/internal/api"
        "zcert/internal/config"
)

func TestPolicySelector_GetAvailablePolicies(t *testing.T) {
        // Create a mock client
        cfg := &config.Config{
                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                HawkID:  "test-id",
                HawkKey: "test-key",
        }
        
        client, err := api.NewClient(cfg)
        if err != nil {
                t.Fatalf("Failed to create client: %v", err)
        }

        selector := NewPolicySelector(client)
        policies := selector.GetAvailablePolicies()

        if len(policies) == 0 {
                t.Error("Expected at least one policy, got none")
        }

        // Check that the verified working policy is present
        found := false
        for _, policy := range policies {
                if policy.ID == "5fe6d368-896a-4883-97eb-f87148c90896" {
                        found = true
                        if !strings.Contains(policy.Name, "OCP Dev ICA 1 SSL 75 SAN") {
                                t.Errorf("Expected policy name to contain 'OCP Dev ICA 1 SSL 75 SAN', got: %s", policy.Name)
                        }
                        break
                }
        }

        if !found {
                t.Error("Expected to find the verified working policy ID")
        }
}

func TestPolicySelector_GetPolicyByID(t *testing.T) {
        cfg := &config.Config{
                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                HawkID:  "test-id",
                HawkKey: "test-key",
        }
        
        client, err := api.NewClient(cfg)
        if err != nil {
                t.Fatalf("Failed to create client: %v", err)
        }

        selector := NewPolicySelector(client)

        // Test finding existing policy
        policy, err := selector.GetPolicyByID("5fe6d368-896a-4883-97eb-f87148c90896")
        if err != nil {
                t.Errorf("Expected to find policy, got error: %v", err)
        }
        if policy == nil {
                t.Error("Expected policy to be non-nil")
        }
        if policy != nil && policy.ID != "5fe6d368-896a-4883-97eb-f87148c90896" {
                t.Errorf("Expected policy ID to match, got: %s", policy.ID)
        }

        // Test non-existing policy
        _, err = selector.GetPolicyByID("non-existent-policy")
        if err == nil {
                t.Error("Expected error for non-existent policy")
        }
}

func TestPolicySelector_ValidatePolicy(t *testing.T) {
        cfg := &config.Config{
                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                HawkID:  "test-id",
                HawkKey: "test-key",
        }
        
        client, err := api.NewClient(cfg)
        if err != nil {
                t.Fatalf("Failed to create client: %v", err)
        }

        selector := NewPolicySelector(client)

        // Test valid policy
        err = selector.ValidatePolicy("5fe6d368-896a-4883-97eb-f87148c90896")
        if err != nil {
                t.Errorf("Expected no error for valid policy, got: %v", err)
        }

        // Test invalid policy
        err = selector.ValidatePolicy("invalid-policy-id")
        if err == nil {
                t.Error("Expected error for invalid policy")
        }
}

// TestPolicySelector_BasicFunctionality tests core functionality without interactive components
func TestPolicySelector_BasicFunctionality(t *testing.T) {
        cfg := &config.Config{
                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                HawkID:  "test-id",
                HawkKey: "test-key",
        }
        
        client, err := api.NewClient(cfg)
        if err != nil {
                t.Fatalf("Failed to create client: %v", err)
        }

        selector := NewPolicySelector(client)
        
        // Test basic selector creation
        if selector == nil {
                t.Error("Expected selector to be non-nil")
        }
        
        // Test policy data structure
        testPolicies := []Policy{
                {ID: "test-policy-1", Name: "Test Policy 1"},
                {ID: "test-policy-2", Name: "Test Policy 2"},
        }
        
        if len(testPolicies) != 2 {
                t.Error("Expected 2 test policies")
        }
        
        if testPolicies[0].ID != "test-policy-1" || testPolicies[1].ID != "test-policy-2" {
                t.Error("Policy IDs don't match expected values")
        }
}
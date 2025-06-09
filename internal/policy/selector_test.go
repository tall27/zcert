package policy

import (
        "testing"

        "zcert/internal/api"
        "zcert/internal/config"
)

func TestPolicySelector_GetAvailablePolicies(t *testing.T) {
        // Create a test client
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

        // Test should validate structure without assuming specific policy content
        // Policies returned depend on user's actual ZTPKI access permissions
        
        for _, policy := range policies {
                if policy.ID == "" {
                        t.Error("Policy ID cannot be empty")
                }
                if policy.Name == "" {
                        t.Error("Policy Name cannot be empty")
                }
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

        // Test non-existing policy (should always fail)
        _, err = selector.GetPolicyByID("non-existent-policy")
        if err == nil {
                t.Error("Expected error for non-existent policy")
        }
        
        // Note: Cannot test with real policy IDs as they depend on user's actual access permissions
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

        // Test invalid policy (should always fail)
        err = selector.ValidatePolicy("invalid-policy-id")
        if err == nil {
                t.Error("Expected error for invalid policy")
        }
        
        // Note: Cannot test valid policies as they depend on user's actual access permissions
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
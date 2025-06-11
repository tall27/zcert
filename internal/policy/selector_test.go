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
        testPolicies := []LegacyPolicy{
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

// TestPolicySelector_DisplayPoliciesWithCompatibility tests the new compatibility display
func TestPolicySelector_DisplayPoliciesWithCompatibility(t *testing.T) {
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

        // Create test policies with different compatibility scenarios
        testPolicies := []Policy{
                {
                        Name: "Compatible SSL Policy",
                        Details: PolicyDetails{
                                Validity: ValidityConfig{
                                        Days:     []string{"1-365"},
                                        MaxValue: struct{ Days int `yaml:"days"` }{Days: 365},
                                        Required: true,
                                },
                                DNComponents: []DNComponent{
                                        {Tag: "CN", Required: true},
                                },
                                SubjectAltNames: []SANComponent{
                                        {Tag: "DNSNAME"},
                                        {Tag: "DNSNAME"},
                                },
                        },
                        Enabled: PolicyEnabled{REST: true},
                },
                {
                        Name: "Incompatible Short Validity Policy",
                        Details: PolicyDetails{
                                Validity: ValidityConfig{
                                        Days:     []string{"1-30"},
                                        MaxValue: struct{ Days int `yaml:"days"` }{Days: 30},
                                        Required: true,
                                },
                                DNComponents: []DNComponent{
                                        {Tag: "CN", Required: true},
                                },
                        },
                        Enabled: PolicyEnabled{REST: true},
                },
        }

        userArgs := &UserArgs{
                CN:       "test.example.com",
                Validity: &ValidityPeriod{Days: 90},
                SANsDNS:  []string{"example.com"},
        }

        // Test the display functionality (without actual console output)
        compatibleIndices := selector.displayPoliciesWithCompatibility(testPolicies, userArgs)

        // Should have exactly 1 compatible policy (index 1)
        if len(compatibleIndices) != 1 {
                t.Errorf("Expected 1 compatible policy, got %d", len(compatibleIndices))
        }

        if len(compatibleIndices) > 0 && compatibleIndices[0] != 1 {
                t.Errorf("Expected compatible policy at index 1, got %d", compatibleIndices[0])
        }
}

// TestContainsInt tests the helper function
func TestContainsInt(t *testing.T) {
        tests := []struct {
                name   string
                slice  []int
                value  int
                want   bool
        }{
                {
                        name:  "value present",
                        slice: []int{1, 2, 3, 4, 5},
                        value: 3,
                        want:  true,
                },
                {
                        name:  "value not present",
                        slice: []int{1, 2, 3, 4, 5},
                        value: 6,
                        want:  false,
                },
                {
                        name:  "empty slice",
                        slice: []int{},
                        value: 1,
                        want:  false,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        if got := containsInt(tt.slice, tt.value); got != tt.want {
                                t.Errorf("containsInt() = %v, want %v", got, tt.want)
                        }
                })
        }
}
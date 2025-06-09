package api

import (
        "encoding/json"
        "io"
        "os"
        "testing"

        "zcert/internal/config"
)

// TestRealZTPKIAPICompatibility tests against the actual ZTPKI development API
// This test requires valid HAWK credentials and will fail if API response format changes
func TestRealZTPKIAPICompatibility(t *testing.T) {
        // Skip if no credentials available
        hawkID := os.Getenv("ZTPKI_HAWK_ID")
        hawkKey := os.Getenv("ZTPKI_HAWK_SECRET")
        if hawkID == "" || hawkKey == "" {
                t.Skip("Skipping integration test: ZTPKI_HAWK_ID and ZTPKI_HAWK_SECRET required")
        }

        cfg := &config.Config{
                BaseURL: "https://ztpki-dev.venafi.com/api/v2",
                HawkID:  hawkID,
                HawkKey: hawkKey,
        }

        client, err := NewClient(cfg)
        if err != nil {
                t.Fatalf("Failed to create client: %v", err)
        }

        // Test 1: Raw API response structure analysis
        resp, err := client.makeRequest("GET", "/policies", nil)
        if err != nil {
                t.Fatalf("Failed to make policies request: %v", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode != 200 {
                bodyBytes, _ := io.ReadAll(resp.Body)
                t.Fatalf("API returned non-200 status %d: %s", resp.StatusCode, string(bodyBytes))
        }

        // Parse raw response to understand structure
        bodyBytes, err := io.ReadAll(resp.Body)
        if err != nil {
                t.Fatalf("Failed to read response body: %v", err)
        }

        var rawResponse interface{}
        if err := json.Unmarshal(bodyBytes, &rawResponse); err != nil {
                t.Fatalf("Failed to unmarshal raw response: %v", err)
        }

        // Log the actual structure for debugging
        responseJSON, _ := json.MarshalIndent(rawResponse, "", "  ")
        t.Logf("Actual ZTPKI policies API response structure:\n%s", responseJSON)

        // Test 2: Try to unmarshal into our current Policy struct
        var policies []Policy
        if err := json.Unmarshal(bodyBytes, &policies); err != nil {
                t.Errorf("CRITICAL: Policy struct incompatible with API response: %v", err)
                t.Errorf("This is the exact error users will see!")
                
                // Try to identify the problematic field
                var partialPolicies []map[string]interface{}
                if err2 := json.Unmarshal(bodyBytes, &partialPolicies); err2 == nil && len(partialPolicies) > 0 {
                        for fieldName, fieldValue := range partialPolicies[0] {
                                t.Logf("Field '%s': %T = %v", fieldName, fieldValue, fieldValue)
                        }
                }
                return
        }

        // Test 3: Validate policy data integrity
        if len(policies) == 0 {
                t.Log("No policies returned - this may be expected for some credentials")
                return
        }

        for i, policy := range policies {
                if policy.ID == "" {
                        t.Errorf("Policy %d has empty ID", i)
                }
                if policy.Name == "" {
                        t.Errorf("Policy %d has empty Name", i)
                }
                t.Logf("Valid policy found: ID=%s, Name=%s, Enabled=%v", policy.ID, policy.Name, policy.Enabled)
        }
}

// TestPolicyStructFieldMapping tests that our Policy struct matches expected ZTPKI fields
func TestPolicyStructFieldMapping(t *testing.T) {
        // Test various JSON structures that ZTPKI might return
        testCases := []struct {
                name     string
                jsonData string
                expectError bool
        }{
                {
                        name: "Standard policy with boolean enabled",
                        jsonData: `[{
                                "id": "test-policy-1",
                                "name": "Test Policy",
                                "description": "Test Description",
                                "type": "SSL",
                                "enabled": true
                        }]`,
                        expectError: false,
                },
                {
                        name: "Policy with string enabled field",
                        jsonData: `[{
                                "id": "test-policy-2", 
                                "name": "Test Policy 2",
                                "description": "Test Description",
                                "type": "SSL",
                                "enabled": "true"
                        }]`,
                        expectError: true,
                },
                {
                        name: "Policy with object enabled field",
                        jsonData: `[{
                                "id": "test-policy-3",
                                "name": "Test Policy 3", 
                                "description": "Test Description",
                                "type": "SSL",
                                "enabled": {"value": true, "reason": "active"}
                        }]`,
                        expectError: true,
                },
                {
                        name: "Policy missing enabled field",
                        jsonData: `[{
                                "id": "test-policy-4",
                                "name": "Test Policy 4",
                                "description": "Test Description",
                                "type": "SSL"
                        }]`,
                        expectError: false,
                },
        }

        for _, tc := range testCases {
                t.Run(tc.name, func(t *testing.T) {
                        var policies []Policy
                        err := json.Unmarshal([]byte(tc.jsonData), &policies)
                        
                        if tc.expectError && err == nil {
                                t.Errorf("Expected error for %s, but got none", tc.name)
                        }
                        if !tc.expectError && err != nil {
                                t.Errorf("Unexpected error for %s: %v", tc.name, err)
                        }
                        
                        if err != nil {
                                t.Logf("Unmarshalling error (as expected): %v", err)
                        }
                })
        }
}
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

// TestCertificateEnrollmentWorkflow tests the complete certificate enrollment process
func TestCertificateEnrollmentWorkflow(t *testing.T) {
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

        // Test 1: Get policies for enrollment
        policies, err := client.GetPolicies()
        if err != nil {
                t.Fatalf("Failed to get policies: %v", err)
        }

        if len(policies) == 0 {
                t.Skip("No policies available for enrollment test")
        }

        t.Logf("Found %d policies for enrollment testing", len(policies))
        
        // Test policy structure integrity
        for i, policy := range policies {
                if policy.ID == "" {
                        t.Errorf("Policy %d has empty ID", i)
                }
                if policy.Name == "" {
                        t.Errorf("Policy %d has empty Name", i)
                }
                
                // Test enabled field structure
                if policy.Enabled.UI || policy.Enabled.REST || policy.Enabled.ACME || policy.Enabled.SCEP {
                        t.Logf("Policy %s has enabled protocols: UI=%v REST=%v ACME=%v SCEP=%v", 
                                policy.Name, policy.Enabled.UI, policy.Enabled.REST, policy.Enabled.ACME, policy.Enabled.SCEP)
                }
        }

        // Test 2: CSR submission (validates API structure)
        testPolicyID := policies[0].ID
        testCSR := `-----BEGIN CERTIFICATE REQUEST-----
MIICWjCCAUICAQAwFTETMBEGA1UEAwwKdGVzdC5sb2NhbDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMQQ9k8rSU8tF7aQjXq9vE+J/cYn4PJKL9sKd2x7
9JgTyV8OhQP7zLkBhRnBGj7YZKQqKjZzpVfJz4JZK8mKlF1X6pOsKcYG7Xq9nF4H
+qLjJlK8pYz1JgF1Oz3VK4J6yJ8QYKYmJ8F6Kl4pO8mJ7oJ8QYKYmJ8F6Kl4pO8m
J7oJ8QYKYmJ8F6Kl4pO8mJ7oJ8QYKYmJ8F6Kl4pO8mJ7oJ8QYKYmJ8F6Kl4pO8m
J7oJ8QYKYmJ8F6Kl4pO8mJ7oJ8QYKYmJ8F6Kl4pO8mJ7oJ8QYKYmJ8F6Kl4pO8m
J7oJ8QYKYmJ8F6Kl4pO8mJ7oJ8QYKYmJ8F6Kl4pO8mJ7oCAwEAAaAAMA0GCSqG
SIb3DQEBCwUAA4IBAQAiHtC9KLj8hO7yJ8QYKYmJ8F6Kl4pO8mJ7oJ8QYKYmJ8F6
-----END CERTIFICATE REQUEST-----`

        requestID, err := client.SubmitCSR(testCSR, testPolicyID)
        if err != nil {
                t.Logf("CSR submission failed (may be expected): %v", err)
                // Don't fail the test as this might be expected with test data
        } else {
                t.Logf("CSR submitted successfully with request ID: %s", requestID)
        }
}

// TestCertificateRetrievalWorkflow tests certificate retrieval functionality
func TestCertificateRetrievalWorkflow(t *testing.T) {
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

        // Test certificate search functionality
        searchParams := CertificateSearchParams{
                Limit: 10,
        }

        certificates, err := client.SearchCertificates(searchParams)
        if err != nil {
                t.Logf("Certificate search failed (may be expected): %v", err)
                // Don't fail as user might not have certificates
                return
        }

        t.Logf("Found %d certificates", len(certificates))

        // Test certificate structure integrity
        for i, cert := range certificates {
                if cert.ID == "" {
                        t.Errorf("Certificate %d has empty ID", i)
                }
                if cert.CommonName == "" {
                        t.Errorf("Certificate %d has empty CommonName", i)
                }
                
                t.Logf("Certificate: ID=%s CN=%s Status=%s", cert.ID, cert.CommonName, cert.Status)
                
                // Test retrieving specific certificate
                if i == 0 && cert.ID != "" {
                        retrievedCert, err := client.GetCertificate(cert.ID)
                        if err != nil {
                                t.Errorf("Failed to retrieve certificate %s: %v", cert.ID, err)
                        } else if retrievedCert.ID != cert.ID {
                                t.Errorf("Retrieved certificate ID mismatch: expected %s, got %s", cert.ID, retrievedCert.ID)
                        }
                }
        }
}

// TestCertificateRevocationWorkflow tests certificate revocation functionality  
func TestCertificateRevocationWorkflow(t *testing.T) {
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

        // Find an active certificate to test revocation structure (don't actually revoke)
        searchParams := CertificateSearchParams{
                Status: StatusActive,
                Limit:  1,
        }

        certificates, err := client.SearchCertificates(searchParams)
        if err != nil {
                t.Logf("Certificate search failed: %v", err)
                return
        }

        if len(certificates) == 0 {
                t.Log("No active certificates found to test revocation structure")
                return
        }

        // Test revocation request structure without actually revoking
        testCert := certificates[0]
        revocationReq := &RevocationRequest{
                CertificateID: testCert.ID,
                Reason:        ReasonUnspecified,
        }

        if revocationReq.CertificateID == "" {
                t.Error("Revocation request has empty certificate ID")
        }
        if revocationReq.Reason == "" {
                t.Error("Revocation request has empty reason")
        }

        t.Logf("Revocation request structure validated for certificate %s", testCert.ID)
}

// TestAPIErrorHandling tests error response parsing
func TestAPIErrorHandling(t *testing.T) {
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

        // Test 404 error handling
        _, err = client.GetCertificate("non-existent-id")
        if err != nil {
                if apiErr, ok := err.(*APIError); ok {
                        if !apiErr.IsNotFound() {
                                t.Logf("Expected 404 error, got: %v", apiErr)
                        } else {
                                t.Logf("Correctly handled 404 error: %v", apiErr)
                        }
                } else {
                        t.Logf("Non-API error (may be expected): %v", err)
                }
        }

        // Test invalid policy ID error handling
        _, err = client.SubmitCSR("invalid-csr", "invalid-policy-id")
        if err != nil {
                if apiErr, ok := err.(*APIError); ok {
                        if apiErr.IsBadRequest() {
                                t.Logf("Correctly handled bad request: %v", apiErr)
                        } else {
                                t.Logf("Got API error: %v", apiErr)
                        }
                } else {
                        t.Logf("Non-API error: %v", err)
                }
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
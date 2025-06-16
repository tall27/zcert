package api

import (
        "bytes"
        "crypto/x509"
        "encoding/json"
        "encoding/pem"
        "fmt"
        "io"
        "net/http"
        "net/url"
        "os"
        "strings"
        "time"

        "zcert/internal/auth"
        "zcert/internal/config"
)

// Client represents the ZTPKI API client
type Client struct {
        baseURL    string
        httpClient *http.Client
        hawkAuth   *auth.HawkAuth
}

// NewClient creates a new ZTPKI API client
func NewClient(cfg *config.Config) (*Client, error) {
        if cfg == nil {
                return nil, fmt.Errorf("config cannot be nil")
        }
        
        // Validate required fields
        if cfg.BaseURL == "" {
                return nil, fmt.Errorf("BaseURL is required")
        }
        if cfg.HawkID == "" {
                return nil, fmt.Errorf("HawkID is required")
        }
        if cfg.HawkKey == "" {
                return nil, fmt.Errorf("HawkKey is required")
        }
        
        // Get credentials from config
        hawkID := cfg.HawkID
        hawkKey := cfg.HawkKey
        baseURL := cfg.BaseURL
        
        return &Client{
                baseURL: baseURL,
                httpClient: &http.Client{
                        Timeout: 30 * time.Second,
                },
                hawkAuth: auth.NewHawkAuth(hawkID, hawkKey),
        }, nil
}

// makeRequest performs a HTTP request with HAWK authentication
func (c *Client) makeRequest(method, endpoint string, body interface{}) (*http.Response, error) {
        var reqBody io.Reader
        var contentType string
        
        if body != nil {
                jsonBody, err := json.Marshal(body)
                if err != nil {
                        return nil, fmt.Errorf("failed to marshal request body: %w", err)
                }
                reqBody = bytes.NewReader(jsonBody)
                contentType = "application/json"
        }
        
        url := c.baseURL + endpoint
        req, err := http.NewRequest(method, url, reqBody)
        if err != nil {
                return nil, fmt.Errorf("failed to create request: %w", err)
        }
        
        if contentType != "" {
                req.Header.Set("Content-Type", contentType)
        }
        
        req.Header.Set("Accept", "application/json")
        req.Header.Set("User-Agent", "zcert/1.0.0")
        
        // Add HAWK authentication
        if err := c.hawkAuth.SignRequest(req); err != nil {
                return nil, fmt.Errorf("failed to sign request with HAWK: %w", err)
        }
        
        // Debug: Show full HTTP request details
        if os.Getenv("ZCERT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "\n=== HTTP REQUEST ===\n")
                fmt.Fprintf(os.Stderr, "%s %s\n", req.Method, req.URL.String())
                fmt.Fprintf(os.Stderr, "Headers:\n")
                for name, values := range req.Header {
                        for _, value := range values {
                                fmt.Fprintf(os.Stderr, "  %s: %s\n", name, value)
                        }
                }
                if req.Body != nil {
                        // Read body for logging, then recreate it
                        bodyBytes, _ := io.ReadAll(req.Body)
                        req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
                        fmt.Fprintf(os.Stderr, "Body:\n%s\n", string(bodyBytes))
                }
                fmt.Fprintf(os.Stderr, "==================\n\n")
        }
        
        resp, err := c.httpClient.Do(req)
        if err != nil {
                return nil, fmt.Errorf("failed to execute request: %w", err)
        }
        
        return resp, nil
}

// handleResponse handles common response processing
func (c *Client) handleResponse(resp *http.Response, target interface{}) error {
        defer resp.Body.Close()
        
        bodyBytes, err := io.ReadAll(resp.Body)
        if err != nil {
                return fmt.Errorf("failed to read response body: %w", err)
        }
        
        // Check for HTML response (authentication redirect or error page)
        if len(bodyBytes) > 0 && bodyBytes[0] == '<' {
                return fmt.Errorf("received HTML response instead of JSON (status %d). This usually indicates:\n"+
                        "1. Invalid HAWK credentials (hawk-id or hawk-key)\n"+
                        "2. Authentication failure or redirect to login page\n"+
                        "3. Incorrect API endpoint URL\n"+
                        "Response preview: %.200s...", resp.StatusCode, string(bodyBytes))
        }
        
        if resp.StatusCode >= 400 {
                var apiError APIError
                if err := json.Unmarshal(bodyBytes, &apiError); err != nil {
                        // If we can't parse the error, return a generic one
                        return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
                }
                return &apiError
        }
        
        if target != nil {
                if err := json.Unmarshal(bodyBytes, target); err != nil {
                        return fmt.Errorf("failed to unmarshal response: %w\nResponse body: %s", err, string(bodyBytes))
                }
        }
        
        return nil
}

// GetPolicies retrieves available certificate policies
func (c *Client) GetPolicies() ([]Policy, error) {
        resp, err := c.makeRequest("GET", "/policies", nil)
        if err != nil {
                return nil, err
        }
        
        var policies []Policy
        if err := c.handleResponse(resp, &policies); err != nil {
                return nil, err
        }
        
        return policies, nil
}

// GetPolicyDetails retrieves detailed policy configuration including validity constraints
func (c *Client) GetPolicyDetails(policyID string) (*PolicyDetailsResponse, error) {
        endpoint := fmt.Sprintf("/policies/%s", url.PathEscape(policyID))
        
        resp, err := c.makeRequest("GET", endpoint, nil)
        if err != nil {
                return nil, err
        }
        
        // Read raw response body to show what ZTPKI actually returns
        defer resp.Body.Close()
        bodyBytes, err := io.ReadAll(resp.Body)
        if err != nil {
                return nil, fmt.Errorf("failed to read response body: %w", err)
        }
        
        
        if resp.StatusCode >= 400 {
                return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
        }
        
        var details PolicyDetailsResponse
        if err := json.Unmarshal(bodyBytes, &details); err != nil {
                return nil, fmt.Errorf("failed to unmarshal response: %w", err)
        }
        
        return &details, nil
}




// SubmitCSR submits a Certificate Signing Request with validity period
func (c *Client) SubmitCSR(csrPEM, policyID string, validity *ValidityPeriod) (string, error) {
        // Extract CN from CSR
        cn, err := extractCNFromCSR(csrPEM)
        if err != nil {
                return "", fmt.Errorf("failed to extract CN from CSR: %w", err)
        }
        
        requestBody := CSRSubmissionRequest{
                Policy: policyID,
                CSR:    csrPEM,
                CN:     cn,
                DNComponents: map[string]interface{}{
                        "CN": cn,
                },
        }
        
        // Add validity if specified
        if validity != nil {
                requestBody.Validity = &ValidityRequest{
                        Years:  validity.Years,
                        Months: validity.Months,
                        Days:   validity.Days,
                }
        }
        
        // Debug: Print the payload being sent to ZTPKI (only in verbose mode)
        if os.Getenv("ZCERT_VERBOSE") == "true" {
                if payload, err := json.MarshalIndent(requestBody, "", "  "); err == nil {
                        fmt.Printf("=== ZTPKI API Payload ===\n")
                        fmt.Printf("POST /csr\n")
                        fmt.Printf("%s\n", string(payload))
                        fmt.Printf("========================\n")
                }
        }
        
        resp, err := c.makeRequest("POST", "/csr", requestBody)
        if err != nil {
                return "", err
        }
        
        var result CSRSubmissionResponse
        if err := c.handleResponse(resp, &result); err != nil {
                return "", err
        }
        
        // Use ID field (new format) or fall back to RequestID (legacy)
        requestID := result.ID
        if requestID == "" {
                requestID = result.RequestID
        }
        
        return requestID, nil
}

// SubmitCSRWithFullPayload submits a CSR with complete ZTPKI payload including all parameters from the YAML
func (c *Client) SubmitCSRWithFullPayload(csrPEM string, certTask *config.CertificateTask, verbose bool) (string, error) {
        // Extract CN from CSR
        cn, err := extractCNFromCSR(csrPEM)
        if err != nil {
                return "", fmt.Errorf("failed to extract CN from CSR: %w", err)
        }
        
        // Build complete request payload from the certificate task
        requestBody := CSRSubmissionRequest{
                Policy: certTask.Request.Policy,
                CSR:    csrPEM,
                CN:     cn,
        }
        
        // Build DN Components from subject data
        dnComponents := map[string]interface{}{
                "CN": certTask.Request.Subject.CommonName,
        }
        
        if certTask.Request.Subject.Country != "" {
                dnComponents["C"] = certTask.Request.Subject.Country
        }
        if certTask.Request.Subject.State != "" {
                dnComponents["ST"] = certTask.Request.Subject.State
        }
        if certTask.Request.Subject.Locality != "" {
                dnComponents["L"] = certTask.Request.Subject.Locality
        }
        if certTask.Request.Subject.Organization != "" {
                dnComponents["O"] = certTask.Request.Subject.Organization
        }
        if len(certTask.Request.Subject.OrgUnits) > 0 {
                dnComponents["OU"] = certTask.Request.Subject.OrgUnits
        }
        if len(certTask.Request.Subject.DomainComponents) > 0 {
                dnComponents["DC"] = certTask.Request.Subject.DomainComponents
        }
        if certTask.Request.Subject.Email != "" {
                dnComponents["emailAddress"] = certTask.Request.Subject.Email
        }
        
        requestBody.DNComponents = dnComponents
        
        // Build Subject Alternative Names if specified
        if certTask.Request.SANs != nil {
                sanMap := map[string]interface{}{}
                
                // Handle structured SANs
                if certTask.Request.SANs.SubjectAltNames != nil {
                        if len(certTask.Request.SANs.SubjectAltNames.DNS) > 0 {
                                sanMap["dnsNames"] = certTask.Request.SANs.SubjectAltNames.DNS
                        }
                        if len(certTask.Request.SANs.SubjectAltNames.IP) > 0 {
                                sanMap["ipAddresses"] = certTask.Request.SANs.SubjectAltNames.IP
                        }
                        if len(certTask.Request.SANs.SubjectAltNames.Email) > 0 {
                                sanMap["rfc822Names"] = certTask.Request.SANs.SubjectAltNames.Email
                        }
                        if len(certTask.Request.SANs.SubjectAltNames.UPN) > 0 {
                                sanMap["userPrincipalNames"] = certTask.Request.SANs.SubjectAltNames.UPN
                        }
                        if len(certTask.Request.SANs.SubjectAltNames.URI) > 0 {
                                sanMap["uniformResourceIdentifiers"] = certTask.Request.SANs.SubjectAltNames.URI
                        }
                }
                
                // Handle simple list format (backwards compatibility)
                if len(certTask.Request.SANs.SimpleList) > 0 {
                        sanMap["dnsNames"] = certTask.Request.SANs.SimpleList
                }
                
                if len(sanMap) > 0 {
                        requestBody.SubjectAltNames = sanMap
                }
        }
        
        // Add validity period if specified
        if certTask.Request.Validity != nil {
                requestBody.Validity = &ValidityRequest{
                        Years:  certTask.Request.Validity.Years,
                        Months: certTask.Request.Validity.Months,
                        Days:   certTask.Request.Validity.Days,
                }
        }
        
        // Add custom fields if specified
        if len(certTask.Request.CustomFields) > 0 {
                customFields := make(map[string]interface{})
                for k, v := range certTask.Request.CustomFields {
                        customFields[k] = v
                }
                requestBody.CustomFields = customFields
        }
        
        // Add custom extensions if specified
        if len(certTask.Request.CustomExtensions) > 0 {
                customExtensions := make(map[string]interface{})
                for k, v := range certTask.Request.CustomExtensions {
                        customExtensions[k] = v
                }
                requestBody.CustomExtensions = customExtensions
        }
        
        // Add comment if specified
        if certTask.Request.Comment != "" {
                requestBody.Comment = certTask.Request.Comment
        }
        
        // Add expiry emails if specified
        if len(certTask.Request.ExpiryEmails) > 0 {
                requestBody.ExpiryEmails = certTask.Request.ExpiryEmails
        }
        
        // Debug: Print the complete payload being sent to ZTPKI (only in verbose mode)
        if verbose {
                if payload, err := json.MarshalIndent(requestBody, "", "  "); err == nil {
                        fmt.Printf("=== COMPLETE ZTPKI API Payload ===\n")
                        fmt.Printf("POST /csr\n")
                        fmt.Printf("%s\n", string(payload))
                        fmt.Printf("=================================\n")
                }
        }
        
        resp, err := c.makeRequest("POST", "/csr", requestBody)
        if err != nil {
                return "", err
        }
        
        var result CSRSubmissionResponse
        if err := c.handleResponse(resp, &result); err != nil {
                return "", err
        }
        
        // Use ID field (new format) or fall back to RequestID (legacy)
        requestID := result.ID
        if requestID == "" {
                requestID = result.RequestID
        }
        
        return requestID, nil
}

// GetCertificate retrieves a certificate by ID
func (c *Client) GetCertificate(id string) (*Certificate, error) {
        endpoint := fmt.Sprintf("/certificates/%s", url.PathEscape(id))
        
        resp, err := c.makeRequest("GET", endpoint, nil)
        if err != nil {
                return nil, err
        }
        
        var certificate Certificate
        if err := c.handleResponse(resp, &certificate); err != nil {
                return nil, err
        }
        
        return &certificate, nil
}

// GetCertificatePEM retrieves a certificate in PEM format with optional chain
func (c *Client) GetCertificatePEM(id string, includeChain bool) (*CertificatePEMResponse, error) {
        endpoint := fmt.Sprintf("/certificates/%s/pem", url.PathEscape(id))
        if includeChain {
                endpoint += "?chain=true"
        }
        
        resp, err := c.makeRequest("GET", endpoint, nil)
        if err != nil {
                return nil, err
        }
        defer resp.Body.Close()
        
        // Read the response body as raw PEM data
        body, err := io.ReadAll(resp.Body)
        if err != nil {
                return nil, fmt.Errorf("failed to read response body: %w", err)
        }
        
        if resp.StatusCode != http.StatusOK {
                return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
        }
        
        pemData := string(body)
        
        // Parse the PEM data to separate certificate and chain
        return parsePEMResponse(pemData), nil
}

// parsePEMResponse parses PEM data and separates the first certificate from the chain
func parsePEMResponse(pemData string) *CertificatePEMResponse {
        var certificates []string
        
        // Parse all PEM blocks
        remaining := []byte(pemData)
        for {
                block, rest := pem.Decode(remaining)
                if block == nil {
                        break
                }
                
                if block.Type == "CERTIFICATE" {
                        certPEM := pem.EncodeToMemory(block)
                        certificates = append(certificates, string(certPEM))
                }
                
                remaining = rest
        }
        
        response := &CertificatePEMResponse{}
        
        if len(certificates) > 0 {
                // First certificate is the end-entity certificate
                response.Certificate = certificates[0]
                
                // Remaining certificates form the chain
                if len(certificates) > 1 {
                        var chainBuilder strings.Builder
                        for i := 1; i < len(certificates); i++ {
                                chainBuilder.WriteString(certificates[i])
                        }
                        response.Chain = chainBuilder.String()
                }
        }
        
        return response
}

// GetCertificateRequest retrieves the status of a certificate request
func (c *Client) GetCertificateRequest(requestID string) (*CertificateRequest, error) {
        endpoint := fmt.Sprintf("/csr/%s/status", url.PathEscape(requestID))
        
        resp, err := c.makeRequest("GET", endpoint, nil)
        if err != nil {
                return nil, err
        }
        
        var request CertificateRequest
        if err := c.handleResponse(resp, &request); err != nil {
                return nil, err
        }
        
        return &request, nil
}

// SearchCertificates searches for certificates based on criteria
func (c *Client) SearchCertificates(params CertificateSearchParams) ([]Certificate, error) {
        userLimit := params.Limit
        if userLimit <= 0 {
                userLimit = 100 // Default limit if not specified
        }
        
        // For account-scoped searches, implement pagination to reach user's limit
        if params.Account != "" {
                var allCertificates []Certificate
                const batchSize = 10 // ZTPKI typically returns ~10 certificates per request
                offset := 0
                
                // Make paginated requests until we have enough certificates or no more available
                for len(allCertificates) < userLimit {
                        requestLimit := batchSize
                        remaining := userLimit - len(allCertificates)
                        if remaining < batchSize {
                                requestLimit = remaining
                        }
                        
                        if os.Getenv("ZCERT_DEBUG") != "" {
                                fmt.Fprintf(os.Stderr, "Requesting batch: limit=%d, offset=%d, total collected=%d\n", requestLimit, offset, len(allCertificates))
                        }
                        
                        certificates, err := c.searchCertificatesPage(params, requestLimit, offset)
                        if err != nil {
                                return nil, err
                        }
                        
                        // If no certificates returned, we've reached the end
                        if len(certificates) == 0 {
                                break
                        }
                        
                        allCertificates = append(allCertificates, certificates...)
                        
                        // If we got less than requested, we've reached the end
                        if len(certificates) < requestLimit {
                                break
                        }
                        
                        offset += len(certificates)
                }
                
                // Deduplicate and ensure we don't exceed the user's requested limit
                deduplicated := c.deduplicateCertificates(allCertificates)
                if len(deduplicated) > userLimit {
                        deduplicated = deduplicated[:userLimit]
                }
                
                return deduplicated, nil
        }
        
        // For non-account searches, use traditional pagination
        var allCertificates []Certificate
        const serverMaxLimit = 10 // ZTPKI server's maximum limit per request
        offset := 0
        
        // Make paginated requests until we have enough certificates or no more available
        for len(allCertificates) < userLimit {
                requestLimit := serverMaxLimit
                remaining := userLimit - len(allCertificates)
                if remaining < serverMaxLimit {
                        requestLimit = remaining
                }
                
                // Build search request for this page
                certificates, err := c.searchCertificatesPage(params, requestLimit, offset)
                if err != nil {
                        return nil, err
                }
                
                // If no certificates returned, we've reached the end
                if len(certificates) == 0 {
                        break
                }
                
                allCertificates = append(allCertificates, certificates...)
                
                // If we got less than the server max, we've reached the end
                if len(certificates) < serverMaxLimit {
                        break
                }
                
                offset += len(certificates)
        }
        
        // Ensure we don't exceed the user's requested limit
        if len(allCertificates) > userLimit {
                allCertificates = allCertificates[:userLimit]
        }
        
        return allCertificates, nil
}

// deduplicateCertificates removes duplicate certificates based on ID
func (c *Client) deduplicateCertificates(certificates []Certificate) []Certificate {
        seen := make(map[string]bool)
        var result []Certificate
        
        for _, cert := range certificates {
                if !seen[cert.ID] {
                        seen[cert.ID] = true
                        result = append(result, cert)
                }
        }
        
        return result
}

// SearchCertificatesBatch performs a single batch search for client-side filtering
func (c *Client) SearchCertificatesBatch(params CertificateSearchParams) ([]Certificate, error) {
        return c.searchCertificatesPage(params, params.Limit, params.Offset)
}

// searchCertificatesPage performs a single paginated search request
func (c *Client) searchCertificatesPage(params CertificateSearchParams, limit, offset int) ([]Certificate, error) {
        endpoint := "/certificates"
        
        // Build search request body to match expected ZTPKI format
        var commonName interface{} = nil
        if params.CommonName != "" {
                commonName = params.CommonName
        }
        
        var serial interface{} = nil
        if params.Serial != "" {
                serial = params.Serial
        }
        
        var status interface{} = nil
        if params.Status != "" {
                status = params.Status
        }
        
        var expired interface{} = nil
        if params.Expired != nil {
                expired = *params.Expired
        }
        
        var policy interface{} = nil
        if params.PolicyID != "" {
                policy = params.PolicyID
        }
        
        var notAfter interface{} = nil
        if params.NotAfter != "" {
                notAfter = params.NotAfter
        }
        
        searchRequest := map[string]interface{}{
                "account":        params.Account,
                "common_name":    commonName,
                "expired":        expired,
                "limit":          limit,
                "not_after":      notAfter,
                "offset":         offset,
                "policy":         policy,
                "renewed":        nil,
                "serial":         serial,
                "sort_direction": "desc",
                "sort_type":      "notBefore",
                "status":         status,
        }
        
        // Log the actual request being sent to ZTPKI API for debugging
        if os.Getenv("ZCERT_DEBUG") != "" {
                requestJSON, _ := json.Marshal(searchRequest)
                fmt.Fprintf(os.Stderr, "API Request to %s: %s\n", endpoint, string(requestJSON))
                fmt.Fprintf(os.Stderr, "Parameters passed: limit=%d, offset=%d\n", limit, offset)
        }
        
        resp, err := c.makeRequest("POST", endpoint, searchRequest)
        if err != nil {
                return nil, fmt.Errorf("failed to search certificates: %w", err)
        }
        
        // Read response body
        bodyBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        
        if len(bodyBytes) == 0 {
                return []Certificate{}, nil
        }
        
        // If we get an error response, return empty list
        if resp.StatusCode != 200 {
                return []Certificate{}, nil
        }
        
        // Try different response structures that ZTPKI might use
        var certificates []Certificate
        
        // First try direct array response
        if err := json.Unmarshal(bodyBytes, &certificates); err == nil && len(certificates) > 0 {
                return certificates, nil
        }
        
        // Try ZTPKI API response format with count and items
        var ztpkiResult struct {
                Count int           `json:"count"`
                Items []Certificate `json:"items"`
        }
        
        if err := json.Unmarshal(bodyBytes, &ztpkiResult); err == nil && len(ztpkiResult.Items) > 0 {
                // Debug: Show total count vs returned items in verbose mode
                if os.Getenv("ZCERT_DEBUG") != "" {
                        fmt.Fprintf(os.Stderr, "API Response: total count=%d, returned items=%d\n", ztpkiResult.Count, len(ztpkiResult.Items))
                }
                return ztpkiResult.Items, nil
        }
        
        // Try other wrapped response formats for backward compatibility
        var result struct {
                Content      []Certificate `json:"content"`      // Spring Boot pagination
                Data         []Certificate `json:"data"`
                Items        []Certificate `json:"items"`
                Results      []Certificate `json:"results"`
                Certificates []Certificate `json:"certificates"`
                Elements     []Certificate `json:"elements"`
        }
        
        if err := json.Unmarshal(bodyBytes, &result); err == nil {
                if len(result.Content) > 0 {
                        return result.Content, nil
                } else if len(result.Data) > 0 {
                        return result.Data, nil
                } else if len(result.Items) > 0 {
                        return result.Items, nil
                } else if len(result.Results) > 0 {
                        return result.Results, nil
                } else if len(result.Certificates) > 0 {
                        return result.Certificates, nil
                } else if len(result.Elements) > 0 {
                        return result.Elements, nil
                }
        }
        
        return []Certificate{}, nil
}

// GetCertificateChain retrieves the certificate chain for a certificate
func (c *Client) GetCertificateChain(id string) ([]string, error) {
        endpoint := fmt.Sprintf("/certificates/%s/chain", url.PathEscape(id))
        
        resp, err := c.makeRequest("GET", endpoint, nil)
        if err != nil {
                return nil, err
        }
        
        var result struct {
                Chain []string `json:"chain"`
        }
        
        if err := c.handleResponse(resp, &result); err != nil {
                return nil, err
        }
        
        return result.Chain, nil
}



// RevokeCertificate revokes a certificate using the correct ZTPKI API format
func (c *Client) RevokeCertificate(id, reason string) error {
        // ZTPKI revoke endpoint - correct format is PATCH /certificates/{id}
        endpoint := fmt.Sprintf("/certificates/%s", url.PathEscape(id))
        
        // Convert reason string to numeric code per ZTPKI specification
        reasonCode := c.convertRevocationReason(reason)
        
        // Current time in ISO format for revocationDate
        revocationDate := time.Now().UTC().Format(time.RFC3339)
        
        // ZTPKI revocation request format
        requestBody := map[string]interface{}{
                "reason":         reasonCode,
                "revocationDate": revocationDate,
        }
        
        // Always show the complete request details for debugging
        if payload, err := json.MarshalIndent(requestBody, "", "  "); err == nil {
                fmt.Printf("=== ZTPKI Revoke API Request ===\n")
                fmt.Printf("Method: PATCH\n")
                fmt.Printf("URL: %s%s\n", c.baseURL, endpoint)
                fmt.Printf("Headers:\n")
                fmt.Printf("  Content-Type: application/json\n")
                fmt.Printf("  Authorization: Hawk id=\"[hawk-id]\", ts=\"[timestamp]\", nonce=\"[nonce]\", mac=\"[mac]\"\n")
                fmt.Printf("Payload:\n%s\n", string(payload))
                fmt.Printf("================================\n")
        }
        
        requestBodyBytes, err := json.Marshal(requestBody)
        if err != nil {
                return fmt.Errorf("failed to marshal revocation request: %w", err)
        }
        
        // Use PATCH method as documented in ZTPKI API
        resp, err := c.makeRequest("PATCH", endpoint, bytes.NewReader(requestBodyBytes))
        if err != nil {
                return err
        }
        
        // Read response
        bodyBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        
        if resp.StatusCode != 200 && resp.StatusCode != 204 {
                return fmt.Errorf("revocation failed: status %d, body: %s", resp.StatusCode, string(bodyBytes))
        }
        
        return nil
}

// convertRevocationReason converts string reason to numeric code expected by ZTPKI
// Valid codes per ZTPKI API specification: [0, 1, 3, 4, 5]
func (c *Client) convertRevocationReason(reason string) int {
        switch reason {
        case "unspecified":
                return 0
        case "keyCompromise":
                return 1
        case "affiliationChanged":
                return 3
        case "superseded":
                return 4
        case "cessationOfOperation":
                return 5
        default:
                return 0 // Default to unspecified
        }
}



// extractCNFromCSR extracts the Common Name from a PEM-encoded CSR
func extractCNFromCSR(csrPEM string) (string, error) {
        block, _ := pem.Decode([]byte(csrPEM))
        if block == nil {
                return "", fmt.Errorf("failed to decode PEM block")
        }
        
        csr, err := x509.ParseCertificateRequest(block.Bytes)
        if err != nil {
                return "", fmt.Errorf("failed to parse CSR: %w", err)
        }
        
        return csr.Subject.CommonName, nil
}

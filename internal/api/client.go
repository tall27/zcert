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
        
        // Debug: Log request details (remove in production)
        fmt.Printf("Debug: Making %s request to %s\n", method, url)
        fmt.Printf("Debug: Authorization header: %s\n", req.Header.Get("Authorization"))
        
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
        // ZTPKI uses POST /certificates for search according to the Swagger documentation
        endpoint := "/certificates"
        
        // Build search request body based on ZTPKI API specification
        searchRequest := map[string]interface{}{
                "limit":  100,
                "offset": 0,
        }
        
        // Add search filters if provided
        if params.CommonName != "" {
                searchRequest["common_name"] = params.CommonName
        }
        if params.Serial != "" {
                searchRequest["serial"] = params.Serial
        }
        if params.Status != "" {
                searchRequest["status"] = params.Status
        }
        if params.PolicyID != "" {
                searchRequest["policy"] = params.PolicyID
        }
        if params.NotAfter != "" {
                searchRequest["not_after"] = params.NotAfter
        }
        if params.NotBefore != "" {
                searchRequest["not_before"] = params.NotBefore
        }
        
        requestBody, err := json.Marshal(searchRequest)
        if err != nil {
                return nil, fmt.Errorf("failed to marshal search request: %w", err)
        }
        

        
        resp, err := c.makeRequest("POST", endpoint, bytes.NewReader(requestBody))
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
        
        // Try wrapped response formats based on typical pagination responses
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



// RevokeCertificate revokes a certificate
func (c *Client) RevokeCertificate(id, reason string) error {
        // ZTPKI revoke endpoint format - try both possible formats
        endpoint := fmt.Sprintf("/certificates/%s/revoke", url.PathEscape(id))
        
        // Try with minimal request body first
        requestBody := map[string]string{
                "reason": reason,
        }
        
        requestBodyBytes, err := json.Marshal(requestBody)
        if err != nil {
                return fmt.Errorf("failed to marshal revocation request: %w", err)
        }
        
        resp, err := c.makeRequest("POST", endpoint, bytes.NewReader(requestBodyBytes))
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

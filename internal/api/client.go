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
        
        // Enable HAWK debug for troubleshooting (disabled for production)
        // req.Header.Set("X-Debug-HAWK", "true")
        req.Header.Set("Accept", "application/json")
        req.Header.Set("User-Agent", "zcert/1.0.0")
        
        // Add HAWK authentication
        if err := c.hawkAuth.SignRequest(req); err != nil {
                return nil, fmt.Errorf("failed to sign request with HAWK: %w", err)
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
                        return fmt.Errorf("failed to unmarshal response: %w", err)
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



// SubmitCSR submits a Certificate Signing Request
func (c *Client) SubmitCSR(csrPEM, policyID string) (string, error) {
        // Extract DN components from CSR
        dnComponents, err := extractDNFromCSR(csrPEM)
        if err != nil {
                return "", fmt.Errorf("failed to extract DN components from CSR: %w", err)
        }
        
        requestBody := CSRSubmissionRequest{
                CSR:          csrPEM,
                Policy:       policyID,
                DNComponents: dnComponents,
        }
        
        resp, err := c.makeRequest("POST", "/csr", requestBody)
        if err != nil {
                return "", err
        }
        
        // Read response body to debug the actual structure
        bodyBytes, err := io.ReadAll(resp.Body)
        if err != nil {
                return "", fmt.Errorf("failed to read response body: %w", err)
        }
        resp.Body.Close()
        
        if resp.StatusCode >= 400 {
                var apiError APIError
                if err := json.Unmarshal(bodyBytes, &apiError); err != nil {
                        return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
                }
                return "", &apiError
        }
        
        // Try to parse as a generic map first to see actual field names
        var rawResult map[string]interface{}
        if err := json.Unmarshal(bodyBytes, &rawResult); err != nil {
                return "", fmt.Errorf("failed to unmarshal response: %w", err)
        }
        
        // Look for common field names that might contain the request ID
        if requestID, ok := rawResult["requestId"].(string); ok && requestID != "" {
                return requestID, nil
        }
        if requestID, ok := rawResult["id"].(string); ok && requestID != "" {
                return requestID, nil
        }
        if requestID, ok := rawResult["certificateId"].(string); ok && requestID != "" {
                return requestID, nil
        }
        if requestID, ok := rawResult["trackingId"].(string); ok && requestID != "" {
                return requestID, nil
        }
        
        return "", fmt.Errorf("no valid request ID found in response: %s", string(bodyBytes))
}

// extractDNFromCSR extracts Distinguished Name components from a PEM-encoded CSR
func extractDNFromCSR(csrPEM string) (map[string]interface{}, error) {
        block, _ := pem.Decode([]byte(csrPEM))
        if block == nil || block.Type != "CERTIFICATE REQUEST" {
                return nil, fmt.Errorf("invalid PEM format or not a certificate request")
        }
        
        csr, err := x509.ParseCertificateRequest(block.Bytes)
        if err != nil {
                return nil, fmt.Errorf("failed to parse certificate request: %w", err)
        }
        
        dnComponents := make(map[string]interface{})
        
        // Extract common DN components
        if csr.Subject.CommonName != "" {
                dnComponents["CN"] = csr.Subject.CommonName
        }
        
        if len(csr.Subject.Organization) > 0 {
                dnComponents["O"] = csr.Subject.Organization[0]
        }
        
        if len(csr.Subject.OrganizationalUnit) > 0 {
                dnComponents["OU"] = csr.Subject.OrganizationalUnit[0]
        }
        
        if len(csr.Subject.Locality) > 0 {
                dnComponents["L"] = csr.Subject.Locality[0]
        }
        
        if len(csr.Subject.Province) > 0 {
                dnComponents["ST"] = csr.Subject.Province[0]
        }
        
        if len(csr.Subject.Country) > 0 {
                dnComponents["C"] = csr.Subject.Country[0]
        }
        
        return dnComponents, nil
}

// GetCertificate retrieves a certificate by CSR request ID
func (c *Client) GetCertificate(requestId string) (*Certificate, error) {
        // First check if the certificate is issued
        statusEndpoint := fmt.Sprintf("/csr/%s/status", url.PathEscape(requestId))
        statusResp, err := c.makeRequest("GET", statusEndpoint, nil)
        if err != nil {
                return nil, fmt.Errorf("failed to check certificate status: %w", err)
        }
        
        var status CSRStatus
        if err := c.handleResponse(statusResp, &status); err != nil {
                return nil, fmt.Errorf("failed to parse certificate status: %w", err)
        }
        
        if status.IssuanceStatus != "ISSUED" {
                return nil, fmt.Errorf("certificate not yet issued, status: %s", status.IssuanceStatus)
        }
        
        // Retrieve the issued certificate metadata
        certEndpoint := fmt.Sprintf("/csr/%s/certificate", url.PathEscape(requestId))
        certResp, err := c.makeRequest("GET", certEndpoint, nil)
        if err != nil {
                return nil, fmt.Errorf("failed to retrieve certificate: %w", err)
        }
        
        var certificate Certificate
        if err := c.handleResponse(certResp, &certificate); err != nil {
                return nil, fmt.Errorf("failed to parse certificate: %w", err)
        }
        
        // Retrieve the actual PEM certificate data
        pemEndpoint := fmt.Sprintf("/certificates/%s/pem", url.PathEscape(certificate.ID))
        pemResp, err := c.makeRequest("GET", pemEndpoint, nil)
        if err != nil {
                return nil, fmt.Errorf("failed to retrieve certificate PEM: %w", err)
        }
        
        // Read PEM data as plain text
        defer pemResp.Body.Close()
        pemBytes, err := io.ReadAll(pemResp.Body)
        if err != nil {
                return nil, fmt.Errorf("failed to read PEM data: %w", err)
        }
        
        if pemResp.StatusCode != 200 {
                return nil, fmt.Errorf("failed to retrieve PEM data: HTTP %d", pemResp.StatusCode)
        }
        
        certificate.Certificate = string(pemBytes)
        
        return &certificate, nil
}

// GetCSRRequest retrieves a certificate request by ID
func (c *Client) GetCSRRequest(requestId string) (*CSRRequest, error) {
        endpoint := fmt.Sprintf("/csr/%s", url.PathEscape(requestId))
        
        resp, err := c.makeRequest("GET", endpoint, nil)
        if err != nil {
                return nil, err
        }
        
        var csrRequest CSRRequest
        if err := c.handleResponse(resp, &csrRequest); err != nil {
                return nil, err
        }
        
        return &csrRequest, nil
}

// GetCSRStatus retrieves the status of a certificate request
func (c *Client) GetCSRStatus(requestId string) (*CSRStatus, error) {
        endpoint := fmt.Sprintf("/csr/%s/status", url.PathEscape(requestId))
        
        resp, err := c.makeRequest("GET", endpoint, nil)
        if err != nil {
                return nil, err
        }
        
        var status CSRStatus
        if err := c.handleResponse(resp, &status); err != nil {
                return nil, err
        }
        
        return &status, nil
}

// SearchCertificates searches for certificates based on criteria
func (c *Client) SearchCertificates(params CertificateSearchParams) ([]Certificate, error) {
        // Build query parameters
        queryParams := url.Values{}
        
        if params.CommonName != "" {
                queryParams.Set("cn", params.CommonName)
        }
        if params.Serial != "" {
                queryParams.Set("serial", params.Serial)
        }
        if params.Issuer != "" {
                queryParams.Set("issuer", params.Issuer)
        }
        if params.PolicyID != "" {
                queryParams.Set("policy", params.PolicyID)
        }
        if params.Status != "" {
                queryParams.Set("status", params.Status)
        }
        if params.Limit > 0 {
                queryParams.Set("limit", fmt.Sprintf("%d", params.Limit))
        }
        if params.ExpiresBefore != nil {
                queryParams.Set("expires_before", params.ExpiresBefore.Format(time.RFC3339))
        }
        
        endpoint := "/certificates"
        if len(queryParams) > 0 {
                endpoint += "?" + queryParams.Encode()
        }
        
        resp, err := c.makeRequest("GET", endpoint, nil)
        if err != nil {
                return nil, err
        }
        
        var result struct {
                Certificates []Certificate `json:"certificates"`
        }
        
        if err := c.handleResponse(resp, &result); err != nil {
                return nil, err
        }
        
        return result.Certificates, nil
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



// GetCertificateInfo retrieves certificate information by certificate ID
func (c *Client) GetCertificateInfo(certificateID string) (*Certificate, error) {
        endpoint := fmt.Sprintf("/certificates/%s", url.PathEscape(certificateID))
        
        resp, err := c.makeRequest("GET", endpoint, nil)
        if err != nil {
                return nil, fmt.Errorf("failed to retrieve certificate info: %w", err)
        }
        
        var certificate Certificate
        if err := c.handleResponse(resp, &certificate); err != nil {
                return nil, fmt.Errorf("failed to parse certificate info: %w", err)
        }
        
        return &certificate, nil
}

// RevokeCertificate revokes a certificate
func (c *Client) RevokeCertificate(id, reason string) error {
        requestBody := RevocationRequest{
                CertificateID: id,
                Reason:        reason,
        }
        
        resp, err := c.makeRequest("POST", "/certificates/revoke", requestBody)
        if err != nil {
                return err
        }
        
        return c.handleResponse(resp, nil)
}

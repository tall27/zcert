package api

import (
        "bytes"
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "net/url"
        "os"
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
        // Get credentials from config or environment
        hawkID := cfg.HawkID
        hawkKey := cfg.HawkKey
        
        if hawkID == "" {
                hawkID = os.Getenv("ZCERT_HAWK_ID")
                if hawkID == "" {
                        hawkID = "165c01284c6c8d872091aed0c7cc0149" // Default test credentials
                }
        }
        
        if hawkKey == "" {
                hawkKey = os.Getenv("ZCERT_HAWK_KEY")
                if hawkKey == "" {
                        hawkKey = "b431afc1ed6a6b7db5f760671840efa14224be60a11e0c164a6d0d021a45748c" // Default test credentials
                }
        }
        
        baseURL := cfg.BaseURL
        if baseURL == "" {
                baseURL = "https://ztpki-dev.venafi.com/api/v2"
        }
        
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
        
        // Enable HAWK debug for troubleshooting
        req.Header.Set("X-Debug-HAWK", "true")
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
        
        var result struct {
                Policies []Policy `json:"policies"`
        }
        
        if err := c.handleResponse(resp, &result); err != nil {
                return nil, err
        }
        
        return result.Policies, nil
}



// SubmitCSR submits a Certificate Signing Request
func (c *Client) SubmitCSR(csrPEM, policyID string) (string, error) {
        requestBody := CSRSubmissionRequest{
                CSR:      csrPEM,
                PolicyID: policyID,
        }
        
        resp, err := c.makeRequest("POST", "/csr", requestBody)
        if err != nil {
                return "", err
        }
        
        var result CSRSubmissionResponse
        if err := c.handleResponse(resp, &result); err != nil {
                return "", err
        }
        
        return result.RequestID, nil
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

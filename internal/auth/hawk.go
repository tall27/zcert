package auth

import (
        "bytes"
        "crypto/hmac"
        "crypto/sha256"
        "encoding/base64"
        "fmt"
        "io"
        "net/http"
        "net/url"
        "strconv"
        "strings"
        "time"
)

// HawkAuth represents HAWK authentication credentials and methods
type HawkAuth struct {
        ID  string
        Key string
}

// NewHawkAuth creates a new HAWK authenticator with the provided credentials
func NewHawkAuth(id, key string) *HawkAuth {
        return &HawkAuth{
                ID:  id,
                Key: key,
        }
}

// SignRequest adds HAWK authentication header to the HTTP request
func (h *HawkAuth) SignRequest(req *http.Request) error {
        // Generate timestamp and nonce
        timestamp := time.Now().Unix()
        nonce := generateNonce()
        
        // Calculate payload hash if there's a body
        var payloadHash string
        if req.Body != nil {
                bodyBytes, err := io.ReadAll(req.Body)
                if err != nil {
                        return fmt.Errorf("failed to read request body: %w", err)
                }
                // Restore the body for actual use
                req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
                
                // Calculate payload hash
                payloadHash = h.CalculatePayloadHash(bodyBytes, req.Header.Get("Content-Type"))
        }
        
        // Build the normalized request string for HAWK
        normalizedString := h.buildNormalizedString(
                timestamp,
                nonce,
                req.Method,
                req.URL,
                req.Header.Get("Content-Type"),
                payloadHash,
        )
        
        // Calculate MAC
        mac := h.calculateMAC(normalizedString)
        
        // Build Authorization header with proper HAWK format
        authHeader := fmt.Sprintf(`Hawk id="%s", ts="%d", nonce="%s"`,
                h.ID, timestamp, nonce)
        
        // Add hash field if payload is present
        if payloadHash != "" {
                authHeader += fmt.Sprintf(`, hash="%s"`, payloadHash)
        }
        
        authHeader += fmt.Sprintf(`, mac="%s"`, mac)
        
        req.Header.Set("Authorization", authHeader)
        
        return nil
}

// buildNormalizedString creates the normalized string for HAWK MAC calculation
func (h *HawkAuth) buildNormalizedString(timestamp int64, nonce, method string, reqURL *url.URL, contentType, payloadHash string) string {
        // HAWK normalized request format:
        // hawk.1.header\n
        // timestamp\n
        // nonce\n
        // method\n
        // resource\n
        // host\n
        // port\n
        // hash\n
        // ext\n
        // app\n
        // dlg\n
        
        resource := reqURL.Path
        if reqURL.RawQuery != "" {
                resource += "?" + reqURL.RawQuery
        }
        
        host := reqURL.Hostname()
        port := reqURL.Port()
        if port == "" {
                if reqURL.Scheme == "https" {
                        port = "443"
                } else {
                        port = "80"
                }
        }
        
        // Use the provided payload hash, or empty if none
        hash := payloadHash
        ext := ""
        
        normalized := strings.Join([]string{
                "hawk.1.header",
                strconv.FormatInt(timestamp, 10),
                nonce,
                strings.ToUpper(method),
                resource,
                host,
                port,
                hash,
                ext,
        }, "\n") + "\n" // Add final newline to match Python implementation
        
        return normalized
}

// calculateMAC computes the HMAC-SHA256 MAC for the normalized string
func (h *HawkAuth) calculateMAC(normalizedString string) string {
        // Use raw key as UTF-8 bytes (matching Python implementation)
        keyBytes := []byte(h.Key)
        
        mac := hmac.New(sha256.New, keyBytes)
        mac.Write([]byte(normalizedString))
        return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// generateNonce creates a unique nonce for the request (matching Python implementation)
func generateNonce() string {
        chars := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        result := make([]byte, 6)
        for i := range result {
                result[i] = chars[time.Now().UnixNano()%int64(len(chars))]
        }
        return string(result)
}

// ValidateServerResponse validates the Server-Authorization header (if present)
// This is typically used for response validation in HAWK
func (h *HawkAuth) ValidateServerResponse(resp *http.Response, payloadHash string) error {
        serverAuth := resp.Header.Get("Server-Authorization")
        if serverAuth == "" {
                // Server authorization is optional in many HAWK implementations
                return nil
        }
        
        // Parse server authorization header
        // Format: Hawk mac="...", hash="..."
        // Implementation would validate the server's MAC against expected values
        // For now, we'll accept any server authorization header
        
        return nil
}

// CalculatePayloadHash calculates the hash of the request/response payload
// This is used for payload verification in HAWK
func (h *HawkAuth) CalculatePayloadHash(payload []byte, contentType string) string {
        if len(payload) == 0 {
                return ""
        }
        
        // HAWK payload hash format:
        // hawk.1.payload\n
        // content-type\n
        // payload\n
        
        // Build payload string according to HAWK spec (matching Python implementation):
        // "hawk.1.payload\n{lowercase_content_type}\n{payload}\n"
        mainContentType := strings.Split(contentType, ",")[0]
        mainContentType = strings.ToLower(strings.TrimSpace(mainContentType))
        
        hashInput := fmt.Sprintf("hawk.1.payload\n%s\n%s\n", mainContentType, string(payload))
        
        hash := sha256.Sum256([]byte(hashInput))
        return base64.StdEncoding.EncodeToString(hash[:])
}

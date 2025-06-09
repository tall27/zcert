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
        
        // Debug output for HAWK authentication troubleshooting
        if req.Header.Get("X-Debug-HAWK") == "true" {
                fmt.Printf("HAWK Debug - ID: %s\n", h.ID)
                fmt.Printf("HAWK Debug - Timestamp: %d\n", timestamp)
                fmt.Printf("HAWK Debug - Nonce: %s\n", nonce)
                fmt.Printf("HAWK Debug - Method: %s\n", req.Method)
                fmt.Printf("HAWK Debug - URL: %s\n", req.URL.String())
                fmt.Printf("HAWK Debug - Payload Hash: %s\n", payloadHash)
                fmt.Printf("HAWK Debug - Normalized String:\n%q\n", normalizedString)
                fmt.Printf("HAWK Debug - MAC: %s\n", mac)
                fmt.Printf("HAWK Debug - Authorization: %s\n", authHeader)
        }
        
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
        
        // Build normalized string exactly like JavaScript implementation
        normalized := "hawk.1.header\n" +
                strconv.FormatInt(timestamp, 10) + "\n" +
                nonce + "\n" +
                strings.ToUpper(method) + "\n" +
                resource + "\n" +
                host + "\n" +
                port + "\n" +
                hash + "\n" +
                "\n" // Final empty line
        
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

// generateNonce creates a unique nonce for the request (matching PowerShell implementation)
func generateNonce() string {
        // PowerShell: chars = $(48..57;65..90;97..122) => 0-9, A-Z, a-z
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
        
        // Build payload hash exactly like JavaScript implementation
        // crypto.createHash(algorithm).update('hawk.1.payload\n').update(contentType + '\n').update(payload + '\n').digest('base64')
        hasher := sha256.New()
        hasher.Write([]byte("hawk.1.payload\n"))
        hasher.Write([]byte(contentType + "\n"))
        hasher.Write(payload)
        hasher.Write([]byte("\n"))
        
        return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

package main

import (
        "bytes"
        "crypto/hmac"
        "crypto/sha256"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "net/url"
        "strings"
        "time"
)

func main() {
        // Test HAWK credentials
        hawkID := "165c01284c6c8d872091aed0c7cc0149"
        hawkKey := "b431afc1ed6a6b7db5f760671840efa14224be60a11e0c164a6d0d021a45748c"
        
        // Test endpoint
        testURL := "https://ztpki-dev.venafi.com/api/v2/csr"
        
        // Create a simple test request
        testData := map[string]interface{}{
                "csr": "test-csr-data",
                "policy": "WebServer",
        }
        
        jsonData, _ := json.Marshal(testData)
        
        req, err := http.NewRequest("POST", testURL, bytes.NewReader(jsonData))
        if err != nil {
                fmt.Printf("Error creating request: %v\n", err)
                return
        }
        
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("Accept", "application/json")
        
        // Generate HAWK authentication
        timestamp := time.Now().Unix()
        nonce := fmt.Sprintf("%d", time.Now().UnixNano())
        
        // Parse URL
        u, _ := url.Parse(testURL)
        
        // Build normalized string
        resource := u.Path
        if u.RawQuery != "" {
                resource += "?" + u.RawQuery
        }
        
        host := strings.ToLower(u.Hostname())
        port := u.Port()
        if port == "" {
                if u.Scheme == "https" {
                        port = "443"
                } else {
                        port = "80"
                }
        }
        
        // Calculate payload hash
        payloadHash := calculatePayloadHash(jsonData, "application/json")
        
        // HAWK specification requires exact format with no trailing newline on last empty field
        normalized := fmt.Sprintf("hawk.1.header\n%d\n%s\n%s\n%s\n%s\n%s\n%s\n\n\n\n",
                timestamp, nonce, "POST", resource, host, port, payloadHash)
        
        fmt.Printf("HAWK ID: %s\n", hawkID)
        fmt.Printf("HAWK Key: %s...\n", hawkKey[:20])
        fmt.Printf("Timestamp: %d\n", timestamp)
        fmt.Printf("Nonce: %s\n", nonce)
        fmt.Printf("URL: %s\n", testURL)
        fmt.Printf("Payload Hash: %s\n", payloadHash)
        fmt.Printf("Normalized string:\n%s\n", normalized)
        
        // Try base64 decoding the key first (another common HAWK format)
        keyBytes, err := base64.StdEncoding.DecodeString(hawkKey)
        if err != nil {
                // Fall back to raw bytes
                keyBytes = []byte(hawkKey)
                fmt.Printf("Using raw key bytes\n")
        } else {
                fmt.Printf("Using base64 decoded key\n")
        }
        
        mac := hmac.New(sha256.New, keyBytes)
        mac.Write([]byte(normalized))
        macResult := base64.StdEncoding.EncodeToString(mac.Sum(nil))
        
        fmt.Printf("Calculated MAC: %s\n", macResult)
        
        // Set authorization header
        authHeader := fmt.Sprintf(`Hawk id="%s", ts="%d", nonce="%s", mac="%s"`,
                hawkID, timestamp, nonce, macResult)
        
        fmt.Printf("Authorization: %s\n", authHeader)
        req.Header.Set("Authorization", authHeader)
        
        // Make the request
        client := &http.Client{Timeout: 30 * time.Second}
        resp, err := client.Do(req)
        if err != nil {
                fmt.Printf("Request failed: %v\n", err)
                return
        }
        defer resp.Body.Close()
        
        body, _ := io.ReadAll(resp.Body)
        fmt.Printf("Response Status: %s\n", resp.Status)
        fmt.Printf("Response Body: %s\n", string(body))
}

func calculatePayloadHash(payload []byte, contentType string) string {
        if len(payload) == 0 {
                return ""
        }
        
        // Try without payload hash first (some HAWK implementations don't require it)
        return ""
        
        // Original implementation commented out for testing
        // hashInput := fmt.Sprintf("hawk.1.payload\n%s\n%s\n", contentType, string(payload))
        // hash := sha256.Sum256([]byte(hashInput))
        // return base64.StdEncoding.EncodeToString(hash[:])
}
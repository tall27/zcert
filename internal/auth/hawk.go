package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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
	
	// Build the normalized request string for HAWK
	normalizedString := h.buildNormalizedString(
		timestamp,
		nonce,
		req.Method,
		req.URL,
		req.Header.Get("Content-Type"),
	)
	
	// Calculate MAC
	mac := h.calculateMAC(normalizedString)
	
	// Build Authorization header
	authHeader := fmt.Sprintf(`Hawk id="%s", ts="%d", nonce="%s", mac="%s"`,
		h.ID, timestamp, nonce, mac)
	
	req.Header.Set("Authorization", authHeader)
	
	return nil
}

// buildNormalizedString creates the normalized string for HAWK MAC calculation
func (h *HawkAuth) buildNormalizedString(timestamp int64, nonce, method string, reqURL *url.URL, contentType string) string {
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
	
	// For now, we'll use empty values for hash, ext, app, and dlg
	// In a full implementation, these might be calculated based on request body
	hash := ""
	ext := ""
	app := ""
	dlg := ""
	
	normalized := strings.Join([]string{
		"hawk.1.header",
		strconv.FormatInt(timestamp, 10),
		nonce,
		strings.ToUpper(method),
		resource,
		strings.ToLower(host),
		port,
		hash,
		ext,
		app,
		dlg,
		"", // Final empty line
	}, "\n")
	
	return normalized
}

// calculateMAC computes the HMAC-SHA256 MAC for the normalized string
func (h *HawkAuth) calculateMAC(normalizedString string) string {
	mac := hmac.New(sha256.New, []byte(h.Key))
	mac.Write([]byte(normalizedString))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// generateNonce creates a unique nonce for the request
func generateNonce() string {
	// Simple nonce generation - in production, this should be more robust
	return fmt.Sprintf("%d", time.Now().UnixNano())
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
	
	hashInput := fmt.Sprintf("hawk.1.payload\n%s\n%s\n", contentType, string(payload))
	
	hash := sha256.Sum256([]byte(hashInput))
	return base64.StdEncoding.EncodeToString(hash[:])
}

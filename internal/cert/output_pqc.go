package cert

import (
	"fmt"
	"os"
	"path/filepath"
)

// PQCOutputHandler handles output of PQC certificates and keys
type PQCOutputHandler struct {
	CertFile    string
	KeyFile     string
	ChainFile   string
	BundleFile  string
	Format      string
	KeyPassword string
	P12Password string
	NoKeyOutput bool
}

// NewPQCOutputHandler creates a new PQC output handler
func NewPQCOutputHandler(certFile, keyFile, chainFile, bundleFile, format, keyPassword, p12Password string, noKeyOutput bool) *PQCOutputHandler {
	return &PQCOutputHandler{
		CertFile:    certFile,
		KeyFile:     keyFile,
		ChainFile:   chainFile,
		BundleFile:  bundleFile,
		Format:      format,
		KeyPassword: keyPassword,
		P12Password: p12Password,
		NoKeyOutput: noKeyOutput,
	}
}

// SaveCertificate saves the certificate to the specified location
func (h *PQCOutputHandler) SaveCertificate(certData []byte) error {
	if h.CertFile == "" {
		return fmt.Errorf("certificate output file not specified")
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(h.CertFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	return os.WriteFile(h.CertFile, certData, 0644)
}

// SavePrivateKey saves the private key to the specified location
func (h *PQCOutputHandler) SavePrivateKey(keyData []byte) error {
	if h.NoKeyOutput {
		return nil
	}

	if h.KeyFile == "" {
		return fmt.Errorf("private key output file not specified")
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(h.KeyFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// If key password is provided, encrypt the key
	if h.KeyPassword != "" {
		// TODO: Implement key encryption using OpenSSL
		return fmt.Errorf("key encryption not yet implemented")
	}

	return os.WriteFile(h.KeyFile, keyData, 0600)
}

// SaveChain saves the certificate chain to the specified location
func (h *PQCOutputHandler) SaveChain(chainData []byte) error {
	if h.ChainFile == "" {
		return nil // Chain file is optional
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(h.ChainFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create chain directory: %w", err)
	}

	return os.WriteFile(h.ChainFile, chainData, 0644)
}

// SaveBundle saves the certificate bundle to the specified location
func (h *PQCOutputHandler) SaveBundle(bundleData []byte) error {
	if h.BundleFile == "" {
		return nil // Bundle file is optional
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(h.BundleFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create bundle directory: %w", err)
	}

	return os.WriteFile(h.BundleFile, bundleData, 0644)
}

// CreatePKCS12Bundle creates a PKCS#12 bundle containing the certificate and private key
func (h *PQCOutputHandler) CreatePKCS12Bundle(certData, keyData []byte) error {
	if h.Format != "p12" || h.BundleFile == "" {
		return nil // Not creating PKCS#12 bundle
	}

	// TODO: Implement PKCS#12 bundle creation using OpenSSL
	return fmt.Errorf("PKCS#12 bundle creation not yet implemented")
} 
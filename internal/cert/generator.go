package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// KeyType represents the type of private key to generate
type KeyType string

const (
	KeyTypeRSA   KeyType = "rsa"
	KeyTypeECDSA KeyType = "ecdsa"
)

// KeyGenerationOptions contains options for key and CSR generation
type KeyGenerationOptions struct {
	KeyType    KeyType
	KeySize    int      // For RSA keys
	CommonName string
	SANs       []string
	Country    []string
	Province   []string
	Locality   []string
	Org        []string
	OrgUnit    []string
}

// GenerateKeyAndCSR generates a private key and Certificate Signing Request
func GenerateKeyAndCSR(opts KeyGenerationOptions) (interface{}, []byte, error) {
	// Generate private key
	privateKey, err := generatePrivateKey(opts.KeyType, opts.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create CSR template
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         opts.CommonName,
			Country:            opts.Country,
			Province:           opts.Province,
			Locality:           opts.Locality,
			Organization:       opts.Org,
			OrganizationalUnit: opts.OrgUnit,
		},
	}

	// Parse and add Subject Alternative Names
	if err := addSANsToTemplate(&template, opts.SANs); err != nil {
		return nil, nil, fmt.Errorf("failed to process SANs: %w", err)
	}

	// Create the CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	return privateKey, csrBytes, nil
}

// generatePrivateKey generates a private key of the specified type and size
func generatePrivateKey(keyType KeyType, keySize int) (interface{}, error) {
	switch keyType {
	case KeyTypeRSA:
		if keySize < 2048 {
			keySize = 2048 // Minimum secure key size
		}
		return rsa.GenerateKey(rand.Reader, keySize)
	case KeyTypeECDSA:
		// ECDSA implementation would go here
		// For now, fall back to RSA
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// addSANsToTemplate parses SANs and adds them to the CSR template
func addSANsToTemplate(template *x509.CertificateRequest, sans []string) error {
	for _, san := range sans {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}

		// Try to parse as IP address
		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}

		// Try to parse as URI
		if uri, err := url.Parse(san); err == nil && uri.Scheme != "" {
			template.URIs = append(template.URIs, uri)
			continue
		}

		// Try to parse as email
		if strings.Contains(san, "@") && strings.Contains(san, ".") {
			template.EmailAddresses = append(template.EmailAddresses, san)
			continue
		}

		// Default to DNS name
		template.DNSNames = append(template.DNSNames, san)
	}

	return nil
}

// EncodePrivateKeyToPEM encodes a private key to PEM format
func EncodePrivateKeyToPEM(privateKey interface{}) ([]byte, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		}), nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

// EncodeCSRToPEM encodes a CSR to PEM format
func EncodeCSRToPEM(csrBytes []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})
}

// ValidateCSR validates a Certificate Signing Request
func ValidateCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("PEM block is not a certificate request")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}

	// Verify the signature on the CSR
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	return csr, nil
}

// GetKeyInfo returns information about a private key
func GetKeyInfo(privateKey interface{}) (string, int, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return "RSA", key.N.BitLen(), nil
	default:
		return "", 0, fmt.Errorf("unsupported private key type")
	}
}

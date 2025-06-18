package cert

import (
	"strings"
)

// Subject represents the subject information for a certificate
type Subject struct {
	CommonName         string
	Country           string
	Province          string
	Locality          string
	Organization      string
	OrganizationalUnit string
}

// String returns the subject string in OpenSSL format
func (s *Subject) String() string {
	var parts []string

	if s.Country != "" {
		parts = append(parts, "C="+s.Country)
	}
	if s.Province != "" {
		parts = append(parts, "ST="+s.Province)
	}
	if s.Locality != "" {
		parts = append(parts, "L="+s.Locality)
	}
	if s.Organization != "" {
		parts = append(parts, "O="+s.Organization)
	}
	if s.OrganizationalUnit != "" {
		parts = append(parts, "OU="+s.OrganizationalUnit)
	}
	if s.CommonName != "" {
		parts = append(parts, "CN="+s.CommonName)
	}

	return "/" + strings.Join(parts, "/")
}

// CertificateInfo represents information about a certificate
type CertificateInfo struct {
	Subject     Subject
	Issuer      Subject
	NotBefore   string
	NotAfter    string
	SerialNumber string
	Algorithm   string
	KeyUsage    []string
	ExtKeyUsage []string
	SANs        []string
}

// EnrollmentResult represents the result of a certificate enrollment
type EnrollmentResult struct {
	Certificate []byte
	Chain       []byte
	PrivateKey  []byte
	Info        CertificateInfo
} 
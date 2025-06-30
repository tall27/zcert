package utils

import (
	"fmt"
	"os"

	"zcert/internal/api"
)

// ChainRetrievalOptions configures certificate chain retrieval behavior
type ChainRetrievalOptions struct {
	IncludeChain bool
	FallbackMode bool // If true, retry without chain if chain retrieval fails
	VerboseLevel int  // For verbose output during fallback
}

// RetrieveCertificateWithChain retrieves a certificate with standardized chain handling
func RetrieveCertificateWithChain(client *api.Client, certificateID string, opts *ChainRetrievalOptions) (*api.Certificate, *api.CertificatePEMResponse, error) {
	if opts == nil {
		opts = &ChainRetrievalOptions{
			IncludeChain: false,
			FallbackMode: true,
			VerboseLevel: 0,
		}
	}

	// First get basic certificate info
	certificate, err := client.GetCertificate(certificateID)
	if err != nil {
		return nil, nil, NewCertificateRetrievalError(err)
	}

	// Get PEM format with optional chain
	pemResponse, err := client.GetCertificatePEM(certificateID, opts.IncludeChain)
	if err != nil {
		if opts.IncludeChain && opts.FallbackMode {
			// Try without chain if chain retrieval fails
			if opts.VerboseLevel > 0 {
				fmt.Fprintf(os.Stderr, "Warning: Failed to retrieve certificate with chain: %v\n", err)
				fmt.Fprintln(os.Stderr, "Retrieving certificate without chain...")
			}
			pemResponse, err = client.GetCertificatePEM(certificateID, false)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to retrieve certificate in PEM format: %w", err)
			}
		} else {
			return nil, nil, fmt.Errorf("failed to retrieve certificate in PEM format: %w", err)
		}
	}

	// Update certificate with PEM data and chain
	certificate.Certificate = pemResponse.Certificate
	if pemResponse.Chain != "" {
		certificate.Chain = []string{pemResponse.Chain}
	}

	return certificate, pemResponse, nil
}

// StandardizeChainHandling ensures consistent chain handling across all commands
func StandardizeChainHandling(certificate *api.Certificate, pemResponse *api.CertificatePEMResponse) {
	// Ensure certificate has the PEM data
	if certificate.Certificate == "" && pemResponse.Certificate != "" {
		certificate.Certificate = pemResponse.Certificate
	}
	
	// Standardize chain handling
	if pemResponse.Chain != "" {
		// Always store chain as a slice of strings for consistency
		certificate.Chain = []string{pemResponse.Chain}
	} else {
		// Ensure chain is empty slice rather than nil for consistency
		certificate.Chain = []string{}
	}
}

// ChainRetrievalResult contains the result of a chain retrieval operation
type ChainRetrievalResult struct {
	Certificate     *api.Certificate
	PEMResponse     *api.CertificatePEMResponse
	ChainRetrieved  bool // Whether chain was successfully retrieved
	FallbackUsed    bool // Whether fallback (no chain) was used
}

// RetrieveCertificateWithChainResult retrieves a certificate with detailed chain retrieval information
func RetrieveCertificateWithChainResult(client *api.Client, certificateID string, opts *ChainRetrievalOptions) (*ChainRetrievalResult, error) {
	if opts == nil {
		opts = &ChainRetrievalOptions{
			IncludeChain: false,
			FallbackMode: true,
			VerboseLevel: 0,
		}
	}

	result := &ChainRetrievalResult{
		ChainRetrieved: false,
		FallbackUsed:   false,
	}

	// First get basic certificate info
	certificate, err := client.GetCertificate(certificateID)
	if err != nil {
		return nil, NewCertificateRetrievalError(err)
	}

	// Get PEM format with optional chain
	pemResponse, err := client.GetCertificatePEM(certificateID, opts.IncludeChain)
	if err != nil {
		if opts.IncludeChain && opts.FallbackMode {
			// Try without chain if chain retrieval fails
			if opts.VerboseLevel > 0 {
				fmt.Fprintf(os.Stderr, "Warning: Failed to retrieve certificate with chain: %v\n", err)
				fmt.Fprintln(os.Stderr, "Retrieving certificate without chain...")
			}
			pemResponse, err = client.GetCertificatePEM(certificateID, false)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve certificate in PEM format: %w", err)
			}
			result.FallbackUsed = true
		} else {
			return nil, fmt.Errorf("failed to retrieve certificate in PEM format: %w", err)
		}
	}

	// Determine if chain was retrieved
	result.ChainRetrieved = opts.IncludeChain && pemResponse.Chain != "" && !result.FallbackUsed

	// Standardize chain handling
	StandardizeChainHandling(certificate, pemResponse)
	
	result.Certificate = certificate
	result.PEMResponse = pemResponse

	return result, nil
}

// GetChainFromCertificate extracts the chain from a certificate in a standardized way
func GetChainFromCertificate(cert *api.Certificate) []string {
	if cert.Chain == nil {
		return []string{}
	}
	return cert.Chain
}

// HasChain checks if a certificate has a chain
func HasChain(cert *api.Certificate) bool {
	return len(GetChainFromCertificate(cert)) > 0
}

// GetFullChainPEM returns the certificate and chain as a combined PEM string
func GetFullChainPEM(cert *api.Certificate) string {
	result := cert.Certificate
	
	chain := GetChainFromCertificate(cert)
	for _, chainCert := range chain {
		if chainCert != "" {
			result += "\n" + chainCert
		}
	}
	
	return result
}
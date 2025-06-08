package cert

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkcs12"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"zcert/internal/api"
)

// OutputFormat represents the output format for certificates
type OutputFormat string

const (
	FormatPEM  OutputFormat = "pem"
	FormatP12  OutputFormat = "p12"
	FormatPFX  OutputFormat = "pfx"
	FormatJKS  OutputFormat = "jks"
	FormatDER  OutputFormat = "der"
)

// Outputter handles certificate output in various formats
type Outputter struct {
	format   OutputFormat
	outfile  string
	password string
}

// NewOutputter creates a new certificate outputter
func NewOutputter(format, outfile, password string) *Outputter {
	return &Outputter{
		format:   OutputFormat(strings.ToLower(format)),
		outfile:  outfile,
		password: password,
	}
}

// OutputCertificate outputs the certificate in the specified format
func (o *Outputter) OutputCertificate(cert *api.Certificate, privateKey interface{}, includeKey bool) error {
	switch o.format {
	case FormatPEM:
		return o.outputPEM(cert, privateKey, includeKey)
	case FormatP12, FormatPFX:
		return o.outputPKCS12(cert, privateKey)
	case FormatJKS:
		return o.outputJKS(cert, privateKey)
	case FormatDER:
		return o.outputDER(cert)
	default:
		return fmt.Errorf("unsupported output format: %s", o.format)
	}
}

// outputPEM outputs certificate in PEM format
func (o *Outputter) outputPEM(cert *api.Certificate, privateKey interface{}, includeKey bool) error {
	// Parse the certificate to ensure it's valid PEM
	certPEM := cert.Certificate
	if !strings.HasPrefix(certPEM, "-----BEGIN CERTIFICATE-----") {
		// If it's not PEM format, it might be base64 encoded DER
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return fmt.Errorf("certificate is not in valid PEM format")
		}
		certPEM = string(pem.EncodeToMemory(block))
	}

	if o.outfile == "" {
		// Output to stdout
		fmt.Print(certPEM)
		
		// Include chain if available
		for _, chainCert := range cert.Chain {
			fmt.Print(chainCert)
		}
		
		return nil
	}

	// Output to file
	certFile := o.outfile
	if !strings.HasSuffix(certFile, ".pem") && !strings.HasSuffix(certFile, ".crt") {
		certFile += ".pem"
	}

	// Write certificate file
	if err := os.WriteFile(certFile, []byte(certPEM), 0644); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	fmt.Printf("Certificate written to: %s\n", certFile)

	// Write chain file if chain is available
	if len(cert.Chain) > 0 {
		chainFile := strings.TrimSuffix(certFile, filepath.Ext(certFile)) + "-chain.pem"
		chainPEM := strings.Join(cert.Chain, "")
		
		if err := os.WriteFile(chainFile, []byte(chainPEM), 0644); err != nil {
			return fmt.Errorf("failed to write chain file: %w", err)
		}
		fmt.Printf("Certificate chain written to: %s\n", chainFile)
	}

	// Write private key file if requested and available
	if includeKey && privateKey != nil {
		keyFile := strings.TrimSuffix(certFile, filepath.Ext(certFile)) + "-key.pem"
		keyPEM, err := EncodePrivateKeyToPEM(privateKey)
		if err != nil {
			return fmt.Errorf("failed to encode private key: %w", err)
		}

		if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
			return fmt.Errorf("failed to write private key file: %w", err)
		}
		fmt.Printf("Private key written to: %s\n", keyFile)
	}

	return nil
}

// outputPKCS12 outputs certificate in PKCS#12/PFX format
func (o *Outputter) outputPKCS12(cert *api.Certificate, privateKey interface{}) error {
	if privateKey == nil {
		return fmt.Errorf("private key is required for PKCS#12 output")
	}

	// Parse certificate
	certBlock, _ := pem.Decode([]byte(cert.Certificate))
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Parse chain certificates
	var caCerts []*x509.Certificate
	for _, chainPEM := range cert.Chain {
		chainBlock, _ := pem.Decode([]byte(chainPEM))
		if chainBlock != nil {
			chainCert, err := x509.ParseCertificate(chainBlock.Bytes)
			if err == nil {
				caCerts = append(caCerts, chainCert)
			}
		}
	}

	// Set password
	password := o.password
	if password == "" {
		password = "changeit" // Default password
		fmt.Fprintf(os.Stderr, "Using default password 'changeit' for PKCS#12 file\n")
	}

	// Create PKCS#12 data
	p12Data, err := pkcs12.Encode(rand.Reader, privateKey, x509Cert, caCerts, password)
	if err != nil {
		return fmt.Errorf("failed to encode PKCS#12: %w", err)
	}

	// Determine output file
	outfile := o.outfile
	if outfile == "" {
		outfile = strings.ReplaceAll(cert.CommonName, "*", "wildcard") + ".p12"
	}
	if !strings.HasSuffix(outfile, ".p12") && !strings.HasSuffix(outfile, ".pfx") {
		outfile += ".p12"
	}

	// Write file
	if err := os.WriteFile(outfile, p12Data, 0600); err != nil {
		return fmt.Errorf("failed to write PKCS#12 file: %w", err)
	}

	fmt.Printf("PKCS#12 file written to: %s\n", outfile)
	fmt.Printf("Password: %s\n", password)

	return nil
}

// outputJKS outputs certificate in Java KeyStore format
func (o *Outputter) outputJKS(cert *api.Certificate, privateKey interface{}) error {
	// JKS output is complex and typically requires Java keytool
	// For now, we'll provide instructions for manual conversion
	
	fmt.Println("Java KeyStore (JKS) output is not directly supported.")
	fmt.Println("To create a JKS file, first save the certificate and key in PKCS#12 format,")
	fmt.Println("then use the Java keytool to convert:")
	fmt.Println("")
	fmt.Println("1. Save as PKCS#12:")
	
	// Create a temporary PKCS#12 outputter
	p12Outputter := &Outputter{
		format:   FormatP12,
		outfile:  o.outfile,
		password: o.password,
	}
	
	if err := p12Outputter.outputPKCS12(cert, privateKey); err != nil {
		return err
	}
	
	p12File := o.outfile
	if p12File == "" {
		p12File = strings.ReplaceAll(cert.CommonName, "*", "wildcard") + ".p12"
	}
	if !strings.HasSuffix(p12File, ".p12") && !strings.HasSuffix(p12File, ".pfx") {
		p12File += ".p12"
	}
	
	jksFile := strings.TrimSuffix(p12File, filepath.Ext(p12File)) + ".jks"
	
	fmt.Printf("\n2. Convert to JKS using keytool:\n")
	fmt.Printf("keytool -importkeystore -srckeystore %s -srcstoretype PKCS12 -destkeystore %s -deststoretype JKS\n", 
		p12File, jksFile)
	
	return nil
}

// outputDER outputs certificate in DER format
func (o *Outputter) outputDER(cert *api.Certificate) error {
	// Parse PEM to get DER bytes
	certBlock, _ := pem.Decode([]byte(cert.Certificate))
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	// Determine output file
	outfile := o.outfile
	if outfile == "" {
		outfile = strings.ReplaceAll(cert.CommonName, "*", "wildcard") + ".der"
	}
	if !strings.HasSuffix(outfile, ".der") {
		outfile += ".der"
	}

	// Write DER file
	if err := os.WriteFile(outfile, certBlock.Bytes, 0644); err != nil {
		return fmt.Errorf("failed to write DER file: %w", err)
	}

	fmt.Printf("DER certificate written to: %s\n", outfile)
	return nil
}

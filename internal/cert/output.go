package cert

import (
        "crypto/rand"
        "crypto/rsa"
        "crypto/x509"
        "encoding/pem"
        "fmt"
        "os"
        "path/filepath"
        "strings"

        "software.sslmate.com/src/go-pkcs12"
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

// OutputOptions provides options for custom file output
type OutputOptions struct {
        CertFile    string // Certificate output file path
        KeyFile     string // Private key output file path
        ChainFile   string // Certificate chain output file path
        BundleFile  string // Combined certificate bundle file path (cert + chain)
        KeyPassword string // Password for private key encryption
}

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

// OutputCertificateToFiles outputs the certificate to specific files with custom options
func (o *Outputter) OutputCertificateToFiles(cert *api.Certificate, privateKey interface{}, includeKey bool, options OutputOptions) error {
        switch o.format {
        case FormatPEM:
                return o.outputPEMToFiles(cert, privateKey, includeKey, options)
        case FormatP12, FormatPFX:
                return o.outputPKCS12ToFiles(cert, privateKey, options)
        default:
                return fmt.Errorf("custom file output not supported for format: %s", o.format)
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
                
                // Include private key if requested
                if includeKey && privateKey != nil {
                        keyPEM, err := o.encodePrivateKeyToPEM(privateKey, o.password)
                        if err != nil {
                                return fmt.Errorf("failed to encode private key: %w", err)
                        }
                        fmt.Print(string(keyPEM))
                        fmt.Println() // Add blank line between key and cert
                }
                
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
                keyPEM, err := o.encodePrivateKeyToPEM(privateKey, o.password)
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

        // Parse the certificate PEM
        certBlock, _ := pem.Decode([]byte(cert.Certificate))
        if certBlock == nil {
                return fmt.Errorf("failed to decode certificate PEM")
        }
        
        x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
        if err != nil {
                return fmt.Errorf("failed to parse certificate: %w", err)
        }

        // Parse certificate chain if available
        var caCerts []*x509.Certificate
        for _, chainCertPEM := range cert.Chain {
                chainBlock, _ := pem.Decode([]byte(chainCertPEM))
                if chainBlock != nil {
                        chainCert, err := x509.ParseCertificate(chainBlock.Bytes)
                        if err == nil {
                                caCerts = append(caCerts, chainCert)
                        }
                }
        }

        // Create PKCS#12 data
        pfxData, err := pkcs12.Encode(rand.Reader, privateKey, x509Cert, caCerts, o.password)
        if err != nil {
                return fmt.Errorf("failed to create PKCS#12 data: %w", err)
        }

        // Determine output file
        outfile := o.outfile
        if outfile == "" {
                outfile = strings.ReplaceAll(cert.CommonName, "*", "wildcard") + ".p12"
        }
        if !strings.HasSuffix(outfile, ".p12") && !strings.HasSuffix(outfile, ".pfx") {
                outfile += ".p12"
        }

        if o.outfile == "" {
                // Output to stdout as base64 (since P12 is binary)
                fmt.Printf("-----BEGIN PKCS12-----\n")
                // Note: For binary data, we could implement base64 output, but P12 files are typically saved to disk
                fmt.Printf("PKCS#12 data created (%d bytes)\n", len(pfxData))
                fmt.Printf("Use --bundle-file to save to a file\n")
                fmt.Printf("-----END PKCS12-----\n")
        } else {
                // Write to file
                if err := os.WriteFile(outfile, pfxData, 0644); err != nil {
                        return fmt.Errorf("failed to write PKCS#12 file: %w", err)
                }
                fmt.Printf("PKCS#12 bundle written to: %s\n", outfile)
        }
        
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

// outputPEMToFiles outputs certificate in PEM format to specific files
func (o *Outputter) outputPEMToFiles(cert *api.Certificate, privateKey interface{}, includeKey bool, options OutputOptions) error {
        // Parse the certificate to ensure it's valid PEM
        certPEM := cert.Certificate
        if !strings.HasPrefix(certPEM, "-----BEGIN CERTIFICATE-----") {
                block, _ := pem.Decode([]byte(certPEM))
                if block == nil {
                        return fmt.Errorf("certificate is not in valid PEM format")
                }
                certPEM = string(pem.EncodeToMemory(block))
        }

        // Write certificate file if specified
        if options.CertFile != "" {
                if err := os.WriteFile(options.CertFile, []byte(certPEM), 0644); err != nil {
                        return fmt.Errorf("failed to write certificate file: %w", err)
                }
                fmt.Printf("Certificate written to: %s\n", options.CertFile)
        }

        // Write chain file if specified and chain is available
        if options.ChainFile != "" && len(cert.Chain) > 0 {
                chainPEM := strings.Join(cert.Chain, "")
                if err := os.WriteFile(options.ChainFile, []byte(chainPEM), 0644); err != nil {
                        return fmt.Errorf("failed to write chain file: %w", err)
                }
                fmt.Printf("Certificate chain written to: %s\n", options.ChainFile)
        }

        // Write bundle file if specified (cert + chain)
        if options.BundleFile != "" {
                bundlePEM := certPEM
                for _, chainCert := range cert.Chain {
                        bundlePEM += chainCert
                }
                if err := os.WriteFile(options.BundleFile, []byte(bundlePEM), 0644); err != nil {
                        return fmt.Errorf("failed to write bundle file: %w", err)
                }
                fmt.Printf("Certificate bundle written to: %s\n", options.BundleFile)
        }

        // Write private key file if requested and available
        if includeKey && privateKey != nil && options.KeyFile != "" {
                keyPEM, err := o.encodePrivateKeyToPEM(privateKey, options.KeyPassword)
                if err != nil {
                        return fmt.Errorf("failed to encode private key: %w", err)
                }

                if err := os.WriteFile(options.KeyFile, keyPEM, 0600); err != nil {
                        return fmt.Errorf("failed to write private key file: %w", err)
                }
                fmt.Printf("Private key written to: %s\n", options.KeyFile)
        }

        // If no specific files provided but we have output to stdout
        if options.CertFile == "" && options.BundleFile == "" {
                // Output to stdout
                if includeKey && privateKey != nil {
                        keyPEM, err := o.encodePrivateKeyToPEM(privateKey, options.KeyPassword)
                        if err != nil {
                                return fmt.Errorf("failed to encode private key: %w", err)
                        }
                        fmt.Print(string(keyPEM))
                        fmt.Println() // Add blank line between key and cert
                }
                
                fmt.Print(certPEM)
                
                // Include chain if available
                for _, chainCert := range cert.Chain {
                        fmt.Print(chainCert)
                }
        }

        return nil
}

// outputPKCS12ToFiles outputs certificate in PKCS#12 format to specific files
func (o *Outputter) outputPKCS12ToFiles(cert *api.Certificate, privateKey interface{}, options OutputOptions) error {
        if privateKey == nil {
                return fmt.Errorf("private key is required for PKCS#12 output")
        }

        bundleFile := options.BundleFile
        if bundleFile == "" {
                bundleFile = strings.ReplaceAll(cert.CommonName, "*", "wildcard") + ".p12"
        }

        // Parse the certificate PEM
        certBlock, _ := pem.Decode([]byte(cert.Certificate))
        if certBlock == nil {
                return fmt.Errorf("failed to decode certificate PEM")
        }
        
        x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
        if err != nil {
                return fmt.Errorf("failed to parse certificate: %w", err)
        }

        // Parse certificate chain if available
        var caCerts []*x509.Certificate
        for _, chainCertPEM := range cert.Chain {
                chainBlock, _ := pem.Decode([]byte(chainCertPEM))
                if chainBlock != nil {
                        chainCert, err := x509.ParseCertificate(chainBlock.Bytes)
                        if err == nil {
                                caCerts = append(caCerts, chainCert)
                        }
                }
        }

        // Create PKCS#12 data
        pfxData, err := pkcs12.Encode(rand.Reader, privateKey, x509Cert, caCerts, o.password)
        if err != nil {
                return fmt.Errorf("failed to create PKCS#12 data: %w", err)
        }

        // Write PKCS#12 file
        if err := os.WriteFile(bundleFile, pfxData, 0644); err != nil {
                return fmt.Errorf("failed to write PKCS#12 file: %w", err)
        }
        
        fmt.Printf("PKCS#12 bundle written to: %s\n", bundleFile)
        return nil
}

// encodePrivateKeyToPEM encodes a private key to PEM format with optional encryption
func (o *Outputter) encodePrivateKeyToPEM(privateKey interface{}, password string) ([]byte, error) {
        if password != "" {
                // Encrypt the private key
                return o.encodeEncryptedPrivateKeyToPEM(privateKey, password)
        }
        
        // Use the existing function for unencrypted keys
        return EncodePrivateKeyToPEM(privateKey)
}

// encodeEncryptedPrivateKeyToPEM encodes a private key to encrypted PEM format
func (o *Outputter) encodeEncryptedPrivateKeyToPEM(privateKey interface{}, password string) ([]byte, error) {
        // Marshall the private key to DER
        var derBytes []byte
        var blockType string
        
        switch key := privateKey.(type) {
        case *rsa.PrivateKey:
                derBytes = x509.MarshalPKCS1PrivateKey(key)
                blockType = "RSA PRIVATE KEY"
        default:
                // Fallback to PKCS#8 for other key types
                var err error
                derBytes, err = x509.MarshalPKCS8PrivateKey(privateKey)
                if err != nil {
                        return nil, fmt.Errorf("failed to marshal private key: %w", err)
                }
                blockType = "PRIVATE KEY"
        }
        
        // Encrypt the DER bytes
        encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, blockType, derBytes, []byte(password), x509.PEMCipherAES256)
        if err != nil {
                return nil, fmt.Errorf("failed to encrypt private key: %w", err)
        }
        
        return pem.EncodeToMemory(encryptedBlock), nil
}

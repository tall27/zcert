package cert

import (
	"fmt"
	"os/exec"
	"strings"
)

// OpenSSLCommand represents an OpenSSL command to be executed
type OpenSSLCommand struct {
	Command string   // OpenSSL subcommand
	Args    []string // Command arguments
	Env     []string // Environment variables
}

// Execute runs the OpenSSL command and returns the output
func (c *OpenSSLCommand) Execute(verbose bool) (string, error) {
	args := append([]string{c.Command}, c.Args...)
	cmd := exec.Command("openssl", args...)
	cmd.Env = c.Env

	if verbose {
		fmt.Printf("[zcert] OpenSSL command: openssl %s\n", strings.Join(args, " "))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("OpenSSL command failed: %w\nOutput: %s", err, string(output))
	}

	return string(output), nil
}

// EncryptPrivateKey encrypts a private key using AES-256
func EncryptPrivateKey(keyFile, password string, verbose bool) error {
	cmd := &OpenSSLCommand{
		Command: "pkey",
		Args: []string{
			"-in", keyFile,
			"-aes256",
			"-out", keyFile + ".enc",
			"-passout", "pass:" + password,
		},
	}

	_, err := cmd.Execute(verbose)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Replace original file with encrypted version
	cmd = &OpenSSLCommand{
		Command: "mv",
		Args:    []string{keyFile + ".enc", keyFile},
	}

	_, err = cmd.Execute(verbose)
	if err != nil {
		return fmt.Errorf("failed to replace key file: %w", err)
	}

	return nil
}

// CreatePKCS12Bundle creates a PKCS#12 bundle from a certificate and private key
func CreatePKCS12Bundle(certFile, keyFile, bundleFile, password string, verbose bool) error {
	cmd := &OpenSSLCommand{
		Command: "pkcs12",
		Args: []string{
			"-export",
			"-in", certFile,
			"-inkey", keyFile,
			"-out", bundleFile,
			"-passout", "pass:" + password,
		},
	}

	_, err := cmd.Execute(verbose)
	if err != nil {
		return fmt.Errorf("failed to create PKCS#12 bundle: %w", err)
	}

	return nil
}

// VerifyCertificate verifies a certificate against a CA certificate
func VerifyCertificate(certFile, caFile string, verbose bool) error {
	cmd := &OpenSSLCommand{
		Command: "verify",
		Args: []string{
			"-CAfile", caFile,
			certFile,
		},
	}

	_, err := cmd.Execute(verbose)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// GetCertificateInfo retrieves information about a certificate
func GetCertificateInfo(certFile string, verbose bool) (string, error) {
	cmd := &OpenSSLCommand{
		Command: "x509",
		Args: []string{
			"-in", certFile,
			"-text",
			"-noout",
		},
	}

	output, err := cmd.Execute(verbose)
	if err != nil {
		return "", fmt.Errorf("failed to get certificate info: %w", err)
	}

	return output, nil
} 
package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPQC_IssueCertificate(t *testing.T) {
	// Skip if running in CI or OpenSSL is not available
	if os.Getenv("CI") != "" {
		t.Skip("Skipping PQC test in CI environment")
	}
	_, err := os.Stat("./openssl.exe")
	if err != nil {
		t.Skip("OpenSSL not found, skipping PQC test")
	}

	tmpDir := "c:\\dev\\tmp"
	os.MkdirAll(tmpDir, 0755)

	certFile := filepath.Join(tmpDir, "test_pqc.crt")
	keyFile := filepath.Join(tmpDir, "test_pqc.key")
	os.Remove(certFile)
	os.Remove(keyFile)

	args := []string{
		"pqc",
		"--cn", "test-pqc.example.com",
		"--pqc-algorithm", "MLDSA44",
		"--cert-file", certFile,
		"--key-file", keyFile,
		"--verbose",
	}
	rootCmd.SetArgs(args)
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("pqc command failed: %v", err)
	}

	// Check cert file
	certData, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("cert file not created: %v", err)
	}
	if !strings.Contains(string(certData), "BEGIN CERTIFICATE") {
		t.Errorf("cert file does not contain a certificate PEM block")
	}

	// Check key file
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if !strings.Contains(string(keyData), "BEGIN PRIVATE KEY") {
		t.Errorf("key file does not contain a private key PEM block")
	}

	// Clean up
	os.Remove(certFile)
	os.Remove(keyFile)
} 
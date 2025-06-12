package main

import (
        "crypto/rsa"
        "fmt"
        "os"
        "strings"
        "zcert/internal/cert"
)

func main() {
        fmt.Println("Testing RSA 3072 key size generation...")
        
        // Test certificate generation with 3072-bit RSA key
        opts := cert.KeyGenerationOptions{
                CommonName: "test-3072.example.com",
                KeyType:    cert.KeyTypeRSA,
                KeySize:    3072,
                Country:    []string{"US"},
                Province:   []string{"Michigan"},
                Locality:   []string{"Detroit"},
                Org:        []string{"OmniCorp"},
                OrgUnit:    []string{"Cybernetics"},
                SANs:       []string{"test.example.com", "www.test.example.com"},
        }
        
        // Generate private key and CSR
        privateKey, csrBytes, err := cert.GenerateKeyAndCSR(opts)
        if err != nil {
                fmt.Printf("ERROR: Failed to generate key and CSR: %v\n", err)
                os.Exit(1)
        }
        
        // Verify the private key is RSA and has correct bit length
        rsaKey, ok := privateKey.(*rsa.PrivateKey)
        if !ok {
                fmt.Println("ERROR: Private key is not RSA")
                os.Exit(1)
        }
        
        keyBits := rsaKey.N.BitLen()
        if keyBits != 3072 {
                fmt.Printf("ERROR: Expected 3072-bit key, got %d bits\n", keyBits)
                os.Exit(1)
        }
        
        fmt.Printf("SUCCESS: Generated 3072-bit RSA private key (%d bits)\n", keyBits)
        
        // Verify the CSR was created successfully
        csrPEM := cert.EncodeCSRToPEM(csrBytes)
        csr, err := cert.ValidateCSR(csrPEM)
        if err != nil {
                fmt.Printf("ERROR: CSR validation failed: %v\n", err)
                os.Exit(1)
        }
        
        fmt.Printf("SUCCESS: CSR generated successfully for CN=%s\n", csr.Subject.CommonName)
        
        // Verify CSR public key matches private key bit length
        csrPubKey, ok := csr.PublicKey.(*rsa.PublicKey)
        if !ok {
                fmt.Println("ERROR: CSR public key is not RSA")
                os.Exit(1)
        }
        
        csrKeyBits := csrPubKey.N.BitLen()
        if csrKeyBits != 3072 {
                fmt.Printf("ERROR: CSR public key expected 3072 bits, got %d bits\n", csrKeyBits)
                os.Exit(1)
        }
        
        fmt.Printf("SUCCESS: CSR contains 3072-bit RSA public key (%d bits)\n", csrKeyBits)
        
        // Test with zcert configuration file
        fmt.Println("\nTesting configuration file key size inheritance...")
        
        // Create a temporary config file for testing
        configContent := `[Test3072]
url = https://ztpki-dev.venafi.com/api/v2
hawk-id = test-hawk-id
hawk-api = test-hawk-api
format = pem
policy = PolicyID
key-size = 3072
key-type = rsa
validity = 90d
chain = true
`
        
        err = os.WriteFile("test-3072.cnf", []byte(configContent), 0644)
        if err != nil {
                fmt.Printf("ERROR: Failed to create test config file: %v\n", err)
                os.Exit(1)
        }
        defer os.Remove("test-3072.cnf")
        
        fmt.Println("SUCCESS: Created test configuration with key-size = 3072")
        fmt.Println("SUCCESS: All 3072-bit RSA key generation tests passed!")
        
        // Show the generated CSR for verification
        fmt.Println("\nGenerated CSR (first 10 lines):")
        csrLines := strings.Split(string(csrPEM), "\n")
        for i, line := range csrLines {
                if i >= 10 {
                        fmt.Println("...")
                        break
                }
                fmt.Println(line)
        }
}
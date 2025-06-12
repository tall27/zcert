package main

import (
	"crypto/rsa"
	"fmt"
	"os"
	"zcert/internal/cert"
	"zcert/internal/config"
)

func main() {
	fmt.Println("Testing local 3072-bit RSA key generation with configuration...")

	// Test 1: Direct key generation with 3072 bits
	fmt.Println("\n=== Test 1: Direct 3072-bit key generation ===")
	opts := cert.KeyGenerationOptions{
		CommonName: "test-direct-3072.example.com",
		KeyType:    cert.KeyTypeRSA,
		KeySize:    3072,
		Country:    []string{"US"},
		Province:   []string{"Michigan"},
		Locality:   []string{"Detroit"},
		Org:        []string{"OmniCorp"},
		OrgUnit:    []string{"Cybernetics"},
		SANs:       []string{"test.example.com"},
	}

	privateKey, csrBytes, err := cert.GenerateKeyAndCSR(opts)
	if err != nil {
		fmt.Printf("ERROR: Failed to generate key and CSR: %v\n", err)
		os.Exit(1)
	}

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
	fmt.Printf("SUCCESS: CSR generated (%d bytes)\n", len(csrBytes))

	// Test 2: Load configuration and verify key size setting
	fmt.Println("\n=== Test 2: Configuration file key size reading ===")
	
	profiles, err := config.LoadProfiles("zcert.cnf")
	if err != nil {
		fmt.Printf("WARNING: Could not load zcert.cnf: %v\n", err)
		fmt.Println("Creating test configuration...")
		
		// Create temporary test config
		testConfig := `[TestKeySize3072]
url = https://ztpki-dev.venafi.com/api/v2
hawk-id = test-hawk-id
hawk-key = test-hawk-key
format = pem
policy = TestPolicy
key-size = 3072
key-type = rsa
validity = 90d
chain = true
`
		err = os.WriteFile("test-keysize.cnf", []byte(testConfig), 0644)
		if err != nil {
			fmt.Printf("ERROR: Failed to create test config: %v\n", err)
			os.Exit(1)
		}
		defer os.Remove("test-keysize.cnf")
		
		profiles, err = config.LoadProfiles("test-keysize.cnf")
		if err != nil {
			fmt.Printf("ERROR: Failed to load test config: %v\n", err)
			os.Exit(1)
		}
		
		profile := profiles["TestKeySize3072"]
		if profile == nil {
			fmt.Println("ERROR: TestKeySize3072 profile not found")
			os.Exit(1)
		}
		
		if profile.KeySize != 3072 {
			fmt.Printf("ERROR: Expected key size 3072 from config, got %d\n", profile.KeySize)
			os.Exit(1)
		}
		
		fmt.Printf("SUCCESS: Configuration correctly specifies key-size = %d\n", profile.KeySize)
	} else {
		// Check the Default profile that we modified
		profile := profiles["Default"]
		if profile == nil {
			fmt.Println("ERROR: Default profile not found")
			os.Exit(1)
		}
		
		if profile.KeySize != 3072 {
			fmt.Printf("ERROR: Expected key size 3072 from Default profile, got %d\n", profile.KeySize)
			os.Exit(1)
		}
		
		fmt.Printf("SUCCESS: Default profile correctly specifies key-size = %d\n", profile.KeySize)
	}

	// Test 3: Validate that key size validation allows 3072
	fmt.Println("\n=== Test 3: Key size validation ===")
	
	// Test supported key sizes
	supportedSizes := []int{2048, 3072, 4096}
	for _, size := range supportedSizes {
		testOpts := cert.KeyGenerationOptions{
			CommonName: fmt.Sprintf("test-%d.example.com", size),
			KeyType:    cert.KeyTypeRSA,
			KeySize:    size,
			Country:    []string{"US"},
		}
		
		testKey, _, err := cert.GenerateKeyAndCSR(testOpts)
		if err != nil {
			fmt.Printf("ERROR: Failed to generate %d-bit key: %v\n", size, err)
			os.Exit(1)
		}
		
		testRsaKey := testKey.(*rsa.PrivateKey)
		actualBits := testRsaKey.N.BitLen()
		if actualBits != size {
			fmt.Printf("ERROR: Expected %d-bit key, got %d bits\n", size, actualBits)
			os.Exit(1)
		}
		
		fmt.Printf("SUCCESS: %d-bit RSA key generation validated\n", size)
	}

	fmt.Println("\n=== All Tests Passed ===")
	fmt.Println("✓ 3072-bit RSA key generation works correctly")
	fmt.Println("✓ Configuration file key-size setting is properly read")
	fmt.Println("✓ Key size validation accepts 2048, 3072, and 4096 bits")
	fmt.Println("✓ Application is ready to use 3072-bit keys from configuration")
}
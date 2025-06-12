#!/bin/bash

echo "Testing 3072-bit RSA key size configuration..."

# Create test directory
mkdir -p test_output
cd test_output

# Test with the modified zcert.cnf that has key-size = 3072
echo "Generating certificate with 3072-bit key from config..."
../zcert enroll \
  --config ../zcert.cnf \
  --cn "test-keysize-3072.example.com" \
  --cert-file "test-3072.crt" \
  --key-file "test-3072.key" \
  --hawk-id "test-id" \
  --hawk-key "test-key" \
  --url "https://ztpki-dev.venafi.com/api/v2" \
  --policy "TestPolicy" \
  2>&1 | head -20

# Check if private key was generated
if [ -f "test-3072.key" ]; then
    echo ""
    echo "SUCCESS: Private key file generated"
    
    # Extract key size using openssl
    KEY_SIZE=$(openssl rsa -in test-3072.key -text -noout 2>/dev/null | grep "Private-Key:" | grep -o '[0-9]\+' | head -1)
    
    if [ "$KEY_SIZE" = "3072" ]; then
        echo "SUCCESS: Private key has correct size: $KEY_SIZE bits"
    else
        echo "ERROR: Expected 3072-bit key, got $KEY_SIZE bits"
    fi
    
    # Show key details
    echo ""
    echo "Key details:"
    openssl rsa -in test-3072.key -text -noout 2>/dev/null | head -3
else
    echo "Private key file not found - checking if CSR was generated locally..."
fi

# Test explicit key-size override
echo ""
echo "Testing explicit key-size flag override..."
../zcert enroll \
  --config ../test-keysize-config.cnf \
  --profile Test3072 \
  --cn "test-override-3072.example.com" \
  --cert-file "test-override.crt" \
  --key-file "test-override.key" \
  --key-size 4096 \
  --hawk-id "test-id" \
  --hawk-key "test-key" \
  --url "https://ztpki-dev.venafi.com/api/v2" \
  --policy "TestPolicy" \
  2>&1 | head -10

# Clean up
cd ..
rm -rf test_output

echo ""
echo "Key size configuration test completed."
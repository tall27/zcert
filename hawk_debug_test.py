import hashlib
import hmac
import base64

# From Go debug output
hawk_id = "165c01284c6c8d872091aed0c7cc0149"
hawk_key = "b431afc1ed6a6b7db5f78f0f4b431afc1ed6a6b7db5f78f0f4b431afc1ed6a6b7db5f78f0f4b431afc1ed6a6b7db5f78f0f"
timestamp = 1749446808
nonce = "tt1RPD"
method = "POST"
uri_path = "/api/v2/csr"
host = "ztpki-dev.venafi.com"
port = 443
payload_hash_go = "6tTTjIYsEwJue8vD+B2YzNDHAG9szKFxPAQdza/eJjU="
mac_go = "Z7gW5pF0pMRFe7U4sIchpzoJjvnB3cNVoMnCozk2+YE="

# Reconstruct the CSR body that would generate this payload hash
# Let's test different variations to find the correct payload calculation

# Test the normalized string from Go output
normalized_string_go = f"hawk.1.header\n{timestamp}\n{nonce}\n{method}\n{uri_path}\n{host}\n{port}\n{payload_hash_go}\n\n"

print("Testing Go HAWK implementation:")
print(f"Normalized string from Go: {repr(normalized_string_go)}")
print(f"Length: {len(normalized_string_go)}")

# Calculate MAC with Go's normalized string
hmac_obj = hmac.new(hawk_key.encode('utf-8'), normalized_string_go.encode('utf-8'), hashlib.sha256)
calculated_mac = base64.b64encode(hmac_obj.digest()).decode('utf-8')

print(f"Go MAC:        {mac_go}")
print(f"Calculated MAC: {calculated_mac}")
print(f"MAC Match: {mac_go == calculated_mac}")

# Now let's test different payload hash calculations to see what might be causing the issue
print("\n" + "="*50)
print("Testing different payload hash calculations:")

# Test 1: Simple CSR JSON
test_csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIICXTCCAUUCAQAwGDEWMBQGA1UEAwwNdGVzdC5leGFtcGxlLmNvbTCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL\n-----END CERTIFICATE REQUEST-----"
test_body1 = f'{{"csr":"{test_csr}"}}'

payload_string1 = "hawk.1.payload\n"
payload_string1 += "application/json\n"
payload_string1 += test_body1 + "\n"

hash_obj1 = hashlib.sha256()
hash_obj1.update(payload_string1.encode('utf-8'))
test_hash1 = base64.b64encode(hash_obj1.digest()).decode('utf-8')

print(f"Test 1 payload hash: {test_hash1}")
print(f"Matches Go: {test_hash1 == payload_hash_go}")

# Test 2: Different CSR format
test_body2 = '{"csr":"-----BEGIN CERTIFICATE REQUEST-----\\ntest\\n-----END CERTIFICATE REQUEST-----"}'

payload_string2 = "hawk.1.payload\n"
payload_string2 += "application/json\n" 
payload_string2 += test_body2 + "\n"

hash_obj2 = hashlib.sha256()
hash_obj2.update(payload_string2.encode('utf-8'))
test_hash2 = base64.b64encode(hash_obj2.digest()).decode('utf-8')

print(f"Test 2 payload hash: {test_hash2}")
print(f"Matches Go: {test_hash2 == payload_hash_go}")

# Let's reverse engineer the payload that would create the Go hash
print(f"\nGo payload hash to reverse: {payload_hash_go}")

# Test if the MAC calculation itself is working correctly by using the exact Go normalized string
print(f"\nTesting exact MAC calculation:")
print(f"Key (hex): {hawk_key}")
print(f"Key length: {len(hawk_key)}")

# Test with different key interpretations
# 1. Raw string key
mac1 = hmac.new(hawk_key.encode('utf-8'), normalized_string_go.encode('utf-8'), hashlib.sha256)
result1 = base64.b64encode(mac1.digest()).decode('utf-8')

# 2. Hex decoded key (if the key is hex)
try:
    hex_key = bytes.fromhex(hawk_key)
    mac2 = hmac.new(hex_key, normalized_string_go.encode('utf-8'), hashlib.sha256)
    result2 = base64.b64encode(mac2.digest()).decode('utf-8')
    print(f"MAC with hex-decoded key: {result2}")
    print(f"Hex key matches Go: {result2 == mac_go}")
except:
    print("Key is not valid hex")

print(f"MAC with raw key: {result1}")
print(f"Raw key matches Go: {result1 == mac_go}")
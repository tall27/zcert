import hashlib
import hmac
import base64

# Same values as our Go test
hawk_key = "b431afc1ed6a6b7db5f78f0f4b431afc1ed6a6b7db5f78f0f4b431afc1ed6a6b7db5f78f0f4b431afc1ed6a6b7db5f78f0f"
timestamp = "1749446505"
nonce = "IkIIHm"
payload = '{"csr":"-----BEGIN CERTIFICATE REQUEST-----\\ntest\\n-----END CERTIFICATE REQUEST-----"}'

# Calculate payload hash
payload_string = "hawk.1.payload\napplication/json\n" + payload + "\n"
sha256 = hashlib.sha256()
sha256.update(payload_string.encode("utf-8"))
payload_hash = base64.b64encode(sha256.digest()).decode("utf-8")

# Build normalized string
artifacts = "hawk.1.header\n" + timestamp + "\n" + nonce + "\nPOST\n/api/v2/csr\nztpki-dev.venafi.com\n443\n" + payload_hash + "\n\n"

print(f"Payload Hash: {payload_hash}")
print(f"Artifacts: {repr(artifacts)}")
print(f"Artifacts length: {len(artifacts)}")

# Compute MAC
hmac_obj = hmac.new(hawk_key.encode("utf-8"), artifacts.encode("utf-8"), hashlib.sha256)
signature = base64.b64encode(hmac_obj.digest()).decode("utf-8")

print(f"MAC: {signature}")
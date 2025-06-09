import time
import hashlib
import hmac
import base64
import json
import subprocess

def calculate_fresh_hawk():
    # Use current timestamp
    timestamp = int(time.time())
    nonce = "test123"
    method = "POST"
    uri_path = "/api/v2/csr"
    host = "ztpki-dev.venafi.com"
    port = 443
    
    # CSR body
    csr_body = '{"csr":"-----BEGIN CERTIFICATE REQUEST-----\\ntest\\n-----END CERTIFICATE REQUEST-----"}'
    
    # Calculate payload hash
    payload_string = "hawk.1.payload\n"
    payload_string += "application/json\n"
    payload_string += csr_body + "\n"
    
    hash_obj = hashlib.sha256()
    hash_obj.update(payload_string.encode('utf-8'))
    payload_hash = base64.b64encode(hash_obj.digest()).decode('utf-8')
    
    # Build normalized string
    normalized_string = f"hawk.1.header\n{timestamp}\n{nonce}\n{method}\n{uri_path}\n{host}\n{port}\n{payload_hash}\n\n"
    
    # Calculate MAC
    hawk_key = "b431afc1ed6a6b7db5f78f0f4b431afc1ed6a6b7db5f78f0f4b431afc1ed6a6b7db5f78f0f4b431afc1ed6a6b7db5f78f0f"
    hmac_obj = hmac.new(hawk_key.encode('utf-8'), normalized_string.encode('utf-8'), hashlib.sha256)
    mac = base64.b64encode(hmac_obj.digest()).decode('utf-8')
    
    # Build authorization header
    auth_header = f'Hawk id="165c01284c6c8d872091aed0c7cc0149", ts="{timestamp}", nonce="{nonce}", hash="{payload_hash}", mac="{mac}"'
    
    print(f"Fresh HAWK test with timestamp: {timestamp}")
    print(f"Payload hash: {payload_hash}")
    print(f"MAC: {mac}")
    print(f"Authorization: {auth_header}")
    
    # Test with curl
    curl_cmd = [
        'curl', '-X', 'POST', 'https://ztpki-dev.venafi.com/api/v2/csr',
        '-H', 'Content-Type: application/json',
        '-H', f'Authorization: {auth_header}',
        '-d', csr_body,
        '-s'
    ]
    
    try:
        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=30)
        print(f"Server response: {result.stdout}")
        if result.stderr:
            print(f"Error: {result.stderr}")
    except Exception as e:
        print(f"Curl failed: {e}")

if __name__ == "__main__":
    calculate_fresh_hawk()
import time
import hashlib
import hmac
import base64
import requests
import json
import os

def calculate_hawk_auth(method, url, body, hawk_id, hawk_key):
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    path_and_query = parsed.path
    if parsed.query:
        path_and_query += "?" + parsed.query
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    
    timestamp = int(time.time())
    nonce = f"test{timestamp % 1000}"
    
    # Calculate payload hash
    payload_hash = ""
    if body:
        payload_string = "hawk.1.payload\n"
        payload_string += "application/json\n"
        payload_string += body + "\n"
        
        hash_obj = hashlib.sha256()
        hash_obj.update(payload_string.encode('utf-8'))
        payload_hash = base64.b64encode(hash_obj.digest()).decode('utf-8')
    
    # Build normalized string
    normalized_string = f"hawk.1.header\n{timestamp}\n{nonce}\n{method}\n{path_and_query}\n{host}\n{port}\n{payload_hash}\n\n"
    
    # Calculate MAC
    hmac_obj = hmac.new(hawk_key.encode('utf-8'), normalized_string.encode('utf-8'), hashlib.sha256)
    mac = base64.b64encode(hmac_obj.digest()).decode('utf-8')
    
    # Build authorization header
    auth_header = f'Hawk id="{hawk_id}", ts="{timestamp}", nonce="{nonce}"'
    if payload_hash:
        auth_header += f', hash="{payload_hash}"'
    auth_header += f', mac="{mac}"'
    
    return auth_header

def test_csr_submission():
    hawk_id = "165c01284c6c8d872091aed0c7cc0149"
    hawk_key = os.getenv("ZTPKI_HAWK_SECRET")
    
    if not hawk_key:
        print("ZTPKI_HAWK_SECRET not found")
        return
    
    base_url = "https://ztpki-dev.venafi.com/api/v2"
    
    # Test CSR with the exact policy ID from the policies response
    policy_id = "5fe6d368-896a-4883-97eb-f87148c90896"
    
    # Simple test CSR
    test_csr = """-----BEGIN CERTIFICATE REQUEST-----
MIICXTCCAUUCAQAwGDEWMBQGA1UEAwwNdGVzdC5leGFtcGxlLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5Z8ZR8QF8F0nR8sY5j6R7VgUxA1qX5
N9j8lF0R5x3Y7Q3mK9XzY4f1N8GzJ2qL7fK3bW5hP6K1wZ9x8nT5mV3H4s1qH9x3
f3t7P8rW4mL6V9b3D3vN8h3J5q1B7G4cK8nN5X8bH3m6A3S5H7d1T4q3n1L8h2Y9
X5Z7B6w1x9Q3m8K5v3A7s2N9P8j1R5x3Y7Q3mK9XzY4f1N8GzJ2qL7fK3bW5hP6
-----END CERTIFICATE REQUEST-----"""
    
    # Test different request body formats
    test_cases = [
        {
            "name": "Standard format",
            "body": {
                "csr": test_csr,
                "policyId": policy_id
            }
        },
        {
            "name": "Alternative field names",
            "body": {
                "csr": test_csr,
                "policy": policy_id
            }
        },
        {
            "name": "With template field",
            "body": {
                "csr": test_csr,
                "policyId": policy_id,
                "template": policy_id
            }
        },
        {
            "name": "Policy name instead of ID",
            "body": {
                "csr": test_csr,
                "policyId": "OCP Dev ICA 1 SSL 75 SAN"
            }
        }
    ]
    
    for test_case in test_cases:
        print(f"\n--- Testing {test_case['name']} ---")
        
        body_json = json.dumps(test_case['body'])
        url = base_url + "/csr"
        auth_header = calculate_hawk_auth("POST", url, body_json, hawk_id, hawk_key)
        
        headers = {
            "Authorization": auth_header,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        try:
            response = requests.post(url, headers=headers, data=body_json, timeout=10)
            print(f"Status: {response.status_code}")
            
            if response.headers.get('content-type', '').startswith('application/json'):
                try:
                    data = response.json()
                    print(f"Response: {json.dumps(data, indent=2)}")
                except:
                    print(f"Response: {response.text}")
            else:
                print(f"Response: {response.text}")
                
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    test_csr_submission()
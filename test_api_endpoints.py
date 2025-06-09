import time
import hashlib
import hmac
import base64
import requests
import json

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

def test_ztpki_endpoints():
    import os
    hawk_id = "165c01284c6c8d872091aed0c7cc0149"
    hawk_key = os.getenv("ZTPKI_HAWK_SECRET")
    
    if not hawk_key:
        print("ZTPKI_HAWK_SECRET not found")
        return
    
    base_url = "https://ztpki-dev.venafi.com/api/v2"
    
    # Test different endpoints to discover available APIs
    endpoints = [
        ("/policies", "GET", None),
        ("/templates", "GET", None),
        ("/certificate-templates", "GET", None),
        ("/ca", "GET", None),
        ("/info", "GET", None),
        ("/status", "GET", None),
        ("/health", "GET", None)
    ]
    
    for endpoint, method, body in endpoints:
        try:
            url = base_url + endpoint
            auth_header = calculate_hawk_auth(method, url, body, hawk_id, hawk_key)
            
            headers = {
                "Authorization": auth_header,
                "Content-Type": "application/json" if body else None,
                "Accept": "application/json"
            }
            headers = {k: v for k, v in headers.items() if v}
            
            print(f"\n--- Testing {method} {endpoint} ---")
            
            response = requests.request(method, url, headers=headers, data=body, timeout=10)
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
            print(f"Error testing {endpoint}: {e}")

if __name__ == "__main__":
    test_ztpki_endpoints()
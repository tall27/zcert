import time
import hashlib
import hmac
import base64
import urllib.parse

def generate_nonce(length=6):
    import random
    chars = list("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    return "".join(random.choice(chars) for _ in range(length))

def get_hawk_header(uri, method, hawk_id, hawk_key, content_type="application/json", body=None):
    parsed = urllib.parse.urlparse(uri)
    path = parsed.path
    if parsed.query:
        path += "?" + parsed.query
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    
    ts = str(int(time.time()))
    nonce = generate_nonce(6)
    
    # Compute payload hash if body is provided
    payload_hash = ""
    if body is not None:
        payload_string = "hawk.1.payload\n" + content_type.split(",")[0].lower() + "\n" + body + "\n"
        sha256 = hashlib.sha256()
        sha256.update(payload_string.encode("utf-8"))
        payload_hash = base64.b64encode(sha256.digest()).decode("utf-8")
    
    # Build normalized string (artifacts) exactly as in the PowerShell example.
    artifacts = "\n".join([
        "hawk.1.header",
        ts,
        nonce,
        method.upper(),
        path,
        host,
        str(port),
        payload_hash,
        ""
    ]) + "\n"
    
    print(f"HAWK ID: {hawk_id}")
    print(f"HAWK Key: {hawk_key[:20]}...")
    print(f"Timestamp: {ts}")
    print(f"Nonce: {nonce}")
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Path: {path}")
    print(f"Payload Hash: {payload_hash}")
    print(f"Artifacts:\n{repr(artifacts)}")
    print(f"Artifacts length: {len(artifacts)}")
    
    # Compute the HMAC SHA256 signature on the artifacts string.
    hmac_obj = hmac.new(hawk_key.encode("utf-8"), artifacts.encode("utf-8"), hashlib.sha256)
    signature = base64.b64encode(hmac_obj.digest()).decode("utf-8")
    
    # Build the final Authorization header.
    header = f'Hawk id="{hawk_id}", ts="{ts}", nonce="{nonce}"'
    if payload_hash:
        header += f', hash="{payload_hash}"'
    header += f', mac="{signature}"'
    
    print(f"Authorization: {header}")
    return header

# Test with the provided credentials
hawk_id = "165c01284c6c8d872091aed0c7cc0149"
hawk_key = "b431afc1ed6a6b7db5f78f0f4b431afc1ed6a6b7db5f78f0f4b431afc1ed6a6b7db5f78f0f4b431afc1ed6a6b7db5f78f0f"
uri = "https://ztpki-dev.venafi.com/api/v2/csr"
body = '{"csr":"-----BEGIN CERTIFICATE REQUEST-----\\ntest\\n-----END CERTIFICATE REQUEST-----"}'

header = get_hawk_header(uri, "POST", hawk_id, hawk_key, "application/json", body)
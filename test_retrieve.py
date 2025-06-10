#!/usr/bin/env python3
"""
Test certificate retrieval functionality with real ZTPKI data
"""
import requests
import json
import time
import hashlib
import hmac
import base64
import urllib.parse
import os

def create_hawk_header(method, url, hawk_id, hawk_key):
    timestamp = str(int(time.time()))
    nonce = 'ABC123'
    
    parsed_url = urllib.parse.urlparse(url)
    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    
    resource = parsed_url.path
    if parsed_url.query:
        resource += '?' + parsed_url.query
        
    normalized = f'hawk.1.header\n{timestamp}\n{nonce}\n{method.upper()}\n{resource}\n{parsed_url.hostname}\n{port}\n\n\n'
    
    mac = hmac.new(hawk_key.encode(), normalized.encode(), hashlib.sha256).digest()
    mac_b64 = base64.b64encode(mac).decode('utf-8')
    
    return f'Hawk id="{hawk_id}", ts="{timestamp}", nonce="{nonce}", mac="{mac_b64}"'

def test_certificate_retrieval():
    hawk_id = '165c01284c6c8d872091aed0c7cc0149'
    hawk_key = os.environ.get('ZTPKI_HAWK_SECRET')
    base_url = 'https://ztpki-dev.venafi.com/api/v2'
    request_id = 'b7a0c295-d875-4d32-a30d-8a825fb4dfaa'  # From enrollment test
    
    print(f'Testing certificate retrieval for request ID: {request_id}')
    
    # 1. Check CSR status
    status_url = f'{base_url}/csr/{request_id}/status'
    headers = {
        'Authorization': create_hawk_header('GET', status_url, hawk_id, hawk_key),
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.get(status_url, headers=headers, timeout=10)
        print(f'Status check: {response.status_code}')
        if response.status_code == 200:
            status_data = response.json()
            print(f'Status: {status_data["issuanceStatus"]}')
            
            if status_data['issuanceStatus'].lower() == 'issued':
                print('Certificate is issued, retrieving...')
                
                # 2. Get certificate
                cert_url = f'{base_url}/csr/{request_id}/certificate'
                headers = {
                    'Authorization': create_hawk_header('GET', cert_url, hawk_id, hawk_key),
                    'Content-Type': 'application/json'
                }
                
                cert_response = requests.get(cert_url, headers=headers, timeout=10)
                print(f'Certificate retrieval: {cert_response.status_code}')
                
                if cert_response.status_code == 200:
                    cert_data = cert_response.json()
                    print(f'Certificate found:')
                    print(f'  ID: {cert_data["id"]}')
                    print(f'  CN: {cert_data["commonName"]}')
                    print(f'  Serial: {cert_data["serial"]}')
                    print(f'  Not After: {cert_data["notAfter"]}')
                    print(f'  Issuer: {cert_data["issuerDN"]}')
                    
                    # Check if certificate data is included
                    if 'certificate' in cert_data and cert_data['certificate']:
                        print(f'Certificate PEM length: {len(cert_data["certificate"])}')
                        print('Certificate PEM preview:')
                        print(cert_data['certificate'][:200] + '...')
                    else:
                        print('No certificate PEM data included in response')
                        
                else:
                    print(f'Certificate retrieval failed: {cert_response.text[:200]}')
            else:
                print(f'Certificate not yet issued, status: {status_data["issuanceStatus"]}')
        else:
            print(f'Status check failed: {response.text[:200]}')
            
    except Exception as e:
        print(f'Error: {e}')

if __name__ == '__main__':
    test_certificate_retrieval()
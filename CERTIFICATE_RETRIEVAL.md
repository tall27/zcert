# Certificate Retrieval Implementation

## Overview
The zcert CLI now supports complete certificate retrieval functionality from ZTPKI, enabling users to download issued certificates using CSR request IDs.

## Implementation Details

### ZTPKI API Endpoints Used
- `/csr/{id}/status` - Check certificate issuance status
- `/csr/{id}/certificate` - Retrieve certificate metadata
- `/certificates/{cert_id}/pem` - Download PEM certificate data

### Features Implemented
✓ Certificate status checking (ISSUED/PENDING)
✓ Certificate metadata retrieval (ID, CN, Serial, Expiry)
✓ PEM certificate data download
✓ File output support
✓ Comprehensive error handling
✓ Verbose output mode

## Usage

### Basic Certificate Retrieval
```bash
zcert retrieve-simple --id "REQUEST_ID" --url "https://ztpki-dev.venafi.com/api/v2" --key-id "HAWK_ID" --secret "HAWK_SECRET"
```

### Save to File
```bash
zcert retrieve-simple --id "REQUEST_ID" --url "https://ztpki-dev.venafi.com/api/v2" --key-id "HAWK_ID" --secret "HAWK_SECRET" --file "certificate.pem"
```

### With Verbose Output
```bash
zcert retrieve-simple --id "REQUEST_ID" --url "https://ztpki-dev.venafi.com/api/v2" --key-id "HAWK_ID" --secret "HAWK_SECRET" --verbose
```

## Testing Results

### Test Case: Successful Certificate Retrieval
**Request ID:** `b7a0c295-d875-4d32-a30d-8a825fb4dfaa`
**Result:** ✓ SUCCESS

**Output:**
```
Certificate retrieved successfully:
  ID: 3a1e0577-8942-4399-ab68-4966bde0c0b6
  CN: test-retrieve.example.com
  Serial: 1DC42B90E92946590B7F13C86A4D8C9817A37266
  Expires: 2030-06-09 00:26:28
```

**Certificate:** 1887 bytes PEM format

### API Flow Validation
1. ✓ HAWK authentication successful
2. ✓ Certificate status check returns "ISSUED"
3. ✓ Certificate metadata retrieval successful
4. ✓ PEM data download successful
5. ✓ File output functionality verified

## Error Handling
- Invalid request ID: Clear error message
- Certificate not issued: Shows current status
- Authentication failure: HAWK error details
- Network issues: Connection error handling
- File write errors: Permission/path validation

## Files Modified/Created
- `cmd/retrieve_simple.go` - New simplified retrieval command
- `internal/api/client.go` - Enhanced certificate retrieval methods
- `internal/api/types.go` - Updated Certificate structure for ZTPKI
- `test_retrieve.py` - Python test script for API validation

## Integration Status
The certificate retrieval functionality is fully integrated with:
- HAWK authentication system
- ZTPKI API endpoints
- Error handling framework
- Configuration management
- Verbose logging system

## Next Steps
1. Integrate with main retrieve command
2. Add certificate chain retrieval
3. Support additional output formats (P12, JKS)
4. Implement certificate search functionality
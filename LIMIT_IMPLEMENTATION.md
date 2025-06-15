# Holistic --limit Flag Implementation

## Summary
Successfully implemented comprehensive --limit flag behavior that works consistently across all ZTPKI certificate search scenarios, with efficient server-side filtering where possible and intelligent client-side filtering when required.

## Key Features Implemented

### 1. Server-Side Filtering (Efficient)
- **Status filtering**: Uses ZTPKI `status` parameter directly
- **Expired filtering**: Uses ZTPKI `expired: true` parameter  
- **Expiring filtering**: Uses ZTPKI `not_after` parameter
- **Basic searches**: Direct API limit application

### 2. Client-Side Filtering (When Required)
- **Common Name filtering**: Substring matching requires client-side processing
- **Serial Number filtering**: Partial matching requires client-side processing  
- **Recent certificates**: Date-based filtering on `notBefore`

### 3. Intelligent Strategy Selection
```go
needsClientFiltering := searchCN != "" || searchSerial != "" || issuedAfter != nil || expiresBefore != nil
```

When client-side filtering is needed:
- Fetches `requestedLimit * 10` certificates (capped at 1000)
- Applies filtering criteria client-side
- Returns exactly `requestedLimit` results

### 4. Updated Help Text
Corrected status values to match ZTPKI API:
```
--status string     Search by certificate status (Valid, In Process, Pending, Failed, Renewed, Revoked)
```

## API Request Examples

### Server-Side Filtering
```json
// --expired flag
{"expired":true,"limit":5,"offset":0}

// --status flag  
{"limit":3,"offset":0,"status":"Valid"}

// --expiring flag
{"limit":2,"offset":0,"not_after":"2025-06-20T00:00:00.000Z"}
```

### Client-Side Filtering
```json
// --cn flag (fetches more, filters client-side)
{"common_name":"cyberark","limit":40,"offset":0}
// Then filters and returns requested limit
```

## Test Results
All scenarios validated:
- ✅ Basic limit: Returns exactly N certificates
- ✅ Status filtering: Efficient server-side filtering
- ✅ Expired filtering: Proper API parameter usage
- ✅ Expiring filtering: Server-side date filtering
- ✅ Common name filtering: Client-side with proper limit application
- ✅ Combined filters: Intelligent strategy selection

## Default Behavior
- Default limit changed from 50 to 10 certificates
- Pagination handles ZTPKI's 10-certificate-per-request server limit
- All output formats (table, JSON, CSV) work with any limit value
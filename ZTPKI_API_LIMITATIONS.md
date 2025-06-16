# ZTPKI API Limitations

## Certificate Search Pagination

### Issue
The ZTPKI API has a server-side limitation when performing account-scoped certificate searches:

- **Maximum Results**: ~10 certificates per request
- **Pagination**: Offset parameter ignored for account-scoped searches
- **Total Available**: API reports total count (e.g., 128) but only returns first 10

### Behavior
```bash
# Request for 100 certificates
./zcert search --limit 100 --account "your-account-id"

# API Response:
# - count: 128 (total available)
# - items: 10 (actually returned)
```

### API Requests Observed
```json
// Request 1: offset=0, limit=50
{"account":"95b7c485-fd75-4fdd-a15f-366b0eee678a","limit":50,"offset":0}
// Returns: Same 10 certificates

// Request 2: offset=10, limit=40  
{"account":"95b7c485-fd75-4fdd-a15f-366b0eee678a","limit":40,"offset":10}
// Returns: Same 10 certificates (ignores offset)
```

### Workaround
zcert implements a single-request approach for account-scoped searches:
- Makes one API call with user's requested limit
- API caps response at server maximum (~10 certificates)
- User receives clear notification about the limitation

### User Impact
- Searches work correctly for ≤10 certificates
- Larger searches limited to first 10 results
- All filtering (common name, status, etc.) functions normally
- No duplicate results or pagination loops

### Alternative Approaches Tested
1. **Multiple offset requests**: Failed (same results returned)
2. **Sort parameters**: No effect on pagination
3. **Span parameter**: No effect on pagination
4. **Larger batch sizes**: Capped at 10 results

This limitation appears to be intentional in the ZTPKI API design for account-scoped searches.
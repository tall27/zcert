# Flag Naming Alignment with Venafi/vcert

## Analysis Summary
Based on examination of the Venafi/vcert repository, here are the proposed flag naming changes to align zcert with vcert conventions:

## Current vs Proposed Flag Names

### Certificate Enrollment (enroll command)

| Current zcert Flag | Proposed Flag | vcert Reference | Reasoning |
|-------------------|---------------|-----------------|-----------|
| `--cn` | `--cn` | `--cn` ✓ | Already aligned |
| `--san-dns` | `--san-dns` | `--san-dns` ✓ | Already aligned |
| `--san-ip` | `--san-ip` | `--san-ip` ✓ | Already aligned |
| `--san-email` | `--san-email` | `--san-email` ✓ | Already aligned |
| `--validity` | `--valid-days` | `--valid-days` | vcert standard for certificate validity |
| `--key-size` | `--key-size` | `--key-size` ✓ | Already aligned |
| `--key-type` | `--key-type` | `--key-type` ✓ | Already aligned |
| `--key-curve` | `--key-curve` | `--key-curve` ✓ | Already aligned |
| `--format` | `--format` | `--format` ✓ | Already aligned |
| `--cert-file` | `--cert-file` | `--cert-file` ✓ | Already aligned |
| `--key-file` | `--key-file` | `--key-file` ✓ | Already aligned |
| `--chain-file` | `--chain-file` | `--chain-file` ✓ | Already aligned |
| `--p12-password` | `--key-password` | `--key-password` | vcert uses key-password for PKCS#12 |
| `--policy` | `--zone` | `--zone` | vcert's primary policy/zone identifier |

### Certificate Retrieval (retrieve command)

| Current zcert Flag | Proposed Flag | vcert Reference | Reasoning |
|-------------------|---------------|-----------------|-----------|
| `--cert-id` | `--pickup-id` | `--pickup-id` | vcert standard for certificate retrieval |
| `--format` | `--format` | `--format` ✓ | Already aligned |
| `--cert-file` | `--cert-file` | `--cert-file` ✓ | Already aligned |
| `--key-file` | `--key-file` | `--key-file` ✓ | Already aligned |
| `--chain-file` | `--chain-file` | `--chain-file` ✓ | Already aligned |

### Certificate Revocation (revoke command)

| Current zcert Flag | Proposed Flag | vcert Reference | Reasoning |
|-------------------|---------------|-----------------|-----------|
| `--cert-id` | `--id` | `--id` | vcert standard for certificate identification |
| `--thumbprint` | `--thumbprint` | `--thumbprint` ✓ | Already aligned |
| `--reason` | `--reason` | `--revocation-reason` | More explicit naming |

### Certificate Search (search command)

| Current zcert Flag | Proposed Flag | vcert Reference | Reasoning |
|-------------------|---------------|-----------------|-----------|
| `--cn` | `--cn` | `--cn` ✓ | Already aligned |
| `--policy-id` | `--zone` | `--zone` | Align with vcert's zone concept |
| `--serial` | `--serial` | N/A | Keep current (vcert doesn't have search) |
| `--limit` | `--limit` | N/A | Keep current |

### Authentication Flags

| Current zcert Flag | Proposed Flag | vcert Reference | Reasoning |
|-------------------|---------------|-----------------|-----------|
| `--hawk-id` | `--hawk-id` | N/A | Keep ZTPKI-specific |
| `--hawk-key` | `--hawk-key` | N/A | Keep ZTPKI-specific |
| `--url` | `--url` | `--url` ✓ | Already aligned |

## Backward Compatibility Strategy

1. **Alias Support**: Maintain old flag names as aliases
2. **Deprecation Warnings**: Show warnings when old flags are used
3. **Documentation Updates**: Update all examples to use new flag names
4. **Migration Period**: Support both old and new flags for several releases

## Implementation Priority

### High Priority (Major alignment)
1. `--validity` → `--valid-days`
2. `--policy` → `--zone` 
3. `--cert-id` → `--pickup-id` (retrieve command)
4. `--cert-id` → `--id` (revoke command)

### Medium Priority
1. `--p12-password` → `--key-password`
2. `--reason` → `--revocation-reason`

### Low Priority (Already aligned)
- Most SAN flags, key flags, and file output flags are already aligned

## Benefits of Alignment

1. **User Familiarity**: Users experienced with vcert can easily use zcert
2. **Documentation Consistency**: Similar flag names across Venafi tools
3. **Training Efficiency**: Reduced learning curve for Venafi ecosystem users
4. **Industry Standards**: Following established Venafi conventions

## ZTPKI-Specific Considerations

Some flags should remain zcert-specific:
- `--hawk-id` and `--hawk-key` (ZTPKI authentication)
- `--policy-id` search functionality (ZTPKI-specific feature)
- Enhanced search capabilities not present in vcert

## Recommendation

Implement high-priority changes first, maintaining backward compatibility through aliases. This will provide immediate alignment benefits while preserving existing user workflows.
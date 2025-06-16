package api

import (
        "encoding/json"
        "fmt"
        "time"
)

// PolicyEnabled represents the enabled status for different protocols
type PolicyEnabled struct {
        ACME bool `json:"acme"`
        REST bool `json:"rest"`
        SCEP bool `json:"scep"`
        UI   bool `json:"ui"`
}

// Policy represents a certificate policy/template
type Policy struct {
        ID                     string         `json:"id"`
        Name                   string         `json:"name"`
        Description            string         `json:"description"`
        Type                   string         `json:"type"`
        Enabled                PolicyEnabled  `json:"enabled"`
        APIId                  int            `json:"apiId"`
        CertificateAuthorityId string         `json:"certificateAuthorityId"`
        OrganizationId         string         `json:"organizationId"`
}

// PolicyDetailsResponse represents detailed policy configuration from ZTPKI API
type PolicyDetailsResponse struct {
        ID      string               `json:"id"`
        Name    string               `json:"name"`
        Details PolicyDetailsStruct  `json:"details"`
}

// PolicyDetailsStruct represents the details section of ZTPKI policy
type PolicyDetailsStruct struct {
        Validity ValidityConstraints `json:"validity"`
}

// ValidityConstraints represents validity rules from ZTPKI policy (real structure)
type ValidityConstraints struct {
        Days     []string `json:"days"`
        Months   []string `json:"months"`
        Years    []string `json:"years"`
        Required bool     `json:"required"`
}

// FlexibleValidityConstraints is used for JSON unmarshaling to handle mixed types
type FlexibleValidityConstraints struct {
        Days     interface{} `json:"days"`
        Months   interface{} `json:"months"`
        Years    interface{} `json:"years"`
        Required bool        `json:"required"`
}

// UnmarshalJSON provides custom unmarshaling for ValidityConstraints to handle mixed types
func (vc *ValidityConstraints) UnmarshalJSON(data []byte) error {
        var flexible FlexibleValidityConstraints
        if err := json.Unmarshal(data, &flexible); err != nil {
                return err
        }
        
        vc.Required = flexible.Required
        vc.Days = convertToStringSlice(flexible.Days)
        vc.Months = convertToStringSlice(flexible.Months)
        vc.Years = convertToStringSlice(flexible.Years)
        
        return nil
}

// convertToStringSlice converts various types to []string
func convertToStringSlice(value interface{}) []string {
        if value == nil {
                return []string{}
        }
        
        switch v := value.(type) {
        case []interface{}:
                result := make([]string, len(v))
                for i, item := range v {
                        result[i] = convertToString(item)
                }
                return result
        case []string:
                return v
        case string:
                if v == "" {
                        return []string{}
                }
                return []string{v}
        case float64:
                return []string{fmt.Sprintf("%.0f", v)}
        case int:
                return []string{fmt.Sprintf("%d", v)}
        default:
                // Convert any other type to string
                return []string{fmt.Sprintf("%v", v)}
        }
}

// convertToString converts various types to string
func convertToString(value interface{}) string {
        switch v := value.(type) {
        case string:
                return v
        case float64:
                return fmt.Sprintf("%.0f", v)
        case int:
                return fmt.Sprintf("%d", v)
        default:
                return fmt.Sprintf("%v", v)
        }
}

// DNConstraint represents DN component rules from ZTPKI policy  
type DNConstraint struct {
        Component    string `json:"component"`
        Required     bool   `json:"required"`
        Pattern      string `json:"pattern"`
        DefaultValue string `json:"defaultValue"`
}

// SANConstraint represents SAN rules from ZTPKI policy
type SANConstraint struct {
        Type     string `json:"type"`
        Required bool   `json:"required"`
        Pattern  string `json:"pattern"`
        MaxCount int    `json:"maxCount"`
}


// Certificate represents a certificate from the ZTPKI API
type Certificate struct {
        ID               string    `json:"id"`
        CommonName       string    `json:"commonName"`
        SerialNumber     string    `json:"serial"`
        Status           string    `json:"revocationStatus"`
        Issuer           string    `json:"issuerDN"`
        Subject          string    `json:"subjectDN"`
        PolicyID         string    `json:"policyId"`
        CreatedDate      time.Time `json:"notBefore"`
        ExpiryDate       time.Time `json:"notAfter"`
        Certificate      string    `json:"pem"`         // PEM-encoded certificate
        Chain            []string  `json:"chain"`       // PEM-encoded certificate chain
        SANs             []string  `json:"SANs"`
        
        // Additional ZTPKI fields
        Policy struct {
                Name string `json:"name"`
        } `json:"policy"`
        
        // Extended ZTPKI response fields
        Imported   bool `json:"imported"`
        Discovered bool `json:"discovered"`
        SelfSigned bool `json:"selfSigned"`
}

// CSRSubmissionRequest represents a request to submit a CSR (ZTPKI API schema)
type CSRSubmissionRequest struct {
        Policy           string                    `json:"policy"`
        CSR              string                    `json:"csr"`
        Validity         *ValidityRequest          `json:"validity,omitempty"`
        DNComponents     map[string]interface{}    `json:"dnComponents,omitempty"`
        SubjectAltNames  map[string]interface{}    `json:"subjectAltNames,omitempty"`
        CustomFields     map[string]interface{}    `json:"customFields,omitempty"`
        CustomExtensions map[string]interface{}    `json:"customExtensions,omitempty"`
        Comment          string                    `json:"comment,omitempty"`
        ExpiryEmails     []string                  `json:"expiryEmails,omitempty"`
        CN               string                    `json:"CN,omitempty"`
}

// ValidityRequest represents the validity field in CSR submission
type ValidityRequest struct {
        Years    int    `json:"years,omitempty"`
        Months   int    `json:"months,omitempty"`
        Days     int    `json:"days,omitempty"`
        NotAfter string `json:"notAfter,omitempty"`
}

// ValidityPeriod represents a parsed validity period for API use
type ValidityPeriod struct {
        Days   int
        Months int
        Years  int
}

// CSRSubmissionResponse represents the response from CSR submission
type CSRSubmissionResponse struct {
        ID             string `json:"id"`
        IssuanceStatus string `json:"issuanceStatus"`
        RequestID      string `json:"requestId"`      // Legacy field
        Status         string `json:"status"`         // Legacy field
        Message        string `json:"message"`        // Legacy field
}

// CertificateRequest represents a certificate request status
type CertificateRequest struct {
        ID             string `json:"id"`
        Status         string `json:"status"`
        IssuanceStatus string `json:"issuanceStatus"`
        CertificateID  string `json:"certificateId"`
        CreatedDate    time.Time `json:"createdDate"`
        CompletedDate  time.Time `json:"completedDate"`
}

// RevocationRequest represents a certificate revocation request
type RevocationRequest struct {
        CertificateID string `json:"certificateId"`
        Reason        string `json:"reason"`
}

// CertificateSearchParams represents search parameters for certificates
type CertificateSearchParams struct {
        Account       string     `json:"account,omitempty"`
        CommonName    string     `json:"commonName,omitempty"`
        Serial        string     `json:"serial,omitempty"`
        Issuer        string     `json:"issuer,omitempty"`
        PolicyID      string     `json:"policyId,omitempty"`
        Status        string     `json:"status,omitempty"`
        Expired       *bool      `json:"expired,omitempty"`       // Pointer to distinguish null vs false
        Limit         int        `json:"limit,omitempty"`
        Offset        int        `json:"offset,omitempty"`
        NotAfter      string     `json:"not_after,omitempty"`
        NotBefore     string     `json:"not_before,omitempty"`
        ExpiresBefore *time.Time `json:"expiresBefore,omitempty"` // For client-side filtering
}

// APIError represents an error response from the ZTPKI API
type APIError struct {
        Code    int    `json:"code"`
        Message string `json:"message"`
        Details string `json:"details,omitempty"`
}

// Error implements the error interface for APIError
func (e *APIError) Error() string {
        if e.Details != "" {
                return fmt.Sprintf("API Error %d: %s (%s)", e.Code, e.Message, e.Details)
        }
        return fmt.Sprintf("API Error %d: %s", e.Code, e.Message)
}

// IsNotFound returns true if the error represents a "not found" condition
func (e *APIError) IsNotFound() bool {
        return e.Code == 404
}

// IsUnauthorized returns true if the error represents an authentication/authorization failure
func (e *APIError) IsUnauthorized() bool {
        return e.Code == 401 || e.Code == 403
}

// IsBadRequest returns true if the error represents a bad request
func (e *APIError) IsBadRequest() bool {
        return e.Code == 400
}

// CertificateStatus constants
const (
        StatusActive   = "active"
        StatusRevoked  = "revoked"
        StatusExpired  = "expired"
        StatusPending  = "pending"
        StatusFailed   = "failed"
)

// RevocationReason constants
const (
        ReasonUnspecified          = "unspecified"
        ReasonKeyCompromise        = "keyCompromise"
        ReasonCACompromise         = "caCompromise"
        ReasonAffiliationChanged   = "affiliationChanged"
        ReasonSuperseded           = "superseded"
        ReasonCessationOfOperation = "cessationOfOperation"
        ReasonCertificateHold      = "certificateHold"
        ReasonRemoveFromCRL        = "removeFromCRL"
        ReasonPrivilegeWithdrawn   = "privilegeWithdrawn"
        ReasonAACompromise         = "aaCompromise"
)

package api

import (
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

// Certificate represents a certificate from the ZTPKI API
type Certificate struct {
        ID                string    `json:"id"`
        Serial            string    `json:"serial"`
        CommonName        string    `json:"commonName"`
        SubjectDN         string    `json:"subjectDN"`
        IssuerDN          string    `json:"issuerDN"`
        NotBefore         time.Time `json:"notBefore"`
        NotAfter          time.Time `json:"notAfter"`
        SignatureAlgorithm string   `json:"signatureAlgorithm"`
        RevocationStatus  string    `json:"revocationStatus"`
        CreatedAt         time.Time `json:"createdAt"`
        CertRequestId     string    `json:"certRequestId"`
        Certificate       string    `json:"certificate"` // PEM-encoded certificate
        Chain             []string  `json:"chain"`       // PEM-encoded certificate chain
}

// CSRRequest represents a certificate request from ZTPKI
type CSRRequest struct {
        ID             string                 `json:"id"`
        Source         string                 `json:"source"`
        Fingerprint    string                 `json:"fingerprint"`
        CommonName     string                 `json:"commonName"`
        Details        map[string]interface{} `json:"details"`
        IssuanceStatus string                 `json:"issuanceStatus"`
        CreatedAt      time.Time              `json:"createdAt"`
        Policy         map[string]interface{} `json:"policy"`
        User           map[string]interface{} `json:"user"`
        CSR            string                 `json:"csr"`
}

// CSRStatus represents the status of a certificate request
type CSRStatus struct {
        ID                string `json:"id"`
        IssuanceStatus    string `json:"issuanceStatus"`
        CertificateId     string `json:"certificateId"`
        RevocationStatus  string `json:"revocationStatus"`
}

// CSRSubmissionRequest represents a request to submit a CSR
type CSRSubmissionRequest struct {
        CSR          string                 `json:"csr"`
        Policy       string                 `json:"policy"`
        DNComponents map[string]interface{} `json:"dnComponents"`
}

// CSRSubmissionResponse represents the response from CSR submission
type CSRSubmissionResponse struct {
        RequestID string `json:"requestId"`
        Status    string `json:"status"`
        Message   string `json:"message"`
}

// RevocationRequest represents a certificate revocation request
type RevocationRequest struct {
        CertificateID string `json:"certificateId"`
        Reason        string `json:"reason"`
}

// CertificateSearchParams represents search parameters for certificates
type CertificateSearchParams struct {
        CommonName    string     `json:"commonName,omitempty"`
        Serial        string     `json:"serial,omitempty"`
        Issuer        string     `json:"issuer,omitempty"`
        PolicyID      string     `json:"policyId,omitempty"`
        Status        string     `json:"status,omitempty"`
        Limit         int        `json:"limit,omitempty"`
        ExpiresBefore *time.Time `json:"expiresBefore,omitempty"`
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

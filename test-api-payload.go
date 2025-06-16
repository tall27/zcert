package main

import (
	"encoding/json"
	"fmt"
	"zcert/internal/api"
	"zcert/internal/config"
)

func main() {
	// Create a comprehensive certificate task to demonstrate the API payload
	certTask := &config.CertificateTask{
		Name:        "ComprehensiveTestCert",
		RenewBefore: "30d",
		Request: config.CertificateRequest{
			CSR: "local",
			Subject: config.CertificateSubject{
				CommonName:       "test.example.com",
				Country:          "US",
				State:            "Utah",
				Locality:         "Salt Lake City",
				Organization:     "Example Corp",
				OrgUnits:         []string{"IT Ops", "Security"},
				DomainComponents: []string{"example", "com"},
				Email:            "admin@example.com",
			},
			Policy: "5fe6d368-896a-4883-97eb-f87148c90896",
			SANs: &config.FlexibleSANs{
				SubjectAltNames: &config.SubjectAltNames{
					DNS:   []string{"www.example.com", "api.example.com"},
					IP:    []string{"192.168.1.100"},
					Email: []string{"webmaster@example.com"},
					UPN:   []string{"service@example.com"},
					URI:   []string{"https://api.example.com"},
				},
			},
			Validity: &config.ValidityConfig{
				Years:  1,
				Months: 0,
				Days:   0,
			},
			CustomFields: map[string]string{
				"department":  "IT",
				"costCenter":  "12345",
				"environment": "production",
			},
			CustomExtensions: map[string]string{
				"1.3.6.1.4.1.311.21.7": "302f06272b060104018237150884f09f0881fe9c1b85fd973886edbb1581edd1228149828fe83b86f9ea32020164020102",
			},
			Comment: "Comprehensive test certificate with all ZTPKI parameters",
			ExpiryEmails: []string{
				"admin@example.com",
				"security@example.com",
			},
		},
	}

	// Build the API payload structure (simulating what SubmitCSRWithFullPayload does)
	requestBody := api.CSRSubmissionRequest{
		Policy: certTask.Request.Policy,
		CSR:    "-----BEGIN CERTIFICATE REQUEST-----\n[CSR CONTENT WOULD BE HERE]\n-----END CERTIFICATE REQUEST-----",
		CN:     certTask.Request.Subject.CommonName,
	}

	// Build DN Components
	dnComponents := map[string]interface{}{
		"CN": certTask.Request.Subject.CommonName,
	}
	if certTask.Request.Subject.Country != "" {
		dnComponents["C"] = certTask.Request.Subject.Country
	}
	if certTask.Request.Subject.State != "" {
		dnComponents["ST"] = certTask.Request.Subject.State
	}
	if certTask.Request.Subject.Locality != "" {
		dnComponents["L"] = certTask.Request.Subject.Locality
	}
	if certTask.Request.Subject.Organization != "" {
		dnComponents["O"] = certTask.Request.Subject.Organization
	}
	if len(certTask.Request.Subject.OrgUnits) > 0 {
		dnComponents["OU"] = certTask.Request.Subject.OrgUnits
	}
	if len(certTask.Request.Subject.DomainComponents) > 0 {
		dnComponents["DC"] = certTask.Request.Subject.DomainComponents
	}
	if certTask.Request.Subject.Email != "" {
		dnComponents["emailAddress"] = certTask.Request.Subject.Email
	}
	requestBody.DNComponents = dnComponents

	// Build Subject Alternative Names
	if certTask.Request.SANs != nil && certTask.Request.SANs.SubjectAltNames != nil {
		sanMap := map[string]interface{}{}
		if len(certTask.Request.SANs.SubjectAltNames.DNS) > 0 {
			sanMap["dnsNames"] = certTask.Request.SANs.SubjectAltNames.DNS
		}
		if len(certTask.Request.SANs.SubjectAltNames.IP) > 0 {
			sanMap["ipAddresses"] = certTask.Request.SANs.SubjectAltNames.IP
		}
		if len(certTask.Request.SANs.SubjectAltNames.Email) > 0 {
			sanMap["rfc822Names"] = certTask.Request.SANs.SubjectAltNames.Email
		}
		if len(certTask.Request.SANs.SubjectAltNames.UPN) > 0 {
			sanMap["userPrincipalNames"] = certTask.Request.SANs.SubjectAltNames.UPN
		}
		if len(certTask.Request.SANs.SubjectAltNames.URI) > 0 {
			sanMap["uniformResourceIdentifiers"] = certTask.Request.SANs.SubjectAltNames.URI
		}
		requestBody.SubjectAltNames = sanMap
	}

	// Add validity period
	if certTask.Request.Validity != nil {
		requestBody.Validity = &api.ValidityRequest{
			Years:  certTask.Request.Validity.Years,
			Months: certTask.Request.Validity.Months,
			Days:   certTask.Request.Validity.Days,
		}
	}

	// Add custom fields
	if len(certTask.Request.CustomFields) > 0 {
		customFields := make(map[string]interface{})
		for k, v := range certTask.Request.CustomFields {
			customFields[k] = v
		}
		requestBody.CustomFields = customFields
	}

	// Add custom extensions
	if len(certTask.Request.CustomExtensions) > 0 {
		customExtensions := make(map[string]interface{})
		for k, v := range certTask.Request.CustomExtensions {
			customExtensions[k] = v
		}
		requestBody.CustomExtensions = customExtensions
	}

	// Add comment and expiry emails
	if certTask.Request.Comment != "" {
		requestBody.Comment = certTask.Request.Comment
	}
	if len(certTask.Request.ExpiryEmails) > 0 {
		requestBody.ExpiryEmails = certTask.Request.ExpiryEmails
	}

	// Print the complete ZTPKI API payload
	fmt.Println("=== COMPREHENSIVE ZTPKI API PAYLOAD ===")
	fmt.Println("POST /csr")
	fmt.Println("Content-Type: application/json")
	fmt.Println("")
	
	payload, _ := json.MarshalIndent(requestBody, "", "  ")
	fmt.Println(string(payload))
	fmt.Println("")
	fmt.Println("This payload includes ALL parameters from your YAML:")
	fmt.Println("✓ Complete DN components (CN, C, ST, L, O, OU, DC, emailAddress)")
	fmt.Println("✓ All SAN types (DNS, IP, email, UPN, URI)")
	fmt.Println("✓ Validity period configuration")
	fmt.Println("✓ Custom fields and extensions")
	fmt.Println("✓ Comments and expiry notifications")
	fmt.Println("=====================================")
}
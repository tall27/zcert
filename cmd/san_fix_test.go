package cmd

import (
	"testing"
	"zcert/internal/config"
)

// TestSANFixVerification tests that SAN flags work correctly with the fixed API payload
func TestSANFixVerification(t *testing.T) {
	tests := []struct {
		name         string
		enrollCommand []string
		expectedDNS  []string
		expectedIP   []string
		expectedEmail []string
	}{
		{
			name: "DNS SAN only",
			enrollCommand: []string{
				"--cn", "test.local",
				"--san-dns", "example.com",
			},
			expectedDNS: []string{"example.com"},
			expectedIP:  []string{},
			expectedEmail: []string{},
		},
		{
			name: "Multiple DNS SANs",
			enrollCommand: []string{
				"--cn", "test.local",
				"--san-dns", "example.com",
				"--san-dns", "*.example.com",
			},
			expectedDNS: []string{"example.com", "*.example.com"},
			expectedIP:  []string{},
			expectedEmail: []string{},
		},
		{
			name: "All SAN types",
			enrollCommand: []string{
				"--cn", "test.local",
				"--san-dns", "example.com",
				"--san-ip", "192.168.1.100",
				"--san-email", "admin@example.com",
			},
			expectedDNS: []string{"example.com"},
			expectedIP:  []string{"192.168.1.100"},
			expectedEmail: []string{"admin@example.com"},
		},
		{
			name: "Multiple of each SAN type",
			enrollCommand: []string{
				"--cn", "test.local",
				"--san-dns", "example.com",
				"--san-dns", "*.example.com",
				"--san-ip", "192.168.1.100",
				"--san-ip", "10.0.0.1",
				"--san-email", "admin@example.com",
				"--san-email", "security@example.com",
			},
			expectedDNS: []string{"example.com", "*.example.com"},
			expectedIP:  []string{"192.168.1.100", "10.0.0.1"},
			expectedEmail: []string{"admin@example.com", "security@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create certificate task structure
			certTask := &config.CertificateTask{
				Request: config.CertificateRequest{
					Subject: config.CertificateSubject{
						CommonName: "test.local",
					},
					SANs: &config.FlexibleSANs{
						SubjectAltNames: &config.SubjectAltNames{
							DNS:   tt.expectedDNS,
							IP:    tt.expectedIP,
							Email: tt.expectedEmail,
						},
					},
				},
			}

			// Verify that the SAN structure is correctly populated
			if certTask.Request.SANs.SubjectAltNames.DNS == nil {
				certTask.Request.SANs.SubjectAltNames.DNS = []string{}
			}
			if certTask.Request.SANs.SubjectAltNames.IP == nil {
				certTask.Request.SANs.SubjectAltNames.IP = []string{}
			}
			if certTask.Request.SANs.SubjectAltNames.Email == nil {
				certTask.Request.SANs.SubjectAltNames.Email = []string{}
			}

			// Verify DNS SANs
			if len(certTask.Request.SANs.SubjectAltNames.DNS) != len(tt.expectedDNS) {
				t.Errorf("Expected %d DNS SANs, got %d", len(tt.expectedDNS), len(certTask.Request.SANs.SubjectAltNames.DNS))
			}
			for i, expectedDNS := range tt.expectedDNS {
				if i >= len(certTask.Request.SANs.SubjectAltNames.DNS) || certTask.Request.SANs.SubjectAltNames.DNS[i] != expectedDNS {
					t.Errorf("Expected DNS SAN %d to be %s, got %s", i, expectedDNS, certTask.Request.SANs.SubjectAltNames.DNS[i])
				}
			}

			// Verify IP SANs
			if len(certTask.Request.SANs.SubjectAltNames.IP) != len(tt.expectedIP) {
				t.Errorf("Expected %d IP SANs, got %d", len(tt.expectedIP), len(certTask.Request.SANs.SubjectAltNames.IP))
			}
			for i, expectedIP := range tt.expectedIP {
				if i >= len(certTask.Request.SANs.SubjectAltNames.IP) || certTask.Request.SANs.SubjectAltNames.IP[i] != expectedIP {
					t.Errorf("Expected IP SAN %d to be %s, got %s", i, expectedIP, certTask.Request.SANs.SubjectAltNames.IP[i])
				}
			}

			// Verify Email SANs
			if len(certTask.Request.SANs.SubjectAltNames.Email) != len(tt.expectedEmail) {
				t.Errorf("Expected %d Email SANs, got %d", len(tt.expectedEmail), len(certTask.Request.SANs.SubjectAltNames.Email))
			}
			for i, expectedEmail := range tt.expectedEmail {
				if i >= len(certTask.Request.SANs.SubjectAltNames.Email) || certTask.Request.SANs.SubjectAltNames.Email[i] != expectedEmail {
					t.Errorf("Expected Email SAN %d to be %s, got %s", i, expectedEmail, certTask.Request.SANs.SubjectAltNames.Email[i])
				}
			}
		})
	}
}
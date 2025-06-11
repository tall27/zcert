package policy

import (
	"reflect"
	"testing"
)

func TestParseValidity(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *ValidityPeriod
		wantErr bool
	}{
		{
			name:  "30 days",
			input: "30d",
			want:  &ValidityPeriod{Days: 30},
		},
		{
			name:  "6 months",
			input: "6m",
			want:  &ValidityPeriod{Months: 6},
		},
		{
			name:  "1 year",
			input: "1y",
			want:  &ValidityPeriod{Years: 1},
		},
		{
			name:  "30 days 6 months",
			input: "30d6m",
			want:  &ValidityPeriod{Days: 30, Months: 6},
		},
		{
			name:  "1 year 6 months",
			input: "1y6m",
			want:  &ValidityPeriod{Years: 1, Months: 6},
		},
		{
			name:  "1 year 6 months 15 days",
			input: "1y6m15d",
			want:  &ValidityPeriod{Years: 1, Months: 6, Days: 15},
		},
		{
			name:  "empty string",
			input: "",
			want:  &ValidityPeriod{},
		},
		{
			name:    "invalid format",
			input:   "invalid",
			wantErr: true,
		},
		{
			name:    "invalid number",
			input:   "abcd",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseValidity(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseValidity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseValidity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidityPeriod_ToTotalDays(t *testing.T) {
	tests := []struct {
		name string
		vp   ValidityPeriod
		want int
	}{
		{
			name: "30 days",
			vp:   ValidityPeriod{Days: 30},
			want: 30,
		},
		{
			name: "6 months",
			vp:   ValidityPeriod{Months: 6},
			want: 180, // 6 * 30
		},
		{
			name: "1 year",
			vp:   ValidityPeriod{Years: 1},
			want: 365,
		},
		{
			name: "1 year 6 months 15 days",
			vp:   ValidityPeriod{Years: 1, Months: 6, Days: 15},
			want: 560, // 365 + 180 + 15
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.vp.ToTotalDays(); got != tt.want {
				t.Errorf("ValidityPeriod.ToTotalDays() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidityPeriod_String(t *testing.T) {
	tests := []struct {
		name string
		vp   ValidityPeriod
		want string
	}{
		{
			name: "30 days",
			vp:   ValidityPeriod{Days: 30},
			want: "30d",
		},
		{
			name: "6 months",
			vp:   ValidityPeriod{Months: 6},
			want: "6m",
		},
		{
			name: "1 year",
			vp:   ValidityPeriod{Years: 1},
			want: "1y",
		},
		{
			name: "1 year 6 months",
			vp:   ValidityPeriod{Years: 1, Months: 6},
			want: "1y6m",
		},
		{
			name: "1 year 6 months 15 days",
			vp:   ValidityPeriod{Years: 1, Months: 6, Days: 15},
			want: "1y6m15d",
		},
		{
			name: "zero validity",
			vp:   ValidityPeriod{},
			want: "0d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.vp.String(); got != tt.want {
				t.Errorf("ValidityPeriod.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicy_ValidateValidity(t *testing.T) {
	policy := &Policy{
		Details: PolicyDetails{
			Validity: ValidityConfig{
				Days:     []string{"1-30", "90"},
				Months:   []string{"1-12"},
				Years:    []string{"1"},
				MaxValue: struct{ Days int `yaml:"days"` }{Days: 398},
				Required: true,
			},
		},
	}

	tests := []struct {
		name         string
		userValidity *ValidityPeriod
		wantIssues   int
		wantContains string
	}{
		{
			name:         "nil validity when required",
			userValidity: nil,
			wantIssues:   1,
			wantContains: "validity period is required",
		},
		{
			name:         "valid 30 days",
			userValidity: &ValidityPeriod{Days: 30},
			wantIssues:   0,
		},
		{
			name:         "valid 90 days",
			userValidity: &ValidityPeriod{Days: 90},
			wantIssues:   0,
		},
		{
			name:         "invalid 60 days",
			userValidity: &ValidityPeriod{Days: 60},
			wantIssues:   1,
			wantContains: "days 60 not in allowed ranges",
		},
		{
			name:         "valid 1 year",
			userValidity: &ValidityPeriod{Years: 1},
			wantIssues:   0,
		},
		{
			name:         "invalid 2 years",
			userValidity: &ValidityPeriod{Years: 2},
			wantIssues:   2, // Both max days (730 > 398) and years range violation
			wantContains: "years 2 not in allowed ranges",
		},
		{
			name:         "exceeds max days",
			userValidity: &ValidityPeriod{Years: 2}, // 730 days > 398
			wantIssues:   2,                          // Both max days and years range
			wantContains: "max validity 398 days",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := policy.ValidateValidity(tt.userValidity)
			if len(issues) != tt.wantIssues {
				t.Errorf("ValidateValidity() issues count = %v, want %v. Issues: %v", len(issues), tt.wantIssues, issues)
			}
			if tt.wantContains != "" {
				found := false
				for _, issue := range issues {
					if contains(issue, tt.wantContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("ValidateValidity() issues should contain '%s', got: %v", tt.wantContains, issues)
				}
			}
		})
	}
}

func TestPolicy_ValidateDNComponents(t *testing.T) {
	policy := &Policy{
		Details: PolicyDetails{
			DNComponents: []DNComponent{
				{
					Tag:      "CN",
					Required: true,
					RegEx:    "^(?!\\*\\.).*", // No leading wildcards
				},
				{
					Tag:          "OU",
					Required:     true,
					Modifiable:   true,
				},
				{
					Tag:          "OU",
					Required:     false,
					Modifiable:   false,
					DefaultValue: "Manufacturing",
				},
				{
					Tag:          "O",
					Required:     true,
					DefaultValue: "ZTPKI Corp",
					Modifiable:   false,
				},
			},
		},
	}

	tests := []struct {
		name         string
		userArgs     *UserArgs
		wantIssues   int
		wantContains string
	}{
		{
			name: "valid arguments",
			userArgs: &UserArgs{
				CN:           "api.example.com",
				Organization: []string{"ZTPKI Corp"},
				OrgUnit:      []string{"IT Department"},
			},
			wantIssues: 0,
		},
		{
			name: "missing required CN",
			userArgs: &UserArgs{
				Organization: []string{"ZTPKI Corp"},
				OrgUnit:      []string{"IT Department"},
			},
			wantIssues:   1,
			wantContains: "CN is required",
		},
		{
			name: "invalid CN regex",
			userArgs: &UserArgs{
				CN:           "*.example.com", // Starts with *.
				Organization: []string{"ZTPKI Corp"},
				OrgUnit:      []string{"IT Department"},
			},
			wantIssues:   1,
			wantContains: "doesn't match policy pattern",
		},
		{
			name: "wrong organization",
			userArgs: &UserArgs{
				CN:           "api.example.com",
				Organization: []string{"Wrong Corp"},
				OrgUnit:      []string{"IT Department"},
			},
			wantIssues:   1,
			wantContains: "must be 'ZTPKI Corp'",
		},
		{
			name: "too many OUs",
			userArgs: &UserArgs{
				CN:           "api.example.com",
				Organization: []string{"ZTPKI Corp"},
				OrgUnit:      []string{"IT", "Security", "Extra"},
			},
			wantIssues:   1,
			wantContains: "policy allows max 2 OU values",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := policy.ValidateDNComponents(tt.userArgs)
			if len(issues) != tt.wantIssues {
				t.Errorf("ValidateDNComponents() issues count = %v, want %v. Issues: %v", len(issues), tt.wantIssues, issues)
			}
			if tt.wantContains != "" {
				found := false
				for _, issue := range issues {
					if contains(issue, tt.wantContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("ValidateDNComponents() issues should contain '%s', got: %v", tt.wantContains, issues)
				}
			}
		})
	}
}

func TestPolicy_ValidateSANs(t *testing.T) {
	policy := &Policy{
		Details: PolicyDetails{
			SubjectAltNames: []SANComponent{
				{
					Tag:   "DNSNAME",
					RegEx: "^(?!\\*\\.).*", // No leading wildcards
				},
				{
					Tag: "DNSNAME",
				},
				{
					Tag: "IPADDRESS",
				},
				{
					Tag: "RFC822NAME",
				},
			},
		},
	}

	tests := []struct {
		name         string
		userArgs     *UserArgs
		wantIssues   int
		wantContains string
	}{
		{
			name: "valid SANs",
			userArgs: &UserArgs{
				SANsDNS:   []string{"example.com", "api.example.com"},
				SANsIP:    []string{"192.168.1.1"},
				SANsEmail: []string{"admin@example.com"},
			},
			wantIssues: 0,
		},
		{
			name: "too many DNS SANs",
			userArgs: &UserArgs{
				SANsDNS: []string{"example.com", "api.example.com", "www.example.com"},
			},
			wantIssues:   1,
			wantContains: "policy allows max 2 DNS SANs",
		},
		{
			name: "invalid DNS SAN regex",
			userArgs: &UserArgs{
				SANsDNS: []string{"*.example.com"}, // Starts with *.
			},
			wantIssues:   1,
			wantContains: "doesn't match policy pattern",
		},
		{
			name: "too many IP SANs",
			userArgs: &UserArgs{
				SANsIP: []string{"192.168.1.1", "10.0.0.1"},
			},
			wantIssues:   1,
			wantContains: "policy allows max 1 IP SANs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := policy.ValidateSANs(tt.userArgs)
			if len(issues) != tt.wantIssues {
				t.Errorf("ValidateSANs() issues count = %v, want %v. Issues: %v", len(issues), tt.wantIssues, issues)
			}
			if tt.wantContains != "" {
				found := false
				for _, issue := range issues {
					if contains(issue, tt.wantContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("ValidateSANs() issues should contain '%s', got: %v", tt.wantContains, issues)
				}
			}
		})
	}
}

func TestPolicy_CheckCompleteCompatibility(t *testing.T) {
	policy := &Policy{
		Details: PolicyDetails{
			Validity: ValidityConfig{
				Days:     []string{"1-90"},
				MaxValue: struct{ Days int `yaml:"days"` }{Days: 90},
				Required: true,
			},
			DNComponents: []DNComponent{
				{Tag: "CN", Required: true},
			},
			CustomFields: []CustomField{
				{Tag: "TRACKING", Required: true, Label: "Tracking Number"},
			},
		},
		Enabled: PolicyEnabled{
			REST: true,
		},
	}

	tests := []struct {
		name           string
		userArgs       *UserArgs
		wantCompatible bool
		wantReasons    int
	}{
		{
			name: "fully compatible",
			userArgs: &UserArgs{
				CN:       "api.example.com",
				Validity: &ValidityPeriod{Days: 30},
			},
			wantCompatible: false, // Has required custom fields
			wantReasons:    1,     // Custom field issue
		},
		{
			name: "multiple incompatibilities",
			userArgs: &UserArgs{
				CN:       "", // Missing required CN
				Validity: &ValidityPeriod{Days: 120}, // Exceeds max
			},
			wantCompatible: false,
			wantReasons:    4, // Missing CN, exceeds max days, days not in range, custom field
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compat := policy.CheckCompleteCompatibility(tt.userArgs)
			if compat.IsCompatible != tt.wantCompatible {
				t.Errorf("CheckCompleteCompatibility() IsCompatible = %v, want %v", compat.IsCompatible, tt.wantCompatible)
			}
			if len(compat.Reasons) != tt.wantReasons {
				t.Errorf("CheckCompleteCompatibility() reasons count = %v, want %v. Reasons: %v", len(compat.Reasons), tt.wantReasons, compat.Reasons)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(substr) <= len(s) && (substr == "" || s[len(s)-len(substr):] == substr || 
		   s[:len(substr)] == substr || (len(s) > len(substr) && 
		   func() bool {
			   for i := 1; i <= len(s)-len(substr); i++ {
				   if s[i:i+len(substr)] == substr {
					   return true
				   }
			   }
			   return false
		   }()))
}
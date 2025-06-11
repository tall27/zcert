package policy

import (
        "fmt"
        "regexp"
        "strconv"
        "strings"
)

// ValidityPeriod represents a parsed validity period
type ValidityPeriod struct {
        Days   int
        Months int
        Years  int
}

// DNComponent represents a Distinguished Name component in a policy
type DNComponent struct {
        Tag          string `yaml:"tag"`
        Label        string `yaml:"label"`
        Required     bool   `yaml:"required"`
        Modifiable   bool   `yaml:"modifiable"`
        DefaultValue string `yaml:"defaultValue"`
        RegEx        string `yaml:"regEx"`
        CopyAsFirstSAN bool `yaml:"copyAsFirstSAN"`
}

// SANComponent represents a Subject Alternative Name component in a policy
type SANComponent struct {
        Tag        string `yaml:"tag"`
        Label      string `yaml:"label"`
        Required   bool   `yaml:"required"`
        Modifiable bool   `yaml:"modifiable"`
        RegEx      string `yaml:"regEx"`
}

// CustomField represents a custom field requirement in a policy
type CustomField struct {
        Tag          string `yaml:"tag"`
        Label        string `yaml:"label"`
        Required     bool   `yaml:"required"`
        Modifiable   bool   `yaml:"modifiable"`
        DefaultValue string `yaml:"defaultValue"`
}

// CustomExtension represents a custom extension in a policy
type CustomExtension struct {
        OID          string `yaml:"oid"`
        Label        string `yaml:"label"`
        Required     bool   `yaml:"required"`
        Modifiable   bool   `yaml:"modifiable"`
        DefaultValue string `yaml:"defaultValue"`
}

// ValidityConfig represents the validity configuration in a policy
type ValidityConfig struct {
        Days         []string `yaml:"days"`
        Months       []string `yaml:"months"`
        Years        []string `yaml:"years"`
        MaxValue     struct {
                Days int `yaml:"days"`
        } `yaml:"maxValue"`
        DefaultValue struct {
                Days  int `yaml:"days"`
                Years int `yaml:"years"`
        } `yaml:"defaultValue"`
        Required   bool `yaml:"required"`
        Modifiable bool `yaml:"modifiable"`
}

// PolicyDetails represents the details section of a policy
type PolicyDetails struct {
        Validity         ValidityConfig    `yaml:"validity"`
        DNComponents     []DNComponent     `yaml:"dnComponents"`
        SubjectAltNames  []SANComponent    `yaml:"subjectAltNames"`
        CustomFields     []CustomField     `yaml:"customFields"`
        CustomExtensions []CustomExtension `yaml:"customExtensions"`
        ApprovalRequired bool              `yaml:"approvalRequired"`
}

// PolicyEnabled represents the enabled protocols for a policy
type PolicyEnabled struct {
        UI   bool `yaml:"ui"`
        REST bool `yaml:"rest"`
        ACME bool `yaml:"acme"`
        SCEP bool `yaml:"scep"`
}

// Policy represents a complete ZTPKI policy
type Policy struct {
        ID      string        `yaml:"id"`
        Name    string        `yaml:"name"`
        Details PolicyDetails `yaml:"details"`
        Enabled PolicyEnabled `yaml:"enabled"`
}

// UserArgs represents the user's certificate request arguments
type UserArgs struct {
        CN           string
        SANsDNS      []string
        SANsIP       []string
        SANsEmail    []string
        Validity     *ValidityPeriod
        Organization []string
        OrgUnit      []string
        Locality     string
        Province     string
        Country      string
        KeyType      string
        KeySize      int
        KeyCurve     string
}

// PolicyCompatibility represents the compatibility result
type PolicyCompatibility struct {
        IsCompatible bool
        Reasons      []string
}

// ParseValidity parses a validity string like "30d", "6m", "1y", "30d6m"
func ParseValidity(input string) (*ValidityPeriod, error) {
        if input == "" {
                return &ValidityPeriod{}, nil
        }

        re := regexp.MustCompile(`(\d+)([dmy])`)
        matches := re.FindAllStringSubmatch(input, -1)

        if len(matches) == 0 {
                return nil, fmt.Errorf("invalid validity format: %s (expected formats: 30d, 6m, 1y, 30d6m, 1y6m)", input)
        }

        vp := &ValidityPeriod{}
        for _, match := range matches {
                value, err := strconv.Atoi(match[1])
                if err != nil {
                        return nil, fmt.Errorf("invalid number in validity: %s", match[1])
                }
                unit := match[2]

                switch unit {
                case "d":
                        vp.Days = value
                case "m":
                        vp.Months = value
                case "y":
                        vp.Years = value
                }
        }
        return vp, nil
}

// ToTotalDays converts the validity period to total days (approximate)
func (vp *ValidityPeriod) ToTotalDays() int {
        return vp.Days + (vp.Months * 30) + (vp.Years * 365)
}

// String returns a string representation of the validity period
func (vp *ValidityPeriod) String() string {
        var parts []string
        if vp.Years > 0 {
                parts = append(parts, fmt.Sprintf("%dy", vp.Years))
        }
        if vp.Months > 0 {
                parts = append(parts, fmt.Sprintf("%dm", vp.Months))
        }
        if vp.Days > 0 {
                parts = append(parts, fmt.Sprintf("%dd", vp.Days))
        }
        if len(parts) == 0 {
                return "0d"
        }
        return strings.Join(parts, "")
}

// CheckCompleteCompatibility validates all certificate attributes against the policy
func (p *Policy) CheckCompleteCompatibility(userArgs *UserArgs) PolicyCompatibility {
        var allIssues []string

        // Validate all aspects (excluding protocol support - all ZTPKI policies support REST API)
        allIssues = append(allIssues, p.ValidateValidity(userArgs.Validity)...)
        allIssues = append(allIssues, p.ValidateDNComponents(userArgs)...)
        allIssues = append(allIssues, p.ValidateSANs(userArgs)...)
        allIssues = append(allIssues, p.ValidateKeyAttributes(userArgs.KeyType, userArgs.KeySize, userArgs.KeyCurve)...)
        allIssues = append(allIssues, p.ValidateCustomFields()...)

        return PolicyCompatibility{
                IsCompatible: len(allIssues) == 0,
                Reasons:      allIssues,
        }
}

// ValidateValidity checks validity period against policy constraints
func (p *Policy) ValidateValidity(userValidity *ValidityPeriod) []string {
        var issues []string

        if userValidity == nil {
                // When no validity is specified, we'll use the policy's maximum validity
                // This allows the API to automatically use the template maximum
                // No compatibility issues when validity is not specified
                return issues
        }

        // Check against maximum days
        totalDays := userValidity.ToTotalDays()
        if p.Details.Validity.MaxValue.Days > 0 && totalDays > p.Details.Validity.MaxValue.Days {
                issues = append(issues, fmt.Sprintf("max validity %d days, you specified %d days", p.Details.Validity.MaxValue.Days, totalDays))
        }

        // Check individual components against allowed ranges
        if userValidity.Days > 0 {
                if !p.isValidInRanges(userValidity.Days, p.Details.Validity.Days) {
                        issues = append(issues, fmt.Sprintf("days %d not in allowed ranges %v", userValidity.Days, p.Details.Validity.Days))
                }
        }

        if userValidity.Months > 0 {
                if !p.isValidInRanges(userValidity.Months, p.Details.Validity.Months) {
                        issues = append(issues, fmt.Sprintf("months %d not in allowed ranges %v", userValidity.Months, p.Details.Validity.Months))
                }
        }

        if userValidity.Years > 0 {
                if !p.isValidInRanges(userValidity.Years, p.Details.Validity.Years) {
                        issues = append(issues, fmt.Sprintf("years %d not in allowed ranges %v", userValidity.Years, p.Details.Validity.Years))
                }
        }

        return issues
}

// ValidateDNComponents checks DN components against policy requirements
func (p *Policy) ValidateDNComponents(userArgs *UserArgs) []string {
        var issues []string

        for _, dnComp := range p.Details.DNComponents {
                switch dnComp.Tag {
                case "CN":
                        issues = append(issues, p.validateDNField("CN", userArgs.CN, dnComp)...)
                case "O":
                        for i, org := range userArgs.Organization {
                                issues = append(issues, p.validateDNField(fmt.Sprintf("O[%d]", i), org, dnComp)...)
                        }
                case "OU":
                        ouSlots := p.getOUSlots()
                        if len(userArgs.OrgUnit) > len(ouSlots) {
                                issues = append(issues, fmt.Sprintf("policy allows max %d OU values, you provided %d", len(ouSlots), len(userArgs.OrgUnit)))
                        } else {
                                for i, ou := range userArgs.OrgUnit {
                                        if i < len(ouSlots) {
                                                issues = append(issues, p.validateDNField(fmt.Sprintf("OU[%d]", i), ou, ouSlots[i])...)
                                        }
                                }
                                // Check for required OUs not provided
                                for i := len(userArgs.OrgUnit); i < len(ouSlots); i++ {
                                        if ouSlots[i].Required && ouSlots[i].DefaultValue == "" {
                                                issues = append(issues, fmt.Sprintf("OU slot %d is required but not provided", i+1))
                                        }
                                }
                        }
                case "L":
                        issues = append(issues, p.validateDNField("L", userArgs.Locality, dnComp)...)
                case "ST":
                        issues = append(issues, p.validateDNField("ST", userArgs.Province, dnComp)...)
                case "C":
                        issues = append(issues, p.validateDNField("C", userArgs.Country, dnComp)...)
                }
        }

        return issues
}

// ValidateSANs checks Subject Alternative Names against policy constraints
func (p *Policy) ValidateSANs(userArgs *UserArgs) []string {
        var issues []string

        // Check DNS SANs
        dnsSlots := p.countSANSlots("DNSNAME")
        if len(userArgs.SANsDNS) > dnsSlots {
                issues = append(issues, fmt.Sprintf("policy allows max %d DNS SANs, you specified %d", dnsSlots, len(userArgs.SANsDNS)))
        }

        // Validate each DNS SAN against regex
        for _, sanComp := range p.Details.SubjectAltNames {
                if sanComp.Tag == "DNSNAME" && sanComp.RegEx != "" {
                        for _, dnsName := range userArgs.SANsDNS {
                                if !p.matchesRegex(dnsName, sanComp.RegEx) {
                                        issues = append(issues, fmt.Sprintf("DNS SAN '%s' doesn't match policy pattern '%s'", dnsName, sanComp.RegEx))
                                }
                        }
                }
        }

        // Check IP SANs
        ipSlots := p.countSANSlots("IPADDRESS")
        if len(userArgs.SANsIP) > 0 && ipSlots == 0 {
                issues = append(issues, "IP SANs not supported by this policy")
        } else if len(userArgs.SANsIP) > ipSlots {
                issues = append(issues, fmt.Sprintf("policy allows max %d IP SANs, you specified %d", ipSlots, len(userArgs.SANsIP)))
        }

        // Check email SANs
        if len(userArgs.SANsEmail) > 0 && !p.supportsSANType("RFC822NAME") {
                issues = append(issues, "email SANs not supported by this policy")
        }

        return issues
}

// ValidateKeyAttributes checks key type and size requirements
func (p *Policy) ValidateKeyAttributes(keyType string, keySize int, keyCurve string) []string {
        var issues []string

        // Basic validation - policies may have specific requirements encoded differently
        if keyType == "ecdsa" && !p.supportsECDSA() {
                issues = append(issues, "ECDSA keys not supported by this policy")
        }

        if keyType == "rsa" {
                minSize := p.getMinRSAKeySize()
                if minSize > 0 && keySize < minSize {
                        issues = append(issues, fmt.Sprintf("minimum RSA key size is %d, you specified %d", minSize, keySize))
                }
        }

        return issues
}

// ValidateCustomFields checks for required custom fields
func (p *Policy) ValidateCustomFields() []string {
        var issues []string

        for _, customField := range p.Details.CustomFields {
                if customField.Required {
                        issues = append(issues, fmt.Sprintf("policy requires custom field '%s' not available via CLI", customField.Label))
                }
        }

        return issues
}


// Helper methods

func (p *Policy) isValidInRanges(value int, ranges []string) bool {
        if len(ranges) == 0 {
                return true // No restrictions
        }

        for _, rangeStr := range ranges {
                if p.isInRange(value, rangeStr) {
                        return true
                }
        }
        return false
}

func (p *Policy) isInRange(value int, rangeStr string) bool {
        if strings.Contains(rangeStr, "-") {
                parts := strings.Split(rangeStr, "-")
                if len(parts) == 2 {
                        min, err1 := strconv.Atoi(parts[0])
                        max, err2 := strconv.Atoi(parts[1])
                        if err1 == nil && err2 == nil {
                                return value >= min && value <= max
                        }
                }
        } else {
                allowed, err := strconv.Atoi(rangeStr)
                if err == nil {
                        return value == allowed
                }
        }
        return false
}

func (p *Policy) validateDNField(fieldName, value string, component DNComponent) []string {
        var issues []string

        // Check if required
        if component.Required && value == "" {
                issues = append(issues, fmt.Sprintf("%s is required by policy", fieldName))
        }

        // Validate against regex if present
        if component.RegEx != "" && value != "" {
                if !p.matchesRegex(value, component.RegEx) {
                        issues = append(issues, fmt.Sprintf("%s '%s' doesn't match policy pattern '%s'", fieldName, value, component.RegEx))
                }
        }

        // Check default value requirements
        if component.DefaultValue != "" && !component.Modifiable && value != component.DefaultValue {
                issues = append(issues, fmt.Sprintf("%s must be '%s' (not modifiable), you provided '%s'", fieldName, component.DefaultValue, value))
        }

        return issues
}

func (p *Policy) matchesRegex(value, pattern string) bool {
        matched, err := regexp.MatchString(pattern, value)
        return err == nil && matched
}

func (p *Policy) getOUSlots() []DNComponent {
        var ouSlots []DNComponent
        for _, dnComp := range p.Details.DNComponents {
                if dnComp.Tag == "OU" {
                        ouSlots = append(ouSlots, dnComp)
                }
        }
        return ouSlots
}

func (p *Policy) countSANSlots(sanType string) int {
        count := 0
        for _, sanComp := range p.Details.SubjectAltNames {
                if sanComp.Tag == sanType {
                        count++
                }
        }
        return count
}

func (p *Policy) supportsSANType(sanType string) bool {
        for _, sanComp := range p.Details.SubjectAltNames {
                if sanComp.Tag == sanType {
                        return true
                }
        }
        return false
}

func (p *Policy) supportsECDSA() bool {
        // This would need to be determined from policy configuration
        // For now, assume ECDSA is supported unless explicitly restricted
        return true
}

func (p *Policy) getMinRSAKeySize() int {
        // This would need to be determined from policy configuration
        // For now, return a reasonable default
        return 2048
}
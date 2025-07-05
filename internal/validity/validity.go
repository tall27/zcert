package validity

import (
	"fmt"
	"regexp"
	"strconv"
)

// ValidityPeriod represents a parsed validity period
// (can be used by both config and API)
type ValidityPeriod struct {
	Years  int
	Months int
	Days   int
}

// ParseValidityPeriod parses a validity period string into a ValidityPeriod struct
func ParseValidityPeriod(validityStr string) (*ValidityPeriod, error) {
	if validityStr == "" {
		return nil, fmt.Errorf("validity period cannot be empty")
	}

	validity := &ValidityPeriod{}

	// Check if it's a plain number (from config file) - assume days
	if matched, _ := regexp.MatchString(`^\d+$`, validityStr); matched {
		days, err := strconv.Atoi(validityStr)
		if err != nil {
			return nil, fmt.Errorf("invalid numeric validity value: %v", err)
		}
		validity.Days = days
		return validity, nil
	}

	// Regular expressions for parsing different components
	dayRe := regexp.MustCompile(`(\d+)d`)
	monthRe := regexp.MustCompile(`(\d+)m`)
	yearRe := regexp.MustCompile(`(\d+)y`)

	// Parse days
	if matches := dayRe.FindStringSubmatch(validityStr); len(matches) > 1 {
		days, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("invalid day value: %v", err)
		}
		validity.Days = days
	}

	// Parse months
	if matches := monthRe.FindStringSubmatch(validityStr); len(matches) > 1 {
		months, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("invalid month value: %v", err)
		}
		validity.Months = months
	}

	// Parse years
	if matches := yearRe.FindStringSubmatch(validityStr); len(matches) > 1 {
		years, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("invalid year value: %v", err)
		}
		validity.Years = years
	}

	// Validate that at least one component was parsed
	if validity.Days == 0 && validity.Months == 0 && validity.Years == 0 {
		return nil, fmt.Errorf("invalid validity format: %s (expected formats: 30d, 6m, 1y, 30d6m, 1y6m, or plain number for days)", validityStr)
	}

	return validity, nil
}

// ToTotalDays converts the validity period to total days (approximate)
func (vp *ValidityPeriod) ToTotalDays() int {
	return vp.Days + (vp.Months * 30) + (vp.Years * 365)
}

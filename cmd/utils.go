package cmd

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"zcert/internal/api"
)

// parseValidityPeriod parses a validity period string like "30d", "6m", "1y"
func parseValidityPeriod(validity string) (*api.ValidityPeriod, error) {
	re := regexp.MustCompile(`^(\d+)([dmy])$`)
	matches := re.FindStringSubmatch(strings.ToLower(validity))
	if len(matches) != 3 {
		return nil, fmt.Errorf("invalid validity format: %s (expected format: 30d, 6m, 1y)", validity)
	}

	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return nil, fmt.Errorf("invalid number in validity: %s", matches[1])
	}

	vp := &api.ValidityPeriod{}
	switch matches[2] {
	case "d":
		vp.Days = value
	case "m":
		vp.Months = value
	case "y":
		vp.Years = value
	default:
		return nil, fmt.Errorf("invalid validity unit: %s (use d, m, or y)", matches[2])
	}

	return vp, nil
}

// promptConfirm prompts the user for confirmation
func promptConfirm(message string, defaultValue bool) (bool, error) {
	reader := bufio.NewReader(os.Stdin)
	
	prompt := message
	if defaultValue {
		prompt += " [Y/n]: "
	} else {
		prompt += " [y/N]: "
	}
	
	fmt.Print(prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	
	response = strings.TrimSpace(strings.ToLower(response))
	
	if response == "" {
		return defaultValue, nil
	}
	
	switch response {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid response: %s (please enter y/yes or n/no)", response)
	}
}
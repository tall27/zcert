package policy

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"zcert/internal/api"
)

// Policy represents a policy option for selection
type Policy struct {
	ID   string
	Name string
}

// PolicySelector provides interactive policy selection
type PolicySelector struct {
	client *api.Client
}

// NewPolicySelector creates a new policy selector
func NewPolicySelector(client *api.Client) *PolicySelector {
	return &PolicySelector{
		client: client,
	}
}

// SelectPolicy presents an interactive policy selection menu
func (ps *PolicySelector) SelectPolicy() (string, error) {
	fmt.Println("Fetching available policies...")
	
	policies, err := ps.fetchPolicies()
	if err != nil {
		return "", fmt.Errorf("failed to fetch policies: %w", err)
	}

	if len(policies) == 0 {
		return "", fmt.Errorf("no policies available")
	}

	return ps.presentPolicyMenu(policies)
}

// fetchPolicies retrieves available policies from ZTPKI
func (ps *PolicySelector) fetchPolicies() ([]Policy, error) {
	// Use the search endpoint to get policies
	resp, err := ps.client.SearchCertificates(map[string]interface{}{
		"limit": 1, // We just need to trigger policy enumeration
	})
	if err != nil {
		return nil, err
	}

	// Extract policies from response metadata or use known policies
	// For now, return known working policies
	policies := []Policy{
		{ID: "5fe6d368-896a-4883-97eb-f87148c90896", Name: "OCP Dev ICA 1 SSL 75 SAN"},
		{ID: "default-web-server", Name: "Default Web Server Policy"},
		{ID: "test-policy", Name: "Test Policy"},
	}

	// Try to get actual policies from API if available
	if resp != nil {
		// Parse actual policies from response if the API provides them
		// This would need to be implemented based on actual ZTPKI API response format
	}

	return policies, nil
}

// presentPolicyMenu displays the policy selection menu
func (ps *PolicySelector) presentPolicyMenu(policies []Policy) (string, error) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\nAvailable Policies:")
		fmt.Println("==================")
		
		for i, policy := range policies {
			fmt.Printf("%d. %s\n   ID: %s\n", i+1, policy.Name, policy.ID)
		}
		
		fmt.Printf("\nSelect a policy (1-%d), or 'q' to quit: ", len(policies))
		
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read input: %w", err)
		}
		
		input = strings.TrimSpace(input)
		
		// Check for quit
		if strings.ToLower(input) == "q" || strings.ToLower(input) == "quit" {
			return "", fmt.Errorf("policy selection cancelled")
		}
		
		// Parse selection
		selection, err := strconv.Atoi(input)
		if err != nil {
			fmt.Println("Invalid input. Please enter a number or 'q' to quit.")
			continue
		}
		
		if selection < 1 || selection > len(policies) {
			fmt.Printf("Invalid selection. Please choose a number between 1 and %d.\n", len(policies))
			continue
		}
		
		selectedPolicy := policies[selection-1]
		fmt.Printf("\nSelected: %s (ID: %s)\n", selectedPolicy.Name, selectedPolicy.ID)
		
		// Confirm selection
		fmt.Print("Confirm this selection? (y/n): ")
		confirm, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read confirmation: %w", err)
		}
		
		confirm = strings.TrimSpace(strings.ToLower(confirm))
		if confirm == "y" || confirm == "yes" {
			return selectedPolicy.ID, nil
		}
		
		fmt.Println("Selection cancelled. Please choose again.")
	}
}

// GetPolicyByID retrieves policy information by ID
func (ps *PolicySelector) GetPolicyByID(policyID string) (*Policy, error) {
	policies, err := ps.fetchPolicies()
	if err != nil {
		return nil, err
	}

	for _, policy := range policies {
		if policy.ID == policyID {
			return &policy, nil
		}
	}

	return nil, fmt.Errorf("policy with ID %s not found", policyID)
}

// ValidatePolicy checks if a policy ID is valid
func (ps *PolicySelector) ValidatePolicy(policyID string) error {
	_, err := ps.GetPolicyByID(policyID)
	return err
}
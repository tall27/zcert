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
        apiPolicies, err := ps.client.GetPolicies()
        if err != nil {
                return "", fmt.Errorf("failed to retrieve policies from ZTPKI API: %w", err)
        }

        if len(apiPolicies) == 0 {
                return "", fmt.Errorf("no policies available from ZTPKI")
        }

        var policies []Policy
        for _, apiPolicy := range apiPolicies {
                policies = append(policies, Policy{
                        ID:   apiPolicy.ID,
                        Name: apiPolicy.Name,
                })
        }

        return ps.presentPolicyMenu(policies)
}

// GetAvailablePolicies returns the list of available policies from ZTPKI API
func (ps *PolicySelector) GetAvailablePolicies() []Policy {
        apiPolicies, err := ps.client.GetPolicies()
        if err != nil {
                return []Policy{}
        }
        
        var policies []Policy
        for _, apiPolicy := range apiPolicies {
                policies = append(policies, Policy{
                        ID:   apiPolicy.ID,
                        Name: apiPolicy.Name,
                })
        }
        return policies
}



// presentPolicyMenu displays the policy selection menu
func (ps *PolicySelector) presentPolicyMenu(policies []Policy) (string, error) {
        reader := bufio.NewReader(os.Stdin)

        for {
                fmt.Println("\nAvailable Certificate Policies:")
                fmt.Println("==============================")
                
                for i, policy := range policies {
                        fmt.Printf("%d. %s\n", i+1, policy.Name)
                        fmt.Printf("   Policy ID: %s\n", policy.ID)
                        if i < len(policies)-1 {
                                fmt.Println()
                        }
                }
                
                fmt.Printf("\nSelect a policy (1-%d) or 'q' to quit: ", len(policies))
                
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
                        fmt.Println("Invalid input. Please enter a number between 1 and", len(policies), "or 'q' to quit.")
                        continue
                }
                
                if selection < 1 || selection > len(policies) {
                        fmt.Printf("Invalid selection. Please choose a number between 1 and %d.\n", len(policies))
                        continue
                }
                
                selectedPolicy := policies[selection-1]
                fmt.Printf("\nYou selected: %s\n", selectedPolicy.Name)
                fmt.Printf("Policy ID: %s\n", selectedPolicy.ID)
                
                // Confirm selection
                fmt.Print("\nConfirm this selection? (y/n): ")
                confirm, err := reader.ReadString('\n')
                if err != nil {
                        return "", fmt.Errorf("failed to read confirmation: %w", err)
                }
                
                confirm = strings.TrimSpace(strings.ToLower(confirm))
                if confirm == "y" || confirm == "yes" {
                        fmt.Printf("Using policy: %s\n", selectedPolicy.ID)
                        return selectedPolicy.ID, nil
                }
                
                fmt.Println("Selection not confirmed. Please choose again.")
        }
}

// GetPolicyByID retrieves policy information by ID
func (ps *PolicySelector) GetPolicyByID(policyID string) (*Policy, error) {
        policies := ps.GetAvailablePolicies()

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
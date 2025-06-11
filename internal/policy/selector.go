package policy

import (
        "bufio"
        "fmt"
        "os"
        "strconv"
        "strings"

        "zcert/internal/api"
)

// LegacyPolicy represents a simple policy option for backward compatibility
type LegacyPolicy struct {
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

        var policies []LegacyPolicy
        for _, apiPolicy := range apiPolicies {
                policies = append(policies, LegacyPolicy{
                        ID:   apiPolicy.ID,
                        Name: apiPolicy.Name,
                })
        }

        return ps.presentPolicyMenu(policies)
}

// GetAvailablePolicies returns the list of available policies from ZTPKI API
func (ps *PolicySelector) GetAvailablePolicies() []LegacyPolicy {
        apiPolicies, err := ps.client.GetPolicies()
        if err != nil {
                return []LegacyPolicy{}
        }
        
        var policies []LegacyPolicy
        for _, apiPolicy := range apiPolicies {
                policies = append(policies, LegacyPolicy{
                        ID:   apiPolicy.ID,
                        Name: apiPolicy.Name,
                })
        }
        return policies
}



// presentPolicyMenu displays the policy selection menu
func (ps *PolicySelector) presentPolicyMenu(policies []LegacyPolicy) (string, error) {
        reader := bufio.NewReader(os.Stdin)

        for {
                fmt.Println("\nAvailable Certificate Policies:")
                fmt.Println("==============================")
                
                for i, policy := range policies {
                        fmt.Printf("%d. %s (Policy ID: %s)\n", i+1, policy.Name, policy.ID)
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
                fmt.Printf("Using policy: %s\n", selectedPolicy.ID)
                return selectedPolicy.ID, nil
        }
}

// GetPolicyByID retrieves policy information by ID
func (ps *PolicySelector) GetPolicyByID(policyID string) (*LegacyPolicy, error) {
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

// SelectCompatiblePolicy displays policies with compatibility indicators and allows selection
func (ps *PolicySelector) SelectCompatiblePolicy(userArgs *UserArgs) (string, error) {
        // Get all available policies with detailed configuration
        policies, err := ps.fetchAllPolicies()
        if err != nil {
                return "", fmt.Errorf("failed to fetch policies: %w", err)
        }

        if len(policies) == 0 {
                return "", fmt.Errorf("no policies available")
        }

        // Display policies with compatibility status
        compatibleIndices := ps.displayPoliciesWithCompatibility(policies, userArgs)

        if len(compatibleIndices) == 0 {
                return "", fmt.Errorf("no policies are compatible with your certificate requirements")
        }

        // Get user selection
        selection, err := ps.getUserSelection(len(policies))
        if err != nil {
                return "", err
        }

        // Validate that selection is compatible
        compatible := false
        for _, idx := range compatibleIndices {
                if idx == selection {
                        compatible = true
                        break
                }
        }
        if !compatible {
                return "", fmt.Errorf("selected policy is incompatible with your certificate requirements")
        }

        // Return the selected policy ID/name
        selectedPolicy := policies[selection-1]
        return ps.getPolicyIdentifier(selectedPolicy), nil
}

// fetchAllPolicies retrieves all available policies from the API
func (ps *PolicySelector) fetchAllPolicies() ([]Policy, error) {
        // Get policies from the real ZTPKI API
        apiPolicies, err := ps.client.GetPolicies()
        if err != nil {
                return nil, fmt.Errorf("failed to retrieve policies from ZTPKI API: %w", err)
        }

        // Convert API policies to internal Policy format
        var policies []Policy
        for _, apiPolicy := range apiPolicies {
                // Get detailed policy configuration including validity constraints
                policyDetails, err := ps.client.GetPolicyDetails(apiPolicy.ID)
                if err != nil {
                        fmt.Fprintf(os.Stderr, "Warning: Could not fetch policy details for %s: %v\n", apiPolicy.Name, err)
                        continue // Skip policies we can't get details for
                }
                
                // Extract real validity constraints from ZTPKI policy
                policy := Policy{
                        Name: apiPolicy.Name,
                        ID:   apiPolicy.ID,
                        Details: PolicyDetails{
                                Validity: ValidityConfig{
                                        Days:     policyDetails.Details.Validity.Days,
                                        Months:   policyDetails.Details.Validity.Months,
                                        Years:    policyDetails.Details.Validity.Years,
                                        Required: policyDetails.Details.Validity.Required,
                                },
                                // Basic DN requirements - CN is always required
                                DNComponents: []DNComponent{
                                        {Tag: "CN", Required: true},
                                },
                        },
                        // REMOVED PolicyEnabled validation - as requested
                        Enabled: PolicyEnabled{REST: true, UI: true, ACME: true, SCEP: true},
                }
                
                        
                policies = append(policies, policy)
        }

        return policies, nil
}

// displayPoliciesWithCompatibility shows all policies with compatibility indicators
func (ps *PolicySelector) displayPoliciesWithCompatibility(policies []Policy, userArgs *UserArgs) []int {
        fmt.Println("Available policies (select by number):")
        fmt.Println("Note: Validity period validation is performed server-side by ZTPKI")
        
        var compatibleIndices []int
        
        for i, policy := range policies {
                compatibility := policy.CheckCompleteCompatibility(userArgs)
                
                if compatibility.IsCompatible {
                        fmt.Printf("  [%d] ✓ %s\n", i+1, policy.Name)
                        compatibleIndices = append(compatibleIndices, i+1)
                } else {
                        reasonStr := strings.Join(compatibility.Reasons, ", ")
                        fmt.Printf("  [%d] ✗ %s (incompatible: %s)\n", i+1, policy.Name, reasonStr)
                }
        }
        
        return compatibleIndices
}

// getUserSelection prompts the user to select a policy
func (ps *PolicySelector) getUserSelection(maxOptions int) (int, error) {
        fmt.Print("\nEnter selection: ")
        
        scanner := bufio.NewScanner(os.Stdin)
        if !scanner.Scan() {
                return 0, fmt.Errorf("failed to read user input")
        }
        
        input := strings.TrimSpace(scanner.Text())
        selection, err := strconv.Atoi(input)
        if err != nil {
                return 0, fmt.Errorf("invalid selection: %s", input)
        }
        
        if selection < 1 || selection > maxOptions {
                return 0, fmt.Errorf("selection %d is out of range (1-%d)", selection, maxOptions)
        }
        
        return selection, nil
}

// getPolicyIdentifier returns the identifier for the policy (ID if available, otherwise name)
func (ps *PolicySelector) getPolicyIdentifier(policy Policy) string {
        if policy.ID != "" {
                return policy.ID
        }
        return policy.Name
}

// ValidatePolicyCompatibility validates if a specific policy is compatible with user requirements
func (ps *PolicySelector) ValidatePolicyCompatibility(policyID string, userArgs *UserArgs) error {
        // Get detailed policy configuration
        policyDetails, err := ps.client.GetPolicyDetails(policyID)
        if err != nil {
                return fmt.Errorf("failed to fetch policy details: %w", err)
        }
        
        // Convert to internal Policy format
        policy := Policy{
                Name: policyDetails.Name,
                ID:   policyDetails.ID,
                Details: PolicyDetails{
                        Validity: ValidityConfig{
                                Days:     policyDetails.Details.Validity.Days,
                                Months:   policyDetails.Details.Validity.Months,
                                Years:    policyDetails.Details.Validity.Years,
                                Required: policyDetails.Details.Validity.Required,
                        },
                        // Basic DN requirements - CN is always required
                        DNComponents: []DNComponent{
                                {Tag: "CN", Required: true},
                        },
                        // SubjectAltNames: Empty for now - ZTPKI API doesn't return SAN constraints in policy details
                        // This means IP SANs will be blocked by default (which is correct for this policy)
                },
                Enabled: PolicyEnabled{REST: true, UI: true, ACME: true, SCEP: true},
        }
        
        // Check compatibility
        compatibility := policy.CheckCompleteCompatibility(userArgs)
        if !compatibility.IsCompatible {
                return fmt.Errorf(strings.Join(compatibility.Reasons, "; "))
        }
        
        return nil
}

// Helper function to check if a slice contains a value
// Removed duplicate function - use internal/utils.ContainsInt instead


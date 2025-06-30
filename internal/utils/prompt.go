package utils

import (
        "bufio"
        "fmt"
        "os"
        "strconv"
        "strings"

        "zcert/internal/api"
)

// PromptString prompts the user for a string input
func PromptString(prompt, defaultValue string) (string, error) {
        reader := bufio.NewReader(os.Stdin)
        
        if defaultValue != "" {
                fmt.Printf("%s [%s]: ", prompt, defaultValue)
        } else {
                fmt.Printf("%s: ", prompt)
        }
        
        input, err := reader.ReadString('\n')
        if err != nil {
                return "", err
        }
        
        input = strings.TrimSpace(input)
        if input == "" && defaultValue != "" {
                return defaultValue, nil
        }
        
        return input, nil
}

// PromptConfirm prompts the user for a yes/no confirmation
func PromptConfirm(prompt string, defaultValue bool) (bool, error) {
        reader := bufio.NewReader(os.Stdin)
        
        var defaultStr string
        if defaultValue {
                defaultStr = "Y/n"
        } else {
                defaultStr = "y/N"
        }
        
        fmt.Printf("%s (%s): ", prompt, defaultStr)
        
        input, err := reader.ReadString('\n')
        if err != nil {
                return false, err
        }
        
        input = strings.TrimSpace(strings.ToLower(input))
        
        if input == "" {
                return defaultValue, nil
        }
        
        return input == "y" || input == "yes", nil
}

// PromptInt prompts the user for an integer input
func PromptInt(prompt string, defaultValue int) (int, error) {
        for {
                var input string
                var err error
                
                if defaultValue != 0 {
                        input, err = PromptString(fmt.Sprintf("%s [%d]", prompt, defaultValue), strconv.Itoa(defaultValue))
                } else {
                        input, err = PromptString(prompt, "")
                }
                
                if err != nil {
                        return 0, err
                }
                
                if input == "" && defaultValue != 0 {
                        return defaultValue, nil
                }
                
                value, err := strconv.Atoi(input)
                if err != nil {
                        fmt.Printf("Please enter a valid number: %v\n", err)
                        continue
                }
                
                return value, nil
        }
}

// SelectPolicy presents an interactive menu for policy selection
func SelectPolicy(policies []api.Policy) (string, error) {
        if len(policies) == 0 {
                return "", fmt.Errorf("no policies available")
        }
        
        // If only one policy, use it automatically
        if len(policies) == 1 {
                fmt.Printf("Using policy: %s (%s)\n", policies[0].Name, policies[0].ID)
                return policies[0].ID, nil
        }
        
        // Display available policies
        fmt.Println("\nAvailable certificate policies:")
        for i, policy := range policies {
                status := "enabled"
                if !policy.Enabled.UI && !policy.Enabled.REST {
                        status = "disabled"
                }
                fmt.Printf("  [%d] %s (%s) - %s\n", i+1, policy.Name, policy.Type, status)
                if policy.Description != "" {
                        fmt.Printf("      %s\n", policy.Description)
                }
        }
        
        // Get user selection
        for {
                selection, err := PromptInt("\nSelect a policy (enter number)", 1)
                if err != nil {
                        return "", err
                }
                
                if selection < 1 || selection > len(policies) {
                        fmt.Printf("Please select a number between 1 and %d\n", len(policies))
                        continue
                }
                
                selectedPolicy := policies[selection-1]
                
                // Check if policy is enabled
                if !selectedPolicy.Enabled.UI && !selectedPolicy.Enabled.REST {
                        confirm, err := PromptConfirm(
                                fmt.Sprintf("Policy '%s' is disabled. Use it anyway?", selectedPolicy.Name),
                                false)
                        if err != nil {
                                return "", err
                        }
                        if !confirm {
                                continue
                        }
                }
                
                fmt.Printf("Selected policy: %s (%s)\n", selectedPolicy.Name, selectedPolicy.ID)
                return selectedPolicy.ID, nil
        }
}

// SelectFromList presents a generic selection menu for a list of items
func SelectFromList(items []string, prompt string) (string, error) {
        if len(items) == 0 {
                return "", fmt.Errorf("no items available for selection")
        }
        
        // If only one item, use it automatically
        if len(items) == 1 {
                return items[0], nil
        }
        
        // Display available items
        fmt.Printf("\n%s:\n", prompt)
        for i, item := range items {
                fmt.Printf("  [%d] %s\n", i+1, item)
        }
        
        // Get user selection
        for {
                selection, err := PromptInt("\nEnter selection number", 1)
                if err != nil {
                        return "", err
                }
                
                if selection < 1 || selection > len(items) {
                        fmt.Printf("Please select a number between 1 and %d\n", len(items))
                        continue
                }
                
                return items[selection-1], nil
        }
}

// IsInteractive checks if the current session is interactive (has a TTY)
func IsInteractive() bool {
        // Check if stdin is a terminal
        fileInfo, err := os.Stdin.Stat()
        if err != nil {
                return false
        }
        
        return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// PromptPassword prompts for a password without echoing input
func PromptPassword(prompt string) (string, error) {
        fmt.Print(prompt)
        
        // For now, we'll use regular input
        // In a production implementation, you'd use golang.org/x/term
        // to hide the password input
        reader := bufio.NewReader(os.Stdin)
        password, err := reader.ReadString('\n')
        if err != nil {
                return "", err
        }
        
        return strings.TrimSpace(password), nil
}

// ConfirmAction prompts for confirmation of a potentially destructive action
func ConfirmAction(action, target string) (bool, error) {
        message := fmt.Sprintf("Are you sure you want to %s %s?", action, target)
        return PromptConfirm(message, false)
}

// DisplayError formats and displays an error message to stderr
func DisplayError(err error) {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
}

// DisplayWarning formats and displays a warning message to stderr
func DisplayWarning(message string) {
        fmt.Fprintf(os.Stderr, "Warning: %s\n", message)
}

// DisplayInfo formats and displays an informational message to stderr
func DisplayInfo(message string) {
        fmt.Fprintf(os.Stderr, "Info: %s\n", message)
}

// SelectCertificate presents an interactive menu for certificate selection
func SelectCertificate(certificates []api.Certificate, prompt string, wide bool) (*api.Certificate, error) {
        if len(certificates) == 0 {
                return nil, fmt.Errorf("no certificates available for selection")
        }
        
        // If only one certificate, use it automatically
        if len(certificates) == 1 {
                fmt.Fprintf(os.Stderr, "Found 1 certificate: %s (ID: %s)\n", 
                        certificates[0].CommonName, certificates[0].ID)
                return &certificates[0], nil
        }
        
        // Check if this is an interactive session
        if !IsInteractive() {
                return nil, fmt.Errorf("multiple certificates found (%d) but running in non-interactive mode. Use --id to specify a particular certificate:\n%s", 
                        len(certificates), formatCertificateList(certificates))
        }
        
        // Display available certificates in table format using centralized utilities
        opts := &CertificateSelectionOptions{
                Wide:   wide,
                Prompt: prompt,
                Writer: os.Stderr,
        }
        err := DisplayCertificatesForSelection(certificates, opts)
        if err != nil {
                return nil, err
        }
        
        // Get user selection
        for {
                fmt.Fprintf(os.Stderr, "\nSelect a certificate (enter number): ")
                
                reader := bufio.NewReader(os.Stdin)
                input, err := reader.ReadString('\n')
                if err != nil {
                        return nil, err
                }
                
                input = strings.TrimSpace(input)
                if input == "" {
                        fmt.Fprintf(os.Stderr, "Please enter a valid number.\n")
                        continue
                }
                
                selection, err := strconv.Atoi(input)
                if err != nil {
                        fmt.Fprintf(os.Stderr, "Please enter a valid number: %v\n", err)
                        continue
                }
                
                if selection < 1 || selection > len(certificates) {
                        fmt.Fprintf(os.Stderr, "Please select a number between 1 and %d\n", len(certificates))
                        continue
                }
                
                selectedCert := &certificates[selection-1]
                fmt.Fprintf(os.Stderr, "Selected certificate: %s (ID: %s)\n", 
                        selectedCert.CommonName, selectedCert.ID)
                return selectedCert, nil
        }
}

// formatCertificateList formats a list of certificates for display in error messages
func formatCertificateList(certificates []api.Certificate) string {
        return FormatCertificateList(certificates)
}


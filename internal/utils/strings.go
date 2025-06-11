package utils

import "strings"

// Contains checks if a string contains a substring (case-sensitive)
func Contains(s, substr string) bool {
        return strings.Contains(s, substr)
}

// ContainsInt checks if an integer slice contains a specific value
func ContainsInt(slice []int, value int) bool {
        for _, item := range slice {
                if item == value {
                        return true
                }
        }
        return false
}
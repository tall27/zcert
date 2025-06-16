//go:build integration
// +build integration

package cmd

import (
        "encoding/json"
        "fmt"
        "os"
        "os/exec"
        "strconv"
        "strings"
        "testing"
)

// Test structure for search limit scenarios
type SearchLimitTest struct {
        name           string
        limit          int
        expectedCount  int
        description    string
}

// TestSearchLimitScenarios tests various limit scenarios using the actual zcert binary
func TestSearchLimitScenarios(t *testing.T) {
        // Check if zcert binary exists
        if _, err := os.Stat("../zcert"); os.IsNotExist(err) {
                t.Skip("zcert binary not found. Run 'go build -o zcert main.go' first")
        }
        
        // Check if environment variables are set for testing
        if os.Getenv("ZTPKI_URL") == "" || os.Getenv("ZTPKI_HAWK_ID") == "" || os.Getenv("ZTPKI_HAWK_SECRET") == "" {
                t.Skip("ZTPKI environment variables not set. Required: ZTPKI_URL, ZTPKI_HAWK_ID, ZTPKI_HAWK_SECRET")
        }
        
        tests := []SearchLimitTest{
                {
                        name:          "LimitLowerThan10",
                        limit:         5,
                        expectedCount: 5,
                        description:   "Search with limit lower than server constraint (5 certificates)",
                },
                {
                        name:          "LimitEqualTo10",
                        limit:         10,
                        expectedCount: 10,
                        description:   "Search with limit equal to server constraint (10 certificates)",
                },
                {
                        name:          "LimitHigherThan10",
                        limit:         25,
                        expectedCount: 25,
                        description:   "Search with limit higher than server constraint (25 certificates)",
                },
                {
                        name:          "DefaultLimit",
                        limit:         -1, // Special value to test default behavior
                        expectedCount: 10,
                        description:   "Search without specifying limit (default 10 certificates)",
                },
                {
                        name:          "VeryHighLimit",
                        limit:         50,
                        expectedCount: 50,
                        description:   "Search with very high limit (50 certificates)",
                },
        }
        
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        // Test JSON format
                        t.Run("JSON", func(t *testing.T) {
                                output, err := runZcertSearchCommand(tt.limit, "json", false)
                                if err != nil {
                                        t.Fatalf("Search command failed: %v", err)
                                }
                                
                                count := countJSONResults(t, output)
                                if count != tt.expectedCount {
                                        t.Errorf("%s - JSON: Expected %d certificates, got %d", 
                                                tt.description, tt.expectedCount, count)
                                }
                        })
                        
                        // Test Table format
                        t.Run("Table", func(t *testing.T) {
                                output, err := runZcertSearchCommand(tt.limit, "table", false)
                                if err != nil {
                                        t.Fatalf("Search command failed: %v", err)
                                }
                                
                                count := countTableResults(output)
                                if count != tt.expectedCount {
                                        t.Errorf("%s - Table: Expected %d certificates, got %d", 
                                                tt.description, tt.expectedCount, count)
                                }
                        })
                        
                        // Test CSV format
                        t.Run("CSV", func(t *testing.T) {
                                output, err := runZcertSearchCommand(tt.limit, "csv", false)
                                if err != nil {
                                        t.Fatalf("Search command failed: %v", err)
                                }
                                
                                count := countCSVResults(output)
                                if count != tt.expectedCount {
                                        t.Errorf("%s - CSV: Expected %d certificates, got %d", 
                                                tt.description, tt.expectedCount, count)
                                }
                        })
                        
                        // Test with --wide flag
                        t.Run("TableWide", func(t *testing.T) {
                                output, err := runZcertSearchCommand(tt.limit, "table", true)
                                if err != nil {
                                        t.Fatalf("Search command with --wide failed: %v", err)
                                }
                                
                                count := countTableResults(output)
                                if count != tt.expectedCount {
                                        t.Errorf("%s - Table Wide: Expected %d certificates, got %d", 
                                                tt.description, tt.expectedCount, count)
                                }
                                
                                // Verify wide format shows full IDs (not truncated with ...)
                                if !strings.Contains(output, "-") || strings.Contains(output, "...") {
                                        t.Logf("Wide format output sample: %s", output[:min(200, len(output))])
                                }
                        })
                })
        }
}

// runZcertSearchCommand executes the actual zcert binary with specified parameters
func runZcertSearchCommand(limit int, format string, wide bool) (string, error) {
        args := []string{"search"}
        
        if limit > 0 {
                args = append(args, "--limit", strconv.Itoa(limit))
        }
        
        args = append(args, "--format", format)
        
        if wide {
                args = append(args, "--wide")
        }
        
        cmd := exec.Command("../zcert", args...)
        output, err := cmd.Output()
        if err != nil {
                return "", fmt.Errorf("command execution failed: %v", err)
        }
        
        return string(output), nil
}

// countJSONResults counts certificates in JSON output
func countJSONResults(t *testing.T, output string) int {
        var results []map[string]interface{}
        err := json.Unmarshal([]byte(output), &results)
        if err != nil {
                t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, output)
        }
        return len(results)
}

// countTableResults counts certificates in table output
func countTableResults(output string) int {
        lines := strings.Split(strings.TrimSpace(output), "\n")
        // Subtract header lines (2 lines: header + separator)
        if len(lines) < 3 {
                return 0
        }
        return len(lines) - 2
}

// countCSVResults counts certificates in CSV output
func countCSVResults(output string) int {
        lines := strings.Split(strings.TrimSpace(output), "\n")
        // Subtract header line
        if len(lines) < 2 {
                return 0
        }
        return len(lines) - 1
}

// TestSearchCommandFlags tests individual flag combinations
func TestSearchCommandFlags(t *testing.T) {
        // Check prerequisites
        if _, err := os.Stat("../zcert"); os.IsNotExist(err) {
                t.Skip("zcert binary not found. Run 'go build -o zcert main.go' first")
        }
        
        if os.Getenv("ZTPKI_URL") == "" || os.Getenv("ZTPKI_HAWK_ID") == "" || os.Getenv("ZTPKI_HAWK_SECRET") == "" {
                t.Skip("ZTPKI environment variables not set. Required: ZTPKI_URL, ZTPKI_HAWK_ID, ZTPKI_HAWK_SECRET")
        }
        
        flagTests := []struct {
                name     string
                limit    int
                format   string
                wide     bool
                expected int
        }{
                {"SmallLimit_JSON", 3, "json", false, 3},
                {"SmallLimit_CSV", 7, "csv", false, 7},
                {"DefaultLimit_Table", 10, "table", false, 10},
                {"LargeLimit_JSON", 30, "json", false, 30},
                {"LargeLimit_CSV_Wide", 15, "csv", true, 15},
                {"VeryLargeLimit_Table_Wide", 100, "table", true, 100},
        }
        
        for _, tt := range flagTests {
                t.Run(tt.name, func(t *testing.T) {
                        output, err := runZcertSearchCommand(tt.limit, tt.format, tt.wide)
                        if err != nil {
                                t.Fatalf("Search command failed: %v", err)
                        }
                        
                        var count int
                        switch tt.format {
                        case "json":
                                count = countJSONResults(t, output)
                        case "csv":
                                count = countCSVResults(output)
                        case "table":
                                count = countTableResults(output)
                        }
                        
                        if count != tt.expected {
                                t.Errorf("%s: Expected %d results, got %d", tt.name, tt.expected, count)
                        }
                })
        }
}

// Helper function for min calculation
func min(a, b int) int {
        if a < b {
                return a
        }
        return b
}
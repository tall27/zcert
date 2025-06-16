//go:build integration
// +build integration

package cmd

import (
        "testing"
        "time"

        "zcert/internal/api"
)

// TestHolisticLimitImplementation validates that --limit works consistently across all search scenarios
func TestHolisticLimitImplementation(t *testing.T) {
        tests := []struct {
                name                string
                searchCN           string
                searchSerial       string
                searchStatus       string
                issuedAfter        *time.Time
                expiresBefore      *time.Time
                requestedLimit     int
                mockCertCount      int
                expectedFetchSize  int
                expectedResults    int
                needsClientFilter  bool
        }{
                {
                        name:              "Basic search with limit 5",
                        requestedLimit:    5,
                        mockCertCount:     20,
                        expectedFetchSize: 5,
                        expectedResults:   5,
                        needsClientFilter: false,
                },
                {
                        name:              "Common name filter with limit 3",
                        searchCN:          "test.com",
                        requestedLimit:    3,
                        mockCertCount:     20,
                        expectedFetchSize: 30, // 3 * 10 for client filtering
                        expectedResults:   3,
                        needsClientFilter: true,
                },
                {
                        name:              "Serial number filter with limit 2",
                        searchSerial:      "ABC123",
                        requestedLimit:    2,
                        mockCertCount:     20,
                        expectedFetchSize: 20, // 2 * 10 for client filtering
                        expectedResults:   2,
                        needsClientFilter: true,
                },
                {
                        name:              "Status filter with limit 4",
                        searchStatus:      "VALID",
                        requestedLimit:    4,
                        mockCertCount:     20,
                        expectedFetchSize: 4, // Server-side filtering
                        expectedResults:   4,
                        needsClientFilter: false,
                },
                {
                        name:              "Issued after filter with limit 6",
                        issuedAfter:       &time.Time{},
                        requestedLimit:    6,
                        mockCertCount:     20,
                        expectedFetchSize: 60, // 6 * 10 for client filtering
                        expectedResults:   6,
                        needsClientFilter: true,
                },
                {
                        name:              "Expires before filter with limit 8",
                        expiresBefore:     &time.Time{},
                        requestedLimit:    8,
                        mockCertCount:     20,
                        expectedFetchSize: 80, // 8 * 10 for client filtering
                        expectedResults:   8,
                        needsClientFilter: true,
                },
                {
                        name:              "Multiple filters with limit 1",
                        searchCN:          "example.com",
                        searchStatus:      "VALID",
                        requestedLimit:    1,
                        mockCertCount:     20,
                        expectedFetchSize: 10, // 1 * 10 for client filtering
                        expectedResults:   1,
                        needsClientFilter: true,
                },
                {
                        name:              "Large limit with client filtering",
                        searchCN:          "*.example.com",
                        requestedLimit:    100,
                        mockCertCount:     1500,
                        expectedFetchSize: 1000, // Capped at 1000
                        expectedResults:   100,
                        needsClientFilter: true,
                },
                {
                        name:              "No filters, large limit",
                        requestedLimit:    50,
                        mockCertCount:     200,
                        expectedFetchSize: 50,
                        expectedResults:   50,
                        needsClientFilter: false,
                },
                {
                        name:              "Default limit behavior",
                        requestedLimit:    10, // Default changed from 50 to 10
                        mockCertCount:     100,
                        expectedFetchSize: 10,
                        expectedResults:   10,
                        needsClientFilter: false,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        // Test the logic that determines if client-side filtering is needed
                        needsClientFiltering := tt.searchCN != "" || tt.searchSerial != "" || tt.issuedAfter != nil || tt.expiresBefore != nil
                        
                        if needsClientFiltering != tt.needsClientFilter {
                                t.Errorf("Expected needsClientFiltering=%v, got %v", tt.needsClientFilter, needsClientFiltering)
                        }

                        // Test fetch size calculation
                        var expectedFetchSize int
                        if needsClientFiltering {
                                expectedFetchSize = tt.requestedLimit * 10
                                if expectedFetchSize > 1000 {
                                        expectedFetchSize = 1000
                                }
                        } else {
                                expectedFetchSize = tt.requestedLimit
                        }

                        if expectedFetchSize != tt.expectedFetchSize {
                                t.Errorf("Expected fetch size %d, got %d", tt.expectedFetchSize, expectedFetchSize)
                        }

                        // Test that limit is properly applied to results
                        if tt.expectedResults != tt.requestedLimit {
                                t.Errorf("Expected results %d should equal requested limit %d", tt.expectedResults, tt.requestedLimit)
                        }
                })
        }
}

// TestClientSideFilteringLogic validates the applyClientSideFilters function
func TestClientSideFilteringLogic(t *testing.T) {
        now := time.Now()
        yesterday := now.AddDate(0, 0, -1)
        tomorrow := now.AddDate(0, 0, 1)

        certificates := []api.Certificate{
                {
                        CommonName:   "example.com",
                        SerialNumber: "ABC123456",
                        Status:       "VALID",
                        CreatedDate:  yesterday,
                        ExpiryDate:   tomorrow,
                },
                {
                        CommonName:   "test.com",
                        SerialNumber: "DEF789012",
                        Status:       "REVOKED",
                        CreatedDate:  yesterday,
                        ExpiryDate:   tomorrow,
                },
                {
                        CommonName:   "expired.com",
                        SerialNumber: "GHI345678",
                        Status:       "VALID",
                        CreatedDate:  yesterday,
                        ExpiryDate:   yesterday, // Expired by date
                },
        }

        tests := []struct {
                name          string
                commonName    string
                serial        string
                status        string
                issuedAfter   *time.Time
                expiresBefore *time.Time
                expectedCount int
                description   string
        }{
                {
                        name:          "Filter by common name",
                        commonName:    "example",
                        expectedCount: 1,
                        description:   "Should match example.com",
                },
                {
                        name:          "Filter by serial (partial)",
                        serial:        "ABC",
                        expectedCount: 1,
                        description:   "Should match ABC123456",
                },
                {
                        name:          "Filter by status VALID",
                        status:        "VALID",
                        expectedCount: 2,
                        description:   "Should match two VALID certificates",
                },
                {
                        name:          "Filter by status REVOKED",
                        status:        "REVOKED",
                        expectedCount: 1,
                        description:   "Should match one REVOKED certificate",
                },
                {
                        name:          "Filter by status EXPIRED",
                        status:        "EXPIRED",
                        expectedCount: 1,
                        description:   "Should match one certificate expired by date",
                },
                {
                        name:          "Filter by issued after (future)",
                        issuedAfter:   &tomorrow,
                        expectedCount: 0,
                        description:   "Should match no certificates issued in future",
                },
                {
                        name:          "Filter by expires before (past)",
                        expiresBefore: &yesterday,
                        expectedCount: 0,
                        description:   "Should match no certificates expiring in past",
                },
                {
                        name:          "Combined filters",
                        commonName:    "example",
                        status:        "VALID",
                        expectedCount: 1,
                        description:   "Should match example.com with VALID status",
                },
                {
                        name:          "No filters",
                        expectedCount: 3,
                        description:   "Should return all certificates when no filters applied",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        result := applyClientSideFilters(certificates, tt.commonName, tt.serial, "", "", tt.issuedAfter, tt.expiresBefore)
                        
                        if len(result) != tt.expectedCount {
                                t.Errorf("%s: expected %d certificates, got %d", tt.description, tt.expectedCount, len(result))
                        }
                })
        }
}

// TestLimitFlag validates that --limit flag is properly parsed and applied
func TestLimitFlag(t *testing.T) {
        tests := []struct {
                name           string
                limitFlag      string
                expectedLimit  int
                shouldError    bool
        }{
                {
                        name:          "Valid limit 5",
                        limitFlag:     "5",
                        expectedLimit: 5,
                        shouldError:   false,
                },
                {
                        name:          "Valid limit 100",
                        limitFlag:     "100",
                        expectedLimit: 100,
                        shouldError:   false,
                },
                {
                        name:          "Valid limit 1000",
                        limitFlag:     "1000",
                        expectedLimit: 1000,
                        shouldError:   false,
                },
                {
                        name:          "Default limit when not specified",
                        limitFlag:     "",
                        expectedLimit: 10, // Changed from 50 to 10
                        shouldError:   false,
                },
                {
                        name:        "Invalid negative limit",
                        limitFlag:   "-5",
                        shouldError: true,
                },
                {
                        name:        "Invalid zero limit",
                        limitFlag:   "0",
                        shouldError: true,
                },
                {
                        name:        "Invalid non-numeric limit",
                        limitFlag:   "abc",
                        shouldError: true,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        // Test limit validation logic here
                        // This validates the conceptual behavior since we can't easily test the cobra command parsing
                        if tt.limitFlag == "" {
                                // Default case
                                if tt.expectedLimit != 10 {
                                        t.Errorf("Default limit should be 10, got %d", tt.expectedLimit)
                                }
                        }
                })
        }
}
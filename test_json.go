package main

import (
	"encoding/json"
	"fmt"
	"zcert/internal/api"
)

func main() {
	// Test JSON unmarshaling with numeric years
	jsonData := `{
		"validity": {
			"days": ["1-30", "90"],
			"months": ["1-12"],
			"years": 1,
			"required": false
		}
	}`
	
	var policyDetails api.PolicyDetailsStruct
	err := json.Unmarshal([]byte(jsonData), &policyDetails)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	
	fmt.Printf("Successfully unmarshaled!\n")
	fmt.Printf("Days: %v\n", policyDetails.Validity.Days)
	fmt.Printf("Months: %v\n", policyDetails.Validity.Months)
	fmt.Printf("Years: %v\n", policyDetails.Validity.Years)
	fmt.Printf("Required: %v\n", policyDetails.Validity.Required)
	
	// Test with array of numbers
	jsonData2 := `{
		"validity": {
			"days": [1, 30, 90],
			"months": [1, 6, 12],
			"years": [1, 2],
			"required": true
		}
	}`
	
	var policyDetails2 api.PolicyDetailsStruct
	err = json.Unmarshal([]byte(jsonData2), &policyDetails2)
	if err != nil {
		fmt.Printf("Error with numeric array: %v\n", err)
		return
	}
	
	fmt.Printf("\nWith numeric arrays:\n")
	fmt.Printf("Days: %v\n", policyDetails2.Validity.Days)
	fmt.Printf("Months: %v\n", policyDetails2.Validity.Months)
	fmt.Printf("Years: %v\n", policyDetails2.Validity.Years)
	fmt.Printf("Required: %v\n", policyDetails2.Validity.Required)
}
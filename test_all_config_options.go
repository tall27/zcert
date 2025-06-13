
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"./internal/config"
)

// TestConfigOption represents a test case for configuration options
type TestConfigOption struct {
	ProfileName    string
	OptionName     string
	ExpectedValue  interface{}
	ActualValue    interface{}
	TestPassed     bool
	Description    string
}

func main() {
	// Set environment variables for testing
	os.Setenv("ZCERT_TEST_URL", "https://env-test.venafi.com/api/v2")
	os.Setenv("ZCERT_TEST_HAWK_ID", "env-test-hawk-id")
	os.Setenv("ZCERT_TEST_HAWK_KEY", "env-test-hawk-key")
	os.Setenv("ZCERT_TEST_POLICY", "EnvTestPolicy")

	configFile := "comprehensive-test.cnf"
	
	fmt.Println("=== Testing All zcert Configuration Options ===")
	fmt.Printf("Loading configuration from: %s\n\n", configFile)

	// Load profile configuration
	profileConfig, err := config.LoadProfileConfig(configFile)
	if err != nil {
		fmt.Printf("❌ Failed to load profile config: %v\n", err)
		os.Exit(1)
	}

	var allTests []TestConfigOption
	var passedTests, failedTests int

	// Test 1: Default profile selection
	fmt.Println("1. Testing Default Profile Selection:")
	defaultProfile := profileConfig.GetProfile("")
	if defaultProfile != nil {
		fmt.Printf("   ✅ Default profile found: %s\n", defaultProfile.Name)
		passedTests++
	} else {
		fmt.Printf("   ❌ Default profile not found\n")
		failedTests++
	}

	// Test 2: Profile listing
	fmt.Println("\n2. Testing Profile Listing:")
	profiles := profileConfig.ListProfiles()
	expectedProfiles := []string{"Default", "Test2048", "Test3072", "Test4096", "TestEC256", "TestValidityFormats", "TestEnvVars", "TestQuotedValues", "TestCaseInsensitive", "TestAllFormats"}
	fmt.Printf("   Found %d profiles: %v\n", len(profiles), profiles)
	
	allFound := true
	for _, expected := range expectedProfiles {
		found := false
		for _, actual := range profiles {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("   ❌ Missing expected profile: %s\n", expected)
			allFound = false
		}
	}
	
	if allFound {
		fmt.Printf("   ✅ All expected profiles found\n")
		passedTests++
	} else {
		failedTests++
	}

	// Test 3: Individual profile configurations
	testCases := []struct {
		profileName string
		tests       []TestConfigOption
	}{
		{
			profileName: "Default",
			tests: []TestConfigOption{
				{"Default", "URL", "https://ztpki-dev.venafi.com/api/v2", "", false, "Base URL setting"},
				{"Default", "KeyID", "test-default-hawk-id", "", false, "HAWK ID setting"},
				{"Default", "Secret", "test-default-secret", "", false, "HAWK Secret setting"},
				{"Default", "Format", "pem", "", false, "Certificate format"},
				{"Default", "PolicyID", "DefaultPolicyID", "", false, "Policy ID"},
				{"Default", "KeySize", 2048, 0, false, "Key size"},
				{"Default", "KeyType", "rsa", "", false, "Key type"},
				{"Default", "Validity", 365, 0, false, "Validity period"},
				{"Default", "Chain", true, false, false, "Include chain"},
				{"Default", "NoKeyOut", false, true, false, "No key output"},
				{"Default", "OutDir", "./certs", "", false, "Output directory"},
				{"Default", "P12Pass", "testpassword123", "", false, "P12 password"},
			},
		},
		{
			profileName: "Test2048",
			tests: []TestConfigOption{
				{"Test2048", "KeySize", 2048, 0, false, "2048-bit key size"},
				{"Test2048", "KeyType", "rsa", "", false, "RSA key type"},
				{"Test2048", "Validity", 90, 0, false, "90-day validity"},
				{"Test2048", "Chain", true, false, false, "Chain inclusion"},
			},
		},
		{
			profileName: "Test3072",
			tests: []TestConfigOption{
				{"Test3072", "KeySize", 3072, 0, false, "3072-bit key size"},
				{"Test3072", "Validity", 60, 0, false, "60-day validity"},
				{"Test3072", "Chain", false, true, false, "No chain inclusion"},
				{"Test3072", "NoKeyOut", true, false, false, "No key output enabled"},
			},
		},
		{
			profileName: "Test4096",
			tests: []TestConfigOption{
				{"Test4096", "KeySize", 4096, 0, false, "4096-bit key size"},
				{"Test4096", "Format", "p12", "", false, "P12 format"},
				{"Test4096", "Validity", 180, 0, false, "180-day validity"},
				{"Test4096", "P12Pass", "secure4096password", "", false, "P12 password"},
				{"Test4096", "OutDir", "./test4096", "", false, "Custom output directory"},
			},
		},
		{
			profileName: "TestEC256",
			tests: []TestConfigOption{
				{"TestEC256", "KeySize", 256, 0, false, "EC 256-bit key size"},
				{"TestEC256", "KeyType", "ec", "", false, "EC key type"},
				{"TestEC256", "Validity", 30, 0, false, "30-day validity"},
				{"TestEC256", "Chain", false, true, false, "No chain for EC"},
			},
		},
		{
			profileName: "TestEnvVars",
			tests: []TestConfigOption{
				{"TestEnvVars", "URL", "https://env-test.venafi.com/api/v2", "", false, "Environment variable expansion for URL"},
				{"TestEnvVars", "KeyID", "env-test-hawk-id", "", false, "Environment variable expansion for HAWK ID"},
				{"TestEnvVars", "Secret", "env-test-hawk-key", "", false, "Environment variable expansion for HAWK key"},
				{"TestEnvVars", "PolicyID", "EnvTestPolicy", "", false, "Environment variable expansion for Policy"},
			},
		},
		{
			profileName: "TestQuotedValues",
			tests: []TestConfigOption{
				{"TestQuotedValues", "URL", "https://ztpki-quoted.venafi.com/api/v2", "", false, "Double quoted URL"},
				{"TestQuotedValues", "KeyID", "quoted-hawk-id", "", false, "Double quoted HAWK ID"},
				{"TestQuotedValues", "Secret", "single-quoted-key", "", false, "Single quoted HAWK key"},
				{"TestQuotedValues", "Format", "pem", "", false, "Quoted format"},
				{"TestQuotedValues", "PolicyID", "QuotedPolicy", "", false, "Quoted policy"},
				{"TestQuotedValues", "KeyType", "rsa", "", false, "Quoted key type"},
			},
		},
	}

	fmt.Println("\n3. Testing Individual Profile Configurations:")
	for _, testCase := range testCases {
		fmt.Printf("\n   Profile: %s\n", testCase.profileName)
		profile := profileConfig.GetProfile(testCase.profileName)
		
		if profile == nil {
			fmt.Printf("   ❌ Profile '%s' not found\n", testCase.profileName)
			failedTests += len(testCase.tests)
			continue
		}

		for i := range testCase.tests {
			test := &testCase.tests[i]
			
			// Use reflection to get the actual value from the profile
			profileValue := reflect.ValueOf(profile).Elem()
			fieldValue := profileValue.FieldByName(test.OptionName)
			
			if !fieldValue.IsValid() {
				fmt.Printf("     ❌ %s: Field not found\n", test.Description)
				test.TestPassed = false
				failedTests++
				continue
			}
			
			test.ActualValue = fieldValue.Interface()
			
			// Compare values
			if reflect.DeepEqual(test.ExpectedValue, test.ActualValue) {
				fmt.Printf("     ✅ %s: %v\n", test.Description, test.ActualValue)
				test.TestPassed = true
				passedTests++
			} else {
				fmt.Printf("     ❌ %s: Expected %v, got %v\n", test.Description, test.ExpectedValue, test.ActualValue)
				test.TestPassed = false
				failedTests++
			}
			
			allTests = append(allTests, *test)
		}
	}

	// Test 4: Case-insensitive profile lookup
	fmt.Println("\n4. Testing Case-Insensitive Profile Lookup:")
	testProfile := profileConfig.GetProfile("DEFAULT")
	if testProfile != nil && strings.EqualFold(testProfile.Name, "default") {
		fmt.Printf("   ✅ Case-insensitive lookup works\n")
		passedTests++
	} else {
		fmt.Printf("   ❌ Case-insensitive lookup failed\n")
		failedTests++
	}

	// Test 5: Profile merging with flags
	fmt.Println("\n5. Testing Profile Merging with Command-Line Flags:")
	baseProfile := profileConfig.GetProfile("Default")
	mergedProfile := config.MergeProfileWithFlags(
		baseProfile,
		"https://override-url.com",    // URL
		"override-hawk-id",            // KeyID
		"override-hawk-key",           // Secret
		"p12",                         // Format
		"OverridePolicy",              // Policy
		"overridepass",                // P12Pass
		4096,                          // KeySize
		"ec",                          // KeyType
	)
	
	if mergedProfile.URL == "https://override-url.com" &&
		mergedProfile.KeyID == "override-hawk-id" &&
		mergedProfile.Secret == "override-hawk-key" &&
		mergedProfile.Format == "p12" &&
		mergedProfile.PolicyID == "OverridePolicy" &&
		mergedProfile.P12Pass == "overridepass" &&
		mergedProfile.KeySize == 4096 &&
		mergedProfile.KeyType == "ec" {
		fmt.Printf("   ✅ Profile merging with flags works correctly\n")
		passedTests++
	} else {
		fmt.Printf("   ❌ Profile merging with flags failed\n")
		failedTests++
	}

	// Test 6: File paths and directory handling
	fmt.Println("\n6. Testing File Paths and Directory Handling:")
	test4096Profile := profileConfig.GetProfile("Test4096")
	if test4096Profile != nil && test4096Profile.OutDir == "./test4096" {
		fmt.Printf("   ✅ Custom output directory setting works\n")
		passedTests++
	} else {
		fmt.Printf("   ❌ Custom output directory setting failed\n")
		failedTests++
	}

	// Summary
	fmt.Printf("\n=== Test Summary ===\n")
	fmt.Printf("Total tests run: %d\n", passedTests+failedTests)
	fmt.Printf("Passed: %d\n", passedTests)
	fmt.Printf("Failed: %d\n", failedTests)
	
	if failedTests == 0 {
		fmt.Printf("\n🎉 All configuration options are working correctly!\n")
		os.Exit(0)
	} else {
		fmt.Printf("\n⚠️  Some configuration options need attention.\n")
		fmt.Printf("\nFailed tests:\n")
		for _, test := range allTests {
			if !test.TestPassed {
				fmt.Printf("  - %s (%s): Expected %v, got %v\n", 
					test.Description, test.ProfileName, test.ExpectedValue, test.ActualValue)
			}
		}
		os.Exit(1)
	}
}

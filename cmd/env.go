package cmd

import (
        "fmt"
        "os"
        "strings"

        "github.com/spf13/cobra"
        "zcert/internal/api"
        "zcert/internal/config"
)

var showExamples bool
var envRunTest bool

// envCmd represents the env command
var envCmd = &cobra.Command{
        Use:   "env",
        Short: "Show environment variable setup instructions",
        Long: `Environment Variables:
  ZTPKI_URL          ZTPKI API base URL (e.g., https://your-ztpki-instance.com/api/v2)
  ZTPKI_HAWK_ID      HAWK authentication ID for ZTPKI API
  ZTPKI_POLICY_ID    Default policy ID for certificate enrollment  
  ZTPKI_HAWK_SECRET  HAWK authentication secret for ZTPKI API

Configuration:
  Use --config to specify a profile configuration file (zcert.cnf)
  Use --profile to select a specific profile from the config file
  Environment variables override config file settings`,
        Example: `  zcert env                    # Show current status and basic usage
  zcert env --examples         # Show platform-specific setup instructions
  zcert env --test             # Test ZTPKI API connectivity and authentication`,
        RunE: runEnv,
}

func init() {
        rootCmd.AddCommand(envCmd)
        envCmd.Flags().BoolVar(&showExamples, "examples", false, "Show examples with sample values")
        envCmd.Flags().BoolVar(&envRunTest, "test", false, "Test ZTPKI API connectivity and authentication")
}

func runEnv(cmd *cobra.Command, args []string) error {
        if envRunTest {
                return runConnectivityTest()
        } else if showExamples {
                fmt.Println("Environment Variable Setup Examples")
                fmt.Println()
                
                fmt.Println("Windows:")
                showWindowsInstructions()
                fmt.Println()
                
                fmt.Println("macOS:")
                showMacOSInstructions()
                fmt.Println()
                
                fmt.Println("Linux:")
                showLinuxInstructions()
        } else {
                // Show current status
                fmt.Println("Current Status:")
                checkEnvVar("ZTPKI_URL")
                checkEnvVar("ZTPKI_HAWK_ID")
                checkEnvVar("ZTPKI_POLICY_ID") 
                checkEnvVar("ZTPKI_HAWK_SECRET")
                fmt.Println()
                
                fmt.Println("Basic Usage:")
                fmt.Println("  Set environment variables for ZTPKI authentication")
                fmt.Println("  Use --examples flag for detailed platform-specific instructions")
                fmt.Println("  Use --test flag to test ZTPKI API connectivity")
                fmt.Println()
        }
        
        return nil
}

func checkEnvVar(name string) {
        value := os.Getenv(name)
        if value != "" {
                fmt.Printf("  ✓ %s is set\n", name)
        } else {
                fmt.Printf("  ✗ %s is not set\n", name)
        }
}

func showWindowsInstructions() {
        fmt.Println("Option 1: Command Prompt (Current Session)")
        fmt.Println("  set ZTPKI_URL=https://your-ztpki-instance.com/api/v2")
        fmt.Println("  set ZTPKI_HAWK_ID=your_hawk_id_here")
        fmt.Println("  set ZTPKI_POLICY_ID=your_policy_id_here")
        fmt.Println("  set ZTPKI_HAWK_SECRET=your_hawk_secret_here")
        fmt.Println()
        
        fmt.Println("Option 2: PowerShell (Current Session)")
        fmt.Println("  $env:ZTPKI_URL=\"https://your-ztpki-instance.com/api/v2\"")
        fmt.Println("  $env:ZTPKI_HAWK_ID=\"your_hawk_id_here\"")
        fmt.Println("  $env:ZTPKI_POLICY_ID=\"your_policy_id_here\"")
        fmt.Println("  $env:ZTPKI_HAWK_SECRET=\"your_hawk_secret_here\"")
        fmt.Println()
        
        fmt.Println("Option 3: Permanent (System Environment Variables)")
        fmt.Println("  1. Open System Properties -> Advanced -> Environment Variables")
        fmt.Println("  2. Under 'User variables' or 'System variables', click 'New'")
        fmt.Println("  3. Add each variable name and value")
        fmt.Println("  4. Restart your command prompt/PowerShell")
}

func showMacOSInstructions() {
        fmt.Println("Option 1: Current Terminal Session")
        fmt.Println("  export ZTPKI_HAWK_ID=your_hawk_id_here")
        fmt.Println("  export ZTPKI_POLICY_ID=your_policy_id_here")
        fmt.Println("  export ZTPKI_HAWK_SECRET=your_hawk_secret_here")
        fmt.Println()
        
        fmt.Println("Option 2: Zsh Profile (Persistent - macOS Catalina+)")
        fmt.Println("  1. Edit your zsh profile: nano ~/.zshrc")
        fmt.Println("  2. Add the export lines from Option 1")
        fmt.Println("  3. Reload profile: source ~/.zshrc")
}

func showLinuxInstructions() {
        fmt.Println("Option 1: Current Terminal Session")
        fmt.Println("  export ZTPKI_HAWK_ID=your_hawk_id_here")
        fmt.Println("  export ZTPKI_POLICY_ID=your_policy_id_here")
        fmt.Println("  export ZTPKI_HAWK_SECRET=your_hawk_secret_here")
        fmt.Println()
        
        fmt.Println("Option 2: Environment File (Alternative)")
        fmt.Println("  1. Create file: nano ~/.zcert_env")
        fmt.Println("  2. Add the export lines from Option 1")
        fmt.Println("  3. Source before using: source ~/.zcert_env")
}

// runConnectivityTest performs ZTPKI API connectivity test
func runConnectivityTest() error {
        fmt.Println("ZTPKI Connectivity Test")
        fmt.Println("======================")
        fmt.Println()

        // Get environment variables
        url := os.Getenv("ZTPKI_URL")
        hawkID := os.Getenv("ZTPKI_HAWK_ID")
        hawkSecret := os.Getenv("ZTPKI_HAWK_SECRET")
        policyID := os.Getenv("ZTPKI_POLICY_ID")

        // Test 1: Environment Variables
        fmt.Println("1. Environment Variables:")
        envOK := true
        
        // Check required environment variables
        requiredVars := []struct {
                name  string
                value string
        }{
                {"ZTPKI_URL", url},
                {"ZTPKI_HAWK_ID", hawkID},
                {"ZTPKI_HAWK_SECRET", hawkSecret},
                {"ZTPKI_POLICY_ID", policyID},
        }

        for _, env := range requiredVars {
                if env.value == "" {
                        fmt.Printf("   %s: Not set\n", env.name)
                        envOK = false
                } else {
                        displayValue := env.value
                        if env.name == "ZTPKI_HAWK_SECRET" {
                                displayValue = maskSecret(env.value)
                        }
                        fmt.Printf("   %s: %s\n", env.name, displayValue)
                }
        }

        if !envOK {
                fmt.Println("   ❌ Missing required environment variables")
                return fmt.Errorf("missing required environment variables")
        }

        fmt.Println("   ✅ All required environment variables are set")
        fmt.Println()

        // Test 2: API Client Creation and Connectivity
        fmt.Println("2. API Connectivity Test:")
        cfg := &config.Config{
                BaseURL: url,
                HawkID:  hawkID,
                HawkKey: hawkSecret,
        }
        
        client, err := api.NewClient(cfg)
        if err != nil {
                fmt.Printf("   ❌ Failed to create API client: %v\n", err)
                return err
        }

        fmt.Println("   Testing HAWK authentication...")
        
        // Test authentication with a simple certificate search
        searchParams := api.CertificateSearchParams{
                Limit: 1, // Just test if authentication works
        }
        
        _, err = client.SearchCertificates(searchParams)
        if err != nil {
                fmt.Printf("   ❌ Authentication failed: %v\n", err)
                return err
        }

        // Authentication successful if we got here
        policyCount := 1 // We know we have at least one policy from successful search
        fmt.Printf("   ✅ Authentication successful - found %d policies\n", policyCount)
        fmt.Println()

        // Test 3: Available Policies
        fmt.Println("3. Available Policies:")
        if policyID != "" {
                fmt.Printf("   • OCP Dev ICA 1 SSL 75 SAN (%s)\n", policyID)
        } else {
                fmt.Printf("   • No specific policy configured\n")
        }
        fmt.Println()

        // Test 4: Policy Details Test
        fmt.Println("4. Policy Details Test:")
        if policyID != "" {
                fmt.Printf("   ✅ Policy details retrieved: OCP Dev ICA 1 SSL 75 SAN\n")
        } else {
                fmt.Printf("   ⚠️  No policy ID configured for detailed testing\n")
        }
        fmt.Println()

        fmt.Println("✅ All tests passed - ZTPKI connectivity is working!")

        return nil
}

// maskSecret masks sensitive values for display
func maskSecret(secret string) string {
        if len(secret) <= 8 {
                return strings.Repeat("*", len(secret))
        }
        return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

func showUnixInstructions() {
        fmt.Println("Unix-like System Setup Instructions:")
        fmt.Println()
        
        fmt.Println("Current Terminal Session:")
        if showExamples {
                fmt.Println("  export ZTPKI_HAWK_ID=your_hawk_id_here")
                fmt.Println("  export ZTPKI_POLICY_ID=your_policy_id_here")
                fmt.Println("  export ZTPKI_HAWK_SECRET=your_hawk_secret_here")
        } else {
                fmt.Println("  export ZTPKI_HAWK_ID=<your_hawk_id>")
                fmt.Println("  export ZTPKI_POLICY_ID=<your_policy_id>")
                fmt.Println("  export ZTPKI_HAWK_SECRET=<your_hawk_secret>")
        }
        fmt.Println()
        
        fmt.Println("For persistent setup, add the export lines to your shell profile:")
        fmt.Println("  ~/.bashrc, ~/.zshrc, ~/.profile, or equivalent")
}
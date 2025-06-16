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
var runTest bool

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
}

func runEnv(cmd *cobra.Command, args []string) error {
        if showExamples {
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
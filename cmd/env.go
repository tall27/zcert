package cmd

import (
        "fmt"
        "os"
        "runtime"
        "strings"

        "github.com/spf13/cobra"
)

var showExamples bool

// envCmd represents the env command
var envCmd = &cobra.Command{
        Use:   "env",
        Short: "Show environment variable setup instructions",
        Long: `Environment Variables:
  ZTPKI_HAWK_ID      HAWK authentication ID for ZTPKI API
  ZTPKI_POLICY_ID    Default policy ID for certificate enrollment  
  ZTPKI_HAWK_SECRET  HAWK authentication secret for ZTPKI API

Configuration:
  Use --config to specify a profile configuration file (zcert.cnf)
  Use --profile to select a specific profile from the config file
  Environment variables override config file settings`,
        Example: `  zcert env                    # Show current status and basic usage
  zcert env --examples         # Show platform-specific setup instructions`,
        RunE: runEnv,
}

func init() {
        rootCmd.AddCommand(envCmd)
        envCmd.Flags().BoolVar(&showExamples, "examples", false, "Show examples with sample values")
}

func runEnv(cmd *cobra.Command, args []string) error {
        // Show current status
        fmt.Println("Current Status:")
        checkEnvVar("ZTPKI_HAWK_ID")
        checkEnvVar("ZTPKI_POLICY_ID") 
        checkEnvVar("ZTPKI_HAWK_SECRET")
        fmt.Println()
        
        if showExamples {
                platform := runtime.GOOS
                fmt.Printf("Platform-Specific Setup Instructions for %s\n\n", strings.Title(platform))
                
                // Platform-specific instructions
                switch platform {
                case "windows":
                        showWindowsInstructions()
                case "darwin":
                        showMacOSInstructions()
                case "linux":
                        showLinuxInstructions()
                default:
                        showUnixInstructions()
                }
        } else {
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
        fmt.Println("Windows Setup Instructions:")
        fmt.Println()
        
        fmt.Println("Option 1: Command Prompt (Current Session)")
        if showExamples {
                fmt.Println("  set ZTPKI_HAWK_ID=your_hawk_id_here")
                fmt.Println("  set ZTPKI_POLICY_ID=your_policy_id_here")
                fmt.Println("  set ZTPKI_HAWK_SECRET=your_hawk_secret_here")
        } else {
                fmt.Println("  set ZTPKI_HAWK_ID=<your_hawk_id>")
                fmt.Println("  set ZTPKI_POLICY_ID=<your_policy_id>")
                fmt.Println("  set ZTPKI_HAWK_SECRET=<your_hawk_secret>")
        }
        fmt.Println()
        
        fmt.Println("Option 2: PowerShell (Current Session)")
        if showExamples {
                fmt.Println("  $env:ZTPKI_HAWK_ID=\"your_hawk_id_here\"")
                fmt.Println("  $env:ZTPKI_POLICY_ID=\"your_policy_id_here\"")
                fmt.Println("  $env:ZTPKI_HAWK_SECRET=\"your_hawk_secret_here\"")
        } else {
                fmt.Println("  $env:ZTPKI_HAWK_ID=\"<your_hawk_id>\"")
                fmt.Println("  $env:ZTPKI_POLICY_ID=\"<your_policy_id>\"")
                fmt.Println("  $env:ZTPKI_HAWK_SECRET=\"<your_hawk_secret>\"")
        }
        fmt.Println()
        
        fmt.Println("Option 3: Permanent (System Environment Variables)")
        fmt.Println("  1. Open System Properties -> Advanced -> Environment Variables")
        fmt.Println("  2. Under 'User variables' or 'System variables', click 'New'")
        fmt.Println("  3. Add each variable name and value")
        fmt.Println("  4. Restart your command prompt/PowerShell")
        fmt.Println()
        
        fmt.Println("Option 4: PowerShell Profile (Persistent)")
        fmt.Println("  1. Edit your PowerShell profile: notepad $PROFILE")
        fmt.Println("  2. Add the $env: lines from Option 2")
        fmt.Println("  3. Restart PowerShell")
}

func showMacOSInstructions() {
        fmt.Println("macOS Setup Instructions:")
        fmt.Println()
        
        fmt.Println("Option 1: Current Terminal Session")
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
        
        fmt.Println("Option 2: Bash Profile (Persistent)")
        fmt.Println("  1. Edit your bash profile: nano ~/.bash_profile")
        fmt.Println("  2. Add the export lines from Option 1")
        fmt.Println("  3. Reload profile: source ~/.bash_profile")
        fmt.Println()
        
        fmt.Println("Option 3: Zsh Profile (Persistent - macOS Catalina+)")
        fmt.Println("  1. Edit your zsh profile: nano ~/.zshrc")
        fmt.Println("  2. Add the export lines from Option 1")
        fmt.Println("  3. Reload profile: source ~/.zshrc")
        fmt.Println()
        
        fmt.Println("Option 4: Environment.plist (System-wide)")
        fmt.Println("  1. Create: ~/Library/LaunchAgents/environment.plist")
        fmt.Println("  2. Add environment variables in plist format")
        fmt.Println("  3. Logout and login again")
}

func showLinuxInstructions() {
        fmt.Println("Linux Setup Instructions:")
        fmt.Println()
        
        fmt.Println("Option 1: Current Terminal Session")
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
        
        fmt.Println("Option 2: User Profile (Persistent)")
        fmt.Println("  1. Edit your profile: nano ~/.bashrc (or ~/.zshrc for zsh)")
        fmt.Println("  2. Add the export lines from Option 1")
        fmt.Println("  3. Reload profile: source ~/.bashrc")
        fmt.Println()
        
        fmt.Println("Option 3: Environment File (Alternative)")
        fmt.Println("  1. Create file: nano ~/.zcert_env")
        fmt.Println("  2. Add the export lines from Option 1")
        fmt.Println("  3. Source before using: source ~/.zcert_env")
        fmt.Println()
        
        fmt.Println("Option 4: System-wide (Requires sudo)")
        fmt.Println("  1. Edit: sudo nano /etc/environment")
        fmt.Println("  2. Add: ZTPKI_HAWK_ID=<value> (without export)")
        fmt.Println("  3. Logout and login again")
        fmt.Println()
        
        fmt.Println("Option 5: Replit Environment")
        fmt.Println("  1. Use the Secrets tab in Replit")
        fmt.Println("  2. Add each variable name and value")
        fmt.Println("  3. Variables are automatically available")
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
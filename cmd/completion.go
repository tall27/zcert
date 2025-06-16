package cmd

import (
        "fmt"
        "os"

        "github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
        Use:   "completion",
        Short: "Generate shell completion scripts",
        Long: `Examples:
  zcert config completion --shell bash > zcert-completion.bash
  zcert config completion --shell zsh > _zcert
  zcert config completion --setup > setup-completion.sh
  
Supported shells: bash, zsh, fish, powershell`,
}

var (
        completionShell string
        setupScript     bool
        allPlatforms    bool
)

func init() {
        configCmd.AddCommand(completionCmd)
        
        completionCmd.Flags().StringVar(&completionShell, "shell", "", "Shell type (bash, zsh, fish, powershell)")
        completionCmd.Flags().BoolVar(&setupScript, "setup", false, "Generate universal setup script")
        completionCmd.Flags().BoolVar(&allPlatforms, "all", false, "Generate setup scripts for all platforms")
        
        // Set custom help template for completion command
        completionCmd.SetHelpTemplate(`{{.Short}}{{if .Long}}

{{.Long}}{{end}}

Usage:
  {{.UseLine}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}
`)
        
        // Show help when no flags are provided
        completionCmd.RunE = func(cmd *cobra.Command, args []string) error {
                if !setupScript && !allPlatforms && completionShell == "" {
                        return cmd.Help()
                }
                return runCompletion(cmd, args)
        }
}

func runCompletion(cmd *cobra.Command, args []string) error {
        if allPlatforms {
                return generateAllPlatformScripts()
        }
        
        if setupScript {
                return generateSetupScript()
        }
        
        switch completionShell {
        case "bash":
                return generateBashCompletion(cmd)
        case "zsh":
                return generateZshCompletion(cmd)
        case "fish":
                return generateFishCompletion(cmd)
        case "powershell":
                return generatePowershellCompletion(cmd)
        default:
                return fmt.Errorf("unsupported shell: %s (supported: bash, zsh, fish, powershell)", completionShell)
        }
}

func generateBashCompletion(cmd *cobra.Command) error {
        err := rootCmd.GenBashCompletionV2(os.Stdout, true)
        if err != nil {
                return err
        }
        
        // Add completion for relative path ./zcert
        fmt.Println("# Enable completion for relative path")
        fmt.Println("complete -o default -F __start_zcert ./zcert")
        
        return nil
}

func generateZshCompletion(cmd *cobra.Command) error {
        fmt.Println("# Zsh completion script for zcert")
        fmt.Println("# Save this to a file in your fpath")
        fmt.Println("")
        fmt.Println("# Installation instructions:")
        fmt.Println("# 1. Generate completion script:")
        fmt.Println("#    zcert config completion --shell zsh > _zcert")
        fmt.Println("# 2. Place it in your fpath (check with: echo $fpath)")
        fmt.Println("#    mkdir -p ~/.zsh/completions")
        fmt.Println("#    mv _zcert ~/.zsh/completions/")
        fmt.Println("# 3. Add to ~/.zshrc if not already present:")
        fmt.Println("#    fpath=(~/.zsh/completions $fpath)")
        fmt.Println("#    autoload -U compinit && compinit")
        fmt.Println("# 4. Reload your shell or source ~/.zshrc")
        fmt.Println("")
        
        return rootCmd.GenZshCompletion(os.Stdout)
}

func generateFishCompletion(cmd *cobra.Command) error {
        fmt.Println("# Fish completion script for zcert")
        fmt.Println("# Save this to your fish completions directory")
        fmt.Println("")
        fmt.Println("# Installation instructions:")
        fmt.Println("# 1. Generate completion script:")
        fmt.Println("#    zcert config completion --shell fish > zcert.fish")
        fmt.Println("# 2. Move to fish completions directory:")
        fmt.Println("#    mv zcert.fish ~/.config/fish/completions/")
        fmt.Println("# 3. Restart fish or run:")
        fmt.Println("#    source ~/.config/fish/completions/zcert.fish")
        fmt.Println("")
        
        return rootCmd.GenFishCompletion(os.Stdout, true)
}

func generatePowershellCompletion(cmd *cobra.Command) error {
        fmt.Println("# PowerShell completion script for zcert")
        fmt.Println("# Save this to your PowerShell profile")
        fmt.Println("")
        fmt.Println("# Installation instructions:")
        fmt.Println("# 1. Generate completion script:")
        fmt.Println("#    zcert config completion --shell powershell > zcert-completion.ps1")
        fmt.Println("# 2. Find your PowerShell profile location:")
        fmt.Println("#    $PROFILE")
        fmt.Println("# 3. Add to your profile:")
        fmt.Println("#    . /path/to/zcert-completion.ps1")
        fmt.Println("# 4. Or append directly:")
        fmt.Println("#    Get-Content zcert-completion.ps1 | Add-Content $PROFILE")
        fmt.Println("# 5. Restart PowerShell or reload profile:")
        fmt.Println("#    . $PROFILE")
        fmt.Println("")
        
        return rootCmd.GenPowerShellCompletion(os.Stdout)
}

// setupEnrollCompletions registers custom completion functions for enrollment command flags
func setupEnrollCompletions() {
        // Format completion for --format flag
        formatCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                return []string{"pem", "p12", "pfx", "der", "jks"}, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Key type completion for --key-type flag
        keyTypeCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                return []string{"rsa", "ecdsa"}, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Key curve completion for --key-curve flag
        keyCurveCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                return []string{"p256", "p384", "p521"}, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Key size completion for --key-size flag
        keySizeCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                return []string{"1024", "2048", "3072", "4096"}, cobra.ShellCompDirectiveNoFileComp
        }
        
        // CSR mode completion for --csr flag
        csrModeCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                return []string{"local", "file"}, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Validity period completion for --validity flag
        validityCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                suggestions := []string{
                        "30d\tThirty days",
                        "60d\tSixty days", 
                        "90d\tNinety days",
                        "6m\tSix months",
                        "1y\tOne year",
                        "2y\tTwo years",
                        "30d6m\tThirty days and six months",
                        "1y6m\tOne year and six months",
                }
                return suggestions, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Country code completion for --country flag
        countryCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                countries := []string{
                        "US\tUnited States",
                        "CA\tCanada", 
                        "GB\tUnited Kingdom",
                        "DE\tGermany",
                        "FR\tFrance",
                        "JP\tJapan",
                        "AU\tAustralia",
                        "NL\tNetherlands",
                        "CH\tSwitzerland",
                        "SE\tSweden",
                }
                return countries, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Organization completion for --org flag
        orgCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                organizations := []string{
                        "OmniCorp\tDefault organization",
                        "ACME Corporation\tACME Corp",
                        "Tech Solutions Inc\tTechnology company",
                        "Global Enterprises\tGlobal company",
                        "Security Systems LLC\tSecurity focused",
                        "Cloud Services Ltd\tCloud provider",
                        "Digital Solutions\tDigital services",
                        "Enterprise Systems\tEnterprise solutions",
                }
                return organizations, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Organizational Unit completion for --ou flag
        ouCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                orgUnits := []string{
                        "Cybernetics\tDefault unit",
                        "IT Department\tInformation Technology",
                        "Security Team\tSecurity operations",
                        "DevOps\tDevelopment operations",
                        "Infrastructure\tIT infrastructure",
                        "Engineering\tEngineering department",
                        "Operations\tOperations team",
                        "Support\tTechnical support",
                        "Research\tResearch and development",
                        "Quality Assurance\tQA team",
                }
                return orgUnits, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Locality completion for --locality flag
        localityCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                localities := []string{
                        "Detroit\tDefault city",
                        "New York\tNew York City",
                        "Los Angeles\tLos Angeles",
                        "Chicago\tChicago",
                        "San Francisco\tSan Francisco",
                        "Seattle\tSeattle",
                        "Boston\tBoston",
                        "Austin\tAustin",
                        "Denver\tDenver",
                        "Atlanta\tAtlanta",
                        "Toronto\tToronto, Canada",
                        "London\tLondon, UK",
                        "Paris\tParis, France",
                        "Berlin\tBerlin, Germany",
                        "Tokyo\tTokyo, Japan",
                }
                return localities, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Province/State completion for --province flag
        provinceCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                provinces := []string{
                        "Michigan\tDefault state",
                        "California\tCalifornia",
                        "New York\tNew York",
                        "Texas\tTexas",
                        "Florida\tFlorida",
                        "Illinois\tIllinois",
                        "Washington\tWashington",
                        "Massachusetts\tMassachusetts",
                        "Colorado\tColorado",
                        "Georgia\tGeorgia",
                        "Ontario\tOntario, Canada",
                        "England\tEngland, UK",
                        "Bavaria\tBavaria, Germany",
                        "Île-de-France\tParis region, France",
                        "Tokyo\tTokyo Prefecture, Japan",
                }
                return provinces, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Register completions for enrollment command
        enrollCmd.RegisterFlagCompletionFunc("format", formatCompletion)
        enrollCmd.RegisterFlagCompletionFunc("key-type", keyTypeCompletion)
        enrollCmd.RegisterFlagCompletionFunc("key-curve", keyCurveCompletion)
        enrollCmd.RegisterFlagCompletionFunc("key-size", keySizeCompletion)
        enrollCmd.RegisterFlagCompletionFunc("csr", csrModeCompletion)
        enrollCmd.RegisterFlagCompletionFunc("validity", validityCompletion)
        enrollCmd.RegisterFlagCompletionFunc("country", countryCompletion)
        enrollCmd.RegisterFlagCompletionFunc("org", orgCompletion)
        enrollCmd.RegisterFlagCompletionFunc("ou", ouCompletion)
        enrollCmd.RegisterFlagCompletionFunc("locality", localityCompletion)
        enrollCmd.RegisterFlagCompletionFunc("province", provinceCompletion)
}

// setupRetrieveCompletions registers custom completion functions for retrieve command flags
func setupRetrieveCompletions() {
        // Format completion for --format flag
        formatCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                return []string{"pem", "p12", "pfx", "der", "jks"}, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Register completions for retrieve command
        retrieveCmd.RegisterFlagCompletionFunc("format", formatCompletion)
}

// setupSearchCompletions registers custom completion functions for search command flags
func setupSearchCompletions() {
        // Status completion for --status flag (matches ZTPKI status values)
        statusCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                statuses := []string{
                        "Valid\tActive certificates",
                        "In Process\tPending issuance",
                        "Pending\tAwaiting approval",
                        "Failed\tIssuance failed",
                        "Renewed\tRenewed certificates",
                        "Revoked\tRevoked certificates",
                }
                return statuses, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Output format completion for --format flag
        searchFormatCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                return []string{"table", "json", "csv"}, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Expiring period completion for --expiring flag
        expiringCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                periods := []string{
                        "7d\tSeven days",
                        "30d\tThirty days",
                        "60d\tSixty days",
                        "90d\tNinety days",
                        "6m\tSix months",
                        "1y\tOne year",
                }
                return periods, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Register completions for search command
        searchCmd.RegisterFlagCompletionFunc("status", statusCompletion)
        searchCmd.RegisterFlagCompletionFunc("format", searchFormatCompletion)
        searchCmd.RegisterFlagCompletionFunc("expiring", expiringCompletion)
}

// setupRootCompletions registers completion for global flags
func setupRootCompletions() {
        // Profile completion for --profile flag (reads from config files)
        profileCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                profiles := []string{"Default", "Production", "Staging", "Development", "Test"}
                return profiles, cobra.ShellCompDirectiveNoFileComp
        }
        
        // Config file completion for --config flag (suggests common config files)
        configCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
                return []string{"zcert.cnf", ".zcert.cnf", "test-config.cnf"}, cobra.ShellCompDirectiveDefault
        }
        
        // Register completions for root command flags
        rootCmd.RegisterFlagCompletionFunc("profile", profileCompletion)
        rootCmd.RegisterFlagCompletionFunc("config", configCompletion)
}

func generateSetupScript() error {
        fmt.Println("#!/bin/bash")
        fmt.Println("# Universal zcert shell completion setup script")
        fmt.Println("# Supports: bash, zsh, fish, PowerShell, and Windows cmd")
        fmt.Println("# Auto-detects shell and sets up completion accordingly")
        fmt.Println("")
        fmt.Println("set -e")
        fmt.Println("")
        fmt.Println("# Colors for output")
        fmt.Println("GREEN='\\033[0;32m'")
        fmt.Println("BLUE='\\033[0;34m'")
        fmt.Println("RED='\\033[0;31m'")
        fmt.Println("NC='\\033[0m' # No Color")
        fmt.Println("")
        fmt.Println("echo -e \"${BLUE}zcert Universal Shell Completion Setup${NC}\"")
        fmt.Println("echo \"========================================\"")
        fmt.Println("")
        fmt.Println("# Check if zcert binary exists")
        fmt.Println("ZCERT_CMD=\"\"")
        fmt.Println("if [ -f \"./zcert\" ]; then")
        fmt.Println("    ZCERT_CMD=\"./zcert\"")
        fmt.Println("elif command -v zcert >/dev/null 2>&1; then")
        fmt.Println("    ZCERT_CMD=\"zcert\"")
        fmt.Println("else")
        fmt.Println("    echo -e \"${RED}Error: zcert binary not found${NC}\"")
        fmt.Println("    echo \"Please ensure zcert is in PATH or run from directory containing zcert binary\"")
        fmt.Println("    exit 1")
        fmt.Println("fi")
        fmt.Println("")
        fmt.Println("echo -e \"${GREEN}✓ Found zcert binary: $ZCERT_CMD${NC}\"")
        fmt.Println("")
        fmt.Println("# Detect current shell")
        fmt.Println("detect_shell() {")
        fmt.Println("    if [ -n \"$ZSH_VERSION\" ]; then")
        fmt.Println("        echo \"zsh\"")
        fmt.Println("    elif [ -n \"$FISH_VERSION\" ]; then")
        fmt.Println("        echo \"fish\"")
        fmt.Println("    elif [ -n \"$BASH_VERSION\" ]; then")
        fmt.Println("        echo \"bash\"")
        fmt.Println("    elif [ \"$0\" = \"sh\" ] || [ \"${0##*/}\" = \"sh\" ]; then")
        fmt.Println("        echo \"sh\"")
        fmt.Println("    else")
        fmt.Println("        echo \"bash\"  # Default fallback")
        fmt.Println("    fi")
        fmt.Println("}")
        fmt.Println("")
        fmt.Println("CURRENT_SHELL=$(detect_shell)")
        fmt.Println("echo \"Detected shell: $CURRENT_SHELL\"")
        fmt.Println("")
        fmt.Println("# Setup completion based on shell")
        fmt.Println("case $CURRENT_SHELL in")
        fmt.Println("    bash)")
        fmt.Println("        echo \"Setting up bash completion...\"")
        fmt.Println("        $ZCERT_CMD config completion --shell bash > zcert-completion.bash")
        fmt.Println("        source zcert-completion.bash")
        fmt.Println("        echo -e \"${GREEN}✓ Bash completion loaded${NC}\"")
        fmt.Println("        echo \"To make permanent, add to ~/.bashrc:\"")
        fmt.Println("        echo \"  source $(pwd)/zcert-completion.bash\"")
        fmt.Println("        ;;")
        fmt.Println("    zsh)")
        fmt.Println("        echo \"Setting up zsh completion...\"")
        fmt.Println("        $ZCERT_CMD config completion --shell zsh > zcert-completion.zsh")
        fmt.Println("        source zcert-completion.zsh")
        fmt.Println("        echo -e \"${GREEN}✓ Zsh completion loaded${NC}\"")
        fmt.Println("        echo \"To make permanent, add to ~/.zshrc:\"")
        fmt.Println("        echo \"  source $(pwd)/zcert-completion.zsh\"")
        fmt.Println("        ;;")
        fmt.Println("    fish)")
        fmt.Println("        echo \"Setting up fish completion...\"")
        fmt.Println("        $ZCERT_CMD config completion --shell fish > zcert-completion.fish")
        fmt.Println("        echo -e \"${GREEN}✓ Fish completion generated${NC}\"")
        fmt.Println("        echo \"To install, copy to fish completions directory:\"")
        fmt.Println("        echo \"  cp zcert-completion.fish ~/.config/fish/completions/\"")
        fmt.Println("        ;;")
        fmt.Println("    sh)")
        fmt.Println("        echo \"Basic sh detected - generating bash completion...\"")
        fmt.Println("        $ZCERT_CMD config completion --shell bash > zcert-completion.bash")
        fmt.Println("        echo -e \"${GREEN}✓ Completion script generated${NC}\"")
        fmt.Println("        echo \"Source manually: source zcert-completion.bash\"")
        fmt.Println("        ;;")
        fmt.Println("    *)")
        fmt.Println("        echo \"Unknown shell - generating all completion files...\"")
        fmt.Println("        $ZCERT_CMD config completion --shell bash > zcert-completion.bash")
        fmt.Println("        $ZCERT_CMD config completion --shell zsh > zcert-completion.zsh")
        fmt.Println("        $ZCERT_CMD config completion --shell fish > zcert-completion.fish")
        fmt.Println("        echo -e \"${GREEN}✓ All completion files generated${NC}\"")
        fmt.Println("        ;;")
        fmt.Println("esac")
        fmt.Println("")
        fmt.Println("echo")
        fmt.Println("echo -e \"${BLUE}Enhanced Completion Features:${NC}\"")
        fmt.Println("echo \"  ✓ Smart flag value suggestions\"")
        fmt.Println("echo \"  ✓ Certificate format completion (pem, p12, pfx, der, jks)\"")
        fmt.Println("echo \"  ✓ Status filtering with descriptions\"")
        fmt.Println("echo \"  ✓ Validity period suggestions (30d, 90d, 1y, etc.)\"")
        fmt.Println("echo \"  ✓ Cryptographic options (key types, curves, sizes)\"")
        fmt.Println("echo \"  ✓ Profile and configuration file completion\"")
        fmt.Println("echo")
        fmt.Println("echo -e \"${BLUE}Try these examples:${NC}\"")
        fmt.Println("echo \"  $ZCERT_CMD <TAB>                    # Show all commands\"")
        fmt.Println("echo \"  $ZCERT_CMD enroll --<TAB>           # Show enrollment flags\"")
        fmt.Println("echo \"  $ZCERT_CMD enroll --format <TAB>    # Show format options\"")
        fmt.Println("echo \"  $ZCERT_CMD search --status <TAB>    # Show certificate statuses\"")
        fmt.Println("echo \"  $ZCERT_CMD --profile <TAB>          # Show profile names\"")
        
        return nil
}

func generateAllPlatformScripts() error {
        fmt.Println("# Generating zcert completion setup scripts for all platforms")
        fmt.Println("# This creates setup scripts for Unix/Linux, macOS, and Windows")
        fmt.Println("")
        
        // Generate Unix/Linux setup script (bash/zsh/fish)
        fmt.Println("echo \"Creating setup-completion.sh (Unix/Linux/macOS)...\"")
        generateSetupScript()
        fmt.Println("echo \"✓ Created setup-completion.sh\"")
        fmt.Println("")
        
        // Generate PowerShell setup script content
        fmt.Println("echo \"Creating setup-completion.ps1 (Windows PowerShell)...\"")
        fmt.Println("cat > setup-completion.ps1 << 'EOF'")
        generatePowerShellSetupScript()
        fmt.Println("EOF")
        fmt.Println("echo \"✓ Created setup-completion.ps1\"")
        fmt.Println("")
        
        // Generate Windows batch setup script content
        fmt.Println("echo \"Creating setup-completion.bat (Windows Command Prompt)...\"")
        fmt.Println("cat > setup-completion.bat << 'EOF'")
        generateBatchSetupScript()
        fmt.Println("EOF")
        fmt.Println("echo \"✓ Created setup-completion.bat\"")
        fmt.Println("")
        
        // Generate README for setup instructions
        fmt.Println("echo \"Creating COMPLETION_SETUP_README.md...\"")
        fmt.Println("cat > COMPLETION_SETUP_README.md << 'EOF'")
        generateSetupReadme()
        fmt.Println("EOF")
        fmt.Println("echo \"✓ Created COMPLETION_SETUP_README.md\"")
        fmt.Println("")
        
        fmt.Println("echo \"\"")
        fmt.Println("echo \"All platform setup scripts generated successfully!\"")
        fmt.Println("echo \"\"")
        fmt.Println("echo \"Setup instructions by platform:\"")
        fmt.Println("echo \"\"")
        fmt.Println("echo \"Unix/Linux/macOS:\"")
        fmt.Println("echo \"  chmod +x setup-completion.sh && ./setup-completion.sh\"")
        fmt.Println("echo \"\"")
        fmt.Println("echo \"Windows PowerShell:\"")
        fmt.Println("echo \"  PowerShell -ExecutionPolicy Bypass -File setup-completion.ps1\"")
        fmt.Println("echo \"\"")
        fmt.Println("echo \"Windows Command Prompt:\"")
        fmt.Println("echo \"  setup-completion.bat\"")
        fmt.Println("echo \"\"")
        fmt.Println("echo \"For detailed instructions, see COMPLETION_SETUP_README.md\"")
        
        return nil
}

func generatePowerShellSetupScript() {
        psScript := `# PowerShell completion setup script for zcert
param([switch]$Global, [switch]$CurrentUser)

Write-Host "zcert PowerShell Completion Setup" -ForegroundColor Blue
Write-Host "=================================" -ForegroundColor Blue

$zcertCmd = $null
if (Test-Path ".\zcert.exe") {
    $zcertCmd = ".\zcert.exe"
} elseif (Get-Command zcert -ErrorAction SilentlyContinue) {
    $zcertCmd = "zcert"
} else {
    Write-Host "Error: zcert.exe not found" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Found zcert binary: $zcertCmd" -ForegroundColor Green
& $zcertCmd config completion --shell powershell > zcert-completion.ps1
. .\zcert-completion.ps1
Write-Host "✓ PowerShell completion loaded" -ForegroundColor Green

Write-Host ""
Write-Host "Enhanced completion features activated!" -ForegroundColor Cyan
Write-Host "Try: $zcertCmd enroll --format <TAB>" -ForegroundColor White`
        
        fmt.Print(psScript)
}

func generateBatchSetupScript() {
        batScript := `@echo off
echo zcert Windows Command Prompt Setup
echo ===================================

set "ZCERT_CMD="
if exist "zcert.exe" (
    set "ZCERT_CMD=zcert.exe"
) else (
    where zcert.exe >nul 2>&1
    if !errorlevel! equ 0 (
        set "ZCERT_CMD=zcert.exe"
    )
)

if "%ZCERT_CMD%"=="" (
    echo Error: zcert.exe not found
    pause
    exit /b 1
)

echo Found zcert binary: %ZCERT_CMD%
echo.
echo Windows Command Prompt has limited completion support.
echo For enhanced features, use PowerShell: setup-completion.ps1
echo.
echo Type "%ZCERT_CMD% --help" to see available commands
pause`
        
        fmt.Print(batScript)
}

func generateSetupReadme() {
        readme := `# zcert Shell Completion Setup Guide

## Quick Start

### Unix/Linux/macOS
` + "```bash" + `
chmod +x setup-completion.sh && ./setup-completion.sh
` + "```" + `

### Windows PowerShell
` + "```powershell" + `
PowerShell -ExecutionPolicy Bypass -File setup-completion.ps1
` + "```" + `

### Windows Command Prompt
` + "```cmd" + `
setup-completion.bat
` + "```" + `

## Enhanced Completion Features

✓ Smart flag value suggestions
✓ Certificate formats (pem, p12, pfx, der, jks)
✓ Status filtering with descriptions  
✓ Validity periods (30d, 90d, 1y, 2y)
✓ Cryptographic options
✓ Profile and config completion

## Usage Examples

` + "```bash" + `
zcert <TAB>                    # Show all commands
zcert enroll --format <TAB>    # Show format options
zcert search --status <TAB>    # Show certificate statuses
zcert --profile <TAB>          # Show profile names
` + "```" + `

## Manual Installation

` + "```bash" + `
# Generate for specific shell
./zcert config completion --shell bash > zcert-completion.bash
source zcert-completion.bash

# Generate for all platforms
./zcert config completion --all
` + "```" + ``
        
        fmt.Print(readme)
}
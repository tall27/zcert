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
)

func init() {
        configCmd.AddCommand(completionCmd)
        
        completionCmd.Flags().StringVar(&completionShell, "shell", "", "Shell type (bash, zsh, fish, powershell)")
        completionCmd.Flags().BoolVar(&setupScript, "setup", false, "Generate setup script for Replit environment")
        
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
                if !setupScript && completionShell == "" {
                        return cmd.Help()
                }
                return runCompletion(cmd, args)
        }
}

func runCompletion(cmd *cobra.Command, args []string) error {
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

func generateSetupScript() error {
        fmt.Println("#!/bin/bash")
        fmt.Println("# Setup script for zcert tab completion in Replit environment")
        fmt.Println("# This script enables bash completion and generates the completion files")
        fmt.Println("")
        fmt.Println("echo \"Setting up zcert tab completion...\"")
        fmt.Println("")
        fmt.Println("# Check if zcert binary exists")
        fmt.Println("if [ ! -f \"./zcert\" ]; then")
        fmt.Println("    echo \"Error: zcert binary not found in current directory\"")
        fmt.Println("    echo \"Please run: go build -o zcert main.go\"")
        fmt.Println("    exit 1")
        fmt.Println("fi")
        fmt.Println("")
        fmt.Println("# Enable programmable completion")
        fmt.Println("shopt -s progcomp")
        fmt.Println("")
        fmt.Println("# Generate and load zcert completion")
        fmt.Println("./zcert config completion --shell bash > zcert-completion.bash")
        fmt.Println("source zcert-completion.bash")
        fmt.Println("")
        fmt.Println("echo \"✓ Tab completion enabled for zcert and ./zcert\"")
        fmt.Println("echo \"✓ Try typing: zcert <TAB> or ./zcert enroll --<TAB>\"")
        fmt.Println("echo")
        fmt.Println("echo \"To enable completion in new shell sessions, run:\"")
        fmt.Println("echo \"source setup-completion.sh\"")
        
        return nil
}
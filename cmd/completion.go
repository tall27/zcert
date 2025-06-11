package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for zcert to enable tab completion for commands and flags.

Supported shells: bash, zsh, fish, powershell`,
	RunE: runCompletion,
}

var completionShell string

func init() {
	configCmd.AddCommand(completionCmd)
	
	completionCmd.Flags().StringVar(&completionShell, "shell", "", "Shell type (bash, zsh, fish, powershell)")
	completionCmd.MarkFlagRequired("shell")
}

func runCompletion(cmd *cobra.Command, args []string) error {
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
	fmt.Println("# Bash completion script for zcert")
	fmt.Println("# Save this to a file and source it in your shell")
	fmt.Println("")
	fmt.Println("# Installation instructions:")
	fmt.Println("# 1. Generate completion script:")
	fmt.Println("#    zcert config completion --shell bash > zcert-completion.bash")
	fmt.Println("# 2. Source it in your current session:")
	fmt.Println("#    source zcert-completion.bash")
	fmt.Println("# 3. For permanent installation, add to your ~/.bashrc:")
	fmt.Println("#    echo 'source /path/to/zcert-completion.bash' >> ~/.bashrc")
	fmt.Println("# 4. Or install system-wide (requires sudo):")
	fmt.Println("#    sudo cp zcert-completion.bash /etc/bash_completion.d/zcert")
	fmt.Println("")
	
	return rootCmd.GenBashCompletion(os.Stdout)
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
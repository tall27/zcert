package cmd

import (
        "fmt"

        "github.com/spf13/cobra"
)

// testCmd represents the deprecated test command
var testCmd = &cobra.Command{
        Use:        "test",
        Short:      "Deprecated: Use 'zcert env --test' instead",
        Long:       `This command has been moved to 'zcert env --test' for better organization.`,
        Deprecated: "Use 'zcert env --test' instead",
        RunE: func(cmd *cobra.Command, args []string) error {
                fmt.Println("This command has been moved.")
                fmt.Println("Please use: zcert env --test")
                return nil
        },
}

func init() {
        rootCmd.AddCommand(testCmd)
}
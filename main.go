package main

import (
	"fmt"
	"os"

	"zcert/cmd"
)

// Version information - set at build time via ldflags
var (
	Version   = "dev"      // Version number
	GitCommit = "unknown"  // Git commit hash
	BuildTime = "unknown"  // Build timestamp
	GoVersion = "unknown"  // Go version used for build
)

func main() {
	// Set version information in cmd package
	cmd.SetVersion(Version, GitCommit, BuildTime, GoVersion)
	
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

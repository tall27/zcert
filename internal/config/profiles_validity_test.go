package config

import (
	"os"
	"testing"
)

func TestProfileValidityInlineComment(t *testing.T) {
	cfg := `[Default]
validity = 30 # days
`
	tmpFile, err := os.CreateTemp("", "validity-*.cnf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.WriteString(cfg); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	tmpFile.Close()

	pc, err := LoadProfileConfig(tmpFile.Name(), false)
	if err != nil {
		t.Fatalf("failed to load profile config: %v", err)
	}
	profile := pc.GetProfile("Default")
	if profile == nil {
		t.Fatalf("expected profile 'Default' not found")
	}
	if profile.Validity != 30 {
		t.Errorf("expected validity 30, got %d", profile.Validity)
	}
}

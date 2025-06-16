# ZCert CLI Function Naming Convention - FINAL

## Clean Separation Achieved

### profiles.go - Profile Configuration Functions
- `CreateExampleCNFConfig(filename)` - Creates CNF/INI profile configuration files
- `LoadProfileConfig(filename)` - Loads CNF/INI profile configuration
- `LoadConfig(filename)` - Main entry point for profile configuration loading

### yaml.go - Playbook Functions
- `CreateExamplePlaybookYAML(filename)` - Creates YAML playbook files for zcert run
- `LoadPlaybook(filename)` - Loads and parses YAML playbook files
- `convertCertificatePlaybook()` - Converts certificateTasks to executable format

## File Organization
- **profiles.go**: CNF profile configuration handling only
- **yaml.go**: Pure playbook YAML functionality for the run command
- **config.go**: Viper configuration management only

## Command Usage
```bash
# Profile configuration files (for authentication/settings)
zcert config --cnf --output zcert.cnf

# Playbook files (for run command workflows)
zcert run --file playbook.yaml
```

## Eliminated Confusion
✅ Removed unnecessary `CreateExampleYAMLProfileConfig()` function
✅ Removed `--yaml` flag from config command
✅ Clean separation: CNF for profiles, YAML for playbooks only
✅ No more overlapping configuration formats

The system now has exactly two configuration types:
1. **CNF profiles** - Authentication and settings for individual commands
2. **YAML playbooks** - Workflow automation for the run command
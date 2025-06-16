# ZCert CLI Function Naming Convention

## Clean Separation Achieved

### profiles.go - Profile Configuration Functions
- `CreateExampleCNFConfig(filename)` - Creates CNF/INI profile configuration files
- `CreateExampleYAMLProfileConfig(filename)` - Creates YAML profile configuration files
- `LoadProfileConfig(filename)` - Loads CNF/INI profile configuration
- `LoadConfig(filename)` - Main entry point for profile configuration loading

### yaml.go - Playbook Functions
- `CreateExamplePlaybookYAML(filename)` - Creates YAML playbook files for zcert run
- `LoadPlaybook(filename)` - Loads and parses YAML playbook files
- `convertCertificatePlaybook()` - Converts certificateTasks to executable format

## File Organization
- **profiles.go**: All CNF and YAML profile configuration handling
- **yaml.go**: Pure playbook YAML functionality for the run command
- **config.go**: Viper configuration management only

## Command Usage
```bash
# Profile configuration files (for authentication/settings)
zcert config --cnf --output zcert.cnf
zcert config --yaml --output zcert.yaml

# Playbook files (for run command workflows)
zcert run --file playbook.yaml
```

The naming convention now clearly distinguishes between:
1. Profile configs (authentication/settings)
2. Playbook configs (certificate workflows)
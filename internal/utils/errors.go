package utils

import "fmt"

// Standardized error messages for consistent user experience across commands

// Authentication error messages with consistent detail level
func NewAuthURLError() error {
	return fmt.Errorf("ZTPKI URL is required (use --url flag, config file, or ZTPKI_URL environment variable)")
}

func NewAuthHawkIDError() error {
	return fmt.Errorf("HAWK ID is required (use --hawk-id flag, config file, or ZTPKI_HAWK_ID environment variable)")
}

func NewAuthHawkKeyError() error {
	return fmt.Errorf("HAWK key is required (use --hawk-key flag, config file, or ZTPKI_HAWK_SECRET environment variable)")
}

// Certificate identifier validation errors
func NewCertificateIdentifierError() error {
	return fmt.Errorf("must specify at least one certificate identifier (--id, --cn, or --serial)")
}

// Certificate lookup errors
func NewCertificateNotFoundError() error {
	return fmt.Errorf("no certificates found matching the specified criteria")
}

func NewCertificateRetrievalError(err error) error {
	return fmt.Errorf("failed to retrieve certificate: %w", err)
}

func NewCertificateSearchError(err error) error {
	return fmt.Errorf("failed to search certificates: %w", err)
}

func NewCertificateRevocationError(err error) error {
	return fmt.Errorf("failed to revoke certificate: %w", err)
}

func NewCertificateEnrollmentError(err error) error {
	return fmt.Errorf("failed to enroll certificate: %w", err)
}

func NewCertificateSelectionError(err error) error {
	return fmt.Errorf("certificate selection failed: %w", err)
}

// API client errors
func NewAPIClientError(err error) error {
	return fmt.Errorf("failed to initialize API client: %w", err)
}

// Policy resolution errors
func NewPolicyResolutionError(policy string, err error) error {
	return fmt.Errorf("failed to resolve policy '%s': %w", policy, err)
}

func NewPolicyNotFoundError(policy string) error {
	return fmt.Errorf("no policies found matching '%s'", policy)
}

func NewPolicyAmbiguousError(policy string) error {
	return fmt.Errorf("multiple policies match '%s', please be more specific", policy)
}

// File I/O errors
func NewFileReadError(fileType string, err error) error {
	return fmt.Errorf("failed to read %s file: %w", fileType, err)
}

func NewFileWriteError(fileType string, err error) error {
	return fmt.Errorf("failed to write %s file: %w", fileType, err)
}

// Format validation errors
func NewUnsupportedFormatError(format string, supported []string) error {
	return fmt.Errorf("unsupported output format: %s (supported: %v)", format, supported)
}

func NewUnsupportedKeyTypeError(keyType string, supported []string) error {
	return fmt.Errorf("unsupported key type: %s (supported: %v)", keyType, supported)
}

// Configuration errors
func NewConfigurationError(message string, err error) error {
	if err != nil {
		return fmt.Errorf("configuration error: %s: %w", message, err)
	}
	return fmt.Errorf("configuration error: %s", message)
}

// Validation errors for specific parameters
func NewParameterValidationError(param, reason string) error {
	return fmt.Errorf("invalid parameter --%s: %s", param, reason)
}

// Interactive mode errors
func NewNonInteractiveModeError(count int, instruction string) error {
	return fmt.Errorf("multiple items found (%d) but running in non-interactive mode. %s", count, instruction)
}

// CSR errors
func NewCSRGenerationError(err error) error {
	return fmt.Errorf("failed to generate certificate signing request: %w", err)
}

func NewCSRParsingError(err error) error {
	return fmt.Errorf("failed to parse certificate signing request: %w", err)
}

// Private key errors
func NewPrivateKeyGenerationError(err error) error {
	return fmt.Errorf("failed to generate private key: %w", err)
}

func NewPrivateKeyParsingError(err error) error {
	return fmt.Errorf("failed to parse private key: %w", err)
}
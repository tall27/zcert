package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"zcert/internal/api"
)

// CertificateOutputOptions configures how certificates are displayed
type CertificateOutputOptions struct {
	Format     string    // "table", "json", "csv"
	Wide       bool      // Show full column content without truncation
	Writer     io.Writer // Output destination (defaults to os.Stdout)
	ShowIndex  bool      // Show index numbers (for interactive selection)
	Title      string    // Optional title for the output
}

// DefaultCertificateOutputOptions returns standard output options
func DefaultCertificateOutputOptions() *CertificateOutputOptions {
	return &CertificateOutputOptions{
		Format: "table",
		Wide:   false,
		Writer: os.Stdout,
	}
}

// OutputCertificates displays a list of certificates in the specified format
func OutputCertificates(certificates []api.Certificate, opts *CertificateOutputOptions) error {
	if opts == nil {
		opts = DefaultCertificateOutputOptions()
	}
	
	if opts.Writer == nil {
		opts.Writer = os.Stdout
	}

	switch opts.Format {
	case "table":
		return outputCertificateTable(certificates, opts)
	case "json":
		return outputCertificateJSON(certificates, opts)
	case "csv":
		return outputCertificateCSV(certificates, opts)
	default:
		return NewUnsupportedFormatError(opts.Format, []string{"table", "json", "csv"})
	}
}

// outputCertificateTable displays certificates in a formatted table
func outputCertificateTable(certificates []api.Certificate, opts *CertificateOutputOptions) error {
	w := tabwriter.NewWriter(opts.Writer, 0, 0, 2, ' ', 0)
	
	// Optional title
	if opts.Title != "" {
		fmt.Fprintf(opts.Writer, "\n%s (%d found):\n", opts.Title, len(certificates))
	}
	
	// Header
	if opts.ShowIndex {
		fmt.Fprintln(w, "#\tID\tCOMMON NAME\tSERIAL\tSTATUS\tISSUER\tEXPIRES")
		fmt.Fprintln(w, "-\t----\t-----------\t------\t------\t------\t--------")
	} else {
		fmt.Fprintln(w, "ID\tCOMMON NAME\tSERIAL\tSTATUS\tISSUER\tEXPIRES")
		fmt.Fprintln(w, "----\t-----------\t------\t------\t------\t--------")
	}
	
	// Data rows
	for i, cert := range certificates {
		var id, cn, serial, issuer string
		
		if opts.Wide {
			// Show full values without truncation
			id = cert.ID
			cn = cert.CommonName
			serial = cert.SerialNumber
			issuer = cert.Issuer
		} else {
			// Truncate long values for table display
			id = TruncateString(cert.ID, 12)
			cn = TruncateString(cert.CommonName, 25)
			serial = TruncateString(cert.SerialNumber, 16)
			issuer = TruncateString(cert.Issuer, 20)
		}
		
		status := cert.Status
		expires := cert.ExpiryDate.Format("2006-01-02")
		
		if opts.ShowIndex {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
				i+1, id, cn, serial, status, issuer, expires)
		} else {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				id, cn, serial, status, issuer, expires)
		}
	}
	
	return w.Flush()
}

// outputCertificateJSON displays certificates in JSON format
func outputCertificateJSON(certificates []api.Certificate, opts *CertificateOutputOptions) error {
	// Use proper JSON marshaling
	data, err := json.MarshalIndent(certificates, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal certificates to JSON: %w", err)
	}
	
	_, err = opts.Writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write JSON output: %w", err)
	}
	
	// Add newline for better formatting
	fmt.Fprintln(opts.Writer)
	return nil
}

// outputCertificateCSV displays certificates in CSV format
func outputCertificateCSV(certificates []api.Certificate, opts *CertificateOutputOptions) error {
	// CSV header
	if opts.ShowIndex {
		fmt.Fprintln(opts.Writer, "#,ID,Common Name,Serial Number,Status,Issuer,Expiry Date,Policy ID")
	} else {
		fmt.Fprintln(opts.Writer, "ID,Common Name,Serial Number,Status,Issuer,Expiry Date,Policy ID")
	}
	
	// CSV data
	for i, cert := range certificates {
		// Escape quotes in CSV values
		id := escapeCsvValue(cert.ID)
		cn := escapeCsvValue(cert.CommonName)
		serial := escapeCsvValue(cert.SerialNumber)
		status := escapeCsvValue(cert.Status)
		issuer := escapeCsvValue(cert.Issuer)
		expiryDate := cert.ExpiryDate.Format("2006-01-02 15:04:05")
		policyID := escapeCsvValue(cert.PolicyID)
		
		if opts.ShowIndex {
			fmt.Fprintf(opts.Writer, "%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
				i+1, id, cn, serial, status, issuer, expiryDate, policyID)
		} else {
			fmt.Fprintf(opts.Writer, "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
				id, cn, serial, status, issuer, expiryDate, policyID)
		}
	}
	
	return nil
}

// TruncateString truncates a string to maxLen characters, adding "..." if truncated
// Made public so it can be reused by other utilities
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// escapeCsvValue escapes quotes in CSV values
func escapeCsvValue(value string) string {
	// Replace double quotes with escaped double quotes
	return fmt.Sprintf("%q", value)[1 : len(fmt.Sprintf("%q", value))-1]
}

// FormatCertificateList formats a list of certificates for display in error messages
func FormatCertificateList(certificates []api.Certificate) string {
	// For error messages, create a simple text representation
	result := ""
	for i, cert := range certificates {
		result += fmt.Sprintf("  [%d] ID: %s, CN: %s, Serial: %s\n",
			i+1, cert.ID, cert.CommonName, cert.SerialNumber)
	}
	return result
}

// CertificateSelectionOptions configures certificate selection display
type CertificateSelectionOptions struct {
	Wide   bool
	Prompt string
	Writer io.Writer // Typically os.Stderr for interactive prompts
}

// DisplayCertificatesForSelection shows certificates in a format suitable for interactive selection
func DisplayCertificatesForSelection(certificates []api.Certificate, opts *CertificateSelectionOptions) error {
	if opts == nil {
		opts = &CertificateSelectionOptions{
			Wide:   false,
			Prompt: "Multiple certificates found",
			Writer: os.Stderr,
		}
	}
	
	if opts.Writer == nil {
		opts.Writer = os.Stderr
	}
	
	outputOpts := &CertificateOutputOptions{
		Format:    "table",
		Wide:      opts.Wide,
		Writer:    opts.Writer,
		ShowIndex: true,
		Title:     opts.Prompt,
	}
	
	return OutputCertificates(certificates, outputOpts)
}

// OutputSingleCertificate displays information about a single certificate
func OutputSingleCertificate(cert *api.Certificate, writer io.Writer) {
	if writer == nil {
		writer = os.Stderr
	}
	
	fmt.Fprintf(writer, "Certificate information:\n")
	fmt.Fprintf(writer, "  ID: %s\n", cert.ID)
	fmt.Fprintf(writer, "  Common Name: %s\n", cert.CommonName)
	fmt.Fprintf(writer, "  Serial Number: %s\n", cert.SerialNumber)
	fmt.Fprintf(writer, "  Issuer: %s\n", cert.Issuer)
	fmt.Fprintf(writer, "  Status: %s\n", cert.Status)
	fmt.Fprintf(writer, "  Expires: %s\n", cert.ExpiryDate.Format(time.RFC3339))
	if cert.PolicyID != "" {
		fmt.Fprintf(writer, "  Policy ID: %s\n", cert.PolicyID)
	}
}
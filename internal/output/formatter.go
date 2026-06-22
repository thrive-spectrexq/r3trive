// Package output provides formatters for rendering R3TRIVE output
// in multiple formats: table, JSON, NDJSON, CSV, and quiet.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Format represents an output format.
type Format string

// Supported output formats.
const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatNDJSON Format = "ndjson"
	FormatCSV   Format = "csv"
	FormatQuiet Format = "quiet"
)

// ParseFormat parses a format string into a Format type.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "table":
		return FormatTable, nil
	case "json":
		return FormatJSON, nil
	case "ndjson":
		return FormatNDJSON, nil
	case "csv":
		return FormatCSV, nil
	case "quiet":
		return FormatQuiet, nil
	default:
		return "", fmt.Errorf("unknown output format %q, valid: table, json, ndjson, csv, quiet", s)
	}
}

// Formatter writes structured data in the configured format.
type Formatter struct {
	format Format
	writer io.Writer
}

// NewFormatter creates a new output formatter.
func NewFormatter(w io.Writer, format Format) *Formatter {
	return &Formatter{
		format: format,
		writer: w,
	}
}

// WriteTable writes tabular data with headers and rows.
func (f *Formatter) WriteTable(headers []string, rows [][]string) error {
	switch f.format {
	case FormatTable:
		return f.writeTableFmt(headers, rows)
	case FormatJSON:
		return f.writeJSONArray(headers, rows)
	case FormatNDJSON:
		return f.writeNDJSON(headers, rows)
	case FormatCSV:
		return f.writeCSV(headers, rows)
	case FormatQuiet:
		return nil // no output
	default:
		return fmt.Errorf("unsupported format: %s", f.format)
	}
}

// WriteObject writes a single object (used for JSON/NDJSON single-item output).
func (f *Formatter) WriteObject(v any) error {
	switch f.format {
	case FormatJSON:
		enc := json.NewEncoder(f.writer)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	case FormatNDJSON:
		return json.NewEncoder(f.writer).Encode(v)
	case FormatQuiet:
		return nil
	default:
		// For table/csv, fall back to JSON
		enc := json.NewEncoder(f.writer)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
}

func (f *Formatter) writeTableFmt(headers []string, rows [][]string) error {
	tw := tabwriter.NewWriter(f.writer, 0, 0, 2, ' ', 0)

	// Write header
	headerLine := strings.Join(headers, "\t")
	if _, err := fmt.Fprintln(tw, headerLine); err != nil {
		return fmt.Errorf("writing table header: %w", err)
	}

	// Write separator
	seps := make([]string, len(headers))
	for i, h := range headers {
		seps[i] = strings.Repeat("─", len(h))
	}
	if _, err := fmt.Fprintln(tw, strings.Join(seps, "\t")); err != nil {
		return fmt.Errorf("writing table separator: %w", err)
	}

	// Write rows
	for _, row := range rows {
		if _, err := fmt.Fprintln(tw, strings.Join(row, "\t")); err != nil {
			return fmt.Errorf("writing table row: %w", err)
		}
	}

	return tw.Flush()
}

func (f *Formatter) writeJSONArray(headers []string, rows [][]string) error {
	objects := rowsToMaps(headers, rows)
	enc := json.NewEncoder(f.writer)
	enc.SetIndent("", "  ")
	return enc.Encode(objects)
}

func (f *Formatter) writeNDJSON(headers []string, rows [][]string) error {
	objects := rowsToMaps(headers, rows)
	enc := json.NewEncoder(f.writer)
	for _, obj := range objects {
		if err := enc.Encode(obj); err != nil {
			return fmt.Errorf("writing ndjson: %w", err)
		}
	}
	return nil
}

func (f *Formatter) writeCSV(headers []string, rows [][]string) error {
	w := csv.NewWriter(f.writer)
	if err := w.Write(headers); err != nil {
		return fmt.Errorf("writing csv header: %w", err)
	}
	for _, row := range rows {
		if err := w.Write(row); err != nil {
			return fmt.Errorf("writing csv row: %w", err)
		}
	}
	w.Flush()
	return w.Error()
}

func rowsToMaps(headers []string, rows [][]string) []map[string]string {
	result := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		m := make(map[string]string, len(headers))
		for i, h := range headers {
			if i < len(row) {
				m[h] = row[i]
			}
		}
		result = append(result, m)
	}
	return result
}

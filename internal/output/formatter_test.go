package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseFormat(t *testing.T) {
	valid := map[string]Format{
		"table":   FormatTable,
		"JSON":    FormatJSON,
		"ndjson":  FormatNDJSON,
		"CSV":     FormatCSV,
		"quiet":   FormatQuiet,
	}

	for input, expected := range valid {
		f, err := ParseFormat(input)
		if err != nil {
			t.Errorf("ParseFormat(%q) returned error: %v", input, err)
		}
		if f != expected {
			t.Errorf("ParseFormat(%q) = %s; want %s", input, f, expected)
		}
	}

	if _, err := ParseFormat("unsupported"); err == nil {
		t.Error("expected error for unsupported format, got nil")
	}
}

func TestFormatter_WriteTable(t *testing.T) {
	headers := []string{"ID", "NAME", "STATUS"}
	rows := [][]string{
		{"1", "agent-alpha", "running"},
		{"2", "agent-beta", "stopped"},
	}

	// 1. Table format
	var bufTable bytes.Buffer
	fTable := NewFormatter(&bufTable, FormatTable)
	if err := fTable.WriteTable(headers, rows); err != nil {
		t.Fatalf("WriteTable (table) error: %v", err)
	}
	tableOut := bufTable.String()
	if !strings.Contains(tableOut, "agent-alpha") || !strings.Contains(tableOut, "running") {
		t.Errorf("unexpected table output: %s", tableOut)
	}

	// 2. JSON format
	var bufJSON bytes.Buffer
	fJSON := NewFormatter(&bufJSON, FormatJSON)
	if err := fJSON.WriteTable(headers, rows); err != nil {
		t.Fatalf("WriteTable (JSON) error: %v", err)
	}
	if !strings.Contains(bufJSON.String(), `"NAME": "agent-alpha"`) {
		t.Errorf("unexpected json output: %s", bufJSON.String())
	}

	// 3. NDJSON format
	var bufNDJSON bytes.Buffer
	fNDJSON := NewFormatter(&bufNDJSON, FormatNDJSON)
	if err := fNDJSON.WriteTable(headers, rows); err != nil {
		t.Fatalf("WriteTable (NDJSON) error: %v", err)
	}
	ndLines := strings.Split(strings.TrimSpace(bufNDJSON.String()), "\n")
	if len(ndLines) != 2 {
		t.Errorf("expected 2 NDJSON lines, got %d", len(ndLines))
	}

	// 4. CSV format
	var bufCSV bytes.Buffer
	fCSV := NewFormatter(&bufCSV, FormatCSV)
	if err := fCSV.WriteTable(headers, rows); err != nil {
		t.Fatalf("WriteTable (CSV) error: %v", err)
	}
	if !strings.Contains(bufCSV.String(), "agent-alpha,running") {
		t.Errorf("unexpected csv output: %s", bufCSV.String())
	}

	// 5. Quiet format
	var bufQuiet bytes.Buffer
	fQuiet := NewFormatter(&bufQuiet, FormatQuiet)
	if err := fQuiet.WriteTable(headers, rows); err != nil {
		t.Fatalf("WriteTable (Quiet) error: %v", err)
	}
	if bufQuiet.Len() != 0 {
		t.Errorf("expected quiet format to produce 0 bytes, got %d", bufQuiet.Len())
	}
}

func TestFormatter_WriteObject(t *testing.T) {
	type testItem struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	item := testItem{Host: "localhost", Port: 8080}

	var buf bytes.Buffer
	f := NewFormatter(&buf, FormatJSON)
	if err := f.WriteObject(item); err != nil {
		t.Fatalf("WriteObject error: %v", err)
	}
	if !strings.Contains(buf.String(), `"host": "localhost"`) {
		t.Errorf("unexpected output: %s", buf.String())
	}

	// Quiet
	buf.Reset()
	fQuiet := NewFormatter(&buf, FormatQuiet)
	if err := fQuiet.WriteObject(item); err != nil {
		t.Fatalf("WriteObject quiet error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected 0 bytes in quiet mode, got %d", buf.Len())
	}
}

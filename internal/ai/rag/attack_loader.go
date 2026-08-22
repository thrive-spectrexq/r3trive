package rag

import (
	"encoding/json"
	"os"
)

// attackJSON represents the expected format of MITRE ATT&CK techniques in JSON.
type attackJSON struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`
	Description string `json:"description"`
}

// LoadATTACKData parses a JSON file containing MITRE ATT&CK techniques
// and returns them as a slice of Documents.
func LoadATTACKData(path string) ([]Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var attackData []attackJSON
	if err := json.Unmarshal(data, &attackData); err != nil {
		return nil, err
	}

	docs := make([]Document, len(attackData))
	for i, item := range attackData {
		docs[i] = Document{
			ID:       item.ID,
			Title:    item.Name,
			Category: item.Tactic,
			Content:  item.Description,
		}
	}

	return docs, nil
}

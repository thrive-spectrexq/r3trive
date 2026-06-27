package correlation

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadRulesFromDirectory scans a directory recursively for .yml or .yaml files
// and parses them into a slice of Rules.
func LoadRulesFromDirectory(dir string) ([]Rule, error) {
	var rules []Rule

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}

		content, err := os.ReadFile(path) // #nosec G122 G304
		if err != nil {
			return fmt.Errorf("failed to read rule file %s: %w", path, err)
		}

		var rule Rule
		if err := yaml.Unmarshal(content, &rule); err != nil {
			return fmt.Errorf("failed to parse rule file %s: %w", path, err)
		}

		rules = append(rules, rule)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk rules directory %s: %w", dir, err)
	}

	return rules, nil
}

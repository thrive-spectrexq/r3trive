package sigma

import (
	"fmt"
	"strings"

	"github.com/thrive-spectrexq/r3trive/internal/correlation"
	"github.com/thrive-spectrexq/r3trive/pkg/sigma"
)

// Transpiler converts Sigma detection rules into native R3TRIVE correlation rules.
type Transpiler struct{}

// NewTranspiler creates a new Sigma transpiler instance.
func NewTranspiler() *Transpiler {
	return &Transpiler{}
}

// Transpile converts a parsed Sigma rule into a R3TRIVE correlation Rule.
func (t *Transpiler) Transpile(sigRule *sigma.Rule) (*correlation.Rule, error) {
	if sigRule == nil {
		return nil, fmt.Errorf("nil sigma rule provided")
	}

	corrRule := &correlation.Rule{
		ID:          sigRule.ID,
		Name:        sigRule.Title,
		Description: sigRule.Description,
		Severity:    sigRule.Level,
		Confidence:  0.8,
		Conditions:  make([]correlation.Condition, 0),
	}

	for tag := range sigRule.Tags {
		tagVal := sigRule.Tags[tag]
		if strings.HasPrefix(tagVal, "attack.t") {
			corrRule.ATTACKTechnique = strings.ToUpper(strings.TrimPrefix(tagVal, "attack."))
		} else if strings.HasPrefix(tagVal, "attack.") {
			corrRule.ATTACKTactic = strings.Title(strings.TrimPrefix(tagVal, "attack."))
		}
	}

	// Basic detection mapping
	if sigRule.Detection != nil {
		for key, val := range sigRule.Detection {
			if key == "condition" {
				continue
			}
			if mMap, ok := val.(map[string]interface{}); ok {
				for fKey, fVal := range mMap {
					fieldName := mapField(fKey)
					strVal := fmt.Sprintf("%v", fVal)
					corrRule.Conditions = append(corrRule.Conditions, correlation.Condition{
						Field:    fieldName,
						Operator: "contains",
						Value:    strVal,
					})
				}
			}
		}
	}

	return corrRule, nil
}

func mapField(sigmaField string) string {
	lower := strings.ToLower(sigmaField)
	switch {
	case strings.HasPrefix(lower, "image"), strings.HasPrefix(lower, "process"):
		return "data.process.name"
	case strings.HasPrefix(lower, "commandline"), strings.HasPrefix(lower, "cmdline"):
		return "data.process.cmdline"
	case strings.HasPrefix(lower, "parentimage"):
		return "data.process.parent.name"
	case strings.HasPrefix(lower, "destinationip"):
		return "data.network.dst_ip"
	case strings.HasPrefix(lower, "targetfilename"):
		return "data.file.path"
	default:
		return "data.process.cmdline"
	}
}

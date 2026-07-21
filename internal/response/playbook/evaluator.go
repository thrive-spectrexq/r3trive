package playbook

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

var templateRegex = regexp.MustCompile(`\{\{\s*(\$\.[a-zA-Z0-9_\.]+)\s*\}\}`)

// EvaluateParams resolves JSONPath expressions and template strings in action parameters using incident data.
func EvaluateParams(params map[string]any, incident event.Incident) map[string]any {
	if params == nil {
		return make(map[string]any)
	}

	evaluated := make(map[string]any)
	for k, v := range params {
		evaluated[k] = evaluateValue(v, incident)
	}

	return evaluated
}

func evaluateValue(val any, incident event.Incident) any {
	switch v := val.(type) {
	case string:
		// Check for direct JSONPath expression like "$.incident.primary_pid"
		if strings.HasPrefix(v, "$.") {
			return resolveJSONPath(v, incident)
		}

		// Check for template string like "Ransomware on {{ $.incident.host_id }}"
		if templateRegex.MatchString(v) {
			return templateRegex.ReplaceAllStringFunc(v, func(match string) string {
				subMatches := templateRegex.FindStringSubmatch(match)
				if len(subMatches) > 1 {
					resolved := resolveJSONPath(subMatches[1], incident)
					return fmt.Sprintf("%v", resolved)
				}
				return match
			})
		}
		return v

	case []any:
		var list []any
		for _, item := range v {
			list = append(list, evaluateValue(item, incident))
		}
		return list

	case map[string]any:
		res := make(map[string]any)
		for k, item := range v {
			res[k] = evaluateValue(item, incident)
		}
		return res

	default:
		return val
	}
}

// resolveJSONPath resolves supported $.incident JSONPath expressions.
func resolveJSONPath(path string, incident event.Incident) any {
	switch path {
	case "$.incident.id":
		return incident.ID
	case "$.incident.title":
		return incident.Title
	case "$.incident.description":
		return incident.Description
	case "$.incident.severity":
		return string(incident.Severity)
	case "$.incident.risk_score":
		return incident.RiskScore
	case "$.incident.host_id":
		if len(incident.HostIDs) > 0 {
			return incident.HostIDs[0]
		}
		return ""
	case "$.incident.host_ids":
		return incident.HostIDs
	case "$.incident.artifact_paths":
		return incident.ArtifactPaths
	case "$.incident.primary_pid":
		return getPrimaryPID(incident)
	case "$.incident.primary_ip":
		return getPrimaryIP(incident)
	case "$.incident.primary_path":
		if len(incident.ArtifactPaths) > 0 {
			return incident.ArtifactPaths[0]
		}
		return getPrimaryFilePath(incident)
	}

	// Dynamic alert index resolution e.g. $.incident.alerts[0].event.data.process.pid
	if strings.HasPrefix(path, "$.incident.alerts") {
		return resolveAlertPath(path, incident)
	}

	return path
}

func getPrimaryPID(incident event.Incident) int {
	for _, alert := range incident.Alerts {
		if alert.Event.Data.Process != nil && alert.Event.Data.Process.PID > 0 {
			return alert.Event.Data.Process.PID
		}
	}
	return 0
}

func getPrimaryIP(incident event.Incident) string {
	for _, alert := range incident.Alerts {
		if alert.Event.Data.Network != nil && alert.Event.Data.Network.DstIP != "" {
			return alert.Event.Data.Network.DstIP
		}
	}
	return ""
}

func getPrimaryFilePath(incident event.Incident) string {
	for _, alert := range incident.Alerts {
		if alert.Event.Data.File != nil && alert.Event.Data.File.Path != "" {
			return alert.Event.Data.File.Path
		}
	}
	return ""
}

func resolveAlertPath(path string, incident event.Incident) any {
	// Simple index extraction: $.incident.alerts[0]...
	re := regexp.MustCompile(`\$\.incident\.alerts\[(\d+)\]\.(.+)`)
	matches := re.FindStringSubmatch(path)
	if len(matches) < 3 {
		return path
	}

	idx, err := strconv.Atoi(matches[1])
	if err != nil || idx < 0 || idx >= len(incident.Alerts) {
		return ""
	}

	subField := matches[2]
	alert := incident.Alerts[idx]

	switch subField {
	case "event.data.process.pid":
		if alert.Event.Data.Process != nil {
			return alert.Event.Data.Process.PID
		}
	case "event.data.process.name":
		if alert.Event.Data.Process != nil {
			return alert.Event.Data.Process.Name
		}
	case "event.data.process.path":
		if alert.Event.Data.Process != nil {
			return alert.Event.Data.Process.Path
		}
	case "event.data.network.dst_ip":
		if alert.Event.Data.Network != nil {
			return alert.Event.Data.Network.DstIP
		}
	case "event.data.file.path":
		if alert.Event.Data.File != nil {
			return alert.Event.Data.File.Path
		}
	}

	return path
}

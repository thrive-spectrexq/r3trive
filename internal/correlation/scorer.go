package correlation

import (
	"math"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// CalculateRiskScore computes a risk score (0-100) from severity and confidence.
//
// Formula from SYSTEM_ARCHITECTURE.md §4.4.3:
//   Risk = finding_weight × confidence × campaign_multiplier × recency_decay
//
// For MVP, campaign_multiplier and recency_decay default to 1.0.
func CalculateRiskScore(severity event.Severity, confidence float64) int {
	weight := float64(severity.Weight())
	score := weight * confidence

	// Clamp to 0-100
	score = math.Max(0, math.Min(100, score))

	return int(math.Round(score))
}

// CalculateIncidentScore computes an aggregate risk score for an incident
// from its constituent alerts.
func CalculateIncidentScore(alerts []event.Alert) int {
	if len(alerts) == 0 {
		return 0
	}

	// Sum weighted scores with diminishing returns
	var totalScore float64
	for i, alert := range alerts {
		// Each additional alert contributes less (diminishing multiplier)
		multiplier := 1.0 / (1.0 + float64(i)*0.3)
		totalScore += float64(alert.RiskScore) * multiplier
	}

	// Campaign multiplier: more alerts = higher multiplier (1.0 to 2.0)
	campaignMultiplier := 1.0 + math.Min(1.0, float64(len(alerts)-1)*0.2)
	totalScore *= campaignMultiplier

	// Clamp to 0-100
	score := math.Max(0, math.Min(100, totalScore))

	return int(math.Round(score))
}

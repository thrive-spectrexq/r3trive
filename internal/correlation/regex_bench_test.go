package correlation

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func BenchmarkCachedRegexRuleEvaluation(b *testing.B) {
	e := New()
	pattern := `(?i)-enc\s+[A-Za-z0-9+/=]+`
	e.LoadRules([]Rule{
		{
			ID:          "rule-regex-bench",
			Name:        "Regex Benchmark Rule",
			Severity:    "high",
			Description: "Benchmark regex evaluation",
			Conditions: []Condition{
				{
					Field:    "data.process.cmdline",
					Operator: "regex",
					Value:    pattern,
				},
			},
		},
	})

	ctx := context.Background()
	evt := event.Event{
		ID:        "evt-bench-1",
		Type:      event.ProcessCreate,
		Timestamp: time.Now().UTC(),
		Data: event.EventData{
			Process: &event.ProcessData{
				PID:     1234,
				Name:    "powershell.exe",
				CmdLine: "powershell.exe -enc SQBFAFgA",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alerts := e.Evaluate(ctx, evt)
		if len(alerts) == 0 {
			b.Fatalf("failed match")
		}
	}
}

func BenchmarkUncachedRegexCompilationAndMatch(b *testing.B) {
	pattern := `(?i)powershell(\.exe)?\s+(-e|-enc|-encodedcommand)`
	input := "powershell.exe -enc SQBFAFgA"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		re, err := regexp.Compile(pattern)
		if err != nil || !re.MatchString(input) {
			b.Fatalf("failed match")
		}
	}
}

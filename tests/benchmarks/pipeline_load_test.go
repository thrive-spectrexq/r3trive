package benchmarks_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/correlation"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func BenchmarkCorrelationThroughput(b *testing.B) {
	rules := []correlation.Rule{
		{
			ID:       "BENCH-001",
			Name:     "Process Monitoring",
			Severity: "high",
			Conditions: []correlation.Condition{
				{
					Field:    "data.process.name",
					Operator: "eq",
					Value:    "svchost.exe",
				},
			},
		},
		{
			ID:       "BENCH-002",
			Name:     "Regex Check",
			Severity: "medium",
			Conditions: []correlation.Condition{
				{
					Field:    "data.process.cmdline",
					Operator: "regex",
					Value:    `(?i)-enc(odedcommand)?\s+[a-z0-9+/=]+`,
				},
			},
		},
	}

	engine := correlation.New()
	engine.LoadRules(rules)

	ctx := context.Background()
	evt := event.Event{
		ID:        "evt-bench-01",
		Timestamp: time.Now(),
		Type:      event.ProcessCreate,
		Data: event.EventData{
			Process: &event.ProcessData{
				Name:    "svchost.exe",
				CmdLine: "svchost.exe -k netsvcs -p -s Schedule",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(ctx, evt)
	}
}

func BenchmarkHighEventRateBurst(b *testing.B) {
	engine := correlation.New()
	ctx := context.Background()

	events := make([]event.Event, 1000)
	for i := 0; i < 1000; i++ {
		events[i] = event.Event{
			ID:        fmt.Sprintf("evt-burst-%d", i),
			Timestamp: time.Now(),
			Type:      event.ProcessCreate,
			Data: event.EventData{
				Process: &event.ProcessData{
					Name: fmt.Sprintf("proc_%d.exe", i%10),
				},
			},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evt := events[i%1000]
		_ = engine.Evaluate(ctx, evt)
	}
}

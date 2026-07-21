package exporter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestExporterSendAlert(t *testing.T) {
	received := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exp := New(Config{
		Type: ExporterWebhook,
		URL:  server.URL,
	})

	alert := event.Alert{
		ID:        "alert-100",
		Timestamp: time.Now().UTC(),
		RuleID:    "R3T-EXEC-001",
		Severity:  event.SeverityHigh,
		Message:   "PowerShell Encoded Command Execution",
	}

	if err := exp.SendAlert(context.Background(), alert); err != nil {
		t.Fatalf("SendAlert failed: %v", err)
	}

	if !received {
		t.Errorf("expected server to receive HTTP payload")
	}
}

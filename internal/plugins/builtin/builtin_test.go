package builtin

import (
	"context"
	"testing"

	"github.com/thrive-spectrexq/r3trive/internal/plugins"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestBuiltinPluginsLifecycle(t *testing.T) {
	ctx := context.Background()

	// 1. Splunk Plugin
	splunk := NewSplunkPlugin()
	if splunk.Metadata().Type != plugins.PluginTypeOutput {
		t.Fatalf("unexpected type for splunk")
	}
	if err := splunk.Init(ctx, map[string]interface{}{"index": "security"}); err != nil {
		t.Fatalf("splunk init failed: %v", err)
	}
	if err := splunk.EmitEvent(ctx, event.Event{}); err != nil {
		t.Fatalf("splunk emit failed: %v", err)
	}

	// 2. Elasticsearch Plugin
	es := NewElasticsearchPlugin()
	if es.Metadata().Type != plugins.PluginTypeOutput {
		t.Fatalf("unexpected type for elasticsearch")
	}
	if err := es.Init(ctx, map[string]interface{}{"index_prefix": "fleet"}); err != nil {
		t.Fatalf("elasticsearch init failed: %v", err)
	}
	if err := es.EmitEvent(ctx, event.Event{}); err != nil {
		t.Fatalf("elasticsearch emit failed: %v", err)
	}

	// 3. Jira Plugin
	jira := NewJiraPlugin()
	if jira.Metadata().Type != plugins.PluginTypeAction {
		t.Fatalf("unexpected type for jira")
	}
	if err := jira.Init(ctx, map[string]interface{}{"project": "IR"}); err != nil {
		t.Fatalf("jira init failed: %v", err)
	}
	res, err := jira.ExecuteAction(ctx, "create_ticket", map[string]interface{}{"title": "Malware Found"})
	if err != nil || res["status"] != "simulated" {
		t.Fatalf("jira execute failed: %v, %v", err, res)
	}

	// 4. PagerDuty Plugin
	pd := NewPagerDutyPlugin()
	if pd.Metadata().Type != plugins.PluginTypeAction {
		t.Fatalf("unexpected type for pagerduty")
	}
	pdRes, err := pd.ExecuteAction(ctx, "trigger_incident", map[string]interface{}{"incident_id": "INC-01"})
	if err != nil || pdRes["status"] != "simulated" {
		t.Fatalf("pagerduty execute failed: %v, %v", err, pdRes)
	}

	// 5. VirusTotal Plugin
	vt := NewVirusTotalPlugin()
	if vt.Metadata().Type != plugins.PluginTypeIntelligence {
		t.Fatalf("unexpected type for virustotal")
	}
	vtRes, err := vt.LookupIOC(ctx, "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if err != nil || vtRes["status"] != "simulated" {
		t.Fatalf("virustotal lookup failed: %v, %v", err, vtRes)
	}

	// 6. MISP Plugin
	misp := NewMISPPlugin()
	if misp.Metadata().Type != plugins.PluginTypeIntelligence {
		t.Fatalf("unexpected type for misp")
	}
	mispRes, err := misp.LookupIOC(ctx, "ip", "1.2.3.4")
	if err != nil || mispRes["status"] != "simulated" {
		t.Fatalf("misp lookup failed: %v, %v", err, mispRes)
	}
}

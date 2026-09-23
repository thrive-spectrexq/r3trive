package rag

import (
	"context"
	"strings"
	"testing"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestKnowledgeBaseAddRetrieve(t *testing.T) {
	embedder := NewMockEmbedder()
	kb := NewKnowledgeBase(embedder)
	ctx := context.Background()

	results := kb.RetrieveRelevant(ctx, "powershell encoded command", 2)
	if len(results) == 0 {
		t.Fatalf("expected RAG search results for powershell query")
	}

	foundPowerShell := false
	for _, doc := range results {
		if doc.ID == "T1059.001" {
			foundPowerShell = true
		}
	}
	if !foundPowerShell {
		t.Errorf("expected technique T1059.001 in results")
	}

	formatted := FormatContext(results)
	if !strings.Contains(formatted, "Knowledge Base Context") {
		t.Errorf("expected formatted context block")
	}

	kb.AddIncident(event.Incident{
		ID:    "INC-999",
		Title: "RDP Brute Force",
	})
	incMatches := kb.SearchIncidents("RDP", 5)
	if len(incMatches) != 1 || incMatches[0].ID != "INC-999" {
		t.Errorf("expected to find searched incident INC-999")
	}

	// Test newly seeded technique retrieval
	ransomResults := kb.RetrieveRelevant(ctx, "ransomware encrypted shadow copy", 2)
	if len(ransomResults) == 0 {
		t.Fatalf("expected RAG search results for ransomware query")
	}
	if ransomResults[0].ID != "T1486" {
		t.Errorf("expected T1486 for ransomware query, got %s", ransomResults[0].ID)
	}

	dnsResults := kb.RetrieveRelevant(ctx, "dns tunneling beaconing", 2)
	if len(dnsResults) == 0 {
		t.Fatalf("expected RAG search results for dns tunneling query")
	}
	if dnsResults[0].ID != "T1071.004" {
		t.Errorf("expected T1071.004 for dns tunneling query, got %s", dnsResults[0].ID)
	}
}

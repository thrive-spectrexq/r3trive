package rag

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// Document represents a knowledge base record (ATT&CK technique, CVE, or Playbook).
type Document struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Category  string    `json:"category"`
	Content   string    `json:"content"`
	Tags      []string  `json:"tags"`
	Relevance float64   `json:"relevance,omitempty"`
	Embedding []float64 `json:"embedding,omitempty"`
}

// KnowledgeBase manages document retrieval and RAG search for AI context.
type KnowledgeBase struct {
	mu            sync.RWMutex
	docs          []Document
	incidentStore []event.Incident
	embedder      Embedder
}

// NewKnowledgeBase creates a new RAG knowledge base initialized with built-in ATT&CK data.
func NewKnowledgeBase(embedder Embedder) *KnowledgeBase {
	kb := &KnowledgeBase{
		docs:          make([]Document, 0),
		incidentStore: make([]event.Incident, 0),
		embedder:      embedder,
	}
	kb.seedATTACKData()
	return kb
}

// AddDocument registers a new document in the RAG store.
func (kb *KnowledgeBase) AddDocument(doc Document) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	
	if kb.embedder != nil && len(doc.Embedding) == 0 {
		text := doc.Title + " " + doc.Content + " " + strings.Join(doc.Tags, " ")
		if emb, err := kb.embedder.Embed(text); err == nil {
			doc.Embedding = emb
		}
	}
	
	kb.docs = append(kb.docs, doc)
}

// AddIncident indexes a historical incident for RAG querying.
func (kb *KnowledgeBase) AddIncident(inc event.Incident) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.incidentStore = append(kb.incidentStore, inc)
}

// RetrieveRelevant finds the top relevant documents matching query keywords.
func (kb *KnowledgeBase) RetrieveRelevant(ctx context.Context, query string, maxResults int) []Document {
	kb.mu.RLock()
	defer kb.mu.RUnlock()

	if kb.embedder == nil {
		return nil
	}

	queryEmb, err := kb.embedder.Embed(query)
	if err != nil {
		return nil
	}

	type scoredDoc struct {
		doc   Document
		score float64
	}

	var candidates []scoredDoc

	for _, doc := range kb.docs {
		if len(doc.Embedding) == 0 {
			continue
		}
		
		score := CosineSimilarity(queryEmb, doc.Embedding)
		
		// Consider adding a small threshold to avoid returning completely irrelevant documents
		if score > 0 {
			d := doc
			d.Relevance = score
			candidates = append(candidates, scoredDoc{doc: d, score: score})
		}
	}

	// Sort candidates by score descending
	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].score > candidates[i].score {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	if maxResults <= 0 || maxResults > len(candidates) {
		maxResults = len(candidates)
	}

	results := make([]Document, 0, maxResults)
	for i := 0; i < maxResults; i++ {
		results = append(results, candidates[i].doc)
	}

	return results
}

// SearchIncidents retrieves historical incidents matching search terms.
func (kb *KnowledgeBase) SearchIncidents(query string, maxResults int) []event.Incident {
	kb.mu.RLock()
	defer kb.mu.RUnlock()

	q := strings.ToLower(query)
	var matches []event.Incident

	for _, inc := range kb.incidentStore {
		if strings.Contains(strings.ToLower(inc.Title), q) ||
			strings.Contains(strings.ToLower(inc.ID), q) ||
			strings.Contains(strings.ToLower(string(inc.Severity)), q) {
			matches = append(matches, inc)
			if maxResults > 0 && len(matches) >= maxResults {
				break
			}
		}
	}
	return matches
}

// FormatContext formats retrieved documents into a string snippet for LLM prompts.
func FormatContext(docs []Document) string {
	if len(docs) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n--- Knowledge Base Context ---\n")
	for _, d := range docs {
		sb.WriteString(fmt.Sprintf("[%s] %s (%s): %s\n", d.ID, d.Title, d.Category, d.Content))
	}
	sb.WriteString("-------------------------------\n")
	return sb.String()
}

func (kb *KnowledgeBase) seedATTACKData() {
	docs := []Document{
		{
			ID:       "T1003.001",
			Title:    "OS Credential Dumping: LSASS Memory",
			Category: "Credential Access",
			Content:  "Adversaries may attempt to access credential material stored in the Process Memory of the Local Security Authority Subsystem Service (LSASS). Tools: Mimikatz, ProcDump, Sekurlsa.",
			Tags:     []string{"lsass", "mimikatz", "procdump", "credentials", "dumping"},
		},
		{
			ID:       "T1059.001",
			Title:    "Command and Scripting Interpreter: PowerShell",
			Category: "Execution",
			Content:  "Adversaries may use PowerShell to execute commands and scripts. PowerShell is often abused with Base64 encoding (-enc, -EncodedCommand) to hide malicious payloads.",
			Tags:     []string{"powershell", "pwsh", "encodedcommand", "execution", "scripting"},
		},
		{
			ID:       "T1071.001",
			Title:    "Application Layer Protocol: Web Protocols",
			Category: "Command and Control",
			Content:  "Adversaries may communicate using application layer protocols to bypass network filtering (HTTP/HTTPS beacons, Tor exit nodes, C2 channels).",
			Tags:     []string{"c2", "beaconing", "http", "https", "tor", "network"},
		},
		{
			ID:       "T1547.001",
			Title:    "Boot or Logon Autostart: Registry Run Keys",
			Category: "Persistence",
			Content:  "Adversaries may achieve persistence by adding an entry to the Windows Registry Run keys (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run).",
			Tags:     []string{"registry", "runkeys", "persistence", "autostart"},
		},
		{
			ID:       "T1055",
			Title:    "Process Injection",
			Category: "Defense Evasion",
			Content:  "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Techniques include DLL injection, Process Hollowing, and Thread Execution Hijacking.",
			Tags:     []string{"injection", "hollowing", "dll", "process", "evasion"},
		},
		{
			ID:       "T1021.001",
			Title:    "Remote Services: Remote Desktop Protocol",
			Category: "Lateral Movement",
			Content:  "Adversaries may use Valid Accounts to log into Remote Desktop Protocol (RDP) services to move laterally across a network.",
			Tags:     []string{"rdp", "remote", "desktop", "lateral", "movement"},
		},
	}
	
	for _, doc := range docs {
		if kb.embedder != nil {
			text := doc.Title + " " + doc.Content + " " + strings.Join(doc.Tags, " ")
			if emb, err := kb.embedder.Embed(text); err == nil {
				doc.Embedding = emb
			}
		}
		kb.docs = append(kb.docs, doc)
	}
}

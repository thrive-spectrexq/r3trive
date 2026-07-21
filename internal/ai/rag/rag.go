package rag

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Document represents a knowledge base record (ATT&CK technique, CVE, or Playbook).
type Document struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Category  string   `json:"category"`
	Content   string   `json:"content"`
	Tags      []string `json:"tags"`
	Relevance float64  `json:"relevance,omitempty"`
}

// KnowledgeBase manages vector-like or keyword-based document retrieval for AI context.
type KnowledgeBase struct {
	mu   sync.RWMutex
	docs []Document
}

// NewKnowledgeBase creates a new RAG knowledge base initialized with built-in ATT&CK data.
func NewKnowledgeBase() *KnowledgeBase {
	kb := &KnowledgeBase{
		docs: make([]Document, 0),
	}
	kb.seedATTACKData()
	return kb
}

// AddDocument registers a new document in the RAG store.
func (kb *KnowledgeBase) AddDocument(doc Document) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.docs = append(kb.docs, doc)
}

// RetrieveRelevant finds the top relevant documents matching query keywords.
func (kb *KnowledgeBase) RetrieveRelevant(ctx context.Context, query string, maxResults int) []Document {
	kb.mu.RLock()
	defer kb.mu.RUnlock()

	queryLower := strings.ToLower(query)
	keywords := strings.Fields(queryLower)

	type scoredDoc struct {
		doc   Document
		score float64
	}

	var candidates []scoredDoc

	for _, doc := range kb.docs {
		score := 0.0
		contentLower := strings.ToLower(doc.Title + " " + doc.Content + " " + strings.Join(doc.Tags, " "))

		for _, kw := range keywords {
			if len(kw) < 3 {
				continue
			}
			if strings.Contains(contentLower, kw) {
				score += 1.0
			}
			if strings.EqualFold(doc.ID, kw) {
				score += 5.0
			}
		}

		if score > 0 {
			doc.Relevance = score
			candidates = append(candidates, scoredDoc{doc: doc, score: score})
		}
	}

	// Sort by score
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

// FormatContext formats retrieved documents into a string snippet for LLM prompts.
func FormatContext(docs []Document) string {
	if len(docs) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n--- Knowledge Base Context ---\n")
	for _, d := range docs {
		sb.WriteString(fmt.Sprintf("[%s] %s: %s\n", d.ID, d.Title, d.Content))
	}
	sb.WriteString("-------------------------------\n")
	return sb.String()
}

func (kb *KnowledgeBase) seedATTACKData() {
	kb.docs = append(kb.docs,
		Document{
			ID:       "T1003.001",
			Title:    "OS Credential Dumping: LSASS Memory",
			Category: "Credential Access",
			Content:  "Adversaries may attempt to access credential material stored in the Process Memory of the Local Security Authority Subsystem Service (LSASS). Tools: Mimikatz, ProcDump, Sekurlsa.",
			Tags:     []string{"lsass", "mimikatz", "procdump", "credentials", "dumping"},
		},
		Document{
			ID:       "T1059.001",
			Title:    "Command and Scripting Interpreter: PowerShell",
			Category: "Execution",
			Content:  "Adversaries may use PowerShell to execute commands and scripts. PowerShell is often abused with Base64 encoding (-enc, -EncodedCommand) to hide malicious payloads.",
			Tags:     []string{"powershell", "pwsh", "encodedcommand", "execution", "scripting"},
		},
		Document{
			ID:       "T1071.001",
			Title:    "Application Layer Protocol: Web Protocols",
			Category: "Command and Control",
			Content:  "Adversaries may communicate using application layer protocols to bypass network filtering (HTTP/HTTPS beacons, Tor exit nodes, C2 channels).",
			Tags:     []string{"c2", "beaconing", "http", "https", "tor", "network"},
		},
		Document{
			ID:       "T1547.001",
			Title:    "Boot or Logon Autostart: Registry Run Keys",
			Category: "Persistence",
			Content:  "Adversaries may achieve persistence by adding an entry to the Windows Registry Run keys (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run).",
			Tags:     []string{"registry", "runkeys", "persistence", "autostart"},
		},
	)
}

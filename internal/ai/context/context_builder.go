package context

import (
	"fmt"
	"strings"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

// Builder constructs token-efficient, sanitized context windows for AI prompts.
type Builder struct {
	maxTokens int
}

// NewBuilder initializes a context builder with a maximum token budget constraint.
func NewBuilder(maxTokens int) *Builder {
	if maxTokens <= 0 {
		maxTokens = 4096
	}
	return &Builder{maxTokens: maxTokens}
}

// BuildEventContext formats a single event into a clean prompt string.
func (b *Builder) BuildEventContext(evt event.Event) string {
	var sb strings.Builder
	sb.WriteString("System Event Context:\n")
	sb.WriteString(fmt.Sprintf("ID: %s | Type: %s | Severity: %s | Sensor: %s\n",
		evt.ID, evt.Type, evt.Severity, evt.Sensor))
	sb.WriteString(fmt.Sprintf("Timestamp: %s | Host: %s (%s)\n",
		evt.Timestamp.Format("2006-01-02 15:04:05"), evt.Host.Hostname, evt.Host.OS))

	if evt.Data.Process != nil {
		p := evt.Data.Process
		sb.WriteString(fmt.Sprintf("Process: PID %d, %s, CmdLine: %s, User: %s\n",
			p.PID, p.Name, p.CmdLine, p.User))
	}
	if evt.Data.Network != nil {
		n := evt.Data.Network
		sb.WriteString(fmt.Sprintf("Network: %s %s:%d -> %s:%d (Process: %s)\n",
			n.Protocol, n.SrcIP, n.SrcPort, n.DstIP, n.DstPort, n.ProcessName))
	}
	if evt.Data.File != nil {
		f := evt.Data.File
		sb.WriteString(fmt.Sprintf("File: Path %s, Size %d\n", f.Path, f.Size))
	}

	return sb.String()
}

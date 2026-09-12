package macos

import (
	"context"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestMacOSSensorMetadataAndLifecycle(t *testing.T) {
	p := NewProcessSensor()
	if p.Name() != "macos_process_sensor" {
		t.Fatalf("unexpected process sensor name: %s", p.Name())
	}
	if p.Type() != "process" {
		t.Fatalf("unexpected type: %s", p.Type())
	}

	f := NewFileSensor()
	if f.Name() != "macos_file_sensor" {
		t.Fatalf("unexpected file sensor name: %s", f.Name())
	}

	n := NewNetworkSensor()
	if n.Name() != "macos_network_sensor" {
		t.Fatalf("unexpected network sensor name: %s", n.Name())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	ch := make(chan event.Event, 10)
	if err := f.Start(ctx, ch); err != nil {
		t.Fatalf("file sensor start failed: %v", err)
	}
	if err := n.Start(ctx, ch); err != nil {
		t.Fatalf("network sensor start failed: %v", err)
	}
}

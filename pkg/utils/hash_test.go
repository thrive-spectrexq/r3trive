package utils

import (
	"testing"
)

func TestConsistentHashRing(t *testing.T) {
	ring := NewConsistentHashRing(20)

	// Empty ring returns empty node
	if node := ring.GetNode("key1"); node != "" {
		t.Fatalf("expected empty node for empty ring, got %s", node)
	}

	ring.AddNode("worker-1")
	ring.AddNode("worker-2")
	ring.AddNode("worker-3")

	nodeA := ring.GetNode("host_alpha")
	nodeB := ring.GetNode("host_alpha")
	if nodeA != nodeB {
		t.Fatalf("expected deterministic node lookup: %s vs %s", nodeA, nodeB)
	}

	ring.RemoveNode("worker-2")
	nodeAfterRemove := ring.GetNode("host_alpha")
	if nodeAfterRemove == "" {
		t.Fatalf("node lookup after removal should return remaining node")
	}
}

func TestAlertFingerprint(t *testing.T) {
	fp1 := AlertFingerprint("host-01", "R3T-PROC-001", "powershell.exe")
	fp2 := AlertFingerprint("host-01", "R3T-PROC-001", "powershell.exe")
	fp3 := AlertFingerprint("host-02", "R3T-PROC-001", "powershell.exe")

	if fp1 != fp2 {
		t.Fatalf("expected identical fingerprints for same input: %s vs %s", fp1, fp2)
	}
	if fp1 == fp3 {
		t.Fatalf("expected different fingerprints for different hosts")
	}
}

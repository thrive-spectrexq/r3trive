package storage

import (
	"strings"
	"testing"
	"time"
)

func TestEventCursorRoundTrip(t *testing.T) {
	timestamp := time.Date(2026, 11, 8, 15, 0, 0, 123, time.FixedZone("test", 3600))
	cursor := EncodeEventCursor(timestamp, "evt-123")

	gotTimestamp, gotID, err := DecodeEventCursor(cursor)
	if err != nil {
		t.Fatalf("DecodeEventCursor() error = %v", err)
	}
	if !gotTimestamp.Equal(timestamp.UTC()) || gotID != "evt-123" {
		t.Fatalf("decoded cursor = %s/%s, want %s/evt-123", gotTimestamp, gotID, timestamp.UTC())
	}
	if strings.ContainsAny(cursor, "+/=") {
		t.Fatalf("cursor is not URL-safe: %q", cursor)
	}
}

func TestDecodeEventCursorRejectsInvalidValues(t *testing.T) {
	for _, cursor := range []string{"not-a-cursor", "e30"} {
		if _, _, err := DecodeEventCursor(cursor); err == nil {
			t.Errorf("DecodeEventCursor(%q) unexpectedly succeeded", cursor)
		}
	}
}

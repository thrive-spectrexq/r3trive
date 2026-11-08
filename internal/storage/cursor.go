package storage

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type eventCursor struct {
	Timestamp time.Time `json:"timestamp"`
	ID        string    `json:"id"`
}

// EncodeEventCursor creates an opaque cursor for the last event in a page.
func EncodeEventCursor(timestamp time.Time, id string) string {
	payload, _ := json.Marshal(eventCursor{Timestamp: timestamp.UTC(), ID: id})
	return base64.RawURLEncoding.EncodeToString(payload)
}

// DecodeEventCursor validates and decodes an event pagination cursor.
func DecodeEventCursor(value string) (time.Time, string, error) {
	if value == "" {
		return time.Time{}, "", nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid event cursor encoding")
	}

	var cursor eventCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.ID == "" || cursor.Timestamp.IsZero() {
		return time.Time{}, "", fmt.Errorf("invalid event cursor")
	}
	return cursor.Timestamp.UTC(), cursor.ID, nil
}

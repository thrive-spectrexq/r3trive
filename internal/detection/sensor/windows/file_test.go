//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestWindowsFileSensor_Metadata(t *testing.T) {
	s := NewFileSensor()

	if s.Name() != "windows_file_sensor" {
		t.Errorf("expected name windows_file_sensor, got %s", s.Name())
	}

	if s.Type() != "file" {
		t.Errorf("expected type file, got %s", s.Type())
	}

	platforms := s.Platform()
	if len(platforms) != 1 || platforms[0] != "windows" {
		t.Errorf("unexpected platforms: %v", platforms)
	}

	h := s.Health()
	if !h.Healthy {
		t.Errorf("expected initial health to be healthy")
	}

	if err := s.Stop(); err != nil {
		t.Errorf("expected Stop to return nil, got %v", err)
	}

	h = s.Health()
	if h.Status != "stopped" {
		t.Errorf("expected status stopped, got %s", h.Status)
	}
}

func TestWindowsFileSensor_DefaultPaths(t *testing.T) {
	paths := defaultWatchPaths()
	if len(paths) == 0 {
		t.Fatalf("expected default watch paths to contain at least one valid path")
	}

	for _, p := range paths {
		if !dirExists(p) {
			t.Errorf("expected default watch path %s to exist as a directory", p)
		}
	}
}

func TestWindowsFileSensor_MissingDirectoryHandling(t *testing.T) {
	missingPath := filepath.Join(os.TempDir(), "nonexistent_dir_r3trive_test_xyz123")
	s := NewFileSensorWithPaths([]string{missingPath}, false)

	ch := make(chan event.Event, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := s.Start(ctx, ch)
	if err != nil {
		t.Fatalf("expected sensor to handle non-existent directory without error, got %v", err)
	}

	h := s.Health()
	if h.ErrorCount == 0 {
		t.Errorf("expected error count to be incremented for missing directory")
	}
}

func TestWindowsFileSensor_NotificationParsing(t *testing.T) {
	tmpDir := `C:\testdir`

	// Helper to encode a FILE_NOTIFY_INFORMATION record
	encodeRecord := func(nextOffset uint32, action uint32, name string) []byte {
		utf16Chars := syscall.StringToUTF16(name)
		// StringToUTF16 includes terminating NULL, we want length in bytes of the name without NULL
		nameBytes := make([]byte, (len(utf16Chars)-1)*2)
		for i := 0; i < len(utf16Chars)-1; i++ {
			binary.LittleEndian.PutUint16(nameBytes[i*2:i*2+2], utf16Chars[i])
		}
		nameLen := uint32(len(nameBytes))

		recLen := 12 + nameLen
		if nextOffset > 0 && nextOffset > recLen {
			recLen = nextOffset
		}
		buf := make([]byte, recLen)
		binary.LittleEndian.PutUint32(buf[0:4], nextOffset)
		binary.LittleEndian.PutUint32(buf[4:8], action)
		binary.LittleEndian.PutUint32(buf[8:12], nameLen)
		copy(buf[12:], nameBytes)
		return buf
	}

	// Build a buffer with:
	// 1. File added (newfile.txt)
	// 2. File rename pair (oldname.txt -> newname.txt)
	// 3. File moved out (moved_out.txt lone old name -> delete)
	// 4. File added (another.txt)
	// 5. File moved in (moved_in.txt lone new name -> create)
	r1 := encodeRecord(36, fileActionAdded, "newfile.txt")
	r2 := encodeRecord(36, fileActionRenamedOldName, "oldname.txt")
	r3 := encodeRecord(36, fileActionRenamedNewName, "newname.txt")
	r4 := encodeRecord(40, fileActionRenamedOldName, "moved_out.txt")
	r5 := encodeRecord(36, fileActionAdded, "another.txt")
	r6 := encodeRecord(0, fileActionRenamedNewName, "moved_in.txt")

	var buf []byte
	buf = append(buf, r1...)
	buf = append(buf, r2...)
	buf = append(buf, r3...)
	buf = append(buf, r4...)
	buf = append(buf, r5...)
	buf = append(buf, r6...)

	s := NewFileSensorWithPaths([]string{tmpDir}, false)
	ch := make(chan event.Event, 10)
	ctx := context.Background()

	s.parseAndEmitEvents(ctx, tmpDir, buf, "localhost", ch)
	close(ch)

	var events []event.Event
	for ev := range ch {
		events = append(events, ev)
	}

	if len(events) != 5 {
		t.Fatalf("expected 5 events, got %d", len(events))
	}

	// 1. newfile.txt -> FileCreate
	if events[0].Type != event.FileCreate || events[0].Data.File.Name != "newfile.txt" {
		t.Errorf("expected FileCreate for newfile.txt, got type=%s name=%s", events[0].Type, events[0].Data.File.Name)
	}

	// 2. oldname.txt -> newname.txt -> FileRename
	if events[1].Type != event.FileRename || events[1].Data.File.Name != "newname.txt" || filepath.Base(events[1].Data.File.OldPath) != "oldname.txt" {
		t.Errorf("expected FileRename with oldpath, got type=%s name=%s old=%s", events[1].Type, events[1].Data.File.Name, events[1].Data.File.OldPath)
	}

	// 3. moved_out.txt -> FileDelete
	if events[2].Type != event.FileDelete || events[2].Data.File.Name != "moved_out.txt" {
		t.Errorf("expected FileDelete for moved_out.txt, got type=%s name=%s", events[2].Type, events[2].Data.File.Name)
	}

	// 4. another.txt -> FileCreate
	if events[3].Type != event.FileCreate || events[3].Data.File.Name != "another.txt" {
		t.Errorf("expected FileCreate for another.txt, got type=%s name=%s", events[3].Type, events[3].Data.File.Name)
	}

	// 5. moved_in.txt -> FileCreate
	if events[4].Type != event.FileCreate || events[4].Data.File.Name != "moved_in.txt" {
		t.Errorf("expected FileCreate for moved_in.txt, got type=%s name=%s", events[4].Type, events[4].Data.File.Name)
	}
}

func TestWindowsFileSensor_LifecycleAndFileEvents(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "r3trive_file_sensor_test_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	s := NewFileSensorWithPaths([]string{tmpDir}, true)

	ch := make(chan event.Event, 100)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- s.Start(ctx, ch)
	}()

	// Allow sensor goroutines to start and establish directory watch
	time.Sleep(150 * time.Millisecond)

	testFilePath := filepath.Join(tmpDir, "payload.exe")
	renamedFilePath := filepath.Join(tmpDir, "payload_renamed.exe")

	// 1. FileCreate
	if err := os.WriteFile(testFilePath, []byte("initial binary content"), 0600); err != nil {
		t.Fatalf("WriteFile create failed: %v", err)
	}

	// 2. FileModify
	time.Sleep(80 * time.Millisecond)
	if err := os.WriteFile(testFilePath, []byte("modified binary content with extra data"), 0600); err != nil {
		t.Fatalf("WriteFile modify failed: %v", err)
	}

	// 3. FileRename
	time.Sleep(80 * time.Millisecond)
	if err := os.Rename(testFilePath, renamedFilePath); err != nil {
		t.Fatalf("Rename failed: %v", err)
	}

	// 4. FileDelete
	time.Sleep(80 * time.Millisecond)
	if err := os.Remove(renamedFilePath); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	// Wait for all 4 events to be collected
	collected := make(map[event.EventType]bool)
	timeout := time.After(4 * time.Second)

	for len(collected) < 4 {
		select {
		case ev := <-ch:
			if ev.Data.File != nil {
				t.Logf("received file event: type=%s path=%s old=%s size=%d", ev.Type, ev.Data.File.Path, ev.Data.File.OldPath, ev.Data.File.Size)
				collected[ev.Type] = true

				if ev.Sensor != s.Name() {
					t.Errorf("expected sensor %s, got %s", s.Name(), ev.Sensor)
				}
				if ev.Host.OS != "windows" {
					t.Errorf("expected OS windows, got %s", ev.Host.OS)
				}
				if ev.Data.File.Extension != ".exe" {
					t.Errorf("expected extension .exe, got %s", ev.Data.File.Extension)
				}
			}
		case <-timeout:
			break
		}
	}

	if !collected[event.FileCreate] {
		t.Errorf("expected FileCreate event to be collected, got events: %v", collected)
	}
	if !collected[event.FileModify] {
		t.Errorf("expected FileModify event to be collected, got events: %v", collected)
	}
	if !collected[event.FileRename] {
		t.Errorf("expected FileRename event to be collected, got events: %v", collected)
	}
	if !collected[event.FileDelete] {
		t.Errorf("expected FileDelete event to be collected, got events: %v", collected)
	}

	// Graceful shutdown
	_ = s.Stop()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("sensor Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sensor did not stop within timeout")
	}

	h := s.Health()
	if !h.Healthy {
		t.Errorf("expected sensor health to be healthy")
	}
	if h.EventsCollected == 0 {
		t.Errorf("expected events collected > 0, got %d", h.EventsCollected)
	}
}

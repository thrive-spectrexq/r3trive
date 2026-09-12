//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

const (
	FileSensorName = "windows_file_sensor"

	fileActionAdded          = 1
	fileActionRemoved        = 2
	fileActionModified       = 3
	fileActionRenamedOldName = 4
	fileActionRenamedNewName = 5

	fileNotifyFilter = syscall.FILE_NOTIFY_CHANGE_FILE_NAME |
		syscall.FILE_NOTIFY_CHANGE_DIR_NAME |
		syscall.FILE_NOTIFY_CHANGE_ATTRIBUTES |
		syscall.FILE_NOTIFY_CHANGE_SIZE |
		syscall.FILE_NOTIFY_CHANGE_LAST_WRITE |
		syscall.FILE_NOTIFY_CHANGE_CREATION

	fileBufferSize = 65536

	errInvalidHandle    = syscall.Errno(6)
	errOperationAborted = syscall.Errno(995)
)

var (
	modKernel32    = syscall.NewLazyDLL("kernel32.dll")
	procCancelIoEx = modKernel32.NewProc("CancelIoEx")
)

// FileSensor monitors file system activity using native Win32 ReadDirectoryChangesW.
// It watches security-critical directories and emits file lifecycle events without requiring elevated privileges.
type FileSensor struct {
	mu              sync.RWMutex
	paths           []string
	watchSubtree    bool
	handles         []syscall.Handle
	eventsCollected atomic.Int64
	errorCount      atomic.Int64
	lastEventTime   time.Time
	cancel          context.CancelFunc
	running         atomic.Bool
	wg              sync.WaitGroup
}

// NewFileSensor creates a native Windows file sensor targeting default security-critical paths.
func NewFileSensor() *FileSensor {
	return NewFileSensorWithPaths(defaultWatchPaths(), false)
}

// NewFileSensorWithPaths creates a native Windows file sensor for specified directory paths.
func NewFileSensorWithPaths(paths []string, watchSubtree bool) *FileSensor {
	cleaned := make([]string, 0, len(paths))
	for _, p := range paths {
		if p != "" {
			cleaned = append(cleaned, filepath.Clean(p))
		}
	}
	return &FileSensor{
		paths:        cleaned,
		watchSubtree: watchSubtree,
	}
}

// Name returns the sensor identifier.
func (s *FileSensor) Name() string {
	return FileSensorName
}

// Platform returns the supported platform.
func (s *FileSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformWindows}
}

// Type returns the event category.
func (s *FileSensor) Type() string {
	return "file"
}

// Health returns current sensor diagnostics.
func (s *FileSensor) Health() sensor.SensorHealth {
	s.mu.RLock()
	lastTime := s.lastEventTime
	numHandles := len(s.handles)
	s.mu.RUnlock()

	lastTimeStr := ""
	if !lastTime.IsZero() {
		lastTimeStr = lastTime.UTC().Format(time.RFC3339)
	}

	healthy := true
	status := "operational"

	if !s.running.Load() {
		status = "stopped"
	} else if numHandles == 0 {
		healthy = false
		status = "no directories available to watch"
	}

	return sensor.SensorHealth{
		Healthy:         healthy,
		Status:          status,
		EventsCollected: s.eventsCollected.Load(),
		LastEventTime:   lastTimeStr,
		ErrorCount:      s.errorCount.Load(),
	}
}

// Start begins monitoring watched directories via ReadDirectoryChangesW and emits events into ch.
func (s *FileSensor) Start(ctx context.Context, ch chan<- event.Event) error {
	slog.Info("starting Windows native file sensor (ReadDirectoryChangesW)")

	ctx, cancel := context.WithCancel(ctx)
	s.running.Store(true)

	openedHandles := make([]syscall.Handle, 0, len(s.paths))
	activePaths := make([]string, 0, len(s.paths))

	s.mu.Lock()
	s.cancel = cancel
	for _, path := range s.paths {
		h, err := openDirectoryHandle(path)
		if err != nil {
			slog.Warn("skipping unwatched directory", "path", path, "error", err)
			s.errorCount.Add(1)
			continue
		}
		openedHandles = append(openedHandles, h)
		activePaths = append(activePaths, path)
	}
	s.handles = openedHandles
	s.mu.Unlock()

	if len(openedHandles) == 0 {
		slog.Warn("no directories could be opened for ReadDirectoryChangesW monitoring")
	}

	for i, h := range openedHandles {
		dirPath := activePaths[i]
		s.wg.Add(1)
		go s.watchDirectory(ctx, dirPath, h, ch)
	}

	// Wait for context cancellation
	<-ctx.Done()
	slog.Info("stopping Windows native file sensor")
	_ = s.Stop()
	return nil
}

// Stop closes all directory handles, cancels pending I/O operations, and waits for watchers to exit.
func (s *FileSensor) Stop() error {
	s.running.Store(false)

	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	handles := s.handles
	s.handles = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	for _, h := range handles {
		_, _, _ = procCancelIoEx.Call(uintptr(h), 0)
		_ = syscall.CloseHandle(h)
	}

	s.wg.Wait()
	return nil
}

type rawFileNotification struct {
	action   uint32
	fullPath string
}

func parseFileNotifications(dir string, buf []byte) []rawFileNotification {
	var notifs []rawFileNotification
	offset := uint32(0)
	bytesReturned := uint32(len(buf))

	for {
		if offset+12 > bytesReturned {
			break
		}

		nextOffset := binary.LittleEndian.Uint32(buf[offset : offset+4])
		action := binary.LittleEndian.Uint32(buf[offset+4 : offset+8])
		nameLen := binary.LittleEndian.Uint32(buf[offset+8 : offset+12])

		if offset+12+nameLen > bytesReturned {
			break
		}

		rawName := buf[offset+12 : offset+12+nameLen]
		words := make([]uint16, nameLen/2)
		for i := range words {
			words[i] = binary.LittleEndian.Uint16(rawName[i*2 : i*2+2])
		}
		relName := syscall.UTF16ToString(words)
		fullPath := filepath.Join(dir, relName)

		notifs = append(notifs, rawFileNotification{
			action:   action,
			fullPath: fullPath,
		})

		if nextOffset == 0 || nextOffset < 12 || offset+nextOffset >= bytesReturned {
			break
		}
		offset += nextOffset
	}
	return notifs
}

func (s *FileSensor) watchDirectory(ctx context.Context, dir string, handle syscall.Handle, ch chan<- event.Event) {
	defer s.wg.Done()

	// Ensure 4-byte (DWORD) memory alignment required by ReadDirectoryChangesW
	alignedBuf := make([]uint32, fileBufferSize/4)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&alignedBuf[0])), fileBufferSize)
	var bytesReturned uint32

	hostname := getHostname()

	for {
		if !s.running.Load() || ctx.Err() != nil {
			return
		}

		err := syscall.ReadDirectoryChanges(
			handle,
			&buf[0],
			uint32(len(buf)),
			s.watchSubtree,
			fileNotifyFilter,
			&bytesReturned,
			nil,
			0,
		)

		if err != nil {
			// If operation was aborted due to sensor stop or context cancellation, exit cleanly
			if !s.running.Load() || ctx.Err() != nil || errors.Is(err, errOperationAborted) || errors.Is(err, errInvalidHandle) {
				return
			}
			s.errorCount.Add(1)
			slog.Debug("ReadDirectoryChanges error", "dir", dir, "error", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if bytesReturned == 0 {
			// In synchronous ReadDirectoryChangesW, bytesReturned == 0 indicates directory buffer overflow
			s.errorCount.Add(1)
			slog.Warn("ReadDirectoryChanges buffer overflow detected, intermediate changes dropped", "dir", dir)
			continue
		}

		s.parseAndEmitEvents(ctx, dir, buf[:bytesReturned], hostname, ch)
	}
}

func (s *FileSensor) parseAndEmitEvents(ctx context.Context, dir string, buf []byte, hostname string, ch chan<- event.Event) {
	notifs := parseFileNotifications(dir, buf)

	for i := 0; i < len(notifs); i++ {
		n := notifs[i]
		var eventType event.EventType
		var oldPath string

		switch n.action {
		case fileActionAdded:
			eventType = event.FileCreate
		case fileActionRemoved:
			eventType = event.FileDelete
		case fileActionModified:
			eventType = event.FileModify
		case fileActionRenamedOldName:
			if i+1 < len(notifs) && notifs[i+1].action == fileActionRenamedNewName {
				eventType = event.FileRename
				oldPath = n.fullPath
				n.fullPath = notifs[i+1].fullPath
				i++ // consume paired new name
			} else {
				// File was renamed or moved OUT of watched directory
				eventType = event.FileDelete
			}
		case fileActionRenamedNewName:
			// File was renamed or moved INTO watched directory from outside
			eventType = event.FileCreate
		default:
			eventType = event.FileModify
		}

		if eventType == "" {
			continue
		}

		now := time.Now().UTC()
		fileData := &event.FileData{
			Path:      n.fullPath,
			Name:      filepath.Base(n.fullPath),
			Extension: filepath.Ext(n.fullPath),
			OldPath:   oldPath,
		}

		if eventType != event.FileDelete {
			if fi, statErr := os.Stat(n.fullPath); statErr == nil {
				fileData.Size = fi.Size()
			}
		}

		ev := event.Event{
			ID:        fmt.Sprintf("winfile_%s", uuid.New().String()),
			Timestamp: now,
			Host: event.HostInfo{
				Hostname: hostname,
				OS:       "windows",
			},
			Type:     eventType,
			Severity: event.SeverityLow,
			Sensor:   s.Name(),
			Data: event.EventData{
				File: fileData,
			},
		}

		select {
		case ch <- ev:
			s.eventsCollected.Add(1)
			s.mu.Lock()
			s.lastEventTime = now
			s.mu.Unlock()
		case <-ctx.Done():
			return
		}
	}
}

func openDirectoryHandle(path string) (syscall.Handle, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return syscall.InvalidHandle, err
	}

	h, err := syscall.CreateFile(
		pathPtr,
		syscall.FILE_LIST_DIRECTORY,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	return h, nil
}

func defaultWatchPaths() []string {
	var paths []string

	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	system32 := filepath.Join(systemRoot, "System32")
	if dirExists(system32) {
		paths = append(paths, system32)
	}

	publicDir := os.Getenv("PUBLIC")
	if publicDir == "" {
		publicDir = `C:\Users\Public`
	}
	if dirExists(publicDir) {
		paths = append(paths, publicDir)
	}

	progData := os.Getenv("ProgramData")
	if progData == "" {
		progData = `C:\ProgramData`
	}
	if dirExists(progData) {
		paths = append(paths, progData)
	}

	tempDir := os.TempDir()
	if dirExists(tempDir) {
		paths = append(paths, tempDir)
	}

	return paths
}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

var _ sensor.Sensor = (*FileSensor)(nil)

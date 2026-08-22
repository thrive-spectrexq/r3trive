//go:build linux

package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/thrive-spectrexq/r3trive/internal/detection/sensor"
	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

type FileSensor struct {
	fd              int
	watchMap        map[int]string
	mu              sync.RWMutex
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	eventsCollected atomic.Int64
	errorCount      atomic.Int64
	lastEventTime   atomic.Pointer[time.Time]
	healthy         atomic.Bool
	status          atomic.Pointer[string]
}

func NewFileSensor() sensor.Sensor {
	s := &FileSensor{
		watchMap: make(map[int]string),
	}
	s.setStatus("Initialized")
	s.healthy.Store(true)
	return s
}

func (s *FileSensor) Name() string {
	return "linux_file"
}

func (s *FileSensor) Platform() []sensor.Platform {
	return []sensor.Platform{sensor.PlatformLinux}
}

func (s *FileSensor) setStatus(status string) {
	s.status.Store(&status)
}

func (s *FileSensor) Start(ctx context.Context, ch chan<- event.Event) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		s.healthy.Store(false)
		s.setStatus(fmt.Sprintf("Failed to init inotify: %v", err))
		return fmt.Errorf("inotify_init1: %w", err)
	}
	s.fd = fd

	directories := []string{"/tmp", "/etc", "/home", "/var/log", "/usr/bin", "/usr/sbin"}
	for _, dir := range directories {
		// Ignore errors for directories that don't exist
		wd, err := unix.InotifyAddWatch(s.fd, dir, unix.IN_CREATE|unix.IN_MODIFY|unix.IN_DELETE|unix.IN_MOVED_FROM|unix.IN_MOVED_TO)
		if err == nil {
			s.mu.Lock()
			s.watchMap[wd] = dir
			s.mu.Unlock()
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	s.setStatus("Running")
	s.healthy.Store(true)

	s.wg.Add(1)
	go s.monitor(ctx, ch)

	return nil
}

func (s *FileSensor) monitor(ctx context.Context, ch chan<- event.Event) {
	defer s.wg.Done()

	// Create epoll to wait for inotify events or context cancellation
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		s.healthy.Store(false)
		s.setStatus(fmt.Sprintf("EpollCreate1: %v", err))
		return
	}
	defer unix.Close(epfd)

	eventInotify := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(s.fd),
	}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, s.fd, &eventInotify); err != nil {
		s.healthy.Store(false)
		s.setStatus(fmt.Sprintf("EpollCtl: %v", err))
		return
	}

	events := make([]unix.EpollEvent, 1)
	buf := make([]byte, unix.SizeofInotifyEvent*4096)

	hostname, _ := os.Hostname()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := unix.EpollWait(epfd, events, 1000)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			s.errorCount.Add(1)
			continue
		}

		if n == 0 {
			continue // timeout
		}

		nbytes, err := unix.Read(s.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			s.errorCount.Add(1)
			continue
		}

		if nbytes < unix.SizeofInotifyEvent {
			continue
		}

		var offset uint32
		for offset <= uint32(nbytes-unix.SizeofInotifyEvent) {
			rawEvent := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))

			nameLen := rawEvent.Len
			var name string
			if nameLen > 0 {
				nameBytes := buf[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+nameLen]
				// Strip null bytes
				for i, b := range nameBytes {
					if b == 0 {
						name = string(nameBytes[:i])
						break
					}
				}
			}

			s.mu.RLock()
			dir, ok := s.watchMap[int(rawEvent.Wd)]
			s.mu.RUnlock()

			if ok {
				var evType event.EventType
				mask := rawEvent.Mask
				if mask&unix.IN_CREATE != 0 {
					evType = event.FileCreate
				} else if mask&unix.IN_MODIFY != 0 {
					evType = event.FileModify
				} else if mask&unix.IN_DELETE != 0 {
					evType = event.FileDelete
				} else if mask&unix.IN_MOVED_FROM != 0 || mask&unix.IN_MOVED_TO != 0 {
					evType = event.FileRename
				}

				if evType != "" {
					fullPath := filepath.Join(dir, name)

					e := event.Event{
						ID:        fmt.Sprintf("file_%d_%d", rawEvent.Wd, time.Now().UnixNano()),
						Type:      evType,
						Timestamp: time.Now().UTC(),
						Severity:  event.SeverityLow,
						Sensor:    s.Name(),
						Host: event.HostInfo{
							Hostname: hostname,
							OS:       "linux",
						},
						Data: event.EventData{
							File: &event.FileData{
								Path: fullPath,
								Name: filepath.Base(fullPath),
							},
						},
					}

					select {
					case ch <- e:
						s.eventsCollected.Add(1)
						now := time.Now()
						s.lastEventTime.Store(&now)
					default:
						s.errorCount.Add(1)
					}
				}
			}
			offset += unix.SizeofInotifyEvent + nameLen
		}
	}
}

func (s *FileSensor) Stop() error {
	if s.cancel != nil {
		s.cancel()
		s.wg.Wait()
	}
	if s.fd > 0 {
		unix.Close(s.fd)
		s.fd = 0
	}
	s.setStatus("Stopped")
	s.healthy.Store(false)
	return nil
}

func (s *FileSensor) Health() sensor.SensorHealth {
	var lastTimeStr string
	if lt := s.lastEventTime.Load(); lt != nil {
		lastTimeStr = lt.Format(time.RFC3339)
	}

	status := "Unknown"
	if st := s.status.Load(); st != nil {
		status = *st
	}

	return sensor.SensorHealth{
		Healthy:         s.healthy.Load(),
		Status:          status,
		EventsCollected: s.eventsCollected.Load(),
		LastEventTime:   lastTimeStr,
		ErrorCount:      s.errorCount.Load(),
	}
}

//go:build !windows

package security

import (
	"golang.org/x/sys/unix"
)

func lockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Mlock(b)
}

func unlockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Munlock(b)
}

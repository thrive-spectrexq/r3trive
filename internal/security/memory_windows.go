//go:build windows

package security

import (
	"syscall"
	"unsafe"
)

var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procVirtualLock   = modkernel32.NewProc("VirtualLock")
	procVirtualUnlock = modkernel32.NewProc("VirtualUnlock")
)

func lockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	addr := uintptr(unsafe.Pointer(&b[0]))
	size := uintptr(len(b))
	r1, _, err := procVirtualLock.Call(addr, size)
	if r1 == 0 {
		return err
	}
	return nil
}

func unlockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	addr := uintptr(unsafe.Pointer(&b[0]))
	size := uintptr(len(b))
	r1, _, err := procVirtualUnlock.Call(addr, size)
	if r1 == 0 {
		return err
	}
	return nil
}

package security

import (
	"crypto/subtle"
	"errors"
)

var (
	// ErrEmptyBuffer indicates that an empty buffer was provided.
	ErrEmptyBuffer = errors.New("cannot lock empty memory buffer")
)

// Wipe overwrites sensitive byte slices with zeros in memory to prevent
// credential residual exposure, using constant-time comparison to deter compiler dead-store elimination.
func Wipe(b []byte) {
	if len(b) == 0 {
		return
	}
	zeros := make([]byte, len(b))
	subtle.ConstantTimeCopy(1, b, zeros)
	// Explicit secondary zeroing loop
	for i := range b {
		b[i] = 0
	}
}

// LockBuffer locks a memory region into physical RAM, preventing it from being paged to disk or swap.
func LockBuffer(b []byte) error {
	if len(b) == 0 {
		return ErrEmptyBuffer
	}
	return lockMemory(b)
}

// UnlockBuffer releases a previously locked memory region.
func UnlockBuffer(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unlockMemory(b)
}

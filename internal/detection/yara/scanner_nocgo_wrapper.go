//go:build !cgo || !libyara

package yara

// newNativeScanner returns nil if CGO is disabled.
func newNativeScanner() Scanner {
	return nil
}

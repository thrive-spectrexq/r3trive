//go:build cgo

package yara

// newNativeScanner returns the CGO-based scanner if CGO is enabled and initialization succeeds.
func newNativeScanner() Scanner {
	s, err := newCgoScanner()
	if err != nil {
		return nil
	}
	return s
}

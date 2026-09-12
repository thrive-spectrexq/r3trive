//go:build linux

package linux

import (
	"os"
	"strconv"
	"strings"
)

// KernelVersion represents a parsed Linux kernel version (major.minor.patch).
type KernelVersion struct {
	Major int
	Minor int
	Patch int
}

// ParseKernelVersion parses a uname release string like "5.15.0-76-generic".
func ParseKernelVersion(release string) KernelVersion {
	parts := strings.Split(release, "-")[0]
	nums := strings.Split(parts, ".")
	var kv KernelVersion
	if len(nums) >= 1 {
		kv.Major, _ = strconv.Atoi(nums[0])
	}
	if len(nums) >= 2 {
		kv.Minor, _ = strconv.Atoi(nums[1])
	}
	if len(nums) >= 3 {
		kv.Patch, _ = strconv.Atoi(nums[2])
	}
	return kv
}

// SupportsCORE returns true if the kernel supports BPF CO-RE (requires kernel >= 5.4 and /sys/kernel/btf/vmlinux).
func SupportsCORE() bool {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return false
	}
	return true
}

// BPFManager abstracts eBPF CO-RE loading and fallback negotiations.
type BPFManager struct {
	coreSupported bool
}

// NewBPFManager creates a new BPFManager with kernel capability detection.
func NewBPFManager() *BPFManager {
	return &BPFManager{
		coreSupported: SupportsCORE(),
	}
}

// IsCORESupported returns whether CO-RE eBPF is available on this system.
func (m *BPFManager) IsCORESupported() bool {
	return m.coreSupported
}

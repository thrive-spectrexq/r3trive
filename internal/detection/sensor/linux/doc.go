// Package process implements the Linux process sensor using procfs polling
// with an upgrade path to eBPF (kernel 5.4+).
package process

// TODO: Implement Linux process sensor using /proc polling.
// Phase 2 will add eBPF support via cilium/ebpf for kernel 5.4+.
//
// See SYSTEM_ARCHITECTURE.md §4.3.1 (Linux Sensors) for requirements:
// - eBPF (kernel 5.8+) / fallback: /proc polling
// - exec, fork, exit events
// - CO-RE (Compile Once, Run Everywhere) for kernel compatibility

// Package process implements the Windows process sensor using the
// Windows API (CreateToolhelp32Snapshot) for process enumeration.
package process

// TODO: Implement Windows process sensor using CreateToolhelp32Snapshot or ETW.
// For MVP, the mock sensor is used. This package will contain the native
// Windows implementation using syscall/windows packages.
//
// See SYSTEM_ARCHITECTURE.md §4.3.1 (Windows Sensors) for requirements:
// - ETW (Event Tracing for Windows) for process create/inject/exit
// - Command line capture
// - Parent process resolution
// - User/SID resolution

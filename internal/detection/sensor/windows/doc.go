//go:build windows

// Package windows implements the Windows sensors using ETW.
package windows

// TODO: Implement Windows process sensor using CreateToolhelp32Snapshot or ETW.
// For MVP, the mock sensor is used. This package will contain the native
// Windows implementation using syscall/windows packages.
//
// See SYSTEM_ARCHITECTURE.md Â§4.3.1 (Windows Sensors) for requirements:
// - ETW (Event Tracing for Windows) for process create/inject/exit
// - Command line capture
// - Parent process resolution
// - User/SID resolution



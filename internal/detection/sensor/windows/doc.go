//go:build windows

// Package windows implements native Windows sensors using unprivileged Win32 APIs
// (Toolhelp32 for processes, iphlpapi for network connections, ReadDirectoryChangesW
// for file system activity).
package windows

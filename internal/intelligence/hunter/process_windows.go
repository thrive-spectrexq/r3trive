//go:build windows

package hunter

import (
	"syscall"
	"unsafe"
)

func getRunningProcesses() ([]ProcessInfo, error) {
	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = syscall.CloseHandle(handle) }()

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := syscall.Process32First(handle, &entry); err != nil {
		return nil, err
	}

	var procs []ProcessInfo
	for {
		exeName := syscall.UTF16ToString(entry.ExeFile[:])
		procs = append(procs, ProcessInfo{
			PID:  int(entry.ProcessID),
			PPID: int(entry.ParentProcessID),
			Name: exeName,
		})
		if err := syscall.Process32Next(handle, &entry); err != nil {
			break
		}
	}
	return procs, nil
}

//go:build windows

package orchestrator

import "syscall"

func pidAlive(pid int) bool {
	h, err := syscall.OpenProcess(0x1000, false, uint32(pid)) // PROCESS_QUERY_LIMITED_INFORMATION
	if err != nil {
		return false
	}
	syscall.CloseHandle(h)
	return true
}

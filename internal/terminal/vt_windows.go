//go:build windows

package terminal

import (
	"os"
	"syscall"
	"unsafe"
)

// enableVT turns on ANSI escape processing; false means the console refused it.
func enableVT(f *os.File) bool {
	k := syscall.NewLazyDLL("kernel32.dll")
	get, set := k.NewProc("GetConsoleMode"), k.NewProc("SetConsoleMode")
	var mode uint32
	if r, _, _ := get.Call(f.Fd(), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return false
	}
	r, _, _ := set.Call(f.Fd(), uintptr(mode|0x0004)) // ENABLE_VIRTUAL_TERMINAL_PROCESSING
	return r != 0
}

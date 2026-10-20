//go:build windows

package terminal

import (
	"os"

	"golang.org/x/sys/windows"
)

// size returns the visible console window size, or zeros when unknown.
func size(f *os.File) (w, h int) {
	var i windows.ConsoleScreenBufferInfo
	if windows.GetConsoleScreenBufferInfo(windows.Handle(f.Fd()), &i) != nil {
		return
	}
	return int(i.Window.Right-i.Window.Left) + 1, int(i.Window.Bottom-i.Window.Top) + 1
}

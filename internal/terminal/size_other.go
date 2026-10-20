//go:build !windows

package terminal

import (
	"os"

	"golang.org/x/sys/unix"
)

// size returns the terminal size, or zeros when unknown.
func size(f *os.File) (w, h int) {
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return
	}
	return int(ws.Col), int(ws.Row)
}

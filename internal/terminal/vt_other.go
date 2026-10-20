//go:build !windows

package terminal

import "os"

func enableVT(*os.File) bool { return true }

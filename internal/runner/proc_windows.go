//go:build windows

package runner

import "os/exec"

// configure is a no-op on Windows; exec's default Cancel kills the process.
func configure(cmd *exec.Cmd) {}

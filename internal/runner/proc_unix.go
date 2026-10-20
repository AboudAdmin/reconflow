//go:build !windows

package runner

import (
	"os/exec"
	"syscall"
)

// configure puts the child in its own process group and terminates the whole
// group on cancellation (SIGTERM first; WaitDelay then force-kills the child).
func configure(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}

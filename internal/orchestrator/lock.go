package orchestrator

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var ErrLocked = errors.New("another ReconFlow process is already working on this target")

// acquire takes an exclusive per-target lock file containing the owner PID.
// A lock whose PID is no longer alive is treated as stale and replaced.
func acquire(path string) (release func(), err error) {
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		b, rerr := os.ReadFile(path)
		pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		if rerr == nil && pid > 0 && pidAlive(pid) {
			return nil, fmt.Errorf("%w (pid %d, lock %s)", ErrLocked, pid, path)
		}
		os.Remove(path) // stale
	}
	return nil, ErrLocked
}

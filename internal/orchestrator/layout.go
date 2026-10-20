package orchestrator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Layout is the on-disk structure for one target. Everything lives under
// <data_dir>/targets/<target>/ and every directory is created 0700.
type Layout struct {
	Root, Target, Runs, JS, JSFiles, Reports, Logs string
}

func safeName(target string) string {
	return strings.NewReplacer(":", "_", "/", "_", "\\", "_").Replace(target)
}

// EnsureDir creates dir (0700) and refuses symlinks or non-directories.
func EnsureDir(dir string) error {
	if st, err := os.Lstat(dir); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("refusing to use %s: not a plain directory (symlink or file)", dir)
		}
		return nil
	}
	return os.MkdirAll(dir, 0o700)
}

func NewLayout(dataDir, target string) (Layout, error) {
	root := filepath.Join(dataDir, "targets")
	t := filepath.Join(root, safeName(target))
	if rel, err := filepath.Rel(root, t); err != nil || strings.HasPrefix(rel, "..") || rel == "." {
		return Layout{}, fmt.Errorf("unsafe target path for %q", target)
	}
	l := Layout{Root: dataDir, Target: t, Runs: filepath.Join(t, "runs"), JS: filepath.Join(t, "javascript"),
		JSFiles: filepath.Join(t, "javascript", "files"), Reports: filepath.Join(t, "reports"), Logs: filepath.Join(t, "logs")}
	for _, d := range []string{dataDir, root, t, l.Runs, l.JS, l.JSFiles, l.Reports, l.Logs} {
		if err := EnsureDir(d); err != nil {
			return l, err
		}
	}
	return l, nil
}

func (l Layout) RunDir(id string) string { return filepath.Join(l.Runs, id) }

// Package testutil turns the running test binary into configurable fake
// external tools (no shell scripts, works on every OS). Test packages call
// MaybeRunFake first thing in TestMain.
package testutil

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type Behavior struct {
	Help      string   `json:"help"`
	Version   string   `json:"version"`
	Stdout    []string `json:"stdout"`
	Stderr    string   `json:"stderr"`
	Exit      int      `json:"exit"`
	SleepMS   int      `json:"sleep_ms"`
	FailFirst int      `json:"fail_first"` // fail (exit Exit, no stdout) this many invocations first
	ArgsLog   string   `json:"args_log"`
}

// MaybeRunFake acts as the fake tool and exits when a sidecar file exists.
func MaybeRunFake() {
	b, err := os.ReadFile(os.Args[0] + ".fake")
	if err != nil {
		return
	}
	var f Behavior
	json.Unmarshal(b, &f)
	args := os.Args[1:]
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "-help") {
		fmt.Fprintln(os.Stderr, f.Help)
		os.Exit(0)
	}
	if len(args) >= 1 && (args[0] == "-version" || args[0] == "--version") {
		fmt.Fprintln(os.Stderr, f.Version)
		os.Exit(0)
	}
	if f.ArgsLog != "" {
		if lf, err := os.OpenFile(f.ArgsLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			json.NewEncoder(lf).Encode(args)
			lf.Close()
		}
	}
	if f.SleepMS > 0 {
		time.Sleep(time.Duration(f.SleepMS) * time.Millisecond)
	}
	if f.FailFirst > 0 {
		cp := os.Args[0] + ".count"
		n := 0
		if c, err := os.ReadFile(cp); err == nil {
			n, _ = strconv.Atoi(string(c))
		}
		os.WriteFile(cp, []byte(strconv.Itoa(n+1)), 0o600)
		if n < f.FailFirst {
			fmt.Fprintln(os.Stderr, f.Stderr)
			os.Exit(f.Exit)
		}
	}
	for _, l := range f.Stdout {
		fmt.Println(l)
	}
	if f.Stderr != "" && f.FailFirst == 0 {
		fmt.Fprintln(os.Stderr, f.Stderr)
	}
	if f.FailFirst == 0 {
		os.Exit(f.Exit)
	}
	os.Exit(0)
}

// Install makes dir/name a fake tool with behaviour b and returns its path.
func Install(t testing.TB, dir, name string, b Behavior) string {
	t.Helper()
	exe := name
	if filepath.Ext(os.Args[0]) == ".exe" {
		exe += ".exe"
	}
	dst := filepath.Join(dir, exe)
	if _, err := os.Lstat(dst); err == nil {
		// already installed: only the sidecar changes (never rewrite a possibly hard-linked binary)
	} else if err := os.Link(os.Args[0], dst); err != nil {
		src, err := os.Open(os.Args[0])
		if err != nil {
			t.Fatal(err)
		}
		defer src.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(out, src); err != nil {
			t.Fatal(err)
		}
		out.Close()
	}
	j, _ := json.Marshal(b)
	if err := os.WriteFile(dst+".fake", j, 0o600); err != nil {
		t.Fatal(err)
	}
	return dst
}

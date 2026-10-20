package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as a fake external tool (see TestMain).
func TestMain(m *testing.M) {
	switch os.Getenv("RF_HELPER") {
	case "args":
		for _, a := range os.Args[1:] {
			fmt.Println(a)
		}
		fmt.Println("SECRET=" + os.Getenv("RF_SECRET"))
		os.Exit(0)
	case "big":
		fmt.Println("ok")
		fmt.Println(strings.Repeat("x", 3<<20))
		fmt.Println("after")
		os.Exit(0)
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	case "fail":
		fmt.Fprintln(os.Stderr, "boom: connection reset")
		os.Exit(3)
	}
	os.Exit(m.Run())
}

func spec(mode string, args ...string) Spec {
	return Spec{Path: os.Args[0], Args: args, ExtraEnv: []string{"RF_HELPER=" + mode}, Timeout: 10 * time.Second, Grace: time.Second}
}

func TestArgsNotInterpretedAndEnvControlled(t *testing.T) {
	t.Setenv("RF_SECRET", "leak")
	var got []string
	s := spec("args", "example.com; touch /tmp/pwn", "$(id)", "a b")
	s.OnLine = func(b []byte) { got = append(got, string(b)) }
	r := Run(context.Background(), s)
	if r.ExitCode != 0 || len(got) != 4 || got[0] != "example.com; touch /tmp/pwn" || got[1] != "$(id)" || got[2] != "a b" {
		t.Fatalf("args mangled: %v %+v", got, r)
	}
	if got[3] != "SECRET=" {
		t.Errorf("parent env leaked: %q", got[3])
	}
}

func TestOversizedLinesAndRawCap(t *testing.T) {
	var lines []string
	s := spec("big")
	s.MaxLine = 1 << 10
	s.MaxRaw = 100
	s.RawPath = filepath.Join(t.TempDir(), "raw")
	s.OnLine = func(b []byte) { lines = append(lines, string(b)) }
	r := Run(context.Background(), s)
	if len(lines) != 2 || lines[0] != "ok" || lines[1] != "after" || r.LongLines != 1 || !r.Truncated {
		t.Fatalf("lines=%v res=%+v", lines, r)
	}
	if st, _ := os.Stat(s.RawPath); st.Size() > 100 {
		t.Errorf("raw file exceeded cap: %d", st.Size())
	}
}

func TestTimeoutCancelFailureAndMissing(t *testing.T) {
	s := spec("sleep")
	s.Timeout = 300 * time.Millisecond
	if r := Run(context.Background(), s); !r.TimedOut {
		t.Errorf("want timeout: %+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	start := time.Now()
	if r := Run(ctx, spec("sleep")); !r.Cancelled || time.Since(start) > 5*time.Second {
		t.Errorf("want prompt cancel: %+v after %v", r, time.Since(start))
	}
	if r := Run(context.Background(), spec("fail")); r.ExitCode != 3 || !strings.Contains(r.Stderr, "connection reset") || r.Err != nil {
		t.Errorf("fail: %+v", r)
	}
	if r := Run(context.Background(), Spec{Path: filepath.Join(t.TempDir(), "nope")}); r.Err == nil {
		t.Error("missing binary must report Err")
	}
}

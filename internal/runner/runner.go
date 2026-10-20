// Package runner executes external tools safely: argument arrays only, a
// controlled environment, bounded output, timeouts and context cancellation.
package runner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"
)

type Spec struct {
	Path      string
	Args      []string
	Dir       string
	ExtraEnv  []string
	Timeout   time.Duration
	Grace     time.Duration
	MaxRaw    int64        // bytes of stdout kept in RawPath; further output is still parsed
	MaxLine   int          // longer lines are dropped (and counted)
	RawPath   string       // optional evidence file (0600)
	RawAppend bool         // append to RawPath instead of truncating (several processes, one stage)
	OnLine    func([]byte) // called for each stdout line; slice valid only during the call
	StderrCap int
}

type Result struct {
	ExitCode  int
	Stderr    string
	Lines     int
	LongLines int
	Bytes     int64
	Truncated bool // raw evidence file hit MaxRaw
	TimedOut  bool
	Cancelled bool
	Err       error // start failure or unexpected wait error
}

// ControlledEnv passes only what tools need to run; no inherited secrets.
func ControlledEnv(extra []string) []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return append(env, extra...)
}

type capBuf struct {
	b   bytes.Buffer
	cap int
}

func (c *capBuf) Write(p []byte) (int, error) {
	if room := c.cap - c.b.Len(); room > 0 {
		if len(p) > room {
			c.b.Write(p[:room])
		} else {
			c.b.Write(p)
		}
	}
	return len(p), nil
}

func Run(ctx context.Context, s Spec) Result {
	var res Result
	if s.Timeout <= 0 {
		s.Timeout = 10 * time.Minute
	}
	if s.StderrCap <= 0 {
		s.StderrCap = 4096
	}
	if s.MaxLine <= 0 {
		s.MaxLine = 1 << 20
	}
	if s.Grace <= 0 {
		s.Grace = 5 * time.Second
	}
	tctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	cmd := exec.CommandContext(tctx, s.Path, s.Args...) // no shell: args are never interpreted
	cmd.Dir = s.Dir
	cmd.Env = ControlledEnv(s.ExtraEnv)
	cmd.Stdin = nil
	configure(cmd)
	cmd.WaitDelay = s.Grace
	stderr := &capBuf{cap: s.StderrCap}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		res.Err = err
		return res
	}
	var raw *os.File
	if s.RawPath != "" {
		flag := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		if s.RawAppend {
			flag = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		}
		if raw, err = os.OpenFile(s.RawPath, flag, 0o600); err != nil {
			res.Err = err
			return res
		}
		defer raw.Close()
	}
	if err := cmd.Start(); err != nil {
		res.Err = err
		res.ExitCode = -1
		return res
	}
	br := bufio.NewReaderSize(out, 64<<10)
	for {
		line, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull { // oversized line: drain and count, never buffer it
			res.LongLines++
			for err == bufio.ErrBufferFull {
				res.Bytes += int64(len(line))
				_, err = br.ReadSlice('\n')
			}
			if err != nil {
				break
			}
			continue
		}
		if len(line) > 0 {
			res.Bytes += int64(len(line))
			if raw != nil {
				if res.Bytes <= s.MaxRaw {
					raw.Write(line)
				} else {
					res.Truncated = true
				}
			}
			t := bytes.TrimRight(line, "\r\n")
			if len(t) > s.MaxLine {
				res.LongLines++
			} else if len(t) > 0 {
				res.Lines++
				if s.OnLine != nil {
					s.OnLine(t)
				}
			}
		}
		if err != nil {
			break
		}
	}
	io.Copy(io.Discard, br)
	werr := cmd.Wait()
	res.Stderr = stderr.b.String()
	res.ExitCode = cmd.ProcessState.ExitCode()
	switch {
	case errors.Is(tctx.Err(), context.DeadlineExceeded):
		res.TimedOut = true
	case ctx.Err() != nil:
		res.Cancelled = true
	case werr != nil:
		var ee *exec.ExitError
		if !errors.As(werr, &ee) {
			res.Err = werr
		}
	}
	return res
}

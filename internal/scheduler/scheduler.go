// Package scheduler runs a DAG of tasks with bounded concurrency, finite
// retries with jittered exponential backoff, and cooperative cancellation.
package scheduler

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"reconflow/internal/model"
)

type Outcome struct {
	Status    model.Status
	Err       error
	Retryable bool // only honoured when Status is Failed/Partial and Err != nil
}

type Task struct {
	ID   string
	Hard []string // must finish Success or Partial, else this task is skipped
	Soft []string // must merely finish (any status) before this task starts
	Run  func(ctx context.Context, attempt int) Outcome
}

type Options struct {
	MaxParallel int
	MaxRetries  int
	BackoffBase time.Duration
	BackoffMax  time.Duration
	Sleep       func(ctx context.Context, d time.Duration) // test hook
}

type Hooks struct {
	OnStart func(id string)
	OnRetry func(id string, attempt int, delay time.Duration, err error)
	OnDone  func(id string, o Outcome)
	OnSkip  func(id, reason string)
}

// Backoff returns the delay before retry number attempt (1-based): the
// exponential value base*2^(attempt-1) capped at max, with "equal jitter"
// so the result lies in [d/2, d].
func Backoff(attempt int, base, max time.Duration, r *rand.Rand) time.Duration {
	d := base
	for i := 1; i < attempt && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	half := d / 2
	if half <= 0 {
		return d
	}
	return half + time.Duration(r.Int63n(int64(half)+1))
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// Run executes tasks; it returns once every task has a terminal outcome.
// Cyclic or unknown dependencies are rejected before anything runs.
func Run(ctx context.Context, tasks []Task, o Options, h Hooks) (map[string]Outcome, error) {
	idx := map[string]*Task{}
	for i := range tasks {
		idx[tasks[i].ID] = &tasks[i]
	}
	for _, t := range tasks {
		for _, d := range append(append([]string{}, t.Hard...), t.Soft...) {
			if idx[d] == nil {
				return nil, fmt.Errorf("task %s depends on unknown task %s", t.ID, d)
			}
		}
	}
	if cyc := findCycle(tasks, idx); cyc != "" {
		return nil, fmt.Errorf("dependency cycle involving %s", cyc)
	}
	if o.MaxParallel < 1 {
		o.MaxParallel = 1
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	done := map[string]chan struct{}{}
	for _, t := range tasks {
		done[t.ID] = make(chan struct{})
	}
	var mu sync.Mutex
	out := map[string]Outcome{}
	sem := make(chan struct{}, o.MaxParallel)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var rmu sync.Mutex
	var wg sync.WaitGroup

	finish := func(id string, oc Outcome) {
		mu.Lock()
		out[id] = oc
		mu.Unlock()
		close(done[id])
	}
	for i := range tasks {
		t := tasks[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, d := range append(append([]string{}, t.Hard...), t.Soft...) {
				<-done[d]
			}
			if ctx.Err() != nil {
				finish(t.ID, Outcome{Status: model.Cancelled, Err: ctx.Err()})
				return
			}
			mu.Lock()
			for _, d := range t.Hard {
				if s := out[d].Status; s != model.Success && s != model.Partial {
					mu.Unlock()
					reason := fmt.Sprintf("prerequisite %s ended %s", d, s)
					if h.OnSkip != nil {
						h.OnSkip(t.ID, reason)
					}
					finish(t.ID, Outcome{Status: model.Skipped, Err: fmt.Errorf("%s", reason)})
					return
				}
			}
			mu.Unlock()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				finish(t.ID, Outcome{Status: model.Cancelled, Err: ctx.Err()})
				return
			}
			defer func() { <-sem }()
			if h.OnStart != nil {
				h.OnStart(t.ID)
			}
			var oc Outcome
			for attempt := 0; ; attempt++ {
				oc = t.Run(ctx, attempt)
				if ctx.Err() != nil && oc.Status != model.Success {
					oc.Status = model.Cancelled
				}
				retry := oc.Retryable && oc.Err != nil && (oc.Status == model.Failed || oc.Status == model.Partial) &&
					attempt < o.MaxRetries && ctx.Err() == nil
				if !retry {
					break
				}
				rmu.Lock()
				d := Backoff(attempt+1, o.BackoffBase, o.BackoffMax, rng)
				rmu.Unlock()
				if h.OnRetry != nil {
					h.OnRetry(t.ID, attempt+1, d, oc.Err)
				}
				o.Sleep(ctx, d)
			}
			if h.OnDone != nil {
				h.OnDone(t.ID, oc)
			}
			finish(t.ID, oc)
		}()
	}
	wg.Wait()
	return out, nil
}

func findCycle(tasks []Task, idx map[string]*Task) string {
	state := map[string]int{}
	var visit func(id string) string
	visit = func(id string) string {
		switch state[id] {
		case 1:
			return id
		case 2:
			return ""
		}
		state[id] = 1
		t := idx[id]
		for _, d := range append(append([]string{}, t.Hard...), t.Soft...) {
			if c := visit(d); c != "" {
				return c
			}
		}
		state[id] = 2
		return ""
	}
	for _, t := range tasks {
		if c := visit(t.ID); c != "" {
			return c
		}
	}
	return ""
}

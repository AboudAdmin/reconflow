package scheduler

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"reconflow/internal/model"
)

func ok(context.Context, int) Outcome { return Outcome{Status: model.Success} }

func noSleep(context.Context, time.Duration) {}

func TestBackoffBounds(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for a := 1; a <= 12; a++ {
		for i := 0; i < 200; i++ {
			d := Backoff(a, time.Second, 10*time.Second, r)
			full := time.Second << (a - 1)
			if full > 10*time.Second || full <= 0 {
				full = 10 * time.Second
			}
			if d < full/2 || d > full {
				t.Fatalf("attempt %d: %v outside [%v,%v]", a, d, full/2, full)
			}
		}
	}
}

func TestDependenciesAndSkip(t *testing.T) {
	var order []string
	var mu sync.Mutex
	rec := func(id string, st model.Status) func(context.Context, int) Outcome {
		return func(context.Context, int) Outcome {
			mu.Lock()
			order = append(order, id)
			mu.Unlock()
			return Outcome{Status: st, Err: errors.New("x")}
		}
	}
	tasks := []Task{
		{ID: "a", Run: rec("a", model.Failed)},
		{ID: "b", Run: rec("b", model.Success)},
		{ID: "c", Hard: []string{"a"}, Run: rec("c", model.Success)}, // skipped: a failed
		{ID: "d", Soft: []string{"a"}, Hard: []string{"b"}, Run: rec("d", model.Success)},
	}
	res, err := Run(context.Background(), tasks, Options{MaxParallel: 4}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if res["c"].Status != model.Skipped || res["d"].Status != model.Success || res["a"].Status != model.Failed {
		t.Fatalf("%+v", res)
	}
	for _, id := range order {
		if id == "c" {
			t.Fatal("skipped task must not run")
		}
	}
}

func TestCycleAndUnknownRejected(t *testing.T) {
	if _, err := Run(context.Background(), []Task{{ID: "a", Hard: []string{"b"}, Run: ok}, {ID: "b", Hard: []string{"a"}, Run: ok}}, Options{}, Hooks{}); err == nil {
		t.Error("cycle accepted")
	}
	if _, err := Run(context.Background(), []Task{{ID: "a", Soft: []string{"zz"}, Run: ok}}, Options{}, Hooks{}); err == nil {
		t.Error("unknown dep accepted")
	}
}

func TestBoundedConcurrency(t *testing.T) {
	var cur, peak int32
	var tasks []Task
	for i := 0; i < 12; i++ {
		tasks = append(tasks, Task{ID: string(rune('a' + i)), Run: func(context.Context, int) Outcome {
			n := atomic.AddInt32(&cur, 1)
			for {
				p := atomic.LoadInt32(&peak)
				if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			atomic.AddInt32(&cur, -1)
			return Outcome{Status: model.Success}
		}})
	}
	Run(context.Background(), tasks, Options{MaxParallel: 3}, Hooks{})
	if peak > 3 || peak < 2 {
		t.Fatalf("peak concurrency %d, want 2..3", peak)
	}
}

func TestRetryLimitsAndPermanentErrors(t *testing.T) {
	var transient, permanent int32
	retries := 0
	tasks := []Task{
		{ID: "t", Run: func(_ context.Context, a int) Outcome {
			atomic.AddInt32(&transient, 1)
			return Outcome{Status: model.Failed, Err: errors.New("reset"), Retryable: true}
		}},
		{ID: "p", Run: func(_ context.Context, a int) Outcome {
			atomic.AddInt32(&permanent, 1)
			return Outcome{Status: model.Failed, Err: errors.New("usage"), Retryable: false}
		}},
		{ID: "r", Run: func(_ context.Context, a int) Outcome {
			if a < 2 {
				return Outcome{Status: model.Failed, Err: errors.New("flaky"), Retryable: true}
			}
			return Outcome{Status: model.Success}
		}},
	}
	var mu sync.Mutex
	res, _ := Run(context.Background(), tasks, Options{MaxParallel: 3, MaxRetries: 2, BackoffBase: time.Millisecond, BackoffMax: time.Millisecond, Sleep: noSleep},
		Hooks{OnRetry: func(string, int, time.Duration, error) { mu.Lock(); retries++; mu.Unlock() }})
	if transient != 3 || permanent != 1 || res["r"].Status != model.Success || retries != 2+2+0 {
		t.Fatalf("transient=%d permanent=%d retries=%d res=%+v", transient, permanent, retries, res)
	}
}

func TestCancellationStopsScheduling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	tasks := []Task{
		{ID: "a", Run: func(c context.Context, _ int) Outcome {
			close(started)
			<-c.Done()
			return Outcome{Status: model.Failed, Err: c.Err()}
		}},
		{ID: "b", Soft: []string{"a"}, Run: func(context.Context, int) Outcome {
			t.Error("b must not start after cancel")
			return Outcome{Status: model.Success}
		}},
	}
	go func() { <-started; cancel() }()
	res, _ := Run(ctx, tasks, Options{MaxParallel: 1}, Hooks{})
	if res["a"].Status != model.Cancelled || res["b"].Status != model.Cancelled {
		t.Fatalf("%+v", res)
	}
}

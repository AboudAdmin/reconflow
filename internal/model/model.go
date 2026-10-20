// Package model holds shared domain types with no I/O and no rendering.
package model

import (
	"sync"
	"time"
)

type Status string

const (
	Queued    Status = "queued"
	Running   Status = "running"
	Success   Status = "success"
	Partial   Status = "partial"
	Failed    Status = "failed"
	Skipped   Status = "skipped"
	Cancelled Status = "cancelled"
)

// Terminal reports whether the status is final.
func (s Status) Terminal() bool {
	return s != Queued && s != Running
}

// Entity kinds persisted in the entities table.
const (
	KindSubdomain = "subdomain"
	KindDNS       = "dns"
	KindService   = "service"
	KindURL       = "url"
)

// Obs is one normalized observation with provenance, as produced by an adapter.
type Obs struct {
	Kind       string
	Key        string
	Tool       string
	Input      string // what was fed to the tool (host, URL, ...)
	ObservedAt time.Time
	Attrs      map[string]any // material attributes; hashed for change detection
	Meta       map[string]any // non-material context (e.g. origin=historical)
}

// Candidate types produced by static JavaScript analysis.
const (
	CandURL       = "url"
	CandEndpoint  = "endpoint"
	CandParam     = "parameter"
	CandGraphQL   = "graphql"
	CandWebSocket = "websocket"
	CandSourceMap = "sourcemap_ref"
	CandLibrary   = "library"
)

const VerifStatic = "static_unverified"

type Event struct {
	Time time.Time
	Text string
}

type StageState struct {
	ID       string
	Title    string
	Tool     string
	Passive  bool
	Status   Status
	Detail   string
	Started  time.Time
	Finished time.Time
	Retries  int
	Output   int
}

// Tracker is the thread-safe live state read by the terminal renderer.
type Tracker struct {
	mu      sync.Mutex
	Target  string
	RunID   string
	Started time.Time
	Stages  []*StageState
	Counts  map[string]int
	Active  int
	Events  []Event
	Errors  []string
	Reports []string
	Note    string
	EvTotal int
	version uint64
}

type Snapshot struct {
	EvTotal             int
	Target, RunID, Note string
	Started             time.Time
	Stages              []StageState
	Counts              map[string]int
	Events              []Event
	Errors              []string
	Reports             []string
}

func NewTracker(target, runID string, stages []*StageState) *Tracker {
	return &Tracker{Target: target, RunID: runID, Started: time.Now(), Stages: stages, Counts: map[string]int{}}
}

func (t *Tracker) With(f func(t *Tracker)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f(t)
	t.version++
}

func (t *Tracker) Version() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.version
}

func (t *Tracker) Event(text string) {
	t.With(func(t *Tracker) {
		t.Events = append(t.Events, Event{time.Now(), text})
		t.EvTotal++
		if len(t.Events) > 50 {
			t.Events = t.Events[len(t.Events)-50:]
		}
	})
}

func (t *Tracker) AddError(text string) {
	t.With(func(t *Tracker) {
		t.Errors = append(t.Errors, text)
		if len(t.Errors) > 20 {
			t.Errors = t.Errors[len(t.Errors)-20:]
		}
	})
}

func (t *Tracker) Stage(id string, f func(s *StageState)) {
	t.With(func(t *Tracker) {
		for _, s := range t.Stages {
			if s.ID == id {
				f(s)
			}
		}
	})
}

func (t *Tracker) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := Snapshot{EvTotal: t.EvTotal, Target: t.Target, RunID: t.RunID, Note: t.Note, Started: t.Started,
		Counts: map[string]int{}, Events: append([]Event(nil), t.Events...),
		Errors: append([]string(nil), t.Errors...), Reports: append([]string(nil), t.Reports...)}
	for _, st := range t.Stages {
		s.Stages = append(s.Stages, *st)
	}
	for k, v := range t.Counts {
		s.Counts[k] = v
	}
	return s
}

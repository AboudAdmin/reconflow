// Package storage is the SQLite source of truth for runs, observations,
// provenance, JavaScript intelligence and checkpoints.
package storage

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"reconflow/internal/model"
)

const SchemaVersion = 1

var migrations = []string{`
CREATE TABLE targets(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
CREATE TABLE runs(
  id TEXT PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES targets(id),
  status TEXT NOT NULL, passive INTEGER NOT NULL, scope_hash TEXT NOT NULL, config_hash TEXT NOT NULL,
  started_at TEXT NOT NULL, finished_at TEXT, baseline_run_id TEXT, baseline_note TEXT,
  out_dir TEXT NOT NULL, version TEXT NOT NULL, plan TEXT NOT NULL DEFAULT '[]');
CREATE INDEX runs_target ON runs(target_id, started_at);
CREATE TABLE scope_rules(run_id TEXT NOT NULL REFERENCES runs(id), action TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL);
CREATE TABLE stage_runs(
  run_id TEXT NOT NULL REFERENCES runs(id), stage TEXT NOT NULL, tool TEXT NOT NULL, passive INTEGER NOT NULL,
  status TEXT NOT NULL, started_at TEXT, finished_at TEXT, inputs INTEGER NOT NULL DEFAULT 0,
  outputs INTEGER NOT NULL DEFAULT 0, dropped INTEGER NOT NULL DEFAULT 0, retries INTEGER NOT NULL DEFAULT 0,
  exit_code INTEGER, error TEXT, artifact TEXT, comparable INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(run_id, stage));
CREATE TABLE tool_versions(run_id TEXT NOT NULL REFERENCES runs(id), tool TEXT NOT NULL, path TEXT, version TEXT,
  status TEXT NOT NULL, detail TEXT, PRIMARY KEY(run_id, tool));
CREATE TABLE entities(
  id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES targets(id), kind TEXT NOT NULL, key TEXT NOT NULL,
  first_run TEXT NOT NULL, last_run TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  UNIQUE(target_id, kind, key));
CREATE INDEX entities_kind ON entities(target_id, kind);
CREATE TABLE sightings(
  entity_id INTEGER NOT NULL REFERENCES entities(id), run_id TEXT NOT NULL REFERENCES runs(id),
  source_tool TEXT NOT NULL, source_input TEXT NOT NULL, observed_at TEXT NOT NULL,
  attrs_json TEXT NOT NULL, attrs_hash TEXT NOT NULL, meta_json TEXT NOT NULL,
  PRIMARY KEY(entity_id, run_id, source_tool, source_input)) WITHOUT ROWID;
CREATE INDEX sightings_run ON sightings(run_id);
CREATE TABLE js_content(sha256 TEXT PRIMARY KEY, size INTEGER NOT NULL, content_type TEXT, path TEXT NOT NULL, first_seen TEXT NOT NULL, first_run TEXT NOT NULL);
CREATE TABLE js_sources(sha256 TEXT NOT NULL REFERENCES js_content(sha256), url TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES runs(id),
  observed_at TEXT NOT NULL, http_status INTEGER, PRIMARY KEY(run_id, url, sha256)) WITHOUT ROWID;
CREATE INDEX js_sources_sha ON js_sources(sha256);
CREATE TABLE js_fetch(run_id TEXT NOT NULL REFERENCES runs(id), url TEXT NOT NULL, outcome TEXT NOT NULL, detail TEXT, observed_at TEXT NOT NULL,
  PRIMARY KEY(run_id, url)) WITHOUT ROWID;
CREATE TABLE js_analysis(sha256 TEXT NOT NULL REFERENCES js_content(sha256), analyzer TEXT NOT NULL, analyzer_version TEXT NOT NULL,
  config_hash TEXT NOT NULL, rules_version TEXT NOT NULL, run_id TEXT NOT NULL, analyzed_at TEXT NOT NULL, candidate_count INTEGER NOT NULL,
  PRIMARY KEY(sha256, analyzer, analyzer_version, config_hash, rules_version)) WITHOUT ROWID;
CREATE TABLE candidates(
  id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL REFERENCES js_content(sha256), type TEXT NOT NULL, value TEXT NOT NULL, rule TEXT NOT NULL,
  analyzer_version TEXT NOT NULL, run_id TEXT NOT NULL, observed_at TEXT NOT NULL, verification TEXT NOT NULL,
  UNIQUE(sha256, type, value, rule, analyzer_version));
CREATE INDEX candidates_sha ON candidates(sha256);
CREATE TABLE errors(id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), stage TEXT, message TEXT NOT NULL, at TEXT NOT NULL);
CREATE TABLE retries(id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), stage TEXT NOT NULL, attempt INTEGER NOT NULL, reason TEXT, delay_ms INTEGER, at TEXT NOT NULL);
CREATE TABLE checkpoints(run_id TEXT NOT NULL REFERENCES runs(id), stage TEXT NOT NULL, state TEXT NOT NULL, artifact_sha256 TEXT, updated_at TEXT NOT NULL, PRIMARY KEY(run_id, stage));
CREATE TABLE artifacts(run_id TEXT NOT NULL REFERENCES runs(id), name TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT, kind TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(run_id, name));
CREATE TABLE comparisons(run_id TEXT NOT NULL REFERENCES runs(id), baseline_run_id TEXT, subject TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL, state TEXT NOT NULL, reason TEXT);
CREATE INDEX comparisons_run ON comparisons(run_id);
`}

type DB struct{ sql *sql.DB }

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTS(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// Open opens (creating if needed) the database and applies migrations.
// A database written by a newer ReconFlow is refused.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	s, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s.SetMaxOpenConns(1) // single writer; callers must drain rows before issuing new queries
	d := &DB{s}
	for _, p := range []string{"journal_mode=WAL", "foreign_keys=ON", "busy_timeout=5000", "synchronous=NORMAL"} {
		if _, err := s.Exec("PRAGMA " + p); err != nil {
			s.Close()
			return nil, fmt.Errorf("pragma %s: %w", p, err)
		}
	}
	var v int
	if err := s.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		s.Close()
		return nil, err
	}
	if v > SchemaVersion {
		s.Close()
		return nil, fmt.Errorf("database schema v%d is newer than this ReconFlow (v%d)", v, SchemaVersion)
	}
	for ; v < SchemaVersion; v++ {
		tx, err := s.Begin()
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			s.Close()
			return nil, fmt.Errorf("migration %d: %w", v+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version=%d", v+1)); err != nil {
			tx.Rollback()
			s.Close()
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			s.Close()
			return nil, err
		}
	}
	return d, nil
}

func (d *DB) Close() error { return d.sql.Close() }

// IntegrityCheck runs SQLite's integrity_check.
func (d *DB) IntegrityCheck() error {
	var r string
	if err := d.sql.QueryRow("PRAGMA integrity_check").Scan(&r); err != nil {
		return err
	}
	if r != "ok" {
		return errors.New("integrity_check: " + r)
	}
	return nil
}

func NewRunID() string {
	b := make([]byte, 3)
	rand.Read(b)
	return time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

func (d *DB) EnsureTarget(name string) (int64, error) {
	if _, err := d.sql.Exec(`INSERT OR IGNORE INTO targets(name, created_at) VALUES(?,?)`, name, ts(time.Now())); err != nil {
		return 0, err
	}
	var id int64
	err := d.sql.QueryRow(`SELECT id FROM targets WHERE name=?`, name).Scan(&id)
	return id, err
}

type Run struct {
	ID, Target, Status, ScopeHash, ConfigHash, OutDir, Version string
	TargetID                                                   int64
	Passive                                                    bool
	Started, Finished                                          time.Time
	BaselineID, BaselineNote                                   string
	Plan                                                       []string
}

func (d *DB) CreateRun(r Run, scopeRules [][3]string) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	plan, _ := json.Marshal(r.Plan)
	if _, err := tx.Exec(`INSERT INTO runs(id,target_id,status,passive,scope_hash,config_hash,started_at,out_dir,version,plan) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.TargetID, r.Status, r.Passive, r.ScopeHash, r.ConfigHash, ts(r.Started), r.OutDir, r.Version, string(plan)); err != nil {
		return err
	}
	for _, s := range scopeRules {
		if _, err := tx.Exec(`INSERT INTO scope_rules VALUES(?,?,?,?)`, r.ID, s[0], s[1], s[2]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) SetRunStatus(id, status string, finished time.Time) error {
	var f any
	if !finished.IsZero() {
		f = ts(finished)
	}
	_, err := d.sql.Exec(`UPDATE runs SET status=?, finished_at=COALESCE(?, finished_at) WHERE id=?`, status, f, id)
	return err
}

func (d *DB) SetBaseline(id, baseline, note string) error {
	_, err := d.sql.Exec(`UPDATE runs SET baseline_run_id=NULLIF(?, ''), baseline_note=? WHERE id=?`, baseline, note, id)
	return err
}

const runCols = `r.id, t.name, r.target_id, r.status, r.passive, r.scope_hash, r.config_hash, r.started_at, COALESCE(r.finished_at,''), COALESCE(r.baseline_run_id,''), COALESCE(r.baseline_note,''), r.out_dir, r.version, r.plan`

func scanRun(sc interface{ Scan(...any) error }) (*Run, error) {
	var r Run
	var st, fin, plan string
	if err := sc.Scan(&r.ID, &r.Target, &r.TargetID, &r.Status, &r.Passive, &r.ScopeHash, &r.ConfigHash, &st, &fin, &r.BaselineID, &r.BaselineNote, &r.OutDir, &r.Version, &plan); err != nil {
		return nil, err
	}
	r.Started, r.Finished = parseTS(st), parseTS(fin)
	json.Unmarshal([]byte(plan), &r.Plan)
	return &r, nil
}

func (d *DB) GetRun(id string) (*Run, error) {
	return scanRun(d.sql.QueryRow(`SELECT `+runCols+` FROM runs r JOIN targets t ON t.id=r.target_id WHERE r.id=?`, id))
}

// LatestRun returns the newest run for a target, or (nil,nil).
func (d *DB) LatestRun(targetID int64) (*Run, error) {
	r, err := scanRun(d.sql.QueryRow(`SELECT `+runCols+` FROM runs r JOIN targets t ON t.id=r.target_id WHERE r.target_id=? ORDER BY r.started_at DESC LIMIT 1`, targetID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// RecentRuns returns up to limit runs for a target, newest first.
func (d *DB) RecentRuns(targetID int64, limit int) ([]Run, error) {
	rows, err := d.sql.Query(`SELECT `+runCols+` FROM runs r JOIN targets t ON t.id=r.target_id WHERE r.target_id=? ORDER BY r.started_at DESC LIMIT ?`, targetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// Baseline selects the newest fully successful run for the same target, scope
// policy and passive/active mode that started before `before`. Partial,
// failed and cancelled runs are never baselines.
func (d *DB) Baseline(targetID int64, scopeHash string, passive bool, before time.Time, exclude string) (*Run, error) {
	r, err := scanRun(d.sql.QueryRow(`SELECT `+runCols+` FROM runs r JOIN targets t ON t.id=r.target_id
		WHERE r.target_id=? AND r.status='success' AND r.scope_hash=? AND r.passive=? AND r.started_at<? AND r.id<>?
		ORDER BY r.started_at DESC LIMIT 1`, targetID, scopeHash, passive, ts(before), exclude))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// LatestUnfinished returns the newest run that is not in a final state.
func (d *DB) LatestUnfinished(targetID int64) (*Run, error) {
	r, err := scanRun(d.sql.QueryRow(`SELECT `+runCols+` FROM runs r JOIN targets t ON t.id=r.target_id
		WHERE r.target_id=? AND r.status IN ('running','cancelled','partial','failed') ORDER BY r.started_at DESC LIMIT 1`, targetID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// ComparableRuns lists run ids sharing target, scope hash and mode.
func (d *DB) ComparableRuns(targetID int64, scopeHash string, passive bool) (map[string]bool, error) {
	rows, err := d.sql.Query(`SELECT id FROM runs WHERE target_id=? AND scope_hash=? AND passive=?`, targetID, scopeHash, passive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]bool{}
	for rows.Next() {
		var id string
		rows.Scan(&id)
		m[id] = true
	}
	return m, rows.Err()
}

type Stage struct {
	Run, ID, Tool, Status, Error, Artifact string
	Passive, Comparable                    bool
	Started, Finished                      time.Time
	Inputs, Outputs, Dropped, Retries      int
	ExitCode                               int
}

func (d *DB) UpsertStage(s Stage) error {
	_, err := d.sql.Exec(`INSERT INTO stage_runs(run_id,stage,tool,passive,status,started_at,finished_at,inputs,outputs,dropped,retries,exit_code,error,artifact,comparable)
	VALUES(?,?,?,?,?,NULLIF(?,''),NULLIF(?,''),?,?,?,?,?,?,?,?)
	ON CONFLICT(run_id,stage) DO UPDATE SET tool=excluded.tool,passive=excluded.passive,status=excluded.status,started_at=excluded.started_at,finished_at=excluded.finished_at,
	 inputs=excluded.inputs,outputs=excluded.outputs,dropped=excluded.dropped,retries=excluded.retries,exit_code=excluded.exit_code,error=excluded.error,artifact=excluded.artifact,comparable=excluded.comparable`,
		s.Run, s.ID, s.Tool, s.Passive, s.Status, ts(s.Started), ts(s.Finished), s.Inputs, s.Outputs, s.Dropped, s.Retries, s.ExitCode, s.Error, s.Artifact, s.Comparable)
	return err
}

func (d *DB) Stages(run string) ([]Stage, error) {
	rows, err := d.sql.Query(`SELECT stage,tool,passive,status,COALESCE(started_at,''),COALESCE(finished_at,''),inputs,outputs,dropped,retries,COALESCE(exit_code,0),COALESCE(error,''),COALESCE(artifact,''),comparable FROM stage_runs WHERE run_id=? ORDER BY rowid`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Stage
	for rows.Next() {
		s := Stage{Run: run}
		var a, b string
		if err := rows.Scan(&s.ID, &s.Tool, &s.Passive, &s.Status, &a, &b, &s.Inputs, &s.Outputs, &s.Dropped, &s.Retries, &s.ExitCode, &s.Error, &s.Artifact, &s.Comparable); err != nil {
			return nil, err
		}
		s.Started, s.Finished = parseTS(a), parseTS(b)
		out = append(out, s)
	}
	return out, rows.Err()
}

type ToolVersion struct{ Tool, Path, Version, Status, Detail string }

func (d *DB) SaveTool(run string, t ToolVersion) error {
	_, err := d.sql.Exec(`INSERT OR REPLACE INTO tool_versions VALUES(?,?,?,?,?,?)`, run, t.Tool, t.Path, t.Version, t.Status, t.Detail)
	return err
}

func (d *DB) Tools(run string) ([]ToolVersion, error) {
	rows, err := d.sql.Query(`SELECT tool,COALESCE(path,''),COALESCE(version,''),status,COALESCE(detail,'') FROM tool_versions WHERE run_id=? ORDER BY tool`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ToolVersion
	for rows.Next() {
		var t ToolVersion
		rows.Scan(&t.Tool, &t.Path, &t.Version, &t.Status, &t.Detail)
		out = append(out, t)
	}
	return out, rows.Err()
}

func AttrsHash(attrs map[string]any) (string, string) {
	b, _ := json.Marshal(attrs) // map keys are sorted by encoding/json
	if attrs == nil {
		b = []byte("{}")
	}
	h := sha256.Sum256(b)
	return string(b), hex.EncodeToString(h[:8])
}

// Persist writes observations in one transaction. Entities are deduplicated by
// (target, kind, key); every (entity, run, tool, input) sighting is retained.
// It returns how many entities were seen for the first time.
func (d *DB) Persist(run string, targetID int64, obs []model.Obs) (int, error) {
	tx, err := d.sql.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	newCount := 0
	for _, o := range obs {
		now := ts(o.ObservedAt)
		var id int64
		var existed bool
		if err := tx.QueryRow(`SELECT id FROM entities WHERE target_id=? AND kind=? AND key=?`, targetID, o.Kind, o.Key).Scan(&id); err == nil {
			existed = true
			if _, err := tx.Exec(`UPDATE entities SET last_run=?, last_seen=? WHERE id=?`, run, now, id); err != nil {
				return 0, err
			}
		} else if errors.Is(err, sql.ErrNoRows) {
			res, err := tx.Exec(`INSERT INTO entities(target_id,kind,key,first_run,last_run,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)`, targetID, o.Kind, o.Key, run, run, now, now)
			if err != nil {
				return 0, err
			}
			id, _ = res.LastInsertId()
		} else {
			return 0, err
		}
		if !existed {
			newCount++
		}
		aj, ah := AttrsHash(o.Attrs)
		mj, _ := json.Marshal(o.Meta)
		if o.Meta == nil {
			mj = []byte("{}")
		}
		if _, err := tx.Exec(`INSERT INTO sightings VALUES(?,?,?,?,?,?,?,?)
			ON CONFLICT(entity_id,run_id,source_tool,source_input) DO UPDATE SET observed_at=excluded.observed_at, attrs_json=excluded.attrs_json, attrs_hash=excluded.attrs_hash, meta_json=excluded.meta_json`,
			id, run, o.Tool, o.Input, now, aj, ah, string(mj)); err != nil {
			return 0, err
		}
	}
	return newCount, tx.Commit()
}

// Counts returns distinct entities sighted in the run, per kind.
func (d *DB) Counts(run string) (map[string]int, error) {
	rows, err := d.sql.Query(`SELECT e.kind, COUNT(DISTINCT e.id) FROM sightings s JOIN entities e ON e.id=s.entity_id WHERE s.run_id=? GROUP BY e.kind`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		rows.Scan(&k, &n)
		m[k] = n
	}
	return m, rows.Err()
}

type Entity struct {
	ID        int64
	Kind, Key string
	FirstRun  string
	LastRun   string // only set by PriorEntities
	Hash      string // combined hash of all sightings' material attributes in the run
	Attrs     map[string]any
	Sources   []string
	Origins   []string // distinct meta.origin values (historical|crawled) across sightings
	Meta      map[string]any
	Seen      time.Time
}

// RunEntities returns entities sighted in a run with merged provenance.
func (d *DB) RunEntities(run string) ([]Entity, error) {
	rows, err := d.sql.Query(`SELECT e.id,e.kind,e.key,e.first_run,s.source_tool,s.attrs_hash,s.attrs_json,s.meta_json,s.observed_at
		FROM sightings s JOIN entities e ON e.id=s.entity_id WHERE s.run_id=? ORDER BY e.kind,e.key,s.source_tool`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entity
	idx := map[int64]int{}
	for rows.Next() {
		var id int64
		var kind, key, first, tool, hash, aj, mj, at string
		if err := rows.Scan(&id, &kind, &key, &first, &tool, &hash, &aj, &mj, &at); err != nil {
			return nil, err
		}
		i, ok := idx[id]
		if !ok {
			i = len(out)
			idx[id] = i
			out = append(out, Entity{ID: id, Kind: kind, Key: key, FirstRun: first, Attrs: map[string]any{}, Meta: map[string]any{}})
		}
		e := &out[i]
		if !strings.Contains(e.Hash, hash) {
			e.Hash += hash // distinct material-attribute hashes only (tools that agree do not change it)
		}
		if !contains(e.Sources, tool) {
			e.Sources = append(e.Sources, tool)
		}
		var a, m map[string]any
		json.Unmarshal([]byte(aj), &a)
		json.Unmarshal([]byte(mj), &m)
		for k, v := range a {
			e.Attrs[k] = v
		}
		for k, v := range m {
			e.Meta[k] = v
		}
		if og, ok := m["origin"].(string); ok && !contains(e.Origins, og) {
			e.Origins = append(e.Origins, og)
		}
		if t := parseTS(at); t.After(e.Seen) {
			e.Seen = t
		}
	}
	return out, rows.Err()
}

// PriorEntities lists entities of comparable runs that were NOT sighted in
// either given runs, with their last_run (used for possibly_removed).
func (d *DB) PriorEntities(targetID int64, cur, base string) ([]Entity, error) {
	rows, err := d.sql.Query(`SELECT e.id,e.kind,e.key,e.last_run FROM entities e WHERE e.target_id=?
		AND NOT EXISTS (SELECT 1 FROM sightings s WHERE s.entity_id=e.id AND s.run_id IN (?,?))`, targetID, cur, base)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entity
	for rows.Next() {
		var e Entity
		rows.Scan(&e.ID, &e.Kind, &e.Key, &e.LastRun)
		out = append(out, e)
	}
	return out, rows.Err()
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (d *DB) AddError(run, stage, msg string) error {
	_, err := d.sql.Exec(`INSERT INTO errors(run_id,stage,message,at) VALUES(?,?,?,?)`, run, stage, msg, ts(time.Now()))
	return err
}

type ErrRow struct{ Stage, Message, At string }

func (d *DB) Errors(run string) ([]ErrRow, error) {
	rows, err := d.sql.Query(`SELECT COALESCE(stage,''),message,at FROM errors WHERE run_id=? ORDER BY id`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ErrRow
	for rows.Next() {
		var e ErrRow
		rows.Scan(&e.Stage, &e.Message, &e.At)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) AddRetry(run, stage string, attempt int, reason string, delay time.Duration) error {
	_, err := d.sql.Exec(`INSERT INTO retries(run_id,stage,attempt,reason,delay_ms,at) VALUES(?,?,?,?,?,?)`, run, stage, attempt, reason, delay.Milliseconds(), ts(time.Now()))
	return err
}

// Checkpoint is saved in the same call that records a stage's final state so
// resume decisions never disagree with stored results.
type Checkpoint struct {
	Stage, State, ArtifactSHA string
}

func (d *DB) FinishStage(s Stage, cp Checkpoint) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO stage_runs(run_id,stage,tool,passive,status,started_at,finished_at,inputs,outputs,dropped,retries,exit_code,error,artifact,comparable)
	VALUES(?,?,?,?,?,NULLIF(?,''),NULLIF(?,''),?,?,?,?,?,?,?,?)
	ON CONFLICT(run_id,stage) DO UPDATE SET status=excluded.status,started_at=excluded.started_at,finished_at=excluded.finished_at,inputs=excluded.inputs,outputs=excluded.outputs,
	 dropped=excluded.dropped,retries=excluded.retries,exit_code=excluded.exit_code,error=excluded.error,artifact=excluded.artifact,comparable=excluded.comparable`,
		s.Run, s.ID, s.Tool, s.Passive, s.Status, ts(s.Started), ts(s.Finished), s.Inputs, s.Outputs, s.Dropped, s.Retries, s.ExitCode, s.Error, s.Artifact, s.Comparable); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO checkpoints VALUES(?,?,?,?,?)`, s.Run, cp.Stage, cp.State, cp.ArtifactSHA, ts(time.Now())); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) Checkpoints(run string) (map[string]Checkpoint, error) {
	rows, err := d.sql.Query(`SELECT stage,state,COALESCE(artifact_sha256,'') FROM checkpoints WHERE run_id=?`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]Checkpoint{}
	for rows.Next() {
		var c Checkpoint
		rows.Scan(&c.Stage, &c.State, &c.ArtifactSHA)
		m[c.Stage] = c
	}
	return m, rows.Err()
}

type Artifact struct{ Name, Path, SHA256, Kind string }

func (d *DB) AddArtifact(run string, a Artifact) error {
	_, err := d.sql.Exec(`INSERT OR REPLACE INTO artifacts VALUES(?,?,?,?,?,?)`, run, a.Name, a.Path, a.SHA256, a.Kind, ts(time.Now()))
	return err
}

func (d *DB) Artifacts(run string) ([]Artifact, error) {
	rows, err := d.sql.Query(`SELECT name,path,COALESCE(sha256,''),kind FROM artifacts WHERE run_id=? ORDER BY name`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Artifact
	for rows.Next() {
		var a Artifact
		rows.Scan(&a.Name, &a.Path, &a.SHA256, &a.Kind)
		out = append(out, a)
	}
	return out, rows.Err()
}

type Comparison struct{ Subject, Kind, Key, State, Reason string }

func (d *DB) SaveComparisons(run, baseline string, cs []Comparison) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM comparisons WHERE run_id=?`, run); err != nil {
		return err
	}
	for _, c := range cs {
		if _, err := tx.Exec(`INSERT INTO comparisons VALUES(?,NULLIF(?,''),?,?,?,?,?)`, run, baseline, c.Subject, c.Kind, c.Key, c.State, c.Reason); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) Comparisons(run string) ([]Comparison, error) {
	rows, err := d.sql.Query(`SELECT subject,kind,key,state,COALESCE(reason,'') FROM comparisons WHERE run_id=? ORDER BY subject,kind,state,key`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Comparison
	for rows.Next() {
		var c Comparison
		rows.Scan(&c.Subject, &c.Kind, &c.Key, &c.State, &c.Reason)
		out = append(out, c)
	}
	return out, rows.Err()
}

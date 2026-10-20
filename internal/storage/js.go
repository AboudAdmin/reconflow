package storage

import (
	"database/sql"
	"errors"
	"time"
)

type JSKey struct{ SHA, Analyzer, Version, ConfigHash, Rules string }

type Candidate struct {
	SHA, Type, Value, Rule, AnalyzerVersion, Verification string
	Run                                                   string
	At                                                    time.Time
}

// PutJSContent records content by hash (idempotent) and the source URL
// relationship for this run.
func (d *DB) PutJSContent(run, sha, url, ctype, path string, size int64, status int, at time.Time) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO js_content VALUES(?,?,?,?,?,?)`, sha, size, ctype, path, ts(at), run); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO js_sources VALUES(?,?,?,?,?)`, sha, url, run, ts(at), status); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) JSFetchOutcome(run, url, outcome, detail string, at time.Time) error {
	_, err := d.sql.Exec(`INSERT OR REPLACE INTO js_fetch VALUES(?,?,?,?,?)`, run, url, outcome, detail, ts(at))
	return err
}

// Analyzed reports whether every cache-key component already has a result.
func (d *DB) Analyzed(k JSKey) (bool, error) {
	var n int
	err := d.sql.QueryRow(`SELECT 1 FROM js_analysis WHERE sha256=? AND analyzer=? AND analyzer_version=? AND config_hash=? AND rules_version=?`,
		k.SHA, k.Analyzer, k.Version, k.ConfigHash, k.Rules).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (d *DB) SaveAnalysis(run string, k JSKey, cs []Candidate, at time.Time) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, c := range cs {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO candidates(sha256,type,value,rule,analyzer_version,run_id,observed_at,verification) VALUES(?,?,?,?,?,?,?,?)`,
			k.SHA, c.Type, c.Value, c.Rule, k.Version, run, ts(at), c.Verification); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO js_analysis VALUES(?,?,?,?,?,?,?,?)`, k.SHA, k.Analyzer, k.Version, k.ConfigHash, k.Rules, run, ts(at), len(cs)); err != nil {
		return err
	}
	return tx.Commit()
}

type JSSource struct {
	SHA, URL, ContentType, Path string
	Size                        int64
	Status                      int
	FirstRun                    string
	At                          time.Time
}

func (d *DB) RunJS(run string) ([]JSSource, error) {
	rows, err := d.sql.Query(`SELECT s.sha256,s.url,COALESCE(c.content_type,''),c.path,c.size,COALESCE(s.http_status,0),c.first_run,s.observed_at
		FROM js_sources s JOIN js_content c ON c.sha256=s.sha256 WHERE s.run_id=? ORDER BY s.url`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JSSource
	for rows.Next() {
		var j JSSource
		var at string
		if err := rows.Scan(&j.SHA, &j.URL, &j.ContentType, &j.Path, &j.Size, &j.Status, &j.FirstRun, &at); err != nil {
			return nil, err
		}
		j.At = parseTS(at)
		out = append(out, j)
	}
	return out, rows.Err()
}

// RunCandidates returns the candidates of every JS content observed in the run.
func (d *DB) RunCandidates(run string) ([]Candidate, error) {
	rows, err := d.sql.Query(`SELECT c.sha256,c.type,c.value,c.rule,c.analyzer_version,c.verification,c.run_id,c.observed_at FROM candidates c
		WHERE c.sha256 IN (SELECT sha256 FROM js_sources WHERE run_id=?) ORDER BY c.type,c.value`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Candidate
	for rows.Next() {
		var c Candidate
		var at string
		if err := rows.Scan(&c.SHA, &c.Type, &c.Value, &c.Rule, &c.AnalyzerVersion, &c.Verification, &c.Run, &at); err != nil {
			return nil, err
		}
		c.At = parseTS(at)
		out = append(out, c)
	}
	return out, rows.Err()
}

type JSFetch struct{ URL, Outcome, Detail string }

func (d *DB) RunJSFetches(run string) ([]JSFetch, error) {
	rows, err := d.sql.Query(`SELECT url,outcome,COALESCE(detail,'') FROM js_fetch WHERE run_id=? ORDER BY url`, run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JSFetch
	for rows.Next() {
		var f JSFetch
		rows.Scan(&f.URL, &f.Outcome, &f.Detail)
		out = append(out, f)
	}
	return out, rows.Err()
}

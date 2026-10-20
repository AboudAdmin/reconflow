// Package config loads, defaults and validates ReconFlow configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Tool struct {
	Path    string `yaml:"path"`    // explicit executable path; empty = look up on PATH
	Enabled *bool  `yaml:"enabled"` // nil = stage default
}

type Config struct {
	DataDir  string          `yaml:"data_dir"`
	Database string          `yaml:"database"`
	Scope    string          `yaml:"scope_file"`
	Enabled  []string        `yaml:"enabled_stages"` // empty = all default-enabled stages
	Disabled []string        `yaml:"disabled_stages"`
	Passive  []string        `yaml:"passive_stages"` // the ONLY stages allowed with --passive
	Tools    map[string]Tool `yaml:"tools"`
	Conc     struct {
		Global   int            `yaml:"global"`    // stages running at once
		PerStage map[string]int `yaml:"per_stage"` // tool thread/concurrency flag value
	} `yaml:"concurrency"`
	Timeouts struct {
		Command  time.Duration            `yaml:"command"`
		PerStage map[string]time.Duration `yaml:"per_stage"`
		Grace    time.Duration            `yaml:"cancel_grace"`
	} `yaml:"timeouts"`
	Retry struct {
		Max         int           `yaml:"max"`
		BackoffBase time.Duration `yaml:"backoff_base"`
		BackoffMax  time.Duration `yaml:"backoff_max"`
	} `yaml:"retry"`
	RateLimit map[string]int `yaml:"rate_limit"` // requests/second per tool
	Limits    struct {
		MaxOutputBytes int64 `yaml:"max_output_bytes"`
		MaxLineBytes   int   `yaml:"max_line_bytes"`
		MaxRecords     int   `yaml:"max_records_per_stage"`
		JSDownload     int64 `yaml:"js_download_bytes"`
		MaxPerShape    int   `yaml:"max_urls_per_shape"` // URL variants kept per path/param-name shape (rest stay in raw evidence)
	} `yaml:"limits"`
	Crawl struct {
		Depth      int           `yaml:"depth"`
		Parallel   int           `yaml:"parallel"`    // hosts crawled at once (one katana process each)
		HostBudget time.Duration `yaml:"host_budget"` // crawl-time budget per host; a host that hits it is reported, not hidden
	} `yaml:"crawl"`
	JS struct {
		Enabled bool          `yaml:"enabled"`
		Workers int           `yaml:"workers"`
		RPS     int           `yaml:"requests_per_second"`
		Timeout time.Duration `yaml:"timeout"`
		MaxFile int           `yaml:"max_files"`
	} `yaml:"javascript"`
	Reports struct {
		HTML  bool `yaml:"html"`
		JSONL bool `yaml:"jsonl"`
	} `yaml:"reports"`
	Terminal struct {
		Color   string        `yaml:"color"`   // auto|always|never
		Unicode string        `yaml:"unicode"` // auto|always|never
		Refresh time.Duration `yaml:"refresh"`
	} `yaml:"terminal"`
	Logging struct {
		Level string `yaml:"level"`
	} `yaml:"logging"`
}

// Default returns safe defaults for small Kali VMs.
func Default() *Config {
	c := &Config{Tools: map[string]Tool{}}
	c.Passive = []string{"subfinder", "gau", "waybackurls"}
	c.Conc.Global = 3
	c.Conc.PerStage = map[string]int{"dnsx": 20, "httpx": 20, "katana": 5}
	c.Timeouts.Command = 20 * time.Minute
	c.Timeouts.Grace = 5 * time.Second
	c.Retry.Max = 2
	c.Retry.BackoffBase = 2 * time.Second
	c.Retry.BackoffMax = 30 * time.Second
	c.RateLimit = map[string]int{"dnsx": 100, "httpx": 20, "katana": 10}
	c.Limits.MaxOutputBytes = 64 << 20
	c.Limits.MaxLineBytes = 1 << 20
	c.Limits.MaxRecords = 200000
	c.Limits.JSDownload = 5 << 20
	c.Limits.MaxPerShape = 5
	c.Crawl.Depth = 2
	c.Crawl.Parallel = 3
	c.Crawl.HostBudget = 3 * time.Minute
	c.JS.Enabled = true
	c.JS.Workers = 4
	c.JS.RPS = 5
	c.JS.Timeout = 20 * time.Second
	c.JS.MaxFile = 500
	c.Reports.HTML = true
	c.Reports.JSONL = true
	c.Terminal.Color, c.Terminal.Unicode = "auto", "auto"
	c.Terminal.Refresh = 250 * time.Millisecond
	c.Logging.Level = "info"
	return c
}

// Load reads path (if non-empty) over the defaults. Unknown keys are errors.
func Load(path string) (*Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	if err := c.resolve(); err != nil {
		return nil, err
	}
	return c, c.Validate()
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[1:])
		}
	}
	return p
}

func (c *Config) resolve() error {
	if c.DataDir == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		c.DataDir = filepath.Join(h, ".reconflow")
	}
	c.DataDir = expandHome(c.DataDir)
	if c.Database == "" {
		c.Database = filepath.Join(c.DataDir, "database", "reconflow.db")
	}
	c.Database = expandHome(c.Database)
	c.Scope = expandHome(c.Scope)
	return nil
}

// Validate checks all values before any network activity.
func (c *Config) Validate() error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if c.Conc.Global < 1 || c.Conc.Global > 32 {
		bad("concurrency.global must be 1..32")
	}
	for k, v := range c.Conc.PerStage {
		if v < 1 || v > 500 {
			bad("concurrency.per_stage.%s must be 1..500", k)
		}
	}
	if c.Timeouts.Command < time.Second {
		bad("timeouts.command must be >= 1s")
	}
	if c.Retry.Max < 0 || c.Retry.Max > 10 {
		bad("retry.max must be 0..10")
	}
	if c.Retry.BackoffBase <= 0 || c.Retry.BackoffMax < c.Retry.BackoffBase {
		bad("retry.backoff_base must be >0 and <= backoff_max")
	}
	if c.Limits.MaxOutputBytes < 1<<10 || c.Limits.MaxLineBytes < 1<<10 || c.Limits.JSDownload < 1<<10 || c.Limits.MaxRecords < 1 {
		bad("limits must be positive (bytes >= 1024)")
	}
	if c.Crawl.Depth < 1 || c.Crawl.Depth > 10 {
		bad("crawl.depth must be 1..10")
	}
	if c.Crawl.Parallel < 1 || c.Crawl.Parallel > 16 || c.Crawl.HostBudget < 10*time.Second || c.Limits.MaxPerShape < 1 {
		bad("crawl.parallel must be 1..16, crawl.host_budget >= 10s, limits.max_urls_per_shape >= 1")
	}
	if c.JS.Workers < 1 || c.JS.Workers > 32 || c.JS.RPS < 1 || c.JS.Timeout <= 0 || c.JS.MaxFile < 1 {
		bad("javascript.* values out of range")
	}
	if !oneOf(c.Terminal.Color, "auto", "always", "never") || !oneOf(c.Terminal.Unicode, "auto", "always", "never") {
		bad("terminal.color/unicode must be auto|always|never")
	}
	if c.Terminal.Refresh < 50*time.Millisecond {
		bad("terminal.refresh must be >= 50ms")
	}
	if !oneOf(strings.ToLower(c.Logging.Level), "debug", "info", "warn", "error") {
		bad("logging.level must be debug|info|warn|error")
	}
	for name, t := range c.Tools {
		if strings.ContainsAny(t.Path, "\x00\n\r") {
			bad("tools.%s.path contains control characters", name)
		}
	}
	return errors.Join(errs...)
}

func oneOf(s string, opts ...string) bool {
	for _, o := range opts {
		if s == o {
			return true
		}
	}
	return false
}

// StageEnabled applies enabled/disabled lists and per-tool enable flags.
func (c *Config) StageEnabled(stage string, defaultOn bool) bool {
	for _, d := range c.Disabled {
		if d == stage {
			return false
		}
	}
	if t, ok := c.Tools[stage]; ok && t.Enabled != nil {
		return *t.Enabled
	}
	if len(c.Enabled) > 0 {
		for _, e := range c.Enabled {
			if e == stage {
				return true
			}
		}
		return false
	}
	return defaultOn
}

func (c *Config) IsPassive(stage string) bool {
	for _, p := range c.Passive {
		if p == stage {
			return true
		}
	}
	return false
}

func (c *Config) StageTimeout(stage string) time.Duration {
	if d, ok := c.Timeouts.PerStage[stage]; ok && d > 0 {
		return d
	}
	return c.Timeouts.Command
}

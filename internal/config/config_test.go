package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, y string) string {
	p := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(p, []byte(y), 0o600)
	return p
}

func TestDefaultsAreValid(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(c.DataDir), ".reconflow") || !strings.HasSuffix(filepath.ToSlash(c.Database), "database/reconflow.db") {
		t.Errorf("paths: %s %s", c.DataDir, c.Database)
	}
	if c.Conc.Global != 3 || !c.IsPassive("subfinder") || c.IsPassive("httpx") {
		t.Error("unexpected defaults")
	}
}

func TestOverridesAndStageSelection(t *testing.T) {
	c, err := Load(write(t, "data_dir: /x/rf\nconcurrency: {global: 2}\ndisabled_stages: [katana]\ntimeouts: {command: 90s, per_stage: {httpx: 5m}}\ntools: {gau: {enabled: false}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.ToSlash(c.DataDir) != "/x/rf" || c.Conc.Global != 2 || c.Timeouts.Command != 90*time.Second || c.StageTimeout("httpx") != 5*time.Minute || c.StageTimeout("dnsx") != 90*time.Second {
		t.Errorf("%+v", c)
	}
	for stage, want := range map[string]bool{"katana": false, "gau": false, "httpx": true} {
		if got := c.StageEnabled(stage, true); got != want {
			t.Errorf("StageEnabled(%s)=%v", stage, got)
		}
	}
	c2, _ := Load(write(t, "enabled_stages: [subfinder]\n"))
	if !c2.StageEnabled("subfinder", true) || c2.StageEnabled("httpx", true) {
		t.Error("enabled_stages must act as an allow-list")
	}
}

func TestValidationRejects(t *testing.T) {
	for name, y := range map[string]string{
		"unknown key":  "nope: 1\n",
		"zero conc":    "concurrency: {global: 0}\n",
		"huge conc":    "concurrency: {per_stage: {httpx: 100000}}\n",
		"retries":      "retry: {max: 99}\n",
		"backoff":      "retry: {backoff_base: 10s, backoff_max: 1s}\n",
		"limits":       "limits: {max_output_bytes: 5}\n",
		"color":        "terminal: {color: rainbow}\n",
		"log level":    "logging: {level: chatty}\n",
		"depth":        "crawl: {depth: 0}\n",
		"bad yaml":     "a: [\n",
		"bad duration": "timeouts: {command: soon}\n",
	} {
		if _, err := Load(write(t, y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("missing file accepted")
	}
}

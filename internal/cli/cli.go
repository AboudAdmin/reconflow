// Package cli parses commands, wires components together and maps outcomes to exit codes.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"reconflow/internal/adapters"
	"reconflow/internal/config"
	"reconflow/internal/diff"
	"reconflow/internal/model"
	"reconflow/internal/orchestrator"
	"reconflow/internal/reporting"
	"reconflow/internal/scope"
	"reconflow/internal/storage"
	"reconflow/internal/terminal"
)

const Version = "0.1.0"

// Documented exit codes.
const (
	ExitOK          = 0
	ExitInternal    = 1
	ExitUsage       = 2 // invalid input, config or scope
	ExitMissingDeps = 3 // no required external tool usable
	ExitPartial     = 4 // run finished but some stages failed, were partial or skipped
	ExitNoResume    = 5 // nothing recoverable / not resumable
	ExitLocked      = 6 // another process is working on the target
	ExitCancelled   = 130
)

const usage = `ReconFlow - dependency-aware reconnaissance orchestrator

Usage:
  reconflow -d <domain> [flags]        run (or compare) a reconnaissance pass
  reconflow report -d <domain>         regenerate reports for the latest run (no network)
  reconflow tools                      detect external tools, versions and flags
  reconflow validate-scope --scope <file> [-d <domain>] [host|url ...]

Flags:
  -d <domain>       target (bare domain or IP; required)
  --config <file>   YAML config (default ~/.reconflow/config/config.yaml if present)
  --scope <file>    explicit scope file (default: the target and its subdomains)
  --passive         only configured passive stages; nothing is sent to the target
  --new             print newly discovered items relative to the baseline
  --all             print the complete current inventory
  --resume          resume the latest unfinished run of this target
  --status          show the latest run's state and exit
  --plain           disable colors, Unicode and cursor redraw
  --version         print version
  --help            print this help

Exit codes: 0 ok, 1 internal error, 2 invalid input, 3 no usable tools,
4 partial/failed stages, 5 nothing to resume, 6 target locked, 130 cancelled.
Use only against assets you are authorized to test.
`

func Main(args []string, out, errw io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "report":
			return cmdReport(args[1:], out, errw)
		case "tools":
			return cmdTools(args[1:], out, errw)
		case "validate-scope":
			return cmdValidateScope(args[1:], out, errw)
		}
	}
	fs := flag.NewFlagSet("reconflow", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		domain, cfgPath, scopePath                string
		passive, showNew, showAll, resume, status bool
		plain, ver, help                          bool
	)
	fs.StringVar(&domain, "d", "", "")
	fs.StringVar(&cfgPath, "config", "", "")
	fs.StringVar(&scopePath, "scope", "", "")
	fs.BoolVar(&passive, "passive", false, "")
	fs.BoolVar(&showNew, "new", false, "")
	fs.BoolVar(&showAll, "all", false, "")
	fs.BoolVar(&resume, "resume", false, "")
	fs.BoolVar(&status, "status", false, "")
	fs.BoolVar(&plain, "plain", false, "")
	fs.BoolVar(&ver, "version", false, "")
	fs.BoolVar(&help, "help", false, "")
	fs.BoolVar(&help, "h", false, "")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(errw, "error: %v\n\n%s", err, usage)
		return ExitUsage
	}
	if ver {
		fmt.Fprintln(out, "reconflow", Version)
		return ExitOK
	}
	if help {
		fmt.Fprint(out, usage)
		return ExitOK
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(errw, "error: unexpected arguments %q\n\n%s", fs.Args(), usage)
		return ExitUsage
	}
	if domain == "" {
		fmt.Fprint(errw, "error: -d <domain> is required\n\n"+usage)
		return ExitUsage
	}
	if status && (resume || passive || showNew || showAll) {
		fmt.Fprintln(errw, "error: --status cannot be combined with run flags")
		return ExitUsage
	}
	cfg, target, pol, code := setup(domain, cfgPath, scopePath, errw)
	if code != 0 {
		return code
	}
	db, err := storage.Open(cfg.Database)
	if err != nil {
		fmt.Fprintf(errw, "error: open database: %v\n", err)
		return ExitInternal
	}
	defer db.Close()
	if status {
		return printStatus(db, target, out)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tr := model.NewTracker(target, "", nil)
	var ui *terminal.UI
	var sopts terminal.Options
	o := orchestrator.Options{Target: target, Passive: passive, Resume: resume, Cfg: cfg, Scope: pol, DB: db, Tracker: tr, Version: Version,
		OnPlan: func(string, *model.Tracker) {
			opts, tty := terminal.Detect(os.Stdout, cfg.Terminal.Color, cfg.Terminal.Unicode)
			if plain {
				opts, tty = terminal.Options{Width: opts.Width}, false
			}
			if f, ok := out.(*os.File); !ok || f != os.Stdout {
				opts, tty = terminal.Options{Width: 80}, false
			}
			ui = terminal.New(out, tr, opts, tty, cfg.Terminal.Refresh)
			ui.Start()
		}}
	res, err := orchestrator.Run(ctx, o)
	if ui != nil {
		ui.Stop()
	}
	switch {
	case errors.Is(err, orchestrator.ErrLocked):
		fmt.Fprintf(errw, "error: %v\n", err)
		return ExitLocked
	case errors.Is(err, orchestrator.ErrNothingToResume), errors.Is(err, orchestrator.ErrResumeIncompatible):
		fmt.Fprintf(errw, "error: %v\n", err)
		return ExitNoResume
	case err != nil:
		fmt.Fprintf(errw, "error: %v\n", err)
		return ExitInternal
	}
	summary(out, res, showNew, showAll, db, sopts)
	switch {
	case res.Status == model.Cancelled:
		return ExitCancelled
	case res.NoTools:
		fmt.Fprintln(errw, "\nNo external tool is usable. Run `reconflow tools` for installation guidance.")
		return ExitMissingDeps
	case res.Status != model.Success:
		return ExitPartial
	}
	return ExitOK
}

func setup(domain, cfgPath, scopePath string, errw io.Writer) (*config.Config, string, *scope.Policy, int) {
	if cfgPath == "" {
		if h, err := os.UserHomeDir(); err == nil {
			if p := filepath.Join(h, ".reconflow", "config", "config.yaml"); fileExists(p) {
				cfgPath = p
			}
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(errw, "error: %v\n", err)
		return nil, "", nil, ExitUsage
	}
	target, err := scope.ParseTarget(domain)
	if err != nil {
		fmt.Fprintf(errw, "error: invalid target: %v\n", err)
		return nil, "", nil, ExitUsage
	}
	if scopePath == "" {
		scopePath = cfg.Scope
	}
	pol := scope.ImplicitFor(target)
	if scopePath != "" {
		if pol, err = scope.Load(scopePath); err != nil {
			fmt.Fprintf(errw, "error: %v\n", err)
			return nil, "", nil, ExitUsage
		}
	}
	if ok, why := pol.AllowHost(target); !ok {
		fmt.Fprintf(errw, "error: target %s is not authorized by the scope (%s); refusing to start\n", target, why)
		return nil, "", nil, ExitUsage
	}
	if err := orchestrator.ValidatePassivePolicy(cfg); err != nil {
		fmt.Fprintf(errw, "error: %v\n", err)
		return nil, "", nil, ExitUsage
	}
	return cfg, target, pol, 0
}

func fileExists(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() }

// termOpts decides colors/unicode for the live view and the final summary.
func termOpts(out io.Writer, cfg *config.Config, plain bool) (terminal.Options, bool) {
	opts, tty := terminal.Detect(os.Stdout, cfg.Terminal.Color, cfg.Terminal.Unicode)
	if plain {
		return terminal.Options{Width: opts.Width}, false
	}
	if f, ok := out.(*os.File); !ok || f != os.Stdout {
		return terminal.Options{Width: 80}, false
	}
	return opts, tty
}

func summary(w io.Writer, res *orchestrator.Result, showNew, showAll bool, db *storage.DB, o terminal.Options) {
	r := res.Run
	mark := map[model.Status]string{model.Success: "[OK]", model.Partial: "[!!] INCOMPLETE -", model.Failed: "[XX]", model.Cancelled: "[--]"}[res.Status]
	fmt.Fprintf(w, "\n== Summary ==\nRun %s: %s %s (%s)\n", r.ID, terminal.Paint(o, terminal.StatusColor(string(res.Status))+terminal.Bold, mark), strings.ToUpper(string(res.Status)), terminal.Elapsed(r.Finished.Sub(r.Started)))
	rows := make([][]string, 0, len(res.Stages))
	for _, s := range res.Stages {
		d := "-"
		if !s.Started.IsZero() && !s.Finished.IsZero() {
			d = terminal.Elapsed(s.Finished.Sub(s.Started))
		}
		rows = append(rows, []string{s.ID, strings.ToUpper(s.Status), fmt.Sprint(s.Outputs), d})
	}
	fmt.Fprintln(w)
	terminal.Table(w, o, []string{"STAGE", "STATUS", "RECORDS", "TIME"}, rows, 1)
	fmt.Fprintln(w)
	if c, err := db.Counts(r.ID); err == nil {
		fmt.Fprintf(w, "Subdomains %d | DNS %d | Live services %d | URLs %d\n", c["subdomain"], c["dns"], c["service"], c["url"])
	}
	if s := res.Summary; s != nil {
		fmt.Fprintf(w, "Leads: %s high, %s medium, %s low  (API endpoints: %d)\n", terminal.Paint(o, terminal.Red, fmt.Sprint(s["leads_high"])),
			terminal.Paint(o, terminal.Yellow, fmt.Sprint(s["leads_medium"])), fmt.Sprint(s["leads_low"]), s["urls_api"])
	}
	if res.Diff != nil {
		if !res.Diff.Established {
			fmt.Fprintln(w, "Comparison:", res.Diff.Note)
		} else {
			fmt.Fprintf(w, "Compared with baseline %s:", res.Diff.BaselineID)
			for _, st := range []string{diff.New, diff.Changed, diff.NotSeen, diff.PossiblyRemoved, diff.Unknown} {
				n := 0
				for k, v := range res.Diff.Counts {
					if strings.HasSuffix(k, "/"+st) {
						n += v
					}
				}
				fmt.Fprintf(w, " %s=%d", st, n)
			}
			fmt.Fprintln(w)
		}
	}
	for _, s := range res.Stages {
		if s.Status != string(model.Success) {
			fmt.Fprintf(w, "  ! %s: %s - %s\n", s.ID, s.Status, s.Error)
		}
	}
	if res.Status != model.Success {
		fmt.Fprintln(w, "Note: this run is not a complete baseline; absence of a result must not be read as removal.")
	}
	if showNew && res.Diff != nil {
		fmt.Fprintln(w, "\n== New since baseline ==")
		if !res.Diff.Established {
			fmt.Fprintln(w, "(no baseline: nothing can be classified as new yet)")
		}
		n := 0
		for _, c := range res.Diff.Items {
			if c.State == diff.New {
				if n++; n <= 50 || showAll {
					fmt.Fprintf(w, "+ %-10s %s\n", c.Kind, c.Key)
				}
			}
		}
		if n > 50 && !showAll {
			fmt.Fprintf(w, "... %d more (use --all, or see new_assets.txt / new_endpoints.txt)\n", n-50)
		}
	}
	if showAll {
		fmt.Fprintln(w, "\n== Current inventory ==")
		if ents, err := db.RunEntities(r.ID); err == nil {
			for _, e := range ents {
				fmt.Fprintf(w, "%-10s %s\n", e.Kind, e.Key)
			}
		}
	}
	for _, a := range res.Reports {
		if a.Name == "latest.html" || a.Name == "latest.json" {
			fmt.Fprintf(w, "Report: %s\n", a.Path)
		}
	}
	if res.ReportErr != nil {
		fmt.Fprintf(w, "Report generation error: %v\n", res.ReportErr)
	}
	fmt.Fprintln(w, "\nWhere your results are:")
	fmt.Fprintf(w, "  Clean lists   %s  (subdomains, live_hosts, urls, js_files, api_endpoints, findings)\n", res.Layout.Norm)
	fmt.Fprintf(w, "  Raw evidence  %s\n", filepath.Join(r.OutDir, "raw"))
	fmt.Fprintf(w, "Run directory: %s\n", r.OutDir)
	if res.Status != model.Success && res.Status != model.Cancelled {
		fmt.Fprintln(w, "Next: fix the stages marked ! above, then `reconflow -d "+r.Target+" --resume` re-runs only unfinished stages.")
	}
}

func printStatus(db *storage.DB, target string, w io.Writer) int {
	tid, err := db.EnsureTarget(target)
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		return ExitInternal
	}
	r, err := db.LatestRun(tid)
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		return ExitInternal
	}
	if r == nil {
		fmt.Fprintf(w, "No runs recorded for %s.\n", target)
		return ExitNoResume
	}
	fmt.Fprintf(w, "Target:   %s\nRun:      %s\nStatus:   %s%s\nStarted:  %s\n", target, r.ID, r.Status, map[bool]string{true: " (passive)"}[r.Passive], r.Started.Format(time.RFC3339))
	if !r.Finished.IsZero() {
		fmt.Fprintf(w, "Finished: %s\n", r.Finished.Format(time.RFC3339))
	}
	if r.BaselineID != "" {
		fmt.Fprintf(w, "Baseline: %s\n", r.BaselineID)
	} else if r.BaselineNote != "" {
		fmt.Fprintf(w, "Baseline: none (%s)\n", r.BaselineNote)
	}
	stages, _ := db.Stages(r.ID)
	cps, _ := db.Checkpoints(r.ID)
	fmt.Fprintln(w, "\nStages:")
	for _, s := range stages {
		cp := cps[s.ID].State
		if cp == "" {
			cp = "-"
		}
		fmt.Fprintf(w, "  %-12s %-10s out=%-6d retries=%d checkpoint=%s", s.ID, s.Status, s.Outputs, s.Retries, cp)
		if s.Error != "" {
			fmt.Fprintf(w, "  %s", s.Error)
		}
		fmt.Fprintln(w)
	}
	tools, _ := db.Tools(r.ID)
	if len(tools) > 0 {
		fmt.Fprintln(w, "\nTools:")
		for _, t := range tools {
			fmt.Fprintf(w, "  %-12s %-12s %s\n", t.Tool, t.Status, t.Version)
		}
	}
	c, _ := db.Counts(r.ID)
	fmt.Fprintf(w, "\nCounts: subdomains=%d dns=%d services=%d urls=%d\n", c["subdomain"], c["dns"], c["service"], c["url"])
	if e, _ := db.Errors(r.ID); len(e) > 0 {
		fmt.Fprintf(w, "Errors: %d recorded (latest: %s: %s)\n", len(e), e[len(e)-1].Stage, e[len(e)-1].Message)
	}
	fmt.Fprintf(w, "Output:   %s\n", r.OutDir)
	arts, _ := db.Artifacts(r.ID)
	for _, a := range arts {
		if a.Name == "latest.html" || a.Name == "latest.json" {
			fmt.Fprintf(w, "Report:   %s\n", a.Path)
		}
	}
	if r.Status == "running" || r.Status == "cancelled" || r.Status == "partial" || r.Status == "failed" {
		fmt.Fprintln(w, "\nThis run is not complete; `--resume` will re-run only unfinished stages.")
	}
	return ExitOK
}

func cmdReport(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var domain, cfgPath string
	fs.StringVar(&domain, "d", "", "")
	fs.StringVar(&cfgPath, "config", "", "")
	if err := fs.Parse(args); err != nil || domain == "" {
		fmt.Fprint(errw, "usage: reconflow report -d <domain> [--config file]\n")
		return ExitUsage
	}
	cfg, target, _, code := setup(domain, cfgPath, "", errw)
	if code != 0 {
		return code
	}
	db, err := storage.Open(cfg.Database)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return ExitInternal
	}
	defer db.Close()
	tid, _ := db.EnsureTarget(target)
	run, err := db.LatestRun(tid)
	if err != nil || run == nil {
		fmt.Fprintf(errw, "error: no runs recorded for %s\n", target)
		return ExitNoResume
	}
	lay, err := orchestrator.NewLayout(cfg.DataDir, target)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return ExitInternal
	}
	var base *storage.Run
	if run.BaselineID != "" {
		base, _ = db.GetRun(run.BaselineID)
	}
	d, err := diff.Compute(db, run, base)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return ExitInternal
	}
	arts, err := reporting.Generate(reporting.Input{DB: db, Run: run, Diff: d, ReportsDir: lay.Reports, JSDir: lay.JS, RunDir: lay.RunDir(run.ID), NormDir: lay.Norm, JSONL: cfg.Reports.JSONL, HTML: cfg.Reports.HTML, Now: time.Now().UTC()})
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return ExitInternal
	}
	for _, a := range arts {
		db.AddArtifact(run.ID, a)
		fmt.Fprintln(out, a.Path)
	}
	return ExitOK
}

func cmdTools(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("tools", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var cfgPath string
	fs.StringVar(&cfgPath, "config", "", "")
	if err := fs.Parse(args); err != nil {
		fmt.Fprint(errw, "usage: reconflow tools [--config file]\n")
		return ExitUsage
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return ExitUsage
	}
	all := adapters.All()
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	fmt.Fprintf(out, "%-12s %-13s %-10s %s\n", "TOOL", "STATUS", "VERSION", "DETAIL")
	n := 0
	for _, a := range all {
		i := a.Detect(context.Background(), cfg.Tools[a.Name].Path)
		detail := i.Path
		if i.Status != adapters.Available {
			detail = i.Detail + " | install: " + i.Install
		} else {
			n++
		}
		fmt.Fprintf(out, "%-12s %-13s %-10s %s\n", i.Name, i.Status, i.Version, detail)
	}
	fmt.Fprintf(out, "\n%d/%d tools usable. Flags are verified against each tool's own help output.\nNot integrated: amass, naabu, tlsx, jsluice, xnLinkFinder, whatweb, nuclei, gowitness.\n", n, len(all))
	return ExitOK
}

func cmdValidateScope(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("validate-scope", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var path, domain string
	fs.StringVar(&path, "scope", "", "")
	fs.StringVar(&domain, "d", "", "")
	if err := fs.Parse(args); err != nil || path == "" {
		fmt.Fprint(errw, "usage: reconflow validate-scope --scope <file> [-d <domain>] [host|url ...]\n")
		return ExitUsage
	}
	pol, err := scope.Load(path)
	if err != nil {
		fmt.Fprintln(errw, "invalid scope:", err)
		return ExitUsage
	}
	f := pol.File
	fmt.Fprintf(out, "scope OK (hash %s)\n  include: domains=%d hosts=%d ips=%d cidrs=%d\n  exclude: domains=%d hosts=%d ips=%d cidrs=%d\n  ports=%v schemes=%v\n",
		pol.Hash()[:16], len(f.Include.Domains), len(f.Include.Hosts), len(f.Include.IPs), len(f.Include.CIDRs),
		len(f.Exclude.Domains), len(f.Exclude.Hosts), len(f.Exclude.IPs), len(f.Exclude.CIDRs), f.Ports, f.Schemes)
	rc := ExitOK
	check := func(s string) {
		var ok bool
		var why string
		if strings.Contains(s, "://") {
			ok, why = pol.AllowURL(s)
		} else {
			ok, why = pol.AllowHost(s)
		}
		v := "ALLOW"
		if !ok {
			v, rc = "DENY ", ExitUsage
		}
		fmt.Fprintf(out, "  %s %s (%s)\n", v, s, why)
	}
	if domain != "" {
		check(domain)
	}
	for _, a := range fs.Args() {
		check(a)
	}
	return rc
}

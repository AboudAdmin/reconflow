# ReconFlow implementation checklist

Status is updated only when code AND tests exist. See README for limitations.

- [x] A. Foundation: module, CLI, config, model, logging, tests
- [x] B. Scope, safe subprocess runner, tool detection, scheduler, terminal UI
- [x] C. SQLite persistence, provenance, run/stage history, diff, checkpoints, resume, cancel, retries
- [x] D. Adapters: subfinder, dnsx, httpx, katana, gau, waybackurls; URL normalization; JS collection+analysis
- [x] E. Reports: JSON/JSONL/text + static HTML dashboard
- [ ] Not implemented: amass, naabu, tlsx, jsluice, xnLinkFinder, whatweb, nuclei, gowitness, live dashboard
- [x] F. Validation (see README "Validation")
- [x] G. Docs

## Decisions
- Pure-Go SQLite (modernc.org/sqlite): no CGO, cross-compiles to Kali from any host.
- yaml.v3 for config (strict decoding). Everything else is stdlib.
- Generic `entities` + `sightings` tables instead of one table per kind: provenance is a first-class row per (entity, run, tool, input).
- Tools get input via files inside the run directory (also evidence) and are invoked with argument arrays only.

## v0.2 signal/noise work
- `internal/triage`: URL classes, shape key (dedup of ID/param variants), scoring, leads. Heuristics only; leads are never "verified".
- katana: one process per host with `-ct` budget (when supported), per-host record in `raw/katana.meta.json`; budget misses => partial.
- URL filtering happens before the record budget; filtered counts go to `raw/<stage>.meta.json` and the manifest.
- Reports: `normalized/` per run + mirror, `report.json` per run, history in the dashboard.
- Dashboard: `dashboard/` (React) -> `internal/reporting/dashboard.html` via `make dashboard`.

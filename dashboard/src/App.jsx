import React, { useMemo, useState, useEffect } from "react";

// Every value below comes from tool output and is untrusted. React escapes text
// children; never render raw HTML.

const n = (v) => (v || 0).toLocaleString();
const dur = (s) => (s >= 3600 ? `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m` : s >= 60 ? `${Math.floor(s / 60)}m ${Math.round(s % 60)}s` : `${(s || 0).toFixed(1)}s`);
const when = (t) => (t ? new Date(t).toLocaleString() : "—");
const Pill = ({ v, label }) => <span className={`pill s-${v}`}>{label || v}</span>;

function Bars({ rows, empty = "Nothing to show." }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  if (!rows.some((r) => r.value)) return <div className="hint">{empty}</div>;
  return (
    <div className="bars">
      {rows.map((r) => (
        <div className="row" key={r.label} title={`${r.label}: ${n(r.value)}`}>
          <span className="lab">{r.label}</span>
          <span className="track"><span className="fill" style={{ width: `${(r.value / max) * 100}%` }} /></span>
          <span className="val">{n(r.value)}</span>
        </div>
      ))}
    </div>
  );
}

function Stat({ label, value, warn }) {
  return <div className={`card stat${warn ? " warn" : ""}`}><b>{n(value)}</b><span>{label}</span></div>;
}

function Table({ rows, cols, initialSort, searchKeys, filters = [], onRow, pageSize = 50, empty }) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState(initialSort || null);
  const [page, setPage] = useState(0);
  const [fv, setFv] = useState({});
  const view = useMemo(() => {
    const ql = q.trim().toLowerCase();
    let r = rows.filter((x) => filters.every((f) => !fv[f.key] || f.get(x) === fv[f.key]));
    if (ql) r = r.filter((x) => searchKeys.some((k) => String(typeof k === "function" ? k(x) : x[k] ?? "").toLowerCase().includes(ql)));
    if (sort) {
      const c = cols.find((c) => c.key === sort.key);
      const get = c.sortBy || c.get || ((x) => x[c.key]);
      r = [...r].sort((a, b) => {
        const A = get(a), B = get(b);
        return (A > B ? 1 : A < B ? -1 : 0) * sort.dir;
      });
    }
    return r;
  }, [rows, q, sort, fv]);
  useEffect(() => setPage(0), [q, sort, fv]);
  const pages = Math.max(1, Math.ceil(view.length / pageSize));
  const slice = view.slice(page * pageSize, (page + 1) * pageSize);
  return (
    <>
      <div className="tools">
        <input type="search" placeholder="Search…" aria-label="Search" value={q} onChange={(e) => setQ(e.target.value)} />
        {filters.map((f) => (
          <select key={f.key} aria-label={f.label} value={fv[f.key] || ""} onChange={(e) => setFv({ ...fv, [f.key]: e.target.value })}>
            <option value="">{f.label}: all</option>
            {[...new Set(rows.map(f.get))].filter(Boolean).sort().map((o) => <option key={o}>{o}</option>)}
          </select>
        ))}
        <span className="hint">{n(view.length)} of {n(rows.length)}</span>
      </div>
      {view.length === 0 ? <div className="empty">{empty || "No rows match."}</div> : (
        <div className="wrap">
          <table>
            <thead><tr>{cols.map((c) => (
              <th key={c.key} aria-sort={sort?.key === c.key ? (sort.dir > 0 ? "ascending" : "descending") : "none"}>
                <button onClick={() => setSort({ key: c.key, dir: sort?.key === c.key ? -sort.dir : c.num ? -1 : 1 })}>
                  {c.label}{sort?.key === c.key ? (sort.dir > 0 ? " ▲" : " ▼") : ""}
                </button>
              </th>))}</tr></thead>
            <tbody>{slice.map((r, i) => (
              <tr key={i} tabIndex={onRow ? 0 : undefined} onClick={() => onRow?.(r)} onKeyDown={(e) => e.key === "Enter" && onRow?.(r)}>
                {cols.map((c) => <td key={c.key} className={c.mono ? "mono" : ""}>{c.render ? c.render(r) : (c.get ? c.get(r) : r[c.key])}</td>)}
              </tr>))}</tbody>
          </table>
        </div>)}
      <div className="pager">
        <button disabled={page === 0} onClick={() => setPage(page - 1)}>Prev</button>
        <span>Page {page + 1} / {pages}</span>
        <button disabled={page >= pages - 1} onClick={() => setPage(page + 1)}>Next</button>
      </div>
    </>
  );
}

function Drawer({ title, fields, onClose }) {
  useEffect(() => {
    const h = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);
  return (
    <aside className="drawer" role="dialog" aria-label={title}>
      <div className="tools"><h2 style={{ margin: 0, flex: 1, wordBreak: "break-all" }}>{title}</h2><button className="btn" onClick={onClose}>Close</button></div>
      <dl>{fields.filter(([, v]) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && !v.length)).map(([k, v]) => (
        <React.Fragment key={k}><dt>{k}</dt><dd className="mono">{Array.isArray(v) ? v.map((x, i) => <div key={i}>{String(x)}</div>) : typeof v === "object" ? JSON.stringify(v) : String(v)}</dd></React.Fragment>))}</dl>
    </aside>
  );
}

const shortUrl = (u) => u.replace(/^https?:\/\//, "");

export default function App({ data: D }) {
  const [tab, setTab] = useState("overview");
  const [sel, setSel] = useState(null);
  if (!D) return <main><div className="banner bad">The embedded report data could not be read. Open latest.json instead.</div></main>;

  const stages = D.stages || [], assets = D.assets || [], urls = D.urls || [], leads = D.findings || [], cands = D.js_candidates || [];
  const subs = assets.filter((a) => a.kind === "subdomain");
  const live = assets.filter((a) => a.kind === "service");
  const problems = stages.filter((s) => s.status !== "success");
  const apiUrls = urls.filter((u) => u.class === "api");
  const jsUrls = urls.filter((u) => u.is_js);
  const changes = (D.changes || []).filter((c) => c.state !== "unchanged");
  const filteredTotal = Object.values(D.filtered || {}).reduce((a, m) => a + Object.values(m).reduce((x, y) => x + y, 0), 0);
  const trunc = D.html_truncated || {};

  const tabs = [
    ["overview", "Overview"], ["leads", "Leads", leads.length], ["hosts", "Hosts", live.length], ["subs", "Subdomains", subs.length],
    ["endpoints", "Endpoints", urls.length], ["js", "JavaScript", (D.javascript || []).length], ["changes", "Changes", changes.length],
    ["runs", "Runs", (D.history || []).length], ["pipeline", "Pipeline", problems.length || undefined],
  ];

  const state = (r) => <Pill v={r.state} />;
  const open = (title, fields) => setSel({ title, fields });

  return (
    <>
      <header className="top">
        <span className="brand">RECONFLOW</span>
        <span className="target">{D.run.target}</span>
        <Pill v={D.run.status} label={D.complete ? "complete" : D.run.status} />
        {D.run.passive && <Pill v="low" label="passive" />}
        <span className="spacer" />
        <span className="meta">run {D.run.id} · {when(D.run.started_at)} · {dur(D.run.duration_sec)} · v{D.run.version}</span>
      </header>
      <nav className="tabs" role="tablist">
        {tabs.map(([k, l, c]) => (
          <button key={k} role="tab" aria-selected={tab === k} onClick={() => { setTab(k); setSel(null); }}>
            {l}{c !== undefined && <span className="n">{n(c)}</span>}
          </button>))}
      </nav>
      <main>
        {!D.complete && (
          <div className={`banner${D.run.status === "failed" ? " bad" : ""}`} role="status">
            <b>This run is {D.run.status}, not complete.</b> Results below are real but may be missing data; absence is not evidence of absence.
            <ul>{problems.map((s) => <li key={s.stage}><b>{s.stage}</b> — {s.status}: <span className="mono">{s.detail || "no detail recorded"}</span></li>)}</ul>
          </div>)}
        {Object.keys(trunc).length > 0 && (
          <div className="banner">This page shows the first rows of: {Object.entries(trunc).map(([k, v]) => `${k} (${n(v)} total)`).join(", ")}. latest.json and the normalized/ files are complete.</div>)}

        {tab === "overview" && (<div className="grid">
          <div className="grid cards">
            <Stat label="Subdomains" value={subs.length} />
            <Stat label="Live hosts" value={live.length} />
            <Stat label="Endpoints kept" value={urls.length} />
            <Stat label="API endpoints" value={apiUrls.length} />
            <Stat label="JS files" value={jsUrls.length} />
            <Stat label="High-priority leads" value={D.summary.leads_high} warn={D.summary.leads_high > 0} />
            <Stat label="New since baseline" value={changes.filter((c) => c.state === "new").length} />
          </div>
          <div className="grid two">
            <div className="card"><h2>Leads by priority</h2>
              <Bars rows={["high", "medium", "low"].map((p) => ({ label: p, value: D.summary["leads_" + p] || 0 }))} empty="No leads were derived from this run." />
              <p className="hint">Leads are pointers for manual review, not confirmed vulnerabilities.</p></div>
            <div className="card"><h2>Endpoints by class</h2>
              <Bars rows={["api", "js", "sourcemap", "page"].map((c) => ({ label: c, value: D.summary["urls_" + c] || 0 }))} /></div>
            <div className="card"><h2>Top leads</h2>
              {leads.slice(0, 6).map((l, i) => (
                <div key={i} style={{ padding: "4px 0" }}><Pill v={l.priority} /> {l.title}<div className="mono hint">{shortUrl(l.subject)}</div></div>))}
              {!leads.length && <div className="hint">None.</div>}
              {leads.length > 6 && <button className="btn" onClick={() => setTab("leads")}>All {n(leads.length)} leads</button>}</div>
            <div className="card"><h2>Noise kept out of the lists</h2>
              {filteredTotal ? (<>
                {Object.entries(D.filtered).map(([st, m]) => (
                  <div key={st}><b>{st}</b> <span className="chips" style={{ display: "inline-flex" }}>{Object.entries(m).map(([k, v]) => <span className="chip" key={k}>{n(v)} {k}</span>)}</span></div>))}
                <p className="hint">Static files, parameter/ID variants and duplicates. All of it remains in raw evidence.</p></>) : <div className="hint">Nothing was filtered.</div>}</div>
          </div>
          <div className="card"><h2>Stages</h2>
            <Timeline stages={stages} /></div>
        </div>)}

        {tab === "leads" && <Table rows={leads} initialSort={null} searchKeys={["title", "subject", "evidence", "type"]}
          filters={[{ key: "p", label: "Priority", get: (r) => r.priority }, { key: "t", label: "Type", get: (r) => r.type }, { key: "s", label: "State", get: (r) => r.state }]}
          onRow={(r) => open(r.title, [["Priority", r.priority], ["Type", r.type], ["Subject", r.subject], ["Evidence", r.evidence], ["Rule", r.rule], ["State", r.state], ["Verified", "no — static heuristic only"]])}
          cols={[{ key: "priority", label: "Priority", render: (r) => <Pill v={r.priority} />, sortBy: (r) => ({ high: 0, medium: 1, low: 2 }[r.priority]) },
            { key: "title", label: "Lead" }, { key: "subject", label: "Subject", mono: true, render: (r) => shortUrl(r.subject) }, { key: "state", label: "State", render: state }]} />}

        {tab === "hosts" && <Table rows={live} searchKeys={["key", (r) => r.attrs?.title, (r) => (r.attrs?.tech || []).join(" ")]}
          filters={[{ key: "c", label: "Status", get: (r) => String(r.attrs?.status_code || "") }]}
          onRow={(r) => open(r.key, [["Status", r.attrs?.status_code], ["Title", r.attrs?.title], ["Server", r.attrs?.webserver], ["Technologies", r.attrs?.tech], ["Location", r.attrs?.location], ["Found by", r.sources], ["First seen in run", r.first_run], ["State", r.state]])}
          cols={[{ key: "key", label: "URL", mono: true }, { key: "code", label: "Status", get: (r) => r.attrs?.status_code || "", num: true },
            { key: "title", label: "Title", get: (r) => r.attrs?.title || "" }, { key: "tech", label: "Tech", get: (r) => (r.attrs?.tech || []).join(", ") },
            { key: "state", label: "State", render: state }]} />}

        {tab === "subs" && <Table rows={subs} searchKeys={["key"]} filters={[{ key: "s", label: "State", get: (r) => r.state }]}
          onRow={(r) => open(r.key, [["Found by", r.sources], ["First seen in run", r.first_run], ["State", r.state]])}
          cols={[{ key: "key", label: "Subdomain", mono: true }, { key: "src", label: "Sources", get: (r) => (r.sources || []).join(", ") }, { key: "state", label: "State", render: state }]} />}

        {tab === "endpoints" && <Table rows={urls} initialSort={{ key: "score", dir: -1 }} searchKeys={["url", (r) => (r.params || []).join(" ")]}
          filters={[{ key: "c", label: "Class", get: (r) => r.class }, { key: "o", label: "Origin", get: (r) => r.origin }, { key: "s", label: "State", get: (r) => r.state }]}
          onRow={(r) => open(r.url, [["Class", r.class], ["Score", r.score], ["Origin", r.origin === "crawled" ? "crawled live this run" : "web archive only (may no longer exist)"], ["Parameters", r.params], ["Found by", r.sources], ["State", r.state]])}
          cols={[{ key: "score", label: "Score", num: true }, { key: "url", label: "URL", mono: true }, { key: "class", label: "Class" }, { key: "origin", label: "Origin" },
            { key: "params", label: "Params", get: (r) => (r.params || []).join(", ") }, { key: "state", label: "State", render: state }]} />}

        {tab === "js" && (<div className="grid">
          <div className="card"><h2>API paths and URLs extracted from JavaScript</h2>
            <p className="hint">Static regex matches: unverified, may be dead code. Third-party and static matches are hidden by default via the class filter.</p>
            <Table rows={cands.filter((c) => c.type !== "library")} initialSort={{ key: "score", dir: -1 }} searchKeys={["value", "rule"]}
              filters={[{ key: "c", label: "Class", get: (r) => r.class }, { key: "t", label: "Type", get: (r) => r.type }]}
              onRow={(r) => open(r.value, [["Type", r.type], ["Class", r.class], ["Rule", r.rule], ["Verification", r.verification], ["Found in", r.source_urls], ["SHA-256", r.sha256]])}
              cols={[{ key: "score", label: "Score", num: true }, { key: "value", label: "Value", mono: true }, { key: "type", label: "Type" }, { key: "class", label: "Class" },
                { key: "files", label: "Files", get: (r) => (r.source_urls || []).length, num: true }]} /></div>
          <div className="card"><h2>JavaScript files analysed</h2>
            <Table rows={D.javascript || []} searchKeys={["sha256", (r) => (r.source_urls || []).join(" ")]}
              cols={[{ key: "urls", label: "Source", mono: true, get: (r) => (r.source_urls || [])[0] || "", render: (r) => (r.source_urls || []).map((u) => <div key={u}>{shortUrl(u)}</div>) },
                { key: "size", label: "Bytes", num: true, render: (r) => n(r.size) }, { key: "candidates", label: "Candidates", num: true }, { key: "state", label: "State", render: state }]} /></div>
          {(D.javascript_fetches || []).some((f) => f.outcome !== "ok") && <div className="card"><h2>Fetch problems</h2>
            <Table rows={(D.javascript_fetches || []).filter((f) => f.outcome !== "ok")} searchKeys={["url", "detail"]}
              cols={[{ key: "url", label: "URL", mono: true }, { key: "outcome", label: "Outcome", render: (r) => <Pill v={r.outcome === "rejected" ? "skipped" : "failed"} label={r.outcome} /> }, { key: "detail", label: "Detail" }]} /></div>}
        </div>)}

        {tab === "changes" && (
          <>
            <div className="banner" style={{ borderColor: "var(--line)" }}>{D.comparison?.note || (D.baseline_run_id ? `Compared with baseline ${D.baseline_run_id}.` : "No baseline.")}</div>
            <Table rows={changes} searchKeys={["key", "kind", "reason"]} filters={[{ key: "s", label: "State", get: (r) => r.state }, { key: "k", label: "Kind", get: (r) => r.kind }]}
              empty="Nothing changed, or there is no baseline yet."
              cols={[{ key: "state", label: "State", render: state }, { key: "kind", label: "Kind" }, { key: "key", label: "Item", mono: true }, { key: "reason", label: "Why" }]} />
          </>)}

        {tab === "runs" && (<div className="grid">
          <div className="card"><h2>Hosts and endpoints per run</h2><Spark history={D.history || []} /></div>
          <Table rows={D.history || []} searchKeys={["id", "status"]} pageSize={30}
            cols={[{ key: "id", label: "Run", mono: true, render: (r) => <>{r.id}{r.id === D.run.id && <span className="chip"> this report</span>}</> },
              { key: "status", label: "Status", render: (r) => <Pill v={r.status} /> }, { key: "started_at", label: "Started", render: (r) => when(r.started_at) },
              { key: "subs", label: "Subs", num: true, get: (r) => r.counts?.subdomain || 0 }, { key: "svc", label: "Live", num: true, get: (r) => r.counts?.service || 0 },
              { key: "urls", label: "URLs", num: true, get: (r) => r.counts?.url || 0 }, { key: "pr", label: "Problem stages", num: true, get: (r) => r.problem_stages }]} />
        </div>)}

        {tab === "pipeline" && (<div className="grid">
          <div className="card"><h2>Stages</h2><Timeline stages={stages} /></div>
          <Table rows={stages} searchKeys={["stage", "detail"]}
            cols={[{ key: "stage", label: "Stage" }, { key: "tool", label: "Tool", mono: true }, { key: "status", label: "Status", render: (r) => <Pill v={r.status} /> },
              { key: "duration_sec", label: "Time", num: true, render: (r) => dur(r.duration_sec) }, { key: "inputs", label: "In", num: true }, { key: "outputs", label: "Kept", num: true },
              { key: "dropped", label: "Out of scope", num: true }, { key: "retries", label: "Retries", num: true }, { key: "detail", label: "Detail" }]} />
          <div className="card"><h2>Tools</h2>
            <Table rows={D.tools || []} searchKeys={["tool", "detail"]} pageSize={20}
              cols={[{ key: "tool", label: "Tool" }, { key: "version", label: "Version", mono: true }, { key: "status", label: "Status", render: (r) => <Pill v={r.status} /> }, { key: "detail", label: "Detail" }]} /></div>
          {(D.errors || []).length > 0 && <div className="card"><h2>Errors</h2>
            {D.errors.map((e, i) => <div key={i} className="mono" style={{ padding: "3px 0" }}>[{e.stage}] {e.message}</div>)}</div>}
          <div className="card"><h2>Notes</h2>{(D.notes || []).map((t, i) => <p key={i} className="hint">{t}</p>)}</div>
        </div>)}
      </main>
      {sel && <Drawer title={sel.title} fields={sel.fields} onClose={() => setSel(null)} />}
    </>
  );
}

function Timeline({ stages }) {
  const max = Math.max(1, ...stages.map((s) => s.duration_sec || 0));
  return (
    <div className="timeline">{stages.map((s) => (
      <div className="tl" key={s.stage} title={s.detail}>
        <span>{s.stage}</span>
        <span style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <span className={`bar s-${s.status}`} style={{ width: `${Math.max(1, ((s.duration_sec || 0) / max) * 60)}%` }} />
          <Pill v={s.status} /><span className="hint">{dur(s.duration_sec)} · {n(s.outputs)} kept</span>
        </span>
      </div>))}</div>
  );
}

function Spark({ history }) {
  const h = [...history].reverse();
  if (h.length < 2) return <div className="hint">History appears after two or more runs.</div>;
  const W = 520, H = 70, P = 6;
  const series = [["Live hosts", (r) => r.counts?.service || 0, "var(--bar)"], ["URLs", (r) => r.counts?.url || 0, "var(--med)"]];
  return (
    <div className="grid two">{series.map(([label, get, color]) => {
      const vals = h.map(get), max = Math.max(1, ...vals);
      const pts = vals.map((v, i) => [P + (i * (W - 2 * P)) / (h.length - 1), H - P - (v / max) * (H - 2 * P)]);
      return (
        <div key={label}><div className="hint">{label} (latest {n(vals[vals.length - 1])}, peak {n(max)})</div>
          <svg className="spark" viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={`${label} per run`}>
            <polyline fill="none" stroke={color} strokeWidth="2" points={pts.map((p) => p.join(",")).join(" ")} />
            {pts.map((p, i) => <circle key={i} cx={p[0]} cy={p[1]} r="3.5" fill={color} stroke="var(--panel)" strokeWidth="2"><title>{`${h[i].id}: ${n(vals[i])} (${h[i].status})`}</title></circle>)}
          </svg></div>);
    })}</div>
  );
}

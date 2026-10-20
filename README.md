# ⚡ ReconFlow
### The Signal-Focused Reconnaissance Orchestrator

**One target. One workflow. A clearer view of your attack surface.**

ReconFlow is a Go-based reconnaissance orchestrator designed to organize external recon tools into a structured, dependency-aware workflow. It helps you collect assets, track discoveries, compare runs, and generate a self-contained HTML report.

> 🚧 **Early development — v0.1.0**
>
> Automated tests currently use mock tools. Real-tool compatibility and runtime behavior on Kali Linux have not yet been fully validated.

---

## 🚀 Why ReconFlow?

- ⚙️ **Automated Workflow** — Run reconnaissance stages in dependency order.
- 🎯 **Scope-Aware** — Validate target scope before execution.
- 🔄 **Change Tracking** — Compare discoveries across runs.
- 🧠 **Evidence & Provenance** — Keep track of where observations came from.
- 🧩 **JavaScript Intelligence** — Organize JavaScript-related discoveries for further analysis.
- 📊 **Interactive Reports** — Review results through a standalone HTML dashboard.
- ⏯️ **Execution Management** — Inspect run status and resume supported interrupted runs.

---

## 🗺️ How It Works

ReconFlow coordinates the workflow rather than replacing the underlying tools.

```mermaid
flowchart TD
    A["🎯 Target & Scope"] --> B["✅ Scope Validation"]
    B --> C["⚙️ Workflow Orchestrator"]
    C --> D["🌐 Subdomain Discovery"]
    D --> E["🔎 DNS Resolution"]
    E --> F["🟢 HTTP Probing"]
    F --> G["📦 URL Collection"]
    G --> H["🕷️ Crawling & JS Discovery"]
    H --> I["🧠 Normalize & Deduplicate"]
    I --> J["🔄 Compare with Baseline"]
    J --> K["📊 HTML Dashboard"]
    J --> L["📄 JSON & Other Artifacts"]

    classDef input fill:#172554,stroke:#60a5fa,color:#eff6ff
    classDef process fill:#132e27,stroke:#34d399,color:#ecfdf5
    classDef output fill:#312e81,stroke:#a5b4fc,color:#eef2ff

    class A,B input
    class C,D,E,F,G,H,I,J process
    class K,L output
```

---

## 🛠️ Integrated Tools

ReconFlow orchestrates external tools; each must be installed and compatible with the relevant workflow stage.

| Tool | Purpose |
|---|---|
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain discovery |
| [dnsx](https://github.com/projectdiscovery/dnsx) | DNS resolution |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing and metadata |
| [gau](https://github.com/lc/gau) | Historical URL collection |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Wayback Machine URL collection |
| [Katana](https://github.com/projectdiscovery/katana) | Web crawling |

*Actual execution depends on the configured pipeline, installed binaries, and their availability.*

---

## 📥 Installation

**Requirements**
- Linux environment — Kali Linux is the intended target.
- Go `1.27.0+`, as declared by the project.
- Git and the external tools required by your selected workflow.

### 1. Clone the repository

```bash
git clone <YOUR-REPOSITORY-URL>
cd reconflow
```

### 2. Install

```bash
chmod +x install.sh
./install.sh
```

If the repository is already on your machine, skip the clone step. The installer is intended for Linux environments.

### 3. Build from source

```bash
go build -o reconflow .
```

> **Note:** Confirm the installer and required tool versions on your system before running a real engagement.

---

## ⚡ Quick Start

Check the available options first:

```bash
./reconflow --help
```

Validate the target scope:

```bash
./reconflow validate-scope
```

Run a passive workflow:

```bash
./reconflow --passive
```

Start a fresh run:

```bash
./reconflow --new
```

Generate a report:

```bash
./reconflow report
```

**Important:** These commands illustrate the intended CLI workflow. Check `--help` and the project configuration for the exact arguments required by your current build.

---

## 📊 Results & Dashboard

ReconFlow organizes results into machine-readable artifacts and a standalone HTML report.

| Output | Purpose |
|---|---|
| `latest.html` | Interactive HTML dashboard |
| `latest.json` | Consolidated report data |
| `execution.json` | Execution details |
| `coverage.json` | Workflow coverage information |
| JSONL inventories | Structured, line-by-line observations |
| Text change lists | Review newly observed or changed assets |
| SQLite database | Persistent structured data |

### Dashboard Highlights

- 📈 Review asset and workflow summaries.
- 🔍 Explore collected observations.
- 🧾 Inspect supporting evidence and provenance.
- 🔄 Review changes between runs.
- 📤 Use structured output for further analysis.

The report is designed to work locally without requiring a hosted dashboard.

---

## 🧰 Useful Commands

| Option / Command | Purpose |
|---|---|
| `--help` | Display CLI usage |
| `tools` | Inspect tool-related information |
| `validate-scope` | Validate configured scope |
| `--passive` | Select passive workflow mode |
| `--new` | Start a fresh run |
| `--all` | Select the full workflow |
| `--status` | Inspect execution status |
| `--resume` | Resume a supported run |
| `report` | Generate a report |

Refer to the current CLI help for required arguments and supported combinations.

---

## 🛡️ Scope & Responsible Use

ReconFlow is intended for authorized security research.

- ✅ Validate the permitted targets before running.
- 🔒 Follow the configured scope restrictions.
- 🚫 Exclusions take precedence over inclusions.
- 🧭 Discovering an asset does not automatically authorize testing it.
- ⚠️ External tools may perform their own DNS requests and network activity.
- 🔎 Treat collected indicators as leads for investigation, not confirmed vulnerabilities.

**Only run reconnaissance against systems you own or have explicit permission to assess.**

---

## 🧪 Project Status

ReconFlow is under active development.

| Area | Current status |
|---|---|
| Workflow orchestration | Implemented; integration validation remains |
| Automated testing | Mock-tool tests |
| Real external-tool compatibility | Not fully validated |
| Kali Linux runtime | Not yet fully validated |
| HTML dashboard | Implemented; real-run validation remains |
| Vulnerability verification | Not a substitute for manual validation |

ReconFlow is a reconnaissance workflow manager, **not a guarantee of vulnerability discovery**. Port scanning, TLS analysis, and vulnerability scanning should not be assumed unless explicitly implemented and configured.

---

## 👨‍💻 Development

Useful project checks:

```bash
make fmt
make vet
make test
make build
```

For implementation details, architecture, and technical decisions, see [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md).

---

## 📄 License

Check the repository for its `LICENSE` file before redistributing or reusing the project. If no license is present, usage and redistribution permissions should not be assumed.

---

<div align="center">

**⚡ ReconFlow**

*Less noise. Better visibility. More structured reconnaissance.*

Built for a more organized bug bounty workflow.

</div>

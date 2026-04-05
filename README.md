# Conan — AI Governance & Detection CLI

**Detect, inspect, and govern AI service usage across your infrastructure.**

Conan is an open-source security tool written in Rust that discovers AI service usage on your systems — network traffic, running processes, shell history, browser history, and source code — and enforces governance policies via a simple TOML config. Think of it as `grep` for AI sprawl: API key leaks, shadow AI usage, unapproved model connections, and DLP violations, all in one binary.

> **Keywords:** AI governance · shadow AI detection · API key scanner · DLP · security compliance · OpenAI · Anthropic · Rust security tool

[![CI](https://github.com/thinkgrid-labs/conan/actions/workflows/ci.yml/badge.svg)](https://github.com/thinkgrid-labs/conan/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

---

## Table of Contents

- [Why conan?](#why-conan)
- [Use Cases](#use-cases)
- [Install](#install)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Commands](#commands)
  - [scan](#conan-scan)
  - [report](#conan-report)
  - [daemon](#conan-daemon)
  - [service](#conan-service)
  - [status](#conan-status)
  - [signatures](#conan-signatures)
  - [policy](#conan-policy)
  - [doctor](#conan-doctor)
- [Policy as Code](#policy-as-code)
- [Signatures](#signatures)
- [Risk Scoring](#risk-scoring)
- [Data & Privacy](#data--privacy)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)

---

## Why conan?

AI services are being adopted faster than security teams can track. Developers connect to OpenAI, Anthropic, and Hugging Face APIs; employees use ChatGPT from their work laptops; codebases accumulate hardcoded API keys. Most organisations have no idea which AI services are actually running inside their infrastructure — until a compliance audit, a data breach, or a leaked key forces the question.

Conan gives you visibility and control without requiring network proxies, cloud agents, or vendor lock-in.

**Key properties:**

- **Local-first** — all scan data stays on your machine or in your private SQLite database. Nothing is phoned home.
- **Single binary, no runtime deps** — drop it on any Linux, macOS, or Windows machine and run. No Docker, no JVM, no Python.
- **Multi-surface detection** — one tool scans network traffic, running processes, shell history, browser history, and source code simultaneously.
- **Community-driven signatures** — AI service fingerprints are plain YAML files. Adding support for a new service takes five minutes and no Rust knowledge.
- **Policy as code** — define allow/warn/block rules in a TOML file that lives in version control alongside your application code.
- **CI/CD native** — outputs SARIF so findings appear directly in the GitHub Security tab, with a ready-made GitHub Action.

---

## Use Cases

### Security & Compliance teams

**Shadow AI discovery** — Employees install and use AI tools that have never been approved. Conan's process and network scanners detect connections to OpenAI, Anthropic, Mistral, and 8 other services, giving your security team a full picture without deploying a network proxy.

**API key leak detection** — Run `conan scan --source codebase` in CI to catch hardcoded API keys before they reach production. Supports OpenAI, Anthropic, HuggingFace, Google AI, and a generic high-entropy key pattern. Results are reported as SARIF findings in the GitHub Security tab.

**Audit evidence** — `conan report --format html` produces a timestamped, self-contained report you can attach to a compliance audit or incident ticket.

```bash
# Weekly audit report for the security team
conan scan && conan report --format html > audit-$(date +%Y-%m-%d).html
```

---

### Platform & DevOps teams

**Continuous governance** — Run the daemon on developer workstations or build servers. It scans every 5 minutes (configurable), persists findings to SQLite, and fires a Slack webhook when a high-risk event is detected — no additional infrastructure required.

```bash
conan daemon start          # background process, survives shell exit
conan report --live         # watch findings stream in real time
```

**Policy enforcement in CI** — Block merges if a PR introduces a connection to an unapproved AI service or a DLP-sensitive pattern:

```yaml
# .github/workflows/conan.yml
- uses: thinkgrid-labs/conan-action@v0.2
  with:
    fail-on: high
```

---

### Development teams

**Pre-commit key scanning** — Catch leaked secrets before `git push`. Conan's codebase ingestor scans `.js`, `.ts`, `.py`, `.go`, `.rs`, and 12 other extensions and reports the exact file and line number.

```bash
# Add to .git/hooks/pre-commit
conan scan --source codebase --path . --output pretty
```

**Understand your AI surface area** — New to a codebase? Run `conan scan --source all` to immediately see which AI services the project talks to, what keys are present, and what processes are running — all in one command.

```bash
conan scan --source all --output json | jq '.[] | {service, risk_level, detail}'
```

---

### Individual developers

**Spot AI usage you forgot about** — That API key you pasted into a config file six months ago, the browser tab running a local Ollama model, the shell history full of `openai` CLI invocations — conan surfaces all of it.

```bash
conan scan         # one-shot scan, pretty output
conan doctor       # check what conan can see on this machine
```

**Local-first, no account needed** — Unlike SaaS security tools, conan stores everything in `~/.conan/findings.db`. No sign-up, no telemetry, no data leaving your machine.

---

## Install

### From crates.io

```bash
cargo install conan
```

### Pre-built binaries

Download the latest release for your platform from the [Releases page](https://github.com/thinkgrid-labs/conan/releases):

```bash
# macOS (Apple Silicon)
curl -L https://github.com/thinkgrid-labs/conan/releases/latest/download/conan-macos-aarch64.tar.gz | tar xz
sudo mv conan /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/thinkgrid-labs/conan/releases/latest/download/conan-macos-x86_64.tar.gz | tar xz
sudo mv conan /usr/local/bin/

# Linux (x86_64)
curl -L https://github.com/thinkgrid-labs/conan/releases/latest/download/conan-linux-x86_64.tar.gz | tar xz
sudo mv conan /usr/local/bin/

# Linux (ARM64)
curl -L https://github.com/thinkgrid-labs/conan/releases/latest/download/conan-linux-aarch64.tar.gz | tar xz
sudo mv conan /usr/local/bin/
```

**Windows** — download `conan-windows-x86_64.zip` from the Releases page, extract it, and add the folder to your `PATH`:

```powershell
# PowerShell (run as Administrator)
Expand-Archive conan-windows-x86_64.zip -DestinationPath C:\conan
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\conan", "Machine")
```

Or place `conan.exe` anywhere already on your `PATH` (e.g. `C:\Windows\System32`).

### From source

```bash
git clone https://github.com/thinkgrid-labs/conan.git
cd conan
cargo build --release
# binary is at ./target/release/conan
```

### First-time setup

```bash
# Check that everything is healthy
conan doctor

# Load the bundled signatures
conan signatures list
```

Conan stores its data in `~/.conan/` — signatures, findings database, policy, and daemon logs.

---

## Quick Start

```bash
# Scan everything on your machine (processes, shell history, browser history, network)
conan scan --source all

# Scan only OS-level sources (processes + shell history)
conan scan --source os

# Scan a codebase for hardcoded API keys and unapproved AI SDKs
conan scan --source codebase --path ./my-project

# Scan with a governance policy, output as JSON
conan scan --source all --policy ~/.conan/policy.toml --output json

# Run continuously, re-scanning every 30 seconds
conan scan --source all --watch 30

# Query findings from the last 24 hours
conan report --last 24

# Start the background daemon (monitors 24/7)
conan daemon start
conan status
```

---

## How It Works

```
Sources                  Analysis                  Output
─────────────────────    ──────────────────────    ──────────────────
Network traffic    ─┐
Running processes  ─┼──► Signature matching  ──►  Findings (SQLite)
Shell history      ─┤    DLP pattern scan    ──►  Console / JSON / MD
Browser history    ─┤    Policy evaluation   ──►  Slack / Discord
Codebase files     ─┘                             GitHub Security
```

1. **Ingestors** collect raw events from each source.
2. The **Analysis Engine** matches events against the signature registry and runs DLP patterns.
3. A **risk score** (0–100) is calculated from the signature's base score plus DLP and policy multipliers.
4. The **Policy Engine** evaluates rules and decides: allow, warn, or block.
5. **Findings** are written to `~/.conan/findings.db` and optionally sent as alerts.

---

## Commands

### `conan scan`

Run a one-shot scan against one or more sources.

```
conan scan [OPTIONS]

Options:
  -s, --source <SOURCE>      Sources: net | os | browser | shell | codebase | pcap | all  [default: all]
  -p, --policy <PATH>        Path to policy TOML file
  -o, --output <FORMAT>      Output format: pretty | json | markdown | sarif  [default: pretty]
      --path <PATH>          Root path for codebase scanning  [default: .]
  -w, --watch <SECS>         Re-scan every N seconds (continuous mode)
      --diff                 Only re-scan files changed since last run (git-aware; codebase source)
      --pcap-secs <SECS>     Duration for live packet capture (--source pcap)  [default: 10]
      --pcap-iface <IFACE>   Network interface for pcap capture (--source pcap)
  -v, --verbose              Enable debug output
```

**Examples:**

```bash
# Quick OS scan with pretty output
conan scan --source os

# Network scan with JSON output (good for SIEM pipelines)
conan scan --source net --output json | jq '.[] | select(.risk_level == "CRITICAL")'

# Codebase scan from CI — output SARIF for GitHub Code Scanning
conan scan --source codebase --path . --output sarif > results.sarif

# Codebase scan from CI — fail on any finding with risk >= high
conan scan --source codebase --path . --output json \
  | jq 'map(select(.risk_score >= 51)) | length' \
  | xargs -I{} test {} -eq 0

# Incremental scan — only re-scan files changed since last run
conan scan --source codebase --path . --diff

# Continuous monitoring every minute
conan scan --source all --watch 60

# Live packet capture for 30 seconds on a specific interface
conan scan --source pcap --pcap-secs 30 --pcap-iface en0

# Markdown report piped to a file
conan scan --source all --output markdown > ai-report.md
```

---

### `conan report`

Query findings stored in the local SQLite database.

```
conan report [OPTIONS]

Options:
      --last <HOURS>     Show findings from the last N hours
      --live             Stream new findings in real-time (polls DB every second)
      --format <FORMAT>  Output format: pretty | json | markdown | html  [default: pretty]
```

**Examples:**

```bash
# Show all findings from the last 24 hours
conan report --last 24

# Show all stored findings as JSON
conan report --format json

# Generate a self-contained HTML report
conan report --format html > report.html

# Stream live findings from the daemon
conan report --live
```

**Pretty output:**

```
[CRITICAL]  [BLOCKED ]  (rule: block-dlp-critical)  openai               openai — API key in cmdline
[HIGH    ]  [WARN    ]  (rule: warn-unapproved-cloud)  anthropic          anthropic — process 'anthropic' running (pid 4821)
[LOW     ]  [ALLOWED ]                                 ollama             ollama — process running (pid 8821)
```

---

### `conan daemon`

Control the long-running background daemon. The daemon continuously monitors your system and writes findings to SQLite without requiring you to run manual scans.

```
conan daemon <COMMAND>

Commands:
  start         Start the background daemon
  stop          Stop the background daemon
  restart       Restart the background daemon
  logs          Print daemon logs
    --follow    Tail logs in real-time
```

**Examples:**

```bash
conan daemon start
conan daemon logs --follow
conan daemon restart
conan daemon stop
```

The daemon reads its config from `~/.conan/config.toml`. See [Configuration](#configuration).

---

### `conan service`

Install conan as an OS-level service so it starts automatically on login or boot.

```
conan service <COMMAND>

Commands:
  install     Register as a system service (launchd on macOS, systemd on Linux)
  uninstall   Remove the system service
  status      Show service status
```

**Examples:**

```bash
# macOS — installs a launchd plist in ~/Library/LaunchAgents/
sudo conan service install
sudo conan service status

# Linux — installs a systemd unit in /etc/systemd/system/
sudo conan service install
sudo systemctl status conan
```

---

### `conan status`

Show the current status of the running daemon, including uptime, finding counts, and data directory.

```bash
conan status
```

```
● conan daemon running (pid 4821)
  findings today : 6
  data dir       : /Users/alice/.conan
```

---

### `conan signatures`

Manage AI service signature files.

```
conan signatures <COMMAND>

Commands:
  list                    List all loaded signatures
  validate <FILE>         Validate a signature YAML file for correctness
  update                  Fetch the latest signatures from upstream
  schedule                View or configure automatic update schedule
    --set-hours <N>       Enable auto-update every N hours (0 = disable)
    --disable             Disable automatic updates
```

**Examples:**

```bash
# List all loaded signatures with risk levels
conan signatures list

# Validate a new signature before submitting a PR
conan signatures validate signatures/my-new-service.yaml

# Pull the latest signature updates manually
conan signatures update

# Enable automatic updates every 24 hours (runs via daemon)
conan signatures schedule --set-hours 24

# Change to every 6 hours
conan signatures schedule --set-hours 6

# Show the current auto-update schedule and last-updated time
conan signatures schedule

# Disable auto-update
conan signatures schedule --disable
```

**`signatures list` output:**

```
ID                   VERSION    RISK    NAME
------------------------------------------------------------
anthropic            1.0.0      60      Anthropic / Claude
azure-openai         1.0.0      55      Azure OpenAI Service
cohere               1.0.0      55      Cohere
google-ai            1.0.0      60      Google AI (Gemini / Vertex)
groq                 1.0.0      55      Groq
huggingface          1.0.0      50      Hugging Face
localai              1.0.0      15      LocalAI
mistral              1.0.0      55      Mistral AI
ollama               1.0.0      20      Ollama (Local LLM)
openai               1.0.0      65      OpenAI
perplexity           1.0.0      50      Perplexity AI
```

---

### `conan policy`

Validate and inspect policy files without running a scan.

```
conan policy <COMMAND>

Commands:
  lint <FILE>    Check a policy file for syntax errors
  check <FILE>   Dry-run — show which rules would fire and their actions
```

**Examples:**

```bash
conan policy lint ~/.conan/policy.toml
conan policy check policy/strict.toml
```

---

### `conan doctor`

Diagnose your conan installation and environment.

```bash
conan doctor
```

```
conan doctor

  ✓ data directory              /Users/alice/.conan
  ✓ signatures loaded           11 YAML files in /Users/alice/.conan/signatures
  ✓ default policy              /Users/alice/.conan/policy.toml
  ✓ findings database           /Users/alice/.conan/findings.db
  ✗ libpcap (for net scanning)  MISSING — install with: brew install libpcap
```

---

## Policy as Code

Define governance rules in a TOML file. Rules are evaluated top-to-bottom; the first match wins.

```toml
# ~/.conan/policy.toml
version = "1.0"

# Default action when no rule matches
mode = "warn"   # "allow" | "warn" | "block"

# ── Rules ──────────────────────────────────────────────────────────────────────

[[rules]]
id = "allow-local-models"
description = "Local models (ollama, localai) are always permitted."
trigger = "ai_detected"
tags = ["local"]
action = "allow"

[[rules]]
id = "block-data-exfil"
description = "Block any AI call where a secret or PII is detected in the payload."
trigger = "dlp_match"
action = "block"
notify = ["slack", "discord"]

[[rules]]
id = "warn-unapproved-cloud"
description = "Warn on any cloud AI service not in the approved list."
trigger = "ai_detected"
exclude_ids = ["openai", "anthropic"]   # approved services — no warning for these
action = "warn"
notify = ["slack"]

# ── Notification Channels ──────────────────────────────────────────────────────

[notifications.slack]
webhook_url = "${CONAN_SLACK_WEBHOOK}"   # reads from environment variable

[notifications.discord]
webhook_url = "${CONAN_DISCORD_WEBHOOK}"
```

### Triggers

| Trigger | Fires when |
|---------|-----------|
| `ai_detected` | Any AI service signature is matched |
| `dlp_match` | A secret or PII pattern is found in the event payload |
| `any` | Always (use for catch-all rules) |

### Rule Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique rule identifier |
| `description` | string | Human-readable description |
| `trigger` | string | `ai_detected` \| `dlp_match` \| `any` |
| `exclude_ids` | list | Signature IDs exempt from this rule |
| `tags` | list | Only match signatures with these tags |
| `min_score` | integer | Only fire if the computed risk score is ≥ this value (0–100) |
| `action` | string | `allow` \| `warn` \| `block` |
| `notify` | list | Channels to alert: `slack`, `discord` |
| `score_override` | integer | Pin the finding's risk score to this value when the rule matches |

### Score Thresholds

Applied after rules, before falling back to `mode`. Useful as a safety net without writing individual rules:

```toml
[thresholds]
block = 90   # auto-block anything scoring ≥ 90 (no rule needed)
warn  = 60   # auto-warn anything scoring ≥ 60
```

---

## Signatures

Signatures are plain YAML files in `signatures/`. They describe a known AI service and how to detect it.

### Full signature schema

```yaml
id: openai                              # unique, lowercase, hyphenated
name: OpenAI                            # human-readable display name
version: "1.0.0"                        # semver — bump when you change fingerprints
risk_base: 65                           # 0–100 baseline risk score
privacy_policy_url: "https://..."       # optional

# Domains to match against network traffic and browser history
domains:
  - api.openai.com
  - openai.com
  - chatgpt.com

# IP ranges (CIDR) for network-level matching (optional)
ip_ranges:
  - "23.102.140.112/28"

# Process names to detect in running processes and shell history
process_names:
  - openai
  - chatgpt

# HTTP fingerprints (for packet inspection in M2)
http_patterns:
  user_agents:
    - openai-python
    - openai-node

# DLP patterns — scanned against request payloads and shell commands
dlp_patterns:
  - id: openai_api_key
    pattern: "sk-[A-Za-z0-9]{20,}"
    severity: critical          # critical | high | low
  - id: openai_org_id
    pattern: "org-[A-Za-z0-9]{24}"
    severity: high

# Tags used for policy rule matching
tags: [llm, cloud, paid, openai]
```

### Contributing a signature

No Rust knowledge required. To add a new AI service:

1. Fork the repository.
2. Copy `signatures/openai.yaml` as a template.
3. Fill in the fields for your service.
4. Validate it locally:
   ```bash
   conan signatures validate signatures/my-service.yaml
   ```
5. Open a pull request. The CI pipeline runs `conan signatures validate` on all changed YAML files automatically.

### Bundled signatures

| ID | Service | Risk Base | Tags |
|----|---------|-----------|------|
| `openai` | OpenAI | 65 | llm, cloud, paid |
| `anthropic` | Anthropic / Claude | 60 | llm, cloud, paid |
| `google-ai` | Google AI (Gemini / Vertex) | 60 | llm, cloud, paid |
| `azure-openai` | Azure OpenAI Service | 55 | llm, cloud, paid, azure |
| `mistral` | Mistral AI | 55 | llm, cloud, paid, open-weights |
| `groq` | Groq | 55 | llm, cloud, paid, inference |
| `cohere` | Cohere | 55 | llm, cloud, paid |
| `huggingface` | Hugging Face | 50 | llm, cloud, open-source |
| `perplexity` | Perplexity AI | 50 | llm, cloud, paid, search |
| `ollama` | Ollama (Local LLM) | 20 | llm, local, free |
| `localai` | LocalAI | 15 | llm, local, free |

---

## Risk Scoring

Every finding receives a risk score from 0 to 100.

```
final_score = base_risk × policy_multiplier × dlp_multiplier

base_risk          — from signature.risk_base (0–100)
policy_multiplier  — 1.5 if unapproved, 1.0 if approved
dlp_multiplier     — 2.0 if dlp_match is critical
                     1.5 if dlp_match is high
                     1.0 if no DLP match
```

| Score | Level | Default action |
|-------|-------|----------------|
| 0–25 | **Low** | Informational |
| 26–50 | **Medium** | Warning |
| 51–75 | **High** | Alert |
| 76–100 | **Critical** | Block |

---

## Data & Privacy

- All findings are stored **locally** in `~/.conan/findings.db` (SQLite). Nothing is sent to external servers by conan itself.
- The `--source net` flag requires capturing network traffic, which may require `sudo` on some systems.
- Browser history scanning copies the history file to a temp file, reads URLs, and deletes the copy immediately.
- DLP patterns only record which *pattern* matched — not the full matched text.

---

## Project Structure

```
conan/
├── Cargo.toml                  # workspace manifest
├── src/
│   ├── main.rs                 # CLI entry point, data_dir()
│   ├── analyzer.rs             # analysis engine (signature + DLP matching)
│   ├── reporter.rs             # pretty / json / markdown / html output
│   ├── sarif.rs                # SARIF 2.1.0 output builder
│   ├── webhook.rs              # HTTP webhook client with per-service debounce
│   ├── config.rs               # ~/.conan/config.toml loader
│   ├── diff.rs                 # git-aware incremental scan state
│   ├── sig_updater.rs          # signature auto-update scheduler
│   └── cli/
│       ├── mod.rs              # Cli struct + Commands enum (clap)
│       ├── scan.rs             # conan scan
│       ├── report.rs           # conan report
│       ├── signatures.rs       # conan signatures
│       ├── policy.rs           # conan policy
│       ├── daemon_cmd.rs       # conan daemon
│       ├── service.rs          # conan service
│       ├── status.rs           # conan status
│       └── doctor.rs           # conan doctor
├── crates/
│   ├── conan-core/             # traits, types, registry, policy engine, risk scoring
│   ├── conan-net/              # DNS, active connections, pcap capture (optional feature)
│   ├── conan-os/               # process, shell history, browser history, codebase ingestors
│   └── conan-db/               # SQLite store (rusqlite + migrations)
├── signatures/                 # YAML AI service fingerprints (community-contributed)
├── policy/
│   └── default.toml            # starter policy file
└── .github/
    ├── workflows/
    │   ├── ci.yml              # test + clippy + signature validation on every PR
    │   └── release.yml         # cross-platform binary builds on tag push
    ├── ISSUE_TEMPLATE/         # bug, feature, and signature-request templates
    └── action.yml              # conan-action: scan codebase + upload SARIF
```

### Crate responsibilities

| Crate | Responsibility |
|-------|---------------|
| `conan-core` | `Ingestor`, `Analyzer` traits; `Event`, `Finding`, `Signature`, `Policy`, `RiskScore` types |
| `conan-os` | `ProcessIngestor`, `ShellHistoryIngestor`, `BrowserHistoryIngestor`, `CodebaseIngestor` |
| `conan-net` | `DnsIngestor`, `ActiveConnectionIngestor`; `PcapIngestor` (opt-in via `--features pcap-capture`) |
| `conan-db` | `Store::open`, `insert_finding`, `query_findings`, `query_findings_since`, `finding_count_today` |

---

## Configuration

Conan reads `~/.conan/config.toml` for daemon, webhook, and signature settings. All fields are optional — conan works without a config file.

```toml
[daemon]
# Seconds between scan cycles. Default: 300 (5 minutes).
scan_interval_secs = 300

[webhook]
# HTTP endpoint for finding alerts (Slack, Discord, or any webhook receiver).
url = "${CONAN_WEBHOOK_URL}"
# Minimum seconds between repeated alerts for the same service. Default: 30.
debounce_secs = 60

[signatures]
# Enable automatic signature updates. Runs on each daemon cycle when due.
auto_update = true
# How often to auto-update (hours). Default: 24.
update_interval_hours = 24
# Override the upstream URL (optional — defaults to the official GitHub repo).
# upstream_base = "https://raw.githubusercontent.com/thinkgrid-labs/conan/main/signatures"
```

All settings can also be managed via CLI commands:

```bash
# Configure signature auto-update schedule
conan signatures schedule --set-hours 24

# Show current schedule and last-updated time
conan signatures schedule
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `CONAN_WEBHOOK_URL` | Webhook URL override (takes precedence over config.toml) |
| `CONAN_SLACK_WEBHOOK` | Slack incoming webhook URL (used by policy `notify = ["slack"]`) |
| `CONAN_DISCORD_WEBHOOK` | Discord webhook URL (used by policy `notify = ["discord"]`) |
| `RUST_LOG` | Log filter (e.g. `conan=debug`, `warn`) |

---

## Contributing

Contributions are welcome — code, signatures, or policy templates.

### Development setup

```bash
git clone https://github.com/thinkgrid-labs/conan.git
cd conan
cargo build
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

### Adding a new scan source

1. Implement `Ingestor` from `conan-core` in the appropriate crate (`conan-os` or `conan-net`).
2. Export it from the crate's `lib.rs`.
3. Wire it into `src/cli/scan.rs` under the matching `ScanSource` variant.
4. Add integration tests.

### Adding a signature (no Rust needed)

See [Contributing a signature](#contributing-a-signature) above.

---

## Roadmap

Conan covers the core detection and governance loop. Here are the high-impact areas being considered for future releases — contributions welcome.

### Detection & Coverage

- **`conan scan --source env`** — Scan environment variables and `.env` files for live API keys; catches secrets that never touch the codebase but are present in the running environment.
- **`conan scan --source git-history`** — Walk the full git commit history of a repository to find API keys that were committed and later deleted; surfaces secrets that `--diff` would miss.
- **Container & Kubernetes support** — Scan running containers and pod environment variables for AI service connections; particularly useful in multi-tenant clusters where shadow AI can appear in any namespace.
- **Expanded signature library** — Coverage for Cohere, Together AI, Replicate, AWS Bedrock, Fireworks, and other emerging inference providers; IP range matching for cloud AI endpoints.

### Policy & Enforcement

- **OPA / Rego integration** — Allow enterprise teams to write governance rules in Open Policy Agent's Rego language rather than conan's TOML format, enabling re-use of existing policy infrastructure.
- **Policy drift detection** — Track policy changes over time and alert when a previously blocked service becomes allowed (or vice versa); useful for audit trails and SOC 2 compliance.
- **`conan scan --block`** — Exit with a non-zero code when any `block`-action finding is produced, making policy enforcement a hard gate in CI/CD without needing `jq` post-processing.
- **Per-repository policy files** — Load `.conan/policy.toml` from the scanned directory and merge it with the global policy; allows teams to self-serve governance rules within guardrails set by security.

### Alerting & Integrations

- **Email alerts** — SMTP-based alert delivery for organisations that don't use Slack or Discord.
- **PagerDuty / OpsGenie integration** — Route critical findings (score ≥ 76) directly to on-call, matching the severity model already built into the policy engine.
- **SIEM export (`conan export`)** — Emit findings as CEF, Syslog, or OCSF events for ingestion into Splunk, Elastic SIEM, or Microsoft Sentinel.
- **GitHub App** — Post finding summaries as PR review comments so developers see results without leaving GitHub; complements the existing GitHub Action.

### Developer Experience

- **Local web dashboard (`conan serve`)** — A lightweight local web server (no cloud) showing findings over time, risk trends, and per-service breakdowns; replaces `conan report --format html` for interactive use.
- **VSCode / JetBrains extension** — Real-time DLP and API key highlighting as you type, backed by conan's existing codebase scanner and signature set.
- **`conan init`** — Interactive setup wizard: downloads signatures, generates a starter `policy.toml` tailored to the detected tech stack, and optionally installs the daemon as a system service.
- **Plugin API** — A stable `Ingestor` and `Analyzer` plugin interface so third parties can add new sources (e.g., Jupyter notebooks, Terraform state files) without forking the binary.

---

## License

Apache-2.0 — see [LICENSE](LICENSE).

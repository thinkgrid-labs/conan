# conan

**Detect, inspect, and govern AI service usage across your infrastructure.**

Conan is an open-source, modular AI usage scanner built in Rust. It discovers when AI services are being used on your systems — through network traffic, running processes, shell history, browser history, or source code — and lets you enforce governance policies with a simple TOML config.

[![CI](https://github.com/conan-ai/conan/actions/workflows/ci.yml/badge.svg)](https://github.com/conan-ai/conan/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

---

## Table of Contents

- [Why conan?](#why-conan)
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

AI services are being adopted faster than security teams can track. Developers connect to OpenAI, Anthropic, and Hugging Face APIs; employees use ChatGPT from their work laptops; codebases accumulate hardcoded API keys. Conan gives you visibility and control — without requiring network proxies, agents, or cloud infrastructure.

**Key properties:**

- **Local-first** — all data stays on your machine or in your private SQLite database.
- **Zero dependencies to run** — single static binary, no daemons required for one-shot scans.
- **Community-driven signatures** — AI service fingerprints are plain YAML files anyone can contribute.
- **Policy as code** — define allow/warn/block rules in a TOML file checked into version control.

---

## Install

### From crates.io

```bash
cargo install conan
```

### Pre-built binaries

Download the latest release for your platform from the [Releases page](https://github.com/conan-ai/conan/releases):

```bash
# macOS (Apple Silicon)
curl -L https://github.com/conan-ai/conan/releases/latest/download/conan-macos-aarch64.tar.gz | tar xz
sudo mv conan /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/conan-ai/conan/releases/latest/download/conan-macos-x86_64.tar.gz | tar xz
sudo mv conan /usr/local/bin/

# Linux (x86_64)
curl -L https://github.com/conan-ai/conan/releases/latest/download/conan-linux-x86_64.tar.gz | tar xz
sudo mv conan /usr/local/bin/
```

### From source

```bash
git clone https://github.com/conan-ai/conan.git
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
  -s, --source <SOURCE>   Sources: net | os | browser | shell | codebase | all  [default: all]
  -p, --policy <PATH>     Path to policy TOML file
  -o, --output <FORMAT>   Output format: pretty | json | markdown  [default: pretty]
      --path <PATH>       Root path for codebase scanning  [default: .]
  -w, --watch <SECS>      Re-scan every N seconds (continuous mode)
  -v, --verbose           Enable debug output
```

**Examples:**

```bash
# Quick OS scan with pretty output
conan scan --source os

# Network scan with JSON output (good for SIEM pipelines)
conan scan --source net --output json | jq '.[] | select(.risk_level == "CRITICAL")'

# Codebase scan from CI — fail on any finding with risk >= high
conan scan --source codebase --path . --output json \
  | jq 'map(select(.risk_score >= 51)) | length' \
  | xargs -I{} test {} -eq 0

# Continuous monitoring every minute
conan scan --source all --watch 60

# Markdown report piped to a file
conan scan --source all --output markdown > ai-report.md
```

---

### `conan report`

Query findings stored in the local SQLite database.

```
conan report [OPTIONS]

Options:
      --last <HOURS>   Show findings from the last N hours
      --live           Stream new findings in real-time (requires daemon)
```

**Examples:**

```bash
# Show all findings from the last 24 hours
conan report --last 24

# Show all stored findings
conan report

# Stream live findings from the daemon
conan report --live
```

**Output format:**

```
[CRITICAL]   openai               openai — API key pattern in request body
[HIGH    ]   anthropic            anthropic — unapproved service detected
[LOW     ]   ollama               ollama — process running (pid 8821)
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
  list              List all loaded signatures
  validate <FILE>   Validate a signature YAML file for correctness
  update            Fetch the latest signatures from upstream
```

**Examples:**

```bash
# List all loaded signatures with risk levels
conan signatures list

# Validate a new signature before submitting a PR
conan signatures validate signatures/my-new-service.yaml

# Pull the latest signature updates
conan signatures update
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
| `action` | string | `allow` \| `warn` \| `block` |
| `notify` | list | Channels to alert: `slack`, `discord` |

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
│   ├── reporter.rs             # pretty / json / markdown output
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
│   ├── conan-net/              # DNS lookup + active connection ingestors
│   ├── conan-os/               # process, shell history, browser history, codebase ingestors
│   └── conan-db/               # SQLite store (rusqlite + migrations)
├── signatures/                 # YAML AI service fingerprints (community-contributed)
├── policy/
│   └── default.toml            # starter policy file
└── .github/
    └── workflows/
        ├── ci.yml              # test + clippy + signature validation on every PR
        └── release.yml         # cross-platform binary builds on tag push
```

### Crate responsibilities

| Crate | Responsibility |
|-------|---------------|
| `conan-core` | `Ingestor`, `Analyzer`, `Reporter` traits; `Event`, `Finding`, `Signature`, `Policy`, `RiskScore` types |
| `conan-os` | `ProcessIngestor`, `ShellHistoryIngestor`, `BrowserHistoryIngestor`, `CodebaseIngestor` |
| `conan-net` | `DnsIngestor`, `ActiveConnectionIngestor` |
| `conan-db` | `Store::open`, `insert_finding`, `query_findings`, `finding_count_today` |

---

## Configuration

The daemon reads `~/.conan/config.toml`:

```toml
[daemon]
poll_interval_secs = 10         # how often to poll OS processes
net_interface = "en0"           # network interface for packet capture
log_level = "info"              # error | warn | info | debug
socket_path = "/tmp/conan.sock" # Unix socket for CLI↔daemon IPC

[signatures]
auto_update = true
update_schedule = "0 3 * * *"  # nightly at 3am (cron syntax)

[policy]
path = "~/.conan/policy.toml"

[alerts]
debounce_secs = 300             # suppress re-alerts for the same service within 5 min
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `CONAN_SLACK_WEBHOOK` | Slack incoming webhook URL |
| `CONAN_DISCORD_WEBHOOK` | Discord webhook URL |
| `RUST_LOG` | Log filter (e.g. `conan=debug`) |

---

## Contributing

Contributions are welcome — code, signatures, or policy templates.

### Development setup

```bash
git clone https://github.com/conan-ai/conan.git
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

### M1 — "Watcher" (current)
- [x] Workspace scaffold, CI, release pipeline
- [x] `conan-core` traits and types
- [x] Process, shell history, browser history, codebase ingestors
- [x] SQLite persistence with migrations
- [x] 11 bundled signatures
- [x] `conan scan`, `report`, `signatures`, `policy`, `doctor`
- [x] JSON, Markdown, and pretty output formats

### M2 — "Deep Diver"
- [ ] `conan-net`: pcap-based packet capture with HTTP header fingerprinting
- [ ] Background daemon with Unix socket IPC
- [ ] `conan daemon start/stop` with PID file management
- [ ] `conan service install` for macOS launchd + Linux systemd
- [ ] Webhook alerting (Slack + Discord) with debounce
- [ ] `conan report --live` streaming output
- [ ] `conan signatures update` (HTTP fetch from GitHub releases)
- [ ] HTML reporter with risk dashboard

### M3 — "Guardian"
- [ ] GitHub Action (`conan-action`) with SARIF output for GitHub Security tab
- [ ] WASM build target (`conan-wasm`) — usable in Cloudflare Workers
- [ ] Risk score thresholds configurable per-policy
- [ ] `conan scan --source cloud` (AWS CloudTrail, GCP audit logs)
- [ ] Signature auto-update via cron

---

## License

Apache-2.0 — see [LICENSE](LICENSE).

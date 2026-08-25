# Changelog

## [1.1.0] — 2026-08-24

One tool, two engines. The Go active-scan core and the Python tool are now a
single command: Python is the mind (orchestration, passive capture, classification,
LLM, the six report formats, the terminal GUI); Go is the hands (fast, low-memory
active discovery, TCP probing, banner grabbing, and the adaptive probe planner).

### Added

- **`--engine [python|go|auto]`.** `go` delegates active discovery/probing to the
  standalone binary and hands the result back to the full Python pipeline; `auto`
  picks Go when the binary is present, else Python. Default stays `python`, so the
  existing path is untouched and directly A/B-comparable. The Go binary is located
  via `$BANSHEE_ENGINE`, `PATH`, or the repo's `engine/` directory.
- **`--adaptive`** (Go engine): select probes by information gain per unit of
  detection risk and stop early once a device class is confident. The planner's
  audit trail — probes sent vs planned, probes saved, detection risk spent vs a
  full scan, and per-host device classification — now surfaces in the report and
  in the JSON output (a new optional `plan` block on `ScanResult`).
- **Cross-engine parity tests** (`tests/test_engine_parity.py`): drive both engines
  through the real CLI against real loopback listeners and assert they agree
  port-for-port (skip cleanly when the Go binary is not built).
- **CI now builds and tests the Go engine** (`go vet` + `go test`) on Linux and
  Windows, so cross-engine parity is verified on every push.
- **Release workflow** cross-compiles the Go engine for linux/amd64, linux/arm64,
  windows/amd64, and darwin amd64/arm64 and attaches the binaries to a GitHub
  Release on a version tag.

### Fixed

- **`--engine go` with a hostname target was refused.** The Go engine does no DNS,
  so a raw hostname never matched the IP allowlist and looked out of scope. Python
  now resolves hostnames to IPs before handing the Go engine concrete targets,
  mirroring the Python engine's own resolver, so both engines see the same
  in-scope target set.
- **Empty collections serialized as `null`.** A Go host with no open ports (and an
  empty scan) emitted `"services":null`/`"findings":null`/`"hosts":null`, which the
  pydantic models reject for a list field. The Go engine now emits `[]`, and the
  Python models tolerantly coerce `null` to `[]`/`{}` from any producer.

## [1.0.1] — 2026-08-21

Integration release. Three features shipped in 1.0.0 were implemented, tested and
documented but never connected to the CLI, so no user could reach them. This closes
that gap and adds end-to-end tests that drive the real CLI rather than the modules.

### Fixed

- **Plugin rules never loaded.** The loader required a top-level `id` per file while
  the shipped `example.yaml` nested rules under `rules:`, so `--plugins` was a
  guaranteed no-op. The loader now accepts both file shapes and the shipped rule pack
  parses. A test asserts the on-disk rules load.
- **SQLite persistence and rogue detection were unreachable.** Added `--db PATH` and
  `--baseline`. The MAC baseline is read before the run is written, so a host no longer
  matches itself.
- **Confidence policy ran before the passes that create findings.** `risk.tier_result`
  now runs after plugins, enrichment, SSVC, rogue detection and the agentic stage. The
  guarantee that LLM-inferred findings can never exceed POTENTIAL was previously
  bypassed by ordering.
- **Oversized targets exhausted memory.** A single target larger than
  `max_hosts_per_scan` is now refused with `TargetTooLargeError` (exit code 2) after an
  arithmetic size check, instead of materialising the address list — `10.0.0.0/8`
  previously built a 16.7-million-element list before any cap applied.
- **`config/settings.toml` was read by nothing.** It now backs the LLM model, base URL
  and timeout; unread keys were removed. The hardcoded `llama3` no longer silently
  overrides the configured model.
- **Rogue detection missed MACs stored in a different case.** Baseline lookups are
  normalised to lower case.
- **Two guaranteed false positives, found by scanning a real host.** Nothing in the
  pipeline ever populated `Service.banner`, so the negative-space check "SSH open with
  no banner - possible honeypot" fired on *every* SSH host alive. The TCP sweep now
  reads a server-speaks-first greeting on the connection it already opened (no extra
  packet, no change to the detection profile), and the check is gated to services the
  sweep actually connected to - a passively-observed service has no banner for the
  trivial reason that nobody opened a socket to it.
- **Clock skew reported single-homed hosts as anycast over long-haul paths.** RTT
  jitter alone pushed the two interval estimates past the disagreement threshold. When
  the measured wall-clock intervals themselves disagree that much, the input is
  unreliable and the result is now "unknown" rather than "anycast".
- **Crashed on a default Windows console.** The block-drawing startup banner raised
  `UnicodeEncodeError` on cp1252 before the scan began, so every invocation failed
  unless `PYTHONIOENCODING=utf-8` was set. An ASCII banner is used when the console
  encoding cannot represent the block glyphs.
- ReAct loop opened a new HTTP session per iteration; now one session per analysis.
- Four `asyncio.run()` calls per invocation collapsed into one event loop.
- README timing table listed delays that did not match `budget.py`; scope example used
  `allow:`/`deny:` instead of the real `allowlist:`/`denylist:`.
- SARIF output identified the tool as `pps` and pointed `informationUri` at a repository
  that does not exist. Any consumer ingesting BANSHEE findings — GitHub code scanning
  included — recorded the wrong tool. Default store path was likewise `pps.db`.

### Added

- `--ports` / `-p` — nmap-style port selection (`22,80,443` or `1-1024`). Previously
  there was no way to choose ports at all.
- `--sniff-timeout` — how long the passive sniffer listens, previously fixed at 10s
  with no way to change it, which is an odd gap for a passive-first tool. Also cuts
  the test suite from 55s to under 10s, since that time was almost entirely capture
  wait rather than work.
- Ground-truth test suite: binds real listeners on loopback, runs the real CLI, and
  asserts the reported ports equal the bound ports exactly — including the negative
  direction, that an unbound port is never reported open.
- Analysis toggles (`ssvc`, `plugins`, `agentic`, `classify`, `ports`, `db`) are now
  recorded in the serialised config, so a report consumer can tell "clean" from
  "that pass never ran".

### Changed

- `--classify` now defaults on. It is local and costs zero packets, and four downstream
  features silently degraded without it.

## [1.0.0] — 2025-06-07

First public release.

### What's in it

- Passive sniffer — discovers hosts from observed traffic, no packets sent
- TCP async sweep with T0–T5 timing templates
- ICMP ping (raw socket)
- PCAP replay — feed a saved capture file instead of live traffic
- OUI lookup — MAC to vendor
- DHCP lease parser — hostname + MAC from dnsmasq / ISC files
- TCP/IP stack fingerprinting — OS guess from TTL, window size, TCP flags
- TLS/JA4 passive fingerprinting
- Clock skew fingerprinting — identify devices by clock drift
- Name resolution — DNS, mDNS, NetBIOS, Zeroconf
- Device classifier — router / IoT / server / workstation
- Attack graph — maps pivot paths across the discovered host set
- Segment map — groups hosts by subnet, finds bridge hosts
- SSVC triage — local vulnerability prioritization
- EPSS + CISA KEV enrichment — opt-in, off by default
- YAML plugin rules — custom detections without writing code
- ReAct LLM loop via local Ollama
- Six report formats: TXT, JSON, XML, HTML, CSV, SARIF 2.1.0
- Live rich terminal dashboard during scan
- JSONL audit trail
- SQLite persistence across runs
- Rogue device detection against MAC baseline
- Scope guard — hard allowlist enforcement
- Docker support
- One-liner installer

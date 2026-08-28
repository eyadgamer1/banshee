# Changelog

## [1.7.0] — 2026-08-28

Scope is open by default, so BANSHEE scans any target out of the box like `nmap`.

### Changed

- **Open default scope (nmap-style).** The built-in default scope now admits
  every IPv4 and IPv6 target, so `banshee <any target>` works immediately with no
  scope file to edit. Previously the default allowed only loopback and RFC1918
  ranges and refused public addresses. **You are responsible for only scanning
  targets you are authorized to test** — unauthorized scanning is illegal in most
  jurisdictions.
- The scope engine is unchanged and still enforces any allowlist/denylist you
  supply. Pass `--scope your.yaml` to restrict BANSHEE to a lab or engagement
  range; out-of-scope targets are still refused with **exit code 3**.
- Raised the default per-scan caps to `max_hosts_per_scan: 1048576` and
  `max_ports_per_host: 65535` so realistic scans aren't capped by the default.
- The startup line and scope banner now print an open-scope authorization
  reminder instead of "loopback + RFC1918".

### Fixed

- Install docs: the Kali/Debian quick-start ran `exec $SHELL` between installing
  uv and installing BANSHEE, which replaced the shell and silently dropped the
  BANSHEE install step. Replaced with a non-destructive `PATH` export plus
  `uv tool update-shell`, and added a "command not found" troubleshooting note.

## [1.6.0] — 2026-08-28

Hardened error handling, a cleaner live dashboard, and a simpler install/update story.

### Added

- **Comprehensive input validation.** Every bad input now fails fast with a
  one-line message and the documented exit code — never a traceback:
  - malformed targets (`999.999.999.999`, `10.0.0.0/99`, `10.0.0.5-999`, `@@@`)
    are rejected; a bad target mixed with good ones is skipped with a warning;
  - out-of-range options are bounded (`--max-detect-risk 0..10`, `--rate >= 0`,
    `--threads >= 1`, `--timeout >= 1`, `--retries >= 0`);
  - a missing `--pcap` file is reported instead of silently scanning nothing;
  - a well-formed but unresolvable hostname reports "no host responded".
- **Error/edge-case test suite** (`tests/test_errors.py`) driving the real CLI
  across malformed targets, out-of-range options, bad files, and unwritable
  output.

### Changed

- **Cleaner live dashboard**: an animated scanning spinner, colour-coded host
  status (discovering / up / fingerprinting / done), a running host count, and a
  colourised stats bar. All glyphs are ASCII, so it renders on a legacy Windows
  console without a `UnicodeEncodeError`.

### Fixed

- **Three crashes that printed a Python traceback are now clean errors:** a
  malformed or unreadable scope file (exit 2), a report path that can't be
  written such as a directory (exit 1), and a `$BANSHEE_ENGINE` that points at a
  non-runnable file — wrong platform or not executable (exit 1).

## [1.5.0] — 2026-08-27

Deception/honeypot signals — `--deception`.

### Added

- **`--deception`** — flag hosts that show signals of being a decoy or honeypot,
  from data already collected (local, **zero packets**). Signals: an unusually
  large number of open services, a cluster of classic legacy bait ports
  (telnet/ftp/mysql/vnc/…), a Windows-vs-Unix service/banner contradiction, and
  known honeypot-framework tokens in a banner (Cowrie, Dionaea, …).

  Honesty first: a honeypot cannot be proven from the outside, so the result is
  always a single **POTENTIAL** finding per host, worded as a lead to verify and
  never a verdict, carrying the exact signals that triggered it. A single weak
  signal never fires on its own, so an ordinary server (web + SSH) is left alone —
  covered by a false-positive test on a real loopback host.

## [1.4.0] — 2026-08-27

Compare two scans — `banshee diff`.

### Added

- **`banshee diff OLD.json NEW.json`** — compare two BANSHEE JSON reports and
  show what changed between them: hosts that appeared or vanished, ports that
  opened or closed, and — pairing with `-sV` — services whose product/version
  changed, which is a real security signal (a patched or downgraded daemon shows
  up immediately). Add `--json OUT` to write the delta as JSON for CI. It is a
  pure comparison of the two inputs — no network, no inference — and an ambiguous
  `open|filtered` port is treated as neither open nor closed, so it never invents
  a spurious change.

  `diff` is a second verb on the same `banshee` command; the primary
  `banshee <targets>` scan form is unchanged.

## [1.3.0] — 2026-08-27

Service and version identification — `-sV` — and a packaging fix.

### Added

- **`-sV` / `--service-scan`** (Go engine): identify a service's product and
  version. Match-only, so it never fabricates an identity:
  - a **free** layer, always on, parses the server-first banner the TCP probe
    already captured (SSH, FTP, SMTP, …) and extracts product + version — no
    extra packet;
  - an **active** layer, only under `-sV`, sends one protocol probe (an HTTP
    `GET /`) to an *open but silent* HTTP port to draw out a `Server:` header.

  Product and version are set **only** when a captured banner matches a
  signature; a port that answers with nothing matchable is reported open with no
  invented version, exactly as a silent UDP port is `open|filtered` and never
  `open`. Verified live against `scanme.nmap.org`: `22/tcp` → OpenSSH 6.6.1p1,
  `80/tcp` → Apache 2.4.7, both from real banner bytes. `-sV` needs `--engine
  go`/`auto` and is TCP-only (not combined with `--udp`).
- **Ground-truth `-sV` tests** in both engines: a server-first banner is parsed
  to product+version; the active HTTP probe fires only on HTTP ports; and a
  silent open port never gets a fabricated identity.

### Fixed

- **`--no-fingerprint` silently disabled `-sV`.** It emits `-banners=false`,
  which turned off the banner reads `-sV` depends on. The engine now forces
  banners on whenever `-sV` is set, so the flag cannot be defeated by an
  unrelated toggle.

## [1.2.0] — 2026-08-25

UDP scanning — done honestly.

### Added

- **`--udp`** (Go engine): a UDP scan of the candidate ports (a UDP default set
  when `-p` is omitted). UDP is connectionless, so the engine reports exactly what
  it can prove and nothing more:
  - a reply from the port → **open** (CONFIRMED; the host is provably up),
  - an ICMP port-unreachable (delivered as a refused/reset on a connected UDP
    socket) → **closed** (CONFIRMED; the host is up),
  - silence → **open\|filtered** (POTENTIAL) — a silent port may be open (the
    service ignored the probe) or filtered, and is **never** collapsed to a plain
    "open". A silent port is excluded from `open_ports`, and silence alone never
    invents a host.

  Protocol-correct probe payloads (DNS, NTP, SNMP, SSDP, mDNS) make an open
  service answer, so silence is meaningful. `--udp` is UDP-only (like `nmap -sU`)
  and mutually exclusive with `--adaptive` (the planner is TCP).
- **Ground-truth UDP tests** in both engines: bind real UDP responders, silent
  sockets, and closed ports on loopback and assert the three-state classification —
  including that a silent port is reported open\|filtered and never open.

### Changed

- `PortState` gains `open|filtered`; JSON/XML/text reports carry it verbatim.

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

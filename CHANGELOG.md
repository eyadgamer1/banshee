# Changelog

All notable changes to BANSHEE are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.0.0] — 2025-06-07

### Added
- **Passive sniffer** — zero-packet discovery via traffic observation
- **TCP async sweep** — connect-scan with configurable timing templates (T0–T5)
- **ICMP ping** — raw ICMP echo with custom checksum
- **PCAP replay** — discover assets from saved `.pcap` files
- **OUI lookup** — vendor identification from MAC address
- **DHCP parser** — hostname + MAC from dnsmasq / ISC lease files
- **TCP/IP stack fingerprinting** — OS guess from TTL, window size, and flags
- **TLS/JA4 fingerprinting** — passive TLS client fingerprinting
- **Clock skew fingerprinting** — NTP-free device identification via clock drift
- **Name resolver** — DNS, mDNS, NetBIOS, Zeroconf
- **Device classifier** — router / IoT / server / workstation labels
- **Attack graph** (C1) — pivot-path analysis across discovered hosts
- **Segment map** (C2) — subnet grouping + bridge-host detection
- **SSVC prioritizer** — local vulnerability triage, no cloud required
- **EPSS / KEV enrichment** — opt-in CVE enrichment via FIRST.org + CISA
- **YAML plugin rules** — custom detection rules without code changes
- **ReAct LLM analysis** — agentic analysis loop via local Ollama
- **6 report formats** — TXT, JSON, XML, HTML, CSV, SARIF 2.1.0
- **Live dashboard** — real-time rich terminal UI during scan
- **JSONL audit trail** — tamper-evident log of every action
- **SQLite store** — persistent host/service/finding history across runs
- **Rogue detector** — alerts on hosts not in MAC baseline
- **Scope guard** — hard allowlist enforcement; `ScopeViolationError` on violation
- **Docker support** — single `docker compose run banshee` to start
- **One-liner installer** — `curl … | bash`
- **239 tests** — unit + integration coverage across all modules

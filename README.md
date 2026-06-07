<div align="center">

```
  ██████╗  █████╗ ███╗   ██╗███████╗██╗  ██╗███████╗███████╗
  ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║  ██║██╔════╝██╔════╝
  ██████╔╝███████║██╔██╗ ██║███████╗███████║█████╗  █████╗
  ██╔══██╗██╔══██║██║╚██╗██║╚════██║██╔══██║██╔══╝  ██╔══╝
  ██████╔╝██║  ██║██║ ╚████║███████║██║  ██║███████╗███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝
```

**Broad-Area Network Scanner for Host Enumeration and Exposure**

*She sees everything you left exposed.*

[![Python](https://img.shields.io/badge/python-3.12%2B-red?style=flat-square&logo=python)](https://python.org)
[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-red?style=flat-square)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/linter-ruff-red?style=flat-square)](https://github.com/astral-sh/ruff)
[![Type checked: mypy](https://img.shields.io/badge/types-mypy%20strict-red?style=flat-square)](https://mypy-lang.org)

</div>

---

## What is BANSHEE?

BANSHEE is a **passive-first** network asset scanner written in Python 3.12. It discovers, fingerprints, and correlates hosts on your network — silently — and produces actionable risk reports without sending a single exploit.

**No exploitation. No weaponized payloads. No scanning outside your defined scope. Ever.**

It is designed for:
- Internal network asset inventory and baseline
- Detection of rogue/unknown devices
- Pre-pentest reconnaissance (authorized engagements only)
- Continuous exposure monitoring in defensive security operations

---

## Features

| Module | What it does |
|---|---|
| **Passive Sniffer** | Watches traffic without sending packets |
| **TCP Sweep** | Async connect-scan with stealth timing templates |
| **ICMP Ping** | Raw ICMP echo with custom checksum |
| **PCAP Replay** | Discover assets from saved `.pcap` files |
| **OUI Lookup** | Vendor from MAC address |
| **DHCP Parser** | Hostname + MAC from dnsmasq / ISC lease files |
| **TCP/IP Stack FP** | OS guess from TTL + window + flags |
| **TLS/JA4** | Passive TLS fingerprinting (JA4 hash) |
| **Clock Skew** | NTP-free device clock drift fingerprinting |
| **Name Resolver** | DNS, mDNS, NetBIOS, Zeroconf |
| **Device Classifier** | Router / IoT / server / workstation labels |
| **Attack Graph** | Pivot-path analysis across discovered hosts |
| **Segment Map** | Subnet grouping + bridge-host detection |
| **SSVC Prioritizer** | Local vulnerability triage (no cloud) |
| **EPSS / KEV** | Optional CVE enrichment (opt-in, data leaves host) |
| **Plugin Rules** | YAML-driven custom detection rules |
| **LLM Analysis** | ReAct reasoning via local Ollama (offline) |
| **6 Report Formats** | TXT · JSON · XML · HTML · CSV · SARIF 2.1.0 |
| **Live Dashboard** | Real-time rich terminal UI during scan |
| **Audit Trail** | Tamper-evident JSONL log of every action |
| **SQLite Store** | Persistent host/service/finding history |
| **Rogue Detector** | Alerts on hosts not in MAC baseline |
| **Scope Guard** | Hard allowlist enforcement — ScopeViolationError on violation |

---

## Installation

### Option 1 — pip (recommended)

```bash
# Requires Python 3.12+
pip install git+https://github.com/eyadgamer1/banshee.git

# or with uv (faster):
uv tool install git+https://github.com/eyadgamer1/banshee.git
```

One-liner installer:

```bash
curl -sSL https://raw.githubusercontent.com/eyadgamer1/banshee/main/install.sh | bash
```

### Option 2 — Docker

```bash
# Clone + build
git clone https://github.com/eyadgamer1/banshee.git
cd banshee
docker build -t banshee-scanner .

# Run (needs NET_RAW for passive sniff)
docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
    --network host \
    -v $(pwd)/config:/app/config:ro \
    -v $(pwd)/output:/app/output \
    banshee-scanner 192.168.1.0/24 --mode normal -T3 --json output/scan.json
```

Or with compose:

```bash
docker compose run banshee 192.168.1.0/24 --mode normal -T3
```

### From source (dev)

```bash
git clone https://github.com/eyadgamer1/banshee.git
cd banshee
uv sync
uv run banshee --help
```

---

## Quick Start

```bash
# See what's in scope (dry run, sends zero packets)
banshee 192.168.1.0/24 --dry-run

# Passive listen only — zero packets sent
banshee 192.168.1.0/24 --mode passive

# Normal scan, timing T3, all formats
banshee 192.168.1.0/24 --mode normal -T3 --all output/scan

# Stealth scan (slow, low-noise) from pcap
banshee --pcap capture.pcap

# Full pipeline: fingerprint + plugins + SSVC + HTML report
banshee 10.0.0.0/24 --mode normal -T2 --fingerprint --plugins --ssvc --html report.html

# Agentic analysis via local Ollama
banshee 192.168.1.0/24 --mode normal --agentic
```

---

## Usage

```
banshee [TARGETS]... [OPTIONS]
```

### Targets & Input

| Flag | Description |
|---|---|
| `TARGETS` | IP, CIDR, range, or hostname — e.g. `192.168.1.0/24 10.0.0.5-20 host.lan` |
| `--iface`, `-i` | Network interface for live capture |
| `--pcap FILE` | Read from a saved `.pcap` file instead of live traffic |

### Intensity

| Flag | Description |
|---|---|
| `--mode`, `-m` | Scan mode: `passive` / `stealth` / `normal` / `aggressive` |
| `--timing`, `-T` | Timing template `0`–`5` (0=paranoid, 5=insane, default 3) |
| `--rate N` | Max packets per second |
| `--timeout MS` | Probe timeout in milliseconds (default: from `-T`) |
| `--retries N` | Probe retries (default: from `-T`) |
| `--threads N` | Max concurrency |
| `--max-detect-risk N` | Detection risk ceiling `0`–`9` (0=passive only) |

### Verbosity

| Flag | Description |
|---|---|
| `-v` / `-vv` | Verbose / very verbose output |
| `-q`, `--quiet` | Results only, no progress |
| `--silent` | No terminal output — file output only |
| `--debug` | Full debug tracing |
| `--no-color` | Disable ANSI colors |

### Output Files

| Flag | Description |
|---|---|
| `--txt FILE` | Write plain-text report |
| `--json FILE` | Write JSON report |
| `--xml FILE` | Write XML report |
| `--html FILE` | Write HTML report |
| `--csv FILE` | Write CSV report |
| `--sarif FILE` | Write SARIF 2.1.0 report |
| `--all`, `-A BASE` | Write all formats to `BASE.txt`, `BASE.json`, etc. |

### Toggles

| Flag | Description |
|---|---|
| `--fingerprint` / `--no-fingerprint` | Enable/disable identity probes (default: on) |
| `--names` / `--no-names` | Enable/disable name resolution (default: on) |
| `--classify` | Device classification (router / IoT / server / etc.) |
| `--plugins` | Apply YAML detection rules from `config/plugins/` |
| `--ssvc` | SSVC priority scoring (fully local, safe) |
| `--enrich` | **[DATA LEAVES HOST]** CVE enrichment via FIRST.org + CISA KEV |
| `--agentic` | ReAct LLM analysis loop via local Ollama |

### Safety

| Flag | Description |
|---|---|
| `--scope FILE` | Scope allowlist (default: `config/scope.yaml`) |
| `--dry-run` | Plan only — sends zero packets, shows what would be scanned |
| `--audit-log FILE` | Append tamper-evident JSONL audit trail |

### Maintenance

| Flag | Description |
|---|---|
| `--version` | Show version and exit |
| `--help` | Show help and exit |

---

## Timing Templates

| `-T` | Name | Delay | Timeout | Retries | Use case |
|---|---|---|---|---|---|
| `-T0` | Paranoid | 300 s | 8 000 ms | 3 | IDS evasion, ultra-slow |
| `-T1` | Sneaky | 15 s | 6 000 ms | 2 | Quiet internal sweep |
| `-T2` | Polite | 400 ms | 5 000 ms | 2 | Low-noise production |
| `-T3` | Normal | 100 ms | 3 000 ms | 1 | Default balanced |
| `-T4` | Aggressive | 10 ms | 1 500 ms | 1 | Fast lab scan |
| `-T5` | Insane | 0 ms | 750 ms | 0 | CTF / trusted network |

---

## Scope Configuration

BANSHEE **will never scan outside your allowlist.** Edit `config/scope.yaml`:

```yaml
# config/scope.yaml
allow:
  - 10.0.0.0/8        # RFC1918
  - 172.16.0.0/12
  - 192.168.0.0/16
  - 127.0.0.0/8       # loopback

deny: []              # explicit deny overrides allow

max_hosts_per_scan: 65535
```

Scanning a target not in `allow` raises `ScopeViolationError` and exits with code **3**.

---

## Plugin Rules

Drop `.yaml` files in `config/plugins/` and run with `--plugins`. See `config/plugins/example.yaml` for the rule format.

```bash
banshee 192.168.1.0/24 --mode normal --plugins --sarif output/findings.sarif
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `2` | Usage error (bad flags, missing scope file) |
| `3` | Scope violation — all targets outside allowlist |

---

## Security Constraints

These are hard-coded invariants, not configuration options:

1. **Never scans outside `config/scope.yaml`** — `ScopeViolationError` is raised, not a warning
2. **Never sends target data to external APIs by default** — `--enrich` is opt-in with an explicit loud warning
3. **Never generates exploit code or weaponized payloads** — the engine only emits findings
4. **Never logs credentials, keys, or PII** — audit trail records IPs and events only

---

## Requirements

- Python 3.12+
- Linux/macOS for passive sniffing (raw socket privileges required)
- Windows: TCP sweep and PCAP replay work; live passive sniff requires WinPcap/Npcap
- Local Ollama (optional, for `--agentic`)

---

## License

[GNU General Public License v3.0](LICENSE) — free to use, modify, and distribute with the same terms.

---

<div align="center">
<sub>Built for authorized security testing only. Always scan with permission.</sub>
</div>

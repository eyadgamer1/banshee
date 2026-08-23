<div align="center">

<img src="assets/banner.png" alt="BANSHEE" width="600"/>

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

[![CI](https://img.shields.io/github/actions/workflow/status/eyadgamer1/banshee/ci.yml?branch=main&style=flat-square&label=tests)](https://github.com/eyadgamer1/banshee/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.12%2B-red?style=flat-square&logo=python)](https://python.org)
[![Go engine](https://img.shields.io/badge/engine-Go%201.26-red?style=flat-square&logo=go)](engine/)
[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-red?style=flat-square)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/linter-ruff-red?style=flat-square)](https://github.com/astral-sh/ruff)
[![Type checked: mypy](https://img.shields.io/badge/types-mypy%20strict-red?style=flat-square)](https://mypy-lang.org)

</div>

---

## Table of contents

- [What is BANSHEE?](#what-is-banshee)
- [Why it's different](#why-its-different)
- [Install](#install) — [Kali](#kali--parrot--debian--ubuntu) · [Windows](#windows) · [macOS](#macos) · [Docker](#docker) · [From source](#from-source--go-engine)
- [Quick start](#quick-start)
- [The live interface](#the-live-interface)
- [Command reference](#command-reference) — every flag
- [Examples cookbook](#examples-cookbook)
- [The Go engine](#the-go-engine)
- [Scope & authorization](#scope--authorization)
- [Prove the results are real](#prove-the-results-are-real)
- [Output formats](#output-formats)
- [Troubleshooting](#troubleshooting)
- [Ethics & license](#ethics--license)

---

## What is BANSHEE?

BANSHEE is a **passive-first network scanner**. Point it at a network you are authorized to assess and it maps every host, fingerprints services, classifies devices, spots rogue hardware, and produces a risk report — in its default mode without sending a single packet.

It is built for ethical hackers and defenders who care about two things most scanners ignore:

1. **Trust** — every result is tied to how it was observed. A port is only reported open if a socket actually opened. Findings are graded `CONFIRMED`, `PROBABLE`, or `POTENTIAL` so you always know what is fact and what is inference. See [Prove the results are real](#prove-the-results-are-real).
2. **Stealth** — the tool tells you how loud a scan is and lets you cap it. The default is silent observation; you opt into noise deliberately.

---

## Why it's different

| Capability | Most scanners | BANSHEE |
|---|---|---|
| **Default posture** | Send probes immediately | Passive — zero packets until you ask |
| **Result honesty** | "Open" with no provenance | `CONFIRMED / PROBABLE / POTENTIAL` tiers, never fabricated |
| **Detection cost** | Not measured | Per-port risk weighting; cap it with a budget |
| **Adaptive probing** | Static top-ports list | Bayesian per-host probe selection (Go engine) |
| **Fingerprinting** | Banner grab | Passive TCP/IP stack, TLS/JA4, DHCP, clock-skew, OUI |
| **Deployment** | `pip install` + runtime | Also a single static Go binary you `scp` onto a jump box |
| **Reporting** | One or two formats | TXT · JSON · XML · HTML · CSV · SARIF 2.1.0 + SQLite history |

---

## Install

> **Requirements:** Python **3.12+**. The active TCP-connect sweep needs **no privileges**. Passive sniffing and ICMP discovery use raw sockets, which need **`sudo`** on Linux/macOS or **[Npcap](https://npcap.com)** on Windows.

The fastest path on every OS is [`uv`](https://github.com/astral-sh/uv). `pipx` (isolated) and `pip` also work.

### Kali / Parrot / Debian / Ubuntu

```bash
# 1. Install uv (one line, no root needed)
curl -LsSf https://astral.sh/uv/install.sh | sh
exec $SHELL                       # reload PATH

# 2. Install BANSHEE as a global tool
uv tool install git+https://github.com/eyadgamer1/banshee

# 3. Verify
banshee --version
banshee --help
```

<details>
<summary>Prefer <code>pipx</code>, or one-line installer?</summary>

```bash
# pipx (isolated venv)
sudo apt update && sudo apt install -y pipx
pipx install git+https://github.com/eyadgamer1/banshee

# or the one-line installer (auto-detects uv / pipx / pip)
curl -sSL https://raw.githubusercontent.com/eyadgamer1/banshee/main/install.sh | bash
```
</details>

Passive capture on an interface needs raw sockets, so prefix those runs with `sudo`:

```bash
sudo $(command -v banshee) -i eth0            # passive sniff on eth0
```

### Windows

```powershell
# 1. Install uv
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# 2. Install BANSHEE
uv tool install git+https://github.com/eyadgamer1/banshee

# 3. Run
banshee --help
banshee 192.168.1.0/24 --mode normal
```

The active TCP-connect sweep works out of the box. **Passive sniffing on Windows requires [Npcap](https://npcap.com)** (install with "WinPcap API-compatible mode"). The banner renders on any console — it falls back to plain ASCII on legacy code pages automatically.

### macOS

```bash
brew install uv                    # or: brew install pipx
uv tool install git+https://github.com/eyadgamer1/banshee
banshee --help

# raw-socket features (passive sniff / ICMP) need sudo:
sudo $(command -v banshee) -i en0
```

### Docker

Raw packet capture inside a container needs `NET_RAW`/`NET_ADMIN` and host networking. The provided `docker-compose.yml` sets both.

```bash
git clone https://github.com/eyadgamer1/banshee && cd banshee

# mount your own scope.yaml + collect output locally
docker compose run --rm banshee 192.168.1.0/24 --mode normal -T3 --html /app/output/report.html
```

### From source + Go engine

```bash
git clone https://github.com/eyadgamer1/banshee && cd banshee

# Python tool
uv sync
uv run banshee --help

# Go engine (single static binary — optional, for fast active sweeps)
cd engine
go build -o banshee-engine ./cmd/banshee-engine
./banshee-engine -h
```

---

## Quick start

```bash
# Passive discovery of your LAN — sends nothing, just listens and infers
banshee 192.168.1.0/24

# Active sweep of one host — confirm open ports and grab banners
banshee 192.168.1.10 --mode normal

# Full local analysis, HTML report, no data leaves your machine
banshee 192.168.1.0/24 --mode normal --classify --ssvc --html report.html
```

By default BANSHEE only scans **loopback and RFC1918 (private) ranges**. Public addresses are refused until you add them to your scope file — see [Scope & authorization](#scope--authorization).

---

## The live interface

BANSHEE renders a live dashboard while it works, then prints a clean summary. Below is a **real run** against loopback (`127.0.0.1`) — the banner art is trimmed for width; the stats line and host table are verbatim:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│   ██████╗  █████╗ ███╗   ██╗███████╗██╗  ██╗███████╗███████╗                │
│   ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║  ██║██╔════╝██╔════╝                │
│   ██████╔╝███████║██╔██╗ ██║███████╗███████║█████╗  █████╗                  │
│   ██████╔╝██║  ██║██║ ╚████║███████║██║  ██║███████╗███████╗                │
│   She sees everything you left exposed.                                     │
│   Broad-Area Network Scanner …                                  |  v1.0.1   │
└─────────────────────────────────────────────────────────────────────────────┘

[!] AUTHORIZED TARGETS ONLY - loopback + RFC1918 default scope
mode=normal -T4 fingerprint=True

hosts up 1  services 2  findings 0  in-scope 1  out-of-scope 0  packets 7

 IP          Name                         MAC   Vendor   OS        Ports      Conf.
 ──────────────────────────────────────────────────────────────────────────────────
 127.0.0.1   kubernetes.docker.internal               Windows   135, 445   confirmed
```

The `Conf.` column is the trust grade. `packets 7` is the exact number of probes sent — passive runs show `packets 0`. During a longer scan the dashboard shows a per-host table updating live (discovering → fingerprinting → done) with a running stats bar.

Colour and detail are controlled independently from scan intensity — see the two dials below.

---

## Command reference

```
banshee [OPTIONS] TARGETS...
```

`TARGETS` are IPs, CIDRs, ranges, or hostnames: `192.168.1.0/24`, `10.0.0.5-20`, `host.lan`.

BANSHEE has **two independent dials.** *Verbosity* controls how much it prints; *intensity* controls how loud it is on the wire. They never affect each other.

### Targets & input

| Flag | Description |
|---|---|
| `-i, --iface TEXT` | Capture interface for passive sniffing |
| `--pcap TEXT` | Read from a saved capture file instead of live traffic |
| `-p, --ports TEXT` | Ports to probe: `22,80,443` or `1-1024` (default: common high-signal set) |
| `--sniff-timeout FLOAT` | Seconds the passive sniffer listens before reporting (default `10.0`) |

### Verbosity — *how much it prints*

| Flag | Description |
|---|---|
| `-v, -vv, -vvv` | Increase detail |
| `-q, --quiet` | Results only |
| `--silent` | No terminal output (files only) |
| `--debug` | Debug tracing |
| `--no-color` | Disable ANSI colour |

### Intensity — *how loud it is*

| Flag | Description |
|---|---|
| `-m, --mode [passive\|stealth\|normal\|aggressive]` | Scan intensity (default **`passive`**) |
| `-T, --timing 0..5` | Timing template, T0 (paranoid) … T5 (insane), default `3` |
| `--rate INTEGER` | Max packets/sec |
| `--timeout INTEGER` | Probe timeout ms (default from `-T`) |
| `--retries INTEGER` | Probe retries (default from `-T`) |
| `--threads INTEGER` | Max concurrency |
| `--max-detect-risk 0..9` | Hard ceiling on noise. `0` forces passive; `9` is full-intensity |

### Toggles

| Flag | Description |
|---|---|
| `--fingerprint / --no-fingerprint` | Identity probes (default on) |
| `--names / --no-names` | DNS / mDNS / NetBIOS name resolution (default on) |
| `--classify / --no-classify` | Device classification — local, **zero packets** (default on) |
| `--ssvc` | SSVC priority tags on findings (local) |
| `--plugins` | Apply YAML detection rules from `config/plugins/` |
| `--enrich` | EPSS + CISA KEV enrichment — **data leaves your host** |
| `--agentic` | ReAct LLM analysis via a local Ollama model |

### Output files

| Flag | Description |
|---|---|
| `--txt / --json / --xml / --html / --csv / --sarif PATH` | Write that report format |
| `-A, --all BASE` | Write every format to `BASE.*` |
| `--db PATH` | Persist this run to SQLite and compare MACs to the baseline |
| `--baseline` | Seed the MAC baseline from this run without raising rogue findings |

### Safety & maintenance

| Flag | Description |
|---|---|
| `--scope TEXT` | Scope allowlist file (default `config/scope.yaml`; a built-in default is used if absent) |
| `--dry-run` | Plan only; send zero packets |
| `--version` | Show version |

---

## Examples cookbook

**Passive — sends nothing:**

```bash
banshee 192.168.1.0/24                        # infer hosts from observed traffic
sudo banshee -i eth0 --sniff-timeout 30       # sniff eth0 for 30s (raw socket → sudo)
banshee --pcap capture.pcap 10.0.0.0/24       # replay a saved capture, no live traffic
```

**Active — you choose the intensity:**

```bash
banshee 192.168.1.10 --mode normal                     # confirm open ports + banners
banshee 10.0.0.5 -p 22,80,443,3389 -m normal -T4       # specific ports, fast
banshee 10.0.0.0/24 -m stealth -T1                      # slow and quiet
banshee 10.0.0.0/24 -m aggressive -T4 --max-detect-risk 9   # loud, full intensity
banshee 10.0.0.0/24 -m normal --max-detect-risk 3      # active, but capped to quiet ports
```

**Analysis & reporting (all local):**

```bash
banshee 10.0.0.0/24 -m normal --classify --ssvc --plugins     # full local triage
banshee 10.0.0.0/24 -m normal -A audit                        # write audit.txt/.json/.html/…
banshee 10.0.0.5 -m normal --json out.json --sarif out.sarif  # feed CI / DefectDojo
```

**Track a network over time (rogue-device detection):**

```bash
banshee 10.0.0.0/24 -m normal --db assets.db --baseline   # 1st run: learn the baseline
banshee 10.0.0.0/24 -m normal --db assets.db              # later runs: flag new/rogue MACs
```

**AI-assisted (needs a local [Ollama](https://ollama.com) model):**

```bash
banshee 10.0.0.0/24 -m normal --agentic                   # ReAct LLM risk analysis, on-device
```

---

## The Go engine

For fast, low-footprint active sweeps — and for hosts where you cannot install Python — BANSHEE ships a standalone Go engine: a single static binary, no runtime, cross-compiles for ARM drop-boxes. It emits the **exact same JSON schema** as the Python tool, so both are interchangeable in a pipeline.

```bash
cd engine && go build -o banshee-engine ./cmd/banshee-engine

# High-signal default sweep
./banshee-engine -scope ../config/scope.yaml 10.0.0.0/28

# Adaptive: stop probing each host once its device class is 85% certain
./banshee-engine -scope ../config/scope.yaml -adaptive -confidence 0.85 -pretty 10.0.0.0/28

# Cap detection risk per host — the planner spends it on the most informative probes first
./banshee-engine -scope ../config/scope.yaml -adaptive -host-risk-budget 8 10.0.0.0/28
```

**What makes it novel:** the adaptive planner carries a Bayesian posterior over device classes for each host and picks the next probe by *expected information gain per unit of detection risk* — unlike a fixed top-ports list, it learns from each answer and avoids loud ports (445, 3389, ICS protocols) unless they are worth it. Measured against a real workstation: **3 probes instead of 26, detection risk 5 instead of 104**, same verdict. On a loopback sweep of ports 1–1024 it runs in **~4 s / 9 MB RAM** versus ~15 s / 28 MB for the Python path. Full design notes: [`engine/README.md`](engine/README.md).

Cross-compile for a drop-box:

```bash
GOOS=linux GOARCH=arm64 go build -o banshee-engine-arm64 ./cmd/banshee-engine
```

---

## Scope & authorization

**BANSHEE refuses to touch anything outside its scope. There is no override flag.** This is the single most important safety property, and it is enforced, not advised.

The default scope (`config/scope.yaml`, or a built-in copy when that file is absent) allows only loopback and private ranges:

```yaml
banner: "AUTHORIZED TARGETS ONLY"
allowlist:
  - 127.0.0.1/8
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
denylist: []
max_hosts_per_scan: 1024
max_ports_per_host: 1000
```

To assess a target you own, add it to `allowlist` and point BANSHEE at your file:

```bash
banshee 203.0.113.0/24 --scope my-engagement.yaml
```

Anything not on the list is refused with a non-zero exit code. A single target larger than `max_hosts_per_scan` is refused outright rather than silently truncated. **Only scan networks you own or are explicitly authorized to test.**

---

## Prove the results are real

The most dangerous thing a security scanner can do is lie — report a port that is not open, or a finding that is not there. BANSHEE is built so that cannot happen quietly, and it ships the proof.

**The guarantee:** a service is reported open **only** as the direct record of a socket that actually opened. Open ports are graded `CONFIRMED`; an inference is at most `PROBABLE`; anything an LLM suggests is capped at `POTENTIAL` and can never be promoted.

**Run the proof yourself.** The ground-truth suite binds real listeners on loopback, runs the real CLI, and asserts the reported open ports equal the bound ports *exactly* — including the negative direction, that an unbound port is never reported open, and that passive mode sends zero packets:

```bash
uv run pytest tests/test_ground_truth.py -v
```

```
10 passed
```

The full suite (255 tests) plus the Go engine's own ground-truth tests (`cd engine && go test ./...`) run on every push via CI on Linux and Windows.

---

## Output formats

| Format | Flag | Use |
|---|---|---|
| Text | `--txt` | Human-readable summary |
| JSON | `--json` | Automation, the canonical schema |
| XML | `--xml` | Legacy tooling |
| HTML | `--html` | Shareable report |
| CSV | `--csv` | Spreadsheets |
| SARIF 2.1.0 | `--sarif` | GitHub code scanning, DefectDojo |
| SQLite | `--db` | Cross-run history + rogue detection |

All six file formats can be written at once with `-A BASE`. A JSONL audit trail of the run is written alongside.

---

## Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `scope file not found` | You passed `--scope` with a path that doesn't exist. Without `--scope`, a built-in default is used automatically. |
| Everything reports out-of-scope | Your target isn't in `allowlist`. Add it to your scope file (see [Scope](#scope--authorization)). |
| Passive sniff finds nothing on Windows | Install [Npcap](https://npcap.com) in WinPcap-compatible mode. Passive capture needs a packet driver. |
| `Operation not permitted` on `-i` / passive | Raw sockets need privileges — run with `sudo` (Linux/macOS) or as Administrator (Windows). The active TCP sweep does not. |
| Garbled banner on an old terminal | Harmless — BANSHEE auto-falls back to an ASCII banner when the console can't render block glyphs. |
| `--agentic` does nothing | It needs a local [Ollama](https://ollama.com) server with a pulled model. |

---

## Ethics & license

BANSHEE performs **no exploitation** and enforces a hard scope boundary. Use it only against networks you own or are explicitly authorized to assess. You are responsible for your use of this tool.

Licensed under **GPL-3.0** — see [LICENSE](LICENSE). Contributions welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) and report issues at the [tracker](https://github.com/eyadgamer1/banshee/issues).

<div align="center">
<sub>BANSHEE — she sees everything you left exposed.</sub>
</div>

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
- [Compare two scans — `banshee diff`](#compare-two-scans--banshee-diff)
- [Spot a decoy — `--deception`](#spot-a-decoy--deception)
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

**TL;DR — one line, any OS** (needs [`uv`](https://github.com/astral-sh/uv); [install uv](https://github.com/astral-sh/uv#installation) first if you don't have it):

```bash
uv tool install git+https://github.com/eyadgamer1/banshee
banshee --help
```

That's the whole install — a single self-contained `banshee` command with a
built-in default scope. No clone, no config, no Go toolchain (the fast Go engine
is optional; see [below](#from-source--go-engine)). Per-OS details and `pipx`/`pip`
alternatives follow.

> **Requirements:** Python **3.12+**. The active TCP-connect sweep needs **no privileges**. Passive sniffing and ICMP discovery use raw sockets, which need **`sudo`** on Linux/macOS or **[Npcap](https://npcap.com)** on Windows.

The fastest path on every OS is [`uv`](https://github.com/astral-sh/uv). `pipx` (isolated) and `pip` also work.

### Kali / Parrot / Debian / Ubuntu

```bash
# 1. Install uv (one line, no root needed)
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"   # put uv on PATH now — do NOT run `exec $SHELL` here; it replaces the shell and aborts the rest of this block

# 2. Install BANSHEE as a global tool
uv tool install git+https://github.com/eyadgamer1/banshee
uv tool update-shell                    # keep `banshee` on PATH in future terminals

# 3. Verify
banshee --version
banshee --help
```

> **`banshee: command not found` right after install?** The `banshee` binary is in `~/.local/bin`, which isn't on your `PATH` yet in this shell. Run `uv tool update-shell` then open a new terminal — or, just for the current shell, `export PATH="$HOME/.local/bin:$PATH"`.

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

# Go engine (single static binary — optional, for fast active sweeps + UDP)
cd engine
go build -o banshee-engine ./cmd/banshee-engine
./banshee-engine -h
```

**Prebuilt Go engine — no toolchain needed.** Every tagged release ships static
`banshee-engine` binaries for Linux (amd64/arm64), Windows, and macOS
(Intel/Apple Silicon) on the [Releases](https://github.com/eyadgamer1/banshee/releases)
page. Download the one for your platform, mark it executable, and either put it on
your `PATH` or point `BANSHEE_ENGINE` at it — then `--engine go` and `--engine auto`
just work:

```bash
chmod +x banshee-engine-linux-amd64
export BANSHEE_ENGINE="$PWD/banshee-engine-linux-amd64"
banshee 192.168.1.0/24 --engine go --mode normal
```

### Updating to the latest version

Run the command that matches how you installed it:

```bash
uv tool upgrade banshee                                   # if installed with uv (recommended)
pipx upgrade banshee                                      # if installed with pipx
pip install --upgrade git+https://github.com/eyadgamer1/banshee   # if installed with pip
```

`uv tool upgrade banshee` re-pulls the latest `main`. If a release ever pins an
old version, force a clean reinstall:

```bash
uv tool install --reinstall git+https://github.com/eyadgamer1/banshee
```

Check what you're on with `banshee --version`. Updating the Go engine binary is
separate: re-download it from [Releases](https://github.com/eyadgamer1/banshee/releases)
or rebuild with `git pull && cd engine && go build -o banshee-engine ./cmd/banshee-engine`.

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

BANSHEE renders a live dashboard while it works, then prints a clean summary. Below is a **real run** against loopback (`127.0.0.1`), verbatim:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│   ██████╗  █████╗ ███╗   ██╗███████╗██╗  ██╗███████╗███████╗                │
│   ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║  ██║██╔════╝██╔════╝                │
│   ██████╔╝███████║██╔██╗ ██║███████╗███████║█████╗  █████╗                  │
│   ██╔══██╗██╔══██║██║╚██╗██║╚════██║██╔══██║██╔══╝  ██╔══╝                  │
│   ██████╔╝██║  ██║██║ ╚████║███████║██║  ██║███████╗███████╗                │
│   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝                │
│   She sees everything you left exposed.                                     │
│   Broad-Area Network Scanner for Host Enumeration and Exposure  |  v1.2.0   │
└─────────────────────────────────────────────────────────────────────────────┘

[!] AUTHORIZED TARGETS ONLY - loopback + RFC1918 default scope
mode=normal -T4 engine=python fingerprint=True

hosts up 1  services 2  findings 0  in-scope 1  out-of-scope 0  packets 6

 IP          Name                         MAC   Vendor   OS        Ports      Conf.
 ──────────────────────────────────────────────────────────────────────────────────
 127.0.0.1   kubernetes.docker.internal               Windows   135, 445   confirmed
```

The `Conf.` column is the trust grade. `mode=normal -T4 engine=python` echoes the two intensity dials and the active-scan engine in force. `packets 6` is the exact number of probes sent — passive runs show `packets 0`. During a longer scan the dashboard shows a per-host table updating live (discovering → fingerprinting → done) with a running stats bar.

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
| `--max-detect-risk 0..10` | Hard ceiling on noise. `0` forces passive; `10` is full-intensity. Out-of-range values are rejected |

### Engine — *who does the active probing*

| Flag | Description |
|---|---|
| `--engine [python\|go\|auto]` | Active-scan core (default **`python`**). `go` delegates discovery/probing to the fast, low-memory static binary; `auto` uses `go` when the binary is present, else `python`. Passive capture, analysis and reporting stay Python either way |
| `--adaptive` | Go only: pick probes by information-gain per unit of detection risk and stop early once a device class is confident. The report and JSON then include a `plan` block — probes saved, detection risk spent, and per-host device classification (requires `--engine go`/`auto`) |
| `--udp` | Go only: UDP scan (like `nmap -sU`). A replying port is **open**, an ICMP-unreachable is **closed**, and a **silent** port is honestly **`open\|filtered`** — never a fake "open" (requires `--engine go`/`auto`; mutually exclusive with `--adaptive`) |
| `-sV, --service-scan` | Go only: identify a service's **product + version** from its banner. Match-only — a version is reported **only** when a captured banner matches a signature, never guessed from the port (requires `--engine go`/`auto`; TCP-only) |

> `--engine go` needs the binary built (`cd engine && go build -o banshee-engine ./cmd/banshee-engine`) and found via `$BANSHEE_ENGINE`, your `PATH`, or the repo's `engine/` directory. See [The Go engine](#the-go-engine).

### Toggles

| Flag | Description |
|---|---|
| `--fingerprint / --no-fingerprint` | Identity probes (default on) |
| `--names / --no-names` | DNS / mDNS / NetBIOS name resolution (default on) |
| `--classify / --no-classify` | Device classification — local, **zero packets** (default on) |
| `--ssvc` | SSVC priority tags on findings (local) |
| `--plugins` | Apply YAML detection rules from `config/plugins/` |
| `--deception` | Flag possible honeypot/decoy hosts from collected data — local, **zero packets**. Always a `POTENTIAL` lead, never a verdict |
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

**Go is the hands, Python is the mind.** You do not have to choose between them: run the normal `banshee` command with `--engine go` and the Go binary does the fast, parallel active probing while Python keeps the passive capture, classification, LLM analysis and all six report formats. It's one tool.

```bash
# Unified: Python drives, Go does the loud active work, one report at the end
banshee 10.0.0.0/28 -m normal --engine go --adaptive --html report.html
```

Or drive the binary directly for a dependency-free sweep on a jump box:

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

### UDP — honest by design

UDP is connectionless, so most scanners either lie (call everything "open") or
guess. BANSHEE reports **only what it can prove**:

| Observation | Reported state | Confidence |
|---|---|---|
| The port sends a reply | `open` | **CONFIRMED** — the host is provably up |
| ICMP port-unreachable (refused/reset) | `closed` | **CONFIRMED** — the host is up |
| Silence | `open\|filtered` | **POTENTIAL** — open *or* filtered; we can't tell |

A silent port is **never** collapsed to a plain "open", is excluded from
`open_ports`, and silence alone never invents a host. Protocol-correct payloads
(DNS, NTP, SNMP, SSDP, mDNS) make an open service answer, so silence is meaningful.

```bash
# UDP scan of the common UDP services on a host (unified CLI drives the Go engine)
banshee 192.168.1.10 --engine go --udp

# UDP scan of specific ports, JSON out
banshee 192.168.1.10 --engine go --udp -p 53,123,161,500,1900 --json udp.json

# or the standalone binary
./banshee-engine -scope ../config/scope.yaml -udp -ports 53,161 192.168.1.10
```

`--udp` is UDP-only (like `nmap -sU`) and cannot be combined with `--adaptive`
(the adaptive planner models TCP detection risk).

### Service & version — `-sV`

`-sV` identifies the **product and version** behind an open TCP port — and, like
everything else in BANSHEE, it reports a version **only when a real banner proves
it**, never a guess from the port number. It works in two layers:

- a **free** layer, always on, reads the greeting a service sends first (SSH,
  FTP, SMTP, …) and matches it — no extra packet;
- an **active** layer, only under `-sV`, sends one `GET /` to an open-but-silent
  HTTP port to pull its `Server:` header.

A port whose banner matches nothing is still reported open, just with no version —
the same honesty rule that makes a silent UDP port `open\|filtered` and not `open`.

```bash
banshee scanme.nmap.org -p 22,80 --engine go -sV --json out.json
```

Real output (`scanme.nmap.org`, which the Nmap Project authorizes for scanning):

```text
22/tcp open  ssh   product=OpenSSH version=6.6.1p1   confirmed
   banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80/tcp open  http  product=Apache  version=2.4.7     confirmed
   banner: HTTP/1.1 200 OK … Server: Apache/2.4.7 (Ubuntu)
```

Both versions came straight from the bytes those services returned. `-sV` needs
`--engine go`/`auto` and is TCP-only (not combined with `--udp`).

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

The full suite (304 tests) proves the hard cases against reality on loopback:
cross-engine **parity** (Python and Go agree port-for-port), **UDP ground
truth** — a replying UDP port is reported `open`, a silent one is `open|filtered`
and *never* a fake "open" — and **service-version honesty**, that `-sV` extracts a
product/version only from a real banner and invents nothing for a silent port. The
Go engine carries its own ground-truth tests (`cd engine && go test ./...`).
Everything runs on every push via CI on Linux and Windows — including the Go build,
so the parity, UDP and `-sV` tests execute, not skip.

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

## Compare two scans — `banshee diff`

Save a JSON report now, another later, and `banshee diff` tells you exactly what
changed — new or vanished hosts, ports that opened or closed, and (with `-sV`)
**service versions that changed**, which is often the first sign of a patched,
downgraded, or swapped daemon.

```bash
banshee 10.0.0.0/24 -m normal --engine go -sV --json monday.json
# … a week later …
banshee 10.0.0.0/24 -m normal --engine go -sV --json friday.json
banshee diff monday.json friday.json          # add --json delta.json for CI
```

```text
+ new host 10.0.0.42  (22/tcp ssh (OpenSSH 9.6p1), 80/tcp http)
- gone host 10.0.0.9
~ 10.0.0.5
    + opened 8080/tcp http-alt
    - closed 23/tcp telnet
    ~ changed 22/tcp  OpenSSH 8.9p1 -> OpenSSH 9.9p1
```

It is a pure comparison of the two files — no network, no inference — and an
ambiguous `open|filtered` port counts as neither open nor closed, so it never
reports a change it cannot prove.

---

## Spot a decoy — `--deception`

`--deception` flags hosts that *look* like a honeypot or decoy, using only data
already collected — it sends **zero packets**. It weighs a few signals: an
unusually large number of open services, a cluster of classic bait ports
(telnet, ftp, mysql, vnc…), a Windows-vs-Unix contradiction between ports and
banners, and known honeypot-framework tokens in a banner (Cowrie, Dionaea…).

```bash
banshee 10.0.0.0/24 -m normal --engine go -sV --deception --html report.html
```

Because a honeypot can't be proven from the outside, the result is **always a
single `POTENTIAL` finding** per host — worded as a lead to verify, never a
verdict — listing the exact signals that fired. A single weak signal never fires
alone, so an ordinary web+SSH server is left untouched.

---

## Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `scope file not found` | You passed `--scope` with a path that doesn't exist. Without `--scope`, a built-in default is used automatically. |
| Everything reports out-of-scope | Your target isn't in `allowlist`. Add it to your scope file (see [Scope](#scope--authorization)). Exit code **3**. |
| `banshee-engine binary not found` | `--engine go` can't find the engine. Build it (`cd engine && go build -o banshee-engine ./cmd/banshee-engine`), download a [release binary](https://github.com/eyadgamer1/banshee/releases), set `BANSHEE_ENGINE=/path/to/banshee-engine`, or use `--engine auto` to fall back to Python. |
| `--udp needs the Go engine` | `--udp` (and `--adaptive`) run only on the Go engine. Add `--engine go` (or `--engine auto` with the binary present). |
| `--udp and --adaptive are mutually exclusive` | Pick one: UDP scan **or** the TCP adaptive planner. |
| UDP scan shows lots of `open\|filtered` | Working as intended — that's an honest "can't tell open from filtered", not a bug. A firewall dropping UDP looks identical to a silent open service; only a reply proves `open`. |
| Passive sniff finds nothing on Windows | Install [Npcap](https://npcap.com) in WinPcap-compatible mode. Passive capture needs a packet driver. |
| `Operation not permitted` on `-i` / passive | Raw sockets need privileges — run with `sudo` (Linux/macOS) or as Administrator (Windows). The active TCP/UDP sweep does not. |
| Garbled banner on an old terminal | Harmless — BANSHEE auto-falls back to an ASCII banner when the console can't render block glyphs. |
| `--agentic` does nothing | It needs a local [Ollama](https://ollama.com) server with a pulled model. |

**Exit codes:** `0` success · `1` engine/runtime error (e.g. a report path that can't be written, or the Go engine failing to run) · `2` bad usage (unknown flag/value, no valid targets, malformed target, bad `--ports`, out-of-range option, missing `--pcap`, unreadable/invalid scope file) · `3` scope violation (every target out of scope).

Every bad input fails fast with a one-line message and one of these codes — never a Python traceback. A malformed target mixed with good ones is skipped with a warning; a well-formed but unresolvable hostname simply reports that no host responded.

---

## Ethics & license

BANSHEE performs **no exploitation** and enforces a hard scope boundary. Use it only against networks you own or are explicitly authorized to assess. You are responsible for your use of this tool.

Licensed under **GPL-3.0** — see [LICENSE](LICENSE). Contributions welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) and report issues at the [tracker](https://github.com/eyadgamer1/banshee/issues).

<div align="center">
<sub>BANSHEE — she sees everything you left exposed.</sub>
</div>

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
- [Install](#install) — one line, both engines; OS-specific notes and [from source](#from-source--go-engine) inside
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

BANSHEE is an **active network scanner** — no passive traffic sniffing, no pcap replay. Point it at a network you are authorized to assess and it maps every host, fingerprints services, classifies devices, spots rogue hardware, and produces a risk report. It **scans actively like `nmap`** — `banshee <target>` just works. Use `--dry-run` to plan a scan and send zero packets, or `-m stealth` for a slow, rate-limited active sweep.

It is built for ethical hackers and defenders who care about two things most scanners ignore:

1. **Trust** — every result is tied to how it was observed. A port is only reported open if a socket actually opened. Findings are graded `CONFIRMED`, `PROBABLE`, or `POTENTIAL` so you always know what is fact and what is inference. See [Prove the results are real](#prove-the-results-are-real).
2. **Stealth** — the tool tells you how loud a scan is and lets you cap it. The default is silent observation; you opt into noise deliberately.

---

## Why it's different

| Capability | Most scanners | BANSHEE |
|---|---|---|
| **Default posture** | Send probes immediately, no budget awareness | Active by default, but honest about cost — `--dry-run` plans with zero packets, `-m stealth` caps the rate |
| **Result honesty** | "Open" with no provenance | `CONFIRMED / PROBABLE / POTENTIAL` tiers, never fabricated |
| **Detection cost** | Not measured | Per-port risk weighting; cap it with a budget |
| **Adaptive probing** | Static top-ports list | Bayesian per-host probe selection (Go engine) |
| **Fingerprinting** | Banner grab | TCP/IP stack, TLS JA4S, DHCP, clock-skew, OUI |
| **Deployment** | `pip install` + runtime | Also a single static Go binary you `scp` onto a jump box |
| **Reporting** | One or two formats | TXT · JSON · XML · HTML · CSV · SARIF 2.1.0 + SQLite history |

---

## Install

**TL;DR — one line, any OS, both engines ready** (needs [`uv`](https://github.com/astral-sh/uv) and a [Go](https://go.dev/dl/) toolchain on `PATH` so the engine bundles automatically; [install uv](https://github.com/astral-sh/uv#installation) first if you don't have it):

```bash
uv tool install git+https://github.com/eyadgamer1/banshee
banshee --help
```

That's the whole install — one command. `banshee-engine` is compiled from the
same source tree as the Python wrapper and packed straight into the installed
package (see [The Go engine](#the-go-engine)), so Python and Go are always the
same version — not a separate fetch that can drift out of sync. If `go` isn't
on `PATH` when you run the command above, the install still succeeds
Python-only (`--engine python`), and `banshee install-engine` fetches a
prebuilt fallback binary afterwards.

> **Requirements:** Python **3.12+**. The active TCP-connect sweep, TLS JA4S fingerprinting, and service/version detection all need **no privileges** and never prompt for one. Only the raw-socket probes (`-i`/`--iface` TCP/IP-stack and clock-skew fingerprinting, ICMP discovery) need elevation, and they auto-elevate through your OS's own **`sudo`** (Linux/macOS) or **UAC** (Windows) prompt the moment you pass `-i` — never a BANSHEE-owned password field. Windows also needs **[Npcap](https://npcap.com)** (WinPcap-compatible mode) for those raw-socket probes once elevated.

<details>
<summary><b>OS-specific notes</b> — Kali/Debian/Ubuntu, Windows, macOS, Docker, <code>pipx</code>/<code>pip</code>, from source</summary>

**Kali / Parrot / Debian / Ubuntu**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"   # do NOT run `exec $SHELL` here; it replaces the shell
sudo apt update && sudo apt install -y golang-go   # so the engine bundles automatically below
uv tool install git+https://github.com/eyadgamer1/banshee
uv tool update-shell                    # keep `banshee` on PATH in future terminals
```

> **`banshee: command not found`?** Run `uv tool update-shell` then open a new terminal, or `export PATH="$HOME/.local/bin:$PATH"` for the current shell.

```bash
# pipx (isolated venv), or the one-line installer (auto-detects uv/pipx/pip,
# installs Go first if missing, then installs BANSHEE — pass --no-go to skip Go):
sudo apt update && sudo apt install -y pipx golang-go && pipx install git+https://github.com/eyadgamer1/banshee
curl -sSL https://raw.githubusercontent.com/eyadgamer1/banshee/main/install.sh | bash
```

**Windows**

```powershell
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
winget install GoLang.Go   # so the engine bundles automatically below; skip to stay Python-only
uv tool install git+https://github.com/eyadgamer1/banshee
banshee 192.168.1.0/24 --mode normal
```

The active TCP-connect sweep works out of the box. Raw-socket fingerprinting needs [Npcap](https://npcap.com) (WinPcap-compatible mode) — BANSHEE re-launches itself through the UAC prompt automatically the moment `-i` is passed. The banner falls back to plain ASCII on legacy code pages automatically.

**macOS**

```bash
brew install uv go                 # or: brew install pipx go
uv tool install git+https://github.com/eyadgamer1/banshee
```

**Docker**

Raw packet capture inside a container needs `NET_RAW`/`NET_ADMIN` and host networking (the provided `docker-compose.yml` sets both) — auto-elevation does not apply inside a container, so run the container itself with those capabilities instead.

```bash
git clone https://github.com/eyadgamer1/banshee && cd banshee
docker compose run --rm banshee 192.168.1.0/24 --mode normal -T3 --html /app/output/report.html
```

</details>

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

**Easiest — one command, and you've likely already done it.** If `go` was on
your `PATH` when you ran `uv tool install`/`pip install`/`install.sh` above, the
engine is already bundled — nothing further to do:

```bash
banshee scanme.nmap.org --engine go -sV --mode normal
```

**No Go toolchain at install time?** Fetch a prebuilt fallback binary instead
(same idea as before, just no longer the default path):

```bash
banshee install-engine
```

It detects your OS/arch, downloads the right `banshee-engine` from the latest
release, drops it next to the `banshee` command, and verifies it runs. Note
this can trail the Python wrapper by a release or two — installing/reinstalling
with a Go toolchain present is what keeps the two version-locked. Options:
`banshee install-engine --tag v1.3.0` pins a release; `--dir PATH` installs
somewhere specific.

**Prebuilt Go engine — manual download.** Every tagged release also ships static
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

BANSHEE installs straight from `main`. The reliable way to update — no matter how
you first installed — is a clean reinstall with `uv`, which re-fetches the latest
commit and rebuilds:

```bash
uv tool install --reinstall git+https://github.com/eyadgamer1/banshee
```

Prefer your package manager's own upgrade? Run the **one** line matching how you
installed. Note the tool is registered under its package name **`banshee-scanner`**
(the command it installs is `banshee`), so upgrade that name, not `banshee`:

```bash
uv tool upgrade banshee-scanner        # if you installed with uv
pipx upgrade banshee-scanner           # if you installed with pipx
```

> **Debian / Kali: do not use bare `pip`.** There it is often Python 2.7, which
> cannot build this Python 3.12 package (`ImportError: No module named importlib`).
> Use `uv` (above), or if you must use pip, call Python 3 explicitly:
> `python3 -m pip install --upgrade git+https://github.com/eyadgamer1/banshee`.

Check what you're on with `banshee --version`. Updating the Go engine binary is
separate: re-download it from [Releases](https://github.com/eyadgamer1/banshee/releases)
or rebuild with `git pull && cd engine && go build -o banshee-engine ./cmd/banshee-engine`.

---

## Quick start

```bash
# One host, default settings — confirm open ports and grab banners
banshee 192.168.1.10

# A subnet, every port
banshee 192.168.1.0/24 -p-

# fast/minimal · full-signal + HTML report · slow and quiet — one word each
banshee quick 192.168.1.0/24
banshee pro 192.168.1.0/24
banshee stealth 192.168.1.0/24

# Plan only — see what would run, send zero packets
banshee 192.168.1.0/24 --dry-run
```

`banshee --help` shows the common flags above; `banshee --help-advanced`
shows everything (raw-socket fingerprinting, the Go engine's adaptive/UDP
modes, output formats, persistence, and more).

By default BANSHEE scans **any target you give it, like `nmap`** — the authorization responsibility is yours. To restrict it to a lab or engagement range, pass a scope allowlist with `--scope` — see [Scope & authorization](#scope--authorization).

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

[!] AUTHORIZED TARGETS ONLY - open scope (any target); you are responsible for authorization
mode=normal -T4 engine=python fingerprint=True

hosts up 1  services 2  findings 0  in-scope 1  out-of-scope 0  packets 6

 IP          Name                         MAC   Vendor   OS        Ports      Conf.
 ──────────────────────────────────────────────────────────────────────────────────
 127.0.0.1   kubernetes.docker.internal               Windows   135, 445   confirmed
```

The `Conf.` column is the trust grade. `mode=normal -T4 engine=python` echoes the two intensity dials and the active-scan engine in force. `packets 6` is the exact number of probes sent — a `--dry-run` shows `packets 0`. During a longer scan the dashboard shows a per-host table updating live (discovering → fingerprinting → done) with a running stats bar.

Colour and detail are controlled independently from scan intensity — see the two dials below.

---

## Command reference

```
banshee [OPTIONS] TARGETS...
```

`TARGETS` are IPs, CIDRs, ranges, or hostnames: `192.168.1.0/24`, `10.0.0.5-20`, `host.lan`.
Ranges take a last-octet shorthand (`10.0.0.5-20`) or two full addresses
(`10.0.0.5-10.0.0.20`), both endpoints included. Every form expands identically
on either engine, and a token that would expand past `max_hosts_per_scan` is
refused rather than truncated.

BANSHEE has **two independent dials.** *Verbosity* controls how much it prints; *intensity* controls how loud it is on the wire. They never affect each other.

The table below is the **common surface** — what `banshee --help` shows by
default. Every other flag (raw-socket fingerprinting, `--engine`/`--adaptive`,
output formats besides JSON/HTML, toggles, persistence, `--audit-log`, …) still
works, just hidden until you ask: run `banshee --help-advanced` to see all of it.

### Targets & input

| Flag | Description |
|---|---|
| `-p, --ports TEXT` | Ports to probe: `22,80,443` or `1-1024`; `-` or `all` = every port 1-65535 (default: common high-signal set) |

### Verbosity — *how much it prints*

| Flag | Description |
|---|---|
| `-v, -vv, -vvv` | Increase detail |
| `-q, --quiet` | Results only |

`--silent`, `--debug`, `--no-color` also exist — `banshee --help-advanced`.

### Intensity — *how loud it is*

| Flag | Description |
|---|---|
| `-m, --mode [stealth\|normal\|aggressive]` | Scan intensity (default **`normal`** — actively probes like `nmap`). `stealth` is slow and rate-limited; `--dry-run` sends zero packets |
| `-T, --timing 0..5` | Timing template, T0 (paranoid) … T5 (insane), default `3` |

`--rate`, `--timeout`, `--threads`, `--max-detect-risk` also exist
(the last is a hard ceiling on noise: `0` = no active probes, `10` = full
intensity) — `banshee --help-advanced`.

### Engine — *who does the active probing*

| Flag | Description |
|---|---|
| `-sV, --service-scan` | Go only: identify a service's **product + version** from its banner. Match-only — a version is reported **only** when a captured banner matches a signature, never guessed from the port (auto-fetches the Go engine on first use; TCP-only) |

`--engine [python\|go\|auto]` (default `auto` — uses Go when present, else
Python), `--adaptive` (Go-only info-gain probe planner), and `--udp` also exist
— `banshee --help-advanced`.

> `--engine go` needs a `banshee-engine` binary. Normally that's already bundled (installed with `go` on `PATH` — see [Install](#install)); otherwise build it (`cd engine && go build -o banshee-engine ./cmd/banshee-engine`) and point `$BANSHEE_ENGINE`/`PATH` at it, or run `banshee install-engine` for a prebuilt fallback. See [The Go engine](#the-go-engine).

### Toggles, output files, persistence — advanced

`--fingerprint/--no-fingerprint`, `--names/--no-names`,
`--classify/--no-classify`, `--ssvc`, `--plugins`, `--deception`, `--enrich`,
`--agentic`, `--txt`/`--xml`/`--csv`/`--sarif`, `-A`/`--all`, `--db`,
`--baseline`, `--audit-log`, `--plugin-dir` — all on by request only, all
covered in `banshee --help-advanced`.

Verbosity is a real three-step dial: `-v` adds BANSHEE's own INFO detail, `-vv`
adds its DEBUG detail, and `-vvv` adds DEBUG from third-party libraries too.
`--silent` overrides all of them, `--debug` is a shorthand for `-vv`.

### Safety & maintenance

| Flag | Description |
|---|---|
| `--scope TEXT` | Scope allowlist file (default `config/scope.yaml`; a built-in default is used if absent) |
| `--dry-run` | Plan only; send zero packets |
| `--version` | Show version |
| `--help-advanced` | Show every flag, common and advanced |

---

## Examples cookbook

**Zero packets — plan only:**

```bash
banshee 192.168.1.0/24 --dry-run              # see what would be probed, send nothing
```

**Active — you choose the intensity:**

```bash
banshee 192.168.1.10 --mode normal                     # confirm open ports + banners
banshee 10.0.0.5 -p 22,80,443,3389 -m normal -T4       # specific ports, fast
banshee 10.0.0.0/24 -p- -m normal                       # every port, 1-65535
banshee 10.0.0.0/24 -m stealth -T1                      # slow and quiet
banshee 10.0.0.0/24 -m aggressive -T4 --max-detect-risk 9   # loud, full intensity
banshee 10.0.0.0/24 -m normal --max-detect-risk 3      # active, but capped to quiet ports
```

**Presets — the common combos, one word:**

```bash
banshee quick 192.168.1.0/24        # fast, no fingerprinting, common ports
banshee pro 10.0.0.0/24             # fingerprint + classify + enrich + ssvc + adaptive -sV, HTML report
banshee stealth 10.0.0.0/24         # -m stealth -T1, one word instead of memorizing the combo
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

**Go is the hands, Python is the mind.** You do not have to choose between them: run the normal `banshee` command with `--engine go` and the Go binary does the fast, parallel active probing while Python keeps classification, LLM analysis, and all six report formats. It's one tool.

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

**BANSHEE is open by default — like `nmap`, it will scan any target you give it. The authorization responsibility is entirely yours.** Only scan networks you own or are explicitly authorized to test. Unauthorized scanning is illegal in most jurisdictions.

The default scope (`config/scope.yaml`, or a built-in copy when that file is absent) admits every IPv4 and IPv6 target:

```yaml
banner: "AUTHORIZED TARGETS ONLY - open scope (any target); you are responsible for authorization"
allowlist:
  - 0.0.0.0/0
  - "::/0"
denylist: []
max_hosts_per_scan: 65536
max_ports_per_host: 65535
```

**Put the safety rail back with a scope file.** The scope engine is fully intact — it still enforces whatever allowlist/denylist you give it. To lock BANSHEE to a lab or engagement range, write your own allowlist and pass it with `--scope`:

```yaml
# my-engagement.yaml — only these ranges may be scanned
allowlist:
  - 10.0.0.0/8
  - 203.0.113.0/24
denylist:
  - 10.9.9.0/24        # deny wins over allow
```

```bash
banshee 203.0.113.5 --scope my-engagement.yaml
```

With a restrictive scope, anything not on the list is refused with **exit code 3**, and a target larger than `max_hosts_per_scan` is refused outright rather than silently truncated. Use a denylist to carve out hosts you must never touch even inside an allowed range.

**Keep the record with `--audit-log`.** Pass a path and BANSHEE appends a JSONL
trail of the run: name resolution, scan start, every scope decision, and the
final result. A refused scan is logged too — a blocked target is exactly when
the record matters — and a dry run is recorded as `dry_run`, distinct from a
real scan. Both engines write the same trail:

```bash
banshee 203.0.113.5 --scope my-engagement.yaml --audit-log engagement.jsonl
```
```json
{"ts": "…", "event": "scan_start", "mode": "normal", "targets": ["203.0.113.5"], "engine": "go"}
{"ts": "…", "event": "scope_violation", "out_of_scope": ["203.0.113.5"], "engine": "go"}
```

---

## Prove the results are real

The most dangerous thing a security scanner can do is lie — report a port that is not open, or a finding that is not there. BANSHEE is built so that cannot happen quietly, and it ships the proof.

**The guarantee:** a service is reported open **only** as the direct record of a socket that actually opened. Open ports are graded `CONFIRMED`; an inference is at most `PROBABLE`; anything an LLM suggests is capped at `POTENTIAL` and can never be promoted — see `scanner/risk/__init__.py`, which is the final authority on every confidence tier in a report.

**Verify it yourself.** Point BANSHEE at a host you control and bind a listener on a port you know is closed, then a port you know is open, and compare:

```bash
python3 -m http.server 8123 &        # something real and open
banshee 127.0.0.1 -p 8123,8124       # 8123 open, 8124 closed — the report must match exactly
```

The Go engine carries its own test suite (`cd engine && go test ./...`), run on every push via CI on Linux and Windows alongside `go vet`, `ruff check`, and `mypy --strict`.

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
| Everything reports out-of-scope | Only happens when you passed a restrictive `--scope`: your target isn't in that file's `allowlist`. Add it, or drop `--scope` to use the open default (see [Scope](#scope--authorization)). Exit code **3**. |
| `banshee-engine binary not found` | It didn't get bundled — `go` probably wasn't on `PATH` when you installed. Easiest fix: install a [Go toolchain](https://go.dev/dl/) and reinstall (`uv tool install --reinstall git+https://github.com/eyadgamer1/banshee`) so it bundles automatically. Or fetch a prebuilt fallback: **`banshee install-engine`**. Or build it (`cd engine && go build -o banshee-engine ./cmd/banshee-engine`), set `BANSHEE_ENGINE=/path/to/banshee-engine`, or use `--engine auto` to fall back to Python. |
| `flag provided but not defined: -watch-stdin` | A stale prebuilt engine from `banshee install-engine` predates a flag the wrapper now sends. Reinstall with a Go toolchain on `PATH` so the engine bundles from the same commit instead of a lagging release tag. |
| `--udp needs the Go engine` | `--udp` (and `--adaptive`) run only on the Go engine. Add `--engine go` (or `--engine auto` with the binary present). |
| `--udp and --adaptive are mutually exclusive` | Pick one: UDP scan **or** the TCP adaptive planner. |
| UDP scan shows lots of `open\|filtered` | Working as intended — that's an honest "can't tell open from filtered", not a bug. A firewall dropping UDP looks identical to a silent open service; only a reply proves `open`. |
| `-i`/`--iface` finds nothing on Windows | Install [Npcap](https://npcap.com) in WinPcap-compatible mode. Raw-socket fingerprinting needs a packet driver. |
| `Operation not permitted` on `-i` / ICMP | Raw sockets need privileges. `-i`/`--iface` auto-re-launches through `sudo`/UAC — on Windows a declined UAC falls back to an unprivileged run; on Linux/macOS a declined `sudo` ends the run with sudo's exit code, since `execvp` has already replaced the process. The active TCP/UDP sweep and TLS JA4S fingerprinting never need privilege at all. |
| Garbled banner on an old terminal | Harmless — BANSHEE auto-falls back to an ASCII banner when the console can't render block glyphs. |
| `--agentic` does nothing | It needs a local [Ollama](https://ollama.com) server with a pulled model. |

**Exit codes:** `0` success · `1` engine/runtime error (e.g. a report path that can't be written, or the Go engine failing to run) · `2` bad usage (unknown flag/value, no valid targets, malformed target, bad `--ports`, out-of-range option, unreadable/invalid scope file) · `3` scope violation (every target out of scope).

Every bad input fails fast with a one-line message and one of these codes — never a Python traceback. A malformed target mixed with good ones is skipped with a warning; a well-formed but unresolvable hostname simply reports that no host responded.

---

## Ethics & license

BANSHEE performs **no exploitation** and enforces a hard scope boundary. Use it only against networks you own or are explicitly authorized to assess. You are responsible for your use of this tool.

Licensed under **GPL-3.0** — see [LICENSE](LICENSE). Contributions welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) and report issues at the [tracker](https://github.com/eyadgamer1/banshee/issues).

<div align="center">
<sub>BANSHEE — she sees everything you left exposed.</sub>
</div>

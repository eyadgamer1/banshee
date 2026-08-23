# banshee-engine

The Go active-scan core for BANSHEE: a single static binary that performs
concurrent TCP-connect discovery, optional server-first banner reads, and — its
distinguishing feature — **per-host adaptive probe selection by expected
information gain per unit of detection risk**.

It exists for two reasons:

1. **Deployability.** A pentester often cannot `pip install` on a client jump box
   or an ARM drop-box, but they can `scp` one file. `banshee-engine` is a
   dependency-free static binary that cross-compiles for any target.
2. **Speed and footprint.** On the same loopback sweep of ports 1–1024 it runs in
   ~4.1 s using ~9 MB RSS, against ~15 s and ~28 MB for the Python path — and it
   starts instantly, with no interpreter or scapy import to pay for.

It is **not** a fork. It emits the exact JSON schema `scanner/` produces, so the
Python side keeps ownership of reporting, enrichment, SSVC and the LLM stages,
and the Python ground-truth suite (`tests/test_ground_truth.py`) validates this
binary unchanged. The Go `host`, `service` and `stats` objects are byte-compatible
with the Python dataclasses, field-for-field and in order.

## Safety

Safety is enforced, not advisory, and has no override flag:

- **Scope guard.** Targets outside `--scope` are refused, never scanned. The
  guard refuses to run at all against an empty allowlist. Scope is re-checked at
  the moment of each connect, as defense in depth.
- **Passive budget.** `--mode passive`, or `--max-detect-risk 0`, puts **zero**
  packets on the wire and marks the result `dry_run` so a consumer can tell
  "nothing was found" from "nothing was probed".
- **No fabrication by construction.** A reported open service exists only as the
  direct record of a socket that actually opened. An accepted connect is
  `confirmed`; a refused connect proves the host is up with the port closed; a
  timeout is no signal.

## Build

```
cd engine
go build -o banshee-engine ./cmd/banshee-engine       # host platform
GOOS=linux   GOARCH=arm64 go build ./cmd/banshee-engine   # ARM drop-box
GOOS=windows GOARCH=amd64 go build ./cmd/banshee-engine
```

No cgo, no external modules beyond `gopkg.in/yaml.v3`.

## Usage

```
# High-signal default sweep, JSON to stdout
banshee-engine -scope config/scope.yaml 10.0.0.0/28

# Explicit ports, fast timing
banshee-engine -scope config/scope.yaml -ports 22,80,443,3389 -T 4 10.0.0.5

# Adaptive: stop probing each host once its class posterior crosses 85%
banshee-engine -scope config/scope.yaml -adaptive -confidence 0.85 -pretty 10.0.0.0/28

# Cap the detection risk spent per host (loud ports like 445/3389 cost more)
banshee-engine -scope config/scope.yaml -adaptive -host-risk-budget 8 10.0.0.0/28
```

Exit codes match the Python CLI: `0` ok, `1` error, `2` bad usage, `3` nothing in
scope.

## The adaptive planner

`internal/adaptive` carries a Bayesian posterior over device classes for each
host. Before every probe it computes, for each candidate port,

```
EIG(p) = H(prior) − [ P(open)·H(post | open) + P(closed)·H(post | closed) ]
```

— the class-uncertainty bits the probe is expected to resolve — and selects
`argmax EIG(p) / cost(p)`, where `cost` is that port's detection risk (1 for 443,
8 for 445, 9 for an ICS port whose probe could disrupt the process). It stops as
soon as the posterior crosses the confidence threshold or the risk budget is
spent.

The effect, measured against a real workstation: **3 probes instead of 26, 5
units of detection risk instead of 104**, same correct verdict. Unlike nmap's
`--top-ports`, the port order is not a fixed global frequency list; it is
recomputed per host from what has been learned about *that* host, and it is
cost-aware. Every choice is recorded in the result's `plan` block — which probe,
what it was expected to buy in bits, what it cost, and what the posterior did —
so the operator can defend the scan afterward.

## Tests

```
go test ./...
```

`internal/adaptive` tests hold the planner to its math (the posterior stays a
distribution, information gain is non-negative, a clear host converges and stops
early, the risk budget is never exceeded, planning is deterministic).
`internal/scan` is the ground-truth mirror of the Python suite: it binds real
listeners on loopback, runs the real engine, and asserts the reported open ports
equal the bound ports exactly — including the negative direction, that an unbound
port is never reported open, and that passive mode sends zero packets.

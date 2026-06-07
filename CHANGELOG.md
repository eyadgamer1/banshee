# Changelog

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

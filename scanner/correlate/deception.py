"""C8 — deception / honeypot signal analysis.

A honeypot is a host built to *look* attractive: many open ports, a cluster of
legacy bait services, or a service stack that contradicts itself. This pass reads
those signals off data BANSHEE already collected — it sends **zero packets** — and
raises at most one finding per host.

Honesty first: a honeypot cannot be proven from the outside, and any of these
signals has innocent explanations (a jump box really can run many services; a
banner can be spoofed either way). So the finding is always **POTENTIAL**, is
worded as a lead to verify rather than a fact, and carries the exact signals that
triggered it. It never asserts "this is a honeypot."
"""

from __future__ import annotations

from scanner.core.models import ConfidenceTier, Finding, PortState, ScanResult, Service, Severity

# A host with at least this many confirmed-open services is unusual enough to be
# worth a look — classic of Honeyd/Dionaea-style "answer everything" honeypots.
MANY_OPEN_PORTS = 10

# Classic bait services a honeypot exposes to attract attackers. Real hosts rarely
# run many of these together, so a cluster is a signal.
BAIT_PORTS: dict[int, str] = {
    21: "ftp", 23: "telnet", 25: "smtp", 110: "pop3", 143: "imap",
    512: "exec", 513: "login", 514: "shell", 1433: "mssql", 3306: "mysql",
    5432: "postgres", 5900: "vnc", 6379: "redis", 27017: "mongodb",
}
DECOY_CLUSTER_MIN = 3

# Ports served (almost) only by Windows. Seeing these next to a distinctly-Unix
# service banner on one IP is a self-contradiction a decoy often gets wrong.
WINDOWS_PORTS = {135, 139, 445, 3389}
UNIX_BANNER_TOKENS = ("debian", "ubuntu", "raspbian", "vsftpd", "proftpd", "dovecot", "exim")

# Tokens that name a known honeypot framework outright — a near-giveaway when a
# service actually returns one, though a banner can still be forged.
HONEYPOT_TOKENS = ("cowrie", "kippo", "dionaea", "nepenthes", "honeyd", "glastopf", "conpot")

# Point weights; a host is flagged at or above the cut. Any one strong signal
# clears it; an OS contradiction alone (weak) does not.
_SCORE_CUT = 2
_W_MANY = 2
_W_CLUSTER = 2
_W_BANNER = 3
_W_CONTRADICTION = 1


def _open_tcp(host_services: list[Service]) -> list[Service]:
    return [s for s in host_services if s.proto.value == "tcp" and s.state == PortState.OPEN]


def _banner_hit(services: list[Service], tokens: tuple[str, ...]) -> tuple[str, int] | None:
    for s in services:
        blob = f"{s.banner or ''} {s.product or ''}".lower()
        for tok in tokens:
            if tok in blob:
                return tok, s.port
    return None


def score_deception(result: ScanResult) -> int:
    """Attach a POTENTIAL deception finding to each host whose signals clear the
    cut. Returns the number of findings added."""
    added = 0
    for host in result.hosts:
        services = _open_tcp(host.services)
        if not services:
            continue
        open_ports = {s.port for s in services}
        score = 0
        reasons: list[str] = []

        if len(open_ports) >= MANY_OPEN_PORTS:
            score += _W_MANY
            reasons.append(f"{len(open_ports)} open services (>= {MANY_OPEN_PORTS}, unusual)")

        bait = sorted(open_ports & BAIT_PORTS.keys())
        if len(bait) >= DECOY_CLUSTER_MIN:
            score += _W_CLUSTER
            named = ", ".join(f"{p} {BAIT_PORTS[p]}" for p in bait)
            reasons.append(f"legacy bait cluster ({len(bait)} classic honeypot ports): {named}")

        win = sorted(open_ports & WINDOWS_PORTS)
        unix = _banner_hit(services, UNIX_BANNER_TOKENS)
        if win and unix:
            score += _W_CONTRADICTION
            reasons.append(
                f"OS contradiction: Windows service(s) {win} alongside a Unix banner "
                f"token '{unix[0]}' on port {unix[1]}"
            )

        hp = _banner_hit(services, HONEYPOT_TOKENS)
        if hp:
            score += _W_BANNER
            reasons.append(f"known honeypot framework token '{hp[0]}' in banner on port {hp[1]}")

        if score >= _SCORE_CUT and reasons:
            host.findings.append(
                Finding(
                    id=f"C8-deception-{host.ip.replace('.', '_').replace(':', '_')}",
                    title="possible deception / honeypot host",
                    severity=Severity.LOW,
                    confidence=ConfidenceTier.POTENTIAL,
                    description=(
                        "Signals consistent with a decoy or honeypot. This is an inference from "
                        "passively-collected scan data, not proof — a real host can look this way, "
                        "and banners can be forged. Treat it as a lead to verify, never a verdict."
                    ),
                    evidence="; ".join(reasons),
                    source="C8",
                )
            )
            added += 1
    return added

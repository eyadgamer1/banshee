"""Compare two BANSHEE scan reports and describe what changed.

Pure comparison of two ``ScanResult`` snapshots — no network, no inference. It
reports only differences the two inputs actually contain: hosts that appeared or
vanished, ports that opened or closed, and — the payoff of ``-sV`` — services
whose product/version changed between runs, which is a real security signal.

Only confirmed-open services (``state == open``) count as present; an ambiguous
``open|filtered`` is neither an open nor a close, so it never manufactures a
spurious change.
"""

from __future__ import annotations

import ipaddress

from pydantic import BaseModel, Field

from scanner.core.models import Host, PortState, ScanResult, Service


class ServiceChange(BaseModel):
    """A service present in both runs whose identity changed."""

    port: int
    proto: str
    old: str | None  # "product version" in the earlier run, or None if unknown
    new: str | None


class HostDiff(BaseModel):
    """Per-host changes for a host present in both runs."""

    ip: str
    opened: list[Service] = Field(default_factory=list)  # open now, not before
    closed: list[Service] = Field(default_factory=list)  # open before, not now
    changed: list[ServiceChange] = Field(default_factory=list)


class ScanDiff(BaseModel):
    """The full delta between an earlier and a later report."""

    new_hosts: list[Host] = Field(default_factory=list)  # in new, not old
    gone_hosts: list[Host] = Field(default_factory=list)  # in old, not new
    host_diffs: list[HostDiff] = Field(default_factory=list)  # common, changed

    @property
    def has_changes(self) -> bool:
        return bool(self.new_hosts or self.gone_hosts or self.host_diffs)


def _ip_key(ip: str) -> tuple[int, object]:
    try:
        return (0, ipaddress.ip_address(ip))
    except ValueError:
        return (1, ip)


def _open_services(host: Host) -> dict[tuple[int, str], Service]:
    return {
        (s.port, s.proto.value): s for s in host.services if s.state == PortState.OPEN
    }


def _identity(s: Service) -> str | None:
    if s.product and s.version:
        return f"{s.product} {s.version}"
    return s.product or None


def compute_diff(old: ScanResult, new: ScanResult) -> ScanDiff:
    """Return the delta from ``old`` to ``new``, keyed by host IP then port."""
    old_by_ip = {h.ip: h for h in old.hosts}
    new_by_ip = {h.ip: h for h in new.hosts}

    new_hosts = [new_by_ip[ip] for ip in sorted(new_by_ip.keys() - old_by_ip.keys(), key=_ip_key)]
    gone_hosts = [old_by_ip[ip] for ip in sorted(old_by_ip.keys() - new_by_ip.keys(), key=_ip_key)]

    host_diffs: list[HostDiff] = []
    for ip in sorted(old_by_ip.keys() & new_by_ip.keys(), key=_ip_key):
        before = _open_services(old_by_ip[ip])
        after = _open_services(new_by_ip[ip])
        opened = [after[k] for k in sorted(after.keys() - before.keys())]
        closed = [before[k] for k in sorted(before.keys() - after.keys())]
        changed = [
            ServiceChange(port=k[0], proto=k[1], old=_identity(before[k]), new=_identity(after[k]))
            for k in sorted(before.keys() & after.keys())
            if _identity(before[k]) != _identity(after[k])
        ]
        if opened or closed or changed:
            host_diffs.append(HostDiff(ip=ip, opened=opened, closed=closed, changed=changed))

    return ScanDiff(new_hosts=new_hosts, gone_hosts=gone_hosts, host_diffs=host_diffs)


def _svc_label(s: Service) -> str:
    ident = _identity(s)
    name = s.name or "?"
    return f"{s.port}/{s.proto.value} {name}" + (f" ({ident})" if ident else "")


def render_diff(diff: ScanDiff, console) -> None:  # type: ignore[no-untyped-def]
    """Print a compact, colored summary of a ScanDiff to a rich Console."""
    if not diff.has_changes:
        console.print(
            "[green]no changes[/green] — identical in hosts and open services"
        )
        return

    for h in diff.new_hosts:
        opens = [s for s in h.services if s.state == PortState.OPEN]
        detail = ", ".join(_svc_label(s) for s in opens) or "no open ports"
        console.print(f"[green]+ new host[/green] {h.ip}  [dim]({detail})[/dim]")

    for h in diff.gone_hosts:
        console.print(f"[red]- gone host[/red] {h.ip}")

    for hd in diff.host_diffs:
        console.print(f"[bold]~ {hd.ip}[/bold]")
        for s in hd.opened:
            console.print(f"    [green]+ opened[/green] {_svc_label(s)}")
        for s in hd.closed:
            console.print(f"    [red]- closed[/red] {_svc_label(s)}")
        for c in hd.changed:
            console.print(
                f"    [yellow]~ changed[/yellow] {c.port}/{c.proto}  "
                f"{c.old or '?'} [dim]->[/dim] {c.new or '?'}"
            )

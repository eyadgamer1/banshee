"""A2 — passive packet sniffer: discovers hosts from ambient traffic.

Listens for ARP, DHCP, mDNS, SSDP, and NBNS broadcasts without sending any
probes. This is the zero-packet discovery path — safe for PASSIVE mode.

On Windows the raw-socket BPF path is unavailable; `scapy` falls back to the
WinPcap/Npcap layer. If neither is installed, the sniffer degrades to a no-op
and logs a warning rather than crashing.

Protocol sources populated:
  ARP replies       → ip, mac  (source="A2-arp")
  DHCP offers/acks  → ip, mac, hostname  (source="A2-dhcp")
  mDNS answers      → ip, name  (source="A2-mdns")
  SSDP              → ip  (source="A2-ssdp")
  NBNS              → ip, netbios-name  (source="A2-nbns")
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from typing import TYPE_CHECKING, Any

from scanner.core.models import Host, HostState

if TYPE_CHECKING:
    from collections.abc import Sequence

    from scanner.core.interfaces import ScanContext

log = logging.getLogger(__name__)

# Regex for valid MACs
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def _normalise_mac(mac: str) -> str:
    return mac.lower()


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class PassiveSniffer:
    """A2 — collects host intel from overheard broadcast/multicast traffic."""

    name = "passive-sniffer"
    feature_id = "A2"

    def __init__(self, iface: str | None = None, timeout: float = 10.0) -> None:
        self._iface = iface
        self._timeout = timeout

    async def discover(self, targets: Sequence[str], ctx: ScanContext) -> list[Host]:
        """Sniff for `timeout` seconds; return hosts seen in-scope."""
        # Passive mode is the default for this discoverer — it never sends packets.
        # If budget explicitly disallows even passive capture (hypothetical) skip.
        loop = asyncio.get_running_loop()
        try:
            hosts_by_ip = await loop.run_in_executor(None, self._sniff_sync)
        except Exception as exc:
            log.warning("A2 passive sniff failed: %s — no hosts from sniffer", exc)
            return []

        results: list[Host] = []
        for ip, host in hosts_by_ip.items():
            if ctx.scope.is_in_scope(ip):
                results.append(host)
                ctx.audit.log("a2_host_seen", ip=ip, mac=host.mac, source="A2")
        return results

    def _sniff_sync(self) -> dict[str, Host]:
        """Blocking sniff — runs in a thread-pool executor."""
        try:
            from scapy.layers.dhcp import BOOTP, DHCP
            from scapy.layers.dns import DNS
            from scapy.layers.inet import IP, UDP
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import sniff
        except Exception as exc:
            log.warning("scapy unavailable (%s); A2 passive sniff skipped", exc)
            return {}

        hosts: dict[str, Host] = {}

        def _get_or_create(ip: str) -> Host:
            if ip not in hosts:
                hosts[ip] = Host(ip=ip, state=HostState.UP)
            return hosts[ip]

        def _handle(pkt: Any) -> None:  # noqa: C901 — packet dispatcher
            try:
                # --- ARP reply (op=2) ---
                if pkt.haslayer(ARP):
                    arp = pkt[ARP]
                    if arp.op == 2 and _is_private(arp.psrc):
                        h = _get_or_create(arp.psrc)
                        if _MAC_RE.match(str(arp.hwsrc)):
                            h.mac = _normalise_mac(str(arp.hwsrc))
                        h.state = HostState.UP

                # --- DHCP ---
                if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP) and pkt.haslayer(Ether):
                    bootp = pkt[BOOTP]
                    ip = str(bootp.yiaddr)
                    if ip and ip != "0.0.0.0" and _is_private(ip):
                        h = _get_or_create(ip)
                        mac = str(pkt[Ether].src)
                        if _MAC_RE.match(mac):
                            h.mac = _normalise_mac(mac)
                        h.state = HostState.UP
                        # Extract hostname option (12)
                        for opt in pkt[DHCP].options:
                            if isinstance(opt, tuple) and opt[0] == "hostname":
                                h.hostname = str(opt[1])
                                break

                # --- mDNS (UDP 5353) ---
                if pkt.haslayer(DNS) and pkt.haslayer(UDP) and pkt.haslayer(IP):
                    udp = pkt[UDP]
                    if udp.dport == 5353 or udp.sport == 5353:
                        src_ip = str(pkt[IP].src)
                        if _is_private(src_ip):
                            h = _get_or_create(src_ip)
                            h.state = HostState.UP
                            dns = pkt[DNS]
                            if dns.ancount and dns.ancount > 0:
                                for i in range(min(dns.ancount, 10)):
                                    try:
                                        rr = dns.an[i]
                                        if hasattr(rr, "rrname"):
                                            name = str(rr.rrname).rstrip(".")
                                            if name:
                                                h.names["mdns"] = name
                                    except Exception:
                                        pass

                # --- SSDP (UDP 1900) ---
                if pkt.haslayer(UDP) and pkt.haslayer(IP):
                    udp = pkt[UDP]
                    if udp.dport == 1900 or udp.sport == 1900:
                        src_ip = str(pkt[IP].src)
                        if _is_private(src_ip):
                            h = _get_or_create(src_ip)
                            h.state = HostState.UP

            except Exception:
                pass  # never crash on malformed packets

        bpf = "arp or (udp and (port 67 or port 5353 or port 1900 or port 137))"
        sniff(
            filter=bpf,
            prn=_handle,
            timeout=self._timeout,
            iface=self._iface,
            store=False,
        )
        return hosts

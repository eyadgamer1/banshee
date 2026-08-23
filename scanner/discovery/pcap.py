"""B12 — Offline PCAP discoverer.

Reads a .pcap / .pcapng file instead of live capture. Extracts host IPs,
MACs, and basic service hints from captured traffic. Used for post-mortem
analysis without sending any packets.

Activated via: `banshee --pcap /path/to/file.pcap <targets>`

Protocols parsed:
  ARP reply     → IP + MAC (CONFIRMED)
  TCP SYN-ACK   → src IP is listening on dst port
  DNS response  → hostname ↔ IP mapping
  DHCP offer    → IP + MAC + hostname
  ICMP echo-rep → host is up
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

    from scanner.core.interfaces import ScanContext
    from scanner.core.models import Host

log = logging.getLogger(__name__)


class PcapDiscoverer:
    name = "pcap"
    feature_id = "B12"

    def __init__(self, pcap_path: str) -> None:
        self.pcap_path = Path(pcap_path)

    async def discover(self, targets: Sequence[str], ctx: ScanContext) -> list[Host]:  # noqa: ARG002
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._read_sync, list(targets))

    def _read_sync(self, targets: list[str]) -> list[Host]:
        try:
            from scapy.utils import rdpcap
        except ImportError:
            log.warning("B12: scapy not available — pcap replay disabled")
            return []

        if not self.pcap_path.exists():
            log.error("B12: pcap file not found: %s", self.pcap_path)
            return []

        try:
            packets = rdpcap(str(self.pcap_path))
        except Exception as exc:
            log.error("B12: failed to read pcap %s: %s", self.pcap_path, exc)
            return []

        from scanner.core.models import ConfidenceTier, Host, HostState

        hosts: dict[str, Host] = {}
        dns_map: dict[str, str] = {}  # ip → hostname

        def _get(ip: str) -> Host:
            if ip not in hosts:
                hosts[ip] = Host(ip=ip, state=HostState.UP, confidence=ConfidenceTier.CONFIRMED)
            return hosts[ip]

        for pkt in packets:
            try:
                self._process_packet(pkt, hosts, dns_map, _get)
            except Exception:
                pass

        # Apply DNS names
        for ip, hostname in dns_map.items():
            if ip in hosts:
                hosts[ip].hostname = hosts[ip].hostname or hostname

        # Filter to targets if specified
        result = list(hosts.values())
        if targets and targets != ["0.0.0.0/0"]:
            import ipaddress
            networks = []
            for t in targets:
                try:
                    networks.append(ipaddress.ip_network(t, strict=False))
                except ValueError:
                    pass
            if networks:
                result = [
                    h for h in result
                    if any(ipaddress.ip_address(h.ip) in n for n in networks)
                ]

        log.info("B12: %d hosts extracted from %s", len(result), self.pcap_path.name)
        return result

    def _process_packet(
        self,
        pkt: Any,
        hosts: dict[str, Host],  # noqa: ARG002 — kept for symmetry with caller
        dns_map: dict[str, str],
        get: Any,
    ) -> None:
        from scapy.layers.inet import ICMP, IP, TCP
        from scapy.layers.l2 import ARP

        from scanner.core.models import PortState, Proto, Service

        # ARP reply → confirmed IP+MAC (vendor OUI lookup is deferred to B1)
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            h = get(pkt[ARP].psrc)
            h.mac = h.mac or pkt[ARP].hwsrc

        # IP layer present
        if not pkt.haslayer(IP):
            return
        src = pkt[IP].src

        # ICMP echo reply → host is up
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 0:
            get(src)

        # TCP SYN-ACK → src is listening on sport
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            if tcp.flags & 0x12 == 0x12:  # SYN+ACK
                h = get(src)
                sport = int(tcp.sport)
                if not any(s.port == sport for s in h.services):
                    h.services.append(
                        Service(port=sport, proto=Proto.TCP, state=PortState.OPEN, source="B12")
                    )

        # DNS response → extract A records
        try:
            from scapy.layers.dns import DNS
            if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
                dns = pkt[DNS]
                for i in range(dns.ancount):
                    rr = dns.an[i]
                    if hasattr(rr, "type") and rr.type == 1:  # A record
                        ip = rr.rdata
                        name = rr.rrname.decode("utf-8").rstrip(".")
                        dns_map[ip] = name
        except Exception:
            pass

        # DHCP offer → IP + MAC + hostname
        try:
            from scapy.layers.dhcp import BOOTP, DHCP
            if pkt.haslayer(BOOTP) and pkt[BOOTP].yiaddr != "0.0.0.0":
                ip = pkt[BOOTP].yiaddr
                mac = pkt[BOOTP].chaddr.hex()[:12]
                mac_fmt = ":".join(mac[i:i+2] for i in range(0, 12, 2))
                h = get(ip)
                h.mac = h.mac or mac_fmt
                if pkt.haslayer(DHCP):
                    for opt in pkt[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == "hostname":
                            h.hostname = h.hostname or opt[1].decode("utf-8", errors="replace")
        except Exception:
            pass

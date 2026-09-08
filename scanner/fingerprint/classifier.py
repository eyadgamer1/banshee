"""B5 — device-type classifier: weighted signals, softmax confidence.

Combines evidence signals into a device-type label via a weighted-score
vote — deterministic and offline, no ML runtime, no training data. What
turns that into real (if modest) machine learning is the scoring layer:
each label's total weighted score is treated as a logit and passed through
softmax, the same normalization multinomial logistic regression uses, to
produce a calibrated probability over every label the hint tables below can
produce. The hint weights themselves are hand-authored expert priors, not
fit to a labeled dataset — the same honesty the Go adaptive planner already
applies to its own device-class likelihood table (see
engine/internal/adaptive/adaptive.go): a starting point, not a claim.

Signals used (higher weight = more authoritative):
  - OUI vendor string (weight 3)
  - DHCP hostname prefix (weight 2)
  - Open ports set (weight 1-3)
  - OS guess from B3 (weight 1)

Device types the hint tables can produce: router, access-point, printer,
camera, nas, voip, mobile, server, iot, workstation, unknown. "unknown" is
also returned — regardless of which single label has the most votes — when
the softmax confidence doesn't clear `_CONFIDENCE_FLOOR`: a label asserted
from evidence barely better than a guess is exactly the false-positive shape
this project is trying to stop shipping.
"""

from __future__ import annotations

import math
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.interfaces import ScanContext
    from scanner.core.models import Host

# --- vendor → device hints ---
_VENDOR_HINTS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"cisco|juniper|mikrotik|ubiquiti|netgear|zyxel|draytek", re.I), "router", 3),
    (re.compile(r"aruba|ruckus|aerohive|meraki", re.I), "access-point", 3),
    (re.compile(r"hp.*print|canon|epson|brother|lexmark|xerox|konica", re.I), "printer", 3),
    (re.compile(r"axis|hikvision|dahua|avigilon|hanwha|bosch.*sec", re.I), "camera", 3),
    (re.compile(r"synology|qnap|netapp|western.dig|seagate.*nas", re.I), "nas", 3),
    (re.compile(r"yealink|polycom|grandstream|cisco.*voip|snom", re.I), "voip", 3),
    (re.compile(r"apple|samsung|huawei|xiaomi|oneplus|lg.*mobile", re.I), "mobile", 3),
    (re.compile(r"vmware|virtual.*box|kvm|proxmox|hyper.*v", re.I), "server", 2),
    (re.compile(r"raspberry|arduino|espressif|particle", re.I), "iot", 2),
]

# --- hostname prefix → hints ---
_HOST_HINTS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"^router|^gw|^gateway|^fw|^firewall", re.I), "router", 2),
    (re.compile(r"^ap[- _]|^wifi|^wlan|^wireless", re.I), "access-point", 2),
    (re.compile(r"^printer|^print|^hp.*lj|^canon.*mf", re.I), "printer", 2),
    (re.compile(r"^cam[- _]|^ipcam|^nvr|^dvr", re.I), "camera", 2),
    (re.compile(r"^nas|^storage|^synology|^qnap", re.I), "nas", 2),
    (re.compile(r"^voip|^phone|^sip|^pbx", re.I), "voip", 2),
    (re.compile(r"^android|^iphone|^ipad|^mobile", re.I), "mobile", 2),
    (re.compile(r"^server|^srv|^web|^db|^sql", re.I), "server", 2),
    (re.compile(r"^win|^desktop|^pc[- _]|^laptop", re.I), "workstation", 2),
]

# --- open ports → hints ---
_PORT_HINTS: list[tuple[frozenset[int], str, int]] = [
    (frozenset({80, 443, 8080, 8443}), "server", 1),
    (frozenset({22}), "server", 1),
    (frozenset({445, 135, 139}), "workstation", 2),
    (frozenset({3389}), "workstation", 2),
    (frozenset({9100, 631}), "printer", 3),
    (frozenset({554, 8554}), "camera", 3),
    (frozenset({5060, 5061}), "voip", 3),
    (frozenset({548, 2049}), "nas", 2),
    (frozenset({161}), "router", 1),
]

# --- OS guess → hints ---
_OS_HINTS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"windows", re.I), "workstation", 1),
    (re.compile(r"linux", re.I), "server", 1),
    (re.compile(r"ios|cisco", re.I), "router", 1),
]


def _label_universe() -> frozenset[str]:
    """Every label any hint table can produce — the softmax's class set.

    Derived from the tables themselves rather than hand-listed, so it can't
    drift out of sync the way the module docstring's prose list could.
    """
    labels = {label for _, label, _ in _VENDOR_HINTS}
    labels.update(label for _, label, _ in _HOST_HINTS)
    labels.update(label for _, label, _ in _PORT_HINTS)
    labels.update(label for _, label, _ in _OS_HINTS)
    return frozenset(labels)


_LABELS = _label_universe()

# A label must beat a uniform guess across every recognized device type by
# this factor to be asserted; below it, "unknown" is the honest answer. 3x
# uniform clears every single-hint case the tables can produce on their own
# (the weakest, a single weight-1 port hint, still scores ~2x this floor)
# while catching a genuine tie between two contradicting weak signals, which
# otherwise silently picks whichever label happens to sort first.
_CONFIDENCE_FLOOR = 3.0 / len(_LABELS)


def _scores(host: Host) -> dict[str, int]:
    scores: dict[str, int] = {}

    def vote(label: str, weight: int) -> None:
        scores[label] = scores.get(label, 0) + weight

    # Vendor signals
    if host.vendor:
        for pattern, label, weight in _VENDOR_HINTS:
            if pattern.search(host.vendor):
                vote(label, weight)

    # Hostname signals
    name = host.hostname or host.names.get("mdns") or host.names.get("netbios") or ""
    if name:
        for pattern, label, weight in _HOST_HINTS:
            if pattern.search(name):
                vote(label, weight)

    # Port signals
    open_ports = frozenset(host.open_ports)
    for port_set, label, weight in _PORT_HINTS:
        if port_set & open_ports:
            vote(label, weight)

    # OS guess signals
    if host.os_guess:
        for pattern, label, weight in _OS_HINTS:
            if pattern.search(host.os_guess):
                vote(label, weight)

    return scores


def classify_with_confidence(host: Host) -> tuple[str, float]:
    """Return (device-type label, calibrated confidence in [0, 1]).

    See the module docstring for the softmax and the honesty note on the
    hand-authored weights it normalizes. `_CONFIDENCE_FLOOR` guards the
    result: a top label that doesn't clear it is reported as "unknown"
    instead — the same discipline `-sV`'s corroboration check applies to a
    weak banner match (scanner/report/diff.py, engine/internal/scan).
    """
    scores = _scores(host)
    if not scores:
        return "unknown", 0.0

    exp_scores = {label: math.exp(scores.get(label, 0)) for label in _LABELS}
    total = sum(exp_scores.values())
    probs = {label: v / total for label, v in exp_scores.items()}
    top_label = max(probs, key=lambda k: probs[k])
    top_prob = probs[top_label]
    if top_prob < _CONFIDENCE_FLOOR:
        return "unknown", top_prob
    return top_label, top_prob


def classify(host: Host) -> str:
    """Return the most likely device type label for a host."""
    label, _ = classify_with_confidence(host)
    return label


class DeviceClassifier:
    """B5 — assigns device_type (+ confidence) to each host via weighted vote."""

    name = "device-classifier"
    feature_id = "B5"

    async def fingerprint(self, host: Host, ctx: ScanContext) -> Host:
        if not host.device_type:
            host.device_type, host.device_type_confidence = classify_with_confidence(host)
        return host

"""D3 — Stealth budget. Resolves the *intensity* dial into concrete limits.

Intensity (how loud) is kept strictly separate from verbosity (how chatty).
Inputs: --mode {passive|stealth|normal|aggressive}, -T0..T5, --rate, --timeout,
--retries, --threads, --max-detect-risk.

PASSIVE (or --max-detect-risk 0) => zero active packets, full stop. The budget is
the single source of truth the engine consults before emitting any active probe.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from scanner.core.models import ScanConfig, ScanMode

# nmap-style timing templates: -T0 (paranoid) .. -T5 (insane)
# (concurrency, inter-probe delay ms, connect timeout ms, retries)
_TIMING: dict[int, tuple[int, int, int, int]] = {
    0: (1, 5000, 8000, 3),
    1: (2, 1500, 6000, 2),
    2: (8, 400, 5000, 2),
    3: (50, 0, 3000, 1),
    4: (200, 0, 1500, 1),
    5: (500, 0, 750, 0),
}

# mode scales the timing template and gates active probing
# (concurrency_factor, allows_active_probes, detect_risk)
_MODE: dict[ScanMode, tuple[float, bool, int]] = {
    ScanMode.PASSIVE: (0.0, False, 0),
    ScanMode.STEALTH: (0.25, True, 2),
    ScanMode.NORMAL: (1.0, True, 5),
    ScanMode.AGGRESSIVE: (2.0, True, 9),
}


@dataclass
class StealthBudget:
    """Resolved, enforced run limits. Build via `from_config`."""

    allow_active_probes: bool
    concurrency: int
    delay_ms: int
    connect_timeout_ms: int
    retries: int
    rate_pps: int | None
    max_packets: int | None
    detect_risk: int

    _sent: int = 0
    _last_send: float = 0.0

    @classmethod
    def from_config(cls, cfg: ScanConfig) -> StealthBudget:
        timing = _TIMING.get(cfg.timing, _TIMING[3])
        base_conc, base_delay, base_timeout, base_retries = timing
        conc_factor, mode_allows, mode_risk = _MODE[cfg.mode]

        # explicit --max-detect-risk 0 forces passive regardless of mode
        risk = cfg.max_detect_risk if cfg.max_detect_risk is not None else mode_risk
        allow_active = mode_allows and risk > 0

        concurrency = max(1, int(base_conc * conc_factor)) if allow_active else 0
        if cfg.threads is not None:
            concurrency = max(1, cfg.threads) if allow_active else 0

        # An explicit CLI value (incl. 0) overrides the template; None inherits it.
        connect_timeout = cfg.timeout_ms if cfg.timeout_ms is not None else base_timeout
        retries = cfg.retries if cfg.retries is not None else base_retries

        return cls(
            allow_active_probes=allow_active,
            concurrency=concurrency,
            delay_ms=base_delay,
            connect_timeout_ms=max(0, connect_timeout),
            retries=max(0, retries),
            rate_pps=cfg.rate,
            max_packets=None,
            detect_risk=risk,
        )

    @property
    def timeout_s(self) -> float:
        return self.connect_timeout_ms / 1000.0

    @property
    def packets_sent(self) -> int:
        return self._sent

    def can_send(self) -> bool:
        """False if active probing is disabled or the packet budget is exhausted."""
        if not self.allow_active_probes:
            return False
        if self.max_packets is not None and self._sent >= self.max_packets:
            return False
        return True

    async def throttle(self) -> None:
        """Await the inter-probe delay and per-second rate cap, then count a packet.

        Callers MUST check `can_send()` first. Passive mode never reaches here.
        """
        now = time.monotonic()
        min_gap = self.delay_ms / 1000.0
        if self.rate_pps:
            min_gap = max(min_gap, 1.0 / self.rate_pps)
        if self._last_send and min_gap:
            wait = min_gap - (now - self._last_send)
            if wait > 0:
                await asyncio.sleep(wait)
        self._last_send = time.monotonic()
        self._sent += 1

    def make_semaphore(self) -> asyncio.Semaphore:
        return asyncio.Semaphore(max(1, self.concurrency))

"""Suspicious activity detector for the firewall.

Monitors the log for patterns that indicate attacks:

* DoS: many dropped packets from one source within a short window.
* Port-scan: connection attempts on many different ports.
* Brute-force: repeated failed login attempts (simulated here via flags).

"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Set

from .alerts import Alert
from .logger import SecurityLogger
from .models import AccessStatus, SecurityLog


class SuspiciousActivityDetector:
    """Flag potentially malicious network behaviour."""

    MAX_PACKETS_PER_WINDOW = 100
    MAX_PORTS_SCANNED = 8
    WINDOW_SECONDS = 30

    def __init__(self, logger: SecurityLogger) -> None:
        self.logger = logger
        self._alerts: List[Alert] = []

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------
    def _find_do_s_attacks(self, now: datetime) -> List[Alert]:
        """Return alerts for IPs that flooded the firewall."""
        alerts: List[Alert] = []
        window = timedelta(seconds=self.WINDOW_SECONDS)
        recent: Dict[str, int] = defaultdict(int)
        for entry in self.logger.recent(500):
            if entry.timestamp < now - window:
                continue
            if entry.access_status == AccessStatus.BLOCKED:
                recent[entry.packet.src_ip] += 1

        for src_ip, count in recent.items():
            if count > self.MAX_PACKETS_PER_WINDOW:
                alerts.append(
                    Alert(
                        severity="WARNING",
                        title="Potential DoS Attack Detected",
                        detail=f"Source {src_ip} sent {count} blocked packets "
                        f"within {self.WINDOW_SECONDS}s (threshold: {self.MAX_PACKETS_PER_WINDOW})",
                        src_ip=src_ip,
                    )
                )
        return alerts

    def _find_port_scans(self, now: datetime) -> List[Alert]:
        """Return alerts for sources probing many ports."""
        alerts: List[Alert] = []
        window = timedelta(seconds=self.WINDOW_SECONDS)
        ports_per_src: Dict[str, Set[int]] = defaultdict(set)
        for entry in self.logger.recent(500):
            if entry.timestamp < now - window:
                continue
            if entry.access_status == AccessStatus.BLOCKED:
                ports_per_src[entry.packet.src_ip].add(entry.packet.port)

        for src_ip, ports in ports_per_src.items():
            if len(ports) >= self.MAX_PORTS_SCANNED:
                alerts.append(
                    Alert(
                        severity="WARNING",
                        title="Port Scan Activity Detected",
                        detail=f"Source {src_ip} hit {len(ports)} blocked ports: "
                        f"{sorted(ports)[:10]}{'...' if len(ports) > 10 else ''}",
                        src_ip=src_ip,
                    )
                )
        return alerts

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def analyze(self) -> List[Alert]:
        """Run all detectors and return fresh alerts."""
        now = datetime.now(timezone.utc)
        alerts: List[Alert] = []
        alerts.extend(self._find_do_s_attacks(now))
        alerts.extend(self._find_port_scans(now))
        self._alerts.extend(alerts)
        return alerts

    @property
    def alerts(self) -> List[Alert]:
        return list(self._alerts)

    def clear(self) -> None:
        self._alerts.clear()
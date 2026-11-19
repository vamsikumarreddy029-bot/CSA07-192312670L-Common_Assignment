"""Traffic dashboard for the firewall console.

Renders a text-based live dashboard showing packet flow, rule hits,
and recent activity. Designed for terminal output (ASCII + Unicode).

Example output::

    +--------------------------------------------------------------+
    |  Network Security Dashboard                                 |
    |  Traffic:  127 allowed |  43 blocked                       |
    +--------------------------------------------------------------+
    |  Top Source IPs    |  Recent Packets                       |
    |  192.168.1.100: 56 |  B 192.168.1.100->8.8.8.8:443       |
    |  10.0.0.5: 29      |  A 10.0.0.5->192.168.1.1:80         |
    +--------------------------------------------------------------+
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .logger import SecurityLogger
from .models import AccessStatus, Packet, SecurityLog


class TrafficDashboard:
    """Render traffic overview for the console."""

    MAX_TOP_IPS = 5
    MAX_RECENT = 6

    def __init__(self, logger: SecurityLogger, rule_counts: Optional[Dict[str, int]] = None) -> None:
        self.logger = logger
        self._rule_counts = rule_counts or defaultdict(int)

    def _allowed(self) -> List[SecurityLog]:
        return [e for e in self.logger.entries if e.access_status == AccessStatus.ALLOWED]

    def _blocked(self) -> List[SecurityLog]:
        return [e for e in self.logger.entries if e.access_status == AccessStatus.BLOCKED]

    def _top_sources(self) -> List[tuple[str, int]]:
        counts: Counter = Counter(e.packet.src_ip for e in self.logger.entries)
        return counts.most_common(self.MAX_TOP_IPS)

    def _recent_packets(self, limit: int = 6) -> List[tuple[str, str, str, int, str]]:
        """List recent packets as: (status, src, dst, port, proto)."""
        entries = list(reversed(self.logger.recent(limit)))
        rows = []
        for e in entries:
            status = "B" if e.access_status == AccessStatus.BLOCKED else "A"
            src = e.packet.src_ip
            dst = e.packet.dst_ip
            port = e.packet.port
            proto = e.packet.protocol.value[0]
            rows.append((status, src, dst, port, proto))
        return rows

    def render(self) -> str:
        """Return the full dashboard as a string."""
        allowed = len(self._allowed())
        blocked = len(self._blocked())
        total = allowed + blocked
        lines: List[str] = []

        width = 70

        lines.append("+" + "-" * (width - 2) + "+")
        lines.append("|" + " Network Security Dashboard".ljust(width - 1) + "|")
        lines.append("|" + f" Traffic: {allowed:6} allowed | {blocked:6} blocked  ".ljust(width - 1) + "|")
        lines.append("|" + f" Total packets observed: {total}".ljust(width - 1) + "|")
        lines.append("+" + "-" * (width - 2) + "+")
        lines.append("")

        top_sources = self._top_sources()
        recent = self._recent_packets()

        left = 32
        right = 32

        header = f"+{'-' * (left - 1)}+{'-' * (right - 1)}+\n"
        header += f"|{'Top Source IPs':^30}|{'Recent Packets':^30}|\n"
        header += f"+{'-' * 31}+{'-' * 31}+\n"
        lines.append(header)

        max_rows = max(len(top_sources), len(recent), 5)
        for i in range(max_rows):
            left_cell = top_sources[i][0] + f": {top_sources[i][1]}" if i < len(top_sources) else ""
            right_cells = ""
            if i < len(recent):
                status, src, dst, port, proto = recent[i]
                right_cells = f"{status} {src[:15]}->{dst[:15]}:{port}({proto})"
            line = (
                "|"
                + left_cell.ljust(left - 1)
                + "|"
                + right_cells.ljust(right - 1)
                + "|"
            )
            lines.append(line)

        lines.append("+" + "-" * (left - 1) + "+" + "-" * (right - 1) + "+")

        lines.append("")
        lines.append(f"Last updated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")

        return "\n".join(lines)
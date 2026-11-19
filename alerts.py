"""Administrator notification system.

Captures alerts from suspicious-activity detection and renders them
as human-readable messages or structured output for further processing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from .models import Alert


class AlertSystem:
    """Manage and display security alerts."""

    COLOURS = {
        "INFO": "\033[94m",
        "WARNING": "\033[93m",
        "CRITICAL": "\033[91m",
    }

    def __init__(self, alerts: List[Alert] | None = None) -> None:
        self._alerts: List[Alert] = alerts or []

    def add(self, alert: Alert) -> None:
        self._alerts.append(alert)

    def extend(self, alerts: List[Alert]) -> None:
        self._alerts.extend(alerts)

    @property
    def alerts(self) -> List[Alert]:
        return list(self._alerts)

    def count(self) -> int:
        return len(self._alerts)

    def as_text(self) -> str:
        """Return a plain-text summary of all alerts."""
        lines: List[str] = []
        for alert in self._alerts:
            colour = self.COLOURS.get(alert.severity, "")
            reset = "\033[0m" if colour else ""
            lines.append(
                f"[{alert.severity:8}] {alert.title}"
                f"{reset}\n          {alert.detail}"
            )
        if not lines:
            return "No alerts."
        return "\n".join(lines)

    def recent(self, limit: int = 10) -> List[Alert]:
        return self._alerts[-limit:]
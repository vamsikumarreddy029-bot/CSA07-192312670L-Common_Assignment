"""Persistent security log for the firewall.

Every packet that reaches the engine produces one :class:`SecurityLog`
entry. The logger stores them in memory and can also append them to a
newline-delimited JSON file so the log survives across runs.
"""

from __future__ import annotations

import json
import os
from datetime import timezone
from typing import List, Optional

from .models import AccessStatus, Packet, SecurityLog


class SecurityLogger:
    """Append-only access log with in-memory and file backends."""

    def __init__(self, log_path: Optional[str] = None) -> None:
        self._log_path = log_path
        self._entries: List[SecurityLog] = []
        if log_path and os.path.exists(log_path):
            self._entries = self._load(log_path)

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------
    def append(self, entry: SecurityLog) -> None:
        """Record a single security-log entry."""
        self._entries.append(entry)
        if self._log_path:
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(self._serialize(entry)) + "\n")

    def extend(self, entries: List[SecurityLog]) -> None:
        """Record a batch of entries efficiently."""
        for entry in entries:
            self.append(entry)

    @property
    def entries(self) -> List[SecurityLog]:
        return list(self._entries)

    @property
    def log_path(self) -> Optional[str]:
        return self._log_path

    # ------------------------------------------------------------------
    # Reporting helpers
    # ------------------------------------------------------------------
    def allowed(self) -> List[SecurityLog]:
        return [e for e in self._entries if e.access_status == AccessStatus.ALLOWED]

    def blocked(self) -> List[SecurityLog]:
        return [e for e in self._entries if e.access_status == AccessStatus.BLOCKED]

    def by_source(self, src_ip: str) -> List[SecurityLog]:
        return [e for e in self._entries if e.packet.src_ip == src_ip]

    def recent(self, limit: int = 50) -> List[SecurityLog]:
        return self._entries[-limit:]

    def count(self) -> int:
        return len(self._entries)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------
    @staticmethod
    def _serialize(entry: SecurityLog) -> dict:
        return {
            "timestamp": entry.timestamp.astimezone(timezone.utc).isoformat(),
            "src_ip": entry.packet.src_ip,
            "dst_ip": entry.packet.dst_ip,
            "port": entry.packet.port,
            "protocol": entry.packet.protocol.value,
            "traffic_type": entry.packet.traffic_type.value,
            "access_status": entry.access_status.value,
            "matched_rule_id": entry.matched_rule_id,
            "reason": entry.reason,
        }

    @classmethod
    def _load(cls, path: str) -> List[SecurityLog]:
        entries: List[SecurityLog] = []
        if not os.path.exists(path):
            return entries
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    packet = Packet(
                        src_ip=data["src_ip"],
                        dst_ip=data["dst_ip"],
                        port=data["port"],
                        protocol=data["protocol"],
                        traffic_type=data["traffic_type"],
                    )
                    entries.append(
                        SecurityLog(
                            packet=packet,
                            access_status=AccessStatus(data["access_status"]),
                            matched_rule_id=data.get("matched_rule_id"),
                            reason=data.get("reason", ""),
                        )
                    )
                except (json.JSONDecodeError, KeyError, ValueError):
                    # Skip corrupt lines rather than failing the whole load.
                    continue
        return entries
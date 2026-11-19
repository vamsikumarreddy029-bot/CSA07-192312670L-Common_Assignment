"""Core data models for the firewall monitoring system.

These classes represent the entities the assignment asks for: source and
destination IP addresses, port numbers, protocols, firewall rules, traffic
types and access statuses.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Protocol(str, Enum):
    """Transport-layer protocol carried by a packet."""

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"

    @classmethod
    def from_string(cls, value: str) -> "Protocol":
        """Parse a protocol name, case-insensitively."""
        try:
            return cls(value.strip().upper())
        except KeyError as exc:  # pragma: no cover - exercised in tests
            raise ValueError(f"Unsupported protocol: {value!r}") from None


class TrafficType(str, Enum):
    """High-level classification of a packet's purpose."""

    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"


class AccessStatus(str, Enum):
    """Decision returned by the firewall for a packet."""

    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    DENIED = "DENIED"  # synonym used for explicit deny rules

    @classmethod
    def from_string(cls, value: str) -> "AccessStatus":
        """Parse an action string, accepting both short and long forms."""
        normalized = value.strip().upper()
        if normalized == "ALLOW":
            return cls.ALLOWED
        if normalized == "DENY":
            return cls.DENIED
        return cls(normalized)


def _validate_ip(value: str, label: str) -> str:
    """Validate that *value* is a usable IPv4 address."""
    try:
        ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid IPv4 address: {value!r}") from exc
    return value


def _validate_ip_cidr(value: str) -> str:
    """Validate that *value* is a usable IPv4 address or CIDR network."""
    try:
        # Try CIDR first
        ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        # Fall back to single address
        ipaddress.IPv4Address(value)
    return value


@dataclass
class FirewallRule:
    """A single packet-filtering rule.

    A rule matches a packet when every non-``None`` field agrees with the
    packet. ``None`` acts as a wildcard ("match anything"). Rules are
    evaluated in priority order (lowest ``priority`` first).

    The ``dst_port`` field allows distinguishing between destination ports
    specifically; ``port`` is a generic alias that matches either source
    or destination port depending on traffic context.
    """

    id: str
    action: AccessStatus
    description: str = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[Protocol] = None
    traffic_type: Optional[TrafficType] = None
    priority: int = 100

    def __post_init__(self) -> None:
        if self.dst_port is not None and not (1 <= self.dst_port <= 65535):
            raise ValueError("dst_port must be in range 1-65535")
        if self.port is not None and not (1 <= self.port <= 65535):
            raise ValueError("port must be in range 1-65535")
        if isinstance(self.protocol, str):
            self.protocol = Protocol.from_string(self.protocol)
        if isinstance(self.action, str):
            self.action = AccessStatus.from_string(self.action)
        if isinstance(self.traffic_type, str):
            self.traffic_type = TrafficType(self.traffic_type.upper())
        if self.src_ip is not None:
            self.src_ip = _validate_ip_cidr(self.src_ip)
        if self.dst_ip is not None:
            self.dst_ip = _validate_ip_cidr(self.dst_ip)

    def matches(self, packet: "Packet") -> bool:
        """Return ``True`` when this rule applies to *packet*."""
        if self.src_ip is not None:
            # Support CIDR matching
            import ipaddress
            if "/" in self.src_ip:
                net = ipaddress.IPv4Network(self.src_ip, strict=False)
                if ipaddress.IPv4Address(packet.src_ip) not in net:
                    return False
            elif self.src_ip != packet.src_ip:
                return False
        if self.dst_ip is not None:
            if "/" in self.dst_ip:
                import ipaddress
                net = ipaddress.IPv4Network(self.dst_ip, strict=False)
                if ipaddress.IPv4Address(packet.dst_ip) not in net:
                    return False
            elif self.dst_ip != packet.dst_ip:
                return False
        if self.port is not None and self.port != packet.port:
            return False
        if self.dst_port is not None and self.dst_port != packet.port:
            return False
        if self.protocol is not None and self.protocol != packet.protocol:
            return False
        if self.traffic_type is not None and self.traffic_type != packet.traffic_type:
            return False
        return True


@dataclass
class Packet:
    """A single network packet observed at the firewall."""

    src_ip: str
    dst_ip: str
    port: int
    protocol: Protocol
    traffic_type: TrafficType = TrafficType.INBOUND
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    payload_size: int = 0

    def __post_init__(self) -> None:
        self.src_ip = _validate_ip(self.src_ip, "src_ip")
        self.dst_ip = _validate_ip(self.dst_ip, "dst_ip")
        if not (1 <= self.port <= 65535):
            raise ValueError("port must be in range 1-65535")
        if isinstance(self.protocol, str):
            self.protocol = Protocol.from_string(self.protocol)
        if isinstance(self.traffic_type, str):
            self.traffic_type = TrafficType(self.traffic_type.upper())
        if self.payload_size < 0:
            raise ValueError("payload_size must be non-negative")

    @property
    def is_inbound(self) -> bool:
        return self.traffic_type == TrafficType.INBOUND


@dataclass
class SecurityLog:
    """One entry written to the firewall's security log."""

    packet: Packet
    access_status: AccessStatus
    matched_rule_id: Optional[str]
    reason: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Alert:
    """A security alert raised by the monitoring system."""

    severity: str  # "INFO" | "WARNING" | "CRITICAL"
    title: str
    detail: str
    src_ip: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
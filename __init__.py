"""Network Security and Firewall Monitoring System.

A demonstration of packet filtering and access control for the Computer
Networks Common Assignment (CSA0712).

The package exposes the public building blocks of a firewall monitoring
system:

* :class:`Packet` / :class:`FirewallRule` -- the network entities.
* :class:`RuleEngine` -- evaluates packets against an ordered rule set.
* :class:`SecurityLogger` -- persistent access log.
* :class:`SuspiciousActivityDetector` -- flags DoS / brute-force patterns.
* :class:`AlertSystem` -- notifies administrators of security events.
* :class:`TrafficDashboard` -- renders a live traffic overview.
"""

from .models import (
    AccessStatus,
    Alert,
    FirewallRule,
    Packet,
    Protocol,
    SecurityLog,
    TrafficType,
)
from .rule_engine import RuleEngine
from .logger import SecurityLogger
from .detector import SuspiciousActivityDetector
from .alerts import AlertSystem
from .dashboard import TrafficDashboard

__all__ = [
    "AccessStatus",
    "Alert",
    "FirewallRule",
    "Packet",
    "Protocol",
    "SecurityLog",
    "TrafficType",
    "RuleEngine",
    "SecurityLogger",
    "SuspiciousActivityDetector",
    "AlertSystem",
    "TrafficDashboard",
]

__version__ = "1.0.0"
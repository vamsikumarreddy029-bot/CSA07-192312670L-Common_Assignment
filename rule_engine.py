"""Packet-filtering rule engine.

The engine evaluates packets against an ordered list of firewall rules
using *first-match-wins* semantics. If no rule matches, the packet is
dropped by the implicit deny-all rule -- the fundamental security posture
of a stateless packet filter.
"""

from __future__ import annotations

from typing import Iterable, List, Optional

from .models import AccessStatus, FirewallRule, Packet, SecurityLog


class RuleEngine:
    """Classify packets against a firewall rule set.

    Rules are sorted by ``priority`` (ascending) before evaluation, so a
    rule with ``priority=1`` always wins over one with ``priority=100``.
    """

    def __init__(self, rules: Iterable[FirewallRule] | None = None) -> None:
        self._rules: List[FirewallRule] = sorted(
            rules or [], key=lambda r: r.priority
        )

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------
    @property
    def rules(self) -> List[FirewallRule]:
        """Return the current rule set, sorted by priority."""
        return list(self._rules)

    def add_rule(self, rule: FirewallRule) -> None:
        """Insert *rule* and keep the set sorted by priority."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by id. Returns ``True`` if it existed."""
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.id != rule_id]
        return len(self._rules) != before

    # ------------------------------------------------------------------
    # Packet evaluation
    # ------------------------------------------------------------------
    def evaluate(self, packet: Packet) -> SecurityLog:
        """Return the :class:`SecurityLog` decision for *packet*.

        The first matching rule decides the outcome. Packets that match
        nothing fall through to the implicit deny-all rule.
        """
        for rule in self._rules:
            if rule.matches(packet):
                return SecurityLog(
                    packet=packet,
                    access_status=rule.action,
                    matched_rule_id=rule.id,
                    reason=f"matched rule {rule.id}: {rule.description or '(no description)'}",
                )

        return SecurityLog(
            packet=packet,
            access_status=AccessStatus.BLOCKED,
            matched_rule_id=None,
            reason="no rule matched; implicit deny-all applied",
        )

    def evaluate_many(self, packets: Iterable[Packet]) -> list[SecurityLog]:
        """Evaluate a batch of packets and return the log entries."""
        return [self.evaluate(p) for p in packets]
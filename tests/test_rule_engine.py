"""Unit tests for the rule engine module."""

import pytest

from ..models import AccessStatus, FirewallRule, Packet, Protocol, TrafficType
from ..rule_engine import RuleEngine


@pytest.fixture
def rules():
    return [
        FirewallRule(id="allow-local", action=AccessStatus.ALLOWED, src_ip="127.0.0.1", priority=1),
        FirewallRule(id="deny-tcpsh", action=AccessStatus.BLOCKED, port=22, protocol=Protocol.TCP, priority=5),
        FirewallRule(id="allow-web", action=AccessStatus.ALLOWED, dst_ip="10.0.0.1", port=80, priority=10),
    ]


@pytest.fixture
def engine(rules):
    return RuleEngine(rules=rules)


class TestRuleEngine:
    def test_empty_engine_allows_all_blocked(self, engine):
        pkt = Packet("8.8.8.8", "1.1.1.1", 1234, Protocol.UDP)
        log = engine.evaluate(pkt)
        assert log.access_status == AccessStatus.BLOCKED
        assert log.matched_rule_id is None

    def test_evaluate_allows_localhost(self, engine):
        pkt = Packet("127.0.0.1", "10.0.0.1", 80, Protocol.TCP)
        log = engine.evaluate(pkt)
        assert log.access_status == AccessStatus.ALLOWED
        assert log.matched_rule_id == "allow-local"

    def test_evaluate_blocks_rdp(self, engine):
        pkt = Packet("192.168.1.1", "10.0.0.1", 22, Protocol.TCP)
        log = engine.evaluate(pkt)
        assert log.access_status == AccessStatus.BLOCKED
        assert log.matched_rule_id == "deny-tcpsh"

    def test_evaluate_allows_web(self, engine):
        pkt = Packet("192.168.1.1", "10.0.0.1", 80, Protocol.TCP)
        log = engine.evaluate(pkt)
        assert log.access_status == AccessStatus.ALLOWED
        assert log.matched_rule_id == "allow-web"

    def test_first_match_wins(self):
        rules = [
            FirewallRule(id="block-all", action=AccessStatus.BLOCKED, priority=10),
            FirewallRule(id="allow-specific", action=AccessStatus.ALLOWED, dst_ip="10.0.0.5", priority=5),
        ]
        engine = RuleEngine(rules=rules)
        pkt = Packet("192.168.1.1", "10.0.0.5", 80, Protocol.TCP)
        log = engine.evaluate(pkt)
        assert log.matched_rule_id == "allow-specific"

    def test_priority_ordering(self):
        rules = [
            FirewallRule(id="low", action=AccessStatus.BLOCKED, priority=100),
            FirewallRule(id="high", action=AccessStatus.ALLOWED, priority=1),
        ]
        engine = RuleEngine(rules=rules)
        assert engine.rules[0].id == "high"

    def test_add_rule(self, engine):
        new_rule = FirewallRule(id="new", action=AccessStatus.ALLOWED, priority=2)
        engine.add_rule(new_rule)
        assert len(engine.rules) == 4
        assert engine.rules[1].id == "new"

    def test_remove_rule(self, engine):
        assert engine.remove_rule("allow-local") is True
        assert len(engine.rules) == 2
        assert engine.remove_rule("nonexistent") is False

    def test_evaluate_many(self, engine):
        pkts = [
            Packet("127.0.0.1", "10.0.0.1", 80, Protocol.TCP),
            Packet("10.0.0.5", "10.0.0.1", 22, Protocol.TCP),
        ]
        logs = engine.evaluate_many(pkts)
        assert len(logs) == 2
        assert logs[0].access_status == AccessStatus.ALLOWED
        assert logs[1].access_status == AccessStatus.BLOCKED
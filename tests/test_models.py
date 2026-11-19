"""Unit tests for the models module."""

import pytest

from ..models import (
    AccessStatus,
    Alert,
    FirewallRule,
    Packet,
    Protocol,
    TrafficType,
)


class TestProtocol:
    def test_from_string_uppercase(self):
        assert Protocol.from_string("TCP") == Protocol.TCP

    def test_from_string_lowercase(self):
        assert Protocol.from_string("tcp") == Protocol.TCP

    def test_from_string_invalid(self):
        with pytest.raises(ValueError):
            Protocol.from_string("SCTP")


class TestTrafficType:
    def test_values(self):
        assert TrafficType.INBOUND.value == "INBOUND"
        assert TrafficType.OUTBOUND.value == "OUTBOUND"


class TestAccessStatus:
    def test_values(self):
        assert AccessStatus.ALLOWED.value == "ALLOWED"
        assert AccessStatus.BLOCKED.value == "BLOCKED"
        assert AccessStatus.DENIED.value == "DENIED"


class TestPacket:
    def test_create_packet(self):
        pkt = Packet("192.168.1.1", "10.0.0.1", 443, Protocol.TCP)
        assert pkt.src_ip == "192.168.1.1"
        assert pkt.dst_ip == "10.0.0.1"
        assert pkt.port == 443
        assert pkt.protocol == Protocol.TCP
        assert pkt.traffic_type == TrafficType.INBOUND

    def test_packet_with_string_protocol(self):
        pkt = Packet("192.168.1.1", "10.0.0.1", 443, "UDP")
        assert pkt.protocol == Protocol.UDP

    def test_packet_invalid_ip(self):
        with pytest.raises(ValueError):
            Packet("not-an-ip", "10.0.0.1", 443, Protocol.TCP)

    def test_packet_invalid_port(self):
        with pytest.raises(ValueError):
            Packet("192.168.1.1", "10.0.0.1", 70000, Protocol.TCP)

    def test_is_inbound(self):
        pkt_in = Packet("192.168.1.1", "10.0.0.1", 80, Protocol.TCP, TrafficType.INBOUND)
        pkt_out = Packet("192.168.1.1", "10.0.0.1", 443, Protocol.TCP, TrafficType.OUTBOUND)
        assert pkt_in.is_inbound is True
        assert pkt_out.is_inbound is False


class TestFirewallRule:
    def test_create_rule(self):
        rule = FirewallRule(id="test", action=AccessStatus.ALLOWED)
        assert rule.id == "test"
        assert rule.action == AccessStatus.ALLOWED
        assert rule.description == ""

    def test_rule_with_all_fields(self):
        rule = FirewallRule(
            id="ssh",
            action=AccessStatus.BLOCKED,
            description="Block SSH",
            src_ip="10.0.0.1",
            dst_ip="192.168.1.1",
            port=22,
            protocol=Protocol.TCP,
            priority=5,
        )
        assert rule.src_ip == "10.0.0.1"
        assert rule.dst_ip == "192.168.1.1"
        assert rule.port == 22
        assert rule.protocol == Protocol.TCP

    def test_rule_matches_exact(self):
        rule = FirewallRule(
            id="test",
            action=AccessStatus.ALLOWED,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            port=443,
            protocol=Protocol.TCP,
        )
        pkt = Packet("192.168.1.1", "10.0.0.1", 443, Protocol.TCP)
        assert rule.matches(pkt) is True

    def test_rule_matches_partial(self):
        rule = FirewallRule(
            id="allow-all-tcp",
            action=AccessStatus.ALLOWED,
            protocol=Protocol.TCP,
        )
        pkt1 = Packet("192.168.1.1", "10.0.0.1", 80, Protocol.TCP)
        pkt2 = Packet("10.0.0.1", "192.168.1.1", 443, Protocol.UDP)
        assert rule.matches(pkt1) is True
        assert rule.matches(pkt2) is False

    def test_rule_matches_wildcard(self):
        rule = FirewallRule(id="deny-all", action=AccessStatus.BLOCKED)
        pkt = Packet("192.168.1.1", "10.0.0.1", 80, Protocol.TCP)
        assert rule.matches(pkt) is True

    def test_rule_matches_cidr(self):
        rule = FirewallRule(id="local", action=AccessStatus.ALLOWED, src_ip="192.168.1.0/24")
        pkt1 = Packet("192.168.1.100", "10.0.0.1", 80, Protocol.TCP)
        pkt2 = Packet("192.168.2.1", "10.0.0.1", 80, Protocol.TCP)
        assert rule.matches(pkt1) is True
        assert rule.matches(pkt2) is False

    def test_rule_invalid_port(self):
        with pytest.raises(ValueError):
            FirewallRule(id="bad", action=AccessStatus.ALLOWED, port=0)

    def test_rule_string_action_protocol(self):
        rule = FirewallRule(id="test", action="ALLOWED", protocol="TCP")
        assert rule.action == AccessStatus.ALLOWED
        assert rule.protocol == Protocol.TCP

    def test_rule_matches_cidr(self):
        rule = FirewallRule(id="local", action=AccessStatus.ALLOWED, src_ip="192.168.1.0/24")
        pkt1 = Packet("192.168.1.100", "10.0.0.1", 80, Protocol.TCP)
        pkt2 = Packet("192.168.2.1", "10.0.0.1", 80, Protocol.TCP)
        assert rule.matches(pkt1) is True
        assert rule.matches(pkt2) is False

    def test_rule_invalid_port(self):
        with pytest.raises(ValueError):
            FirewallRule(id="bad", action=AccessStatus.ALLOWED, port=0)

    def test_rule_string_action_protocol(self):
        rule = FirewallRule(id="test", action="ALLOW", protocol="TCP")
        assert rule.action == AccessStatus.ALLOWED
        assert rule.protocol == Protocol.TCP


class TestAlert:
    def test_create_alert(self):
        from datetime import datetime, timezone
        alert = Alert(severity="WARNING", title="Test", detail="Details", src_ip="10.0.0.1")
        assert alert.severity == "WARNING"
        assert alert.title == "Test"
        assert alert.src_ip == "10.0.0.1"
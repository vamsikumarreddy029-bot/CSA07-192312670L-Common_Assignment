"""Unit tests for the security logger module."""

import tempfile
from datetime import datetime, timezone

import pytest

from ..logger import SecurityLogger
from ..models import AccessStatus, FirewallRule, Packet, Protocol, SecurityLog, TrafficType


class TestSecurityLogger:
    def test_empty_logger(self):
        logger = SecurityLogger()
        assert logger.count() == 0
        assert logger.entries == []

    def test_append_single_entry(self):
        logger = SecurityLogger()
        pkt = Packet("192.168.1.1", "10.0.0.1", 443, Protocol.TCP)
        log = SecurityLog(packet=pkt, access_status=AccessStatus.ALLOWED, matched_rule_id="r1")
        logger.append(log)
        assert logger.count() == 1

    def test_extend_batch(self):
        logger = SecurityLogger()
        pkt = Packet("192.168.1.1", "10.0.0.1", 443, Protocol.TCP)
        logs = [
            SecurityLog(packet=pkt, access_status=AccessStatus.ALLOWED, matched_rule_id="r1"),
            SecurityLog(packet=pkt, access_status=AccessStatus.BLOCKED, matched_rule_id="r2"),
        ]
        logger.extend(logs)
        assert logger.count() == 2

    def test_allowed_and_blocked(self):
        logger = SecurityLogger()
        pkt = Packet("192.168.1.1", "10.0.0.1", 443, Protocol.TCP)
        logger.append(SecurityLog(packet=pkt, access_status=AccessStatus.ALLOWED, matched_rule_id="r1"))
        logger.append(SecurityLog(packet=pkt, access_status=AccessStatus.BLOCKED, matched_rule_id="r2"))
        assert len(logger.allowed()) == 1
        assert len(logger.blocked()) == 1

    def test_filter_by_source(self):
        logger = SecurityLogger()
        pkt1 = Packet("192.168.1.1", "10.0.0.1", 80, Protocol.TCP)
        pkt2 = Packet("192.168.1.2", "10.0.0.1", 443, Protocol.TCP)
        logger.append(SecurityLog(packet=pkt1, access_status=AccessStatus.ALLOWED, matched_rule_id="r1"))
        logger.append(SecurityLog(packet=pkt2, access_status=AccessStatus.BLOCKED, matched_rule_id="r2"))
        assert len(logger.by_source("192.168.1.1")) == 1
        assert len(logger.by_source("192.168.1.3")) == 0

    def test_recent(self):
        logger = SecurityLogger()
        pkt = Packet("192.168.1.1", "10.0.0.1", 80, Protocol.TCP)
        for i in range(10):
            logger.append(SecurityLog(packet=pkt, access_status=AccessStatus.ALLOWED, matched_rule_id="r1"))
        recent = logger.recent(3)
        assert len(recent) == 3

    def test_file_persistence(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            path = f.name
        try:
            logger = SecurityLogger(log_path=path)
            pkt = Packet("192.168.1.1", "10.0.0.1", 443, Protocol.TCP)
            log = SecurityLog(packet=pkt, access_status=AccessStatus.ALLOWED, matched_rule_id="r1")
            logger.append(log)
            assert logger.count() == 1

            logger2 = SecurityLogger(log_path=path)
            assert logger2.count() == 1
        finally:
            import os
            os.unlink(path)
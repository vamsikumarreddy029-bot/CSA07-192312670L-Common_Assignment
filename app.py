#!/usr/bin/env python3
"""Command-line interface for the Network Security and Firewall Monitoring System.

Usage:
    python -m network_firewall_monitor run [--file CONFIG.json]
    python -m network_firewall_monitor simulate [--count N]

The `run` command loads rules and enters an interactive demo where simulated
traffic is processed and the dashboard is rendered.

The `simulate` command runs a batch simulation with random traffic and attack
patterns, then prints the final report.

Example:
    python -m network_firewall_monitor simulate --count 200
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timezone
from typing import List

from .alerts import AlertSystem
from .detector import SuspiciousActivityDetector
from .logger import SecurityLogger
from .models import (
    AccessStatus,
    Alert,
    FirewallRule,
    Packet,
    Protocol,
    TrafficType,
)
from .rule_engine import RuleEngine

# ----------------------------------------------------------------------
# Default firewall rule set (implicit deny-all at the end)
# ----------------------------------------------------------------------
DEFAULT_RULES: List[FirewallRule] = [
    FirewallRule(
        id="allow-localhost",
        action=AccessStatus.ALLOWED,
        description="Allow all loopback traffic",
        src_ip="127.0.0.1",
        priority=1,
    ),
    FirewallRule(
        id="allow-established-egress",
        action=AccessStatus.ALLOWED,
        description="Allow established outbound connections",
        traffic_type=TrafficType.OUTBOUND,
        priority=10,
    ),
    FirewallRule(
        id="allow-ssh-ingress",
        action=AccessStatus.ALLOWED,
        description="Allow SSH from management subnet",
        src_ip="192.168.1.0/24",
        port=22,
        protocol=Protocol.TCP,
        priority=5,
    ),
    FirewallRule(
        id="block-known-bad-ips",
        action=AccessStatus.BLOCKED,
        description="Block traffic from known malicious IPs",
        src_ip="10.0.0.99",
        priority=2,
    ),
    FirewallRule(
        id="deny-rdp-public",
        action=AccessStatus.BLOCKED,
        description="Block RDP access",
        port=3389,
        protocol=Protocol.TCP,
        priority=20,
    ),
    FirewallRule(
        id="deny-suspicious-ports",
        action=AccessStatus.BLOCKED,
        description="Block well-known attack ports",
        port=135,
        protocol=Protocol.TCP,
        priority=30,
    ),
    FirewallRule(
        id="deny-broad-ingress",
        action=AccessStatus.BLOCKED,
        description="Deny all other inbound traffic",
        traffic_type=TrafficType.INBOUND,
        priority=100,
    ),
]


def load_rules(path: str) -> List[FirewallRule]:
    """Load rules from a JSON file.

    Expected format::

        [
            {"id": "rule-1", "action": "ALLOW", "src_ip": "192.168.1.0/24", "port": 80, ...},
            ...
        ]
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    rules: List[FirewallRule] = []
    for item in data:
        rule = FirewallRule(
            id=item["id"],
            action=item["action"],
            description=item.get("description", ""),
            src_ip=item.get("src_ip"),
            dst_ip=item.get("dst_ip"),
            port=item.get("port"),
            dst_port=item.get("dst_port"),
            protocol=Protocol.from_string(item["protocol"]) if item.get("protocol") else None,
            traffic_type=TrafficType(item["traffic_type"]) if item.get("traffic_type") else None,
            priority=item.get("priority", 100),
        )
        rules.append(rule)
    return rules


# ----------------------------------------------------------------------
# Traffic simulator
# ----------------------------------------------------------------------
INTERNAL_NET = ["192.168.1." + str(i) for i in range(1, 254)]
EXTERNAL_NET = ["10.0.0." + str(i) for i in range(1, 254)]


def random_packet(attacking: bool = False) -> Packet:
    """Generate a random packet. When *attacking* is True, bias towards
    blocked/denied destinations and DoS patterns."""
    proto = random.choice([Protocol.TCP, Protocol.UDP])
    port = random.randint(1024, 65535)

    if attacking:
        src = random.choice(EXTERNAL_NET)
        dst = random.choice(INTERNAL_NET)
        port = random.choice([22, 80, 443, 3389, 5432])
        traffic_type = TrafficType.INBOUND
    else:
        src = random.choice(INTERNAL_NET)
        dst = "8.8.8.8"
        traffic_type = TrafficType.OUTBOUND

    # Sometimes use ICMP for DoS demonstration
    if attacking and random.random() < 0.2:
        proto = Protocol.UDP
        port = 53

    return Packet(
        src_ip=src,
        dst_ip=dst,
        port=port,
        protocol=proto,
        traffic_type=traffic_type,
    )


def simulate(count: int = 100, attacks: bool = True) -> None:
    """Run a batch traffic simulation.

    Simulates normal traffic plus a few attack patterns:
    - DoS flood on SSH port
    - Port scan across 10 ports
    - Traffic from a blocked IP (10.0.0.99)
    """
    logger = SecurityLogger()
    engine = RuleEngine(rules=DEFAULT_RULES.copy())
    detector = SuspiciousActivityDetector(logger)
    alerts = AlertSystem()

    attack_ips: set = set()
    blocked_packets: list = []

    for _ in range(count):
        attack = attacks and random.random() < 0.08
        pkt = random_packet(attacking=attack)
        if attack:
            attack_ips.add(pkt.src_ip)

        log = engine.evaluate(pkt)
        logger.append(log)
        if log.access_status == AccessStatus.BLOCKED:
            blocked_packets.append(pkt)

    # Run detection
    new_alerts = detector.analyze()
    alerts.extend(new_alerts)

    # Summary report
    print("=" * 60)
    print("SIMULATION REPORT")
    print("=" * 60)
    print(f"Packets processed: {logger.count()}")
    print(f"  Allowed:  {len(logger.allowed())}")
    print(f"  Blocked:  {len(logger.blocked())}")
    print(f"Alerts generated: {len(alerts.alerts)}")

    if alerts.alerts:
        print("\nAlerts:")
        for a in alerts.alerts:
            print(f"  [{a.severity}] {a.title}: {a.detail[:60]}...")

    report_path = "simulation_report.json"
    with open(report_path, "w") as fh:
        json.dump(
            {
                "summary": {
                    "total_packets": logger.count(),
                    "allowed": len(logger.allowed()),
                    "blocked": len(logger.blocked()),
                    "alerts": len(alerts.alerts),
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            fh,
            indent=2,
        )
    print(f"\nReport saved to: {report_path}")


# ----------------------------------------------------------------------
# Interactive demo runner
# ----------------------------------------------------------------------
def run_demo(steps: int = 8) -> None:
    """Run an interactive demo showing packet processing and dashboard."""
    from .dashboard import TrafficDashboard

    logger = SecurityLogger()
    engine = RuleEngine(rules=DEFAULT_RULES.copy())
    detector = SuspiciousActivityDetector(logger)
    alert_system = AlertSystem()

    rule_counter: dict[str, int] = {}

    print("\n" + "=" * 60)
    print("NETWORK SECURITY & FIREWALL MONITORING SYSTEM - DEMO")
    print("=" * 60)
    print("Processing simulated packets...\n")

    for i in range(steps):
        attacking = (i % 3 == 0) or (i % 7 == 0)
        pkt = random_packet(attacking=attacking)

        log = engine.evaluate(pkt)
        logger.append(log)

        rid = log.matched_rule_id
        if rid:
            rule_counter[rid] = rule_counter.get(rid, 0) + 1

        traffic = "IN" if pkt.is_inbound else "OUT"
        status = log.access_status.value
        print(f"[{i+1}/{steps}] {traffic} packet: {pkt.src_ip}->{pkt.dst_ip}:{pkt.port} ({pkt.protocol.value})")
        print(f"        Result: {status} | Rule: {rid or 'IMPLICIT-DENY'}")
        if log.reason:
            print(f"        Reason: {log.reason[:50]}...")

        alerts = detector.analyze()
        if alerts:
            for a in alerts:
                alert_system.add(a)
                print(f"        ** ALERT ** [{a.severity}] {a.title}")
        print()

    dashboard = TrafficDashboard(logger, rule_counter)
    print(dashboard.render())

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total packets: {logger.count()}")
    print(f"Allowed:       {len(logger.allowed())}")
    print(f"Blocked:       {len(logger.blocked())}")
    print(f"Alerts:        {alert_system.count()}")
    print(f"Rules hit:     {rule_counter}")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="firewall",
        description="Network Security and Firewall Monitoring System",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_parser = sub.add_parser("run", help="Interactive demo")
    run_parser.add_argument("-n", "--steps", type=int, default=8, help="Number of packets to process")

    sim_parser = sub.add_parser("simulate", help="Batch traffic simulation")
    sim_parser.add_argument("--count", type=int, default=100, help="Total packets to simulate")
    sim_parser.add_argument("--attacks", action="store_true", default=True, help="Include attack patterns")

    args = parser.parse_args(argv)

    if args.cmd == "run":
        run_demo(steps=args.steps)
    elif args.cmd == "simulate":
        simulate(count=args.count, attacks=args.attacks)

    return 0


if __name__ == "__main__":
    sys.exit(main())
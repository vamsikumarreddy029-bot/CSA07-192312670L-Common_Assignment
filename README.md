# Network Security & Firewall Monitoring System

Computer Networks Common Assignment (CSA0712) — 100 marks.

A Python-based demonstration of packet filtering and access control for a network firewall. The system simulates incoming/outgoing network traffic, evaluates it against configurable firewall rules, classifies each packet as **Allowed** or **Blocked**, maintains a persistent security log, detects suspicious activity (DoS flooding, port scanning), raises alerts to administrators, and renders a live traffic dashboard.

## Features

* **Packet filtering** — firewall rules match on source/destination IP, port, protocol (TCP/UDP/ICMP), and traffic type (inbound/outbound).
* **First-match-wins semantics** — rules are evaluated in priority order; the first matching rule decides the outcome.
* **Implicit deny-all** — any packet that matches no rule is dropped by default.
* **CIDR support** — rules can match whole subnets (e.g. `192.168.1.0/24`).
* **Security logging** — every decision is recorded as a `SecurityLog` entry, persisted to a newline-delimited JSON file.
* **Suspicious activity detection** — flags DoS floods (>100 blocked packets/30s from one IP) and port scans (>8 distinct blocked ports).
* **Alert system** — severity-based alerts (INFO / WARNING / CRITICAL) raised to administrators.
* **Traffic dashboard** — terminal-based live overview showing allowed/blocked counts, top source IPs, and recent packets.
* **Traffic simulator** — generates normal traffic plus attack patterns (DoS floods, port scans, blocked-IP traffic) for demonstration.
* **Unit tests** — 35 tests covering models, rule engine, and logger (all passing).

## Project Structure

```
network_firewall_monitor/
├── __init__.py        # Public API exports
├── __main__.py        # Entry point for `python -m network_firewall_monitor`
├── app.py             # CLI: `run` (interactive demo) and `simulate` (batch)
├── models.py          # Packet, FirewallRule, SecurityLog, Alert, enums
├── rule_engine.py     # First-match-wins packet filter
├── logger.py          # Persistent security log (in-memory + JSONL file)
├── detector.py        # Suspicious activity detection (DoS, port scan)
├── alerts.py          # Alert management
├── dashboard.py       # Terminal traffic dashboard
├── requirements.txt   # Python dependencies
├── README.md          # This file
└── tests/
    ├── test_models.py
    ├── test_rule_engine.py
    └── test_logger.py
```

## Installation

```bash
cd network_firewall_monitor
python -m pip install -r requirements.txt
```

Python 3.10+ required. No external libraries beyond `pytest` (for tests).

## Usage

Run the interactive demo (processes simulated packets step by step):

```bash
python -m network_firewall_monitor run --steps 10
```

Run a batch traffic simulation with attack patterns:

```bash
python -m network_firewall_monitor simulate --count 200 --attacks
```

Load custom rules from a JSON configuration file:

```bash
python -m network_firewall_monitor run --file rules.json
```

## Example Output

```
============================================================
NETWORK SECURITY & FIREWALL MONITORING SYSTEM - DEMO
============================================================
Processing simulated packets...

[1/10] IN packet: 10.0.0.61->192.168.1.187:443 (TCP)
        Result: BLOCKED | Rule: deny-broad-ingress
[2/10] OUT packet: 192.168.1.232->8.8.8.8:26291 (TCP)
        Result: ALLOWED | Rule: allow-established-egress
...
+--------------------------------------------------------------+
| Network Security Dashboard                                  |
| Traffic:       5 allowed |       5 blocked                   |
| Total packets observed: 10                                  |
+--------------------------------------------------------------+
...
SUMMARY
------------------------------------------------------------
Total packets: 10
Allowed:        5
Blocked:        5
Alerts:         0
```

## Rule Format (JSON)

Custom rule files must be a JSON array of rule objects:

```json
[
  {
    "id": "allow-localhost",
    "action": "ALLOW",
    "description": "Allow loopback traffic",
    "src_ip": "127.0.0.1",
    "priority": 1
  },
  {
    "id": "block-rdp",
    "action": "BLOCK",
    "description": "Block RDP",
    "port": 3389,
    "protocol": "TCP",
    "priority": 20
  },
  {
    "id": "allow-web-egress",
    "action": "ALLOW",
    "description": "Allow outbound HTTPS",
    "traffic_type": "OUTBOUND",
    "port": 443,
    "priority": 15
  }
]
```

Accepted fields: `id`, `action` ("ALLOW"/"BLOCK"/"DENY"), `description`, `src_ip`, `dst_ip`, `port`, `dst_port`, `protocol` ("TCP"/"UDP"/"ICMP"), `traffic_type` ("INBOUND"/"OUTBOUND"), `priority`.

## License

Educational assignment for Computer Networks coursework.
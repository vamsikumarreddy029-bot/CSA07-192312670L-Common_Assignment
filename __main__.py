#!/usr/bin/env python3
"""Entry point for ``python -m network_firewall_monitor``."""

from .app import main

if __name__ == "__main__":
    exit(main())
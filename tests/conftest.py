"""Shared fixtures for the test suite.

Only the standard library is used. No test touches the real Windows Firewall:
every command is injected through ``inspection_runner`` / ``firewall_runner``
and every state-changing action uses a fake elevation adapter.
"""

import sys
from pathlib import Path

# Make ``tests/defense_support.py`` importable regardless of pytest's import
# mode. The tests directory is not a package.
sys.path.insert(0, str(Path(__file__).resolve().parent))

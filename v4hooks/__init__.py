"""Uniswap v4 hook security scanner.

Deterministic detectors decide findings (see ``detectors/``); an optional model
only explains them (``explain.py``). See README.md in this directory.
"""

__version__ = "0.1.0"

from .model import HookFinding
from .scanner import ScanResult, scan_project, scan_units

__all__ = ["__version__", "HookFinding", "ScanResult", "scan_project", "scan_units"]

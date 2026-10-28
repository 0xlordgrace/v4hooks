from .base import Detector, Hook, find_hooks
from .caller_check import MissingCallerCheck
from .permission_bits import PermissionBitMismatch
from .poolkey_validation import UnvalidatedPoolKey

ALL_DETECTORS: list[Detector] = [MissingCallerCheck(), UnvalidatedPoolKey(), PermissionBitMismatch()]
DETECTORS_BY_ID = {d.id: d for d in ALL_DETECTORS}

__all__ = ["ALL_DETECTORS", "DETECTORS_BY_ID", "Detector", "Hook", "find_hooks"]

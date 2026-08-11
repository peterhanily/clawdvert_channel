"""Immutable filesystem views and managed snapshot primitives for Code Artifacts."""

from .core import (
    DEFAULT_LIMITS,
    FORMAT,
    FORMAT_VERSION,
    Snapshot,
    SnapshotEntry,
    SnapshotError,
    SnapshotLimits,
    decode_snapshot,
    encode_snapshot,
    snapshot_directory,
    validate_relative_path,
)

__all__ = [
    "DEFAULT_LIMITS",
    "FORMAT",
    "FORMAT_VERSION",
    "Snapshot",
    "SnapshotEntry",
    "SnapshotError",
    "SnapshotLimits",
    "decode_snapshot",
    "encode_snapshot",
    "snapshot_directory",
    "validate_relative_path",
]

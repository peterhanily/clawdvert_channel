"""Read-only, exact-version bridge for Claude artifacts."""

from .client import BridgeClient
from .models import (
    Artifact,
    ArtifactRef,
    ArtifactVersion,
    AuthStatus,
    FetchedArtifact,
    Representation,
)

__version__ = "0.1.0"

__all__ = [
    "Artifact",
    "ArtifactRef",
    "ArtifactVersion",
    "AuthStatus",
    "BridgeClient",
    "FetchedArtifact",
    "Representation",
]

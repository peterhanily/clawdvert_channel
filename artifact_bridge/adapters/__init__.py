"""Adapter interface for read-only artifact providers."""

from __future__ import annotations

from typing import List, Optional, Protocol

from ..models import Artifact, ArtifactRef, ArtifactVersion, AuthStatus, FetchedArtifact


class ArtifactAdapter(Protocol):
    """Small provider contract consumed by :class:`BridgeClient`.

    Implementations must make only read requests and ``fetch`` must honor the
    supplied version exactly.  Returned metadata must not contain credentials.
    """

    name: str

    def auth_status(self) -> AuthStatus:
        ...

    def list_artifacts(self, limit: Optional[int] = None) -> List[Artifact]:
        ...

    def inspect(self, ref: ArtifactRef) -> Artifact:
        ...

    def versions(self, ref: ArtifactRef) -> List[ArtifactVersion]:
        ...

    def fetch(self, ref: ArtifactRef, version: str) -> FetchedArtifact:
        ...


from .owner_frame import OwnerFrameAdapter
from .compliance import AnthropicComplianceAdapter, ComplianceAdapter

__all__ = [
    "AnthropicComplianceAdapter",
    "ArtifactAdapter",
    "ComplianceAdapter",
    "OwnerFrameAdapter",
]

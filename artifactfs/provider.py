"""Read-only Code Artifact views suitable for an immutable ArtifactFS mount.

The owner-frame adapter can retrieve an exact *served* representation, which
may include provider runtime. It also has a measured anonymous fallback for a
public Artifact; ``provider='owner'`` identifies the adapter, not proof of
ownership. This module preserves the representation distinction deliberately:
the mounted file is named ``served.html`` and is never presented as authored
source.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional

from artifact_bridge.adapters.owner_frame import OwnerFrameAdapter
from artifact_bridge.client import BridgeClient
from artifact_bridge.errors import IntegrityError, ResponseTooLargeError
from artifact_bridge.models import FetchedArtifact, Representation, safe_json_value


MAX_SERVED_BYTES = 16 * 1024 * 1024
MAX_METADATA_BYTES = 256 * 1024
_ROOT = "."
_CONTROL = ".artifactfs"
_METADATA = ".artifactfs/metadata.json"
_SERVED = "served.html"


@dataclass(frozen=True)
class ServedViewEntry:
    """One immutable entry in a served-representation mount."""

    path: str
    kind: str
    size: int
    inode_id: int


class ServedArtifactSnapshot:
    """Synthetic directory containing one exact served Code Artifact version."""

    def __init__(self, fetched: FetchedArtifact) -> None:
        if not isinstance(fetched, FetchedArtifact):
            raise TypeError("fetched must be a FetchedArtifact")
        artifact = fetched.artifact
        version = fetched.version
        if artifact.kind != "code" or artifact.provider != "owner":
            raise IntegrityError(
                "served mounts require a Code Artifact from the owner-frame adapter"
            )
        try:
            parsed_artifact_id = uuid.UUID(artifact.artifact_id)
        except (AttributeError, TypeError, ValueError) as exc:
            raise IntegrityError("served mount requires a canonical Artifact UUID") from exc
        if str(parsed_artifact_id) != artifact.artifact_id:
            raise IntegrityError("served mount requires a canonical Artifact UUID")
        if version.provider != artifact.provider:
            raise IntegrityError("served version uses a different provider")
        if version.artifact_id != artifact.artifact_id:
            raise IntegrityError("served version belongs to a different artifact")
        if (
            not isinstance(version.version_id, str)
            or not version.version_id
            or len(version.version_id) > 256
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E
                for character in version.version_id
            )
        ):
            raise IntegrityError("served mount requires an exact version ID")

        representations = [
            item
            for item in fetched.representations
            if isinstance(item, Representation) and item.label == "served"
        ]
        if len(representations) != 1:
            raise IntegrityError(
                "Code Artifact must provide one served representation"
            )
        representation = representations[0]
        if not isinstance(representation.data, bytes):
            raise IntegrityError("served representation must contain bytes")
        if representation.size > MAX_SERVED_BYTES:
            raise ResponseTooLargeError(
                "served representation exceeds the ArtifactFS byte limit",
                provider="owner",
            )

        self.version = version.version_id
        self._artifact_id = artifact.artifact_id
        self._served = representation.data
        metadata = safe_json_value(
            {
                "schema": "artifactfs.served-snapshot.v1",
                "representation": "served",
                "warning": (
                    "served.html may contain provider runtime and is not the "
                    "artifact's authored source"
                ),
                "artifact": {
                    "provider": artifact.provider,
                    "artifact_id": artifact.artifact_id,
                    "kind": artifact.kind,
                    "title": artifact.title,
                    "visibility": artifact.visibility,
                    "live_version": artifact.live_version,
                    "published_version": artifact.published_version,
                },
                "version": {
                    "provider": version.provider,
                    "artifact_id": version.artifact_id,
                    "version_id": version.version_id,
                    "is_live": version.is_live,
                    "is_published": version.is_published,
                },
                "content": {
                    "bytes": representation.size,
                    "sha256": representation.sha256,
                    "media_type": representation.media_type,
                },
                "provenance": fetched.provenance,
            }
        )
        self._metadata = (
            json.dumps(
                metadata,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if len(self._metadata) > MAX_METADATA_BYTES:
            raise ResponseTooLargeError(
                "served metadata exceeds the ArtifactFS byte limit",
                provider="owner",
            )
        self._entries = {
            _ROOT: self._entry(_ROOT, "directory", 0),
            _CONTROL: self._entry(_CONTROL, "directory", 0),
            _METADATA: self._entry(_METADATA, "file", len(self._metadata)),
            _SERVED: self._entry(_SERVED, "file", len(self._served)),
        }

    def _entry(self, path: str, kind: str, size: int) -> ServedViewEntry:
        identity = (self.version + "\0" + path).encode("utf-8")
        inode = int.from_bytes(
            hashlib.blake2b(identity, digest_size=8, person=b"aodfs-view").digest(),
            "big",
        ) & ((1 << 63) - 1)
        if path == _ROOT:
            inode = 1
        elif inode <= 1:
            inode += 2
        return ServedViewEntry(path=path, kind=kind, size=size, inode_id=inode)

    @property
    def artifact_id(self) -> str:
        """Return the stable UUID slug without exposing any capability token."""

        return self._artifact_id

    def get(self, path: str) -> ServedViewEntry:
        canonical = _canonical_path(path)
        try:
            return self._entries[canonical]
        except KeyError as exc:
            raise FileNotFoundError(canonical) from exc

    def iterdir(self, path: str = _ROOT) -> Iterable[ServedViewEntry]:
        canonical = _canonical_path(path)
        entry = self.get(canonical)
        if entry.kind != "directory":
            raise NotADirectoryError(canonical)
        if canonical == _ROOT:
            names = (_CONTROL, _SERVED)
        elif canonical == _CONTROL:
            names = (_METADATA,)
        else:  # defensive; all directory paths are covered above
            names = ()
        return tuple(self._entries[name] for name in names)

    def read_file(self, path: str) -> bytes:
        canonical = _canonical_path(path)
        entry = self.get(canonical)
        if entry.kind != "file":
            raise IsADirectoryError(canonical)
        if canonical == _SERVED:
            return self._served
        if canonical == _METADATA:
            return self._metadata
        raise FileNotFoundError(canonical)


def fetch_owner_served_snapshot(
    reference: object,
    *,
    version: Optional[str] = None,
    adapter: Optional[Any] = None,
) -> ServedArtifactSnapshot:
    """Fetch and pin one Code Artifact as a read-only served snapshot.

    When ``version`` is omitted, Artifact Bridge resolves the current live
    version once; the resulting snapshot still carries that concrete version
    and never follows later remote changes. Public references may use the
    adapter's anonymous fallback; inspect the sanitized provenance metadata to
    distinguish that from authenticated owner retrieval.
    """

    owned_adapter = adapter is None
    selected = adapter if adapter is not None else OwnerFrameAdapter()
    client = BridgeClient([selected])
    try:
        fetched = client.fetch(reference, version=version, provider="owner")
        return ServedArtifactSnapshot(fetched)
    finally:
        if owned_adapter:
            client.close()


def _canonical_path(path: object) -> str:
    if not isinstance(path, str) or not path:
        raise FileNotFoundError("invalid snapshot path")
    if path == _ROOT:
        return path
    if (
        path.startswith("/")
        or path.endswith("/")
        or "\\" in path
        or "\x00" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
    ):
        raise FileNotFoundError("invalid snapshot path")
    return path

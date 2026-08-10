"""Provider-neutral value objects used by artifact adapters and clients."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

from .errors import redact_text


SENSITIVE_KEY_PARTS = (
    "access_key",
    "accesskey",
    "accesstoken",
    "api_key",
    "apikey",
    "asset_token",
    "assettoken",
    "authorization",
    "bearer",
    "consenttoken",
    "cookie",
    "credential",
    "oauth_token",
    "password",
    "private_key",
    "privatekey",
    "refreshtoken",
    "refresh_token",
    "secret",
    "share_key",
    "subscriptiontoken",
    "synctoken",
    "token",
    "wstoken",
)
MAX_SAFE_JSON_DEPTH = 64
MAX_SAFE_JSON_NODES = 65536


def is_sensitive_key(key: object) -> bool:
    normalized = unicodedata.normalize("NFKC", str(key)).casefold()
    compact = re.sub(r"[^a-z0-9]+", "", normalized)
    return any(
        re.sub(r"[^a-z0-9]+", "", part.casefold()) in compact
        for part in SENSITIVE_KEY_PARTS
    )


def safe_json_value(value: Any) -> Any:
    """Convert provider data to bounded deterministic JSON without credentials."""

    nodes = 0
    active = set()

    def convert(current: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_SAFE_JSON_NODES:
            raise ValueError(
                "metadata exceeds the %d-node structure limit"
                % MAX_SAFE_JSON_NODES
            )
        if depth > MAX_SAFE_JSON_DEPTH:
            raise ValueError(
                "metadata exceeds the %d-level depth limit" % MAX_SAFE_JSON_DEPTH
            )
        if current is None or isinstance(current, (bool, int)):
            return current
        if isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError("metadata contains a non-finite number")
            return current
        if isinstance(current, str):
            return redact_text(current)
        if isinstance(current, bytes):
            return {
                "bytes": len(current),
                "sha256": hashlib.sha256(current).hexdigest(),
            }
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in active:
                raise ValueError("metadata contains a reference cycle")
            active.add(identity)
            try:
                result: Dict[str, Any] = {}
                for key in sorted(current, key=lambda item: str(item)):
                    if is_sensitive_key(key):
                        continue
                    rendered_key = str(key)
                    if rendered_key in result:
                        raise ValueError(
                            "metadata contains duplicate stringified key %r"
                            % rendered_key
                        )
                    result[rendered_key] = convert(current[key], depth + 1)
                return result
            finally:
                active.remove(identity)
        if isinstance(current, (list, tuple, set, frozenset)):
            identity = id(current)
            if identity in active:
                raise ValueError("metadata contains a reference cycle")
            active.add(identity)
            try:
                source = current
                if isinstance(current, (set, frozenset)):
                    source = sorted(
                        current,
                        key=lambda item: (type(item).__name__, repr(item)),
                    )
                converted = [convert(item, depth + 1) for item in source]
                if isinstance(current, (set, frozenset)):
                    converted.sort(
                        key=lambda item: json.dumps(
                            item,
                            ensure_ascii=True,
                            allow_nan=False,
                            sort_keys=True,
                        )
                    )
                return converted
            finally:
                active.remove(identity)
        return redact_text(current)

    return convert(value, 1)


@dataclass(frozen=True)
class ArtifactRef:
    provider: str
    artifact_id: str
    version: Optional[str] = None
    original: Optional[str] = None
    kind: str = "code"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "artifact_id": self.artifact_id,
            "version": self.version,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class AuthStatus:
    provider: str
    authenticated: bool
    source: Optional[str] = None
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return safe_json_value(
            {
                "provider": self.provider,
                "authenticated": self.authenticated,
                "source": self.source,
                "detail": self.detail,
            }
        )


@dataclass(frozen=True)
class Artifact:
    provider: str
    artifact_id: str
    title: Optional[str] = None
    url: Optional[str] = None
    visibility: Optional[str] = None
    live_version: Optional[str] = None
    published_version: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    owner: Optional[str] = None
    kind: str = "code"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return safe_json_value(
            {
                "provider": self.provider,
                "artifact_id": self.artifact_id,
                "kind": self.kind,
                "title": self.title,
                "url": self.url,
                "visibility": self.visibility,
                "live_version": self.live_version,
                "published_version": self.published_version,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "owner": self.owner,
                "metadata": self.metadata,
            }
        )


@dataclass(frozen=True)
class ArtifactVersion:
    provider: str
    artifact_id: str
    version_id: str
    created_at: Optional[str] = None
    is_live: bool = False
    is_published: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return safe_json_value(
            {
                "provider": self.provider,
                "artifact_id": self.artifact_id,
                "version_id": self.version_id,
                "created_at": self.created_at,
                "is_live": self.is_live,
                "is_published": self.is_published,
                "metadata": self.metadata,
            }
        )


@dataclass(frozen=True)
class Representation:
    label: str
    media_type: str
    data: bytes
    suggested_name: Optional[str] = None
    source_url: Optional[str] = None

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def size(self) -> int:
        return len(self.data)

    def to_dict(self) -> Dict[str, Any]:
        return safe_json_value(
            {
                "label": self.label,
                "media_type": self.media_type,
                "suggested_name": self.suggested_name,
                "source_url": self.source_url,
                "bytes": self.size,
                "sha256": self.sha256,
            }
        )


@dataclass(frozen=True)
class FetchedArtifact:
    artifact: Artifact
    version: ArtifactVersion
    representations: Tuple[Representation, ...]
    provenance: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact": self.artifact.to_dict(),
            "version": self.version.to_dict(),
            "representations": [item.to_dict() for item in self.representations],
            "provenance": safe_json_value(self.provenance),
        }

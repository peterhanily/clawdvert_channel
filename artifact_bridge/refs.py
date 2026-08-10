"""Strict parsing for supported Claude artifact references."""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import unquote, urlsplit

from .errors import ReferenceError, UnsupportedReferenceError
from .models import ArtifactRef


UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
UUID_RE = re.compile(r"^%s$" % UUID)
CODE_PATH_RE = re.compile(r"^/code/(?:artifact|frame)/(?:[A-Za-z0-9_-]*-)?(%s)(?:/)?$" % UUID)
CONTENT_HOST_RE = re.compile(r"^(%s)\.frame\.claudeusercontent\.com$" % UUID, re.IGNORECASE)
CONTENT_PATH_RE = re.compile(r"^/_f/([^/]+)/?$", re.IGNORECASE)
PUBLIC_PATH_RE = re.compile(r"^/public/artifacts/([^/?#]+)/?$", re.IGNORECASE)
STANDARD_VERSION_RE = re.compile(r"^claude_artifact_version_[A-Za-z0-9_-]+$")
CODE_COMPLIANCE_RE = re.compile(
    r"^(?:claude_code_artifact|claude_code_artifact_version)_[A-Za-z0-9_-]+$"
)
CART_RE = re.compile(r"^cart_[A-Za-z0-9_-]+$")


def _provider_for(default_provider: Optional[str], inferred: str) -> str:
    if default_provider in (None, "auto"):
        return inferred
    return default_provider


def parse_ref(value: object, default_provider: Optional[str] = "auto") -> ArtifactRef:
    """Parse a provider ID, Code viewer URL, or exact content-origin URL."""

    if isinstance(value, ArtifactRef):
        if default_provider not in (None, "auto", value.provider):
            return ArtifactRef(
                provider=str(default_provider),
                artifact_id=value.artifact_id,
                version=value.version,
                original=value.original,
                kind=value.kind,
            )
        return value
    if not isinstance(value, str) or not value.strip():
        raise ReferenceError("artifact reference must be a non-empty string")

    raw = value.strip()
    if any(ord(char) < 32 for char in raw):
        raise ReferenceError("artifact reference contains control characters")

    if UUID_RE.fullmatch(raw):
        return ArtifactRef(
            provider=_provider_for(default_provider, "owner"),
            artifact_id=raw.lower(),
            original=raw,
            kind="code",
        )
    if STANDARD_VERSION_RE.fullmatch(raw):
        return ArtifactRef(
            provider=_provider_for(default_provider, "compliance"),
            artifact_id=raw,
            version=raw,
            original=raw,
            kind="standard",
        )
    if CODE_COMPLIANCE_RE.fullmatch(raw):
        is_version = raw.startswith("claude_code_artifact_version_")
        return ArtifactRef(
            provider=_provider_for(default_provider, "compliance"),
            artifact_id=raw,
            version=raw if is_version else None,
            original=raw,
            kind="code",
        )
    if CART_RE.fullmatch(raw):
        return ArtifactRef(
            provider=_provider_for(default_provider, "compliance"),
            artifact_id=raw,
            original=raw,
            kind="code",
        )

    try:
        parsed = urlsplit(raw)
    except ValueError:
        parsed = None
    if parsed is None:
        raise ReferenceError("invalid artifact URL")
    if parsed.scheme != "https" or not parsed.hostname:
        raise ReferenceError("expected a Code Artifact URL, UUID slug, or compliance artifact ID")
    try:
        port = parsed.port
        invalid_port = False
    except ValueError:
        port = None
        invalid_port = True
    if invalid_port:
        raise ReferenceError("invalid artifact URL port")
    if parsed.username or parsed.password or port not in (None, 443):
        raise ReferenceError("artifact URLs may not contain credentials or a non-HTTPS port")

    hostname = parsed.hostname.lower()
    if hostname == "claude.ai" or hostname.endswith(".claude.ai"):
        code_match = CODE_PATH_RE.fullmatch(unquote(parsed.path))
        if code_match:
            return ArtifactRef(
                provider=_provider_for(default_provider, "owner"),
                artifact_id=code_match.group(1).lower(),
                original=raw,
                kind="code",
            )
        public_match = PUBLIC_PATH_RE.fullmatch(unquote(parsed.path))
        if public_match:
            return ArtifactRef(
                provider=_provider_for(default_provider, "compliance"),
                artifact_id=public_match.group(1),
                original=raw,
                kind="standard-public",
            )

    host_match = CONTENT_HOST_RE.fullmatch(hostname)
    path_match = CONTENT_PATH_RE.fullmatch(unquote(parsed.path))
    if host_match and path_match:
        if parsed.query or parsed.fragment:
            raise ReferenceError("content-origin references must not contain query credentials or fragments")
        version = path_match.group(1)
        if not version or any(char in version for char in "\\\x00"):
            raise ReferenceError("invalid content-origin version")
        return ArtifactRef(
            provider=_provider_for(default_provider, "owner"),
            artifact_id=host_match.group(1).lower(),
            version=version,
            original=raw,
            kind="code",
        )

    raise ReferenceError("unsupported artifact reference")


def require_resolvable(ref: ArtifactRef) -> ArtifactRef:
    if ref.kind == "standard-public":
        raise UnsupportedReferenceError(
            "public /public/artifacts URLs do not expose the version ID required for exact retrieval; "
            "use a claude_artifact_version_* ID from the Compliance API"
        )
    return ref

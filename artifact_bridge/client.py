"""Provider routing and exact-version operations for the artifact bridge."""

from __future__ import annotations

import difflib
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .errors import (
    AdapterError,
    IntegrityError,
    ReferenceError,
    ResponseTooLargeError,
    VersionNotFoundError,
)
from .models import Artifact, ArtifactRef, ArtifactVersion, AuthStatus, FetchedArtifact, Representation
from .refs import parse_ref, require_resolvable


DEFAULT_MAX_REPRESENTATION_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_DIFF_INPUT_BYTES = 2 * 1024 * 1024
MAX_DIFF_LINES = 10000
MAX_MIRROR_VERSIONS = 1024
_SYMBOLIC_VERSIONS = frozenset(("latest", "live", "published"))


class BridgeClient:
    """A read-only facade over one or more artifact provider adapters."""

    def __init__(
        self,
        adapters: Iterable[Any],
        *,
        max_representation_bytes: int = DEFAULT_MAX_REPRESENTATION_BYTES,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    ) -> None:
        if max_representation_bytes <= 0 or max_total_bytes <= 0:
            raise ValueError("byte limits must be positive")
        self.max_representation_bytes = max_representation_bytes
        self.max_total_bytes = max_total_bytes
        self.adapters: Dict[str, Any] = {}
        for adapter in adapters:
            name = getattr(adapter, "name", None)
            if not isinstance(name, str) or not name:
                raise ValueError("artifact adapter must expose a non-empty name")
            if name in self.adapters:
                raise ValueError("duplicate artifact adapter: %s" % name)
            self.adapters[name] = adapter
        if not self.adapters:
            raise ValueError("at least one artifact adapter is required")

    def close(self) -> None:
        for adapter in self.adapters.values():
            close = getattr(adapter, "close", None)
            if callable(close):
                close()

    def auth_status(self, provider: Optional[str] = None) -> List[AuthStatus]:
        if provider not in (None, "auto"):
            return [self._adapter(provider).auth_status()]
        return [self.adapters[name].auth_status() for name in sorted(self.adapters)]

    def list_artifacts(self, provider: Optional[str], limit: Optional[int] = None) -> List[Artifact]:
        if provider in (None, "auto"):
            raise ReferenceError(
                "list has no reference to identify an authority surface; "
                "choose --adapter owner or --adapter compliance"
            )
        else:
            adapter = self._adapter(provider)
        return adapter.list_artifacts(limit=limit)

    def inspect(self, value: object, provider: Optional[str] = "auto") -> Artifact:
        ref, adapter = self._route(value, provider)
        return adapter.inspect(ref)

    def versions(self, value: object, provider: Optional[str] = "auto") -> List[ArtifactVersion]:
        ref, adapter = self._route(value, provider)
        return adapter.versions(ref)

    def fetch(
        self,
        value: object,
        version: Optional[str] = None,
        provider: Optional[str] = "auto",
    ) -> FetchedArtifact:
        ref, adapter = self._route(value, provider)
        exact = self._resolve_version(ref, adapter, version)
        fetched = adapter.fetch(ref, exact)
        self._validate_fetch(ref, exact, fetched)
        return fetched

    def mirror(
        self,
        value: object,
        versions: Optional[Sequence[str]] = None,
        provider: Optional[str] = "auto",
    ) -> List[FetchedArtifact]:
        ref, adapter = self._route(value, provider)
        if versions:
            selected = list(versions)
        elif ref.version:
            selected = [ref.version]
        else:
            listed = adapter.versions(ref)
            if not isinstance(listed, list) or any(
                not isinstance(item, ArtifactVersion) for item in listed
            ):
                raise IntegrityError("adapter returned an invalid version listing")
            for item in listed:
                if item.provider != ref.provider or item.artifact_id != ref.artifact_id:
                    raise IntegrityError(
                        "adapter version listing contains a different artifact identity"
                    )
            if any(
                item.metadata.get("listing_completeness") == "partial"
                for item in listed
            ):
                raise AdapterError(
                    "provider returned only a partial version listing; pass one or more exact "
                    "--version values instead of mirroring implicitly",
                    provider=getattr(adapter, "name", None),
                )
            selected = [item.version_id for item in listed]
        unique = []
        seen = set()
        for exact in selected:
            exact = self._require_exact_version(exact, adapter)
            if exact in seen:
                continue
            seen.add(exact)
            unique.append(exact)
            if len(unique) > MAX_MIRROR_VERSIONS:
                raise ResponseTooLargeError(
                    "mirror exceeds the %d exact-version operation limit"
                    % MAX_MIRROR_VERSIONS,
                    provider=getattr(adapter, "name", None),
                )
        selected = unique
        if not selected:
            raise VersionNotFoundError(
                "provider returned no retained versions to mirror",
                provider=getattr(adapter, "name", None),
            )
        results = []
        total = 0
        for exact in selected:
            if ref.version is not None and ref.version != exact:
                raise VersionNotFoundError(
                    "reference pins version %s, not requested version %s" % (ref.version, exact),
                    provider=getattr(adapter, "name", None),
                )
            fetched = adapter.fetch(ref, exact)
            self._validate_fetch(ref, exact, fetched)
            total += sum(representation.size for representation in fetched.representations)
            if total > self.max_total_bytes:
                raise ResponseTooLargeError(
                    "mirror exceeds the %d byte aggregate limit" % self.max_total_bytes
                )
            results.append(fetched)
        return results

    def cat(
        self,
        value: object,
        version: Optional[str] = None,
        representation: Optional[str] = None,
        provider: Optional[str] = "auto",
    ) -> bytes:
        fetched = self.fetch(value, version, provider)
        return self._representation(fetched, representation).data

    def diff(
        self,
        value: object,
        from_version: str,
        to_version: str,
        representation: Optional[str] = None,
        context: int = 3,
        provider: Optional[str] = "auto",
    ) -> str:
        if not from_version or not to_version:
            raise VersionNotFoundError("diff requires two concrete version IDs")
        if context < 0 or context > 10000:
            raise ValueError("diff context must be between 0 and 10000")
        ref, adapter = self._route(value, provider)
        from_version = self._require_exact_version(from_version, adapter)
        to_version = self._require_exact_version(to_version, adapter)
        if ref.version is not None:
            self._require_exact_version(ref.version, adapter)
        if ref.version is not None and ref.version not in (from_version, to_version):
            raise VersionNotFoundError(
                "reference pins version %s, which matches neither diff endpoint" % ref.version,
                provider=getattr(adapter, "name", None),
            )
        # Remove the embedded pin only for the two explicitly named endpoints;
        # both exact IDs remain verified below.
        diff_ref = ArtifactRef(
            provider=ref.provider,
            artifact_id=ref.artifact_id,
            original=ref.original,
            kind=ref.kind,
        )
        before = adapter.fetch(diff_ref, from_version)
        after = adapter.fetch(diff_ref, to_version)
        self._validate_fetch(diff_ref, from_version, before)
        self._validate_fetch(diff_ref, to_version, after)
        if before.artifact.artifact_id != after.artifact.artifact_id:
            raise IntegrityError("diff endpoints belong to different artifact lineages")
        before_rep = self._representation(before, representation)
        after_rep = self._representation(after, representation or before_rep.label)
        if before_rep.size + after_rep.size > MAX_DIFF_INPUT_BYTES:
            raise ResponseTooLargeError(
                "diff inputs exceed the %d byte computation limit" % MAX_DIFF_INPUT_BYTES
            )
        before_text = before_rep.data.decode("utf-8", "replace").splitlines(keepends=True)
        after_text = after_rep.data.decode("utf-8", "replace").splitlines(keepends=True)
        if len(before_text) + len(after_text) > MAX_DIFF_LINES:
            raise ResponseTooLargeError(
                "diff inputs exceed the %d line computation limit" % MAX_DIFF_LINES
            )
        return "".join(
            difflib.unified_diff(
                before_text,
                after_text,
                fromfile="%s:%s:%s" % (ref.artifact_id, from_version, before_rep.label),
                tofile="%s:%s:%s" % (ref.artifact_id, to_version, after_rep.label),
                n=context,
            )
        )

    def _route(self, value: object, provider: Optional[str]) -> Tuple[ArtifactRef, Any]:
        requested = provider or "auto"
        ref = require_resolvable(parse_ref(value, default_provider=requested))
        return ref, self._adapter(ref.provider)

    def _adapter(self, provider: str) -> Any:
        adapter = self.adapters.get(provider)
        if adapter is None:
            available = ", ".join(sorted(self.adapters)) or "none"
            raise AdapterError(
                "adapter %r is unavailable (available: %s)" % (provider, available),
                provider=provider,
            )
        return adapter

    @staticmethod
    def _resolve_version(ref: ArtifactRef, adapter: Any, requested: Optional[str]) -> str:
        if requested is not None:
            requested = BridgeClient._require_exact_version(requested, adapter)
            if ref.version is not None and ref.version != requested:
                raise VersionNotFoundError(
                    "reference pins version %s, not requested version %s"
                    % (ref.version, requested),
                    provider=getattr(adapter, "name", None),
                )
            return requested
        if ref.version:
            return BridgeClient._require_exact_version(ref.version, adapter)
        artifact = adapter.inspect(ref)
        exact = artifact.live_version or artifact.published_version
        if not exact:
            raise VersionNotFoundError(
                "no exact live/published version is available; pass --version with a retained version ID",
                provider=getattr(adapter, "name", None),
            )
        return BridgeClient._require_exact_version(exact, adapter)

    @staticmethod
    def _require_exact_version(value: object, adapter: Any = None) -> str:
        if not isinstance(value, str) or not value:
            raise VersionNotFoundError(
                "version must be a non-empty provider version ID",
                provider=getattr(adapter, "name", None),
            )
        if value.lower() in _SYMBOLIC_VERSIONS:
            raise VersionNotFoundError(
                "symbolic versions are not allowed; supply the exact provider version ID",
                provider=getattr(adapter, "name", None),
            )
        return value

    def _validate_fetch(self, ref: ArtifactRef, exact: str, fetched: FetchedArtifact) -> None:
        if not isinstance(fetched, FetchedArtifact):
            raise IntegrityError("adapter returned an invalid fetched artifact")
        if fetched.version.version_id != exact:
            raise IntegrityError(
                "adapter returned version %s for exact request %s"
                % (fetched.version.version_id, exact),
                provider=fetched.artifact.provider,
            )
        if ref.kind != "standard" and fetched.artifact.artifact_id != ref.artifact_id:
            raise IntegrityError("adapter returned content for a different artifact")
        if fetched.version.artifact_id != fetched.artifact.artifact_id:
            raise IntegrityError("adapter version belongs to a different artifact")
        if fetched.artifact.provider != ref.provider or fetched.version.provider != ref.provider:
            raise IntegrityError("adapter returned content for a different provider")
        if fetched.artifact.kind != ref.kind:
            raise IntegrityError("adapter returned a different artifact kind")
        if not fetched.representations:
            raise IntegrityError("adapter returned no representations")
        labels = set()
        total = 0
        for representation in fetched.representations:
            if not isinstance(representation, Representation) or not representation.label:
                raise IntegrityError("adapter returned an invalid representation")
            if representation.label in labels:
                raise IntegrityError("adapter returned duplicate representation labels")
            labels.add(representation.label)
            if not isinstance(representation.data, bytes):
                raise IntegrityError("adapter representation is not bytes")
            if representation.size > self.max_representation_bytes:
                raise ResponseTooLargeError(
                    "representation %s exceeds the %d byte client limit"
                    % (representation.label, self.max_representation_bytes)
                )
            total += representation.size
            if total > self.max_total_bytes:
                raise ResponseTooLargeError(
                    "fetched artifact exceeds the %d byte aggregate limit"
                    % self.max_total_bytes
                )

    @staticmethod
    def _representation(
        fetched: FetchedArtifact, label: Optional[str]
    ) -> Representation:
        if label is not None:
            for representation in fetched.representations:
                if representation.label == label:
                    return representation
            raise AdapterError(
                "representation %r is unavailable (available: %s)"
                % (label, ", ".join(item.label for item in fetched.representations))
            )
        if len(fetched.representations) == 1:
            return fetched.representations[0]
        for preferred in ("served", "stored", "content", "source"):
            for representation in fetched.representations:
                if representation.label == preferred:
                    return representation
        raise AdapterError(
            "multiple representations are available; choose --representation (%s)"
            % ", ".join(item.label for item in fetched.representations)
        )

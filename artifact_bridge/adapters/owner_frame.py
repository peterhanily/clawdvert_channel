"""Read-only adapter for owner and public Claude Code frames."""

from __future__ import annotations

import gzip
import http.client
import io
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple
from urllib.parse import quote
from urllib.request import Request, urlopen

from clawdvert import frames

from ..errors import (
    AdapterError,
    AuthenticationError,
    NotFoundError,
    ResponseTooLargeError,
    TruncatedResponseError,
    VersionNotFoundError,
)
from ..models import (
    Artifact,
    ArtifactRef,
    ArtifactVersion,
    AuthStatus,
    FetchedArtifact,
    Representation,
)
from ..json_safety import strict_json_loads, validate_json_text
from ..refs import parse_ref, require_resolvable


DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024


def _close_quietly(value: Any) -> None:
    """Close a transport without letting cleanup expose credential state."""

    try:
        value.close()
    except Exception:
        pass


class _BoundedFrameSession(frames.Session):
    """Frame OAuth/header behavior with bounded read-only response parsing."""

    def __init__(self, *args: Any, max_metadata_bytes: int = MAX_METADATA_BYTES, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.max_metadata_bytes = max_metadata_bytes

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        headers: Optional[Mapping[str, str]] = None,
        retries: int = 2,
    ) -> Tuple[int, Any, Mapping[str, str]]:
        if method != "GET" or body is not None:
            raise frames.FrameError("artifact bridge session permits GET requests only")
        for attempt in range(retries + 1):
            transport_failed = False
            try:
                with self._lock:
                    conn = self._connect()
                    conn.request(method, path, headers=self.headers(headers))
                    response = conn.getresponse()
                    response_headers = {key.lower(): value for key, value in response.getheaders()}
                    declared = response_headers.get("content-length")
                    expected: Optional[int] = None
                    if declared is not None:
                        try:
                            expected = int(declared)
                        except ValueError:
                            expected = None
                        if expected is not None and expected > self.max_metadata_bytes:
                            _close_quietly(response)
                            self._conn = None
                            raise ResponseTooLargeError(
                                "frame metadata exceeds %d bytes" % self.max_metadata_bytes,
                                provider="owner",
                            )
                    raw = response.read(self.max_metadata_bytes + 1)
                    status = response.status
                    if response.will_close:
                        self._conn = None
                self.requests += 1
                if len(raw) > self.max_metadata_bytes:
                    raise ResponseTooLargeError(
                        "frame metadata exceeds %d bytes" % self.max_metadata_bytes,
                        provider="owner",
                    )
                if expected is not None and len(raw) != expected:
                    raise TruncatedResponseError(
                        "frame metadata response ended early",
                        provider="owner",
                    )
                if response_headers.get("content-encoding", "").lower() == "gzip" and raw:
                    invalid_gzip = False
                    try:
                        raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read(
                            self.max_metadata_bytes + 1
                        )
                    except (OSError, EOFError):
                        invalid_gzip = True
                    if invalid_gzip:
                        raise TruncatedResponseError(
                            "frame metadata returned invalid gzip data", provider="owner"
                        )
                    if len(raw) > self.max_metadata_bytes:
                        raise ResponseTooLargeError(
                            "decompressed frame metadata exceeds %d bytes"
                            % self.max_metadata_bytes,
                            provider="owner",
                        )
                parse_failed = False
                try:
                    decoded = raw.decode("utf-8")
                    validate_json_text(decoded)
                    value = strict_json_loads(decoded) if decoded else {}
                except (UnicodeDecodeError, ValueError, RecursionError):
                    parse_failed = True
                    value = {}
                if parse_failed:
                    raise frames.FrameError(
                        "frame metadata was not valid bounded JSON",
                        status=status,
                        body=None,
                    )
                return status, value, response_headers
            except (ResponseTooLargeError, TruncatedResponseError):
                _close_quietly(self)
                raise
            except (http.client.HTTPException, OSError):
                # Raise only after leaving this block.  Some transports echo
                # Authorization headers in their exception text, so retaining
                # the raw error as context would retain the OAuth credential.
                transport_failed = True

            if transport_failed:
                _close_quietly(self)
                self.reconnects += 1
                if attempt < retries:
                    time.sleep(0.4 * (attempt + 1))
                    continue
                break
        raise frames.FrameError("bounded frame GET failed", body=None)


class OwnerFrameAdapter:
    """Read Claude Code Artifacts through the frame control/content planes.

    OAuth is resolved lazily by ``clawdvert.frames``.  When no owner credential
    exists, public boot metadata and the pinned content-origin version remain
    readable anonymously.  Bearer and asset tokens never leave this adapter.
    """

    name = "owner"

    def __init__(
        self,
        session: Optional[Any] = None,
        *,
        timeout: int = 30,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        anonymous_opener: Optional[Any] = None,
        content_fetcher: Optional[Callable[..., Any]] = None,
    ) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self._session = session
        self._session_supplied = session is not None
        self._session_error: Optional[Exception] = None
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self._anonymous_opener = anonymous_opener
        self._content_fetcher = content_fetcher

    def close(self) -> None:
        if self._session is not None and hasattr(self._session, "close"):
            self._session.close()

    def auth_status(self) -> AuthStatus:
        if self._session is not None:
            source = frames.credential_source_label(
                getattr(self._session, "token_source", None),
                caller_supplied=self._session_supplied,
            )
            return AuthStatus("owner", True, source, "OAuth credential available")
        if self._session_error is not None:
            return AuthStatus("owner", False, None, "Claude Code OAuth was rejected")
        try:
            token, source = frames.read_token()
            del token
            return AuthStatus(
                "owner",
                True,
                frames.credential_source_label(source),
                "OAuth credential available",
            )
        except frames.FrameError:
            return AuthStatus(
                "owner",
                False,
                None,
                "No Claude Code OAuth credential; public pinned artifacts remain readable",
            )

    def _owner_session(self, required: bool = False) -> Optional[Any]:
        if self._session is not None:
            return self._session
        if self._session_error is None:
            try:
                self._session = _BoundedFrameSession(
                    timeout=self.timeout, max_metadata_bytes=MAX_METADATA_BYTES
                )
            except frames.FrameError as exc:
                self._session_error = exc
        if required and self._session is None:
            raise AuthenticationError(
                "Claude Code OAuth is required for this operation; log in with `claude` first",
                provider=self.name,
            )
        return self._session

    @staticmethod
    def _map_frame_error(exc: frames.FrameError, action: str) -> AdapterError:
        status = getattr(exc, "status", None)
        if status == 401:
            return AuthenticationError(
                "Claude Code OAuth expired while %s" % action,
                provider="owner",
                status=status,
            )
        if status == 404:
            return NotFoundError(
                "artifact was not found while %s" % action,
                provider="owner",
                status=status,
            )
        return AdapterError(
            "could not %s (HTTP %s)" % (action, status if status is not None else "transport error"),
            provider="owner",
            status=status,
        )

    def list_artifacts(self, limit: Optional[int] = None) -> List[Artifact]:
        session = self._owner_session(required=True)
        requested = 200 if limit is None else limit
        if isinstance(requested, bool) or not isinstance(requested, int) or requested <= 0:
            raise AdapterError("limit must be positive", provider=self.name)
        mapped_error: Optional[AdapterError] = None
        transport_failed = False
        response_value: Any = None
        try:
            response_value = session.request(
                "GET", "/api/frame/frames?limit=%d" % requested
            )
        except frames.FrameError as exc:
            mapped_error = self._map_frame_error(exc, "list artifacts")
        except (http.client.HTTPException, OSError):
            transport_failed = True
        if mapped_error is not None:
            raise mapped_error
        if transport_failed:
            raise AdapterError("could not list artifacts (transport error)", provider=self.name)
        if not isinstance(response_value, tuple) or len(response_value) != 3:
            raise AdapterError(
                "artifact list endpoint returned an unexpected response",
                provider=self.name,
            )
        status, data, _headers = response_value
        if isinstance(status, bool) or not isinstance(status, int):
            raise AdapterError("artifact list endpoint returned an invalid status", provider=self.name)
        if status != 200:
            raise self._map_frame_error(
                frames.FrameError("artifact list endpoint failed", status=status, body=None),
                "list artifacts",
            )
        if not isinstance(data, Mapping) or "frames" not in data:
            raise AdapterError(
                "artifact list endpoint omitted its artifact list",
                provider=self.name,
                status=status,
            )
        records = data.get("frames")
        if not isinstance(records, list):
            raise AdapterError(
                "artifact list endpoint returned an unexpected shape",
                provider=self.name,
                status=status,
            )
        result: List[Artifact] = []
        for record in records:
            if not isinstance(record, Mapping):
                raise AdapterError(
                    "artifact list endpoint returned an invalid record",
                    provider=self.name,
                )
            slug = self._record_slug(record)
            if not slug:
                raise AdapterError(
                    "artifact list endpoint returned a record without an artifact ID",
                    provider=self.name,
                )
            result.append(self._artifact_from_record(record, slug))
        return result[:requested]

    def inspect(self, ref: ArtifactRef) -> Artifact:
        normalized = self._normalize_ref(ref)
        record, _session = self._boot(normalized.artifact_id)
        return self._artifact_from_record(record, normalized.artifact_id)

    def versions(self, ref: ArtifactRef) -> List[ArtifactVersion]:
        normalized = self._normalize_ref(ref)
        record, session = self._boot(normalized.artifact_id)
        partial_metadata: Mapping[str, Any] = {}
        if session is not None:
            mapped_error: Optional[AdapterError] = None
            transport_failed = False
            response_value: Any = None
            try:
                response_value = session.request(
                    "GET", "/api/frame/versions/%s" % normalized.artifact_id
                )
            except frames.FrameError as exc:
                mapped_error = self._map_frame_error(exc, "list artifact versions")
            except (http.client.HTTPException, OSError):
                transport_failed = True
            if mapped_error is not None:
                raise mapped_error
            if transport_failed:
                raise AdapterError(
                    "could not list artifact versions (transport error)",
                    provider=self.name,
                )
            if not isinstance(response_value, tuple) or len(response_value) != 3:
                raise AdapterError(
                    "artifact versions endpoint returned an unexpected response",
                    provider=self.name,
                )
            status, data, _headers = response_value
            if isinstance(status, bool) or not isinstance(status, int):
                raise AdapterError(
                    "artifact versions endpoint returned an invalid status",
                    provider=self.name,
                )
            if status != 200:
                raise self._map_frame_error(
                    frames.FrameError("versions endpoint failed", status=status, body=None),
                    "list artifact versions",
                )
            if not isinstance(data, Mapping):
                raise AdapterError(
                    "artifact versions endpoint returned an unexpected shape",
                    provider=self.name,
                    status=status,
                )
            version_payload = data
            candidates = version_payload.get("versions")
            if candidates is None:
                candidates = version_payload.get("history")
            if not isinstance(candidates, list):
                raise AdapterError(
                    "artifact versions endpoint omitted its version list",
                    provider=self.name,
                    status=status,
                )
        else:
            # Anonymous boot describes the exposed public pin, not retained
            # owner history.  Mark every synthesized entry so callers cannot
            # mistake this result for a complete version listing.
            version_payload = record
            candidates = []
            partial_metadata = {
                "listing_completeness": "partial",
                "source": "anonymous_public_boot",
            }

        live = self._text(version_payload.get("live")) or self._text(record.get("live"))
        live = live or self._text(record.get("ver"))
        shared = self._text(version_payload.get("shared")) or self._text(record.get("shared"))

        result: List[ArtifactVersion] = []
        seen = set()
        for item in candidates:
            version = self._version_from_item(item)
            if version is None:
                raise AdapterError(
                    "artifact versions endpoint returned an invalid version entry",
                    provider=self.name,
                )
            if version[0] in seen:
                continue
            version_id, created_at, metadata = version
            seen.add(version_id)
            result.append(
                ArtifactVersion(
                    provider=self.name,
                    artifact_id=normalized.artifact_id,
                    version_id=version_id,
                    created_at=created_at,
                    is_live=version_id == live,
                    is_published=version_id == shared,
                    metadata=dict(metadata, **partial_metadata),
                )
            )
        for version_id in (live, shared, normalized.version):
            if version_id and version_id not in seen:
                seen.add(version_id)
                result.append(
                    ArtifactVersion(
                        provider=self.name,
                        artifact_id=normalized.artifact_id,
                        version_id=version_id,
                        is_live=version_id == live,
                        is_published=version_id == shared,
                        metadata=dict(partial_metadata),
                    )
                )
        return result

    def fetch(self, ref: ArtifactRef, version: str) -> FetchedArtifact:
        normalized = self._normalize_ref(ref)
        if not isinstance(version, str) or not version or version in ("latest", "live", "published"):
            raise VersionNotFoundError(
                "fetch requires a concrete provider version ID",
                provider=self.name,
            )
        if normalized.version is not None and normalized.version != version:
            raise VersionNotFoundError(
                "reference pins version %s, not requested version %s"
                % (normalized.version, version),
                provider=self.name,
            )
        record, session = self._boot(normalized.artifact_id)
        artifact = self._artifact_from_record(record, normalized.artifact_id)
        asset_token = record.get("assetToken") if session is not None else None
        try:
            if self._content_fetcher is not None:
                fetched = self._content_fetcher(
                    session,
                    normalized.artifact_id,
                    version,
                    asset_token,
                    self.max_response_bytes,
                )
                if isinstance(fetched, tuple):
                    data, media_type = fetched
                else:
                    data, media_type = fetched, "text/html; charset=utf-8"
                if isinstance(data, str):
                    data = data.encode("utf-8")
                if not isinstance(data, bytes):
                    raise AdapterError("content fetcher returned non-bytes data", provider=self.name)
                if len(data) > self.max_response_bytes:
                    raise ResponseTooLargeError(
                        "served representation exceeds %d bytes" % self.max_response_bytes,
                        provider=self.name,
                    )
            else:
                data, media_type = self._download_content(
                    normalized.artifact_id, version, asset_token, session
                )
        finally:
            asset_token = None

        source_url = "https://%s.frame.claudeusercontent.com/_f/%s/" % (
            normalized.artifact_id,
            quote(version, safe=""),
        )
        version_model = ArtifactVersion(
            provider=self.name,
            artifact_id=normalized.artifact_id,
            version_id=version,
            is_live=version == artifact.live_version,
            is_published=version == artifact.published_version,
        )
        representation = Representation(
            label="served",
            media_type=media_type or "text/html; charset=utf-8",
            data=data,
            suggested_name="index.html",
            source_url=source_url,
        )
        return FetchedArtifact(
            artifact=artifact,
            version=version_model,
            representations=(representation,),
            provenance={
                "provider": self.name,
                "surface": "Claude Code frame content origin",
                "artifact_id": normalized.artifact_id,
                "version_id": version,
                "retrieval": "owner OAuth" if session is not None else "anonymous public pin",
                "source_url": source_url,
            },
        )

    def _normalize_ref(self, ref: ArtifactRef) -> ArtifactRef:
        normalized = require_resolvable(parse_ref(ref, default_provider=self.name))
        if normalized.kind != "code":
            raise AdapterError("owner adapter supports Claude Code Artifacts only", provider=self.name)
        return normalized

    def _boot(self, slug: str) -> Tuple[Mapping[str, Any], Optional[Any]]:
        session = self._owner_session(required=False)
        if session is not None:
            mapped_error: Optional[AdapterError] = None
            status: Optional[int] = None
            try:
                return frames.boot(session, slug), session
            except frames.FrameError as exc:
                status = getattr(exc, "status", None)
                if status != 404:
                    mapped_error = self._map_frame_error(exc, "inspect artifact")

            if mapped_error is not None:
                if status == 401:
                    self._session_error = RuntimeError("Claude Code OAuth rejected")
                    _close_quietly(session)
                    self._session = None
                raise mapped_error
            # A valid owner session may still 404 for somebody else's public
            # frame.  Probe anonymously without discarding it.
        return self._anonymous_boot(slug), None

    def _anonymous_boot(self, slug: str) -> Mapping[str, Any]:
        url = "%s/api/frame/%s?via=model_read" % (frames.API_BASE, slug)
        request = Request(
            url,
            method="GET",
            headers={
                "User-Agent": frames.UA,
                "Accept": "application/json",
                "X-Frame-CP": "go",
                "X-Frame-Surface": "code",
                "X-Frame-Platform": "cli",
            },
        )
        raw = b""
        failure_status: Optional[int] = None
        transport_failed = False
        try:
            opener = self._anonymous_opener
            if opener is None:
                response = urlopen(request, timeout=self.timeout)
            elif hasattr(opener, "open"):
                response = opener.open(request, timeout=self.timeout)
            else:
                response = opener(request, timeout=self.timeout)
            with response:
                status = getattr(response, "status", None)
                if status is None:
                    status = response.getcode()
                if status != 200:
                    failure_status = status
                else:
                    raw = response.read(MAX_METADATA_BYTES + 1)
        except Exception as exc:
            candidate_status = getattr(exc, "code", None)
            failure_status = candidate_status if isinstance(candidate_status, int) else None
            transport_failed = True
            _close_quietly(exc)
        if failure_status in (401, 403, 404):
            raise NotFoundError(
                "artifact is not public and no usable owner OAuth credential was found",
                provider=self.name,
                status=failure_status,
            )
        if failure_status is not None:
            raise AdapterError(
                "public metadata returned HTTP %s" % failure_status,
                provider=self.name,
                status=failure_status,
            )
        if transport_failed:
            raise AdapterError("could not read public artifact metadata", provider=self.name)
        if len(raw) > MAX_METADATA_BYTES:
            raise ResponseTooLargeError("artifact metadata exceeds the safety limit", provider=self.name)
        parse_failed = False
        try:
            decoded = raw.decode("utf-8")
            validate_json_text(decoded)
            data = strict_json_loads(decoded)
        except (UnicodeDecodeError, ValueError, RecursionError):
            parse_failed = True
            data = None
        if parse_failed:
            raise AdapterError("public artifact metadata was not valid JSON", provider=self.name)
        if not isinstance(data, Mapping):
            raise AdapterError("public artifact metadata had an unexpected shape", provider=self.name)
        return data

    def _download_content(
        self,
        slug: str,
        version: str,
        asset_token: Optional[str],
        session: Optional[Any],
    ) -> Tuple[bytes, str]:
        host = frames.CONTENT_HOST.format(slug=slug)
        path = "/_f/%s/" % quote(version, safe="")
        if asset_token:
            path += "?__frame_t=" + quote(str(asset_token), safe="")
        timeout = getattr(session, "timeout", self.timeout) if session is not None else self.timeout
        conn = http.client.HTTPSConnection(host, timeout=timeout)
        transport_failed = False
        try:
            conn.request(
                "GET",
                path,
                headers={"User-Agent": frames.UA, "Accept-Encoding": "gzip", "Host": host},
            )
            response = conn.getresponse()
            status = response.status
            if status != 200:
                response.read(4096)
                if status in (403, 404):
                    raise VersionNotFoundError(
                        "exact version is unavailable to this credential or public pin (HTTP %d)" % status,
                        provider=self.name,
                        status=status,
                    )
                raise AdapterError(
                    "content origin returned HTTP %d" % status,
                    provider=self.name,
                    status=status,
                )
            length = response.getheader("Content-Length")
            expected_length: Optional[int] = None
            if length:
                try:
                    expected_length = int(length)
                    if expected_length > self.max_response_bytes:
                        raise ResponseTooLargeError(
                            "served representation exceeds %d bytes" % self.max_response_bytes,
                            provider=self.name,
                        )
                except ValueError:
                    pass
            truncated = False
            try:
                raw = response.read(self.max_response_bytes + 1)
            except http.client.IncompleteRead:
                truncated = True
            if truncated:
                raise TruncatedResponseError(
                    "content origin response ended early",
                    provider=self.name,
                )
            if len(raw) > self.max_response_bytes:
                raise ResponseTooLargeError(
                    "served representation exceeds %d bytes" % self.max_response_bytes,
                    provider=self.name,
                )
            if expected_length is not None and len(raw) != expected_length:
                raise TruncatedResponseError(
                    "content origin returned %d of %d encoded bytes"
                    % (len(raw), expected_length),
                    provider=self.name,
                )
            if (response.getheader("Content-Encoding") or "").lower() == "gzip" and raw:
                invalid_gzip = False
                try:
                    expanded = gzip.GzipFile(fileobj=io.BytesIO(raw)).read(
                        self.max_response_bytes + 1
                    )
                except (OSError, EOFError):
                    invalid_gzip = True
                if invalid_gzip:
                    raise TruncatedResponseError(
                        "content origin returned invalid gzip data",
                        provider=self.name,
                    )
                if len(expanded) > self.max_response_bytes:
                    raise ResponseTooLargeError(
                        "decompressed representation exceeds %d bytes" % self.max_response_bytes,
                        provider=self.name,
                    )
                raw = expanded
            media_type = response.getheader("Content-Type") or "text/html; charset=utf-8"
            return raw, media_type
        except (AdapterError, VersionNotFoundError):
            raise
        except (http.client.HTTPException, OSError):
            # The request path can carry an asset token.  Do not retain a raw
            # transport exception which may have echoed that path.
            transport_failed = True
        finally:
            _close_quietly(conn)
        if transport_failed:
            raise AdapterError("content origin request failed", provider=self.name)
        raise AdapterError("content origin request failed", provider=self.name)

    @staticmethod
    def _text(value: Any) -> Optional[str]:
        return value if isinstance(value, str) and value else None

    @classmethod
    def _record_slug(cls, record: Mapping[str, Any]) -> Optional[str]:
        for key in ("slug", "uuid", "id", "artifact_id"):
            value = cls._text(record.get(key))
            if value:
                return value.lower()
        return None

    @classmethod
    def _artifact_from_record(cls, record: Mapping[str, Any], slug: str) -> Artifact:
        perm = record.get("perm") if isinstance(record.get("perm"), Mapping) else {}
        read = perm.get("read") if isinstance(perm.get("read"), Mapping) else {}
        visibility = (
            cls._text(perm.get("mode"))
            or cls._text(read.get("mode"))
            or cls._text(record.get("mode"))
        )
        record_read = record.get("read")
        if visibility is None and isinstance(record_read, str):
            visibility = record_read
        elif visibility is None and isinstance(record_read, Mapping):
            visibility = cls._text(record_read.get("mode"))
        live = cls._text(record.get("live")) or cls._text(record.get("ver"))
        shared = cls._text(record.get("shared"))
        if shared is None and visibility == "public" and record.get("live") is None:
            shared = cls._text(record.get("ver"))
        metadata: Dict[str, Any] = {}
        for key in (
            "description",
            "favicon",
            "label",
            "kind",
            "softDeleted",
            "mcpDeclared",
            "hasThumb",
        ):
            if key in record:
                metadata[key] = record[key]
        return Artifact(
            provider="owner",
            artifact_id=slug,
            title=cls._text(record.get("title")),
            url=frames.viewer_url(slug),
            visibility=visibility,
            live_version=live,
            published_version=shared,
            created_at=cls._text(record.get("created_at")) or cls._text(record.get("createdAt")),
            updated_at=cls._text(record.get("updated_at")) or cls._text(record.get("updatedAt")),
            kind="code",
            metadata=metadata,
        )

    @classmethod
    def _version_from_item(
        cls, item: Any
    ) -> Optional[Tuple[str, Optional[str], Mapping[str, Any]]]:
        if isinstance(item, str) and item:
            return item, None, {}
        if not isinstance(item, Mapping):
            return None
        version_id = None
        for key in ("version_id", "version", "ver", "uuid", "id"):
            version_id = cls._text(item.get(key))
            if version_id:
                break
        if not version_id:
            return None
        created_at = cls._text(item.get("created_at")) or cls._text(item.get("createdAt"))
        metadata = {
            key: item[key]
            for key in ("label", "description")
            if key in item
        }
        return version_id, created_at, metadata

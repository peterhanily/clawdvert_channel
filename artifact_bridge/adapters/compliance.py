"""Read-only adapter for Anthropic's official Compliance Artifact APIs.

The Compliance API is an organization governance/export surface.  It can list
Claude Code Artifacts and retrieve retained versions, and can retrieve a
standard chat Artifact when its version ID is already known.  It is not a
publishing API.

This module deliberately uses the standard library rather than the Anthropic
model SDK.  Compliance responses are streamed with a hard byte limit and are
only exposed after all available length and digest checks have passed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from artifact_bridge.errors import (
    AdapterError,
    AuthenticationError,
    IntegrityError,
    NotFoundError,
    ResponseTooLargeError,
    StaleVersionError,
    TruncatedResponseError,
    VersionNotFoundError,
    redact_text,
)
from artifact_bridge.json_safety import strict_json_loads, validate_json_text
from artifact_bridge.models import (
    Artifact,
    ArtifactRef,
    ArtifactVersion,
    AuthStatus,
    FetchedArtifact,
    Representation,
    safe_json_value,
)


_API_ORIGIN = "https://api.anthropic.com"
_CODE_ARTIFACTS_PATH = "/v1/compliance/apps/code/artifacts"
_STANDARD_ARTIFACTS_PATH = "/v1/compliance/apps/artifacts"
_ACCESS_KEY_ENV = "ANTHROPIC_COMPLIANCE_ACCESS_KEY"
_DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_DEFAULT_MAX_PAGES = 1000
_MAX_MAX_PAGES = 1000
_MAX_JSON_NESTING_DEPTH = 64
_MAX_JSON_NODES = 65536
_MAX_PAGE_TOKEN_BYTES = 8192
_READ_CHUNK_BYTES = 64 * 1024
_SPOOL_MEMORY_BYTES = 1024 * 1024
_UPDATED_AT_OPERATORS = frozenset(("gt", "gte", "lt", "lte"))
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._ -]+")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Turn redirects into ordinary HTTP errors instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _default_opener():
    return urllib.request.build_opener(_NoRedirectHandler())


def _header(headers: Any, name: str) -> Optional[str]:
    """Read a header from HTTPMessage objects and simple test mappings."""

    if headers is None:
        return None
    try:
        value = headers.get(name)
    except (AttributeError, TypeError):
        value = None
    if value is not None:
        return str(value)
    try:
        items = headers.items()
    except AttributeError:
        return None
    wanted = name.lower()
    for key, value in items:
        if str(key).lower() == wanted:
            return str(value)
    return None


def _status(response: Any) -> int:
    value = getattr(response, "status", None)
    if value is None:
        try:
            value = response.getcode()
        except AttributeError:
            value = 200
    try:
        return int(value)
    except (TypeError, ValueError):
        return 200


def _close_quietly(value: Any) -> None:
    try:
        value.close()
    except Exception:
        pass


def _md5_hasher():
    # ``usedforsecurity`` lets this RFC-mandated transport checksum work on
    # FIPS builds.  Older Python builds do not expose that keyword.
    try:
        return hashlib.md5(usedforsecurity=False)
    except TypeError:  # pragma: no cover - only on older Python builds
        return hashlib.md5()


def _normalise_ids(value: Optional[Iterable[str]], singular: Optional[str]) -> Tuple[str, ...]:
    if value is None:
        values: List[str] = []
    elif isinstance(value, str):
        values = [value]
    else:
        values = [str(item) for item in value]
    if singular is not None:
        values.append(str(singular))
    return tuple(item for item in values if item)


def _string_or_none(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


class AnthropicComplianceAdapter:
    """Official, read-only Anthropic Compliance API adapter.

    ``opener`` and ``sleep`` are injectable so callers can test the complete
    HTTP behavior without real credentials or network access.  ``base_url`` is
    accepted for explicitness but may only name Anthropic's canonical HTTPS
    API origin.
    """

    name = "compliance"

    def __init__(
        self,
        access_key: Optional[str] = None,
        *,
        base_url: str = _API_ORIGIN,
        timeout: float = 30.0,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
        max_pages: int = _DEFAULT_MAX_PAGES,
        max_retries: int = 3,
        backoff_seconds: float = 0.25,
        max_backoff_seconds: float = 8.0,
        opener: Any = None,
        sleep: Any = time.sleep,
    ) -> None:
        self._base_url = self._validated_origin(base_url)
        self._timeout = float(timeout)
        self._max_response_bytes = int(max_response_bytes)
        if (
            isinstance(max_pages, bool)
            or not isinstance(max_pages, int)
            or not 1 <= max_pages <= _MAX_MAX_PAGES
        ):
            raise ValueError(
                "max_pages must be an integer between 1 and %d" % _MAX_MAX_PAGES
            )
        self._max_pages = max_pages
        self._max_retries = int(max_retries)
        self._backoff_seconds = float(backoff_seconds)
        self._max_backoff_seconds = float(max_backoff_seconds)
        if self._timeout <= 0:
            raise ValueError("timeout must be positive")
        if self._max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if not 0 <= self._max_retries <= 8:
            raise ValueError("max_retries must be between 0 and 8")
        if self._backoff_seconds < 0 or self._max_backoff_seconds < 0:
            raise ValueError("retry backoff values cannot be negative")

        if access_key is None:
            self._access_key = os.environ.get(_ACCESS_KEY_ENV)
            self._access_key_source = _ACCESS_KEY_ENV if self._access_key else None
        else:
            self._access_key = str(access_key)
            self._access_key_source = "injected"
        if self._access_key is not None and ("\r" in self._access_key or "\n" in self._access_key):
            raise ValueError("Compliance access key contains invalid characters")

        self._opener = opener if opener is not None else _default_opener()
        self._sleep = sleep

    @staticmethod
    def _validated_origin(base_url: str) -> str:
        parsed = urllib.parse.urlsplit(str(base_url))
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Invalid Anthropic API origin") from exc
        if (
            parsed.scheme.lower() != "https"
            or (parsed.hostname or "").lower() != "api.anthropic.com"
            or port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Compliance API origin must be https://api.anthropic.com")
        return _API_ORIGIN

    def auth_status(self) -> AuthStatus:
        if self._access_key:
            return AuthStatus(
                provider=self.name,
                authenticated=True,
                source=self._access_key_source,
                detail="Compliance access key configured",
            )
        return AuthStatus(
            provider=self.name,
            authenticated=False,
            source=None,
            detail="Set ANTHROPIC_COMPLIANCE_ACCESS_KEY",
        )

    def _require_access_key(self) -> str:
        if not self._access_key:
            raise AuthenticationError(
                "Anthropic Compliance access key is not configured",
                provider=self.name,
            )
        return self._access_key

    def _url(self, path: str, query: Sequence[Tuple[str, str]] = ()) -> str:
        if not path.startswith("/"):
            raise ValueError("Compliance API path must be absolute")
        suffix = urllib.parse.urlencode(list(query)) if query else ""
        url = self._base_url + path + (("?" + suffix) if suffix else "")
        # Defense in depth: future callers cannot accidentally turn this into a
        # credential-bearing request to another host.
        self._assert_anthropic_url(url)
        return url

    @staticmethod
    def _assert_anthropic_url(url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        try:
            port = parsed.port
        except ValueError as exc:
            raise AdapterError("Invalid Compliance API URL", provider="compliance") from exc
        if (
            parsed.scheme.lower() != "https"
            or (parsed.hostname or "").lower() != "api.anthropic.com"
            or port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise AdapterError("Refusing a non-Anthropic Compliance API URL", provider="compliance")

    def _request(self, url: str):
        key = self._require_access_key()
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json, application/octet-stream;q=0.9, text/plain;q=0.9",
                "x-api-key": key,
            },
            method="GET",
        )

        for attempt in range(self._max_retries + 1):
            response = None
            failed_status = None
            retry_delay = None
            transport_failed = False
            try:
                if hasattr(self._opener, "open"):
                    response = self._opener.open(request, timeout=self._timeout)
                else:
                    response = self._opener(request, timeout=self._timeout)
            except urllib.error.HTTPError as exc:
                status = int(exc.code)
                if status in (429, 503) and attempt < self._max_retries:
                    retry_delay = self._retry_delay(attempt, getattr(exc, "headers", None))
                else:
                    failed_status = status
                _close_quietly(exc)
            except (urllib.error.URLError, OSError, http.client.HTTPException):
                # Never include the transport exception in the message: custom
                # transports and proxies have been observed to echo headers.
                transport_failed = True

            # Raise only after leaving the ``except`` block.  That prevents a
            # transport exception which echoed request headers from surviving
            # as ``__context__`` on the sanitized public exception.
            if transport_failed:
                raise AdapterError(
                    "Anthropic Compliance API request failed",
                    provider=self.name,
                )
            if retry_delay is not None:
                self._sleep(retry_delay)
                continue
            if failed_status is not None:
                self._raise_http_status(
                    failed_status,
                    version_request=self._is_version_url(url),
                )
            if response is None:  # defensive: non-conforming injected opener
                raise AdapterError(
                    "Anthropic Compliance API returned no response",
                    provider=self.name,
                )

            status = _status(response)
            if status in (429, 503) and attempt < self._max_retries:
                delay = self._retry_delay(attempt, getattr(response, "headers", None))
                _close_quietly(response)
                self._sleep(delay)
                continue
            if status < 200 or status >= 300:
                _close_quietly(response)
                self._raise_http_status(status, version_request=self._is_version_url(url))

            final_url = None
            try:
                final_url = response.geturl()
            except AttributeError:
                pass
            if final_url and final_url != url:
                _close_quietly(response)
                raise AdapterError(
                    "Compliance API redirects are not allowed",
                    provider=self.name,
                    status=status,
                )
            return response

        raise AdapterError("Anthropic Compliance API request failed", provider=self.name)

    @staticmethod
    def _is_version_url(url: str) -> bool:
        path = urllib.parse.urlsplit(url).path
        if path.startswith(_STANDARD_ARTIFACTS_PATH + "/"):
            return True
        return path.startswith(_CODE_ARTIFACTS_PATH + "/") and "/versions/" in path

    def _retry_delay(self, attempt: int, headers: Any) -> float:
        retry_after = _header(headers, "Retry-After")
        if retry_after is not None:
            try:
                seconds = max(0.0, float(retry_after.strip()))
                return min(seconds, self._max_backoff_seconds)
            except ValueError:
                pass
        return min(self._backoff_seconds * (2 ** attempt), self._max_backoff_seconds)

    def _raise_http_status(self, status: int, *, version_request: bool) -> None:
        if status in (401, 403):
            raise AuthenticationError(
                "Anthropic Compliance API rejected the access key",
                provider=self.name,
                status=status,
            )
        if status == 404 and version_request:
            raise StaleVersionError(
                "Artifact version is unavailable; re-list retained versions",
                provider=self.name,
                status=status,
            )
        if status == 404:
            raise NotFoundError(
                "Artifact was not found",
                provider=self.name,
                status=status,
            )
        raise AdapterError(
            "Anthropic Compliance API returned HTTP %d" % status,
            provider=self.name,
            status=status,
        )

    def _read_response(
        self,
        response: Any,
        *,
        expected_md5_hex: Optional[str] = None,
        expected_size: Optional[int] = None,
    ) -> Tuple[bytes, Mapping[str, Any]]:
        headers = getattr(response, "headers", {})
        content_length = _header(headers, "Content-Length")
        declared_length: Optional[int] = None
        if content_length is not None:
            try:
                candidate = int(content_length)
                if candidate >= 0:
                    declared_length = candidate
            except ValueError:
                pass

        if declared_length is not None and declared_length > self._max_response_bytes:
            _close_quietly(response)
            raise ResponseTooLargeError(
                "Compliance API response exceeds the configured byte limit",
                provider=self.name,
            )
        if expected_size is not None and expected_size > self._max_response_bytes:
            _close_quietly(response)
            raise ResponseTooLargeError(
                "Artifact metadata exceeds the configured byte limit",
                provider=self.name,
            )

        digest = _md5_hasher()
        total = 0
        spool_limit = min(_SPOOL_MEMORY_BYTES, self._max_response_bytes)
        try:
            with tempfile.SpooledTemporaryFile(max_size=spool_limit, mode="w+b") as spool:
                stream_failed = False
                try:
                    while True:
                        chunk = response.read(_READ_CHUNK_BYTES)
                        if not chunk:
                            break
                        if not isinstance(chunk, (bytes, bytearray, memoryview)):
                            raise TypeError("HTTP response read() returned non-bytes")
                        chunk = bytes(chunk)
                        total += len(chunk)
                        if total > self._max_response_bytes:
                            raise ResponseTooLargeError(
                                "Compliance API response exceeds the configured byte limit",
                                provider=self.name,
                            )
                        spool.write(chunk)
                        digest.update(chunk)
                except ResponseTooLargeError:
                    raise
                except (
                    OSError,
                    EOFError,
                    TypeError,
                    urllib.error.ContentTooShortError,
                    http.client.HTTPException,
                ):
                    stream_failed = True
                if stream_failed:
                    raise TruncatedResponseError(
                        "Artifact response ended before the stream completed",
                        provider=self.name,
                    )

                if declared_length is not None and total != declared_length:
                    error_type = TruncatedResponseError if total < declared_length else IntegrityError
                    raise error_type(
                        "Artifact response length did not match Content-Length",
                        provider=self.name,
                    )
                if expected_size is not None and total != expected_size:
                    error_type = TruncatedResponseError if total < expected_size else IntegrityError
                    raise error_type(
                        "Artifact response size did not match its metadata",
                        provider=self.name,
                    )

                content_md5 = _header(headers, "Content-MD5")
                if content_md5 is not None and not self._digest_matches(content_md5, digest):
                    raise IntegrityError(
                        "Artifact response failed Content-MD5 validation",
                        provider=self.name,
                    )
                if expected_md5_hex is not None:
                    expected = expected_md5_hex.strip().lower()
                    if not re.fullmatch(r"[0-9a-f]{32}", expected) or digest.hexdigest() != expected:
                        raise IntegrityError(
                            "Artifact response failed metadata MD5 validation",
                            provider=self.name,
                        )

                spool.seek(0)
                return spool.read(), headers
        finally:
            _close_quietly(response)

    @staticmethod
    def _digest_matches(expected_value: str, digest: Any) -> bool:
        expected = expected_value.strip().strip('"')
        if re.fullmatch(r"[0-9A-Fa-f]{32}", expected):
            return digest.hexdigest().lower() == expected.lower()
        try:
            decoded = base64.b64decode(expected, validate=True)
        except (binascii.Error, ValueError):
            return False
        return decoded == digest.digest()

    def _get_bytes(
        self,
        path: str,
        query: Sequence[Tuple[str, str]] = (),
        *,
        expected_md5_hex: Optional[str] = None,
        expected_size: Optional[int] = None,
    ) -> Tuple[bytes, Mapping[str, Any], str]:
        url = self._url(path, query)
        response = self._request(url)
        data, headers = self._read_response(
            response,
            expected_md5_hex=expected_md5_hex,
            expected_size=expected_size,
        )
        return data, headers, url

    def _get_json(
        self,
        path: str,
        query: Sequence[Tuple[str, str]] = (),
    ) -> Mapping[str, Any]:
        raw, _headers, _url = self._get_bytes(path, query)
        invalid_json = False
        value = None
        try:
            text = raw.decode("utf-8")
            validate_json_text(
                text,
                max_depth=_MAX_JSON_NESTING_DEPTH,
                max_nodes=_MAX_JSON_NODES,
            )
            value = strict_json_loads(text)
        except (UnicodeDecodeError, ValueError, RecursionError):
            invalid_json = True
        if invalid_json:
            raise AdapterError(
                "Anthropic Compliance API returned invalid JSON",
                provider=self.name,
            )
        if not isinstance(value, Mapping):
            raise AdapterError(
                "Anthropic Compliance API returned an unexpected JSON shape",
                provider=self.name,
            )
        return value

    def _page_records(self, payload: Mapping[str, Any]) -> Tuple[Mapping[str, Any], ...]:
        raw_records = payload.get("data")
        if not isinstance(raw_records, list):
            raise AdapterError(
                "Compliance API returned an invalid data list",
                provider=self.name,
            )
        if any(not isinstance(record, Mapping) for record in raw_records):
            raise AdapterError(
                "Compliance API data list contained a non-object record",
                provider=self.name,
            )
        if any(
            not isinstance(record.get("id"), str) or not record.get("id")
            for record in raw_records
        ):
            raise AdapterError(
                "Compliance API data list contained an invalid artifact ID",
                provider=self.name,
            )
        return tuple(raw_records)

    def _retained_code_versions(
        self,
        record: Mapping[str, Any],
    ) -> Tuple[Mapping[str, Any], ...]:
        raw_versions = record.get("versions")
        if not isinstance(raw_versions, list):
            raise AdapterError(
                "Code Artifact record returned an invalid versions list",
                provider=self.name,
            )

        versions: List[Mapping[str, Any]] = []
        seen_ids = set()
        for item in raw_versions:
            if not isinstance(item, Mapping):
                raise AdapterError(
                    "Code Artifact versions list contained a non-object entry",
                    provider=self.name,
                )
            version_id = item.get("id")
            if not isinstance(version_id, str) or not version_id:
                raise AdapterError(
                    "Code Artifact versions list contained an invalid version ID",
                    provider=self.name,
                )
            if version_id in seen_ids:
                raise AdapterError(
                    "Code Artifact versions list contained a duplicate version ID",
                    provider=self.name,
                )
            seen_ids.add(version_id)
            versions.append(item)
        return tuple(versions)

    def _model_metadata(self, value: Mapping[str, Any]) -> Mapping[str, Any]:
        sanitized = safe_json_value(value)
        if not isinstance(sanitized, Mapping):  # defensive against future sanitizer changes
            raise AdapterError(
                "Compliance API metadata could not be sanitized",
                provider=self.name,
            )
        return sanitized

    @staticmethod
    def _updated_filters(
        updated_at: Optional[Mapping[str, str]],
        *,
        updated_at_gt: Optional[str],
        updated_at_gte: Optional[str],
        updated_at_lt: Optional[str],
        updated_at_lte: Optional[str],
    ) -> Mapping[str, str]:
        values: Dict[str, str] = {}
        if updated_at is not None:
            for operator, value in updated_at.items():
                if operator not in _UPDATED_AT_OPERATORS:
                    raise ValueError("updated_at supports only gt, gte, lt, and lte")
                if value is not None:
                    values[operator] = str(value)
        explicit = {
            "gt": updated_at_gt,
            "gte": updated_at_gte,
            "lt": updated_at_lt,
            "lte": updated_at_lte,
        }
        for operator, value in explicit.items():
            if value is not None:
                values[operator] = str(value)
        return values

    def _iter_code_artifact_records(
        self,
        *,
        limit: int = 100,
        organization_ids: Optional[Iterable[str]] = None,
        user_ids: Optional[Iterable[str]] = None,
        organization_id: Optional[str] = None,
        user_id: Optional[str] = None,
        updated_at: Optional[Mapping[str, str]] = None,
        updated_at_gt: Optional[str] = None,
        updated_at_gte: Optional[str] = None,
        updated_at_lt: Optional[str] = None,
        updated_at_lte: Optional[str] = None,
        page: Optional[str] = None,
    ) -> Iterator[Mapping[str, Any]]:
        """Yield validated raw Code Artifact records for internal operations.

        ``limit`` is the API's per-page limit, not a total-result limit.  The
        iterator follows ``next_page`` whenever it is a non-empty string,
        regardless of page length or ``has_more``, up to the adapter's
        configured ``max_pages`` safety bound.
        """

        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("Compliance API page limit must be between 1 and 100")
        page_limit = limit
        organizations = _normalise_ids(organization_ids, organization_id)
        users = _normalise_ids(user_ids, user_id)
        if len(organizations) > 500:
            raise ValueError("organization_ids accepts at most 500 values")
        if len(users) > 200:
            raise ValueError("user_ids accepts at most 200 values")
        updated = self._updated_filters(
            updated_at,
            updated_at_gt=updated_at_gt,
            updated_at_gte=updated_at_gte,
            updated_at_lt=updated_at_lt,
            updated_at_lte=updated_at_lte,
        )

        token = page
        seen_token_digests = set()
        if page is not None:
            if not isinstance(page, str):
                raise ValueError("Compliance API page token must be a string")
            encoded_page = None
            try:
                encoded_page = page.encode("utf-8")
            except UnicodeEncodeError:
                pass
            if encoded_page is None:
                raise ValueError("Compliance API page token must be valid UTF-8")
            if len(encoded_page) > _MAX_PAGE_TOKEN_BYTES:
                raise ValueError(
                    "Compliance API page token exceeds the %d-byte limit"
                    % _MAX_PAGE_TOKEN_BYTES
                )
            seen_token_digests.add(hashlib.sha256(encoded_page).digest())
        pages_fetched = 0
        while True:
            query: List[Tuple[str, str]] = [("limit", str(page_limit))]
            query.extend(("organization_ids[]", item) for item in organizations)
            query.extend(("user_ids[]", item) for item in users)
            query.extend(("updated_at.%s" % operator, updated[operator]) for operator in sorted(updated))
            if token is not None:
                query.append(("page", str(token)))

            payload = self._get_json(_CODE_ARTIFACTS_PATH, query)
            records = self._page_records(payload)
            pages_fetched += 1
            for record in records:
                yield dict(record)

            next_page = payload.get("next_page") if "next_page" in payload else None
            if next_page is None or next_page == "":
                return
            if not isinstance(next_page, str):
                raise AdapterError(
                    "Compliance API returned a non-string next_page token",
                    provider=self.name,
                )
            encoded_next_page = None
            try:
                encoded_next_page = next_page.encode("utf-8")
            except UnicodeEncodeError:
                pass
            if encoded_next_page is None:
                raise AdapterError(
                    "Compliance API returned an invalid pagination token",
                    provider=self.name,
                )
            if len(encoded_next_page) > _MAX_PAGE_TOKEN_BYTES:
                raise AdapterError(
                    "Compliance API pagination token exceeds the configured byte limit",
                    provider=self.name,
                )
            next_page_digest = hashlib.sha256(encoded_next_page).digest()
            if next_page_digest in seen_token_digests:
                raise AdapterError(
                    "Compliance API repeated a pagination token",
                    provider=self.name,
                )
            if pages_fetched >= self._max_pages:
                raise AdapterError(
                    "Compliance API exceeded the configured pagination limit",
                    provider=self.name,
                )
            seen_token_digests.add(next_page_digest)
            token = next_page

    def iter_code_artifact_records(
        self,
        *,
        limit: int = 100,
        organization_ids: Optional[Iterable[str]] = None,
        user_ids: Optional[Iterable[str]] = None,
        organization_id: Optional[str] = None,
        user_id: Optional[str] = None,
        updated_at: Optional[Mapping[str, str]] = None,
        updated_at_gt: Optional[str] = None,
        updated_at_gte: Optional[str] = None,
        updated_at_lt: Optional[str] = None,
        updated_at_lte: Optional[str] = None,
        page: Optional[str] = None,
    ) -> Iterator[Mapping[str, Any]]:
        """Yield sanitized records while preserving benign unknown fields."""

        for record in self._iter_code_artifact_records(
            limit=limit,
            organization_ids=organization_ids,
            user_ids=user_ids,
            organization_id=organization_id,
            user_id=user_id,
            updated_at=updated_at,
            updated_at_gt=updated_at_gt,
            updated_at_gte=updated_at_gte,
            updated_at_lt=updated_at_lt,
            updated_at_lte=updated_at_lte,
            page=page,
        ):
            yield self._model_metadata(record)

    # The shorter name is useful for direct integrations.
    iter_code_artifacts = iter_code_artifact_records

    def list_code_artifact_records(self, **filters: Any) -> List[Mapping[str, Any]]:
        return list(self.iter_code_artifact_records(**filters))

    list_code_artifacts = list_code_artifact_records

    def list_artifacts(self, limit: Optional[int] = None) -> List[Artifact]:
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
                raise ValueError("limit must be an integer between 0 and 100")
            if limit == 0:
                return []
            if limit > 100:
                raise ValueError("Compliance adapter limit cannot exceed 100")
            total_limit = limit
            page_limit = total_limit
        else:
            total_limit = None
            page_limit = 100

        results: List[Artifact] = []
        seen_artifact_ids = set()
        for record in self._iter_code_artifact_records(limit=page_limit):
            artifact = self._artifact_from_code_record(record)
            if artifact.artifact_id in seen_artifact_ids:
                continue
            seen_artifact_ids.add(artifact.artifact_id)
            results.append(artifact)
            if total_limit is not None and len(results) >= total_limit:
                break
        return results

    def _artifact_from_code_record(self, record: Mapping[str, Any]) -> Artifact:
        raw_versions = self._retained_code_versions(record)
        artifact_id = _string_or_none(record.get("id"))
        if not artifact_id:
            raise AdapterError(
                "Code Artifact record omitted a valid artifact ID",
                provider=self.name,
            )
        published = _string_or_none(record.get("published_version_id"))
        selected = None
        if published:
            selected = next((item for item in raw_versions if item.get("id") == published), None)
        if selected is None and raw_versions:
            selected = raw_versions[0]
        title = _string_or_none(selected.get("name")) if selected is not None else None
        user = _mapping(record.get("user"))
        owner = _string_or_none(user.get("email_address")) or _string_or_none(record.get("owner_user_id"))
        return Artifact(
            provider="compliance",
            artifact_id=artifact_id,
            title=title,
            visibility=_string_or_none(record.get("read_mode")),
            # The API names only the version served to non-owners.  It does
            # not expose a distinct owner-live version, so do not infer one.
            live_version=None,
            published_version=published,
            updated_at=_string_or_none(record.get("updated_at")),
            owner=owner,
            kind="code",
            metadata=self._model_metadata(record),
        )

    def _validate_ref(self, ref: ArtifactRef) -> None:
        if ref.provider != self.name:
            raise AdapterError(
                "Artifact reference belongs to a different provider",
                provider=self.name,
            )

    @staticmethod
    def _standard_version_id(ref: ArtifactRef, explicit: Optional[str] = None) -> str:
        if explicit and ref.version and explicit != ref.version:
            raise VersionNotFoundError(
                "Requested version conflicts with the exact Artifact reference",
                provider="compliance",
            )
        if explicit:
            return explicit
        if ref.version:
            return ref.version
        if ref.artifact_id.startswith("claude_artifact_version_"):
            return ref.artifact_id
        raise VersionNotFoundError(
            "A standard Artifact requires a claude_artifact_version_* ID",
            provider="compliance",
        )

    def inspect(self, ref: ArtifactRef) -> Artifact:
        self._validate_ref(ref)
        if ref.kind == "standard" or ref.artifact_id.startswith("claude_artifact_version_"):
            metadata = self._get_standard_artifact_metadata(self._standard_version_id(ref))
            return self._artifact_from_standard_metadata(metadata)

        return self._artifact_from_code_record(
            self._find_code_artifact_record(ref.artifact_id)
        )

    def _find_code_artifact_record(self, artifact_id: str) -> Mapping[str, Any]:
        for record in self._iter_code_artifact_records(limit=100):
            if record.get("id") == artifact_id:
                return record
        raise NotFoundError("Code Artifact was not found", provider=self.name, status=404)

    def versions(self, ref: ArtifactRef) -> List[ArtifactVersion]:
        self._validate_ref(ref)
        if ref.kind == "standard" or ref.artifact_id.startswith("claude_artifact_version_"):
            metadata = self._get_standard_artifact_metadata(self._standard_version_id(ref))
            artifact = self._artifact_from_standard_metadata(metadata)
            version_id = _string_or_none(metadata.get("version_id")) or self._standard_version_id(ref)
            return [
                ArtifactVersion(
                    provider=self.name,
                    artifact_id=artifact.artifact_id,
                    version_id=version_id,
                    created_at=_string_or_none(metadata.get("created_at")),
                    metadata=self._model_metadata(metadata),
                )
            ]

        record = self._find_code_artifact_record(ref.artifact_id)
        raw_versions = self._retained_code_versions(record)
        artifact = self._artifact_from_code_record(record)
        values: List[ArtifactVersion] = []
        for item in raw_versions:
            version_id = item["id"]
            values.append(
                ArtifactVersion(
                    provider=self.name,
                    artifact_id=artifact.artifact_id,
                    version_id=version_id,
                    created_at=_string_or_none(item.get("created_at")),
                    is_live=False,
                    is_published=version_id == artifact.published_version,
                    metadata=self._model_metadata(item),
                )
            )
        return values

    def _download_code_artifact_version(
        self,
        artifact_id: str,
        version_id: str,
    ) -> Tuple[bytes, str, str]:
        path = "%s/%s/versions/%s" % (
            _CODE_ARTIFACTS_PATH,
            urllib.parse.quote(str(artifact_id), safe=""),
            urllib.parse.quote(str(version_id), safe=""),
        )
        data, headers, url = self._get_bytes(path)
        media_type = _header(headers, "Content-Type") or "application/octet-stream"
        return data, media_type, url

    def download_code_artifact_version(self, artifact_id: str, version_id: str) -> bytes:
        """Download and validate the exact retained Code Artifact version."""

        return self._download_code_artifact_version(artifact_id, version_id)[0]

    retrieve_code_artifact_version = download_code_artifact_version

    def _get_standard_artifact_metadata(self, artifact_version_id: str) -> Mapping[str, Any]:
        path = "%s/%s" % (
            _STANDARD_ARTIFACTS_PATH,
            urllib.parse.quote(str(artifact_version_id), safe=""),
        )
        metadata = dict(self._get_json(path))
        self._validate_standard_metadata(metadata, artifact_version_id)
        return metadata

    def _validate_standard_metadata(
        self,
        metadata: Any,
        artifact_version_id: str,
    ) -> Mapping[str, Any]:
        if not isinstance(metadata, Mapping):
            raise IntegrityError(
                "Standard Artifact metadata had an invalid shape",
                provider=self.name,
            )
        stable_id = metadata.get("id")
        if not isinstance(stable_id, str) or not stable_id:
            raise IntegrityError(
                "Standard Artifact metadata omitted a valid artifact ID",
                provider=self.name,
            )
        returned_version = metadata.get("version_id")
        if (
            not isinstance(returned_version, str)
            or not returned_version
            or returned_version != artifact_version_id
        ):
            raise IntegrityError(
                "Standard Artifact metadata did not match the requested version ID",
                provider=self.name,
            )
        expected_md5 = metadata.get("md5")
        if not isinstance(expected_md5, str) or not re.fullmatch(r"[0-9a-f]{32}", expected_md5):
            raise IntegrityError(
                "Standard Artifact metadata omitted a valid lowercase MD5",
                provider=self.name,
            )
        expected_size = metadata.get("size_bytes")
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
        ):
            raise IntegrityError(
                "Standard Artifact metadata omitted a valid byte size",
                provider=self.name,
            )
        if expected_size > self._max_response_bytes:
            raise ResponseTooLargeError(
                "Artifact metadata exceeds the configured byte limit",
                provider=self.name,
            )
        return metadata

    def get_standard_artifact_metadata(self, artifact_version_id: str) -> Mapping[str, Any]:
        """Return sanitized exact-version metadata with benign unknowns intact."""

        metadata = self._get_standard_artifact_metadata(artifact_version_id)
        return self._model_metadata(metadata)

    # Verb aliases matching the endpoint's documentation language.
    retrieve_standard_artifact_metadata = get_standard_artifact_metadata

    def _download_standard_artifact_content(
        self,
        artifact_version_id: str,
        *,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[bytes, str, str]:
        if metadata is None:
            metadata = self._get_standard_artifact_metadata(artifact_version_id)
        else:
            metadata = self._validate_standard_metadata(metadata, artifact_version_id)
        expected_md5 = metadata["md5"]
        expected_size = metadata["size_bytes"]
        path = "%s/%s/content" % (
            _STANDARD_ARTIFACTS_PATH,
            urllib.parse.quote(str(artifact_version_id), safe=""),
        )
        data, headers, url = self._get_bytes(
            path,
            expected_md5_hex=expected_md5,
            expected_size=expected_size,
        )
        metadata_type = _string_or_none(metadata.get("artifact_type")) if metadata else None
        media_type = _header(headers, "Content-Type") or metadata_type or "text/plain; charset=utf-8"
        return data, media_type, url

    def download_standard_artifact_content(
        self,
        artifact_version_id: str,
        *,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> bytes:
        """Download standard Artifact text after validating exact metadata."""

        return self._download_standard_artifact_content(
            artifact_version_id,
            metadata=metadata,
        )[0]

    retrieve_standard_artifact_content = download_standard_artifact_content

    def _artifact_from_standard_metadata(self, metadata: Mapping[str, Any]) -> Artifact:
        stable_id = _string_or_none(metadata.get("id"))
        version_id = _string_or_none(metadata.get("version_id"))
        if not stable_id or not version_id:
            raise AdapterError(
                "Standard Artifact metadata omitted its IDs",
                provider="compliance",
            )
        return Artifact(
            provider="compliance",
            artifact_id=stable_id,
            title=_string_or_none(metadata.get("title")),
            created_at=_string_or_none(metadata.get("created_at")),
            kind="standard",
            metadata=self._model_metadata(metadata),
        )

    @staticmethod
    def _suggested_name(title: Optional[str], artifact_id: str, media_type: str) -> str:
        base = redact_text((title or artifact_id).strip() or artifact_id)
        base = _SAFE_NAME_RE.sub("_", base).strip(" .") or artifact_id
        base = base[:180].rstrip(" .") or artifact_id
        bare_media_type = media_type.split(";", 1)[0].strip().lower()
        extension = {
            "text/html": ".html",
            "text/markdown": ".md",
            "text/plain": ".txt",
            "application/json": ".json",
        }.get(bare_media_type, "")
        if extension and not base.lower().endswith(extension):
            base += extension
        return base

    def fetch(self, ref: ArtifactRef, version: str) -> FetchedArtifact:
        self._validate_ref(ref)
        if ref.kind == "standard" or ref.artifact_id.startswith("claude_artifact_version_"):
            version_id = self._standard_version_id(ref, version)
            metadata = self._get_standard_artifact_metadata(version_id)
            artifact = self._artifact_from_standard_metadata(metadata)
            canonical_version = _string_or_none(metadata.get("version_id")) or version_id
            data, media_type, source_url = self._download_standard_artifact_content(
                version_id,
                metadata=metadata,
            )
            artifact_version = ArtifactVersion(
                provider=self.name,
                artifact_id=artifact.artifact_id,
                version_id=canonical_version,
                created_at=_string_or_none(metadata.get("created_at")),
                metadata=self._model_metadata(metadata),
            )
        else:
            version_id = version or ref.version
            if not version_id:
                raise VersionNotFoundError(
                    "An exact Code Artifact version ID is required",
                    provider=self.name,
                )
            if ref.version and version_id != ref.version:
                raise VersionNotFoundError(
                    "Requested version conflicts with the exact Artifact reference",
                    provider=self.name,
                )
            data, media_type, source_url = self._download_code_artifact_version(
                ref.artifact_id,
                version_id,
            )
            artifact = Artifact(
                provider=self.name,
                artifact_id=ref.artifact_id,
                kind="code",
            )
            artifact_version = ArtifactVersion(
                provider=self.name,
                artifact_id=ref.artifact_id,
                version_id=version_id,
            )

        representation = Representation(
            label="stored",
            media_type=media_type,
            data=data,
            suggested_name=self._suggested_name(artifact.title, artifact.artifact_id, media_type),
            source_url=source_url,
        )
        return FetchedArtifact(
            artifact=artifact,
            version=artifact_version,
            representations=(representation,),
            provenance={
                "provider": self.name,
                "api": "anthropic-compliance",
                "exact_version": artifact_version.version_id,
            },
        )


# A concise import name while retaining an explicit class name in help output.
ComplianceAdapter = AnthropicComplianceAdapter


__all__ = ["AnthropicComplianceAdapter", "ComplianceAdapter"]

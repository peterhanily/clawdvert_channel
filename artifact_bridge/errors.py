"""Typed failures raised by the read-only artifact bridge."""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlsplit, urlunsplit


_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)?\s*)[^\s,}\]]+"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+\-/=]+"),
    re.compile(r"(?i)([?&]__frame_t=)[^&#\s]+"),
    re.compile(r"(?i)(\"?(?:asset|oauth|access|refresh|sync|ws|consent|subscription)[_-]?token\"?\s*[:=]\s*\"?)[^\"\s,}\]]+"),
    re.compile(
        r"(?i)(\"?(?:x[\s_-]*api[\s_-]*key|api[\s_-]*key|access[\s_-]*key|"
        r"password|credential|private[\s_-]*key|client[\s_-]*secret|"
        r"static[\s_-]*auth[\s_-]*secret|"
        r"cookie|set-cookie)\"?\s*[:=]\s*\"?)[^\"\s,}\]]+"
    ),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]+"),
)

_PEM_MARKERS = re.compile(
    r"(?P<begin>-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----)|"
    r"(?P<end>-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----)",
    re.IGNORECASE,
)
_HTTP_URL = re.compile(r'''(?i)\bhttps?://[^\s<>"']+''')
_URL_TRAILING_PUNCTUATION = ".,;!)}"
_REDACTED_URL_USERINFO = "redacted"


def _redact_url_credentials(text: str) -> str:
    """Remove URL userinfo and all query/fragment data from diagnostics."""

    def replace(match: re.Match) -> str:
        raw = match.group(0)
        core = raw
        trailing = ""
        while core and core[-1] in _URL_TRAILING_PUNCTUATION:
            trailing = core[-1] + trailing
            core = core[:-1]
        try:
            parsed = urlsplit(core)
            username = parsed.username
            password = parsed.password
        except ValueError:
            return "[REDACTED_URL]" + trailing
        if not (username is not None or password is not None or parsed.query or parsed.fragment):
            return raw
        netloc = parsed.netloc
        if username is not None or password is not None:
            hostname = parsed.hostname or "host"
            if ":" in hostname and not hostname.startswith("["):
                hostname = "[" + hostname + "]"
            try:
                port = parsed.port
            except ValueError:
                port = None
            host_port = hostname + ((":" + str(port)) if port is not None else "")
            # Keep the replacement valid URL userinfo.  Square brackets are
            # reserved for IP literals in a URL authority, so a value such as
            # ``[REDACTED]@host`` is rejected by newer urlsplit versions on a
            # second sanitisation pass.  A valid placeholder makes redaction
            # idempotent across supported Python versions.
            netloc = _REDACTED_URL_USERINFO + "@" + host_port
        sanitized = urlunsplit(
            (
                parsed.scheme,
                netloc,
                parsed.path,
                "[REDACTED]" if parsed.query else "",
                "[REDACTED]" if parsed.fragment else "",
            )
        )
        return sanitized + trailing

    return _HTTP_URL.sub(replace, text)


def _redact_private_key_blocks(text: str) -> str:
    pieces = []
    emitted = 0
    begin_at: Optional[int] = None
    for marker in _PEM_MARKERS.finditer(text):
        if marker.lastgroup == "begin":
            if begin_at is None:
                begin_at = marker.start()
        elif begin_at is not None:
            pieces.append(text[emitted:begin_at])
            pieces.append("[REDACTED]")
            emitted = marker.end()
            begin_at = None
    if begin_at is not None:
        pieces.append(text[emitted:begin_at])
        pieces.append("[REDACTED]")
        emitted = len(text)
    pieces.append(text[emitted:])
    return "".join(pieces)


def redact_text(value: object) -> str:
    """Return text safe for diagnostics without known bearer credentials."""

    text = _redact_url_credentials(_redact_private_key_blocks(str(value)))
    for pattern in _SECRET_PATTERNS:
        if pattern.groups:
            text = pattern.sub(r"\1[REDACTED]", text)
        else:
            text = pattern.sub("[REDACTED]", text)
    return text


class ArtifactBridgeError(Exception):
    """Base class for expected, user-facing bridge failures."""

    exit_code = 1

    def __init__(self, message: str) -> None:
        super().__init__(redact_text(message))


class UsageError(ArtifactBridgeError):
    exit_code = 2


class ReferenceError(UsageError):
    pass


class UnsupportedReferenceError(ReferenceError):
    pass


class AdapterError(ArtifactBridgeError):
    """A provider rejected or could not complete a read operation."""

    def __init__(
        self,
        message: str,
        *,
        provider: Optional[str] = None,
        status: Optional[int] = None,
    ) -> None:
        self.provider = provider
        self.status = status
        prefix = "%s: " % provider if provider else ""
        super().__init__(prefix + message)


class AuthenticationError(AdapterError):
    pass


class NotFoundError(AdapterError):
    pass


class VersionNotFoundError(NotFoundError):
    pass


class StaleVersionError(VersionNotFoundError):
    """The provider once knew a version but no longer retains its bytes."""


class IntegrityError(AdapterError):
    pass


class ResponseTooLargeError(AdapterError):
    pass


class TruncatedResponseError(AdapterError):
    pass


class CollisionError(ArtifactBridgeError):
    pass


class UnsafePathError(ArtifactBridgeError):
    pass


class LockfileError(ArtifactBridgeError):
    pass

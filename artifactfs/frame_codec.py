"""Inert, deterministic Code Artifact transport for ArtifactFS snapshots.

Code Artifacts store one HTML document, not a directory tree.  This codec puts
the canonical bytes of one immutable ArtifactFS snapshot into an inert
``template`` element.  The bytes are compressed before being base64 encoded,
so file content is never interpreted as markup.

Decoding is deliberately stricter than finding a marker with a regular
expression.  It accepts one canonical envelope, verifies its digest, rebuilds
the complete document, and accepts only the exact document or the measured
version-bound provider insertion at the opening ``head`` boundary.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import hmac
import re
import zlib
from dataclasses import dataclass

from clawdvert import frames

from .core import (
    DEFAULT_LIMITS as DEFAULT_SNAPSHOT_LIMITS,
    Snapshot,
    SnapshotLimits,
    decode_snapshot,
    encode_snapshot,
)


FORMAT_VERSION = 1
BEGIN_MARKER = "<!-- clawdvert-artifactfs:v1:begin -->"
END_MARKER = "<!-- clawdvert-artifactfs:v1:end -->"
TEMPLATE_ID = "clawdvert-artifactfs-v1"
TEMPLATE_MARKER = 'id="%s"' % TEMPLATE_ID
ENCODING = "gzip+base64"

_TEMPLATE_PREFIX = (
    '<template id="%s" data-encoding="%s" data-sha256="'
    % (TEMPLATE_ID, ENCODING)
)
_DIGEST_SUFFIX = '">'
_TEMPLATE_SUFFIX = "</template>"
_BLOCK_PREFIX = BEGIN_MARKER + "\n" + _TEMPLATE_PREFIX
_BLOCK_SUFFIX = _TEMPLATE_SUFFIX + "\n" + END_MARKER
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")


class FrameCodecError(ValueError):
    """A served page is not one valid ArtifactFS-managed snapshot."""


@dataclass(frozen=True)
class CodecLimits:
    """Memory and document bounds applied before expanding untrusted input."""

    # A highly compressible snapshot may be larger than the HTML page carrying
    # it.  Keep that expansion finite even though frames.compose separately
    # enforces the provider's 16 MiB document limit.
    max_snapshot_bytes: int = 64 * 1024 * 1024
    max_compressed_bytes: int = frames.MAX_BYTES
    max_served_bytes: int = frames.MAX_BYTES + 300_000

    def __post_init__(self) -> None:
        for name in (
            "max_snapshot_bytes",
            "max_compressed_bytes",
            "max_served_bytes",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError("%s must be a positive integer" % name)


DEFAULT_LIMITS = CodecLimits()


@dataclass(frozen=True)
class DecodedSnapshotBytes:
    """Verified snapshot bytes and the exact authored page that carried them."""

    snapshot_bytes: bytes
    sha256: str
    expected_page: str
    compressed_bytes: int


def render_snapshot_page(
    snapshot: Snapshot,
    *,
    snapshot_limits: SnapshotLimits = DEFAULT_SNAPSHOT_LIMITS,
    codec_limits: CodecLimits = DEFAULT_LIMITS,
) -> str:
    """Render one structured snapshot as an inert Code Artifact page."""

    serialized = encode_snapshot(snapshot, limits=snapshot_limits).encode("utf-8")
    return render_snapshot_bytes(serialized, limits=codec_limits)


def recover_snapshot_page(
    served_html: str,
    version: str,
    *,
    snapshot_limits: SnapshotLimits = DEFAULT_SNAPSHOT_LIMITS,
    codec_limits: CodecLimits = DEFAULT_LIMITS,
) -> Snapshot:
    """Recover and validate one ArtifactFS-managed structured snapshot."""

    decoded = recover_snapshot_bytes(served_html, version, limits=codec_limits)
    snapshot = decode_snapshot(decoded.snapshot_bytes, limits=snapshot_limits)
    if snapshot.sha256 != decoded.sha256:
        raise FrameCodecError("snapshot and frame digests do not match")
    return snapshot


def render_snapshot_bytes(
    snapshot_bytes: bytes, *, limits: CodecLimits = DEFAULT_LIMITS
) -> str:
    """Render canonical serialized snapshot bytes as one complete HTML page."""

    raw = _validate_snapshot_bytes(snapshot_bytes, limits)
    packed = _canonical_gzip(raw)
    if len(packed) > limits.max_compressed_bytes:
        raise FrameCodecError("compressed snapshot exceeds the codec limit")
    payload = base64.b64encode(packed).decode("ascii")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        return frames.compose(_render_body(digest, payload))
    except frames.FrameError as exc:
        raise FrameCodecError("snapshot envelope exceeds the Code Artifact limit") from exc


def recover_snapshot_bytes(
    served_html: str,
    version: str,
    *,
    limits: CodecLimits = DEFAULT_LIMITS,
) -> DecodedSnapshotBytes:
    """Recover one snapshot from an exact or provider-wrapped served page.

    ``version`` binds the accepted head-inserted runtime to the version being
    read.  No HTML is executed and arbitrary pages containing a lookalike
    payload are rejected because the complete canonical page is reconstructed
    and compared.
    """

    _validate_served_input(served_html, version, limits)
    block = _extract_unique_block(served_html)
    digest, payload = _parse_block(block)

    # Reject oversized input before allocating decoded or decompressed buffers.
    if len(payload) > _max_base64_chars(limits.max_compressed_bytes):
        raise FrameCodecError("encoded snapshot exceeds the codec limit")
    if not payload or len(payload) % 4 or not _BASE64_RE.fullmatch(payload):
        raise FrameCodecError("snapshot payload is not canonical base64")
    try:
        packed = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FrameCodecError("snapshot payload is not valid base64") from exc
    if base64.b64encode(packed).decode("ascii") != payload:
        raise FrameCodecError("snapshot payload is not canonical base64")
    if len(packed) > limits.max_compressed_bytes:
        raise FrameCodecError("compressed snapshot exceeds the codec limit")

    raw = _bounded_gzip_decompress(packed, limits.max_snapshot_bytes)
    if not raw:
        raise FrameCodecError("snapshot serialization is empty")
    actual_digest = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual_digest, digest):
        raise FrameCodecError("snapshot digest mismatch")

    # Bind the deterministic header without assuming that independent zlib
    # releases produce bit-identical DEFLATE blocks. The bounded decoder above
    # already rejects concatenated members, trailing bytes and bad CRC/length.
    if not _has_canonical_gzip_header(packed):
        raise FrameCodecError("snapshot payload is not canonically compressed")

    try:
        expected_page = frames.compose(_render_body(digest, payload))
    except frames.FrameError as exc:
        raise FrameCodecError("snapshot envelope exceeds the Code Artifact limit") from exc
    if not _matches_managed_page(served_html, expected_page, version):
        raise FrameCodecError(
            "served page is not the exact ArtifactFS-managed document"
        )

    return DecodedSnapshotBytes(
        snapshot_bytes=raw,
        sha256=digest,
        expected_page=expected_page,
        compressed_bytes=len(packed),
    )


def _validate_snapshot_bytes(snapshot_bytes: bytes, limits: CodecLimits) -> bytes:
    if not isinstance(snapshot_bytes, bytes):
        raise TypeError("snapshot serialization must be bytes")
    if not snapshot_bytes:
        raise FrameCodecError("snapshot serialization is empty")
    if len(snapshot_bytes) > limits.max_snapshot_bytes:
        raise FrameCodecError("snapshot serialization exceeds the codec limit")
    return snapshot_bytes


def _validate_served_input(
    served_html: str, version: str, limits: CodecLimits
) -> None:
    if not isinstance(served_html, str):
        raise TypeError("served page must be text")
    if not isinstance(version, str) or not version or len(version) > 256:
        raise FrameCodecError("artifact version is invalid")
    try:
        served_size = len(served_html.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise FrameCodecError("served page is not valid UTF-8 text") from exc
    if served_size > limits.max_served_bytes:
        raise FrameCodecError("served page exceeds the codec limit")


def _extract_unique_block(served_html: str) -> str:
    # Fixed marker counts are intentional: a second marker in a provider
    # prefix or authored decoy makes provenance ambiguous and must fail closed.
    if served_html.count(BEGIN_MARKER) != 1:
        raise FrameCodecError("served page must contain one ArtifactFS begin marker")
    if served_html.count(END_MARKER) != 1:
        raise FrameCodecError("served page must contain one ArtifactFS end marker")
    if served_html.count(TEMPLATE_MARKER) != 1:
        raise FrameCodecError("served page must contain one ArtifactFS template")

    start = served_html.find(BEGIN_MARKER)
    finish = served_html.find(END_MARKER)
    if finish < start:
        raise FrameCodecError("ArtifactFS envelope markers are out of order")
    finish += len(END_MARKER)
    return served_html[start:finish]


def _parse_block(block: str) -> tuple[str, str]:
    if not block.startswith(_BLOCK_PREFIX) or not block.endswith(_BLOCK_SUFFIX):
        raise FrameCodecError("ArtifactFS envelope is malformed")
    content = block[len(_BLOCK_PREFIX) : -len(_BLOCK_SUFFIX)]
    # The digest has a fixed width, so no general-purpose HTML parser ever
    # observes untrusted file bytes or decides where the payload ends.
    if len(content) < 64 + len(_DIGEST_SUFFIX):
        raise FrameCodecError("ArtifactFS envelope is truncated")
    digest = content[:64]
    if not _SHA256_RE.fullmatch(digest):
        raise FrameCodecError("ArtifactFS envelope has an invalid digest")
    if content[64 : 64 + len(_DIGEST_SUFFIX)] != _DIGEST_SUFFIX:
        raise FrameCodecError("ArtifactFS envelope is malformed")
    payload = content[64 + len(_DIGEST_SUFFIX) :]
    return digest, payload


def _render_body(digest: str, payload: str) -> str:
    return (
        _BLOCK_PREFIX
        + digest
        + _DIGEST_SUFFIX
        + payload
        + _BLOCK_SUFFIX
    )


def _canonical_gzip(raw: bytes) -> bytes:
    packed = bytearray(gzip.compress(raw, compresslevel=9, mtime=0))
    # Python 3.11 and 3.12 may inherit zlib's platform OS byte when mtime is
    # zero.  It is informational, so normalize it to gzip's unknown value.
    if len(packed) >= 10:
        packed[9] = 255
    return bytes(packed)


def _has_canonical_gzip_header(packed: bytes) -> bool:
    # RFC 1952 fixed header: deflate, no optional fields, zero timestamp,
    # maximum-compression hint, and normalized unknown OS byte.
    return (
        len(packed) >= 18
        and packed[:4] == b"\x1f\x8b\x08\x00"
        and packed[4:8] == b"\x00\x00\x00\x00"
        and packed[8:10] == b"\x02\xff"
    )


def _matches_managed_page(served: str, expected_page: str, version: str) -> bool:
    # These are public document bytes, not secrets; ordinary equality also
    # handles non-ASCII authored prefixes without compare_digest TypeErrors.
    if served == expected_page:
        return True

    head = expected_page.find("<head")
    if head < 0 or not expected_page.startswith("<!doctype html><html><head"):
        return False
    split = head + len("<head")
    prefix = expected_page[:split]
    tail = expected_page[split:]
    if not tail or not served.startswith(prefix) or not served.endswith(tail):
        return False
    runtime = served[split : -len(tail)]
    runtime_start = (
        '><!-- frame-runtime --><base href="/_f/%s/">'
        '<script>window.__FRAME_PREAMBLE=' % version
    )
    return (
        len(runtime.encode("utf-8")) <= 262_144
        and runtime.startswith(runtime_start)
        and runtime.endswith("</script><!-- /frame-runtime --")
    )


def _bounded_gzip_decompress(packed: bytes, maximum: int) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw = decoder.decompress(packed, maximum + 1)
    except zlib.error as exc:
        raise FrameCodecError("snapshot payload is not valid gzip") from exc
    if len(raw) > maximum or decoder.unconsumed_tail:
        raise FrameCodecError("expanded snapshot exceeds the codec limit")
    if not decoder.eof:
        raise FrameCodecError("snapshot gzip stream is truncated")
    if decoder.unused_data:
        raise FrameCodecError("snapshot gzip stream has trailing data")
    try:
        tail = decoder.flush(maximum - len(raw) + 1)
    except zlib.error as exc:
        raise FrameCodecError("snapshot payload is not valid gzip") from exc
    if len(raw) + len(tail) > maximum:
        raise FrameCodecError("expanded snapshot exceeds the codec limit")
    return raw + tail


def _max_base64_chars(maximum_bytes: int) -> int:
    return 4 * ((maximum_bytes + 2) // 3)

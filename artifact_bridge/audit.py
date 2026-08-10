"""Offline integrity and secret-safety checks for artifact bridge bundles."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from .errors import redact_text
from .fs_safety import FilesystemEntryLimitError, iter_bounded_tree
from .json_safety import strict_json_loads, validate_json_text
from .models import is_sensitive_key
from .store import (
    DEFAULT_MAX_REPRESENTATION_BYTES,
    DEFAULT_MAX_TOTAL_BYTES,
    LOCK_NAME,
    LOCK_SCHEMA_VERSION,
    MAX_LOCK_BYTES,
)


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_AUDIT_VERSIONS = 1024
MAX_AUDIT_REPRESENTATIONS = 4096
MAX_AUDIT_FILES = 8192
MAX_AUDIT_JSON_DEPTH = 64
MAX_AUDIT_STRUCTURE_NODES = 65536
MAX_AUDIT_PATH_BYTES = 4096
MAX_AUDIT_PATH_COMPONENTS = 64
MAX_STATIC_INSPECTION_BYTES = 256 * 1024
MAX_AUDIT_ISSUES = 1024

_TEXT_MEDIA_TYPES = frozenset(
    (
        "application/javascript",
        "application/json",
        "application/ld+json",
        "application/xhtml+xml",
        "application/xml",
        "image/svg+xml",
    )
)
_TEXT_EXTENSIONS = (".css", ".htm", ".html", ".js", ".json", ".md", ".svg", ".txt", ".xml")
_STATIC_INDICATORS: Tuple[Tuple[str, str, re.Pattern], ...] = (
    ("script", "contains an executable script block", re.compile(r"<script\b", re.I)),
    (
        "inline-handler",
        "contains an inline browser event handler",
        re.compile(r"\bon[a-z][a-z0-9_-]*\s*=", re.I),
    ),
    (
        "external-resource",
        "contains an active markup reference to an external HTTP resource",
        re.compile(
            r"<(?:audio|form|iframe|img|link|script|source|video)\b[^<>]*"
            r"(?:action|href|src)\s*=\s*['\"]https?://",
            re.I | re.S,
        ),
    ),
    (
        "network-api",
        "contains a browser network API",
        re.compile(
            r"\b(?:fetch\s*\(|new\s+(?:EventSource|WebSocket|XMLHttpRequest)\b|"
            r"navigator\.sendBeacon\s*\(|RTCPeerConnection\s*\()",
            re.I,
        ),
    ),
    (
        "dynamic-code",
        "contains a dynamic code execution primitive",
        re.compile(r"\b(?:eval\s*\(|new\s+Function\s*\()", re.I),
    ),
    (
        "dom-html-sink",
        "contains a DOM HTML injection sink",
        re.compile(
            r"\b(?:innerHTML|outerHTML)\s*=|\binsertAdjacentHTML\s*\(|"
            r"\bdocument\.write(?:ln)?\s*\(",
            re.I,
        ),
    ),
    (
        "browser-storage",
        "contains browser storage or cookie access",
        re.compile(r"\b(?:localStorage|sessionStorage|indexedDB|document\.cookie)\b", re.I),
    ),
    (
        "embedded-context",
        "contains an iframe or form",
        re.compile(r"<(?:iframe|form)\b", re.I),
    ),
    (
        "prompt-instruction",
        "contains language commonly used in prompt-injection instructions",
        re.compile(
            r"\b(?:ignore (?:all |any )?(?:previous|prior) instructions|"
            r"system message|developer message|do not tell the user|"
            r"reveal (?:your )?(?:prompt|instructions))\b",
            re.I,
        ),
    ),
)


@dataclass(frozen=True)
class AuditIssue:
    code: str
    message: str
    path: Optional[str] = None
    severity: str = "error"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": redact_text(self.message),
            "path": redact_text(self.path) if self.path is not None else None,
            "severity": self.severity,
        }


class _IssueCollector(list):
    """Keep machine-readable audit output bounded even for hostile locks."""

    def __init__(self) -> None:
        super().__init__()
        self._truncated = False

    def append(self, issue: AuditIssue) -> None:
        if self._truncated:
            return
        if len(self) >= MAX_AUDIT_ISSUES - 1:
            super().append(
                AuditIssue(
                    "limit",
                    "audit issue output was truncated at %d entries"
                    % MAX_AUDIT_ISSUES,
                )
            )
            self._truncated = True
            return
        super().append(issue)


@dataclass(frozen=True)
class AuditReport:
    ok: bool
    root: str
    lockfile: str
    representations: int
    total_bytes: int
    issues: tuple

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "root": redact_text(self.root),
            "lockfile": redact_text(self.lockfile),
            "representations": self.representations,
            "total_bytes": self.total_bytes,
            "issues": [issue.to_dict() for issue in self.issues],
        }


def audit_bundle(
    path: os.PathLike,
    *,
    max_representation_bytes: int = DEFAULT_MAX_REPRESENTATION_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> AuditReport:
    if (
        isinstance(max_representation_bytes, bool)
        or not isinstance(max_representation_bytes, int)
        or max_representation_bytes <= 0
        or isinstance(max_total_bytes, bool)
        or not isinstance(max_total_bytes, int)
        or max_total_bytes <= 0
    ):
        raise ValueError("audit byte limits must be positive integers")
    supplied = Path(path)
    lock_path = supplied if supplied.name == LOCK_NAME else supplied / LOCK_NAME
    root = lock_path.parent
    issues: List[AuditIssue] = _IssueCollector()
    representations = 0
    total_bytes = 0
    tracked: Set[str] = set()
    tracked_folded: Dict[str, str] = {}
    exhausted = False

    if root.is_symlink() or lock_path.is_symlink() or not lock_path.is_file():
        issues.append(AuditIssue("lock-missing", "artifact.lock.json is missing or not a regular file"))
        return AuditReport(False, str(root), str(lock_path), 0, 0, tuple(issues))
    try:
        info = lock_path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_LOCK_BYTES:
            raise ValueError("lockfile is not a bounded regular file")
        raw, _opened_info = _read_bounded_regular(lock_path, MAX_LOCK_BYTES)
        text = raw.decode("utf-8")
    except (OSError, OverflowError, UnicodeDecodeError, ValueError) as exc:
        issues.append(AuditIssue("lock-invalid", "could not parse lockfile: %s" % redact_text(exc)))
        return AuditReport(False, str(root), str(lock_path), 0, 0, tuple(issues))

    try:
        validate_json_text(
            text,
            max_depth=MAX_AUDIT_JSON_DEPTH,
            max_nodes=MAX_AUDIT_STRUCTURE_NODES,
        )
    except ValueError as exc:
        issues.append(
            AuditIssue(
                "limit",
                "lockfile exceeds structural audit limits: %s" % redact_text(exc),
            )
        )
        return AuditReport(False, str(root), str(lock_path), 0, 0, tuple(issues))
    try:
        data = strict_json_loads(text)
    except (ValueError, RecursionError) as exc:
        issues.append(AuditIssue("lock-invalid", "could not parse lockfile: %s" % redact_text(exc)))
        return AuditReport(False, str(root), str(lock_path), 0, 0, tuple(issues))

    if redact_text(text) != text:
        issues.append(AuditIssue("credential", "lockfile contains a bearer-shaped credential"))
    _find_sensitive_keys(data, issues)
    artifact_identity: Optional[Tuple[str, str]] = None
    if (
        not isinstance(data, Mapping)
        or isinstance(data.get("schema_version"), bool)
        or not isinstance(data.get("schema_version"), int)
        or data.get("schema_version") != LOCK_SCHEMA_VERSION
    ):
        issues.append(AuditIssue("schema", "unsupported artifact lock schema"))
        versions = []
    else:
        artifact = data.get("artifact")
        if not isinstance(artifact, Mapping):
            issues.append(AuditIssue("schema", "lockfile artifact must be an object"))
        else:
            provider = artifact.get("provider")
            artifact_id = artifact.get("artifact_id")
            kind = artifact.get("kind")
            if not _valid_identity(provider):
                issues.append(AuditIssue("schema", "invalid artifact provider"))
            if not _valid_identity(artifact_id):
                issues.append(AuditIssue("schema", "invalid artifact ID"))
            if not _valid_identity(kind):
                issues.append(AuditIssue("schema", "invalid artifact kind"))
            if all(_valid_identity(value) for value in (provider, artifact_id, kind)):
                artifact_identity = (provider, artifact_id)
        versions = data.get("versions")
        if not isinstance(versions, list) or not versions:
            issues.append(AuditIssue("schema", "lockfile versions must be a non-empty array"))
            versions = []
        elif len(versions) > MAX_AUDIT_VERSIONS:
            issues.append(
                AuditIssue(
                    "limit",
                    "lockfile exceeds the %d version audit limit" % MAX_AUDIT_VERSIONS,
                )
            )
            versions = versions[:MAX_AUDIT_VERSIONS]

    seen_labels = set()
    seen_version_ids = set()
    for version in versions:
        if not isinstance(version, Mapping):
            issues.append(AuditIssue("schema", "invalid version entry"))
            continue
        version_id = version.get("version_id")
        provider = version.get("provider")
        artifact_id = version.get("artifact_id")
        if not _valid_identity(version_id):
            issues.append(AuditIssue("schema", "invalid version ID"))
            continue
        if version_id in seen_version_ids:
            issues.append(AuditIssue("duplicate-version", "duplicate version ID in lockfile"))
        seen_version_ids.add(version_id)
        if not _valid_identity(provider) or not _valid_identity(artifact_id):
            issues.append(AuditIssue("schema", "invalid version artifact identity"))
            continue
        if artifact_identity is not None and (provider, artifact_id) != artifact_identity:
            issues.append(AuditIssue("schema", "version artifact identity does not match lockfile"))
        reps = version.get("representations")
        if not isinstance(reps, list) or not reps:
            issues.append(AuditIssue("schema", "version representations must be a non-empty array"))
            continue
        for rep in reps:
            if representations >= MAX_AUDIT_REPRESENTATIONS:
                if not exhausted:
                    issues.append(
                        AuditIssue(
                            "limit",
                            "lockfile exceeds the %d representation audit limit"
                            % MAX_AUDIT_REPRESENTATIONS,
                        )
                    )
                exhausted = True
                break
            representations += 1
            if not isinstance(rep, Mapping):
                issues.append(AuditIssue("schema", "invalid representation entry"))
                continue
            label = rep.get("label")
            if not _valid_identity(label):
                issues.append(AuditIssue("schema", "invalid representation label"))
                continue
            label_key = (version_id, label)
            if label_key in seen_labels:
                issues.append(AuditIssue("duplicate", "duplicate representation label in version"))
            seen_labels.add(label_key)
            supplied_relative = rep.get("path")
            path_details = _relative_path_details(supplied_relative)
            if path_details is None:
                issue_path = supplied_relative if isinstance(supplied_relative, str) else None
                issues.append(AuditIssue("path", "unsafe representation path", issue_path))
                continue
            relative, is_canonical = path_details
            folded = _path_collision_key(relative)
            if folded in tracked_folded:
                issues.append(
                    AuditIssue(
                        "duplicate-path",
                        "representation path aliases another lock entry",
                        relative,
                    )
                )
                if not is_canonical:
                    issues.append(
                        AuditIssue(
                            "path",
                            "representation path is not in canonical POSIX form",
                            supplied_relative,
                        )
                    )
                continue
            if not is_canonical:
                issues.append(
                    AuditIssue(
                        "path",
                        "representation path is not in canonical POSIX form",
                        supplied_relative,
                    )
                )
                continue
            tracked_folded[folded] = relative
            tracked.add(relative)
            target = root.joinpath(*PurePosixPath(relative).parts)
            unsafe_parent = _unsafe_parent(root, target.parent)
            if unsafe_parent is not None:
                issues.append(
                    AuditIssue(
                        "path",
                        "representation has a symlinked or non-directory parent",
                        unsafe_parent,
                    )
                )
                continue
            try:
                file_info = target.lstat()
            except OSError:
                issues.append(AuditIssue("missing", "representation file is missing", relative))
                continue
            if stat.S_ISLNK(file_info.st_mode) or not stat.S_ISREG(file_info.st_mode):
                issues.append(AuditIssue("path", "representation is not a regular file", relative))
                continue
            if file_info.st_size > max_representation_bytes:
                issues.append(
                    AuditIssue(
                        "limit",
                        "representation exceeds the %d byte audit limit"
                        % max_representation_bytes,
                        relative,
                    )
                )
                continue
            if total_bytes + file_info.st_size > max_total_bytes:
                issues.append(
                    AuditIssue(
                        "limit",
                        "bundle exceeds the %d byte total audit limit"
                        % max_total_bytes,
                        relative,
                    )
                )
                exhausted = True
                break
            expected_size = rep.get("bytes")
            if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size < 0:
                issues.append(AuditIssue("schema", "invalid byte count", relative))
            elif file_info.st_size != expected_size:
                issues.append(AuditIssue("size", "file size does not match lockfile", relative))
            expected_hash = rep.get("sha256")
            content: Optional[bytes] = None
            if not isinstance(expected_hash, str) or not _SHA256_RE.fullmatch(expected_hash):
                issues.append(AuditIssue("schema", "invalid SHA-256 value", relative))
            else:
                try:
                    content, opened_info = _read_bounded_regular(
                        target, max_representation_bytes
                    )
                except OverflowError:
                    issues.append(
                        AuditIssue(
                            "limit",
                            "representation exceeds the %d byte audit limit"
                            % max_representation_bytes,
                            relative,
                        )
                    )
                    content = None
                except OSError as exc:
                    issues.append(AuditIssue("read", "could not read representation: %s" % exc, relative))
                else:
                    if opened_info.st_size != file_info.st_size:
                        issues.append(
                            AuditIssue("size", "file changed while it was audited", relative)
                        )
                    if hashlib.sha256(content).hexdigest() != expected_hash:
                        issues.append(AuditIssue("sha256", "file hash does not match lockfile", relative))
            if content is not None:
                _inspect_static_content(
                    rep,
                    relative,
                    content,
                    issues,
                )
            total_bytes += file_info.st_size
        if exhausted:
            break

    if root.is_dir():
        try:
            for candidate, is_directory in iter_bounded_tree(root, MAX_AUDIT_FILES):
                relative = candidate.relative_to(root).as_posix()
                if not is_directory and relative != LOCK_NAME and relative not in tracked:
                    issues.append(
                        AuditIssue("untracked", "file is not recorded in lockfile", relative)
                    )
        except FilesystemEntryLimitError as exc:
            issues.append(AuditIssue("limit", str(exc)))
        except OSError as exc:
            issues.append(AuditIssue("read", "could not traverse bundle: %s" % exc))

    return AuditReport(
        not any(issue.severity == "error" for issue in issues),
        str(root),
        str(lock_path),
        representations,
        total_bytes,
        tuple(issues),
    )


def _relative_path_details(value: Any) -> Optional[Tuple[str, bool]]:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return None
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if len(encoded) > MAX_AUDIT_PATH_BYTES:
        return None
    path = PurePosixPath(value)
    normalized = unicodedata.normalize("NFKC", path.as_posix())
    normalized_path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or normalized_path.is_absolute()
        or len(normalized_path.parts) > MAX_AUDIT_PATH_COMPONENTS
        or any(part in ("", ".", "..") for part in path.parts)
        or any(part in ("", ".", "..") for part in normalized_path.parts)
    ):
        return None
    try:
        normalized_bytes = normalized.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if len(normalized_bytes) > MAX_AUDIT_PATH_BYTES:
        return None
    canonical = normalized_path.as_posix()
    return canonical, value == canonical


def _path_collision_key(value: str) -> str:
    return unicodedata.normalize("NFKC", value.casefold())


def _valid_identity(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and redact_text(value) == value


def _unsafe_parent(root: Path, parent: Path) -> Optional[str]:
    current = root
    try:
        parts = parent.relative_to(root).parts
    except ValueError:
        return str(parent)
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return str(current)
        except OSError:
            return str(current)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            return str(current.relative_to(root))
    return None


def _read_bounded_regular(path: Path, limit: int) -> Tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("path is not a regular file")
        if info.st_size > limit:
            raise OverflowError("file exceeds the bounded read limit")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            data = handle.read(limit + 1)
        if len(data) > limit:
            raise OverflowError("file exceeds the bounded read limit")
        if len(data) != info.st_size:
            raise OSError("file size changed during bounded read")
        return data, info
    finally:
        if fd >= 0:
            os.close(fd)


def _inspect_static_content(
    representation: Mapping[str, Any],
    relative: str,
    content: bytes,
    issues: List[AuditIssue],
) -> None:
    full_text = content.decode("utf-8", "replace")
    if redact_text(full_text) != full_text:
        issues.append(
            AuditIssue(
                "content-credential",
                "representation contains a bearer-shaped credential",
                relative,
            )
        )
    media_type = representation.get("media_type")
    bare_media = media_type.split(";", 1)[0].strip().lower() if isinstance(media_type, str) else ""
    textual = bare_media.startswith("text/") or bare_media in _TEXT_MEDIA_TYPES
    if not textual and not relative.lower().endswith(_TEXT_EXTENSIONS):
        prefix = content[:256].lstrip().lower()
        textual = prefix.startswith((b"<!doctype html", b"<html", b"<svg", b"# "))
    if not textual:
        return
    truncated = len(content) > MAX_STATIC_INSPECTION_BYTES
    if truncated:
        issues.append(
            AuditIssue(
                "static-limit",
                "static content inspection was limited to the first %d bytes"
                % MAX_STATIC_INSPECTION_BYTES,
                relative,
                "warning",
            )
        )
    inspected_text = content[:MAX_STATIC_INSPECTION_BYTES].decode("utf-8", "replace")
    for code, message, pattern in _STATIC_INDICATORS:
        if pattern.search(inspected_text):
            issues.append(AuditIssue(code, message, relative, "warning"))


def _find_sensitive_keys(value: Any, issues: List[AuditIssue], location: str = "$") -> None:
    stack = [(value, location)]
    discovered = 1
    while stack:
        current, current_location = stack.pop()
        children = []
        if isinstance(current, Mapping):
            for key, nested in current.items():
                child = _bounded_location(current_location, ".%s" % key)
                if is_sensitive_key(key):
                    issues.append(
                        AuditIssue(
                            "credential-key",
                            "sensitive credential field in lockfile",
                            child,
                        )
                    )
                if discovered >= MAX_AUDIT_STRUCTURE_NODES:
                    issues.append(
                        AuditIssue(
                            "limit",
                            "lockfile exceeds the %d-node structure audit limit"
                            % MAX_AUDIT_STRUCTURE_NODES,
                        )
                    )
                    return
                discovered += 1
                children.append((nested, child))
        elif isinstance(current, list):
            for index, nested in enumerate(current):
                child = _bounded_location(current_location, "[%d]" % index)
                if discovered >= MAX_AUDIT_STRUCTURE_NODES:
                    issues.append(
                        AuditIssue(
                            "limit",
                            "lockfile exceeds the %d-node structure audit limit"
                            % MAX_AUDIT_STRUCTURE_NODES,
                        )
                    )
                    return
                discovered += 1
                children.append((nested, child))
        stack.extend(reversed(children))


def _bounded_location(location: str, suffix: str, maximum: int = 512) -> str:
    remaining = maximum - len(location)
    if remaining <= 0:
        return location[:maximum]
    if len(suffix) <= remaining:
        return location + suffix
    if remaining <= 3:
        return location + suffix[:remaining]
    return location + suffix[: remaining - 3] + "..."

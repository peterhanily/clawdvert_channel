"""Deterministic, inert directory snapshots for ArtifactFS-managed workspaces."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, Mapping, Optional, Sequence, Tuple, Union

from artifact_bridge.json_safety import validate_json_text


FORMAT = "artifactfs.snapshot.v1"
FORMAT_VERSION = 1
RESERVED_ROOT_NAME = ".artifactfs"


class SnapshotError(ValueError):
    """A directory or serialization is not one safe ArtifactFS snapshot."""


@dataclass(frozen=True)
class SnapshotLimits:
    """Resource bounds for local capture and untrusted snapshot decoding."""

    max_entries: int = 128
    max_total_bytes: int = 8 * 1024 * 1024
    max_file_bytes: int = 8 * 1024 * 1024
    max_serialized_bytes: int = 12 * 1024 * 1024
    max_path_bytes: int = 512
    max_component_bytes: int = 255

    def __post_init__(self) -> None:
        for name in (
            "max_entries",
            "max_total_bytes",
            "max_file_bytes",
            "max_serialized_bytes",
            "max_path_bytes",
            "max_component_bytes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError("%s must be a positive integer" % name)


DEFAULT_LIMITS = SnapshotLimits()


@dataclass(frozen=True)
class SnapshotEntry:
    """One regular file or explicit directory in an immutable snapshot."""

    path: str
    kind: str
    mode: int
    size: int
    digest: Optional[str]
    inode_id: int
    data: Optional[bytes] = None


class Snapshot:
    """An immutable, content-addressed ArtifactFS directory generation."""

    format_version = FORMAT_VERSION

    def __init__(
        self,
        entries: Iterable[SnapshotEntry],
        *,
        limits: SnapshotLimits = DEFAULT_LIMITS,
    ) -> None:
        if not isinstance(limits, SnapshotLimits):
            raise TypeError("limits must be SnapshotLimits")
        supplied = tuple(entries)
        if any(not isinstance(item, SnapshotEntry) for item in supplied):
            raise TypeError("snapshot entries must be SnapshotEntry")
        ordered = tuple(
            sorted(supplied, key=lambda item: (item.path != ".", item.path))
        )
        _validate_entries(ordered, limits)
        self._limits = limits
        self._entries: Tuple[SnapshotEntry, ...] = ordered
        self._by_path: Mapping[str, SnapshotEntry] = {
            entry.path: entry for entry in ordered
        }
        self._serialized = _canonical_bytes(ordered)
        if len(self._serialized) > limits.max_serialized_bytes:
            raise SnapshotError("snapshot serialization exceeds the byte limit")
        self.version = hashlib.sha256(self._serialized).hexdigest()

    @property
    def entries(self) -> Tuple[SnapshotEntry, ...]:
        return self._entries

    @property
    def sha256(self) -> str:
        return self.version

    def get(self, path: str) -> SnapshotEntry:
        canonical = _require_canonical_path(path, self._limits)
        try:
            return self._by_path[canonical]
        except KeyError as exc:
            raise FileNotFoundError(canonical) from exc

    def iterdir(self, path: str = ".") -> Tuple[SnapshotEntry, ...]:
        canonical = _require_canonical_path(path, self._limits)
        parent = self.get(canonical)
        if parent.kind != "directory":
            raise NotADirectoryError(canonical)
        prefix = "" if canonical == "." else canonical + "/"
        children = []
        for entry in self._entries:
            if entry.path == "." or not entry.path.startswith(prefix):
                continue
            remainder = entry.path[len(prefix) :]
            if "/" not in remainder:
                children.append(entry)
        return tuple(children)

    def read_file(self, path: str) -> bytes:
        entry = self.get(path)
        if entry.kind != "file":
            raise IsADirectoryError(entry.path)
        if not isinstance(entry.data, bytes):  # guarded during construction
            raise SnapshotError("snapshot file has no bytes")
        return entry.data


def validate_relative_path(
    path: object,
    *,
    limits: SnapshotLimits = DEFAULT_LIMITS,
    allow_root: bool = True,
) -> str:
    """Return the NFC canonical form of one safe snapshot-relative path."""

    if not isinstance(path, str) or not path or "\x00" in path or "\\" in path:
        raise SnapshotError("snapshot path is invalid")
    if path == ".":
        if allow_root:
            return path
        raise SnapshotError("root is not a child path")
    if path.startswith("/") or path.endswith("/"):
        raise SnapshotError("snapshot path must be relative and canonical")
    raw_parts = path.split("/")
    if any(part in ("", ".", "..") for part in raw_parts):
        raise SnapshotError("snapshot path contains an unsafe component")
    parts = []
    for raw in raw_parts:
        canonical = unicodedata.normalize("NFC", raw)
        if not canonical or any(ord(char) < 32 for char in canonical):
            raise SnapshotError("snapshot path contains a control character")
        try:
            component_bytes = canonical.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise SnapshotError("snapshot path is not valid UTF-8") from exc
        if len(component_bytes) > limits.max_component_bytes:
            raise SnapshotError("snapshot path component exceeds the byte limit")
        parts.append(canonical)
    if parts[0].casefold() == RESERVED_ROOT_NAME.casefold():
        raise SnapshotError(".artifactfs is reserved for mount status")
    result = "/".join(parts)
    try:
        result_bytes = result.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SnapshotError("snapshot path is not valid UTF-8") from exc
    if len(result_bytes) > limits.max_path_bytes:
        raise SnapshotError("snapshot path exceeds the byte limit")
    return result


def snapshot_directory(
    root: Union[str, os.PathLike[str]],
    *,
    limits: SnapshotLimits = DEFAULT_LIMITS,
) -> Snapshot:
    """Capture regular files and directories without following links."""

    try:
        root_path = os.path.abspath(os.fspath(root))
    except (TypeError, ValueError) as exc:
        raise SnapshotError("snapshot root must be a filesystem path") from exc
    if not isinstance(root_path, str) or "\x00" in root_path:
        raise SnapshotError("snapshot root must be a text filesystem path")
    root_fd = -1
    root_parent_fd = -1
    root_leaf: Optional[str] = None
    try:
        raw_root = os.lstat(root_path)
        if stat.S_ISLNK(raw_root.st_mode) or not stat.S_ISDIR(raw_root.st_mode):
            raise SnapshotError("snapshot root must be a real directory")
        # macOS exposes stable system aliases such as /var -> /private/var.
        # Resolve those before the descriptor walk, then prove that the opened
        # directory is still the exact object observed through the caller's
        # path. Descendants are never resolved by pathname.
        resolved_root = os.path.realpath(root_path)
        root_fd, root_parent_fd, root_leaf = _open_directory_path(resolved_root)
        root_before = os.fstat(root_fd)
        _require_owner_controlled(root_before, "snapshot root")
        if (raw_root.st_dev, raw_root.st_ino) != (
            root_before.st_dev,
            root_before.st_ino,
        ):
            raise SnapshotError("snapshot root changed while being opened")
    except SnapshotError:
        if root_fd >= 0:
            os.close(root_fd)
        if root_parent_fd >= 0:
            os.close(root_parent_fd)
        raise
    except OSError as exc:
        if root_fd >= 0:
            os.close(root_fd)
        if root_parent_fd >= 0:
            os.close(root_parent_fd)
        raise SnapshotError("snapshot root is unavailable or contains a link") from exc

    entries = [_directory_entry(".")]
    canonical_paths: Dict[str, str] = {".": "."}
    total_bytes = 0

    def add_path(original_relative: str, canonical: str) -> None:
        folded = canonical.casefold()
        previous = canonical_paths.get(folded)
        if previous is not None:
            raise SnapshotError(
                "snapshot contains a Unicode or case-fold path collision"
            )
        canonical_paths[folded] = original_relative

    def visit(directory_fd: int, relative_parent: str = "") -> None:
        nonlocal total_bytes
        directory_before = os.fstat(directory_fd)
        _require_owner_controlled(directory_before, "snapshot directory")
        try:
            with os.scandir(directory_fd) as iterator:
                names = sorted(item.name for item in iterator)
        except OSError as exc:
            raise SnapshotError("snapshot directory could not be read") from exc
        local_names: Dict[str, str] = {}
        for name in names:
            normalized_name = unicodedata.normalize("NFC", name)
            folded_name = normalized_name.casefold()
            if folded_name in local_names:
                raise SnapshotError(
                    "snapshot contains a Unicode or case-fold name collision"
                )
            local_names[folded_name] = name
            raw_relative = (
                name if not relative_parent else relative_parent + "/" + name
            )
            canonical = validate_relative_path(raw_relative, limits=limits, allow_root=False)
            add_path(raw_relative, canonical)
            if len(entries) >= limits.max_entries:
                raise SnapshotError("snapshot exceeds the entry limit")
            try:
                initial = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise SnapshotError("snapshot entry changed while being read") from exc
            if stat.S_ISLNK(initial.st_mode):
                raise SnapshotError("snapshot does not support symbolic links")
            _require_owner_controlled(initial, "snapshot entry")
            if stat.S_ISDIR(initial.st_mode):
                child_fd = _open_child_directory(directory_fd, name, initial)
                try:
                    entries.append(_directory_entry(canonical, initial.st_mode))
                    visit(child_fd, canonical)
                    _require_child_identity(directory_fd, name, child_fd, directory=True)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(initial.st_mode):
                raise SnapshotError("snapshot supports regular files and directories only")
            data, stable_mode = _read_regular_file_at(
                directory_fd, name, initial, limits
            )
            total_bytes += len(data)
            if total_bytes > limits.max_total_bytes:
                raise SnapshotError("snapshot exceeds the aggregate byte limit")
            entries.append(_file_entry(canonical, data, stable_mode))
        directory_after = os.fstat(directory_fd)
        if (
            (directory_before.st_dev, directory_before.st_ino)
            != (directory_after.st_dev, directory_after.st_ino)
            or directory_before.st_mtime_ns != directory_after.st_mtime_ns
            or directory_before.st_ctime_ns != directory_after.st_ctime_ns
        ):
            raise SnapshotError("snapshot directory changed while being read")

    try:
        visit(root_fd)
        root_after = os.fstat(root_fd)
        if (
            root_after.st_dev != root_before.st_dev
            or root_after.st_ino != root_before.st_ino
            or not stat.S_ISDIR(root_after.st_mode)
        ):
            raise SnapshotError("snapshot root changed while being read")
        if root_parent_fd >= 0 and root_leaf is not None:
            _require_child_identity(
                root_parent_fd, root_leaf, root_fd, directory=True
            )
        try:
            caller_after = os.lstat(root_path)
        except OSError as exc:
            raise SnapshotError("snapshot root changed while being read") from exc
        if (
            stat.S_ISLNK(caller_after.st_mode)
            or (caller_after.st_dev, caller_after.st_ino)
            != (root_before.st_dev, root_before.st_ino)
        ):
            raise SnapshotError("snapshot root changed while being read")
        return Snapshot(entries, limits=limits)
    finally:
        if root_fd >= 0:
            os.close(root_fd)
        if root_parent_fd >= 0:
            os.close(root_parent_fd)


def encode_snapshot(
    snapshot: Snapshot,
    *,
    limits: SnapshotLimits = DEFAULT_LIMITS,
) -> str:
    """Return the one canonical UTF-8 JSON serialization for ``snapshot``."""

    if not isinstance(snapshot, Snapshot):
        raise TypeError("snapshot must be Snapshot")
    raw = _canonical_bytes(snapshot.entries)
    if len(raw) > limits.max_serialized_bytes:
        raise SnapshotError("snapshot serialization exceeds the byte limit")
    return raw.decode("utf-8")


def decode_snapshot(
    raw: Union[str, bytes],
    *,
    limits: SnapshotLimits = DEFAULT_LIMITS,
) -> Snapshot:
    """Strictly decode untrusted canonical snapshot JSON."""

    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise SnapshotError("snapshot serialization is not valid UTF-8") from exc
        text = raw
    elif isinstance(raw, bytes):
        encoded = raw
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SnapshotError("snapshot serialization is not valid UTF-8") from exc
    else:
        raise TypeError("snapshot serialization must be text or bytes")
    if not encoded or len(encoded) > limits.max_serialized_bytes:
        raise SnapshotError("snapshot serialization exceeds the byte limit")
    try:
        validate_json_text(
            text,
            max_depth=8,
            max_nodes=min(65_536, max(64, limits.max_entries * 16 + 32)),
        )
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_int=_bounded_json_int,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except (ValueError, RecursionError) as exc:
        raise SnapshotError("snapshot serialization is not valid strict JSON") from exc
    if not isinstance(value, dict) or set(value) != {"entries", "format"}:
        raise SnapshotError("snapshot document has an invalid shape")
    if value["format"] != FORMAT or not isinstance(value["entries"], list):
        raise SnapshotError("snapshot document has an unsupported format")
    if not value["entries"] or len(value["entries"]) > limits.max_entries:
        raise SnapshotError("snapshot has an invalid entry count")

    entries = []
    total_bytes = 0
    for item in value["entries"]:
        if not isinstance(item, dict):
            raise SnapshotError("snapshot entry is not an object")
        kind = item.get("kind")
        if kind == "directory":
            if set(item) != {"kind", "mode", "path"}:
                raise SnapshotError("snapshot directory has an invalid shape")
            path = _decoded_path(item["path"], limits)
            mode = _decoded_mode(item["mode"], directory=True)
            entries.append(_directory_entry(path, mode))
        elif kind == "file":
            if set(item) != {"data", "kind", "mode", "path", "sha256", "size"}:
                raise SnapshotError("snapshot file has an invalid shape")
            path = _decoded_path(item["path"], limits)
            mode = _decoded_mode(item["mode"], directory=False)
            size = item["size"]
            digest = item["sha256"]
            payload = item["data"]
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise SnapshotError("snapshot file size is invalid")
            if size > limits.max_file_bytes:
                raise SnapshotError("snapshot file exceeds the byte limit")
            if not isinstance(digest, str) or len(digest) != 64:
                raise SnapshotError("snapshot file digest is invalid")
            maximum_payload = 4 * ((limits.max_file_bytes + 2) // 3)
            if (
                not isinstance(payload, str)
                or len(payload) % 4
                or len(payload) > maximum_payload
            ):
                raise SnapshotError("snapshot file data is invalid")
            try:
                data = base64.b64decode(payload, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise SnapshotError("snapshot file data is invalid") from exc
            if base64.b64encode(data).decode("ascii") != payload:
                raise SnapshotError("snapshot file data is not canonical base64")
            if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
                raise SnapshotError("snapshot file integrity check failed")
            total_bytes += size
            if total_bytes > limits.max_total_bytes:
                raise SnapshotError("snapshot exceeds the aggregate byte limit")
            entries.append(_file_entry(path, data, mode))
        else:
            raise SnapshotError("snapshot entry kind is unsupported")

    snapshot = Snapshot(entries, limits=limits)
    if encode_snapshot(snapshot, limits=limits) != text:
        raise SnapshotError("snapshot serialization is not canonical")
    return snapshot


def _strict_object(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _bounded_json_int(value: str) -> int:
    # Snapshot integers are modes and bounded byte counts. Avoid asking Python
    # to construct attacker-controlled, multi-megabyte integers before the
    # structural validators get a chance to reject them.
    digits = value[1:] if value.startswith("-") else value
    if not digits or len(digits) > 20:
        raise ValueError("JSON integer exceeds the snapshot bound")
    return int(value)


def _reject_json_number(value: str) -> None:
    raise ValueError("snapshot JSON does not support this number: %s" % value[:32])


def _decoded_path(value: object, limits: SnapshotLimits) -> str:
    canonical = validate_relative_path(value, limits=limits)
    if canonical != value:
        raise SnapshotError("snapshot path is not NFC canonical")
    return canonical


def _decoded_mode(value: object, *, directory: bool) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SnapshotError("snapshot mode is invalid")
    allowed = 0o755 if directory else 0o755
    if value < 0 or value & ~allowed:
        raise SnapshotError("snapshot mode is invalid")
    canonical = 0o755 if directory else (0o755 if value & 0o111 else 0o644)
    if value != canonical:
        raise SnapshotError("snapshot mode is not canonical")
    return value


def _require_canonical_path(
    path: str, limits: SnapshotLimits = DEFAULT_LIMITS
) -> str:
    canonical = validate_relative_path(path, limits=limits)
    if canonical != path:
        raise SnapshotError("snapshot path is not canonical")
    return canonical


def _read_regular_file_at(
    parent_fd: int,
    name: str,
    initial: os.stat_result,
    limits: SnapshotLimits,
) -> Tuple[bytes, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise SnapshotError("snapshot file could not be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SnapshotError("snapshot entry changed type while being read")
        if (before.st_dev, before.st_ino) != (initial.st_dev, initial.st_ino):
            raise SnapshotError("snapshot file was replaced while being opened")
        maximum = min(limits.max_file_bytes, limits.max_total_bytes)
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - size + 1))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise SnapshotError("snapshot file exceeds the byte limit")
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or size != after.st_size
        ):
            raise SnapshotError("snapshot file changed while being read")
        mode = 0o755 if after.st_mode & 0o111 else 0o644
        _require_child_identity(parent_fd, name, descriptor, directory=False)
        return b"".join(chunks), mode
    finally:
        os.close(descriptor)


def _open_directory_path(path: str) -> Tuple[int, int, Optional[str]]:
    """Open an absolute directory through pinned, non-link components."""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if not nofollow or not directory:
        raise OSError("secure snapshot capture requires O_NOFOLLOW and O_DIRECTORY")
    parts = [part for part in path.split(os.sep) if part]
    current_fd = os.open(os.sep, os.O_RDONLY | directory | cloexec)
    parent_fd = -1
    try:
        if not parts:
            return current_fd, -1, None
        for index, component in enumerate(parts):
            next_fd = os.open(
                component,
                os.O_RDONLY | directory | cloexec | nofollow,
                dir_fd=current_fd,
            )
            if index == len(parts) - 1:
                parent_fd = current_fd
                return next_fd, parent_fd, component
            os.close(current_fd)
            current_fd = next_fd
    except BaseException:
        os.close(current_fd)
        raise
    raise AssertionError("unreachable directory walk")


def _open_child_directory(
    parent_fd: int, name: str, initial: os.stat_result
) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
        os, "O_CLOEXEC", 0
    ) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise SnapshotError("snapshot directory changed while being opened") from exc
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino)
    ):
        os.close(descriptor)
        raise SnapshotError("snapshot directory was replaced while being opened")
    return descriptor


def _require_owner_controlled(details: os.stat_result, label: str) -> None:
    if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o022:
        raise SnapshotError("%s must be owner-controlled" % label)


def _require_child_identity(
    parent_fd: int, name: str, opened_fd: int, *, directory: bool
) -> None:
    opened = os.fstat(opened_fd)
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise SnapshotError("snapshot entry changed while being read") from exc
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(current.st_mode)
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise SnapshotError("snapshot entry was replaced while being read")


def _directory_entry(path: str, source_mode: int = 0o755) -> SnapshotEntry:
    del source_mode
    return SnapshotEntry(
        path=path,
        kind="directory",
        mode=0o755,
        size=0,
        digest=None,
        inode_id=_inode(path, "directory", None),
        data=None,
    )


def _file_entry(path: str, data: bytes, source_mode: int) -> SnapshotEntry:
    digest = hashlib.sha256(data).hexdigest()
    mode = 0o755 if source_mode & 0o111 else 0o644
    return SnapshotEntry(
        path=path,
        kind="file",
        mode=mode,
        size=len(data),
        digest=digest,
        inode_id=_inode(path, "file", digest),
        data=data,
    )


def _inode(path: str, kind: str, digest: Optional[str]) -> int:
    if path == ".":
        return 1
    identity = (path + "\0" + kind + "\0" + (digest or "")).encode("utf-8")
    value = int.from_bytes(
        hashlib.blake2b(identity, digest_size=8, person=b"aodfs-node").digest(),
        "big",
    ) & ((1 << 63) - 1)
    return value if value > 1 else value + 2


def _validate_entries(entries: Tuple[SnapshotEntry, ...], limits: SnapshotLimits) -> None:
    if not entries or len(entries) > limits.max_entries:
        raise SnapshotError("snapshot has an invalid entry count")
    if entries[0].path != "." or entries[0].kind != "directory":
        raise SnapshotError("snapshot must contain one root directory")
    seen = set()
    folded = set()
    inodes = set()
    total = 0
    directories = set()
    for entry in entries:
        path = _require_canonical_path(entry.path, limits)
        if path in seen or path.casefold() in folded:
            raise SnapshotError("snapshot contains a duplicate or case-fold path")
        seen.add(path)
        folded.add(path.casefold())
        parent = "." if "/" not in path else path.rsplit("/", 1)[0]
        if path != "." and parent not in directories:
            raise SnapshotError("snapshot entry parent is missing or not a directory")
        if entry.kind == "directory":
            if (
                entry.mode != 0o755
                or entry.size != 0
                or entry.digest is not None
                or entry.data is not None
            ):
                raise SnapshotError("snapshot directory metadata is invalid")
            directories.add(path)
        elif entry.kind == "file":
            if entry.mode not in (0o644, 0o755) or not isinstance(entry.data, bytes):
                raise SnapshotError("snapshot file metadata is invalid")
            if entry.size != len(entry.data) or entry.size > limits.max_file_bytes:
                raise SnapshotError("snapshot file size is invalid")
            digest = hashlib.sha256(entry.data).hexdigest()
            if entry.digest != digest:
                raise SnapshotError("snapshot file digest is invalid")
            total += entry.size
            if total > limits.max_total_bytes:
                raise SnapshotError("snapshot exceeds the aggregate byte limit")
        else:
            raise SnapshotError("snapshot entry kind is unsupported")
        if entry.inode_id != _inode(entry.path, entry.kind, entry.digest):
            raise SnapshotError("snapshot inode identity is invalid")
        if entry.inode_id in inodes:
            raise SnapshotError("snapshot contains an inode collision")
        inodes.add(entry.inode_id)


def _canonical_bytes(entries: Iterable[SnapshotEntry]) -> bytes:
    serialized = []
    for entry in entries:
        if entry.kind == "directory":
            serialized.append(
                {"kind": "directory", "mode": entry.mode, "path": entry.path}
            )
        else:
            serialized.append(
                {
                    "data": base64.b64encode(entry.data or b"").decode("ascii"),
                    "kind": "file",
                    "mode": entry.mode,
                    "path": entry.path,
                    "sha256": entry.digest,
                    "size": entry.size,
                }
            )
    value = {"entries": serialized, "format": FORMAT}
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


__all__ = [
    "DEFAULT_LIMITS",
    "FORMAT",
    "FORMAT_VERSION",
    "Snapshot",
    "SnapshotEntry",
    "SnapshotError",
    "SnapshotLimits",
    "decode_snapshot",
    "encode_snapshot",
    "snapshot_directory",
    "validate_relative_path",
]

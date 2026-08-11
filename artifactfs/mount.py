"""Optional, read-only FUSE frontend for immutable ArtifactFS snapshots.

The module deliberately does not import :mod:`mfusepy` at import time.  The
filesystem operations can therefore be exercised on every supported platform,
including CI hosts without FUSE installed.  Only :func:`mount_snapshot` needs
the optional Python and native FUSE dependencies.
"""

from __future__ import annotations

import errno
import hashlib
import importlib
import os
import posixpath
import stat
import unicodedata
from typing import Any, Iterable, Optional, Protocol, Union, runtime_checkable


Version = Union[int, str]


@runtime_checkable
class SnapshotEntry(Protocol):
    """The part of a snapshot entry consumed by the FUSE adapter."""

    path: str
    kind: str
    size: int


@runtime_checkable
class SnapshotBackend(Protocol):
    """Minimal immutable snapshot contract required by the mount frontend."""

    version: Version

    def get(self, path: str) -> SnapshotEntry:
        """Return the entry at a canonical snapshot-relative path."""

    def iterdir(self, path: str = ".") -> Iterable[SnapshotEntry]:
        """Return the direct children of a directory."""

    def read_file(self, path: str) -> bytes:
        """Return all bytes for a regular file."""


class FuseUnavailableError(RuntimeError):
    """Raised when the optional Python or native FUSE runtime is unavailable."""


def deterministic_inode(version: Version, path: str) -> int:
    """Return a stable, non-zero 63-bit inode for a version and path.

    Snapshot implementations may provide their own deterministic ``inode_id``.
    This function is the frontend's portable fallback and is also useful to
    lightweight test backends.
    """

    canonical = _canonical_snapshot_path(path)
    if canonical == ".":
        return 1
    identity = "%s:%s\0%s" % (type(version).__name__, version, canonical)
    digest = hashlib.blake2b(
        identity.encode("utf-8"), digest_size=8, person=b"artifactfs-ino"
    ).digest()
    inode = int.from_bytes(digest, "big") & ((1 << 63) - 1)
    # Reserve inode 1 for the root and never expose inode 0.
    return inode if inode > 1 else inode + 2


class ArtifactFuseOperations:
    """High-level FUSE operations over one exact, immutable snapshot.

    This class intentionally does not inherit from ``mfusepy.Operations``.
    MFusepy accepts a duck-typed operations object, which keeps construction and
    unit testing independent of an installed FUSE runtime.
    """

    FILE_MODE = stat.S_IFREG | 0o400
    DIRECTORY_MODE = stat.S_IFDIR | 0o500
    # Fixed snapshot timestamps are represented as integer nanoseconds. This
    # also opts into mfusepy's non-deprecated timestamp convention.
    use_ns = True

    def __init__(
        self,
        snapshot: SnapshotBackend,
        *,
        version: Optional[Version] = None,
    ) -> None:
        actual_version = _snapshot_version(snapshot)
        if version is not None and version != actual_version:
            raise ValueError(
                "requested snapshot version %r, but backend is pinned to %r"
                % (version, actual_version)
            )
        self._snapshot = snapshot
        self._version = actual_version
        self._uid = os.getuid() if hasattr(os, "getuid") else 0
        self._gid = os.getgid() if hasattr(os, "getgid") else 0

    @property
    def version(self) -> Version:
        """The exact version pinned when this operations object was created."""

        return self._version

    def _assert_pinned(self) -> None:
        if _snapshot_version(self._snapshot) != self._version:
            raise _os_error(
                getattr(errno, "ESTALE", errno.EIO),
                "snapshot backend changed after the mount pinned its version",
            )

    def _entry(self, fuse_path: str) -> Any:
        self._assert_pinned()
        snapshot_path = _fuse_to_snapshot_path(fuse_path)
        try:
            entry = self._snapshot.get(snapshot_path)
        except FileNotFoundError as exc:
            raise _os_error(errno.ENOENT, fuse_path) from exc
        except NotADirectoryError as exc:
            raise _os_error(errno.ENOTDIR, fuse_path) from exc
        except KeyError as exc:
            raise _os_error(errno.ENOENT, fuse_path) from exc
        _validate_entry(entry, expected_path=snapshot_path)
        return entry

    def _attributes(self, entry: Any) -> dict[str, Any]:
        kind = _entry_kind(entry)
        if kind == "directory":
            mode = self.DIRECTORY_MODE
            size = 0
            links = 2
        else:
            mode = self.FILE_MODE
            size = _entry_size(entry)
            links = 1
        return {
            "st_mode": mode,
            "st_nlink": links,
            "st_size": size,
            "st_uid": self._uid,
            "st_gid": self._gid,
            "st_ino": _entry_inode(entry, self._version),
            # Snapshots have content identity rather than mutable timestamps.
            # Fixed values avoid metadata changing between mounts.
            "st_atime": 0,
            "st_mtime": 0,
            "st_ctime": 0,
        }

    def getattr(self, path: str, fh: Optional[int] = None) -> dict[str, Any]:
        del fh
        return self._attributes(self._entry(path))

    def readdir(self, path: str, fh: int) -> list[tuple[str, dict[str, Any], int]]:
        del fh
        entry = self._entry(path)
        if _entry_kind(entry) != "directory":
            raise _os_error(errno.ENOTDIR, path)

        snapshot_path = _fuse_to_snapshot_path(path)
        try:
            children = tuple(self._snapshot.iterdir(snapshot_path))
        except FileNotFoundError as exc:
            raise _os_error(errno.ENOENT, path) from exc
        except NotADirectoryError as exc:
            raise _os_error(errno.ENOTDIR, path) from exc

        rows = []
        for child in children:
            child_path = _validate_entry(child)
            parent = posixpath.dirname(child_path) or "."
            name = posixpath.basename(child_path)
            if parent != snapshot_path or name in ("", ".", ".."):
                raise _os_error(
                    errno.EIO,
                    "snapshot iterdir returned a non-child entry",
                )
            rows.append((name, self._attributes(child), 0))
        names = [name for name, _, _ in rows]
        if len(set(names)) != len(names):
            raise _os_error(errno.EIO, "snapshot iterdir returned duplicate names")
        parent_path = "/" if path == "/" else posixpath.dirname(path.rstrip("/")) or "/"
        parent_entry = entry if path == "/" else self._entry(parent_path)
        return [
            (".", self._attributes(entry), 0),
            ("..", self._attributes(parent_entry), 0),
        ] + sorted(rows, key=lambda row: row[0])

    def open(self, path: str, flags: int) -> int:
        entry = self._entry(path)
        if _entry_kind(entry) == "directory":
            raise _os_error(errno.EISDIR, path)
        if _requests_write(flags):
            raise _os_error(errno.EROFS, "ArtifactFS snapshots are read-only")
        return 0

    def opendir(self, path: str) -> int:
        entry = self._entry(path)
        if _entry_kind(entry) != "directory":
            raise _os_error(errno.ENOTDIR, path)
        return 0

    def read(self, path: str, size: int, offset: int, fh: int) -> bytes:
        del fh
        if size < 0 or offset < 0:
            raise _os_error(errno.EINVAL, "negative read size or offset")
        entry = self._entry(path)
        if _entry_kind(entry) == "directory":
            raise _os_error(errno.EISDIR, path)
        snapshot_path = _fuse_to_snapshot_path(path)
        try:
            data = self._snapshot.read_file(snapshot_path)
        except FileNotFoundError as exc:
            raise _os_error(errno.ENOENT, path) from exc
        except IsADirectoryError as exc:
            raise _os_error(errno.EISDIR, path) from exc
        if not isinstance(data, bytes):
            raise _os_error(errno.EIO, "snapshot read_file must return bytes")
        if len(data) != _entry_size(entry):
            raise _os_error(errno.EIO, "snapshot file size changed after pinning")
        return data[offset : offset + size]

    def access(self, path: str, mode: int) -> int:
        entry = self._entry(path)
        if mode & os.W_OK:
            raise _os_error(errno.EROFS, "ArtifactFS snapshots are read-only")
        if mode & os.X_OK and _entry_kind(entry) != "directory":
            raise _os_error(errno.EACCES, path)
        return 0

    def statfs(self, path: str) -> dict[str, int]:
        self._entry(path)
        return {
            "f_bsize": 4096,
            "f_frsize": 4096,
            "f_blocks": 0,
            "f_bfree": 0,
            "f_bavail": 0,
            "f_files": 0,
            "f_ffree": 0,
            "f_namemax": 255,
        }

    def getxattr(self, path: str, name: str, position: int = 0) -> bytes:
        del name, position
        self._entry(path)
        no_attribute = getattr(
            errno, "ENOATTR", getattr(errno, "ENODATA", errno.ENOTSUP)
        )
        raise _os_error(no_attribute, "snapshot entries have no extended attributes")

    def listxattr(self, path: str) -> list[str]:
        self._entry(path)
        return []

    def readlink(self, path: str) -> str:
        self._entry(path)
        raise _os_error(errno.EINVAL, "snapshot entries are not symbolic links")

    # FUSE lifecycle operations which cannot change snapshot state.
    def flush(self, path: str, fh: int) -> int:
        del path, fh
        return 0

    def fsync(self, path: str, datasync: int, fh: int) -> int:
        del path, datasync, fh
        return 0

    def fsyncdir(self, path: str, datasync: int, fh: int) -> int:
        del path, datasync, fh
        return 0

    def release(self, path: str, fh: int) -> int:
        del path, fh
        return 0

    def releasedir(self, path: str, fh: int) -> int:
        del path, fh
        return 0

    # Mutating callbacks used by this high-level adapter are explicit; the
    # mount is also opened with ro=True, so absent optional callbacks cannot
    # turn the snapshot into writable storage.
    def chmod(self, *args: Any) -> None:
        _raise_read_only(*args)

    def chown(self, *args: Any) -> None:
        _raise_read_only(*args)

    def create(self, *args: Any) -> None:
        _raise_read_only(*args)

    def fallocate(self, *args: Any) -> None:
        _raise_read_only(*args)

    def link(self, *args: Any) -> None:
        _raise_read_only(*args)

    def mkdir(self, *args: Any) -> None:
        _raise_read_only(*args)

    def mknod(self, *args: Any) -> None:
        _raise_read_only(*args)

    def removexattr(self, *args: Any) -> None:
        _raise_read_only(*args)

    def rename(self, *args: Any) -> None:
        _raise_read_only(*args)

    def rmdir(self, *args: Any) -> None:
        _raise_read_only(*args)

    def setxattr(self, *args: Any) -> None:
        _raise_read_only(*args)

    def symlink(self, *args: Any) -> None:
        _raise_read_only(*args)

    def truncate(self, *args: Any) -> None:
        _raise_read_only(*args)

    def unlink(self, *args: Any) -> None:
        _raise_read_only(*args)

    def utimens(self, *args: Any) -> None:
        _raise_read_only(*args)

    def write(self, *args: Any) -> None:
        _raise_read_only(*args)


def mount_snapshot(
    snapshot: SnapshotBackend,
    mountpoint: Union[str, os.PathLike[str]],
    *,
    version: Optional[Version] = None,
    foreground: bool = True,
    debug: bool = False,
    fuse_factory: Optional[Any] = None,
) -> Any:
    """Mount one exact snapshot with secure, read-only FUSE options.

    ``fuse_factory`` is an injection seam for tests.  In normal use it is
    omitted and ``mfusepy.FUSE`` is loaded lazily.  ``allow_other`` is neither
    enabled nor exposed: the mount is visible only under the invoking user's
    normal FUSE policy, while ``default_permissions`` lets the kernel enforce
    the owner-only modes returned by :meth:`ArtifactFuseOperations.getattr`.
    """

    operations = ArtifactFuseOperations(snapshot, version=version)
    try:
        mount_path = os.fspath(mountpoint)
    except TypeError as exc:
        raise TypeError("mountpoint must be a filesystem path") from exc
    if not isinstance(mount_path, str):
        raise TypeError("mountpoint must resolve to a text path")
    if not mount_path or "\0" in mount_path:
        raise ValueError("mountpoint must be non-empty and contain no NUL byte")
    factory = fuse_factory if fuse_factory is not None else _load_fuse_factory()
    return factory(
        operations,
        mount_path,
        foreground=foreground,
        debug=debug,
        ro=True,
        default_permissions=True,
        use_ino=True,
    )


def require_fuse_runtime() -> Any:
    """Load and return the optional FUSE factory before provider access."""

    return _load_fuse_factory()


def _load_fuse_factory() -> Any:
    try:
        module = importlib.import_module("mfusepy")
        factory = module.FUSE
        if not callable(factory):
            raise AttributeError("mfusepy.FUSE is not callable")
    except (ImportError, OSError, AttributeError) as exc:
        raise FuseUnavailableError(
            "FUSE mounting is optional and unavailable. Install the 'mfusepy' "
            "Python package plus the platform FUSE runtime (libfuse on Linux "
            "or macFUSE on macOS). Snapshot access and tests do not require "
            "either dependency."
        ) from exc
    return factory


def _snapshot_version(snapshot: Any) -> Version:
    try:
        version = snapshot.version
    except AttributeError as exc:
        raise TypeError("snapshot backend must expose an immutable version") from exc
    if isinstance(version, bool) or not isinstance(version, (int, str)):
        raise TypeError("snapshot version must be an integer or string")
    if isinstance(version, str) and not version:
        raise ValueError("snapshot version must not be empty")
    return version


def _canonical_snapshot_path(path: str) -> str:
    if not isinstance(path, str):
        raise TypeError("snapshot paths must be strings")
    if not path or path.startswith("/") or "\0" in path:
        raise ValueError("snapshot path is not canonical")
    if path == ".":
        return path
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("snapshot path is not canonical")
    return path


def _fuse_to_snapshot_path(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
        raise _os_error(errno.EINVAL, "invalid FUSE path")
    if path == "/":
        return "."
    raw_parts = path[1:].split("/")
    if any(part in ("", ".", "..") for part in raw_parts):
        raise _os_error(errno.EINVAL, "non-canonical FUSE path")
    parts = []
    for raw in raw_parts:
        normalized = unicodedata.normalize("NFC", raw)
        if (
            not normalized
            or "\\" in normalized
            or any(ord(character) < 32 for character in normalized)
        ):
            raise _os_error(errno.EINVAL, "non-canonical FUSE path")
        try:
            normalized.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise _os_error(errno.EINVAL, "non-canonical FUSE path") from exc
        parts.append(normalized)
    return "/".join(parts)


def _validate_entry(entry: Any, expected_path: Optional[str] = None) -> str:
    try:
        path = entry.path
    except AttributeError as exc:
        raise _os_error(errno.EIO, "snapshot returned an invalid entry") from exc
    try:
        canonical = _canonical_snapshot_path(path)
    except (TypeError, ValueError) as exc:
        raise _os_error(errno.EIO, "snapshot returned a non-canonical path") from exc
    if expected_path is not None and canonical != expected_path:
        raise _os_error(errno.EIO, "snapshot returned an entry for the wrong path")
    _entry_kind(entry)
    if _entry_kind(entry) == "file":
        _entry_size(entry)
    return canonical


def _entry_kind(entry: Any) -> str:
    try:
        kind = entry.kind
    except AttributeError as exc:
        raise _os_error(errno.EIO, "snapshot entry has no kind") from exc
    if kind not in ("file", "directory"):
        raise _os_error(errno.EIO, "snapshot entry has an unsupported kind")
    return kind


def _entry_size(entry: Any) -> int:
    try:
        size = entry.size
    except AttributeError as exc:
        raise _os_error(errno.EIO, "snapshot file has no size") from exc
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise _os_error(errno.EIO, "snapshot file has an invalid size")
    return size


def _entry_inode(entry: Any, version: Version) -> int:
    for attribute in ("inode_id", "inode"):
        inode = getattr(entry, attribute, None)
        if inode is None:
            continue
        if (
            isinstance(inode, bool)
            or not isinstance(inode, int)
            or inode <= 0
            or inode >= (1 << 64)
        ):
            raise _os_error(errno.EIO, "snapshot entry has an invalid inode")
        if (entry.path == ".") != (inode == 1):
            raise _os_error(errno.EIO, "snapshot entry conflicts with the root inode")
        return inode
    return deterministic_inode(version, entry.path)


def _requests_write(flags: int) -> bool:
    if not isinstance(flags, int):
        raise _os_error(errno.EINVAL, "open flags must be an integer")
    access_mask = getattr(os, "O_ACCMODE", os.O_WRONLY | os.O_RDWR)
    if flags & access_mask != os.O_RDONLY:
        return True
    modifying_flags = os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_TRUNC
    return bool(flags & modifying_flags)


def _raise_read_only(*args: Any) -> None:
    del args
    raise _os_error(errno.EROFS, "ArtifactFS snapshots are read-only")


def _os_error(code: int, detail: str) -> OSError:
    return OSError(code, detail)


__all__ = [
    "ArtifactFuseOperations",
    "FuseUnavailableError",
    "SnapshotBackend",
    "SnapshotEntry",
    "deterministic_inode",
    "mount_snapshot",
    "require_fuse_runtime",
]

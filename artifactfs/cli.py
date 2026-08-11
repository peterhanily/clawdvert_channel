"""Command-line entry point for the experimental ArtifactFS prototype."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from typing import Any, Callable, Optional, Sequence

from artifact_bridge.errors import ArtifactBridgeError, redact_text

from .core import DEFAULT_LIMITS, decode_snapshot, encode_snapshot, snapshot_directory
from .mount import FuseUnavailableError, mount_snapshot, require_fuse_runtime
from .provider import fetch_owner_served_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="artifactfs",
        description="Create and mount immutable ArtifactFS snapshots.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    pack = subparsers.add_parser(
        "pack",
        help="capture a local directory as a deterministic snapshot",
    )
    pack.add_argument("directory", help="local directory to capture")
    pack.add_argument("output", help="new owner-only snapshot JSON file")

    mount = subparsers.add_parser(
        "mount-code",
        help="mount an exact served Code Artifact snapshot",
    )
    mount.add_argument("reference", help="Code Artifact UUID or viewer URL")
    mount.add_argument("mountpoint", help="existing empty directory")
    mount.add_argument(
        "--version",
        help="exact provider version ID; current live is pinned once when omitted",
    )
    mount.add_argument(
        "--background",
        action="store_true",
        help="ask the FUSE runtime to detach after mounting",
    )
    mount.add_argument("--debug", action="store_true", help="enable FUSE diagnostics")

    local_mount = subparsers.add_parser(
        "mount-snapshot",
        help="mount a local deterministic ArtifactFS snapshot",
    )
    local_mount.add_argument("snapshot", help="snapshot JSON produced by `artifactfs pack`")
    local_mount.add_argument("mountpoint", help="existing empty directory")
    local_mount.add_argument("--background", action="store_true")
    local_mount.add_argument("--debug", action="store_true")
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    snapshot_fetcher: Callable[..., Any] = fetch_owner_served_snapshot,
    mounter: Callable[..., Any] = mount_snapshot,
    runtime_loader: Optional[Callable[[], Any]] = None,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "pack":
            snapshot = snapshot_directory(args.directory)
            serialized = encode_snapshot(snapshot).encode("utf-8")
            output = _write_new_private_file(args.output, serialized)
            print("ArtifactFS snapshot: %s" % snapshot.version)
            print("ArtifactFS entries: %d" % len(snapshot.entries))
            print("ArtifactFS output: %s" % output)
            return 0

        mountpoint = _validated_mountpoint(args.mountpoint)
        mountpoint_identity = _mountpoint_identity(mountpoint)
        fuse_factory = None
        if runtime_loader is not None:
            fuse_factory = runtime_loader()
        elif mounter is mount_snapshot:
            # Fail before resolving credentials or fetching provider bytes.
            fuse_factory = require_fuse_runtime()
        if args.command == "mount-code":
            snapshot = snapshot_fetcher(args.reference, version=args.version)
            representation = "served (read-only)"
        elif args.command == "mount-snapshot":
            snapshot = _read_snapshot_file(args.snapshot)
            representation = "managed snapshot (read-only)"
        else:  # argparse currently makes this unreachable
            raise AssertionError("unhandled ArtifactFS command")
        if (
            _validated_mountpoint(mountpoint) != mountpoint
            or _mountpoint_identity(mountpoint) != mountpoint_identity
        ):
            raise ValueError("mountpoint changed while the Artifact was being fetched")
        # The provider view resolves a symbolic/current request before this
        # point, so the FUSE layer always receives one immutable exact version.
        version = snapshot.version
        print("ArtifactFS representation: %s" % representation)
        print("ArtifactFS pinned version: %s" % version)
        print("ArtifactFS mountpoint: %s" % mountpoint)
        mount_options = {
            "version": version,
            "foreground": not args.background,
            "debug": args.debug,
        }
        if fuse_factory is not None:
            mount_options["fuse_factory"] = fuse_factory
        if (
            _validated_mountpoint(mountpoint) != mountpoint
            or _mountpoint_identity(mountpoint) != mountpoint_identity
        ):
            raise ValueError("mountpoint changed immediately before mounting")
        mounter(
            snapshot,
            mountpoint,
            **mount_options,
        )
        return 0
    except (
        ArtifactBridgeError,
        FuseUnavailableError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        # Provider errors and OS errors can include URLs.  Preserve the useful
        # class of failure without echoing query credentials or local secrets.
        print("artifactfs: %s" % redact_text(str(exc)), file=sys.stderr)
        return 2


def _validated_mountpoint(value: object) -> str:
    try:
        path = os.path.abspath(os.fspath(value))
    except (TypeError, ValueError) as exc:
        raise ValueError("mountpoint must be a filesystem path") from exc
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise OSError(exc.errno, "mountpoint is unavailable") from None
    if stat.S_ISLNK(info.st_mode):
        raise ValueError("mountpoint must not be a symbolic link")
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("mountpoint must be a directory")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError("mountpoint must be an owner-controlled directory")
    try:
        names = os.listdir(path)
    except OSError as exc:
        raise OSError(exc.errno, "mountpoint cannot be read") from None
    if names:
        raise ValueError("mountpoint must be empty")
    return path


def _mountpoint_identity(path: str) -> tuple[int, int]:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise OSError(exc.errno, "mountpoint is unavailable") from None
    return info.st_dev, info.st_ino


def _read_snapshot_file(value: object) -> Any:
    parent_fd, leaf, path, parent_path = _open_parent_path(value, "snapshot")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(leaf, flags, dir_fd=parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        raise OSError(exc.errno, "snapshot file is unavailable") from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("snapshot path must be a regular file")
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o022:
            raise ValueError("snapshot file must be owner-controlled")
        if before.st_nlink != 1:
            raise ValueError("snapshot file must not be hard-linked")
        chunks = []
        size = 0
        maximum = DEFAULT_LIMITS.max_serialized_bytes
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - size + 1))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise ValueError("snapshot file exceeds the byte limit")
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or size != after.st_size
        ):
            raise ValueError("snapshot file changed while being read")
        _require_leaf_matches_fd(parent_fd, leaf, descriptor, regular=True)
        _require_directory_path_matches_fd(parent_path, parent_fd)
        return decode_snapshot(b"".join(chunks))
    finally:
        os.close(descriptor)
        os.close(parent_fd)


def _write_new_private_file(value: object, data: bytes) -> str:
    parent_fd, leaf, path, parent_path = _open_parent_path(value, "output")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(leaf, flags, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        raise OSError(exc.errno, "output already exists or cannot be created") from None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
        ):
            raise OSError("snapshot output was not created as a private file")
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("snapshot output write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        _require_leaf_matches_fd(parent_fd, leaf, descriptor, regular=True)
        _require_directory_path_matches_fd(parent_path, parent_fd)
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            raise OSError(
                exc.errno,
                "snapshot file exists but its directory was not synced",
            ) from None
        _require_leaf_matches_fd(parent_fd, leaf, descriptor, regular=True)
        _require_directory_path_matches_fd(parent_path, parent_fd)
    finally:
        # There is no portable atomic "unlink only if this inode still owns
        # the name" operation. On a failed write, retain the private partial
        # file instead of risking deletion of a concurrently swapped leaf.
        os.close(descriptor)
        os.close(parent_fd)
    return path


def _open_parent_path(
    value: object, label: str
) -> tuple[int, str, str, str]:
    try:
        path = os.path.abspath(os.fspath(value))
    except (TypeError, ValueError) as exc:
        raise ValueError("%s must be a filesystem path" % label) from exc
    if not isinstance(path, str) or "\x00" in path:
        raise ValueError("%s must be a text filesystem path" % label)
    leaf = os.path.basename(path)
    if leaf in ("", ".", ".."):
        raise ValueError("%s must name a file" % label)
    parent_path = os.path.dirname(path)
    try:
        observed = os.stat(parent_path)
    except OSError as exc:
        raise OSError(exc.errno, "%s directory is unavailable" % label) from None
    if not stat.S_ISDIR(observed.st_mode):
        raise ValueError("%s parent must be a directory" % label)
    resolved = os.path.realpath(parent_path)
    parent_fd = _open_directory_path(resolved, label)
    opened = os.fstat(parent_fd)
    if (observed.st_dev, observed.st_ino) != (opened.st_dev, opened.st_ino):
        os.close(parent_fd)
        raise ValueError("%s directory changed while being opened" % label)
    if opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) & 0o022:
        os.close(parent_fd)
        raise ValueError("%s parent must be owner-controlled" % label)
    return parent_fd, leaf, path, parent_path


def _open_directory_path(path: str, label: str) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if not nofollow or not directory:
        raise OSError("secure %s paths require O_NOFOLLOW and O_DIRECTORY" % label)
    descriptor = os.open(os.sep, os.O_RDONLY | directory | cloexec)
    try:
        for component in (part for part in path.split(os.sep) if part):
            next_descriptor = os.open(
                component,
                os.O_RDONLY | directory | cloexec | nofollow,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _leaf_matches_fd(parent_fd: int, leaf: str, descriptor: int) -> bool:
    opened = os.fstat(descriptor)
    try:
        current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return (opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino)


def _require_leaf_matches_fd(
    parent_fd: int, leaf: str, descriptor: int, *, regular: bool
) -> None:
    if not _leaf_matches_fd(parent_fd, leaf, descriptor):
        raise ValueError("filesystem path was replaced while it was open")
    if regular and not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise ValueError("filesystem path changed type while it was open")


def _require_directory_path_matches_fd(path: str, descriptor: int) -> None:
    opened = os.fstat(descriptor)
    try:
        current = os.stat(path)
    except OSError as exc:
        raise ValueError("directory path changed while it was open") from exc
    if (
        not stat.S_ISDIR(current.st_mode)
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise ValueError("directory path was replaced while it was open")


if __name__ == "__main__":  # pragma: no cover - exercised through __main__
    raise SystemExit(main())

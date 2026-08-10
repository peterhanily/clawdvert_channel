"""Collision-safe, content-addressed local storage for fetched artifacts."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import unicodedata
from contextlib import ExitStack, contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

from .errors import (
    CollisionError,
    LockfileError,
    ResponseTooLargeError,
    UnsafePathError,
    redact_text,
)
from .json_safety import strict_json_loads, validate_json_text
from .models import FetchedArtifact, Representation, safe_json_value


LOCK_NAME = "artifact.lock.json"
LOCK_SCHEMA_VERSION = 1
DEFAULT_MAX_REPRESENTATION_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_LOCK_BYTES = 4 * 1024 * 1024
MAX_LOCK_JSON_DEPTH = 64
MAX_LOCK_JSON_NODES = 65536
MAX_LOCK_VERSIONS = 1024
MAX_LOCK_REPRESENTATIONS = 4096
MAX_BUNDLE_ENTRIES = 8192
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _component(value: str, fallback: str, always_hash: bool = False) -> str:
    """Map an untrusted remote label to one deterministic path component."""

    raw = unicodedata.normalize("NFKC", str(value))
    secret_shaped = redact_text(raw) != raw
    normalized = "redacted" if secret_shaped else raw
    if (
        not always_hash
        and _SAFE_COMPONENT.fullmatch(normalized)
        and normalized not in (".", "..")
    ):
        return normalized
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", normalized).strip("._-")[:80]
    stem = stem or fallback
    digest = hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:12]
    return "%s-%s" % (stem, digest)


def _filename(representation: Representation) -> str:
    proposed = representation.suggested_name or "content.bin"
    proposed = proposed.replace("\\", "/").rsplit("/", 1)[-1]
    return _component(proposed, "content.bin")


def _representation_path(version_id: str, representation: Representation) -> str:
    version_digest = hashlib.sha256(
        unicodedata.normalize("NFKC", version_id).encode("utf-8", "surrogatepass")
    ).hexdigest()[:24]
    label_digest = hashlib.sha256(
        unicodedata.normalize("NFKC", representation.label).encode(
            "utf-8", "surrogatepass"
        )
    ).hexdigest()[:24]
    return "representation-%s-%s-%s" % (
        version_digest,
        label_digest,
        _filename(representation),
    )


def default_output_name(fetched: FetchedArtifact) -> str:
    return "%s-%s" % (
        _component(fetched.artifact.artifact_id, "artifact", always_hash=True),
        _component(fetched.version.version_id, "version", always_hash=True),
    )


def canonical_json(data: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            safe_json_value(data),
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


class ArtifactStore:
    """Write bundles safely while the output has no non-cooperating local writer."""

    def __init__(
        self,
        *,
        max_representation_bytes: int = DEFAULT_MAX_REPRESENTATION_BYTES,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    ) -> None:
        if max_representation_bytes <= 0 or max_total_bytes <= 0:
            raise ValueError("byte limits must be positive")
        self.max_representation_bytes = max_representation_bytes
        self.max_total_bytes = max_total_bytes

    def write(
        self,
        fetched: Iterable[FetchedArtifact],
        output_dir: os.PathLike,
    ) -> Dict[str, Any]:
        items = list(fetched)
        if not items:
            raise LockfileError("cannot create a mirror with no fetched versions")
        self._validate_items(items)
        root = Path(output_dir)
        if root.name in ("", ".", "..") or ".." in root.parts:
            raise UnsafePathError(
                "output must be a canonical dedicated directory path: %s" % root
            )
        self._reject_bundle_ancestor(root)
        with self._locked_output_parent(root) as locked_parent:
            self._reject_bundle_ancestor(root)
            if root.exists() and os.path.samefile(str(root), str(locked_parent)):
                raise UnsafePathError(
                    "output must name a dedicated child directory, not its parent: %s"
                    % root
                )
            if root.exists() and root.is_symlink():
                raise UnsafePathError("output directory may not be a symlink: %s" % root)
            if root.exists() and not root.is_dir():
                raise CollisionError(
                    "output path already exists and is not a directory: %s" % root
                )

            artifact = items[0].artifact
            if root.exists():
                return self._extend_existing(items, root, artifact)

            lock, writes = self._build_lock(items, None)
            self._validate_final_lock(lock)
            lock_bytes = canonical_json(lock)
            if len(lock_bytes) > MAX_LOCK_BYTES:
                raise LockfileError(
                    "generated lock exceeds the %d byte safety limit" % MAX_LOCK_BYTES
                )
            self._commit_new(root, writes, lock, lock_bytes)
            return lock

    @contextmanager
    def _locked_output_parent(self, root: Path) -> Iterator[Path]:
        probe = root.parent
        missing: List[str] = []
        while not probe.exists():
            if probe.name in ("", ".", ".."):
                raise UnsafePathError(
                    "could not resolve a safe output ancestor: %s" % root
                )
            missing.append(probe.name)
            parent = probe.parent
            if parent == probe:
                raise UnsafePathError(
                    "could not resolve a safe output ancestor: %s" % root
                )
            probe = parent
        current = probe.resolve(strict=True)
        with ExitStack() as locks:
            locks.enter_context(self._exclusive_directory_lock(current))
            self._reject_bundle_ancestor(root)
            for part in reversed(missing):
                candidate = current / part
                try:
                    os.mkdir(str(candidate), mode=0o700)
                except FileExistsError:
                    pass
                try:
                    info = candidate.lstat()
                except OSError:
                    raise UnsafePathError(
                        "output parent changed while acquiring locks: %s" % candidate
                    ) from None
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    raise UnsafePathError(
                        "output parent is not a safe directory: %s" % candidate
                    )
                current = candidate.resolve(strict=True)
                locks.enter_context(self._exclusive_directory_lock(current))
                self._reject_bundle_ancestor(root)
            yield current

    def _reject_bundle_ancestor(self, root: Path) -> None:
        ancestor = root.parent
        nearest_existing: Optional[Path] = None
        checked = set()
        while True:
            if ancestor.exists():
                if nearest_existing is None:
                    nearest_existing = ancestor
                resolved = ancestor.resolve(strict=True)
                checked.add(str(resolved))
                if self._is_bridge_bundle_directory(resolved):
                    raise CollisionError(
                        "refusing to create a bundle inside existing bridge bundle: %s"
                        % resolved
                    )
            parent = ancestor.parent
            if parent == ancestor:
                break
            ancestor = parent
        if nearest_existing is None:
            return
        ancestor = nearest_existing.resolve(strict=True)
        while True:
            key = str(ancestor)
            if key not in checked and self._is_bridge_bundle_directory(ancestor):
                raise CollisionError(
                    "refusing to create a bundle inside existing bridge bundle: %s"
                    % ancestor
                )
            parent = ancestor.parent
            if parent == ancestor:
                break
            ancestor = parent

    def _is_bridge_bundle_directory(self, directory: Path) -> bool:
        try:
            resolved = directory.resolve(strict=True)
            directory_fd = os.open(str(resolved), _DIRECTORY_FLAGS)
        except OSError:
            return False
        try:
            if not self._relative_entry_exists(directory_fd, LOCK_NAME):
                return False
            try:
                lock, _ = self._read_lock_at(directory_fd, resolved / LOCK_NAME)
            except (LockfileError, UnsafePathError, OSError):
                return False
            return isinstance(lock.get("artifact"), Mapping) and isinstance(
                lock.get("versions"), list
            )
        finally:
            os.close(directory_fd)

    def _extend_existing(
        self, items: List[FetchedArtifact], root: Path, artifact: Any
    ) -> Dict[str, Any]:
        with self._exclusive_directory_lock(root) as root_fd:
            if not self._path_matches_directory_fd(root, root_fd):
                raise UnsafePathError("output directory changed during write: %s" % root)
            with os.scandir(root_fd) as entries:
                has_entries = next(entries, None) is not None
            has_lock = self._relative_entry_exists(root_fd, LOCK_NAME)
            if has_entries and not has_lock:
                raise CollisionError(
                    "refusing non-empty output directory without %s: %s" % (LOCK_NAME, root)
                )
            existing: Optional[Dict[str, Any]] = None
            lock_snapshot: Optional[Tuple[int, int, int, str]] = None
            if has_lock:
                existing, lock_snapshot = self._read_lock_at(root_fd, root / LOCK_NAME)
                existing_artifact = existing.get("artifact")
                if not isinstance(existing_artifact, Mapping) or (
                    existing_artifact.get("provider") != artifact.provider
                    or existing_artifact.get("artifact_id") != artifact.artifact_id
                    or existing_artifact.get("kind") != artifact.kind
                ):
                    raise CollisionError(
                        "output lock belongs to a different artifact: %s" % root
                    )
                self._verify_existing_bundle(root, root_fd, existing)

            lock, writes = self._build_lock(items, existing)
            self._validate_final_lock(lock)
            lock_bytes = canonical_json(lock)
            if len(lock_bytes) > MAX_LOCK_BYTES:
                raise LockfileError(
                    "generated lock exceeds the %d byte safety limit" % MAX_LOCK_BYTES
                )
            if not self._path_matches_directory_fd(root, root_fd):
                raise UnsafePathError("output directory changed during write: %s" % root)
            self._commit_existing(
                root, root_fd, writes, lock, lock_bytes, lock_snapshot
            )
            return lock

    @staticmethod
    @contextmanager
    def _exclusive_directory_lock(root: Path):
        fd = os.open(str(root), _DIRECTORY_FLAGS)
        try:
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode):
                raise UnsafePathError("output path is not a directory: %s" % root)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield fd
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _validate_items(self, items: List[FetchedArtifact]) -> None:
        first = items[0]
        self._validate_identity(first.artifact.provider, "artifact provider")
        self._validate_identity(first.artifact.artifact_id, "artifact ID")
        self._validate_identity(first.artifact.kind, "artifact kind")
        provider_id = (first.artifact.provider, first.artifact.artifact_id, first.artifact.kind)
        total = 0
        versions = set()
        for item in items:
            if (item.artifact.provider, item.artifact.artifact_id, item.artifact.kind) != provider_id:
                raise LockfileError("all fetched versions in one bundle must belong to one artifact")
            if item.version.provider != item.artifact.provider:
                raise LockfileError("version provider does not match artifact provider")
            if item.version.artifact_id != item.artifact.artifact_id:
                raise LockfileError("version artifact ID does not match artifact")
            if not item.version.version_id:
                raise LockfileError("version ID may not be empty")
            self._validate_identity(item.version.version_id, "version ID")
            if item.version.version_id in versions:
                raise LockfileError("duplicate fetched version: %s" % item.version.version_id)
            versions.add(item.version.version_id)
            labels = set()
            if not item.representations:
                raise LockfileError("version %s has no representations" % item.version.version_id)
            for representation in item.representations:
                self._validate_identity(representation.label, "representation label")
                if representation.label in labels:
                    raise LockfileError(
                        "representation labels must be non-empty and unique within a version"
                    )
                labels.add(representation.label)
                if not isinstance(representation.data, bytes):
                    raise LockfileError("representation data must be bytes")
                if representation.size > self.max_representation_bytes:
                    raise ResponseTooLargeError(
                        "representation %s exceeds %d bytes"
                        % (representation.label, self.max_representation_bytes)
                    )
                total += representation.size
                if total > self.max_total_bytes:
                    raise ResponseTooLargeError(
                        "mirror exceeds the %d byte total safety limit" % self.max_total_bytes
                    )

    @staticmethod
    def _validate_identity(value: Any, field: str) -> None:
        if not isinstance(value, str) or not value:
            raise LockfileError("%s must be a non-empty string" % field)
        if redact_text(value) != value:
            raise LockfileError("%s contains credential-shaped data" % field)

    def _build_lock(
        self,
        items: List[FetchedArtifact],
        existing: Optional[Dict[str, Any]],
    ) -> Tuple[Dict[str, Any], List[Tuple[str, bytes]]]:
        lock: Dict[str, Any] = {
            "schema_version": LOCK_SCHEMA_VERSION,
            "artifact": items[0].artifact.to_dict(),
            "versions": [],
        }
        versions: Dict[str, Dict[str, Any]] = {}
        if existing is not None:
            old_versions = existing.get("versions")
            if not isinstance(old_versions, list):
                raise LockfileError("existing lock has no versions array")
            for entry in old_versions:
                if not isinstance(entry, Mapping) or not isinstance(entry.get("version_id"), str):
                    raise LockfileError("existing lock contains an invalid version entry")
                versions[entry["version_id"]] = dict(entry)

        writes: List[Tuple[str, bytes]] = []
        new_paths: Dict[str, str] = {}
        for item in items:
            version_id = item.version.version_id
            old_entry = versions.get(version_id)
            old_paths = {}
            if isinstance(old_entry, Mapping):
                old_representations = old_entry.get("representations")
                if isinstance(old_representations, list):
                    old_paths = {
                        rep.get("label"): rep.get("path")
                        for rep in old_representations
                        if isinstance(rep, Mapping)
                        and isinstance(rep.get("label"), str)
                        and isinstance(rep.get("path"), str)
                    }
            representations = []
            for representation in item.representations:
                relative = old_paths.get(
                    representation.label,
                    _representation_path(version_id, representation),
                )
                folded = unicodedata.normalize("NFKC", relative.casefold())
                if folded in new_paths and new_paths[folded] != relative:
                    raise CollisionError(
                        "remote representation paths collide on a case-insensitive filesystem: "
                        "%s and %s" % (new_paths[folded], relative)
                    )
                new_paths[folded] = relative
                rep_entry = representation.to_dict()
                rep_entry["path"] = relative
                representations.append(rep_entry)
                writes.append((relative, representation.data))
            entry = item.version.to_dict()
            entry["representations"] = sorted(representations, key=lambda rep: rep["label"])
            entry["provenance"] = safe_json_value(item.provenance)
            if version_id in versions:
                if safe_json_value(versions[version_id]) != safe_json_value(entry):
                    raise CollisionError(
                        "exact version %s differs from the existing mirror" % version_id
                    )
            else:
                versions[version_id] = entry
        lock["versions"] = [versions[key] for key in sorted(versions)]
        return lock, writes

    def _validate_final_lock(self, lock: Mapping[str, Any]) -> None:
        total = 0
        paths: Dict[str, str] = {}
        version_ids = set()
        artifact = lock.get("artifact")
        if not isinstance(artifact, Mapping):
            raise LockfileError("lock artifact must be an object")
        artifact_provider = artifact.get("provider")
        artifact_id = artifact.get("artifact_id")
        artifact_kind = artifact.get("kind")
        self._validate_identity(artifact_provider, "artifact provider")
        self._validate_identity(artifact_id, "artifact ID")
        self._validate_identity(artifact_kind, "artifact kind")
        versions = lock.get("versions")
        if not isinstance(versions, list):
            raise LockfileError("lock versions must be an array")
        if not versions:
            raise LockfileError("lock must contain at least one exact version")
        if len(versions) > MAX_LOCK_VERSIONS:
            raise LockfileError(
                "lock exceeds the %d version safety limit" % MAX_LOCK_VERSIONS
            )
        representation_count = 0
        for version in versions:
            if not isinstance(version, Mapping):
                raise LockfileError("invalid version in lock")
            version_id = version.get("version_id")
            self._validate_identity(version_id, "version ID")
            if (
                version.get("provider") != artifact_provider
                or version.get("artifact_id") != artifact_id
            ):
                raise LockfileError(
                    "version %s belongs to a different artifact identity" % version_id
                )
            if version_id in version_ids:
                raise LockfileError("duplicate version ID in lock: %s" % version_id)
            version_ids.add(version_id)
            representations = version.get("representations")
            if not isinstance(representations, list):
                raise LockfileError("invalid representations in lock")
            if not representations:
                raise LockfileError("version %s has no representations" % version_id)
            labels = set()
            for representation in representations:
                representation_count += 1
                if representation_count > MAX_LOCK_REPRESENTATIONS:
                    raise LockfileError(
                        "lock exceeds the %d representation safety limit"
                        % MAX_LOCK_REPRESENTATIONS
                    )
                if not isinstance(representation, Mapping):
                    raise LockfileError("invalid representation in lock")
                label = representation.get("label")
                self._validate_identity(label, "representation label")
                if label in labels:
                    raise LockfileError(
                        "duplicate representation label in version %s: %s"
                        % (version_id, label)
                    )
                labels.add(label)
                size = representation.get("bytes")
                path = representation.get("path")
                sha256 = representation.get("sha256")
                if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                    raise LockfileError("invalid representation size in lock")
                if size > self.max_representation_bytes:
                    raise ResponseTooLargeError(
                        "existing representation exceeds %d bytes"
                        % self.max_representation_bytes
                    )
                total += size
                if total > self.max_total_bytes:
                    raise ResponseTooLargeError(
                        "mirror exceeds the %d byte total safety limit"
                        % self.max_total_bytes
                    )
                if not isinstance(path, str):
                    raise LockfileError("invalid representation path in lock")
                if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
                    raise LockfileError("invalid representation SHA-256 in lock")
                self._canonical_relative_path(path)
                folded = unicodedata.normalize("NFKC", path.casefold())
                if folded in paths:
                    raise CollisionError(
                        "lock contains aliased representation paths: %s and %s"
                        % (paths[folded], path)
                    )
                paths[folded] = path

    def _commit_new(
        self,
        root: Path,
        writes: List[Tuple[str, bytes]],
        final_lock: Mapping[str, Any],
        lock_bytes: bytes,
    ) -> None:
        parent = root.parent
        parent.mkdir(parents=True, exist_ok=True)
        if root.name in ("", ".", ".."):
            raise UnsafePathError("unsafe output directory name: %s" % root)
        canonical_parent = parent.resolve(strict=True)
        parent_fd = os.open(str(canonical_parent), _DIRECTORY_FLAGS)
        root_fd = -1
        root_identity: Optional[Tuple[int, int]] = None
        created_files: List[Tuple[str, int, int]] = []
        created_directories: List[Tuple[str, int, int]] = []
        try:
            root_fd = self._claim_output_directory(parent_fd, root.name, root)
            root_info = os.fstat(root_fd)
            root_identity = (root_info.st_dev, root_info.st_ino)
            for relative, data in writes:
                device, inode = self._atomic_create_at(
                    root_fd, relative, data, created_directories
                )
                created_files.append((relative, device, inode))
            for relative, device, inode in created_files:
                if not self._relative_matches_identity(
                    root_fd, relative, device, inode
                ):
                    raise UnsafePathError(
                        "created representation moved during bridge write: %s"
                        % self._safe_target(root, relative)
                    )
            self._verify_existing_bundle(root, root_fd, final_lock)
            device, inode = self._atomic_create_at(root_fd, LOCK_NAME, lock_bytes)
            created_files.append((LOCK_NAME, device, inode))
            if not self._parent_entry_matches_fd(
                parent_fd, root.name, root_identity[0], root_identity[1]
            ):
                raise UnsafePathError("output directory changed during write: %s" % root)
            if not self._path_matches_directory_fd(root, root_fd):
                raise UnsafePathError("output directory changed during write: %s" % root)
        except Exception:
            if root_fd >= 0:
                for relative, device, inode in reversed(created_files):
                    self._unlink_if_identity(root_fd, relative, device, inode)
                self._remove_created_directories(root_fd, created_directories)
            if root_identity is not None and self._parent_entry_matches_fd(
                parent_fd, root.name, root_identity[0], root_identity[1]
            ):
                try:
                    os.rmdir(root.name, dir_fd=parent_fd)
                except OSError:
                    pass
            raise
        finally:
            if root_fd >= 0:
                os.close(root_fd)
            os.close(parent_fd)

    @staticmethod
    def _claim_output_directory(parent_fd: int, name: str, display_path: Path) -> int:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            raise CollisionError(
                "output directory appeared during write: %s" % display_path
            ) from None
        try:
            claimed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            raise UnsafePathError(
                "new output directory changed before it could be opened: %s"
                % display_path
            ) from None
        try:
            directory_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        except OSError:
            raise UnsafePathError(
                "could not safely open newly claimed output directory: %s"
                % display_path
            ) from None
        opened = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(claimed.st_mode)
            or claimed.st_dev != opened.st_dev
            or claimed.st_ino != opened.st_ino
        ):
            os.close(directory_fd)
            raise UnsafePathError(
                "new output directory was replaced while opening: %s" % display_path
            )
        with os.scandir(directory_fd) as entries:
            if next(entries, None) is not None:
                os.close(directory_fd)
                raise CollisionError(
                    "new output directory was modified while opening: %s"
                    % display_path
                )
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
        return directory_fd

    def _commit_existing(
        self,
        root: Path,
        root_fd: int,
        writes: List[Tuple[str, bytes]],
        final_lock: Mapping[str, Any],
        lock_bytes: bytes,
        lock_snapshot: Optional[Tuple[int, int, int, str]],
    ) -> None:
        pending: List[Tuple[str, bytes]] = []
        for relative, data in writes:
            self._canonical_relative_path(relative)
            try:
                digest, size = self._digest_bounded_relative(root_fd, relative, len(data))
            except FileNotFoundError:
                pending.append((relative, data))
                continue
            except UnsafePathError:
                raise
            except (OSError, OverflowError):
                raise CollisionError(
                    "refusing to overwrite changed file: %s"
                    % self._safe_target(root, relative)
                ) from None
            if size != len(data) or digest != hashlib.sha256(data).hexdigest():
                raise CollisionError(
                    "refusing to overwrite changed file: %s"
                    % self._safe_target(root, relative)
                )

        created: List[Tuple[str, int, int]] = []
        created_directories: List[Tuple[str, int, int]] = []
        manifest_committed = False
        try:
            for relative, data in pending:
                device, inode = self._atomic_create_at(
                    root_fd, relative, data, created_directories
                )
                created.append((relative, device, inode))
            for relative, device, inode in created:
                if not self._relative_matches_identity(
                    root_fd, relative, device, inode
                ):
                    raise UnsafePathError(
                        "created representation moved during bridge write: %s"
                        % self._safe_target(root, relative)
                    )
            self._verify_existing_bundle(root, root_fd, final_lock)
            if not self._path_matches_directory_fd(root, root_fd):
                raise UnsafePathError("output directory changed during write: %s" % root)
            if lock_snapshot is None:
                self._atomic_create_at(root_fd, LOCK_NAME, lock_bytes)
            else:
                self._atomic_replace_at(
                    root_fd, LOCK_NAME, lock_bytes, lock_snapshot
                )
            manifest_committed = True
            if not self._path_matches_directory_fd(root, root_fd):
                raise UnsafePathError("output directory changed during write: %s" % root)
        except Exception:
            if not manifest_committed:
                for relative, device, inode in reversed(created):
                    self._unlink_if_identity(root_fd, relative, device, inode)
                self._remove_created_directories(root_fd, created_directories)
            raise

    @staticmethod
    def _safe_target(root: Path, relative: str) -> Path:
        canonical = ArtifactStore._canonical_relative_path(relative)
        return root.joinpath(*PurePosixPath(canonical).parts)

    @staticmethod
    def _canonical_relative_path(value: Any) -> str:
        if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
            raise UnsafePathError("unsafe representation path: %r" % value)
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or any(part in ("", ".", "..") for part in path.parts)
            or path.as_posix() != value
            or unicodedata.normalize("NFKC", value) != value
        ):
            raise UnsafePathError("noncanonical representation path: %r" % value)
        return value

    @staticmethod
    def _path_matches_directory_fd(path: Path, directory_fd: int) -> bool:
        try:
            path_info = os.stat(str(path), follow_symlinks=False)
            fd_info = os.fstat(directory_fd)
        except OSError:
            return False
        return (
            stat.S_ISDIR(path_info.st_mode)
            and path_info.st_dev == fd_info.st_dev
            and path_info.st_ino == fd_info.st_ino
        )

    @staticmethod
    def _parent_entry_matches_fd(
        parent_fd: int, name: str, device: int, inode: int
    ) -> bool:
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            return False
        return (
            stat.S_ISDIR(info.st_mode)
            and info.st_dev == device
            and info.st_ino == inode
        )

    @staticmethod
    def _relative_entry_exists(root_fd: int, relative: str) -> bool:
        try:
            os.stat(relative, dir_fd=root_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    @staticmethod
    def _open_directory_chain(
        root_fd: int,
        parts: Tuple[str, ...],
        *,
        create: bool = False,
        created_directories: Optional[List[Tuple[str, int, int]]] = None,
    ) -> int:
        current_fd = os.dup(root_fd)
        traversed: List[str] = []
        try:
            for part in parts:
                if part in ("", ".", "..") or "/" in part or "\x00" in part:
                    raise UnsafePathError("unsafe directory component: %r" % part)
                made = False
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=current_fd)
                        made = True
                    except FileExistsError:
                        pass
                try:
                    next_fd = os.open(part, _DIRECTORY_FLAGS, dir_fd=current_fd)
                except OSError as exc:
                    if exc.errno == errno.ELOOP:
                        raise UnsafePathError(
                            "refusing symlink inside output directory: %s"
                            % "/".join(traversed + [part])
                        ) from None
                    if exc.errno == errno.ENOTDIR:
                        try:
                            component_info = os.stat(
                                part, dir_fd=current_fd, follow_symlinks=False
                            )
                        except OSError:
                            component_info = None
                        if component_info is not None and stat.S_ISLNK(
                            component_info.st_mode
                        ):
                            raise UnsafePathError(
                                "refusing symlink inside output directory: %s"
                                % "/".join(traversed + [part])
                            ) from None
                        raise CollisionError(
                            "path component is not a directory: %s"
                            % "/".join(traversed + [part])
                        ) from None
                    raise
                os.close(current_fd)
                current_fd = next_fd
                traversed.append(part)
                if made and created_directories is not None:
                    info = os.fstat(current_fd)
                    created_directories.append(
                        ("/".join(traversed), info.st_dev, info.st_ino)
                    )
            return current_fd
        except Exception:
            os.close(current_fd)
            raise

    @staticmethod
    def _digest_bounded_relative(
        root_fd: int, relative: str, limit: int
    ) -> Tuple[str, int]:
        canonical = ArtifactStore._canonical_relative_path(relative)
        parts = PurePosixPath(canonical).parts
        parent_fd = ArtifactStore._open_directory_chain(root_fd, parts[:-1])
        fd = -1
        try:
            try:
                fd = os.open(parts[-1], os.O_RDONLY | _NOFOLLOW, dir_fd=parent_fd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise UnsafePathError(
                        "refusing symlink inside output directory: %s" % canonical
                    ) from None
                raise
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise OSError("path is not a regular file")
            if info.st_size > limit:
                raise OverflowError("file exceeds the bounded verification limit")
            digest = hashlib.sha256()
            total = 0
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                while True:
                    chunk = handle.read(min(1024 * 1024, limit + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise OverflowError(
                            "file exceeds the bounded verification limit"
                        )
                    digest.update(chunk)
            if total != info.st_size:
                raise OSError("file size changed during bounded verification")
            return digest.hexdigest(), total
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent_fd)

    @staticmethod
    def _snapshot_relative(
        root_fd: int, relative: str, limit: int
    ) -> Tuple[int, int, int, str]:
        canonical = ArtifactStore._canonical_relative_path(relative)
        parts = PurePosixPath(canonical).parts
        parent_fd = ArtifactStore._open_directory_chain(root_fd, parts[:-1])
        fd = -1
        try:
            try:
                fd = os.open(parts[-1], os.O_RDONLY | _NOFOLLOW, dir_fd=parent_fd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise UnsafePathError(
                        "refusing symlink inside output directory: %s" % canonical
                    ) from None
                raise
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise OverflowError("file is not a bounded regular file")
            digest = hashlib.sha256()
            total = 0
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                while True:
                    chunk = handle.read(min(1024 * 1024, limit + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise OverflowError("file exceeds the bounded snapshot limit")
                    digest.update(chunk)
            if total != info.st_size:
                raise OSError("file size changed during bounded snapshot")
            return info.st_dev, info.st_ino, total, digest.hexdigest()
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent_fd)

    @staticmethod
    def _create_temp_at(parent_fd: int, target_name: str, data: bytes) -> Tuple[str, int, int]:
        temporary = ""
        fd = -1
        for _ in range(32):
            temporary = ".%s.%s.tmp" % (target_name, secrets.token_hex(8))
            try:
                fd = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    0o600,
                    dir_fd=parent_fd,
                )
                break
            except FileExistsError:
                continue
        if fd < 0:
            raise CollisionError("could not allocate a private bridge temporary file")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
                info = os.fstat(handle.fileno())
            return temporary, info.st_dev, info.st_ino
        except Exception:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except OSError:
                pass
            raise

    @staticmethod
    def _atomic_create_at(
        root_fd: int,
        relative: str,
        data: bytes,
        created_directories: Optional[List[Tuple[str, int, int]]] = None,
    ) -> Tuple[int, int]:
        """Publish complete bytes without following parents or replacing a path."""

        canonical = ArtifactStore._canonical_relative_path(relative)
        parts = PurePosixPath(canonical).parts
        parent_fd = ArtifactStore._open_directory_chain(
            root_fd,
            parts[:-1],
            create=True,
            created_directories=created_directories,
        )
        temporary = ""
        linked = False
        device = inode = -1
        try:
            temporary, device, inode = ArtifactStore._create_temp_at(
                parent_fd, parts[-1], data
            )
            try:
                os.link(
                    temporary,
                    parts[-1],
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                linked = True
            except FileExistsError:
                raise CollisionError(
                    "output path appeared during bridge write: %s" % canonical
                ) from None
            try:
                os.unlink(temporary, dir_fd=parent_fd)
                temporary = ""
            except OSError:
                if linked:
                    ArtifactStore._unlink_name_if_identity(
                        parent_fd, parts[-1], device, inode
                    )
                raise
            return device, inode
        finally:
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=parent_fd)
                except OSError:
                    pass
            os.close(parent_fd)

    @staticmethod
    def _atomic_replace_at(
        root_fd: int,
        relative: str,
        data: bytes,
        expected: Tuple[int, int, int, str],
    ) -> None:
        """Replace a manifest only when its immediately rechecked snapshot matches."""

        canonical = ArtifactStore._canonical_relative_path(relative)
        parts = PurePosixPath(canonical).parts
        parent_fd = ArtifactStore._open_directory_chain(root_fd, parts[:-1])
        temporary = ""
        try:
            temporary, _, _ = ArtifactStore._create_temp_at(parent_fd, parts[-1], data)
            try:
                current = ArtifactStore._snapshot_relative(
                    root_fd, canonical, MAX_LOCK_BYTES
                )
            except (OSError, OverflowError, UnsafePathError):
                raise CollisionError(
                    "bundle manifest changed during bridge extension"
                ) from None
            if current != expected:
                raise CollisionError(
                    "bundle manifest changed during bridge extension"
                )
            os.replace(
                temporary,
                parts[-1],
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            temporary = ""
        finally:
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=parent_fd)
                except OSError:
                    pass
            os.close(parent_fd)

    @staticmethod
    def _unlink_name_if_identity(
        parent_fd: int, name: str, device: int, inode: int
    ) -> None:
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if info.st_dev == device and info.st_ino == inode:
                os.unlink(name, dir_fd=parent_fd)
        except OSError:
            pass

    @staticmethod
    def _relative_matches_identity(
        root_fd: int, relative: str, device: int, inode: int
    ) -> bool:
        try:
            parts = PurePosixPath(
                ArtifactStore._canonical_relative_path(relative)
            ).parts
            parent_fd = ArtifactStore._open_directory_chain(root_fd, parts[:-1])
        except (OSError, UnsafePathError, CollisionError):
            return False
        try:
            try:
                info = os.stat(
                    parts[-1], dir_fd=parent_fd, follow_symlinks=False
                )
            except OSError:
                return False
            return (
                stat.S_ISREG(info.st_mode)
                and info.st_dev == device
                and info.st_ino == inode
            )
        finally:
            os.close(parent_fd)

    @staticmethod
    def _unlink_if_identity(
        root_fd: int, relative: str, device: int, inode: int
    ) -> None:
        try:
            parts = PurePosixPath(
                ArtifactStore._canonical_relative_path(relative)
            ).parts
            parent_fd = ArtifactStore._open_directory_chain(root_fd, parts[:-1])
        except (OSError, UnsafePathError, CollisionError):
            return
        try:
            ArtifactStore._unlink_name_if_identity(
                parent_fd, parts[-1], device, inode
            )
        finally:
            os.close(parent_fd)

    @staticmethod
    def _remove_created_directories(
        root_fd: int, created_directories: List[Tuple[str, int, int]]
    ) -> None:
        for relative, device, inode in sorted(
            created_directories, key=lambda item: item[0].count("/"), reverse=True
        ):
            parts = PurePosixPath(relative).parts
            try:
                parent_fd = ArtifactStore._open_directory_chain(root_fd, parts[:-1])
            except (OSError, UnsafePathError, CollisionError):
                continue
            try:
                try:
                    info = os.stat(
                        parts[-1], dir_fd=parent_fd, follow_symlinks=False
                    )
                    if (
                        stat.S_ISDIR(info.st_mode)
                        and info.st_dev == device
                        and info.st_ino == inode
                    ):
                        os.rmdir(parts[-1], dir_fd=parent_fd)
                except OSError:
                    pass
            finally:
                os.close(parent_fd)

    def _verify_existing_bundle(
        self, root: Path, root_fd: int, lock: Mapping[str, Any]
    ) -> None:
        if safe_json_value(lock) != lock:
            raise LockfileError("existing lock contains credential-shaped metadata")
        self._validate_final_lock(lock)
        tracked = set()
        versions = lock.get("versions", [])
        for version in versions:
            for representation in version.get("representations", []):
                relative = self._canonical_relative_path(representation.get("path"))
                target = self._safe_target(root, relative)
                expected_size = representation.get("bytes")
                expected_hash = representation.get("sha256")
                try:
                    digest, opened_size = self._digest_bounded_relative(
                        root_fd, relative, expected_size
                    )
                except UnsafePathError:
                    raise
                except (OSError, OverflowError) as exc:
                    raise CollisionError(
                        "could not verify existing bundle representation: %s" % target
                    ) from exc
                if opened_size != expected_size:
                    raise CollisionError(
                        "existing bundle representation size changed: %s" % target
                    )
                if not isinstance(expected_hash, str) or digest != expected_hash:
                    raise CollisionError(
                        "existing bundle representation hash changed: %s" % target
                    )
                tracked.add(relative)

        try:
            for relative, is_directory, is_symlink in self._iter_bounded_tree_at(
                root_fd, MAX_BUNDLE_ENTRIES
            ):
                candidate = root / relative
                if is_symlink:
                    raise UnsafePathError(
                        "refusing symlink inside output directory: %s" % candidate
                    )
                if is_directory:
                    continue
                if relative != LOCK_NAME and relative not in tracked:
                    raise CollisionError(
                        "existing bundle contains an untracked file: %s" % candidate
                    )
        except ValueError as exc:
            raise LockfileError(str(exc)) from None

    @staticmethod
    def _iter_bounded_tree_at(
        root_fd: int, max_entries: int
    ) -> Iterator[Tuple[str, bool, bool]]:
        if max_entries <= 0:
            raise ValueError("filesystem entry limit must be positive")
        stack: List[Tuple[str, ...]] = [()]
        discovered = 0
        while stack:
            parts = stack.pop()
            directory_fd = ArtifactStore._open_directory_chain(root_fd, parts)
            try:
                with os.scandir(directory_fd) as entries:
                    for entry in entries:
                        discovered += 1
                        if discovered > max_entries:
                            raise ValueError(
                                "bundle exceeds the %d filesystem-entry limit"
                                % max_entries
                            )
                        relative_parts = parts + (entry.name,)
                        relative = PurePosixPath(*relative_parts).as_posix()
                        try:
                            is_symlink = entry.is_symlink()
                            is_directory = entry.is_dir(follow_symlinks=False)
                        except OSError:
                            is_symlink = False
                            is_directory = False
                        yield relative, is_directory, is_symlink
                        if is_directory:
                            stack.append(relative_parts)
            finally:
                os.close(directory_fd)

    @staticmethod
    def _read_lock_at(
        root_fd: int, display_path: Path
    ) -> Tuple[Dict[str, Any], Tuple[int, int, int, str]]:
        fd = -1
        try:
            fd = os.open(LOCK_NAME, os.O_RDONLY | _NOFOLLOW, dir_fd=root_fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_LOCK_BYTES:
                raise LockfileError(
                    "existing lock is not a bounded regular file: %s" % display_path
                )
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                raw = handle.read(MAX_LOCK_BYTES + 1)
            if len(raw) != info.st_size:
                raise LockfileError("existing lock changed while reading: %s" % display_path)
            text = raw.decode("utf-8")
            validate_json_text(
                text,
                max_depth=MAX_LOCK_JSON_DEPTH,
                max_nodes=MAX_LOCK_JSON_NODES,
            )
            data = strict_json_loads(text)
            ArtifactStore._validate_json_shape(data)
        except LockfileError:
            raise
        except (OSError, UnicodeDecodeError, ValueError, RecursionError):
            raise LockfileError(
                "could not parse existing lock: %s" % display_path
            ) from None
        finally:
            if fd >= 0:
                os.close(fd)
        schema_version = data.get("schema_version") if isinstance(data, dict) else None
        if (
            not isinstance(data, dict)
            or isinstance(schema_version, bool)
            or not isinstance(schema_version, int)
            or schema_version != LOCK_SCHEMA_VERSION
        ):
            raise LockfileError(
                "unsupported or invalid existing lock: %s" % display_path
            )
        snapshot = (
            info.st_dev,
            info.st_ino,
            info.st_size,
            hashlib.sha256(raw).hexdigest(),
        )
        return data, snapshot

    @staticmethod
    def _validate_json_shape(value: Any) -> None:
        nodes = 0
        stack: List[Tuple[Any, int]] = [(value, 1)]
        while stack:
            current, depth = stack.pop()
            nodes += 1
            if nodes > MAX_LOCK_JSON_NODES:
                raise ValueError(
                    "lock exceeds the %d-node structure limit" % MAX_LOCK_JSON_NODES
                )
            if depth > MAX_LOCK_JSON_DEPTH:
                raise ValueError(
                    "lock exceeds the %d-level structure depth limit"
                    % MAX_LOCK_JSON_DEPTH
                )
            if isinstance(current, Mapping):
                stack.extend((nested, depth + 1) for nested in current.values())
            elif isinstance(current, list):
                stack.extend((nested, depth + 1) for nested in current)

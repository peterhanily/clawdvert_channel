"""Durable, provider-independent write-back transaction records.

The journal deliberately records only enough information to reconcile an
Artifact publish after a crash: opaque provider identifiers, a commit UUID,
and the target snapshot digest.  It never stores snapshot bytes, credentials,
headers, cookies, capability tokens, or provider response bodies.

Publishing is outside this module.  In particular, a process recovering a
transaction at or beyond :class:`TransactionStage.DISPATCHED` must not replay
the mutation.  It may only inspect provider state and append a later record
once that state has been reconciled.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import stat
import uuid
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple, Union


JOURNAL_FORMAT = "artifactfs.transaction-record.v1"
MAX_RECORD_BYTES = 4096
MAX_JOURNAL_BYTES = 16 * 1024 * 1024
MAX_JOURNAL_RECORDS = 25_000
_READ_CHUNK_BYTES = 64 * 1024
_RECORD_KEYS = frozenset(
    {
        "format",
        "stage",
        "slug",
        "base_version",
        "commit_uuid",
        "target_snapshot_sha",
        "provider_response_version",
    }
)


class TransactionJournalError(RuntimeError):
    """Base class for transaction journal failures."""


class JournalSecurityError(TransactionJournalError):
    """The journal path, owner, type, or permissions are unsafe."""


class JournalCorruptionError(TransactionJournalError):
    """The append-only journal is malformed or has an invalid history."""


class JournalCapacityError(TransactionJournalError):
    """The bounded journal cannot safely accept or parse more records."""


class InvalidTransitionError(TransactionJournalError):
    """A record does not make the one permitted next state transition."""


class TransactionStage(str, Enum):
    """Durable stages of one at-most-once write-back transaction."""

    PREPARED = "prepared"
    DISPATCHED = "dispatched"
    RESPONSE_BOUND = "response_bound"
    READBACK_VERIFIED = "readback_verified"
    CHECKPOINTED = "checkpointed"
    # A provider-declared compare-and-set conflict is an explicit terminal
    # branch.  It is never inferred from a transport failure.
    CONFLICTED = "conflicted"


class RecoveryClassification(str, Enum):
    """The only safe action permitted after loading a transaction."""

    SAFE_TO_DISPATCH = "safe_to_dispatch"
    READ_ONLY_RECONCILIATION_REQUIRED = "read_only_reconciliation_required"
    CONFLICT_REQUIRES_RESOLUTION = "conflict_requires_resolution"
    COMPLETE = "complete"


@dataclass(frozen=True)
class TransactionRecord:
    """One immutable record in an ArtifactFS write-back transaction."""

    stage: TransactionStage
    slug: str
    base_version: str
    commit_uuid: str
    target_snapshot_sha: str
    provider_response_version: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.stage, TransactionStage):
            raise TypeError("stage must be TransactionStage")
        _require_canonical_uuid(self.slug, "slug")
        _require_provider_identifier(self.base_version, "base_version")
        _require_canonical_uuid(self.commit_uuid, "commit_uuid")
        _require_snapshot_sha(self.target_snapshot_sha)

        needs_response = self.stage in (
            TransactionStage.RESPONSE_BOUND,
            TransactionStage.READBACK_VERIFIED,
            TransactionStage.CHECKPOINTED,
            TransactionStage.CONFLICTED,
        )
        if needs_response:
            _require_provider_identifier(
                self.provider_response_version, "provider_response_version"
            )
        elif self.provider_response_version is not None:
            raise ValueError(
                "%s must not carry a provider response version" % self.stage.value
            )
        if (
            self.stage is TransactionStage.CONFLICTED
            and self.provider_response_version == self.base_version
        ):
            raise ValueError("a conflict must identify a different live version")

    @classmethod
    def prepared(
        cls,
        *,
        slug: str,
        base_version: str,
        target_snapshot_sha: str,
        commit_uuid: Optional[str] = None,
    ) -> "TransactionRecord":
        """Create the first record, generating a UUID when one is not supplied."""

        selected_uuid = str(uuid.uuid4()) if commit_uuid is None else commit_uuid
        return cls(
            stage=TransactionStage.PREPARED,
            slug=slug,
            base_version=base_version,
            commit_uuid=selected_uuid,
            target_snapshot_sha=target_snapshot_sha,
        )

    def advance(
        self,
        stage: TransactionStage,
        *,
        provider_response_version: Optional[str] = None,
    ) -> "TransactionRecord":
        """Return the immutable record for one valid immediate transition."""

        if not isinstance(stage, TransactionStage):
            raise TypeError("stage must be TransactionStage")
        if stage not in _ALLOWED_TRANSITIONS[self.stage]:
            raise InvalidTransitionError(
                "cannot advance %s to %s" % (self.stage.value, stage.value)
            )
        if provider_response_version is None:
            provider_response_version = self.provider_response_version
        return TransactionRecord(
            stage=stage,
            slug=self.slug,
            base_version=self.base_version,
            commit_uuid=self.commit_uuid,
            target_snapshot_sha=self.target_snapshot_sha,
            provider_response_version=provider_response_version,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Return the fixed, non-secret on-disk schema for this record."""

        return {
            "format": JOURNAL_FORMAT,
            "stage": self.stage.value,
            "slug": self.slug,
            "base_version": self.base_version,
            "commit_uuid": self.commit_uuid,
            "target_snapshot_sha": self.target_snapshot_sha,
            "provider_response_version": self.provider_response_version,
        }


@dataclass(frozen=True)
class TransactionState:
    """Validated latest state for one commit UUID."""

    record: TransactionRecord
    record_count: int

    @property
    def recovery(self) -> RecoveryClassification:
        return classify_recovery(self.record.stage)

    @property
    def safe_to_dispatch(self) -> bool:
        return self.recovery is RecoveryClassification.SAFE_TO_DISPATCH

    @property
    def read_only_reconciliation_required(self) -> bool:
        return (
            self.recovery
            is RecoveryClassification.READ_ONLY_RECONCILIATION_REQUIRED
        )

    @property
    def conflicted(self) -> bool:
        return self.recovery is RecoveryClassification.CONFLICT_REQUIRES_RESOLUTION


_ALLOWED_TRANSITIONS = {
    TransactionStage.PREPARED: frozenset({TransactionStage.DISPATCHED}),
    TransactionStage.DISPATCHED: frozenset(
        {TransactionStage.RESPONSE_BOUND, TransactionStage.CONFLICTED}
    ),
    TransactionStage.RESPONSE_BOUND: frozenset(
        {TransactionStage.READBACK_VERIFIED}
    ),
    TransactionStage.READBACK_VERIFIED: frozenset(
        {TransactionStage.CHECKPOINTED}
    ),
    TransactionStage.CHECKPOINTED: frozenset(),
    TransactionStage.CONFLICTED: frozenset(),
}


def classify_recovery(
    value: Union[TransactionState, TransactionRecord, TransactionStage]
) -> RecoveryClassification:
    """Classify recovery without ever authorizing an ambiguous redispatch."""

    if isinstance(value, TransactionState):
        stage = value.record.stage
    elif isinstance(value, TransactionRecord):
        stage = value.stage
    elif isinstance(value, TransactionStage):
        stage = value
    else:
        raise TypeError("recovery value must be a transaction state, record, or stage")

    if stage is TransactionStage.PREPARED:
        return RecoveryClassification.SAFE_TO_DISPATCH
    if stage is TransactionStage.CHECKPOINTED:
        return RecoveryClassification.COMPLETE
    if stage is TransactionStage.CONFLICTED:
        return RecoveryClassification.CONFLICT_REQUIRES_RESOLUTION
    # DISPATCHED and every successful post-response stage remain mutation-free
    # recovery states.  A caller can reconcile and append; it must not replay.
    return RecoveryClassification.READ_ONLY_RECONCILIATION_REQUIRED


def parse_transaction_records(
    records: Iterable[TransactionRecord],
) -> Mapping[str, TransactionState]:
    """Validate record histories and return latest state by commit UUID.

    Histories from different commits may be interleaved.  Within a commit, the
    identity fields are immutable and every stage must be the exact next stage.
    """

    mutable: Dict[str, TransactionState] = {}
    for position, record in enumerate(records, 1):
        if position > MAX_JOURNAL_RECORDS:
            raise JournalCapacityError("journal exceeds the record limit")
        if not isinstance(record, TransactionRecord):
            raise JournalCorruptionError(
                "journal record %d is not a TransactionRecord" % position
            )
        previous = mutable.get(record.commit_uuid)
        if previous is None:
            if record.stage is not TransactionStage.PREPARED:
                raise JournalCorruptionError(
                    "transaction %s does not begin with prepared"
                    % record.commit_uuid
                )
            mutable[record.commit_uuid] = TransactionState(record, 1)
            continue

        before = previous.record
        if _identity(before) != _identity(record):
            raise JournalCorruptionError(
                "transaction %s changed immutable identity fields"
                % record.commit_uuid
            )
        if record.stage not in _ALLOWED_TRANSITIONS[before.stage]:
            raise JournalCorruptionError(
                "transaction %s has invalid transition %s -> %s"
                % (record.commit_uuid, before.stage.value, record.stage.value)
            )
        if (
            before.provider_response_version is not None
            and record.provider_response_version
            != before.provider_response_version
        ):
            raise JournalCorruptionError(
                "transaction %s changed its bound provider response version"
                % record.commit_uuid
            )
        mutable[record.commit_uuid] = TransactionState(
            record, previous.record_count + 1
        )
    return MappingProxyType(mutable)


class TransactionJournal:
    """A locked, mode-0600, append-only JSONL transaction journal.

    The journal's containing directory must already exist, be owned by the
    effective user, and not be group- or world-writable.  Every path component
    is opened with ``O_NOFOLLOW``.  Existing journals must be regular,
    single-link files owned by the effective user with exactly mode ``0600``.
    """

    def __init__(self, path: Union[str, os.PathLike[str]]) -> None:
        self._path = _validate_journal_path(path)

    @property
    def path(self) -> str:
        return self._path

    def append(self, record: TransactionRecord) -> TransactionState:
        """Validate, append, and fsync exactly one complete JSONL record."""

        if not isinstance(record, TransactionRecord):
            raise TypeError("record must be TransactionRecord")
        encoded = _encode_record(record)
        parent_fd, leaf = _open_parent_directory(self._path)
        journal_fd = -1
        created = False
        locked = False
        try:
            journal_fd, created = _open_journal_for_append(parent_fd, leaf)
            _lock(journal_fd, fcntl.LOCK_EX)
            locked = True
            before = _validate_journal_fd(journal_fd, require_append=True)
            _require_path_matches_fd(parent_fd, leaf, journal_fd)
            records = _read_records_fd(journal_fd)
            states = parse_transaction_records(tuple(records) + (record,))
            if before.st_size + len(encoded) > MAX_JOURNAL_BYTES:
                raise JournalCapacityError("journal exceeds the byte limit")
            _require_path_matches_fd(parent_fd, leaf, journal_fd)
            written = os.write(journal_fd, encoded)
            if written != len(encoded):
                raise TransactionJournalError("journal append was incomplete")
            os.fsync(journal_fd)
            if created:
                os.fsync(parent_fd)
            after = _validate_journal_fd(journal_fd, require_append=True)
            if after.st_size != before.st_size + len(encoded):
                raise JournalSecurityError("journal size changed during append")
            _require_path_matches_fd(parent_fd, leaf, journal_fd)
            return states[record.commit_uuid]
        except OSError as exc:
            raise TransactionJournalError("journal append failed") from exc
        finally:
            if journal_fd >= 0:
                try:
                    if locked:
                        _lock(journal_fd, fcntl.LOCK_UN)
                finally:
                    os.close(journal_fd)
            os.close(parent_fd)

    def read_records(self) -> Tuple[TransactionRecord, ...]:
        """Read and validate a stable journal snapshot under a shared lock."""

        parent_fd, leaf = _open_parent_directory(self._path)
        journal_fd = -1
        locked = False
        try:
            try:
                journal_fd = _open_existing_journal(parent_fd, leaf, os.O_RDONLY)
            except FileNotFoundError:
                return ()
            _lock(journal_fd, fcntl.LOCK_SH)
            locked = True
            _validate_journal_fd(journal_fd, require_append=False)
            _require_path_matches_fd(parent_fd, leaf, journal_fd)
            records = _read_records_fd(journal_fd)
            parse_transaction_records(records)
            _require_path_matches_fd(parent_fd, leaf, journal_fd)
            return records
        except OSError as exc:
            raise TransactionJournalError("journal read failed") from exc
        finally:
            if journal_fd >= 0:
                try:
                    if locked:
                        _lock(journal_fd, fcntl.LOCK_UN)
                finally:
                    os.close(journal_fd)
            os.close(parent_fd)

    def read_states(self) -> Mapping[str, TransactionState]:
        """Return fully validated latest state for every journalled commit."""

        return parse_transaction_records(self.read_records())

    def state(self, commit_uuid: str) -> Optional[TransactionState]:
        """Return one transaction state, or ``None`` when it is not present."""

        _require_canonical_uuid(commit_uuid, "commit_uuid")
        return self.read_states().get(commit_uuid)


def _identity(record: TransactionRecord) -> Tuple[str, str, str, str]:
    return (
        record.slug,
        record.base_version,
        record.commit_uuid,
        record.target_snapshot_sha,
    )


def _require_canonical_uuid(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError("%s must be a string" % name)
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError("%s must be a canonical UUID" % name) from exc
    if str(parsed) != value:
        raise ValueError("%s must be a canonical UUID" % name)
    return value


def _require_provider_identifier(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError("%s must be a string" % name)
    if not value or len(value) > 256:
        raise ValueError("%s must contain 1 to 256 characters" % name)
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
        raise ValueError("%s must contain printable ASCII without spaces" % name)
    return value


def _require_snapshot_sha(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("target_snapshot_sha must be a string")
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("target_snapshot_sha must be a lowercase SHA-256 digest")
    return value


def _encode_record(record: TransactionRecord) -> bytes:
    raw = json.dumps(
        record.to_dict(),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("transaction record exceeds the byte limit")
    return raw


def _decode_record(raw: bytes, line_number: int) -> TransactionRecord:
    if not raw.endswith(b"\n"):
        raise JournalCorruptionError("journal has an incomplete final record")
    if len(raw) > MAX_RECORD_BYTES:
        raise JournalCorruptionError(
            "journal record %d exceeds the byte limit" % line_number
        )
    try:
        text = raw[:-1].decode("ascii")
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise JournalCorruptionError(
            "journal record %d is not strict JSON" % line_number
        ) from exc
    if not isinstance(value, dict) or frozenset(value) != _RECORD_KEYS:
        raise JournalCorruptionError(
            "journal record %d does not match the fixed schema" % line_number
        )
    if value.get("format") != JOURNAL_FORMAT:
        raise JournalCorruptionError(
            "journal record %d has an unsupported format" % line_number
        )
    try:
        stage = TransactionStage(value["stage"])
        return TransactionRecord(
            stage=stage,
            slug=value["slug"],
            base_version=value["base_version"],
            commit_uuid=value["commit_uuid"],
            target_snapshot_sha=value["target_snapshot_sha"],
            provider_response_version=value["provider_response_version"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise JournalCorruptionError(
            "journal record %d has invalid field values" % line_number
        ) from exc


def _strict_object(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError("non-finite JSON value: %s" % value)


def _read_records_fd(fd: int) -> Tuple[TransactionRecord, ...]:
    if os.fstat(fd).st_size > MAX_JOURNAL_BYTES:
        raise JournalCapacityError("journal exceeds the byte limit")
    os.lseek(fd, 0, os.SEEK_SET)
    records = []
    pending = b""
    line_number = 0
    while True:
        chunk = os.read(fd, _READ_CHUNK_BYTES)
        if not chunk:
            break
        pending += chunk
        while True:
            end = pending.find(b"\n")
            if end < 0:
                if len(pending) >= MAX_RECORD_BYTES:
                    raise JournalCorruptionError(
                        "journal record exceeds the byte limit"
                    )
                break
            line_number += 1
            if line_number > MAX_JOURNAL_RECORDS:
                raise JournalCapacityError("journal exceeds the record limit")
            raw = pending[: end + 1]
            pending = pending[end + 1 :]
            records.append(_decode_record(raw, line_number))
    if pending:
        raise JournalCorruptionError("journal has an incomplete final record")
    return tuple(records)


def _validate_journal_path(path: Union[str, os.PathLike[str]]) -> str:
    try:
        raw = os.fspath(path)
    except TypeError as exc:
        raise JournalSecurityError("journal path must be path-like") from exc
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise JournalSecurityError("journal path must be a non-empty text path")
    if any(part == ".." for part in raw.split(os.sep)):
        raise JournalSecurityError("journal path must not contain parent traversal")
    absolute = os.path.abspath(raw)
    leaf = os.path.basename(absolute)
    if leaf in ("", ".", ".."):
        raise JournalSecurityError("journal path must name a file")
    return absolute


def _open_parent_directory(path: str) -> Tuple[int, str]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if not nofollow or not directory:
        raise JournalSecurityError(
            "secure journal paths require O_NOFOLLOW and O_DIRECTORY"
        )
    parts = path.split(os.sep)
    leaf = parts[-1]
    parent_parts = [part for part in parts[1:-1] if part]
    current_fd = os.open(os.sep, os.O_RDONLY | directory | cloexec)
    try:
        for component in parent_parts:
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | directory | cloexec | nofollow,
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise JournalSecurityError(
                    "journal path contains an unavailable or linked directory"
                ) from exc
            os.close(current_fd)
            current_fd = next_fd
        parent_stat = os.fstat(current_fd)
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise JournalSecurityError("journal parent is not a directory")
        if parent_stat.st_uid != os.geteuid():
            raise JournalSecurityError("journal parent is not owned by this user")
        if stat.S_IMODE(parent_stat.st_mode) & 0o022:
            raise JournalSecurityError("journal parent is group- or world-writable")
        return current_fd, leaf
    except BaseException:
        os.close(current_fd)
        raise


def _open_existing_journal(parent_fd: int, leaf: str, access: int) -> int:
    flags = access | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    try:
        return os.open(leaf, flags, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            raise FileNotFoundError(leaf) from exc
        raise JournalSecurityError(
            "journal is unavailable or is a symbolic link"
        ) from exc


def _open_journal_for_append(parent_fd: int, leaf: str) -> Tuple[int, bool]:
    flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    try:
        return os.open(leaf, flags, dir_fd=parent_fd), False
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise JournalSecurityError(
                "journal is unavailable or is a symbolic link"
            ) from exc
    try:
        return os.open(
            leaf,
            flags | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=parent_fd,
        ), True
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            reopened = _open_existing_journal(
                parent_fd, leaf, os.O_RDWR | os.O_APPEND
            )
            return reopened, False
        raise JournalSecurityError("journal could not be created securely") from exc


def _validate_journal_fd(fd: int, *, require_append: bool) -> os.stat_result:
    details = os.fstat(fd)
    if not stat.S_ISREG(details.st_mode):
        raise JournalSecurityError("journal must be a regular file")
    if details.st_uid != os.geteuid():
        raise JournalSecurityError("journal is not owned by this user")
    if stat.S_IMODE(details.st_mode) != 0o600:
        raise JournalSecurityError("journal mode must be exactly 0600")
    if details.st_nlink != 1:
        raise JournalSecurityError("journal must not be hard-linked")
    if require_append:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if not flags & os.O_APPEND:
            raise JournalSecurityError("journal writer must use O_APPEND")
    return details


def _require_path_matches_fd(parent_fd: int, leaf: str, fd: int) -> None:
    """Reject concurrent removal, replacement, or rotation of the journal."""

    opened = os.fstat(fd)
    try:
        current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise JournalSecurityError("journal path changed while it was open") from exc
    if not stat.S_ISREG(current.st_mode):
        raise JournalSecurityError("journal path no longer names a regular file")
    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        raise JournalSecurityError("journal path was replaced while it was open")


def _lock(fd: int, operation: int) -> None:
    try:
        fcntl.flock(fd, operation)
    except OSError as exc:
        raise TransactionJournalError("journal lock failed") from exc


__all__ = [
    "JOURNAL_FORMAT",
    "MAX_JOURNAL_BYTES",
    "MAX_JOURNAL_RECORDS",
    "MAX_RECORD_BYTES",
    "InvalidTransitionError",
    "JournalCapacityError",
    "JournalCorruptionError",
    "JournalSecurityError",
    "RecoveryClassification",
    "TransactionJournal",
    "TransactionJournalError",
    "TransactionRecord",
    "TransactionStage",
    "TransactionState",
    "classify_recovery",
    "parse_transaction_records",
]

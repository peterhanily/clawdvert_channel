"""Owner-only lifecycle journals for seeded Standard Artifact publication."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from typing import Any

from .chat_seeded_publish import (
    DIGEST_RE,
    UUID_RE,
    SeedBinding,
    SeededCloneBinding,
    SeededPublicResult,
)
from .frames import FrameError


SCHEMA = "clawdvert.seeded-public-standard.v1"
MAX_RECEIPT_BYTES = 512 * 1024
MAX_RECORD_BYTES = 32 * 1024
SAFE_BASENAME_RE = re.compile(r"^[^/\\\x00]{1,255}$")

_KEYS = {
    "schema",
    "stage",
    "organization_uuid",
    "account_email_sha256",
    "target_source_sha256",
    "target_source_bytes",
    "seed_source_sha256",
    "seed_source_bytes",
    "seed_published_uuid",
    "seed_conversation_uuid",
    "seed_artifact_uuid",
    "seed_version_uuid",
    "seed_message_uuid",
    "seed_artifact_identifier",
    "seed_artifact_type",
    "seed_code_language",
    "seed_title",
    "clone_conversation_uuid",
    "clone_artifact_uuid",
    "clone_version_uuid",
    "clone_message_uuid",
    "clone_artifact_identifier",
    "clone_artifact_type",
    "clone_code_language",
    "clone_title",
    "observed_clone_conversation_uuid",
    "observed_published_uuid",
    "published_uuid",
    "public_url",
}
_STAGES = {
    "prepared",
    "remix_pending",
    "clone_bound",
    "publish_pending",
    "publish_rejected",
    "public_bound",
    "published",
    "unpublish_pending",
    "unpublished",
    "delete_pending",
    "deleted",
}
_TRANSITIONS = {
    "prepared": {"remix_pending"},
    "remix_pending": {"clone_bound"},
    "clone_bound": {"publish_pending", "delete_pending"},
    "publish_pending": {"public_bound", "publish_rejected"},
    "publish_rejected": {"delete_pending"},
    "public_bound": {"published", "unpublish_pending", "unpublished"},
    "published": {"unpublish_pending"},
    "unpublish_pending": {"unpublished"},
    "unpublished": {"delete_pending"},
    "delete_pending": {"deleted"},
    "deleted": set(),
}
_IMMUTABLE = {
    "schema",
    "organization_uuid",
    "account_email_sha256",
    "target_source_sha256",
    "target_source_bytes",
    "seed_source_sha256",
    "seed_source_bytes",
    "seed_published_uuid",
    "seed_conversation_uuid",
    "seed_artifact_uuid",
    "seed_version_uuid",
    "seed_message_uuid",
    "seed_artifact_identifier",
    "seed_artifact_type",
    "seed_code_language",
    "seed_title",
}
_PROGRESSIVE = _KEYS - _IMMUTABLE - {"stage"}
_OBSERVATION_KEYS = {
    "observed_clone_conversation_uuid",
    "observed_published_uuid",
}


def _safe_text(value: Any, *, allow_empty: bool = False) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 1000
        and (allow_empty or bool(value))
        and re.search(r"[\x00-\x1f\x7f]", value) is None
    )


def _hash_source(source: Any, label: str) -> tuple[str, int]:
    if not isinstance(source, str) or not source:
        raise FrameError(f"seeded-public {label} must be non-empty text")
    try:
        encoded = source.encode("utf-8")
    except UnicodeEncodeError:
        raise FrameError(f"seeded-public {label} is not valid UTF-8") from None
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


def _open_parent(path: str) -> tuple[str, int, str]:
    absolute = os.path.abspath(path)
    parent = os.path.dirname(absolute) or os.curdir
    basename = os.path.basename(absolute)
    if not SAFE_BASENAME_RE.fullmatch(basename):
        raise FrameError("seeded-public receipt filename is invalid")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(parent, flags)
    except OSError:
        raise FrameError("seeded-public receipt directory is unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise FrameError("seeded-public receipt parent is not a directory")
    except Exception:
        os.close(descriptor)
        raise
    return absolute, descriptor, basename


def validate_new_receipt(path: str) -> None:
    _absolute, parent, basename = _open_parent(path)
    try:
        try:
            os.stat(basename, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            raise FrameError(
                "seeded-public receipt path could not be checked safely"
            ) from None
        raise FrameError("seeded-public receipt already exists; refusing to overwrite it")
    finally:
        os.close(parent)


def load_seed_binding(
    path: str,
    *,
    organization_uuid: str,
    account_email_sha256: str,
    source: str,
    read_only: bool = False,
) -> SeedBinding:
    """Load one fully published conversation receipt as a reusable seed."""

    # Import lazily to avoid a module cycle while the CLI imports this module.
    from . import publish as publish_cli

    lifecycle = publish_cli._ConversationReceiptLifecycle(
        path,
        organization_uuid=organization_uuid,
        account_email_sha256=account_email_sha256,
        source=source,
        repair_partial_tail=False,
    )
    try:
        if lifecycle.has_partial_tail and not read_only:
            raise FrameError(
                "seeded-public seed receipt has a partial trailing record; "
                "review and repair it before a live operation"
            )
        if lifecycle.stage != "published":
            raise FrameError(
                "seeded-public seed receipt must describe an active verified "
                f"publication; current stage: {lifecycle.stage}"
            )
        result = lifecycle.result()
        if (
            result.public is not True
            or result.published_deleted
            or result.published_uuid is None
            or result.organization_uuid != organization_uuid
            or result.source_sha256 != hashlib.sha256(source.encode("utf-8")).hexdigest()
        ):
            raise FrameError("seeded-public seed receipt is not an active publication")
        return SeedBinding(
            organization_uuid=organization_uuid,
            account_email_sha256=account_email_sha256,
            published_uuid=result.published_uuid,
            conversation_uuid=result.conversation_uuid,
            artifact_uuid=result.artifact_uuid,
            version_uuid=result.version_uuid,
            message_uuid=result.message_uuid,
            artifact_identifier=result.artifact_identifier,
            artifact_type=result.artifact_type,
            code_language=result.code_language,
            title=result.title,
            source=source,
            source_sha256=result.source_sha256,
        )
    finally:
        lifecycle.close()


class _ReceiptFile:
    def __init__(self) -> None:
        self.path: str
        self._parent: int | None = None
        self._descriptor: int | None = None
        self._basename: str
        self._device: int
        self._inode: int
        self._partial_tail_size = 0

    def _check_boundary(self) -> os.stat_result:
        if self._descriptor is None or self._parent is None:
            raise FrameError("seeded-public receipt is closed")
        current = os.fstat(self._descriptor)
        path_status = os.stat(
            self._basename, dir_fd=self._parent, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.getuid()
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_dev != self._device
            or current.st_ino != self._inode
            or path_status.st_dev != self._device
            or path_status.st_ino != self._inode
            or stat.S_ISLNK(path_status.st_mode)
            or current.st_size > MAX_RECEIPT_BYTES
        ):
            raise FrameError("seeded-public receipt lost its owner-only boundary")
        return current

    def _append(self, value: dict[str, Any]) -> None:
        payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        if len(payload) > MAX_RECORD_BYTES:
            raise FrameError("seeded-public receipt record is too large")
        status = self._check_boundary()
        if self._partial_tail_size:
            raise FrameError(
                "seeded-public receipt has a partial trailing record; "
                "repair it explicitly before mutation"
            )
        if status.st_size + len(payload) > MAX_RECEIPT_BYTES:
            raise FrameError("seeded-public receipt is too large")
        try:
            os.lseek(self._descriptor, 0, os.SEEK_END)
            written = 0
            while written < len(payload):
                count = os.write(self._descriptor, payload[written:])
                if count <= 0:
                    raise OSError("short write")
                written += count
            os.fsync(self._descriptor)
        except OSError:
            raise FrameError("seeded-public receipt could not be updated") from None

    @property
    def has_partial_tail(self) -> bool:
        """Whether a crash fragment was observed without modifying the file."""

        return bool(self._partial_tail_size)

    def repair_partial_tail(self) -> None:
        """Explicitly discard only an incomplete final JSONL record.

        Loading is deliberately non-repairing so inspection and ``--dry-run``
        stay byte-for-byte read-only.  Callers that intend a later mutation may
        opt into this narrowly bounded repair after reviewing the receipt.
        """

        if not self._partial_tail_size:
            return
        status = self._check_boundary()
        valid_size = status.st_size - self._partial_tail_size
        if valid_size < 1:
            raise FrameError("seeded-public receipt has no durable record to repair")
        try:
            os.ftruncate(self._descriptor, valid_size)
            os.fsync(self._descriptor)
        except OSError:
            raise FrameError(
                "seeded-public receipt tail could not be repaired"
            ) from None
        self._partial_tail_size = 0

    def close(self) -> None:
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None
        if self._parent is not None:
            os.close(self._parent)
            self._parent = None


class SeededReceiptJournal(_ReceiptFile):
    """Create and append one seeded-public operation journal."""

    def __init__(self, path: str, *, seed: SeedBinding, target_source: str) -> None:
        super().__init__()
        self._seed = seed
        target_sha, target_bytes = _hash_source(target_source, "target source")
        seed_sha, seed_bytes = _hash_source(seed.source, "seed source")
        self.path, self._parent, self._basename = _open_parent(path)
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            self._descriptor = os.open(
                self._basename, flags, 0o600, dir_fd=self._parent
            )
            os.fchmod(self._descriptor, 0o600)
            fcntl.flock(self._descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            status = os.fstat(self._descriptor)
            self._device, self._inode = status.st_dev, status.st_ino
            self._value = {
                "schema": SCHEMA,
                "stage": "prepared",
                "organization_uuid": seed.organization_uuid,
                "account_email_sha256": seed.account_email_sha256,
                "target_source_sha256": target_sha,
                "target_source_bytes": target_bytes,
                "seed_source_sha256": seed_sha,
                "seed_source_bytes": seed_bytes,
                "seed_published_uuid": seed.published_uuid,
                "seed_conversation_uuid": seed.conversation_uuid,
                "seed_artifact_uuid": seed.artifact_uuid,
                "seed_version_uuid": seed.version_uuid,
                "seed_message_uuid": seed.message_uuid,
                "seed_artifact_identifier": seed.artifact_identifier,
                "seed_artifact_type": seed.artifact_type,
                "seed_code_language": seed.code_language,
                "seed_title": seed.title,
                "clone_conversation_uuid": None,
                "clone_artifact_uuid": None,
                "clone_version_uuid": None,
                "clone_message_uuid": None,
                "clone_artifact_identifier": None,
                "clone_artifact_type": None,
                "clone_code_language": None,
                "clone_title": None,
                "observed_clone_conversation_uuid": None,
                "observed_published_uuid": None,
                "published_uuid": None,
                "public_url": None,
            }
            self._append(self._value)
            os.fsync(self._parent)
        except Exception:
            self.close()
            raise

    @property
    def stage(self) -> str:
        return self._value["stage"]

    def _advance(self, stage: str) -> None:
        if stage not in _TRANSITIONS.get(self.stage, set()):
            raise FrameError(
                f"seeded-public receipt cannot move from {self.stage} to {stage}"
            )
        previous = self._value["stage"]
        self._value["stage"] = stage
        try:
            self._append(self._value)
        except Exception:
            self._value["stage"] = previous
            raise

    def mark_remix_pending(self, _intent: Any = None) -> None:
        self._advance("remix_pending")

    def record_observations(
        self,
        *,
        clone_conversation_uuid: str | None = None,
        published_uuid: str | None = None,
    ) -> None:
        _record_observations(
            self,
            clone_conversation_uuid=clone_conversation_uuid,
            published_uuid=published_uuid,
        )

    def record_clone(self, clone: SeededCloneBinding) -> None:
        if (
            self.stage != "remix_pending"
            or clone.seed != self.seed_binding()
            or (
                self._value["observed_clone_conversation_uuid"] is not None
                and self._value["observed_clone_conversation_uuid"]
                != clone.conversation_uuid
            )
        ):
            raise FrameError("seeded-public clone receipt binding changed")
        fields = {
            "clone_conversation_uuid": clone.conversation_uuid,
            "clone_artifact_uuid": clone.artifact_uuid,
            "clone_version_uuid": clone.version_uuid,
            "clone_message_uuid": clone.message_uuid,
            "clone_artifact_identifier": clone.artifact_identifier,
            "clone_artifact_type": clone.artifact_type,
            "clone_code_language": clone.code_language,
            "clone_title": clone.title,
        }
        self._value.update(fields)
        try:
            self._advance("clone_bound")
        except Exception:
            self._value.update({key: None for key in fields})
            raise

    def mark_publish_pending(self, _intent: Any = None) -> None:
        self._advance("publish_pending")

    def record_publish_rejected(self) -> None:
        """Record a definite rejection while retaining the exact private clone."""

        self._advance("publish_rejected")

    def _require_public_result(
        self, result: SeededPublicResult, *, verified: bool | None = None
    ) -> None:
        if self.stage != "publish_pending" or result.clone != self.clone_binding():
            raise FrameError("seeded-public publication receipt binding changed")
        if (
            result.public_source_sha256 != self._value["target_source_sha256"]
            or result.published_deleted
            or (verified is not None and result.public_verified is not verified)
        ):
            raise FrameError("seeded-public publication receipt source changed")

    def record_public_bound(self, result: SeededPublicResult) -> None:
        """Durably retain an owner-bound public UUID before public readback."""

        self._require_public_result(result)
        fields = {
            "published_uuid": result.published_uuid,
            "public_url": result.url,
        }
        self._value.update(fields)
        try:
            self._advance("public_bound")
        except Exception:
            self._value.update({key: None for key in fields})
            raise

    def mark_published(self, result: SeededPublicResult) -> None:
        """Advance only after exact anonymous public readback was verified."""

        if (
            self.stage != "public_bound"
            or result.clone != self.clone_binding()
            or result.published_uuid != self._value["published_uuid"]
            or result.url != self._value["public_url"]
            or result.public_source_sha256 != self._value["target_source_sha256"]
            or result.public_verified is not True
            or result.published_deleted
        ):
            raise FrameError("seeded-public public verification binding changed")
        self._advance("published")

    def record_published(self, result: SeededPublicResult) -> None:
        """Compatibility helper for an already fully verified public result."""

        if self.stage == "publish_pending":
            self._require_public_result(result, verified=True)
            self.record_public_bound(result)
        self.mark_published(result)

    def seed_binding(self) -> SeedBinding:
        return _seed_from_value(self._value, self._seed_source())

    def _seed_source(self) -> str:
        # Journal construction has the exact source only transiently; callbacks
        # compare against the seed object cached below instead of persisting it.
        return self._seed.source

    def clone_binding(self) -> SeededCloneBinding:
        return _clone_from_value(self._value, self.seed_binding())


def _seed_from_value(value: dict[str, Any], source: str) -> SeedBinding:
    return SeedBinding(
        organization_uuid=value["organization_uuid"],
        account_email_sha256=value["account_email_sha256"],
        published_uuid=value["seed_published_uuid"],
        conversation_uuid=value["seed_conversation_uuid"],
        artifact_uuid=value["seed_artifact_uuid"],
        version_uuid=value["seed_version_uuid"],
        message_uuid=value["seed_message_uuid"],
        artifact_identifier=value["seed_artifact_identifier"],
        artifact_type=value["seed_artifact_type"],
        code_language=value["seed_code_language"],
        title=value["seed_title"],
        source=source,
        source_sha256=value["seed_source_sha256"],
    )


def _clone_from_value(
    value: dict[str, Any], seed: SeedBinding
) -> SeededCloneBinding:
    required = (
        "clone_conversation_uuid",
        "clone_artifact_uuid",
        "clone_version_uuid",
        "clone_message_uuid",
        "clone_artifact_identifier",
        "clone_artifact_type",
        "clone_title",
    )
    if any(value.get(key) is None for key in required):
        raise FrameError("seeded-public receipt has no exact clone binding")
    return SeededCloneBinding(
        seed=seed,
        conversation_uuid=value["clone_conversation_uuid"],
        artifact_uuid=value["clone_artifact_uuid"],
        version_uuid=value["clone_version_uuid"],
        message_uuid=value["clone_message_uuid"],
        artifact_identifier=value["clone_artifact_identifier"],
        artifact_type=value["clone_artifact_type"],
        code_language=value["clone_code_language"],
        title=value["clone_title"],
    )


def _record_observations(
    receipt: _ReceiptFile,
    *,
    clone_conversation_uuid: str | None,
    published_uuid: str | None,
) -> None:
    """Append response-only identifiers without granting cleanup authority."""

    if clone_conversation_uuid is None and published_uuid is None:
        raise FrameError("seeded-public receipt observation is empty")
    if receipt._value["stage"] == "deleted":
        raise FrameError("seeded-public deleted receipt cannot gain observations")
    proposed = {
        "observed_clone_conversation_uuid": clone_conversation_uuid,
        "observed_published_uuid": published_uuid,
    }
    seed_ids = {
        receipt._value["seed_published_uuid"],
        receipt._value["seed_conversation_uuid"],
        receipt._value["seed_artifact_uuid"],
        receipt._value["seed_version_uuid"],
        receipt._value["seed_message_uuid"],
    }
    clone_ids = {
        receipt._value[key]
        for key in (
            "clone_conversation_uuid",
            "clone_artifact_uuid",
            "clone_version_uuid",
            "clone_message_uuid",
        )
        if receipt._value[key] is not None
    }
    for key, value in proposed.items():
        if value is None:
            continue
        if not UUID_RE.fullmatch(value):
            raise FrameError("seeded-public receipt observation is not a provider UUID")
        current = receipt._value[key]
        if current is not None and current != value:
            raise FrameError("seeded-public receipt observation changed")
        if value in seed_ids:
            raise FrameError("seeded-public receipt observation overlaps the seed")
    if clone_conversation_uuid is not None:
        bound = receipt._value["clone_conversation_uuid"]
        if bound is not None and clone_conversation_uuid != bound:
            raise FrameError("seeded-public clone observation conflicts with its binding")
    if published_uuid is not None:
        if published_uuid in clone_ids:
            raise FrameError("seeded-public public observation overlaps clone provenance")
    effective_clone = (
        clone_conversation_uuid
        or receipt._value["observed_clone_conversation_uuid"]
    )
    effective_public = published_uuid or receipt._value["observed_published_uuid"]
    if effective_clone is not None and effective_clone == effective_public:
        raise FrameError("seeded-public receipt observations overlap")
    changed_keys: list[str] = []
    for key, value in proposed.items():
        if value is not None and receipt._value[key] is None:
            receipt._value[key] = value
            changed_keys.append(key)
    if changed_keys:
        try:
            receipt._append(receipt._value)
        except Exception:
            for key in changed_keys:
                receipt._value[key] = None
            raise


def _validate_value(
    value: Any,
    *,
    organization_uuid: str,
    account_email_sha256: str,
    seed_source: str,
    target_source: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _KEYS:
        raise FrameError("seeded-public receipt has an unsupported shape")
    if value.get("schema") != SCHEMA or value.get("stage") not in _STAGES:
        raise FrameError("seeded-public receipt has an unsupported schema or stage")
    if (
        value.get("organization_uuid") != organization_uuid
        or not UUID_RE.fullmatch(organization_uuid or "")
    ):
        raise FrameError("seeded-public receipt belongs to another organization")
    if (
        value.get("account_email_sha256") != account_email_sha256
        or not DIGEST_RE.fullmatch(account_email_sha256 or "")
    ):
        raise FrameError("seeded-public receipt belongs to another account binding")
    seed_sha, seed_bytes = _hash_source(seed_source, "seed source")
    target_sha, target_bytes = _hash_source(target_source, "target source")
    if (
        value.get("seed_source_sha256") != seed_sha
        or value.get("seed_source_bytes") != seed_bytes
        or value.get("target_source_sha256") != target_sha
        or value.get("target_source_bytes") != target_bytes
    ):
        raise FrameError("seeded-public receipt does not match the source files")
    for key in (
        "seed_published_uuid",
        "seed_conversation_uuid",
        "seed_artifact_uuid",
        "seed_version_uuid",
        "seed_message_uuid",
    ):
        if not UUID_RE.fullmatch(value.get(key) or ""):
            raise FrameError("seeded-public receipt contains an invalid seed identifier")
    if len(
        {
            value["seed_published_uuid"],
            value["seed_conversation_uuid"],
            value["seed_artifact_uuid"],
            value["seed_version_uuid"],
            value["seed_message_uuid"],
        }
    ) != 5:
        raise FrameError("seeded-public receipt seed identifiers overlap")
    for key in ("seed_artifact_identifier", "seed_artifact_type", "seed_title"):
        if not _safe_text(value.get(key)):
            raise FrameError("seeded-public receipt contains invalid seed metadata")
    if value.get("seed_code_language") is not None and not _safe_text(
        value["seed_code_language"], allow_empty=True
    ):
        raise FrameError("seeded-public receipt contains invalid seed language")

    clone_fields = (
        "clone_conversation_uuid",
        "clone_artifact_uuid",
        "clone_version_uuid",
        "clone_message_uuid",
        "clone_artifact_identifier",
        "clone_artifact_type",
        "clone_code_language",
        "clone_title",
    )
    clone_bound = value["stage"] not in {"prepared", "remix_pending"}
    if clone_bound:
        for key in clone_fields[:4]:
            if not UUID_RE.fullmatch(value.get(key) or ""):
                raise FrameError("seeded-public receipt contains an invalid clone ID")
        if any(value[key] in {
            value["seed_published_uuid"], value["seed_conversation_uuid"],
            value["seed_artifact_uuid"], value["seed_version_uuid"],
            value["seed_message_uuid"],
        } for key in clone_fields[:4]):
            raise FrameError("seeded-public receipt clone identifier overlaps the seed")
        if len({value[key] for key in clone_fields[:4]}) != 4:
            raise FrameError("seeded-public receipt clone identifiers overlap")
        for key in ("clone_artifact_identifier", "clone_artifact_type", "clone_title"):
            if not _safe_text(value.get(key)):
                raise FrameError("seeded-public receipt contains invalid clone metadata")
        if value.get("clone_code_language") is not None and not _safe_text(
            value["clone_code_language"], allow_empty=True
        ):
            raise FrameError("seeded-public receipt contains invalid clone language")
        if (
            value["clone_artifact_type"] != value["seed_artifact_type"]
            or value["clone_code_language"] != value["seed_code_language"]
            or value["clone_title"] != value["seed_title"]
        ):
            raise FrameError("seeded-public receipt clone metadata changed")
    elif any(value.get(key) is not None for key in clone_fields):
        raise FrameError("seeded-public receipt binds a clone before remix completion")

    observed_clone = value.get("observed_clone_conversation_uuid")
    observed_public = value.get("observed_published_uuid")
    for observed in (observed_clone, observed_public):
        if observed is not None and not UUID_RE.fullmatch(observed):
            raise FrameError("seeded-public receipt contains an invalid observation")
    seed_ids = {
        value["seed_published_uuid"], value["seed_conversation_uuid"],
        value["seed_artifact_uuid"], value["seed_version_uuid"],
        value["seed_message_uuid"],
    }
    if observed_clone in seed_ids or observed_public in seed_ids:
        raise FrameError("seeded-public receipt observation overlaps the seed")
    if (
        observed_clone is not None
        and value.get("clone_conversation_uuid") is not None
        and observed_clone != value["clone_conversation_uuid"]
    ):
        raise FrameError("seeded-public clone observation conflicts with its binding")
    if observed_public is not None and observed_public in {
        value.get("clone_conversation_uuid"), value.get("clone_artifact_uuid"),
        value.get("clone_version_uuid"), value.get("clone_message_uuid"),
    }:
        raise FrameError("seeded-public public observation overlaps clone provenance")
    if observed_clone is not None and observed_clone == observed_public:
        raise FrameError("seeded-public receipt observations overlap")

    public_required = value["stage"] in {
        "public_bound", "published", "unpublish_pending", "unpublished"
    }
    public_fields = (
        value.get("published_uuid") is not None,
        value.get("public_url") is not None,
    )
    if public_fields[0] != public_fields[1]:
        raise FrameError("seeded-public receipt has a partial public binding")
    has_public_binding = all(public_fields)
    if public_required and not has_public_binding:
        raise FrameError("seeded-public receipt has no required public binding")
    if has_public_binding:
        if not UUID_RE.fullmatch(value.get("published_uuid") or ""):
            raise FrameError("seeded-public receipt contains an invalid public ID")
        if value["published_uuid"] in {
            value["seed_published_uuid"], value["seed_conversation_uuid"],
            value["seed_artifact_uuid"], value["seed_version_uuid"],
            value["seed_message_uuid"], value["clone_conversation_uuid"],
            value["clone_artifact_uuid"], value["clone_version_uuid"],
            value["clone_message_uuid"],
        }:
            raise FrameError("seeded-public receipt public mapping overlaps provenance")
        if value.get("public_url") != (
            "https://claude.ai/public/artifacts/" + value["published_uuid"]
        ):
            raise FrameError("seeded-public receipt contains an invalid public URL")
    if (
        has_public_binding
        and value["stage"] in {
            "prepared", "remix_pending", "clone_bound", "publish_pending",
            "publish_rejected",
        }
    ):
        raise FrameError("seeded-public receipt binds publication too early")
    return value


def _validate_history(records: list[dict[str, Any]]) -> None:
    if not records or records[0]["stage"] != "prepared":
        raise FrameError("seeded-public receipt has no prepared record")
    for before, after in zip(records, records[1:]):
        if after["stage"] == before["stage"]:
            changed = {
                key for key in _KEYS if before[key] != after[key]
            }
            if not changed or not changed <= _OBSERVATION_KEYS:
                raise FrameError("seeded-public receipt has an invalid observation history")
        elif after["stage"] not in _TRANSITIONS.get(before["stage"], set()):
            raise FrameError("seeded-public receipt has an invalid stage history")
        if any(before[key] != after[key] for key in _IMMUTABLE):
            raise FrameError("seeded-public receipt changed immutable provenance")
        for key in _PROGRESSIVE:
            if before[key] is not None and before[key] != after[key]:
                raise FrameError("seeded-public receipt changed a bound value")


class SeededReceiptLifecycle(_ReceiptFile):
    """Open, validate, lock, and advance an existing seeded-public receipt."""

    def __init__(
        self,
        path: str,
        *,
        organization_uuid: str,
        account_email_sha256: str,
        seed_source: str,
        target_source: str,
    ) -> None:
        super().__init__()
        self._seed_source = seed_source
        self._target_source = target_source
        self.path, self._parent, self._basename = _open_parent(path)
        descriptor: int | None = None
        try:
            before = os.stat(
                self._basename, dir_fd=self._parent, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_ISLNK(before.st_mode)
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size > MAX_RECEIPT_BYTES
            ):
                raise FrameError(
                    "seeded-public receipt must be an owner-only mode-0600 file"
                )
            flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self._basename, flags, dir_fd=self._parent)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._descriptor = descriptor
            after = os.fstat(descriptor)
            self._device, self._inode = after.st_dev, after.st_ino
            if before.st_dev != after.st_dev or before.st_ino != after.st_ino:
                raise FrameError("seeded-public receipt changed while opening")
            raw = os.read(descriptor, MAX_RECEIPT_BYTES + 1)
            if len(raw) > MAX_RECEIPT_BYTES:
                raise FrameError("seeded-public receipt is too large")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise FrameError("seeded-public receipt is not UTF-8") from None
            records: list[dict[str, Any]] = []
            valid_size = 0
            for line in text.splitlines(keepends=True):
                if not line.endswith("\n"):
                    break
                valid_size += len(line.encode("utf-8"))
                try:
                    item = json.loads(line)
                except ValueError:
                    raise FrameError("seeded-public receipt is not valid JSON") from None
                records.append(
                    _validate_value(
                        item,
                        organization_uuid=organization_uuid,
                        account_email_sha256=account_email_sha256,
                        seed_source=seed_source,
                        target_source=target_source,
                    )
                )
            _validate_history(records)
            self._partial_tail_size = len(raw) - valid_size
            self._value = records[-1]
            self._public_verified = any(
                record["stage"] == "published" for record in records
            )
            os.lseek(descriptor, 0, os.SEEK_END)
        except Exception:
            if descriptor is not None and self._descriptor is None:
                os.close(descriptor)
            self.close()
            raise

    @property
    def stage(self) -> str:
        return self._value["stage"]

    @property
    def seed(self) -> SeedBinding:
        return _seed_from_value(self._value, self._seed_source)

    @property
    def has_public_binding(self) -> bool:
        return self._value["published_uuid"] is not None

    @property
    def published_uuid(self) -> str | None:
        return self._value["published_uuid"]

    @property
    def observed_clone_conversation_uuid(self) -> str | None:
        return self._value["observed_clone_conversation_uuid"]

    @property
    def observed_published_uuid(self) -> str | None:
        return self._value["observed_published_uuid"]

    def clone_binding(self) -> SeededCloneBinding:
        return _clone_from_value(self._value, self.seed)

    def mark_remix_pending(self, _intent: Any = None) -> None:
        self._advance("remix_pending")

    def record_clone(self, clone: SeededCloneBinding) -> None:
        if (
            self.stage != "remix_pending"
            or clone.seed != self.seed
            or (
                self.observed_clone_conversation_uuid is not None
                and self.observed_clone_conversation_uuid != clone.conversation_uuid
            )
        ):
            raise FrameError("seeded-public clone receipt binding changed")
        fields = {
            "clone_conversation_uuid": clone.conversation_uuid,
            "clone_artifact_uuid": clone.artifact_uuid,
            "clone_version_uuid": clone.version_uuid,
            "clone_message_uuid": clone.message_uuid,
            "clone_artifact_identifier": clone.artifact_identifier,
            "clone_artifact_type": clone.artifact_type,
            "clone_code_language": clone.code_language,
            "clone_title": clone.title,
        }
        self._value.update(fields)
        try:
            self._advance("clone_bound")
        except Exception:
            self._value.update({key: None for key in fields})
            raise

    def mark_publish_pending(self, _intent: Any = None) -> None:
        self._advance("publish_pending")

    def record_publish_rejected(self) -> None:
        """Record a definite rejection while retaining the exact private clone."""

        self._advance("publish_rejected")

    def record_observations(
        self,
        *,
        clone_conversation_uuid: str | None = None,
        published_uuid: str | None = None,
    ) -> None:
        _record_observations(
            self,
            clone_conversation_uuid=clone_conversation_uuid,
            published_uuid=published_uuid,
        )

    def result(self) -> SeededPublicResult:
        if not self.has_public_binding or self.stage not in {
            "public_bound", "published", "unpublish_pending", "unpublished",
            "delete_pending", "deleted",
        }:
            raise FrameError(
                "seeded-public receipt has no exact public binding; "
                f"current stage: {self.stage}"
            )
        return SeededPublicResult(
            clone=self.clone_binding(),
            published_uuid=self._value["published_uuid"],
            public_source=self._target_source,
            public_source_sha256=self._value["target_source_sha256"],
            public_verified=self._public_verified,
            published_deleted=self.stage in {"unpublished", "delete_pending", "deleted"},
        )

    def _advance(self, stage: str) -> None:
        if stage not in _TRANSITIONS.get(self.stage, set()):
            raise FrameError(
                f"seeded-public receipt cannot move from {self.stage} to {stage}"
            )
        previous = self._value["stage"]
        self._value["stage"] = stage
        try:
            self._append(self._value)
        except Exception:
            self._value["stage"] = previous
            raise
        if stage == "published":
            self._public_verified = True

    def _public_result_matches(
        self,
        result: SeededPublicResult,
        *,
        require_verified: bool | None = None,
        require_deleted: bool | None = None,
    ) -> bool:
        return (
            result.clone == self.clone_binding()
            and result.published_uuid == self._value["published_uuid"]
            and result.url == self._value["public_url"]
            and result.public_source_sha256 == self._value["target_source_sha256"]
            and (
                require_verified is None
                or result.public_verified is require_verified
            )
            and (
                require_deleted is None
                or result.published_deleted is require_deleted
            )
        )

    def record_public_bound(self, result: SeededPublicResult) -> None:
        if (
            self.stage != "publish_pending"
            or result.clone != self.clone_binding()
            or result.public_source_sha256 != self._value["target_source_sha256"]
            or result.published_deleted
        ):
            raise FrameError("seeded-public public receipt binding changed")
        self._value.update(
            {
                "published_uuid": result.published_uuid,
                "public_url": result.url,
            }
        )
        try:
            self._advance("public_bound")
        except Exception:
            self._value["published_uuid"] = None
            self._value["public_url"] = None
            raise

    def mark_published(self, result: SeededPublicResult) -> None:
        if self.stage == "publish_pending":
            if result.public_verified is not True or result.published_deleted:
                raise FrameError("seeded-public reconciled publication is not verified")
            self.record_public_bound(result)
        if (
            self.stage != "public_bound"
            or not self._public_result_matches(
                result, require_verified=True, require_deleted=False
            )
        ):
            raise FrameError("seeded-public public verification binding changed")
        self._advance("published")

    def record_published(self, result: SeededPublicResult) -> None:
        self.mark_published(result)

    def mark_unpublish_pending(self, result: SeededPublicResult) -> None:
        if self.stage not in {"public_bound", "published"} or result != self.result():
            raise FrameError("seeded-public unpublish receipt binding changed")
        self._advance("unpublish_pending")

    def mark_unpublished(self, result: SeededPublicResult | None = None) -> None:
        if self.stage == "publish_pending":
            if (
                result is None
                or result.clone != self.clone_binding()
                or result.public_source_sha256 != self._value["target_source_sha256"]
                or not result.published_deleted
            ):
                raise FrameError("seeded-public tombstone reconciliation changed binding")
            self._value.update(
                {
                    "published_uuid": result.published_uuid,
                    "public_url": result.url,
                }
            )
            try:
                self._advance("public_bound")
            except Exception:
                self._value["published_uuid"] = None
                self._value["public_url"] = None
                raise
        if self.stage == "public_bound":
            if (
                result is None
                or not self._public_result_matches(result, require_deleted=True)
            ):
                raise FrameError("seeded-public tombstone reconciliation changed binding")
            self._advance("unpublished")
            return
        if self.stage != "unpublish_pending":
            raise FrameError(
                f"seeded-public receipt cannot move from {self.stage} to unpublished"
            )
        if result is not None and not self._public_result_matches(
            result, require_deleted=True
        ):
            raise FrameError("seeded-public unpublish receipt binding changed")
        self._advance("unpublished")

    def mark_delete_pending(self, result: SeededPublicResult | None = None) -> None:
        if self.stage not in {"clone_bound", "publish_rejected", "unpublished"}:
            raise FrameError(
                "seeded-public delete requires clone_bound, publish_rejected, "
                f"or unpublished, got {self.stage}"
            )
        if self.stage in {"clone_bound", "publish_rejected"} and result is not None:
            raise FrameError("seeded-public private clone deletion has public state")
        if self.stage == "unpublished" and result is not None and result != self.result():
            raise FrameError("seeded-public delete receipt binding changed")
        self._advance("delete_pending")

    def mark_deleted(self) -> None:
        self._advance("deleted")

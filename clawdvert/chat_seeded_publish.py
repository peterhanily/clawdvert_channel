"""Model-free seeded publication for standard Claude Artifacts.

The adapter clones one active, owned public Standard Artifact and publishes a
new public mapping from the clone's provider-issued provenance.  The requested
public source is verified byte-for-byte, while the private clone is required to
retain the seed source.  The seed is rebound before and after every mutation and
is never a cleanup target.

This module deliberately does not share the conversation publisher's result
type: for a seeded publication the private and public sources are different.
HTML is handled as inert text and is never opened or rendered by the driver.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .chat_publish import CdpSession, _localhost_json, _validate_port
from .frames import FrameError


CLAUDE_ORIGIN = "https://claude.ai"
UUID_PATTERN = (
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
UUID_RE = re.compile(r"^" + UUID_PATTERN + r"$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
TARGET_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
SAFE_STAGE_RE = re.compile(r"^[a-z0-9_]{1,100}$")
MAX_SOURCE_BYTES = 750_000
MAX_TEXT = 1000


class SeededCapabilityUnavailable(FrameError):
    """The provider rejected the seeded-public operation without creating it."""


class SeededRemoteStateUnknown(FrameError):
    """A non-retried provider mutation may have completed."""

    def __init__(
        self,
        message: str,
        *,
        stage: str | None = None,
        clone: "SeededCloneBinding | None" = None,
        clone_conversation_uuid: str | None = None,
        published_uuid: str | None = None,
        observed_published_uuid: str | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.clone = clone
        self.clone_conversation_uuid = (
            clone_conversation_uuid
            if UUID_RE.fullmatch(clone_conversation_uuid or "")
            else None
        )
        self.published_uuid = (
            published_uuid if UUID_RE.fullmatch(published_uuid or "") else None
        )
        self.observed_published_uuid = (
            observed_published_uuid
            if UUID_RE.fullmatch(observed_published_uuid or "")
            else None
        )


class SeededLocalCleanupError(FrameError):
    """The remote result is known, but the controlled tab did not close."""

    def __init__(self, message: str, *, remote_result: Any) -> None:
        super().__init__(message)
        self.remote_result = remote_result


def _safe_text(value: Any, *, allow_empty: bool = False) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= MAX_TEXT
        and (allow_empty or bool(value))
        and re.search(r"[\x00-\x1f\x7f]", value) is None
    )


def _require_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str) or not UUID_RE.fullmatch(value):
        raise FrameError(f"seeded-public {label} is not a valid provider UUID")
    return value


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise FrameError(f"seeded-public {label} is not a SHA-256 digest")
    return value


def _source_bytes(source: Any, label: str) -> bytes:
    if not isinstance(source, str) or not source:
        raise FrameError(f"seeded-public {label} must be non-empty text")
    try:
        encoded = source.encode("utf-8")
    except UnicodeEncodeError:
        raise FrameError(f"seeded-public {label} is not valid UTF-8") from None
    if len(encoded) > MAX_SOURCE_BYTES:
        raise FrameError(
            f"seeded-public {label} exceeds the {MAX_SOURCE_BYTES}-byte limit"
        )
    return encoded


def _require_metadata(
    artifact_identifier: Any,
    artifact_type: Any,
    code_language: Any,
    title: Any,
) -> None:
    if not _safe_text(artifact_identifier):
        raise FrameError("seeded-public Artifact identifier is invalid")
    if not _safe_text(artifact_type):
        raise FrameError("seeded-public Artifact type is invalid")
    if code_language is not None and not _safe_text(code_language, allow_empty=True):
        raise FrameError("seeded-public code language is invalid")
    if not _safe_text(title):
        raise FrameError("seeded-public title is invalid")


@dataclass(frozen=True)
class SeedBinding:
    organization_uuid: str
    account_email_sha256: str
    published_uuid: str
    conversation_uuid: str
    artifact_uuid: str
    version_uuid: str
    message_uuid: str
    artifact_identifier: str
    artifact_type: str
    code_language: str | None
    title: str
    source: str
    source_sha256: str

    def __post_init__(self) -> None:
        _require_uuid(self.organization_uuid, "organization")
        _require_digest(self.account_email_sha256, "account binding")
        for label, value in (
            ("seed publication", self.published_uuid),
            ("seed conversation", self.conversation_uuid),
            ("seed Artifact", self.artifact_uuid),
            ("seed version", self.version_uuid),
            ("seed message", self.message_uuid),
        ):
            _require_uuid(value, label)
        if len(
            {
                self.published_uuid,
                self.conversation_uuid,
                self.artifact_uuid,
                self.version_uuid,
                self.message_uuid,
            }
        ) != 5:
            raise FrameError("seeded-public seed identifiers overlap")
        _require_metadata(
            self.artifact_identifier,
            self.artifact_type,
            self.code_language,
            self.title,
        )
        source_bytes = _source_bytes(self.source, "seed source")
        if hashlib.sha256(source_bytes).hexdigest() != _require_digest(
            self.source_sha256, "seed source digest"
        ):
            raise FrameError("seeded-public seed source digest does not match")

    @property
    def chat_url(self) -> str:
        return f"{CLAUDE_ORIGIN}/chat/{self.conversation_uuid}"

    @property
    def public_url(self) -> str:
        return f"{CLAUDE_ORIGIN}/public/artifacts/{self.published_uuid}"


@dataclass(frozen=True)
class SeededCloneBinding:
    seed: SeedBinding
    conversation_uuid: str
    artifact_uuid: str
    version_uuid: str
    message_uuid: str
    artifact_identifier: str
    artifact_type: str
    code_language: str | None
    title: str

    def __post_init__(self) -> None:
        for label, value in (
            ("clone conversation", self.conversation_uuid),
            ("clone Artifact", self.artifact_uuid),
            ("clone version", self.version_uuid),
            ("clone message", self.message_uuid),
        ):
            _require_uuid(value, label)
        _require_metadata(
            self.artifact_identifier,
            self.artifact_type,
            self.code_language,
            self.title,
        )
        seed_ids = {
            self.seed.published_uuid,
            self.seed.conversation_uuid,
            self.seed.artifact_uuid,
            self.seed.version_uuid,
            self.seed.message_uuid,
        }
        clone_ids = {
            self.conversation_uuid,
            self.artifact_uuid,
            self.version_uuid,
            self.message_uuid,
        }
        if len(clone_ids) != 4:
            raise FrameError("seeded-public clone identifiers overlap")
        if seed_ids & clone_ids:
            raise FrameError("seeded-public clone identifier equals a seed identifier")
        if (
            self.artifact_type != self.seed.artifact_type
            or self.code_language != self.seed.code_language
            or self.title != self.seed.title
        ):
            raise FrameError("seeded-public clone metadata changed from the seed")

    @property
    def chat_url(self) -> str:
        return f"{CLAUDE_ORIGIN}/chat/{self.conversation_uuid}"

    @property
    def private_source(self) -> str:
        return self.seed.source

    @property
    def private_source_sha256(self) -> str:
        return self.seed.source_sha256


@dataclass(frozen=True)
class SeededPublicResult:
    clone: SeededCloneBinding
    published_uuid: str
    public_source: str
    public_source_sha256: str
    public_verified: bool = True
    published_deleted: bool = False

    def __post_init__(self) -> None:
        _require_uuid(self.published_uuid, "public mapping")
        if self.published_uuid in {
            self.clone.seed.published_uuid,
            self.clone.seed.conversation_uuid,
            self.clone.seed.artifact_uuid,
            self.clone.seed.version_uuid,
            self.clone.seed.message_uuid,
            self.clone.conversation_uuid,
            self.clone.artifact_uuid,
            self.clone.version_uuid,
            self.clone.message_uuid,
        }:
            raise FrameError("seeded-public public mapping overlaps provenance")
        encoded = _source_bytes(self.public_source, "target source")
        if hashlib.sha256(encoded).hexdigest() != _require_digest(
            self.public_source_sha256, "target source digest"
        ):
            raise FrameError("seeded-public target source digest does not match")
        if type(self.public_verified) is not bool:
            raise FrameError("seeded-public public verification state is invalid")
        if type(self.published_deleted) is not bool:
            raise FrameError("seeded-public tombstone state is invalid")

    @property
    def url(self) -> str:
        return f"{CLAUDE_ORIGIN}/public/artifacts/{self.published_uuid}"

    @property
    def private_source_sha256(self) -> str:
        return self.clone.private_source_sha256

    @property
    def content_diverges(self) -> bool:
        return self.private_source_sha256 != self.public_source_sha256


def _seed_expected(seed: SeedBinding, target: str) -> dict[str, Any]:
    target_bytes = _source_bytes(target, "target source")
    return {
        "organizationUuid": seed.organization_uuid,
        "accountEmailSha256": seed.account_email_sha256,
        "seedPublishedUuid": seed.published_uuid,
        "seedConversationUuid": seed.conversation_uuid,
        "seedArtifactUuid": seed.artifact_uuid,
        "seedVersionUuid": seed.version_uuid,
        "seedMessageUuid": seed.message_uuid,
        "seedArtifactIdentifier": seed.artifact_identifier,
        "seedArtifactType": seed.artifact_type,
        "seedCodeLanguage": seed.code_language,
        "seedTitle": seed.title,
        "seedSourceSha256": seed.source_sha256,
        "targetSha256": hashlib.sha256(target_bytes).hexdigest(),
    }


def _clone_expected(clone: SeededCloneBinding, target: str) -> dict[str, Any]:
    value = _seed_expected(clone.seed, target)
    value.update(
        {
            "cloneConversationUuid": clone.conversation_uuid,
            "cloneArtifactUuid": clone.artifact_uuid,
            "cloneVersionUuid": clone.version_uuid,
            "cloneMessageUuid": clone.message_uuid,
            "cloneArtifactIdentifier": clone.artifact_identifier,
            "cloneArtifactType": clone.artifact_type,
            "cloneCodeLanguage": clone.code_language,
            "cloneTitle": clone.title,
        }
    )
    return value


class SeededPublicArtifactPublisher:
    """Publish and clean one exact seed-backed Standard Artifact mapping."""

    def __init__(
        self,
        port: int,
        *,
        expected_email_sha256: str,
        organization_uuid: str,
        timeout: float = 240.0,
    ) -> None:
        self.port = _validate_port(port)
        self.expected_email_sha256 = _require_digest(
            expected_email_sha256, "account binding"
        )
        self.organization_uuid = _require_uuid(organization_uuid, "organization")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            raise FrameError("seeded-public timeout must be numeric")
        self.timeout = float(timeout)
        if not 30.0 <= self.timeout <= 600.0:
            raise FrameError("seeded-public timeout must be between 30 and 600 seconds")

    def _browser_command(
        self, method: str, params: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        version = _localhost_json(self.port, "/json/version")
        socket_url = version.get("webSocketDebuggerUrl") if isinstance(version, dict) else None
        with CdpSession(
            socket_url, self.port, timeout=min(self.timeout, 60.0), kind="browser"
        ) as browser:
            return browser.command(method, dict(params or {}))

    def _target(self, target_id: str) -> dict[str, Any]:
        values = _localhost_json(self.port, "/json/list")
        if not isinstance(values, list):
            raise FrameError("Chrome returned an invalid target list")
        matches = [
            item
            for item in values
            if isinstance(item, dict)
            and item.get("id") == target_id
            and item.get("type") == "page"
            and isinstance(item.get("webSocketDebuggerUrl"), str)
        ]
        if len(matches) != 1:
            raise FrameError("controlled seeded-public tab is unavailable")
        return matches[0]

    def _close_target(self, target_id: str) -> None:
        if not TARGET_ID_RE.fullmatch(target_id or ""):
            raise FrameError("controlled seeded-public tab identifier is invalid")
        command_ok = False
        try:
            response = self._browser_command(
                "Target.closeTarget", {"targetId": target_id}
            )
            command_ok = response.get("success") is True
        except Exception:
            command_ok = False
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                values = _localhost_json(self.port, "/json/list")
                if isinstance(values, list) and not any(
                    isinstance(item, dict) and item.get("id") == target_id
                    for item in values
                ):
                    return
            except Exception:
                pass
            time.sleep(0.1)
        suffix = " after Chrome rejected closeTarget" if not command_ok else ""
        raise FrameError("controlled seeded-public tab cleanup was not confirmed" + suffix)

    def _create_auth_target(self) -> tuple[str, CdpSession]:
        created = self._browser_command(
            "Target.createTarget", {"url": f"{CLAUDE_ORIGIN}/new"}
        )
        target_id = created.get("targetId")
        if not isinstance(target_id, str) or not TARGET_ID_RE.fullmatch(target_id):
            raise FrameError("Chrome returned an invalid seeded-public tab")
        ready: CdpSession | None = None
        try:
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline:
                session: CdpSession | None = None
                try:
                    item = self._target(target_id)
                    parts = urlsplit(str(item.get("url", "")))
                    if (
                        parts.scheme != "https"
                        or parts.hostname != "claude.ai"
                        or parts.port is not None
                        or parts.path.rstrip("/") != "/new"
                        or parts.query
                        or parts.fragment
                    ):
                        raise FrameError("controlled seeded-public tab left /new")
                    session = CdpSession(
                        item["webSocketDebuggerUrl"],
                        self.port,
                        timeout=self.timeout + 90.0,
                    )
                    if session.evaluate(
                        "location.origin === 'https://claude.ai' && "
                        "(document.readyState === 'interactive' || "
                        "document.readyState === 'complete')"
                    ) is True:
                        ready = session
                        return target_id, session
                except Exception:
                    pass
                finally:
                    if session is not None and session is not ready:
                        try:
                            session.close()
                        except Exception:
                            pass
                time.sleep(0.25)
            raise FrameError("controlled seeded-public tab did not become ready")
        except BaseException:
            try:
                self._close_target(target_id)
            except Exception:
                pass
            raise

    @staticmethod
    def _expression(
        action: str,
        expected: Mapping[str, Any],
        seed_source: str,
        target_source: str,
    ) -> str:
        return "(" + _TRANSACTION_JS + ")(" + ",".join(
            json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            for value in (action, dict(expected), seed_source, target_source)
        ) + ")"

    def _evaluate(
        self,
        session: CdpSession,
        action: str,
        expected: Mapping[str, Any],
        seed_source: str,
        target_source: str,
    ) -> dict[str, Any]:
        value = session.evaluate(
            self._expression(action, expected, seed_source, target_source)
        )
        return self._validate_phase_result(value)

    @staticmethod
    def _validate_phase_result(value: Any) -> dict[str, Any]:
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("stage"), str)
            or not SAFE_STAGE_RE.fullmatch(value["stage"])
            or type(value.get("mutationAttempted")) is not bool
        ):
            raise SeededRemoteStateUnknown(
                "seeded-public returned an invalid browser result"
            )
        raw_ids = value.get("ids")
        if not isinstance(raw_ids, dict):
            raise SeededRemoteStateUnknown(
                "seeded-public returned invalid provider bindings",
                stage=value["stage"],
            )
        ids: dict[str, str] = {}
        for key, item in raw_ids.items():
            if key not in {
                "cloneConversationUuid",
                "cloneArtifactUuid",
                "cloneVersionUuid",
                "cloneMessageUuid",
                "publishedUuid",
            }:
                continue
            if not isinstance(item, str) or not UUID_RE.fullmatch(item):
                raise SeededRemoteStateUnknown(
                    "seeded-public returned an invalid provider identifier",
                    stage=value["stage"],
                )
            ids[key] = item
        metadata = value.get("metadata")
        if metadata is not None:
            if not isinstance(metadata, dict) or set(metadata) != {
                "artifactIdentifier", "artifactType", "codeLanguage", "title"
            }:
                raise SeededRemoteStateUnknown(
                    "seeded-public returned invalid clone metadata",
                    stage=value["stage"],
                )
            try:
                _require_metadata(
                    metadata["artifactIdentifier"],
                    metadata["artifactType"],
                    metadata["codeLanguage"],
                    metadata["title"],
                )
            except FrameError as error:
                raise SeededRemoteStateUnknown(
                    "seeded-public returned invalid clone metadata",
                    stage=value["stage"],
                ) from error
        result = {
            "stage": value["stage"],
            "mutationAttempted": value["mutationAttempted"],
            "ids": ids,
            "metadata": metadata,
        }
        observed_published_uuid = value.get("observedPublishedUuid")
        if observed_published_uuid is not None:
            if (
                not isinstance(observed_published_uuid, str)
                or not UUID_RE.fullmatch(observed_published_uuid)
            ):
                raise SeededRemoteStateUnknown(
                    "seeded-public returned an invalid publication observation",
                    stage=value["stage"],
                )
            result["observedPublishedUuid"] = observed_published_uuid
        for key in (
            "ownerBound",
            "publicReadVerified",
            "seedVerified",
            "tombstoneVerified",
            "containerDeleted",
        ):
            if key in value:
                if type(value[key]) is not bool:
                    raise SeededRemoteStateUnknown(
                        "seeded-public returned an invalid verification result",
                        stage=value["stage"],
                    )
                result[key] = value[key]
        return result

    @staticmethod
    def _clone_from_phase(seed: SeedBinding, phase: Mapping[str, Any]) -> SeededCloneBinding:
        ids = phase.get("ids") or {}
        metadata = phase.get("metadata")
        if not isinstance(metadata, dict):
            raise SeededRemoteStateUnknown(
                "seeded-public did not return an exact clone binding",
                stage=phase.get("stage"),
            )
        try:
            return SeededCloneBinding(
                seed=seed,
                conversation_uuid=ids["cloneConversationUuid"],
                artifact_uuid=ids["cloneArtifactUuid"],
                version_uuid=ids["cloneVersionUuid"],
                message_uuid=ids["cloneMessageUuid"],
                artifact_identifier=metadata["artifactIdentifier"],
                artifact_type=metadata["artifactType"],
                code_language=metadata["codeLanguage"],
                title=metadata["title"],
            )
        except (KeyError, TypeError, FrameError) as error:
            raise SeededRemoteStateUnknown(
                "seeded-public returned an invalid clone binding",
                stage=phase.get("stage"),
            ) from error

    @staticmethod
    def _result_from_phase(
        clone: SeededCloneBinding,
        target_source: str,
        phase: Mapping[str, Any],
        *,
        verified: bool = True,
        deleted: bool = False,
    ) -> SeededPublicResult:
        published_uuid = (phase.get("ids") or {}).get("publishedUuid")
        try:
            return SeededPublicResult(
                clone=clone,
                published_uuid=published_uuid,
                public_source=target_source,
                public_source_sha256=hashlib.sha256(
                    target_source.encode("utf-8")
                ).hexdigest(),
                public_verified=verified,
                published_deleted=deleted,
            )
        except FrameError as error:
            raise SeededRemoteStateUnknown(
                "seeded-public returned an invalid public binding",
                stage=phase.get("stage"),
                clone=clone,
                published_uuid=published_uuid,
            ) from error

    @staticmethod
    def _intent(seed: SeedBinding, target_source: str, operation: str) -> dict[str, Any]:
        return {
            "operation": operation,
            "organization_uuid": seed.organization_uuid,
            "seed_published_uuid": seed.published_uuid,
            "seed_source_sha256": seed.source_sha256,
            "target_source_sha256": hashlib.sha256(
                target_source.encode("utf-8")
            ).hexdigest(),
        }

    def _run_controlled(self, operation: Callable[[CdpSession], Any]) -> Any:
        target_id: str | None = None
        session: CdpSession | None = None
        primary: BaseException | None = None
        remote_result: Any = None
        have_remote_result = False
        try:
            target_id, session = self._create_auth_target()
            remote_result = operation(session)
            have_remote_result = True
        except BaseException as error:
            primary = error
            raise
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass
            if target_id is not None:
                try:
                    self._close_target(target_id)
                except FrameError as cleanup_error:
                    if primary is None:
                        if have_remote_result:
                            raise SeededLocalCleanupError(
                                str(cleanup_error), remote_result=remote_result
                            ) from cleanup_error
                        raise
                    try:
                        primary.add_note(str(cleanup_error))
                    except AttributeError:
                        pass
        return remote_result

    def create_and_publish(
        self,
        seed: SeedBinding,
        target_source: str,
        *,
        on_remix_intent: Callable[[Mapping[str, Any]], None] | None = None,
        on_clone_bound: Callable[[SeededCloneBinding], None] | None = None,
        on_publish_intent: Callable[[Mapping[str, Any]], None] | None = None,
        on_publish_rejected: Callable[[], None] | None = None,
        on_public_bound: Callable[[SeededPublicResult], None] | None = None,
        on_published: Callable[[SeededPublicResult], None] | None = None,
    ) -> SeededPublicResult:
        """Clone ``seed`` once and publish ``target_source`` once.

        The callbacks are ordered so a durable journal can record intent before
        each mutation and the exact clone before publication.  Mutations are
        never retried.
        """

        self._require_authority(seed)
        _source_bytes(target_source, "target source")
        expected = _seed_expected(seed, target_source)

        def transaction(session: CdpSession) -> SeededPublicResult:
            preflight = self._evaluate(
                session, "preflight", expected, seed.source, target_source
            )
            if preflight["stage"] != "seed_verified" or preflight["mutationAttempted"]:
                raise SeededCapabilityUnavailable(
                    "seeded-public seed is not an active exact owned publication"
                )
            if on_remix_intent is not None:
                on_remix_intent(self._intent(seed, target_source, "remix"))
            remix = self._evaluate(
                session, "remix", expected, seed.source, target_source
            )
            if remix["stage"] != "remix_bound":
                # Only remix_bound grants authority over a clone.  In
                # particular, a provider response can name a pre-existing or
                # structurally conflicting conversation.  Retain an observed
                # conversation for automatic GET-only reconciliation only
                # when it was absent from the exhaustive preflight catalog, or
                # after it was proved exact and only the final seed check failed.
                observed_conversation = None
                if remix["stage"] in {
                    "remix_response_unresolved",
                    "remix_seed_unverified",
                }:
                    observed_conversation = (remix.get("ids") or {}).get(
                        "cloneConversationUuid"
                    )
                raise SeededRemoteStateUnknown(
                    "seeded-public clone state is unknown after a non-retried remix",
                    stage=remix["stage"],
                    clone_conversation_uuid=observed_conversation,
                )
            clone = self._clone_from_phase(seed, remix)
            if on_clone_bound is not None:
                on_clone_bound(clone)
            clone_expected = _clone_expected(clone, target_source)
            publish_preflight = self._evaluate(
                session,
                "publish_preflight",
                clone_expected,
                seed.source,
                target_source,
            )
            if publish_preflight["stage"] != "clone_private_verified":
                raise SeededRemoteStateUnknown(
                    "seeded-public clone could not be rebound before publication",
                    stage=publish_preflight["stage"],
                    clone=clone,
                )
            if on_publish_intent is not None:
                on_publish_intent(self._intent(seed, target_source, "publish"))
            published = self._evaluate(
                session,
                "publish",
                clone_expected,
                seed.source,
                target_source,
            )
            published_uuid = (published.get("ids") or {}).get("publishedUuid")
            if published["stage"] == "publish_rejected":
                if on_publish_rejected is not None:
                    on_publish_rejected()
                raise SeededCapabilityUnavailable(
                    "seeded-public publication was rejected; the exact private "
                    "clone was retained"
                )
            public_bound = None
            if published.get("ownerBound") is True and published_uuid is not None:
                public_bound = self._result_from_phase(
                    clone,
                    target_source,
                    published,
                    verified=(
                        published["stage"] == "published"
                        and published.get("publicReadVerified") is True
                        and published.get("seedVerified") is True
                    ),
                )
                if on_public_bound is not None:
                    on_public_bound(public_bound)
            if published["stage"] != "published":
                raise SeededRemoteStateUnknown(
                    "seeded-public state is unknown after a non-retried publication",
                    stage=published["stage"],
                    clone=clone,
                    published_uuid=published_uuid,
                    observed_published_uuid=published.get("observedPublishedUuid"),
                )
            if published.get("ownerBound") is not True:
                raise SeededRemoteStateUnknown(
                    "seeded-public publication lacked an exact owner binding",
                    stage=published["stage"],
                    clone=clone,
                    published_uuid=published_uuid,
                    observed_published_uuid=published.get("observedPublishedUuid"),
                )
            result = public_bound or self._result_from_phase(
                clone, target_source, published
            )
            if not published.get("publicReadVerified") or not published.get("seedVerified"):
                raise SeededRemoteStateUnknown(
                    "seeded-public publication did not satisfy exact readback",
                    stage=published["stage"],
                    clone=clone,
                    published_uuid=result.published_uuid,
                    observed_published_uuid=published.get("observedPublishedUuid"),
                )
            if on_published is not None:
                on_published(result)
            return result

        return self._run_controlled(transaction)

    def reconcile_publish(
        self,
        clone: SeededCloneBinding,
        target_source: str,
        *,
        on_public_bound: Callable[[SeededPublicResult], None] | None = None,
        on_published: Callable[[SeededPublicResult], None] | None = None,
        on_unpublished: Callable[[SeededPublicResult], None] | None = None,
    ) -> SeededPublicResult:
        """Reconcile a previously attempted publish using GET requests only."""

        self._require_authority(clone.seed)
        expected = _clone_expected(clone, target_source)

        def transaction(session: CdpSession) -> SeededPublicResult:
            phase = self._evaluate(
                session, "reconcile_publish", expected, clone.seed.source, target_source
            )
            published_uuid = (phase.get("ids") or {}).get("publishedUuid")
            if phase["stage"] in {"published", "public_bound", "unpublished"}:
                result = self._result_from_phase(
                    clone,
                    target_source,
                    phase,
                    verified=(
                        phase["stage"] == "published"
                        and phase.get("publicReadVerified") is True
                        and phase.get("seedVerified") is True
                    ),
                    deleted=phase["stage"] == "unpublished",
                )
                if phase["stage"] == "published":
                    if on_public_bound is not None:
                        on_public_bound(result)
                    if on_published is not None:
                        on_published(result)
                elif phase["stage"] == "public_bound":
                    if on_public_bound is not None:
                        on_public_bound(result)
                elif on_unpublished is not None:
                    on_unpublished(result)
                return result
            raise SeededRemoteStateUnknown(
                "seeded-public publication remains unresolved after read-only reconciliation",
                stage=phase["stage"],
                clone=clone,
                published_uuid=published_uuid,
                observed_published_uuid=phase.get("observedPublishedUuid"),
            )

        return self._run_controlled(transaction)

    def publish_clone(
        self,
        clone: SeededCloneBinding,
        target_source: str,
        *,
        on_publish_intent: Callable[[Mapping[str, Any]], None] | None = None,
        on_publish_rejected: Callable[[], None] | None = None,
        on_public_bound: Callable[[SeededPublicResult], None] | None = None,
        on_published: Callable[[SeededPublicResult], None] | None = None,
    ) -> SeededPublicResult:
        """Publish an already journaled exact private clone once."""

        self._require_authority(clone.seed)
        _source_bytes(target_source, "target source")
        expected = _clone_expected(clone, target_source)

        def transaction(session: CdpSession) -> SeededPublicResult:
            preflight = self._evaluate(
                session,
                "publish_preflight",
                expected,
                clone.seed.source,
                target_source,
            )
            if preflight["stage"] != "clone_private_verified":
                raise SeededRemoteStateUnknown(
                    "seeded-public clone could not be rebound before publication",
                    stage=preflight["stage"],
                    clone=clone,
                )
            if on_publish_intent is not None:
                on_publish_intent(
                    self._intent(clone.seed, target_source, "publish")
                )
            phase = self._evaluate(
                session, "publish", expected, clone.seed.source, target_source
            )
            published_uuid = (phase.get("ids") or {}).get("publishedUuid")
            if phase["stage"] == "publish_rejected":
                if on_publish_rejected is not None:
                    on_publish_rejected()
                raise SeededCapabilityUnavailable(
                    "seeded-public publication was rejected; the exact private "
                    "clone was retained"
                )
            bound = None
            if phase.get("ownerBound") is True and published_uuid is not None:
                bound = self._result_from_phase(
                    clone,
                    target_source,
                    phase,
                    verified=(
                        phase["stage"] == "published"
                        and phase.get("publicReadVerified") is True
                        and phase.get("seedVerified") is True
                    ),
                )
                if on_public_bound is not None:
                    on_public_bound(bound)
            if (
                phase["stage"] != "published"
                or phase.get("ownerBound") is not True
                or not phase.get("publicReadVerified")
                or not phase.get("seedVerified")
            ):
                raise SeededRemoteStateUnknown(
                    "seeded-public state is unknown after a non-retried publication",
                    stage=phase["stage"],
                    clone=clone,
                    published_uuid=published_uuid,
                    observed_published_uuid=phase.get("observedPublishedUuid"),
                )
            result = bound or self._result_from_phase(clone, target_source, phase)
            if on_published is not None:
                on_published(result)
            return result

        return self._run_controlled(transaction)

    def reconcile_remix(
        self,
        seed: SeedBinding,
        target_source: str,
        observed_conversation_uuid: str,
        *,
        on_clone_bound: Callable[[SeededCloneBinding], None] | None = None,
    ) -> SeededCloneBinding:
        """Bind a response-observed remix conversation using GET requests only."""

        self._require_authority(seed)
        expected = _seed_expected(seed, target_source)
        expected["observedCloneConversationUuid"] = _require_uuid(
            observed_conversation_uuid, "observed clone conversation"
        )

        def transaction(session: CdpSession) -> SeededCloneBinding:
            phase = self._evaluate(
                session, "reconcile_remix", expected, seed.source, target_source
            )
            if phase["stage"] != "remix_bound":
                raise SeededRemoteStateUnknown(
                    "seeded-public clone remains unresolved after read-only reconciliation",
                    stage=phase["stage"],
                    clone_conversation_uuid=observed_conversation_uuid,
                )
            clone = self._clone_from_phase(seed, phase)
            if on_clone_bound is not None:
                on_clone_bound(clone)
            return clone

        return self._run_controlled(transaction)

    def reconcile_unpublish(
        self,
        result: SeededPublicResult,
        *,
        on_verified: Callable[[], None] | None = None,
    ) -> SeededPublicResult:
        """Confirm an already-attempted unpublish without repeating DELETE."""

        self._require_authority(result.clone.seed)
        expected = _clone_expected(result.clone, result.public_source)
        expected["publishedUuid"] = result.published_uuid

        def transaction(session: CdpSession) -> SeededPublicResult:
            phase = self._evaluate(
                session,
                "reconcile_unpublish",
                expected,
                result.clone.seed.source,
                result.public_source,
            )
            if phase["stage"] != "unpublished" or not phase.get("tombstoneVerified"):
                raise SeededRemoteStateUnknown(
                    "seeded-public unpublish remains unresolved after read-only reconciliation",
                    stage=phase["stage"],
                    clone=result.clone,
                    published_uuid=result.published_uuid,
                )
            deleted = self._result_from_phase(
                result.clone,
                result.public_source,
                phase,
                verified=result.public_verified,
                deleted=True,
            )
            if on_verified is not None:
                on_verified()
            return deleted

        return self._run_controlled(transaction)

    def reconcile_delete(
        self,
        clone: SeededCloneBinding,
        target_source: str,
        *,
        published_uuid: str | None = None,
        on_verified: Callable[[], None] | None = None,
    ) -> bool:
        """Confirm an already-attempted container deletion using GETs only."""

        self._require_authority(clone.seed)
        expected = _clone_expected(clone, target_source)
        if published_uuid is not None:
            expected["publishedUuid"] = _require_uuid(
                published_uuid, "public mapping"
            )

        def transaction(session: CdpSession) -> bool:
            phase = self._evaluate(
                session,
                "reconcile_delete",
                expected,
                clone.seed.source,
                target_source,
            )
            if phase["stage"] != "deleted" or not phase.get("containerDeleted"):
                raise SeededRemoteStateUnknown(
                    "seeded-public container deletion remains unresolved after read-only reconciliation",
                    stage=phase["stage"],
                    clone=clone,
                    published_uuid=published_uuid,
                )
            if on_verified is not None:
                on_verified()
            return True

        return self._run_controlled(transaction)

    def _require_authority(self, seed: SeedBinding) -> None:
        if (
            seed.organization_uuid != self.organization_uuid
            or seed.account_email_sha256 != self.expected_email_sha256
        ):
            raise FrameError(
                "seeded-public binding belongs to another account or organization"
            )

    def unpublish(
        self,
        result: SeededPublicResult,
        *,
        on_intent: Callable[[Mapping[str, Any]], None] | None = None,
        on_verified: Callable[[], None] | None = None,
    ) -> SeededPublicResult:
        if result.published_deleted:
            return result
        self._require_authority(result.clone.seed)
        expected = _clone_expected(result.clone, result.public_source)
        expected["publishedUuid"] = result.published_uuid

        def transaction(session: CdpSession) -> SeededPublicResult:
            preflight = self._evaluate(
                session,
                "unpublish_preflight",
                expected,
                result.clone.seed.source,
                result.public_source,
            )
            if preflight["stage"] != "public_owner_verified":
                raise SeededRemoteStateUnknown(
                    "seeded-public public mapping could not be rebound for cleanup",
                    stage=preflight["stage"],
                    clone=result.clone,
                    published_uuid=result.published_uuid,
                )
            if on_intent is not None:
                on_intent(
                    self._intent(result.clone.seed, result.public_source, "unpublish")
                )
            removed = self._evaluate(
                session,
                "unpublish",
                expected,
                result.clone.seed.source,
                result.public_source,
            )
            if removed["stage"] != "unpublished" or not removed.get(
                "tombstoneVerified"
            ):
                raise SeededRemoteStateUnknown(
                    "seeded-public public cleanup is unknown after a non-retried DELETE",
                    stage=removed["stage"],
                    clone=result.clone,
                    published_uuid=result.published_uuid,
                )
            deleted = self._result_from_phase(
                result.clone,
                result.public_source,
                removed,
                verified=result.public_verified,
                deleted=True,
            )
            if on_verified is not None:
                on_verified()
            return deleted

        return self._run_controlled(transaction)

    def delete_container(
        self,
        result: SeededPublicResult,
        *,
        on_intent: Callable[[Mapping[str, Any]], None] | None = None,
        on_verified: Callable[[], None] | None = None,
    ) -> bool:
        if not result.published_deleted:
            raise FrameError("seeded-public container deletion requires verified unpublish")
        self._require_authority(result.clone.seed)
        expected = _clone_expected(result.clone, result.public_source)
        expected["publishedUuid"] = result.published_uuid

        def transaction(session: CdpSession) -> bool:
            preflight = self._evaluate(
                session,
                "delete_preflight",
                expected,
                result.clone.seed.source,
                result.public_source,
            )
            if preflight["stage"] != "tombstone_verified":
                raise SeededRemoteStateUnknown(
                    "seeded-public clone could not be rebound for deletion",
                    stage=preflight["stage"],
                    clone=result.clone,
                    published_uuid=result.published_uuid,
                )
            if on_intent is not None:
                on_intent(
                    self._intent(result.clone.seed, result.public_source, "delete")
                )
            removed = self._evaluate(
                session,
                "delete",
                expected,
                result.clone.seed.source,
                result.public_source,
            )
            if removed["stage"] != "deleted" or not removed.get("containerDeleted"):
                raise SeededRemoteStateUnknown(
                    "seeded-public container state is unknown after a non-retried DELETE",
                    stage=removed["stage"],
                    clone=result.clone,
                    published_uuid=result.published_uuid,
                )
            if on_verified is not None:
                on_verified()
            return True

        return self._run_controlled(transaction)

    def delete_private_clone(
        self,
        clone: SeededCloneBinding,
        target_source: str,
        *,
        on_intent: Callable[[Mapping[str, Any]], None] | None = None,
        on_verified: Callable[[], None] | None = None,
    ) -> bool:
        """Delete an exact never-published private clone with one mutation."""

        self._require_authority(clone.seed)
        expected = _clone_expected(clone, target_source)

        def transaction(session: CdpSession) -> bool:
            preflight = self._evaluate(
                session,
                "delete_private_preflight",
                expected,
                clone.seed.source,
                target_source,
            )
            if preflight["stage"] != "private_clone_verified":
                raise SeededRemoteStateUnknown(
                    "seeded-public private clone could not be rebound for deletion",
                    stage=preflight["stage"],
                    clone=clone,
                )
            if on_intent is not None:
                on_intent(self._intent(clone.seed, target_source, "delete_private"))
            removed = self._evaluate(
                session,
                "delete_private",
                expected,
                clone.seed.source,
                target_source,
            )
            if removed["stage"] != "deleted" or not removed.get("containerDeleted"):
                raise SeededRemoteStateUnknown(
                    "seeded-public private clone deletion is unknown after a non-retried DELETE",
                    stage=removed["stage"],
                    clone=clone,
                )
            if on_verified is not None:
                on_verified()
            return True

        return self._run_controlled(transaction)

    delete = delete_container


# Browser transaction is appended below.  Keeping it one pure expression makes
# offline contract tests able to parse and inspect the exact code sent to Chrome.
_TRANSACTION_JS = r"""
async (ACTION, EXPECTED, SEED_SOURCE, TARGET_SOURCE) => {
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const DIGEST = /^[0-9a-f]{64}$/;
  const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
  const safe = (value, empty=false) => typeof value === 'string'
    && value.length <= 1000 && (empty || value.length > 0)
    && !/[\x00-\x1f\x7f]/.test(value);
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const deadline = Date.now() + 60000;
  const ids = {};
  for (const key of [
    'cloneConversationUuid', 'cloneArtifactUuid', 'cloneVersionUuid',
    'cloneMessageUuid', 'publishedUuid'
  ]) {
    if (UUID.test(EXPECTED[key] || '')) ids[key] = EXPECTED[key];
  }
  let metadata = null;
  let observedPublishedUuid = null;
  const done = (stage, mutationAttempted=false, extra={}) => ({
    stage, mutationAttempted, ids:{...ids}, metadata,
    observedPublishedUuid, ...extra
  });
  const digest = async text => {
    const value = await crypto.subtle.digest(
      'SHA-256', new TextEncoder().encode(text)
    );
    return [...new Uint8Array(value)]
      .map(byte => byte.toString(16).padStart(2, '0')).join('');
  };
  const boundedJson = async response => {
    const contentType = response.headers.get('content-type') || '';
    if (!/^application\/json(?:\s*;|$)/i.test(contentType) || !response.body) {
      try { await response.body?.cancel(); } catch {}
      return {ok:false};
    }
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > 2000000) {
          try { await reader.cancel(); } catch {}
          return {ok:false};
        }
        chunks.push(part.value);
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return {
        ok:true,
        value:JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(bytes))
      };
    } catch { return {ok:false}; }
  };
  const cookie = name => {
    let raw;
    try { raw = document.cookie; } catch { return null; }
    const prefix = name + '=';
    const item = raw.split(';').map(value => value.trim())
      .find(value => value.startsWith(prefix));
    if (!item) return null;
    try { return decodeURIComponent(item.slice(prefix.length)); } catch { return null; }
  };
  const printable = value => typeof value === 'string'
    ? (value.replace(/[^\x20-\x7e]/g, '').trim() || 'invalid') : 'invalid';
  const unquote = value => typeof value === 'string' && value.length >= 2
    && value[0] === '"' && value[value.length - 1] === '"'
    ? value.slice(1, -1) : value;
  const anonymousId = unquote(cookie('ajs_anonymous_id'));
  const dataset = document.documentElement?.dataset || {};
  const deviceId = cookie('anthropic-device-id');
  const headers = typeof anonymousId === 'string'
    && /^[A-Za-z0-9_.-]{1,128}$/.test(anonymousId) ? {
      'Content-Type':'application/json',
      'anthropic-anonymous-id':anonymousId,
      'anthropic-device-id':deviceId === null ? 'unknown' : printable(deviceId),
      'anthropic-client-platform':'web_claude_ai',
      'anthropic-client-sha':dataset.gitHash ?? 'unknown',
      'anthropic-client-version':dataset.version ?? 'unknown',
      'anthropic-client-build':dataset.buildTimestamp ?? 'unknown'
    } : null;
  const activity = cookie('activitySessionId');
  if (headers && activity) headers['x-activity-session-id'] = printable(activity);
  const request = async (path, init={}, authenticated=true) => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) return {kind:'deadline'};
    const mutating = init.method && init.method !== 'GET';
    try {
      const response = await fetch(path, {
        ...init,
        ...(authenticated ? {headers:{...headers, ...(init.headers || {})}} : {}),
        credentials:authenticated ? 'same-origin' : 'omit',
        cache:'no-store', redirect:'error', referrerPolicy:'no-referrer',
        signal:AbortSignal.timeout(Math.max(
          1, Math.min(mutating ? 30000 : 15000, remaining)
        ))
      });
      return {kind:'response', response};
    } catch { return {kind:'network'}; }
  };
  const jsonApi = async (path, init={}, authenticated=true) => {
    const fetched = await request(path, init, authenticated);
    if (fetched.kind !== 'response') return {kind:fetched.kind};
    const status = fetched.response.status;
    if (!fetched.response.ok) {
      try { await fetched.response.body?.cancel(); } catch {}
      return {kind:'http', status};
    }
    const parsed = await boundedJson(fetched.response);
    return parsed.ok ? {kind:'ok', status, value:parsed.value}
      : {kind:'malformed', status};
  };
  const statusApi = async (path, init={}) => {
    const fetched = await request(path, init, true);
    if (fetched.kind !== 'response') return {kind:fetched.kind};
    const status = fetched.response.status;
    try { await fetched.response.body?.cancel(); } catch {}
    return fetched.response.ok ? {kind:'ok', status} : {kind:'http', status};
  };
  const identity = async () => {
    const result = await jsonApi('/api/account');
    if (result.kind !== 'ok' || result.status !== 200) return false;
    const email = typeof result.value?.email_address === 'string'
      ? result.value.email_address.toLowerCase() : '';
    return await digest(email) === EXPECTED.accountEmailSha256
      && Array.isArray(result.value?.memberships)
      && result.value.memberships.some(
        item => item?.organization?.uuid === EXPECTED.organizationUuid
      );
  };
  const published = async includeDeleted => {
    const result = await jsonApi(
      `/api/organizations/${EXPECTED.organizationUuid}/published_artifacts`
        + `?include_deleted_artifacts=${includeDeleted ? 'true' : 'false'}`
    );
    return result.kind === 'ok' && result.status === 200
      && Array.isArray(result.value) && result.value.length < 10000
      && result.value.every(item => item && typeof item === 'object')
      ? {ok:true, rows:result.value} : {ok:false};
  };
  const catalog = async () => {
    let limit = 30;
    while (Date.now() < deadline) {
      const result = await jsonApi(
        `/api/organizations/${EXPECTED.organizationUuid}/user_artifacts`
          + `?limit=${limit}&offset=0`
          + '&include_latest_published_artifact_uuid=true'
      );
      const rows = result.value?.artifacts;
      if (result.kind !== 'ok' || result.status !== 200
          || !Array.isArray(rows) || rows.length > limit
          || rows.some(item => !item || typeof item !== 'object')) return {ok:false};
      if (rows.length < limit) return {ok:true, rows};
      if (limit === 10000) return {ok:false};
      limit = Math.min(10000, limit + 30);
    }
    return {ok:false};
  };
  const versions = async conversationUuid => {
    const result = await jsonApi(
      `/api/organizations/${EXPECTED.organizationUuid}/artifacts/`
        + `${conversationUuid}/versions`
    );
    const rows = result.value?.artifact_versions;
    return result.kind === 'ok' && result.status === 200
      && Array.isArray(rows)
      && rows.every(item => item && typeof item === 'object')
      ? {ok:true, rows} : {ok:false, kind:result.kind, status:result.status};
  };
  const publicRead = publishedUuid => jsonApi(
    `/api/published_artifacts/${publishedUuid}`, {method:'GET'}, false
  );
  const ownerExact = (row, bound, publishedUuid, deleted) =>
    row?.published_artifact_uuid === publishedUuid
    && row.chat_conversation_uuid === bound.conversationUuid
    && row.message_uuid === bound.messageUuid
    && row.artifact_identifier === bound.artifactIdentifier
    && row.artifact_type === bound.artifactType
    && row.code_language === bound.codeLanguage
    && row.title === bound.title && row.deleted === deleted
    && own(row, 'artifact_version_uuid')
    && (row.artifact_version_uuid === null
      || row.artifact_version_uuid === bound.versionUuid);
  const seedBound = {
    conversationUuid:EXPECTED.seedConversationUuid,
    artifactUuid:EXPECTED.seedArtifactUuid,
    versionUuid:EXPECTED.seedVersionUuid,
    messageUuid:EXPECTED.seedMessageUuid,
    artifactIdentifier:EXPECTED.seedArtifactIdentifier,
    artifactType:EXPECTED.seedArtifactType,
    codeLanguage:EXPECTED.seedCodeLanguage,
    title:EXPECTED.seedTitle
  };
  const verifySeed = async () => {
    const [allCatalog, allVersions, active, history, publicValue] = await Promise.all([
      catalog(), versions(EXPECTED.seedConversationUuid), published(false),
      published(true), publicRead(EXPECTED.seedPublishedUuid)
    ]);
    if (!allCatalog.ok || !allVersions.ok || !active.ok || !history.ok
        || publicValue.kind !== 'ok' || publicValue.status !== 200) return false;
    const catalogs = allCatalog.rows.filter(
      item => item.chat_conversation_uuid === EXPECTED.seedConversationUuid
    );
    const versionRows = allVersions.rows.filter(
      item => item.uuid === EXPECTED.seedVersionUuid
    );
    const activeRows = active.rows.filter(
      item => item.published_artifact_uuid === EXPECTED.seedPublishedUuid
        || item.chat_conversation_uuid === EXPECTED.seedConversationUuid
    );
    const historyRows = history.rows.filter(
      item => item.published_artifact_uuid === EXPECTED.seedPublishedUuid
        || item.chat_conversation_uuid === EXPECTED.seedConversationUuid
    );
    if (catalogs.length !== 1 || allVersions.rows.length !== 1
        || versionRows.length !== 1
        || activeRows.length !== 1 || historyRows.length !== 1
        || !ownerExact(activeRows[0], seedBound, EXPECTED.seedPublishedUuid, false)
        || !ownerExact(historyRows[0], seedBound, EXPECTED.seedPublishedUuid, false)) {
      return false;
    }
    const item = catalogs[0], row = versionRows[0], view = publicValue.value;
    return item.uuid === EXPECTED.seedArtifactUuid
      && item.latest_artifact_version_uuid === EXPECTED.seedVersionUuid
      && item.latest_published_artifact_uuid === EXPECTED.seedPublishedUuid
      && item.artifact_identifier === EXPECTED.seedArtifactIdentifier
      && item.artifact_type === EXPECTED.seedArtifactType
      && item.code_language === EXPECTED.seedCodeLanguage
      && item.title === EXPECTED.seedTitle
      && row.artifact_uuid === EXPECTED.seedArtifactUuid
      && row.message_uuid === EXPECTED.seedMessageUuid
      && row.result_state === SEED_SOURCE
      && row.artifact_type === EXPECTED.seedArtifactType
      && row.code_language === EXPECTED.seedCodeLanguage
      && row.title === EXPECTED.seedTitle
      && row.published_artifact_uuid === EXPECTED.seedPublishedUuid
      && row.published_artifact_deleted_at === null
      && view?.content === SEED_SOURCE && view.title === EXPECTED.seedTitle
      && view.type === EXPECTED.seedArtifactType
      && (EXPECTED.seedCodeLanguage === null
        ? view.language == null : view.language === EXPECTED.seedCodeLanguage)
      && await identity();
  };
  const expectedClone = () => {
    if (![EXPECTED.cloneConversationUuid, EXPECTED.cloneArtifactUuid,
          EXPECTED.cloneVersionUuid, EXPECTED.cloneMessageUuid].every(UUID.test.bind(UUID))
        || !safe(EXPECTED.cloneArtifactIdentifier)
        || !safe(EXPECTED.cloneArtifactType)
        || !(EXPECTED.cloneCodeLanguage === null
          || safe(EXPECTED.cloneCodeLanguage, true))
        || !safe(EXPECTED.cloneTitle)) return null;
    return {
      conversationUuid:EXPECTED.cloneConversationUuid,
      artifactUuid:EXPECTED.cloneArtifactUuid,
      versionUuid:EXPECTED.cloneVersionUuid,
      messageUuid:EXPECTED.cloneMessageUuid,
      artifactIdentifier:EXPECTED.cloneArtifactIdentifier,
      artifactType:EXPECTED.cloneArtifactType,
      codeLanguage:EXPECTED.cloneCodeLanguage,
      title:EXPECTED.cloneTitle
    };
  };
  const inspectClone = async (conversationUuid, bound=null, state='private') => {
    const allCatalog = await catalog();
    if (!allCatalog.ok) return {ok:false, retry:true};
    const rows = allCatalog.rows.filter(
      item => item.chat_conversation_uuid === conversationUuid
    );
    if (rows.length === 0) return {ok:false, retry:true};
    if (rows.length !== 1) return {ok:false, retry:false};
    const item = rows[0];
    if (!UUID.test(item.uuid || '') || !UUID.test(item.latest_artifact_version_uuid || '')
        || conversationUuid === EXPECTED.seedConversationUuid
        || item.uuid === EXPECTED.seedArtifactUuid
        || item.artifact_type !== EXPECTED.seedArtifactType
        || item.code_language !== EXPECTED.seedCodeLanguage
        || item.title !== EXPECTED.seedTitle
        || !safe(item.artifact_identifier)
        || !own(item, 'latest_published_artifact_uuid')) return {ok:false, retry:false};
    const allVersions = await versions(conversationUuid);
    if (!allVersions.ok) return {ok:false, retry:true};
    if (allVersions.rows.length !== 1) return {ok:false, retry:false};
    const matches = allVersions.rows.filter(
      row => row.uuid === item.latest_artifact_version_uuid
    );
    if (matches.length !== 1) return {ok:false, retry:matches.length === 0};
    const row = matches[0];
    const derived = {
      conversationUuid,
      artifactUuid:item.uuid,
      versionUuid:row.uuid,
      messageUuid:row.message_uuid,
      artifactIdentifier:item.artifact_identifier,
      artifactType:item.artifact_type,
      codeLanguage:item.code_language,
      title:item.title
    };
    const cloneIds = [conversationUuid, item.uuid, row.uuid, row.message_uuid];
    const seedIds = [EXPECTED.seedPublishedUuid, EXPECTED.seedConversationUuid,
      EXPECTED.seedArtifactUuid, EXPECTED.seedVersionUuid, EXPECTED.seedMessageUuid];
    if (!UUID.test(row.artifact_uuid || '') || !UUID.test(row.message_uuid || '')
        || row.artifact_uuid !== item.uuid || row.result_state !== SEED_SOURCE
        || row.artifact_type !== item.artifact_type
        || row.code_language !== item.code_language || row.title !== item.title
        || new Set(cloneIds).size !== 4
        || cloneIds.some(value => seedIds.includes(value))
        || (bound && Object.keys(derived).some(key => derived[key] !== bound[key]))) {
      return {ok:false, retry:false};
    }
    const active = await published(false), history = await published(true);
    if (!active.ok || !history.ok) return {ok:false, retry:true};
    const stateId = state === 'private' ? null : state.publishedUuid;
    const related = entry => entry.chat_conversation_uuid === conversationUuid
      || (entry.message_uuid === row.message_uuid
        && entry.artifact_identifier === item.artifact_identifier)
      || (stateId !== null && entry.published_artifact_uuid === stateId);
    const activeRows = active.rows.filter(
      entry => related(entry)
    );
    const historyRows = history.rows.filter(
      entry => related(entry)
    );
    if (state === 'private') {
      if (item.latest_published_artifact_uuid !== null
          || row.published_artifact_uuid !== null
          || row.published_artifact_deleted_at !== null
          || activeRows.length !== 0 || historyRows.length !== 0) {
        return {ok:false, retry:false};
      }
    } else if (state.kind === 'active') {
      const id = state.publishedUuid;
      if (item.latest_published_artifact_uuid !== id
          || row.published_artifact_uuid !== id
          || row.published_artifact_deleted_at !== null
          || activeRows.length !== 1 || historyRows.length !== 1
          || !ownerExact(activeRows[0], derived, id, false)
          || !ownerExact(historyRows[0], derived, id, false)) {
        return {ok:false, retry:false};
      }
    } else {
      const id = state.publishedUuid;
      if (item.latest_published_artifact_uuid !== null
          || row.published_artifact_uuid !== id
          || !safe(row.published_artifact_deleted_at)
          || activeRows.length !== 0 || historyRows.length !== 1
          || !ownerExact(historyRows[0], derived, id, true)) {
        return {ok:false, retry:false};
      }
    }
    return {ok:true, item, row, bound:derived};
  };
  const keepClone = bound => {
    ids.cloneConversationUuid = bound.conversationUuid;
    ids.cloneArtifactUuid = bound.artifactUuid;
    ids.cloneVersionUuid = bound.versionUuid;
    ids.cloneMessageUuid = bound.messageUuid;
    metadata = {
      artifactIdentifier:bound.artifactIdentifier,
      artifactType:bound.artifactType,
      codeLanguage:bound.codeLanguage,
      title:bound.title
    };
  };
  const exactPublicView = (view, bound) => view.kind === 'ok'
    && view.status === 200 && view.value?.content === TARGET_SOURCE
    && view.value.title === bound.title && view.value.type === bound.artifactType
    && (bound.codeLanguage === null
      ? view.value.language == null : view.value.language === bound.codeLanguage);
  const relatedToClone = (entry, bound, publishedUuid=null) =>
    entry?.chat_conversation_uuid === bound.conversationUuid
    || (entry?.message_uuid === bound.messageUuid
      && entry?.artifact_identifier === bound.artifactIdentifier)
    || (publishedUuid !== null
      && entry?.published_artifact_uuid === publishedUuid);
  const overlapsProvenance = (id, bound) => [
    EXPECTED.seedPublishedUuid, EXPECTED.seedConversationUuid,
    EXPECTED.seedArtifactUuid, EXPECTED.seedVersionUuid,
    EXPECTED.seedMessageUuid, bound.conversationUuid, bound.artifactUuid,
    bound.versionUuid, bound.messageUuid
  ].includes(id);
  const findActive = async bound => {
    const active = await published(false);
    if (!active.ok) return {kind:'read_failure'};
    const related = active.rows.filter(item => relatedToClone(item, bound));
    if (related.length === 0) return {kind:'absent'};
    if (related.length !== 1) return {kind:'ambiguous'};
    const id = related[0].published_artifact_uuid;
    if (!UUID.test(id || '') || overlapsProvenance(id, bound)
        || active.rows.filter(item => item.published_artifact_uuid === id).length !== 1
        || !ownerExact(related[0], bound, id, false)) return {kind:'mismatch'};
    const rebound = await inspectClone(
      bound.conversationUuid, bound, {kind:'active', publishedUuid:id}
    );
    if (!rebound.ok) return {kind:'mismatch', publishedUuid:id};
    const view = await publicRead(id);
    return {
      kind:'bound', publishedUuid:id,
      publicReadVerified:exactPublicView(view, bound)
    };
  };
  const findTombstone = async bound => {
    const [active, history] = await Promise.all([published(false), published(true)]);
    if (!active.ok || !history.ok) return {kind:'read_failure'};
    const activeRelated = active.rows.filter(item => relatedToClone(item, bound));
    const related = history.rows.filter(item => relatedToClone(item, bound));
    if (activeRelated.length !== 0 || related.length === 0) return {kind:'absent'};
    if (related.length !== 1) return {kind:'ambiguous'};
    const id = related[0].published_artifact_uuid;
    if (!UUID.test(id || '') || overlapsProvenance(id, bound)
        || history.rows.filter(item => item.published_artifact_uuid === id).length !== 1
        || !ownerExact(related[0], bound, id, true)) return {kind:'mismatch'};
    const [rebound, view] = await Promise.all([
      inspectClone(bound.conversationUuid, bound, {kind:'deleted', publishedUuid:id}),
      publicRead(id)
    ]);
    return rebound.ok && view.kind === 'http' && view.status === 404
      ? {kind:'bound', publishedUuid:id} : {kind:'mismatch', publishedUuid:id};
  };
  const conversationPath = bound =>
    `/api/organizations/${EXPECTED.organizationUuid}/chat_conversations/`
      + `${bound.conversationUuid}`
      + '?tree=True&rendering_mode=messages&render_all_tools=true&consistency=strong';
  const conversationDeleted = async (bound, publishedUuid=null) => {
    const [detail, allCatalog, versionRows, active, history, view] = await Promise.all([
      jsonApi(conversationPath(bound)), catalog(), versions(bound.conversationUuid),
      published(false), published(true),
      publishedUuid === null ? Promise.resolve({kind:'not_applicable'})
        : publicRead(publishedUuid)
    ]);
    if (detail.kind !== 'http' || detail.status !== 404 || !allCatalog.ok
        || allCatalog.rows.some(item => item.chat_conversation_uuid === bound.conversationUuid
          || item.uuid === bound.artifactUuid)
        || versionRows.kind !== 'http' || versionRows.status !== 404
        || !active.ok || !history.ok
        || active.rows.some(item => relatedToClone(item, bound, publishedUuid))) return false;
    const historyRelated = history.rows.filter(
      item => relatedToClone(item, bound, publishedUuid)
    );
    if (publishedUuid === null) {
      if (historyRelated.length !== 0) return false;
    } else if (historyRelated.length !== 1
        || !ownerExact(historyRelated[0], bound, publishedUuid, true)
        || view.kind !== 'http' || view.status !== 404) return false;
    return await verifySeed();
  };
  const baseValid = location.origin === 'https://claude.ai'
    && location.pathname.replace(/\/+$/, '') === '/new'
    && !location.search && !location.hash && headers !== null
    && UUID.test(EXPECTED.organizationUuid || '')
    && DIGEST.test(EXPECTED.accountEmailSha256 || '')
    && UUID.test(EXPECTED.seedPublishedUuid || '')
    && UUID.test(EXPECTED.seedConversationUuid || '')
    && UUID.test(EXPECTED.seedArtifactUuid || '')
    && UUID.test(EXPECTED.seedVersionUuid || '')
    && UUID.test(EXPECTED.seedMessageUuid || '')
    && new Set([EXPECTED.seedPublishedUuid, EXPECTED.seedConversationUuid,
      EXPECTED.seedArtifactUuid, EXPECTED.seedVersionUuid,
      EXPECTED.seedMessageUuid]).size === 5
    && safe(EXPECTED.seedArtifactIdentifier)
    && safe(EXPECTED.seedArtifactType)
    && (EXPECTED.seedCodeLanguage === null
      || safe(EXPECTED.seedCodeLanguage, true))
    && safe(EXPECTED.seedTitle)
    && DIGEST.test(EXPECTED.seedSourceSha256 || '')
    && DIGEST.test(EXPECTED.targetSha256 || '')
    && await digest(SEED_SOURCE) === EXPECTED.seedSourceSha256
    && await digest(TARGET_SOURCE) === EXPECTED.targetSha256;
  if (!baseValid || !(await identity())) return done('browser_preflight');

  if (ACTION === 'preflight') {
    const verified = await verifySeed();
    return done(verified ? 'seed_verified' : 'seed_mismatch', false, {
      seedVerified:verified
    });
  }

  if (ACTION === 'remix') {
    if (!(await verifySeed())) return done('seed_mismatch');
    const before = await catalog();
    if (!before.ok) return done('catalog_preflight');
    const beforeIds = new Set(before.rows.map(item => item.uuid));
    const beforeConversations = new Set(
      before.rows.map(item => item.chat_conversation_uuid)
    );
    const response = await jsonApi(
      `/api/organizations/${EXPECTED.organizationUuid}/published_artifacts/`
        + `${EXPECTED.seedPublishedUuid}/remixv2`,
      {method:'POST', body:'{}'}
    );
    let conversationUuid = response.kind === 'ok'
      && UUID.test(response.value?.uuid || '') ? response.value.uuid : null;
    if (conversationUuid) ids.cloneConversationUuid = conversationUuid;
    if (!conversationUuid) {
      // A catalog delta is not an ownership token: another same-account
      // operation could create the sole matching clone concurrently.  Preserve
      // the ambiguous mutation instead of guessing a cleanup target.
      return done('remix_unresolved', true);
    }
    if (beforeConversations.has(conversationUuid)) {
      return done('remix_preexisting_response', true);
    }
    let inspected = null;
    const stop = Math.min(deadline, Date.now() + 45000);
    while (Date.now() < stop) {
      const candidate = await inspectClone(conversationUuid);
      if (candidate.ok) { inspected = candidate; break; }
      if (!candidate.retry) return done('remix_binding_mismatch', true);
      await sleep(500);
    }
    if (!inspected) {
      return done('remix_response_unresolved', true);
    }
    keepClone(inspected.bound);
    if (beforeIds.has(inspected.bound.artifactUuid)) {
      return done('remix_preexisting_response', true);
    }
    if (own(response.value || {}, 'artifact_identifier')
        && response.value.artifact_identifier !== inspected.bound.artifactIdentifier) {
      return done('remix_response_mismatch', true);
    }
    if (!(await verifySeed())) return done('remix_seed_unverified', true);
    return done('remix_bound', true, {seedVerified:true});
  }

  if (ACTION === 'reconcile_remix') {
    const conversationUuid = EXPECTED.observedCloneConversationUuid;
    if (!UUID.test(conversationUuid || '')
        || conversationUuid === EXPECTED.seedConversationUuid) {
      return done('remix_observation_binding');
    }
    ids.cloneConversationUuid = conversationUuid;
    const inspected = await inspectClone(conversationUuid);
    if (!inspected.ok || !(await verifySeed())) {
      return done('remix_reconcile_unresolved');
    }
    keepClone(inspected.bound);
    return done('remix_bound', false, {seedVerified:true});
  }

  const clone = expectedClone();
  if (!clone) return done('clone_expected_binding');
  keepClone(clone);
  if (ACTION === 'publish_preflight') {
    const exact = await inspectClone(clone.conversationUuid, clone);
    const seedExact = exact.ok && await verifySeed();
    return done(seedExact ? 'clone_private_verified' : 'clone_private_mismatch',
      false, {seedVerified:seedExact});
  }
  if (ACTION === 'publish') {
    const exact = await inspectClone(clone.conversationUuid, clone);
    if (!exact.ok || !(await verifySeed())) return done('publish_preflight_mismatch');
    const response = await jsonApi(
      `/api/organizations/${EXPECTED.organizationUuid}/publish_artifact`,
      {method:'POST', body:JSON.stringify({
        title:clone.title, artifact_type:clone.artifactType,
        code_language:clone.codeLanguage, message_uuid:clone.messageUuid,
        conversation_uuid:clone.conversationUuid,
        artifact_identifier:clone.artifactIdentifier, content:TARGET_SOURCE,
        artifact_version_uuid:clone.versionUuid
      })}
    );
    const responseId = response.kind === 'ok'
      && UUID.test(response.value?.published_artifact_uuid || '')
      && !overlapsProvenance(response.value.published_artifact_uuid, clone)
      ? response.value.published_artifact_uuid : null;
    if (responseId) observedPublishedUuid = responseId;
    let mapping = null;
    const stop = Math.min(deadline, Date.now() + 45000);
    while (Date.now() < stop) {
      mapping = await findActive(clone);
      if (mapping.kind === 'bound') break;
      if (!['absent', 'read_failure'].includes(mapping.kind)) {
        if (!observedPublishedUuid && UUID.test(mapping.publishedUuid || '')
            && !overlapsProvenance(mapping.publishedUuid, clone)) {
          observedPublishedUuid = mapping.publishedUuid;
        }
        return done('publish_owner_mismatch', true, {ownerBound:false});
      }
      await sleep(500);
    }
    if (!mapping || mapping.kind !== 'bound') {
      let cleanRejection = false;
      if (response.kind === 'http'
        && [400, 401, 403, 404, 409, 413, 422].includes(response.status)
        && responseId === null && mapping?.kind === 'absent') {
        const exactPrivate = await inspectClone(
          clone.conversationUuid, clone, 'private'
        );
        cleanRejection = exactPrivate.ok && await verifySeed();
      }
      return done(cleanRejection ? 'publish_rejected' : 'publish_unresolved', true, {
        seedVerified:cleanRejection
      });
    }
    const publicId = mapping.publishedUuid;
    ids.publishedUuid = publicId;
    const publicExact = mapping.publicReadVerified;
    const seedExact = await verifySeed();
    const responseConsistent = response.kind === 'ok'
      && response.status >= 200 && response.status < 300
      && responseId === publicId;
    if (!publicExact || !seedExact || !responseConsistent) return done(
      publicExact ? 'publish_response_mismatch' : 'publish_public_mismatch', true,
      {ownerBound:true, publicReadVerified:publicExact, seedVerified:seedExact}
    );
    return done('published', true, {
      ownerBound:true, publicReadVerified:true, seedVerified:true
    });
  }

  if (ACTION === 'reconcile_publish') {
    const active = await findActive(clone);
    if (active.kind === 'bound') {
      ids.publishedUuid = active.publishedUuid;
      const seedExact = await verifySeed();
      return done(active.publicReadVerified && seedExact ? 'published' : 'public_bound',
        false, {ownerBound:true, publicReadVerified:active.publicReadVerified,
          seedVerified:seedExact});
    }
    if (!['absent', 'read_failure'].includes(active.kind)) {
      if (UUID.test(active.publishedUuid || '')
          && !overlapsProvenance(active.publishedUuid, clone)) {
        observedPublishedUuid = active.publishedUuid;
      }
      return done('publish_reconcile_mismatch', false, {ownerBound:false});
    }
    const tombstone = await findTombstone(clone);
    if (tombstone.kind === 'bound' && await verifySeed()) {
      ids.publishedUuid = tombstone.publishedUuid;
      return done('unpublished', false, {
        ownerBound:true, publicReadVerified:false,
        tombstoneVerified:true, seedVerified:true
      });
    }
    return done('publish_reconcile_unresolved', false);
  }

  const privateCloneExact = async () => {
    const exact = await inspectClone(clone.conversationUuid, clone, 'private');
    return exact.ok && await verifySeed();
  };
  if (ACTION === 'delete_private_preflight') {
    const verified = await privateCloneExact();
    return done(verified ? 'private_clone_verified' : 'private_clone_mismatch',
      false, {seedVerified:verified});
  }
  if (ACTION === 'delete_private') {
    if (!(await privateCloneExact())) return done('delete_private_preflight_mismatch');
    const detail = await jsonApi(conversationPath(clone));
    if (detail.kind !== 'ok' || detail.status !== 200
        || detail.value?.uuid !== clone.conversationUuid || !(await identity())) {
      return done('delete_conversation_binding');
    }
    await statusApi(
      `/api/organizations/${EXPECTED.organizationUuid}/chat_conversations/`
        + clone.conversationUuid,
      {method:'DELETE', headers:{'Content-Type':'application/json'}, body:'{}'}
    );
    const stop = Math.min(deadline, Date.now() + 45000);
    while (Date.now() < stop) {
      if (await conversationDeleted(clone, null)) return done('deleted', true, {
        containerDeleted:true, seedVerified:true
      });
      await sleep(500);
    }
    return done('delete_unresolved', true, {containerDeleted:false});
  }
  if (ACTION === 'reconcile_delete' && !own(EXPECTED, 'publishedUuid')) {
    const verified = await conversationDeleted(clone, null);
    return done(verified ? 'deleted' : 'delete_reconcile_unresolved', false, {
      containerDeleted:verified, seedVerified:verified
    });
  }

  const publicId = EXPECTED.publishedUuid;
  if (!UUID.test(publicId || '') || overlapsProvenance(publicId, clone)) {
    return done('public_expected_binding');
  }
  ids.publishedUuid = publicId;
  const activeOwnerExact = async () => {
    const [rebound, view] = await Promise.all([
      inspectClone(clone.conversationUuid, clone, {kind:'active', publishedUuid:publicId}),
      publicRead(publicId)
    ]);
    const ownerBound = rebound.ok && await verifySeed();
    return {ownerBound, publicReadVerified:exactPublicView(view, clone)};
  };
  const tombstoneExact = async () => {
    const [rebound, view] = await Promise.all([
      inspectClone(clone.conversationUuid, clone, {kind:'deleted', publishedUuid:publicId}),
      publicRead(publicId)
    ]);
    return rebound.ok && view.kind === 'http' && view.status === 404
      && await verifySeed();
  };
  if (ACTION === 'unpublish_preflight') {
    const verified = await activeOwnerExact();
    return done(verified.ownerBound ? 'public_owner_verified' : 'public_mismatch', false, {
      ownerBound:verified.ownerBound,
      publicReadVerified:verified.publicReadVerified,
      seedVerified:verified.ownerBound
    });
  }
  if (ACTION === 'reconcile_unpublish') {
    const verified = await tombstoneExact();
    return done(verified ? 'unpublished' : 'unpublish_reconcile_unresolved', false, {
      tombstoneVerified:verified, seedVerified:verified
    });
  }
  if (ACTION === 'unpublish') {
    const active = await activeOwnerExact();
    if (!active.ownerBound) return done('unpublish_preflight_mismatch');
    await statusApi(
      `/api/organizations/${EXPECTED.organizationUuid}/published_artifacts/${publicId}`,
      {method:'DELETE', headers:{'Content-Type':'application/json'}, body:'{}'}
    );
    const stop = Math.min(deadline, Date.now() + 45000);
    while (Date.now() < stop) {
      if (await tombstoneExact()) return done('unpublished', true, {
        tombstoneVerified:true, seedVerified:true
      });
      await sleep(500);
    }
    return done('unpublish_unresolved', true, {tombstoneVerified:false});
  }
  if (ACTION === 'delete_preflight') {
    const verified = await tombstoneExact();
    return done(verified ? 'tombstone_verified' : 'tombstone_mismatch', false, {
      tombstoneVerified:verified, seedVerified:verified
    });
  }
  if (ACTION === 'delete') {
    if (!(await tombstoneExact())) return done('delete_preflight_mismatch');
    const detail = await jsonApi(conversationPath(clone));
    if (detail.kind !== 'ok' || detail.status !== 200
        || detail.value?.uuid !== clone.conversationUuid || !(await identity())) {
      return done('delete_conversation_binding');
    }
    await statusApi(
      `/api/organizations/${EXPECTED.organizationUuid}/chat_conversations/`
        + clone.conversationUuid,
      {method:'DELETE', headers:{'Content-Type':'application/json'}, body:'{}'}
    );
    const stop = Math.min(deadline, Date.now() + 45000);
    while (Date.now() < stop) {
      if (await conversationDeleted(clone, publicId)) return done('deleted', true, {
            containerDeleted:true, seedVerified:true
      });
      await sleep(500);
    }
    return done('delete_unresolved', true, {containerDeleted:false});
  }
  if (ACTION === 'reconcile_delete') {
    const verified = await conversationDeleted(clone, publicId);
    return done(verified ? 'deleted' : 'delete_reconcile_unresolved', false, {
      containerDeleted:verified, seedVerified:verified
    });
  }
  return done('unsupported_action');
}
"""

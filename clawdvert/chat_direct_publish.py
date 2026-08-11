"""Experimental raw-content adapter for standard Claude Artifacts.

This adapter reproduces the browser client's measured ``share_from_content``
contract.  It uses a controlled claude.ai tab only as a same-origin authenticated
fetch context: it never exports cookies, enters a prompt, invokes a model, opens
an Artifact preview, or falls back to the conversation adapter.

The endpoint is capability-gated.  A reference accepted by the native Cowork
client is required; ordinary Code/Cowork session IDs may receive 404.  That
outcome is reported distinctly and is never retried.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Optional, Tuple
from urllib.parse import urlsplit

from .chat_publish import CdpSession, _localhost_json, _validate_port
from .frames import FrameError


CLAUDE_ORIGIN = "https://claude.ai"
UUID_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
UUID_RE = re.compile(r"^" + UUID_PATTERN + r"$")
EMAIL_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
NATIVE_SESSION_REF_RE = re.compile(
    r"^(?:local_" + UUID_PATTERN + r"|(?:cse|session)_[A-Za-z0-9_-]{8,120})$"
)
FILENAME_RE = re.compile(r"^[^/\\\x00-\x1f\x7f]{1,160}\.html?$", re.IGNORECASE)
MAX_SOURCE_BYTES = 750_000
MAX_TITLE_CHARS = 280
DEFAULT_TIMEOUT = 45.0


class NativeCapabilityUnavailable(FrameError):
    """The provider did not expose the native share capability for this anchor."""


class RemoteStateUnknown(FrameError):
    """A non-retried mutation may have reached the provider.

    Validated provider identifiers are safe to report and are retained so an
    operator can reconcile or clean up an ambiguous result.  The native session
    reference and source are never included.
    """

    def __init__(
        self,
        message: str,
        *,
        artifact_uuid: Optional[str] = None,
        version_uuid: Optional[str] = None,
        message_uuid: Optional[str] = None,
        conversation_uuid: Optional[str] = None,
        published_uuid: Optional[str] = None,
        published_revocation_confirmed: bool = False,
    ) -> None:
        self.artifact_uuid = artifact_uuid
        self.version_uuid = version_uuid
        self.message_uuid = message_uuid
        self.conversation_uuid = conversation_uuid
        self.published_uuid = published_uuid
        self.published_revocation_confirmed = published_revocation_confirmed
        identifiers = []
        if artifact_uuid:
            identifiers.append("artifact=" + artifact_uuid)
        if version_uuid:
            identifiers.append("version=" + version_uuid)
        if message_uuid:
            identifiers.append("message=" + message_uuid)
        if conversation_uuid:
            identifiers.append("conversation=" + conversation_uuid)
        if published_uuid:
            identifiers.append("published=" + published_uuid)
            identifiers.append(
                "published-revoked="
                + ("yes" if published_revocation_confirmed else "not-confirmed")
            )
        if identifiers:
            message += "; cleanup identifiers: " + ", ".join(identifiers)
        super().__init__(message)


@dataclass(frozen=True)
class NativeShareResult:
    url: str
    artifact_uuid: str
    version_uuid: str
    message_uuid: str
    source_sha256: str
    public: bool = False
    published_uuid: Optional[str] = None


def hash_session_ref(value: str) -> str:
    validate_session_ref(value)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_session_ref(value: str) -> str:
    if not isinstance(value, str) or not NATIVE_SESSION_REF_RE.fullmatch(value):
        raise FrameError(
            "native session reference has an unsupported format; use the exact "
            "reference supplied by the native Cowork client"
        )
    return value


def _validate_uuid(value: str, option: str) -> str:
    if not isinstance(value, str) or not UUID_RE.fullmatch(value):
        raise FrameError(option + " must be a lowercase UUID")
    return value


def validate_organization_uuid(value: str) -> str:
    return _validate_uuid(value, "--organization-uuid")


def validate_browser_port(value: int) -> int:
    return _validate_port(value)


def _validate_source(source: str) -> bytes:
    if not isinstance(source, str) or not source:
        raise FrameError("native-share source must be a non-empty string")
    try:
        encoded = source.encode("utf-8")
    except UnicodeEncodeError:
        raise FrameError("native-share source is not valid UTF-8") from None
    if len(encoded) > MAX_SOURCE_BYTES:
        raise FrameError(
            "native-share source exceeds the conservative "
            + str(MAX_SOURCE_BYTES)
            + " byte limit"
        )
    return encoded


def _validate_filename(filename: str) -> str:
    if not isinstance(filename, str) or not FILENAME_RE.fullmatch(filename):
        raise FrameError("native-share filename must be a simple .html or .htm basename")
    return filename


def validate_request(source: str, filename: str, title: Optional[str] = None) -> bytes:
    encoded = _validate_source(source)
    _validate_filename(filename)
    if title is not None:
        if not isinstance(title, str) or not title.strip() or len(title) > MAX_TITLE_CHARS:
            raise FrameError(
                "native-share display title must be 1-"
                + str(MAX_TITLE_CHARS)
                + " characters"
            )
    return encoded


def _binding_kwargs(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    binding = {}
    for remote, local in (
        ("artifactUuid", "artifact_uuid"),
        ("versionUuid", "version_uuid"),
        ("messageUuid", "message_uuid"),
        ("conversationUuid", "conversation_uuid"),
        ("publishedUuid", "published_uuid"),
    ):
        candidate = value.get(remote)
        if isinstance(candidate, str) and UUID_RE.fullmatch(candidate):
            binding[local] = candidate
    if "published_uuid" in binding:
        binding["published_revocation_confirmed"] = (
            value.get("revocationConfirmed") is True
            or (
                type(value.get("revokedStatus")) is int
                and 200 <= value["revokedStatus"] < 300
            )
        )
    return binding


class NativeShareArtifactPublisher:
    """One-shot native share-from-content publisher with exact verification."""

    def __init__(
        self,
        port: int,
        *,
        expected_email_sha256: str,
        organization_uuid: str,
        native_session_ref: str,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.port = _validate_port(port)
        if not isinstance(expected_email_sha256, str) or not EMAIL_DIGEST_RE.fullmatch(
            expected_email_sha256
        ):
            raise FrameError("expected account email SHA-256 must be 64 lowercase hex characters")
        self.expected_email_sha256 = expected_email_sha256
        self.organization_uuid = validate_organization_uuid(organization_uuid)
        self.native_session_ref = validate_session_ref(native_session_ref)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 5 <= float(timeout) <= 180
        ):
            raise FrameError("native-share timeout must be between 5 and 180 seconds")
        self.timeout = float(timeout)

    def _browser_command(self, method: str, params: Optional[dict] = None) -> dict:
        version = _localhost_json(self.port, "/json/version")
        socket_url = version.get("webSocketDebuggerUrl") if isinstance(version, dict) else None
        with CdpSession(socket_url, self.port, timeout=self.timeout, kind="browser") as browser:
            return browser.command(method, params)

    def _target(self, target_id: str) -> dict:
        targets = _localhost_json(self.port, "/json/list")
        if not isinstance(targets, list):
            raise FrameError("Chrome returned an invalid target list")
        matches = [
            item
            for item in targets
            if isinstance(item, dict)
            and item.get("id") == target_id
            and item.get("type") == "page"
            and isinstance(item.get("webSocketDebuggerUrl"), str)
        ]
        if len(matches) != 1:
            raise FrameError("the controlled Claude authentication tab is unavailable")
        return matches[0]

    def _create_auth_target(self) -> Tuple[str, CdpSession]:
        created = self._browser_command(
            "Target.createTarget", {"url": CLAUDE_ORIGIN + "/new"}
        )
        target_id = created.get("targetId")
        if not isinstance(target_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", target_id):
            raise FrameError("Chrome did not create a controlled Claude authentication tab")
        ready_session = None
        failure = "the controlled Claude authentication tab did not become ready"
        try:
            deadline = time.monotonic() + min(self.timeout, 30.0)
            while time.monotonic() < deadline:
                session = None
                try:
                    target = self._target(target_id)
                    parts = urlsplit(str(target.get("url", "")))
                    if (
                        parts.scheme != "https"
                        or parts.hostname != "claude.ai"
                        or parts.port is not None
                        or parts.username is not None
                        or parts.password is not None
                        or parts.path.rstrip("/") != "/new"
                        or parts.query
                        or parts.fragment
                    ):
                        raise FrameError(
                            "the controlled Claude authentication tab changed location"
                        )
                    session = CdpSession(
                        target["webSocketDebuggerUrl"], self.port, timeout=self.timeout
                    )
                    ready = session.evaluate(
                        "location.origin === 'https://claude.ai' && "
                        "(document.readyState === 'complete' || "
                        "document.readyState === 'interactive')"
                    )
                    if ready is True:
                        ready_session = session
                        return target_id, session
                except FrameError as error:
                    failure = str(error)
                finally:
                    if session is not None and session is not ready_session:
                        try:
                            session.close()
                        except Exception:
                            pass
                time.sleep(0.25)
        finally:
            if ready_session is None:
                try:
                    self._close_target(target_id)
                except FrameError:
                    raise FrameError(
                        failure
                        + "; cleanup of the controlled authentication tab was not confirmed"
                    ) from None
        raise FrameError(failure)

    def _close_target(self, target_id: str) -> None:
        command_error = False
        try:
            result = self._browser_command("Target.closeTarget", {"targetId": target_id})
            command_error = result.get("success") is not True
        except FrameError:
            command_error = True
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                targets = _localhost_json(self.port, "/json/list")
                if isinstance(targets, list) and not any(
                    isinstance(item, dict) and item.get("id") == target_id
                    for item in targets
                ):
                    return
            except FrameError:
                command_error = True
            time.sleep(0.1)
        suffix = " after Chrome rejected the close request" if command_error else ""
        raise FrameError("controlled authentication tab cleanup was not confirmed" + suffix)

    def _transaction(
        self,
        session: CdpSession,
        source: str,
        filename: Optional[str],
        title: Optional[str],
        *,
        public: bool,
        action: str = "create",
        expected: Optional[dict] = None,
    ) -> Any:
        """Execute one browser-side transaction without exporting auth material."""

        arguments = ", ".join(
            json.dumps(value)
            for value in (
                self.expected_email_sha256,
                self.organization_uuid,
                self.native_session_ref,
                source,
                filename,
                title,
                public,
                action,
                expected,
            )
        )
        expression = r"""
(async (EXPECTED_DIGEST, EXPECTED_ORG, SESSION_REF, SOURCE, FILENAME, TITLE,
        REQUEST_PUBLIC, ACTION, EXPECTED) => {
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
  const safeText = (value, allowEmpty=false) => typeof value === 'string'
    && value.length <= 1000 && (allowEmpty || value.length > 0)
    && !/[\x00-\x1f\x7f]/.test(value);
  const boundedBytes = async (response, limit=2000000) => {
    const reader = response.body?.getReader();
    if (!reader) return {ok:false};
    const chunks = [];
    let size = 0;
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      size += item.value.byteLength;
      if (size > limit) {
        try { await reader.cancel(); } catch {}
        return {ok:false};
      }
      chunks.push(item.value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return {ok:true, bytes};
  };
  const boundedJson = async response => {
    const type = response.headers.get('content-type') || '';
    if (!/^application\/json(?:\s*;|$)/i.test(type)) return {ok:false};
    const body = await boundedBytes(response);
    if (!body.ok) return {ok:false};
    try {
      const text = new TextDecoder('utf-8', {fatal:true}).decode(body.bytes);
      return {ok:true, value:JSON.parse(text)};
    } catch { return {ok:false}; }
  };
  const readCookie = name => {
    let text;
    try { text = document.cookie; } catch { return null; }
    const prefix = name + '=';
    const part = text.split(';').map(value => value.trim())
      .find(value => value.startsWith(prefix));
    if (!part) return null;
    try { return decodeURIComponent(part.slice(prefix.length)); } catch { return null; }
  };
  const printable = value => {
    if (value === '') return '';
    if (typeof value !== 'string') return 'invalid';
    return value.replace(/[^\x20-\x7e]/g, '').trim() || 'invalid';
  };
  const stripOuterQuotes = value => {
    if (typeof value !== 'string' || value.length < 2) return value;
    return value[0] === '"' && value[value.length - 1] === '"'
      ? value.slice(1, -1) : value;
  };
  const anonymousId = stripOuterQuotes(readCookie('ajs_anonymous_id'));
  if (location.origin !== 'https://claude.ai'
      || typeof anonymousId !== 'string'
      || !/^[A-Za-z0-9_.-]{1,128}$/.test(anonymousId)) {
    return {stage:'preflight_headers'};
  }
  const dataset = document.documentElement?.dataset || {};
  const deviceId = readCookie('anthropic-device-id');
  const headers = {
    'Content-Type':'application/json',
    'anthropic-anonymous-id':anonymousId,
    'anthropic-device-id':deviceId === null ? 'unknown' : printable(deviceId),
    'anthropic-client-platform':'web_claude_ai',
    'anthropic-client-sha':dataset.gitHash ?? 'unknown',
    'anthropic-client-version':dataset.version ?? 'unknown',
    'anthropic-client-build':dataset.buildTimestamp ?? 'unknown',
  };
  const activityRaw = readCookie('activitySessionId');
  if (activityRaw) headers['x-activity-session-id'] = printable(activityRaw);
  const apiJson = async (path, init={}) => {
    let response;
    try {
      response = await fetch(path, {
        ...init, headers:{...headers, ...(init.headers || {})},
        credentials:'include', cache:'no-store', redirect:'error'
      });
    } catch { return {kind:'network'}; }
    if (!response.ok) return {kind:'http', status:response.status};
    const decoded = await boundedJson(response);
    return decoded.ok
      ? {kind:'ok', status:response.status, value:decoded.value}
      : {kind:'malformed', status:response.status};
  };
  const apiStatus = async (path, init={}) => {
    let response;
    try {
      response = await fetch(path, {
        ...init, headers:{...headers, ...(init.headers || {})},
        credentials:'include', cache:'no-store', redirect:'error'
      });
    } catch { return {kind:'network'}; }
    return response.ok
      ? {kind:'ok', status:response.status}
      : {kind:'http', status:response.status};
  };
  const identity = async () => {
    const response = await apiJson('/api/account');
    if (response.kind !== 'ok') return false;
    const payload = response.value;
    const email = typeof payload?.email_address === 'string'
      ? payload.email_address.toLowerCase() : '';
    const bytes = new Uint8Array(await crypto.subtle.digest(
      'SHA-256', new TextEncoder().encode(email)
    ));
    const digest = [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
    const member = Array.isArray(payload?.memberships)
      && payload.memberships.some(item => item?.organization?.uuid === EXPECTED_ORG);
    return digest === EXPECTED_DIGEST && member === true;
  };
  if (!(await identity())) return {stage:'preflight_identity'};

  const resolveCatalog = async (artifactUuid, versionUuid) => {
    let limit = 30;
    while (true) {
      const result = await apiJson(
        `/api/organizations/${EXPECTED_ORG}/user_artifacts?limit=${limit}`
          + '&offset=0&include_latest_published_artifact_uuid=true'
      );
      if (result.kind !== 'ok') return {ok:false, kind:result.kind, status:result.status};
      const list = result.value?.artifacts;
      if (!Array.isArray(list) || list.length > limit) return {ok:false, kind:'shape'};
      const matches = list.filter(item => item?.uuid === artifactUuid);
      if (matches.length > 1) return {ok:false, kind:'ambiguous'};
      if (matches.length === 1) {
        const item = matches[0];
        const valid = item.latest_artifact_version_uuid === versionUuid
          && safeText(item.artifact_identifier)
          && safeText(item.artifact_type)
          && UUID.test(item.chat_conversation_uuid || '')
          && (item.code_language === null || safeText(item.code_language, true))
          && safeText(item.title)
          && own(item, 'latest_published_artifact_uuid')
          && (item.latest_published_artifact_uuid === null
            || UUID.test(item.latest_published_artifact_uuid || ''));
        return valid ? {ok:true, item} : {ok:false, kind:'shape'};
      }
      if (list.length < limit || limit === 10000) return {ok:false, kind:'missing'};
      limit = Math.min(10000, limit + 30);
    }
  };
  const resolveVersion = async (catalog, binding) => {
    const result = await apiJson(
      `/api/organizations/${EXPECTED_ORG}/artifacts/`
        + `${catalog.chat_conversation_uuid}/versions`
    );
    if (result.kind !== 'ok') return {ok:false, kind:result.kind, status:result.status};
    const list = result.value?.artifact_versions;
    if (!Array.isArray(list)) return {ok:false, kind:'shape'};
    const matches = list.filter(item => item?.uuid === binding.versionUuid);
    if (matches.length !== 1) return {ok:false, kind:'match'};
    const row = matches[0];
    const valid = row.artifact_uuid === binding.artifactUuid
      && row.message_uuid === binding.messageUuid
      && row.result_state === SOURCE
      && row.artifact_type === catalog.artifact_type
      && row.code_language === catalog.code_language
      && row.title === catalog.title
      && own(row, 'published_artifact_uuid')
      && (row.published_artifact_uuid === null
        || UUID.test(row.published_artifact_uuid || ''))
      && own(row, 'published_artifact_deleted_at')
      && (row.published_artifact_deleted_at === null
        || safeText(row.published_artifact_deleted_at));
    return valid ? {ok:true, row} : {ok:false, kind:'binding'};
  };
  const listPublished = async includeDeleted => {
    const result = await apiJson(
      `/api/organizations/${EXPECTED_ORG}/published_artifacts?include_deleted_artifacts=`
        + (includeDeleted ? 'true' : 'false')
    );
    return result.kind === 'ok' && Array.isArray(result.value)
      ? {ok:true, list:result.value}
      : {ok:false, kind:result.kind, status:result.status};
  };
  const exactPublished = (item, catalog, row, binding, publishedUuid, deleted) =>
    own(item, 'published_artifact_uuid')
    && item.published_artifact_uuid === publishedUuid
    && own(item, 'artifact_identifier')
    && item.artifact_identifier === catalog.artifact_identifier
    && own(item, 'artifact_type') && item.artifact_type === row.artifact_type
    && own(item, 'artifact_version_uuid')
    && (item.artifact_version_uuid === null
      || item.artifact_version_uuid === binding.versionUuid)
    && own(item, 'chat_conversation_uuid')
    && item.chat_conversation_uuid === catalog.chat_conversation_uuid
    && own(item, 'code_language') && item.code_language === row.code_language
    && own(item, 'created_at') && safeText(item.created_at)
    && own(item, 'deleted') && item.deleted === deleted
    && own(item, 'message_uuid') && item.message_uuid === binding.messageUuid
    && own(item, 'title') && item.title === row.title;
  const verifyPublishedList = async (catalog, row, binding, publishedUuid, deleted) => {
    const listed = await listPublished(deleted);
    if (!listed.ok) return listed;
    const matches = listed.list.filter(
      item => item?.published_artifact_uuid === publishedUuid
    );
    if (matches.length !== 1
        || !exactPublished(matches[0], catalog, row, binding, publishedUuid, deleted)) {
      return {ok:false, kind:'binding'};
    }
    return {ok:true};
  };
  const verifyActiveZero = async publishedUuid => {
    const listed = await listPublished(false);
    if (!listed.ok) return listed;
    return listed.list.filter(item => item?.published_artifact_uuid === publishedUuid).length === 0
      ? {ok:true} : {ok:false, kind:'still_active'};
  };
  const rereadPublishedVersion = async (catalog, binding, publishedUuid, deleted) => {
    const version = await resolveVersion(catalog, binding);
    if (!version.ok) return version;
    const row = version.row;
    const valid = row.published_artifact_uuid === publishedUuid
      && (deleted
        ? safeText(row.published_artifact_deleted_at)
        : row.published_artifact_deleted_at === null);
    return valid ? {ok:true, row} : {ok:false, kind:'published_binding'};
  };
  const deleteAndVerify = async (catalog, row, binding, publishedUuid) => {
    const active = await verifyPublishedList(
      catalog, row, binding, publishedUuid, false
    );
    if (!active.ok) return {ok:false, step:'active_pre'};
    const removed = await apiStatus(
      `/api/organizations/${EXPECTED_ORG}/published_artifacts/${publishedUuid}`,
      {method:'DELETE', body:'{}'}
    );
    if (removed.kind !== 'ok') {
      return {ok:false, step:'delete', kind:removed.kind, status:removed.status};
    }
    const zero = await verifyActiveZero(publishedUuid);
    if (!zero.ok) return {ok:false, step:'active_zero'};
    const tombstone = await verifyPublishedList(
      catalog, row, binding, publishedUuid, true
    );
    if (!tombstone.ok) return {ok:false, step:'tombstone'};
    const version = await rereadPublishedVersion(
      catalog, binding, publishedUuid, true
    );
    if (!version.ok) return {ok:false, step:'version_deleted'};
    return {ok:true, status:removed.status};
  };
  const statelessShell = async publishedUuid => {
    let response;
    try {
      response = await fetch(`/public/artifacts/${publishedUuid}`, {
        method:'GET', credentials:'omit', cache:'no-store', redirect:'error',
        referrerPolicy:'no-referrer'
      });
    } catch { return false; }
    const type = response.headers.get('content-type') || '';
    const body = await boundedBytes(response);
    return response.status === 200 && /^text\/html(?:\s*;|$)/i.test(type) && body.ok;
  };

  if (ACTION === 'unpublish') {
    const binding = {
      artifactUuid:EXPECTED?.artifactUuid,
      versionUuid:EXPECTED?.versionUuid,
      messageUuid:EXPECTED?.messageUuid,
    };
    const publishedUuid = EXPECTED?.publishedUuid;
    if (!UUID.test(binding.artifactUuid || '') || !UUID.test(binding.versionUuid || '')
        || !UUID.test(binding.messageUuid || '') || !UUID.test(publishedUuid || '')) {
      return {stage:'unpublish_preflight'};
    }
    const ids = {...binding, publishedUuid};
    const catalogResult = await resolveCatalog(binding.artifactUuid, binding.versionUuid);
    if (!catalogResult.ok) return {stage:'unpublish_precheck', ...ids};
    const catalog = catalogResult.item;
    if (catalog.latest_published_artifact_uuid !== publishedUuid) {
      return {stage:'unpublish_precheck', ...ids};
    }
    const versionResult = await resolveVersion(catalog, binding);
    if (!versionResult.ok || versionResult.row.published_artifact_uuid !== publishedUuid
        || versionResult.row.published_artifact_deleted_at !== null) {
      return {stage:'unpublish_precheck', ...ids};
    }
    const removed = await deleteAndVerify(
      catalog, versionResult.row, binding, publishedUuid
    );
    if (!removed.ok) {
      return {stage:removed.step === 'delete' ? 'unpublish_mutation' : 'unpublish_verify',
        status:removed.status, mutationKind:removed.kind, ...ids};
    }
    if (!(await identity())) return {stage:'unpublish_final_identity', ...ids};
    return {stage:'unpublish_complete', revocationConfirmed:true, ...ids};
  }

  const anchor = {
    kind:'synthetic_stub', client_session_ref:SESSION_REF, source_kind:'cowork'
  };
  if (TITLE !== null) anchor.display_name = TITLE;
  const created = await apiJson(
    `/api/organizations/${EXPECTED_ORG}/artifacts/share_from_content`,
    {method:'POST', body:JSON.stringify({
      filename:FILENAME, content:SOURCE, operation:'share', anchor
    })}
  );
  if (created.kind === 'network') return {stage:'share_network'};
  if (created.kind === 'http') return {stage:'share_http', status:created.status};
  if (created.kind !== 'ok') return {stage:'share_malformed'};
  const artifactUuid = created.value?.artifact_uuid;
  const versionUuid = created.value?.artifact_version_uuid;
  const messageUuid = created.value?.message_uuid;
  const responsePublishedUuid = created.value?.published_artifact_uuid;
  if (!UUID.test(artifactUuid || '') || !UUID.test(versionUuid || '')
      || !UUID.test(messageUuid || '')
      || !(responsePublishedUuid === undefined || responsePublishedUuid === null
        || UUID.test(responsePublishedUuid || ''))) {
    return {stage:'share_malformed'};
  }
  const binding = {artifactUuid, versionUuid, messageUuid};
  const ids = {...binding,
    ...(UUID.test(responsePublishedUuid || '')
      ? {publishedUuid:responsePublishedUuid} : {})};
  if (!(await identity())) return {stage:'post_share_identity', ...ids};
  const catalogResult = await resolveCatalog(artifactUuid, versionUuid);
  if (!catalogResult.ok) return {stage:'catalog_verify', ...ids};
  const catalog = catalogResult.item;
  const conversationUuid = catalog.chat_conversation_uuid;
  const boundIds = {...ids, conversationUuid};
  const versionResult = await resolveVersion(catalog, binding);
  if (!versionResult.ok) return {stage:'version_verify', ...boundIds};
  const row = versionResult.row;
  const privacy = await apiStatus(
    `/api/organizations/${EXPECTED_ORG}/artifact-versions/${versionUuid}/visibility`,
    {method:'POST', body:'{"visibility":"private"}'}
  );
  if (privacy.kind !== 'ok') {
    return {stage:'privacy_mutation', status:privacy.status, ...boundIds};
  }
  const privacyCheck = await apiJson(
    `/api/organizations/${EXPECTED_ORG}/artifact-versions/${versionUuid}/visibility`
  );
  if (privacyCheck.kind !== 'ok' || privacyCheck.value?.visibility !== 'private') {
    return {stage:'privacy_verify', status:privacyCheck.status, ...boundIds};
  }
  if (UUID.test(responsePublishedUuid || '')) {
    const removed = await deleteAndVerify(
      catalog, row, binding, responsePublishedUuid
    );
    return {stage:removed.ok ? 'unexpected_public' : 'unexpected_public_cleanup',
      revocationConfirmed:removed.ok, ...boundIds, publishedUuid:responsePublishedUuid};
  }
  if (catalog.latest_published_artifact_uuid !== null
      || row.published_artifact_uuid !== null
      || row.published_artifact_deleted_at !== null) {
    return {stage:'unexpected_public_binding', ...boundIds};
  }
  if (!REQUEST_PUBLIC) {
    if (!(await identity())) return {stage:'final_identity', ...boundIds};
    return {stage:'complete', ...boundIds};
  }
  const publication = await apiJson(
    `/api/organizations/${EXPECTED_ORG}/publish_artifact`,
    {method:'POST', body:JSON.stringify({
      title:row.title,
      artifact_type:row.artifact_type,
      code_language:row.code_language,
      message_uuid:binding.messageUuid,
      conversation_uuid:catalog.chat_conversation_uuid,
      artifact_identifier:catalog.artifact_identifier,
      content:row.result_state,
      artifact_version_uuid:binding.versionUuid,
    })}
  );
  if (publication.kind === 'network') return {stage:'publish_network', ...boundIds};
  if (publication.kind === 'http') {
    return {stage:'publish_http', status:publication.status, ...boundIds};
  }
  if (publication.kind !== 'ok'
      || !UUID.test(publication.value?.published_artifact_uuid || '')) {
    return {stage:'publish_malformed', ...boundIds};
  }
  const publishedUuid = publication.value.published_artifact_uuid;
  const publicIds = {...boundIds, publishedUuid};
  const active = await verifyPublishedList(
    catalog, row, binding, publishedUuid, false
  );
  if (!active.ok) return {stage:'publish_active_verify', ...publicIds};
  const publishedVersion = await rereadPublishedVersion(
    catalog, binding, publishedUuid, false
  );
  if (!publishedVersion.ok) return {stage:'publish_version_verify', ...publicIds};
  if (!(await statelessShell(publishedUuid))) {
    return {stage:'publish_shell_verify', ...publicIds};
  }
  if (!(await identity())) return {stage:'publish_final_identity', ...publicIds};
  return {stage:'complete', ...publicIds};
})(__ARGS__)
""".replace("__ARGS__", arguments)
        return session.evaluate(expression)

    def _run_transaction(self, *args: Any, **kwargs: Any) -> tuple[Any, bool]:
        target_id = None
        session = None
        value = None
        local_cleanup_failed = False
        try:
            target_id, session = self._create_auth_target()
            try:
                value = self._transaction(session, *args, **kwargs)
            except FrameError:
                value = {"stage": "transport_unknown"}
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass
            if target_id is not None:
                try:
                    self._close_target(target_id)
                except FrameError:
                    local_cleanup_failed = True
        return value, local_cleanup_failed

    @staticmethod
    def _local_suffix(failed: bool) -> str:
        return (
            "; cleanup of the controlled authentication tab was not confirmed"
            if failed
            else ""
        )

    def publish(
        self,
        source: str,
        filename: str,
        title: Optional[str] = None,
        *,
        public: bool = False,
    ) -> NativeShareResult:
        encoded = validate_request(source, filename, title)
        if type(public) is not bool:
            raise FrameError("native-share public must be a boolean")
        value, local_cleanup_failed = self._run_transaction(
            source,
            _validate_filename(filename),
            title,
            public=public,
        )
        suffix = self._local_suffix(local_cleanup_failed)
        if not isinstance(value, dict):
            raise RemoteStateUnknown(
                "native-share returned an invalid result; remote state is unknown" + suffix
            )
        stage = value.get("stage")
        status = value.get("status")
        binding = _binding_kwargs(value)
        if stage == "preflight_headers":
            raise FrameError(
                "Claude's required anonymous browser identifier was absent or invalid" + suffix
            )
        if stage == "preflight_identity":
            raise FrameError(
                "the controlled Chrome profile did not match the required account and organization"
                + suffix
            )
        if stage == "share_http" and type(status) is int and status == 404:
            raise NativeCapabilityUnavailable(
                "native capability unavailable: the provider did not expose "
                "share-from-content for this account/session; no creation was confirmed"
                + suffix
            )
        if stage == "share_http" and type(status) is int and status in (401, 403):
            word = "authentication" if status == 401 else "authorization"
            raise FrameError(
                "native-share " + word + " was rejected; no creation was confirmed" + suffix
            )
        if stage == "share_http" and type(status) is int and 400 <= status < 500:
            raise FrameError(
                "native-share request was rejected with HTTP "
                + str(status)
                + "; no creation was confirmed"
                + suffix
            )
        if stage != "complete":
            detail = ""
            if stage in {"unexpected_public", "unexpected_public_cleanup"}:
                detail = "; the unexpected public mapping was removed only if confirmed"
            raise RemoteStateUnknown(
                "native-share remote state is unknown after a non-retried operation"
                + detail
                + suffix,
                **binding,
            )
        required = {"artifact_uuid", "version_uuid", "message_uuid", "conversation_uuid"}
        if (
            not required.issubset(binding)
            or (public and "published_uuid" not in binding)
            or (not public and "published_uuid" in binding)
        ):
            raise RemoteStateUnknown(
                "native-share returned an invalid provider binding" + suffix,
                **binding,
            )
        if local_cleanup_failed:
            raise RemoteStateUnknown(
                "native-share completed, but cleanup of the controlled "
                "authentication tab was not confirmed",
                **binding,
            )
        published_uuid = binding.get("published_uuid")
        return NativeShareResult(
            url=(
                CLAUDE_ORIGIN + "/public/artifacts/" + published_uuid
                if public
                else CLAUDE_ORIGIN + "/artifacts/" + binding["version_uuid"]
            ),
            artifact_uuid=binding["artifact_uuid"],
            version_uuid=binding["version_uuid"],
            message_uuid=binding["message_uuid"],
            source_sha256=hashlib.sha256(encoded).hexdigest(),
            public=public,
            published_uuid=published_uuid,
        )

    def unpublish(self, result: NativeShareResult, source: str) -> bool:
        """Remove and verify the exact public mapping represented by ``result``."""

        encoded = _validate_source(source)
        if not isinstance(result, NativeShareResult) or not result.public:
            raise FrameError("unpublish requires a public native-share result")
        if hashlib.sha256(encoded).hexdigest() != result.source_sha256:
            raise FrameError("unpublish source did not match the published source digest")
        for value, label in (
            (result.artifact_uuid, "artifact"),
            (result.version_uuid, "version"),
            (result.message_uuid, "message"),
            (result.published_uuid, "published artifact"),
        ):
            _validate_uuid(value, label)
        expected = {
            "artifactUuid": result.artifact_uuid,
            "versionUuid": result.version_uuid,
            "messageUuid": result.message_uuid,
            "publishedUuid": result.published_uuid,
        }
        value, local_cleanup_failed = self._run_transaction(
            source,
            None,
            None,
            public=False,
            action="unpublish",
            expected=expected,
        )
        suffix = self._local_suffix(local_cleanup_failed)
        binding = _binding_kwargs(value)
        exact_complete = (
            isinstance(value, dict)
            and value.get("stage") == "unpublish_complete"
            and value.get("revocationConfirmed") is True
            and binding.get("artifact_uuid") == result.artifact_uuid
            and binding.get("version_uuid") == result.version_uuid
            and binding.get("message_uuid") == result.message_uuid
            and binding.get("published_uuid") == result.published_uuid
        )
        if exact_complete:
            if local_cleanup_failed:
                raise RemoteStateUnknown(
                    "unpublish completed, but authentication tab cleanup was not confirmed",
                    **binding,
                )
            return True
        stage = value.get("stage") if isinstance(value, dict) else None
        if stage in {"preflight_headers", "preflight_identity", "unpublish_preflight"}:
            raise FrameError("unpublish preflight failed before mutation" + suffix)
        if stage == "unpublish_precheck":
            raise FrameError("the exact active public mapping could not be verified" + suffix)
        if stage == "unpublish_mutation" and value.get("mutationKind") == "http":
            status = value.get("status")
            if type(status) is int and 400 <= status < 500:
                raise FrameError("unpublish was rejected with HTTP " + str(status) + suffix)
        raise RemoteStateUnknown(
            "unpublish state is unknown after the single, non-retried deletion" + suffix,
            **binding,
        )

"""Browser-backed publisher for standard Claude chat Artifacts.

This module is deliberately separate from :mod:`clawdvert.frames`.  Claude
Code Artifacts and standard chat Artifacts are different products with
different identifiers, URLs, authentication surfaces, and lifecycle APIs.

The standard Artifact creation API is coupled to a Claude conversation. This
driver asks Claude to issue one exact ``create_file`` request in its output
directory, binds that request and one ``present_files`` request to the newly
created conversation, and converts the bound path with one non-retried provider
operation. It then requires the converted version's ``result_state`` to match
the input byte-for-byte. Public publication is a separate direct, one-shot API
operation. The driver never opens the Artifact preview, evaluates the returned
HTML, or exports browser cookies.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, replace
from typing import Any, Callable
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener

from .frames import FrameError


CHAT_ORIGIN = "https://claude.ai"
MAX_CHAT_SOURCE_CHARS = 100_000
MAX_CDP_JSON_BYTES = 4 * 1024 * 1024
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
CHAT_PATH_RE = re.compile(rf"^/chat/({UUID})$")
PUBLIC_PATH_RE = re.compile(rf"^/public/artifacts/({UUID})$")
OUTPUT_PATH_RE = re.compile(
    r"^/mnt/user-data/outputs/[A-Za-z0-9._/-]+$"
)
CDP_SOCKET_PATH_RE = {
    "browser": re.compile(r"^/devtools/browser/[A-Za-z0-9_-]+$"),
    "page": re.compile(r"^/devtools/page/[A-Za-z0-9_-]+$"),
}


# Claude currently returns the submitted human prompt in structured ``content``
# while retaining an empty legacy ``text`` field. Keep every browser-side
# transcript check on one implementation: the empty legacy field is only a
# placeholder, while every non-empty representation must agree exactly.
_EXACT_HUMAN_TEXT_JS = r"""
  const exactHumanText = message => {
    if (!message || !['human', 'user'].includes(message.sender)) return null;
    const representations = [];
    if (Object.prototype.hasOwnProperty.call(message, 'text')) {
      if (typeof message.text !== 'string') return null;
      if (message.text !== '') representations.push(message.text);
    }
    if (Array.isArray(message.content)) {
      const textual = message.content.filter(block => block?.type === 'text');
      if (textual.length > 1
          || textual.some(block => typeof block?.text !== 'string')) return null;
      if (textual.length === 1) representations.push(textual[0].text);
    }
    if (representations.length === 0
        || !representations.every(value => value === representations[0])) return null;
    return representations[0];
  };
"""


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generated_output_path(source: str, title: str) -> str:
    """Return a deterministic, provider-safe output path for one conversation."""

    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", title).strip(".-_")[:72]
    if not slug:
        slug = "artifact"
    path = f"/mnt/user-data/outputs/{slug}-{sha256_text(source)[:16]}.html"
    if not OUTPUT_PATH_RE.fullmatch(path) or "/../" in path or path.endswith("/.."):
        raise FrameError("could not derive a safe generated-file output path")
    return path


def build_prompt(source: str, title: str, output_path: str | None = None) -> str:
    """Return the fixed creation request sent to Claude.

    The prompt intentionally asks only for exact transcription.  It does not
    attempt to weaken product safeguards or hide what is being created.
    """

    if not source or len(source) > MAX_CHAT_SOURCE_CHARS:
        raise FrameError(
            f"chat Artifact source must be 1-{MAX_CHAT_SOURCE_CHARS} characters"
        )
    path = output_path or generated_output_path(source, title)
    if not OUTPUT_PATH_RE.fullmatch(path) or "/../" in path or path.endswith("/.."):
        raise FrameError("generated-file path must stay under /mnt/user-data/outputs")
    return (
        f"Create exactly one file at {path} by calling create_file exactly once. "
        "Set create_file.file_text to the complete HTML below byte-for-byte, "
        "without changing any character. Then call present_files exactly once "
        f"with only {path}. Do not create an Artifact, use any other tool, add "
        "dependencies, explain the file, or perform any other action.\n\n"
        "--- BEGIN EXACT HTML ---\n"
        f"{source}\n"
        "--- END EXACT HTML ---"
    )


def composer_form(prompt: str) -> str:
    """Model Claude's current contenteditable representation of newlines."""

    doubled = prompt.replace("\n", "\n\n")
    return doubled.replace("\n\n\n\n", "\n\n\n\n\n")


def validate_public_url(raw_url: Any, expected_published_uuid: str | None = None) -> str:
    if not isinstance(raw_url, str):
        raise FrameError("standard Artifact publish did not return a URL")
    parts = urlsplit(raw_url.rstrip("/"))
    if (
        parts.scheme != "https"
        or parts.hostname != "claude.ai"
        or parts.port is not None
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise FrameError("standard Artifact publish returned an unexpected URL")
    match = PUBLIC_PATH_RE.fullmatch(parts.path)
    if match is None:
        raise FrameError("standard Artifact publish returned an unexpected URL")
    if expected_published_uuid is not None and match.group(1) != expected_published_uuid:
        raise FrameError("the public Artifact link did not match the verified publication")
    return raw_url.rstrip("/")


def _validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise FrameError("--browser-port must be an integer from 1 to 65535")
    return port


def _localhost_json(port: int, path: str) -> Any:
    _validate_port(port)
    if path not in {"/json/list", "/json/version"}:
        raise FrameError("unsupported Chrome debugging endpoint")
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{port}{path}", timeout=4) as response:
            raw = response.read(MAX_CDP_JSON_BYTES + 1)
    except OSError as error:
        raise FrameError(
            f"cannot reach local Chrome debugging port {port}; start Chrome "
            "with --remote-debugging-port and sign in to claude.ai"
        ) from None
    if len(raw) > MAX_CDP_JSON_BYTES:
        raise FrameError("Chrome debugging response exceeded the size limit")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise FrameError("Chrome debugging endpoint returned invalid JSON") from None


def _validate_socket_url(raw_url: Any, port: int, kind: str = "page") -> str:
    if not isinstance(raw_url, str):
        raise FrameError("Chrome debugging target has no WebSocket URL")
    parts = urlsplit(raw_url)
    if (
        parts.scheme != "ws"
        or parts.hostname not in {"127.0.0.1", "localhost"}
        or parts.port != port
        or parts.username is not None
        or parts.password is not None
        or kind not in CDP_SOCKET_PATH_RE
        or not CDP_SOCKET_PATH_RE[kind].fullmatch(parts.path)
        or parts.query
        or parts.fragment
    ):
        raise FrameError("Chrome returned an unsafe debugging WebSocket URL")
    return raw_url


class CdpSession:
    """Small synchronous CDP client with bounded, fixed-purpose operations."""

    def __init__(
        self, socket_url: str, port: int, timeout: float = 30.0, *, kind: str = "page"
    ):
        try:
            import websocket
        except ImportError:
            raise FrameError(
                "chat Artifact publishing needs websocket-client; install the "
                "project requirements first"
            ) from None
        self._next_id = 1
        try:
            self._socket = websocket.create_connection(
                _validate_socket_url(socket_url, port, kind),
                timeout=timeout,
                suppress_origin=True,
                http_proxy_host=None,
            )
        except FrameError:
            raise
        except Exception:
            raise FrameError("could not attach to the local Chrome debugging target") from None

    def close(self) -> None:
        self._socket.close()

    def __enter__(self) -> "CdpSession":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def command(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        try:
            self._socket.send(
                json.dumps(
                    {"id": request_id, "method": method, "params": params or {}},
                    separators=(",", ":"),
                )
            )
            while True:
                reply = json.loads(self._socket.recv())
                if reply.get("id") != request_id:
                    continue
                if "error" in reply:
                    raise FrameError("Chrome rejected a debugging protocol command")
                result = reply.get("result")
                return result if isinstance(result, dict) else {}
        except FrameError:
            raise
        except (TypeError, ValueError):
            raise FrameError("Chrome debugging protocol returned invalid JSON") from None
        except Exception:
            raise FrameError("the local Chrome debugging connection failed") from None

    def evaluate(self, expression: str, *, user_gesture: bool = False) -> Any:
        result = self.command(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": True,
                "userGesture": user_gesture,
            },
        )
        if "exceptionDetails" in result:
            raise FrameError("Chrome rejected browser-side publisher logic")
        remote = result.get("result")
        if not isinstance(remote, dict) or "value" not in remote:
            raise FrameError("Chrome returned no browser-side publisher result")
        value = remote.get("value")
        return value


@dataclass(frozen=True)
class ChatPublishResult:
    url: str
    chat_url: str
    artifact_uuid: str
    version_uuid: str
    public: bool
    source_sha256: str
    published_uuid: str | None = None
    organization_uuid: str | None = None
    conversation_uuid: str | None = None
    message_uuid: str | None = None
    artifact_identifier: str | None = None
    artifact_type: str | None = None
    code_language: str | None = None
    title: str | None = None
    output_path: str | None = None
    prompt_sha256: str | None = None
    published_deleted: bool = False


@dataclass(frozen=True)
class ChatArtifactBinding:
    chat_url: str
    organization_uuid: str
    conversation_uuid: str
    artifact_uuid: str
    version_uuid: str
    message_uuid: str
    artifact_identifier: str
    artifact_type: str
    code_language: str | None
    title: str


@dataclass(frozen=True)
class ChatConversationBinding:
    """One exact newly created conversation, before generated-file acceptance."""

    chat_url: str
    organization_uuid: str
    conversation_uuid: str


@dataclass(frozen=True)
class ChatFileBinding:
    """Exact generated-file tool requests bound to one new conversation."""

    chat_url: str
    organization_uuid: str
    conversation_uuid: str
    output_path: str


@dataclass(frozen=True)
class ChatPreconversionBinding:
    """Durable provenance for cleanup before an Artifact UUID was accepted."""

    chat_url: str
    organization_uuid: str
    conversation_uuid: str
    output_path: str
    request_title: str
    source_sha256: str
    prompt_sha256: str
    receipt_stage: str


class ChatArtifactPublisher:
    """Create and optionally publish one exact standard chat Artifact."""

    def __init__(
        self,
        port: int,
        *,
        expected_email_sha256: str | None = None,
        organization_uuid: str | None = None,
        timeout: float = 240.0,
    ):
        self.port = _validate_port(port)
        self.timeout = max(30.0, min(float(timeout), 900.0))
        if expected_email_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", expected_email_sha256
        ):
            raise FrameError("--account-email-sha256 must be 64 lowercase hex characters")
        if organization_uuid is not None and not re.fullmatch(UUID, organization_uuid):
            raise FrameError("--organization-uuid must be a lowercase UUID")
        self.expected_email_sha256 = expected_email_sha256
        self.organization_uuid = organization_uuid

    def _browser_command(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        version = _localhost_json(self.port, "/json/version")
        socket_url = version.get("webSocketDebuggerUrl") if isinstance(version, dict) else None
        with CdpSession(socket_url, self.port, kind="browser") as session:
            return session.command(method, params)

    def _target(self, target_id: str) -> dict[str, Any]:
        targets = _localhost_json(self.port, "/json/list")
        if not isinstance(targets, list):
            raise FrameError("Chrome debugging target list was not an array")
        matches = [
            item
            for item in targets if isinstance(item, dict)
            if item.get("type") == "page"
            and item.get("id") == target_id
            and isinstance(item.get("webSocketDebuggerUrl"), str)
        ]
        if len(matches) != 1:
            raise FrameError("the controlled Claude chat tab is no longer available")
        return matches[0]

    def _create_chat_target(self) -> tuple[str, CdpSession]:
        result = self._browser_command("Target.createTarget", {"url": f"{CHAT_ORIGIN}/new"})
        target_id = result.get("targetId")
        if not isinstance(target_id, str):
            raise FrameError("Chrome did not create a new Claude chat tab")
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            session = None
            try:
                target = self._target(target_id)
                target_parts = urlsplit(target.get("url", ""))
                if (
                    target_parts.scheme != "https"
                    or target_parts.hostname != "claude.ai"
                    or target_parts.port is not None
                    or target_parts.username is not None
                    or target_parts.password is not None
                    or target_parts.path.rstrip("/") != "/new"
                    or target_parts.query
                    or target_parts.fragment
                ):
                    raise FrameError("the new Claude chat tab is still navigating")
                session = CdpSession(
                    target["webSocketDebuggerUrl"],
                    self.port,
                    timeout=self.timeout + 90.0,
                )
                ready = session.evaluate(
                    "location.origin === 'https://claude.ai' && "
                    "(document.readyState === 'complete' || document.readyState === 'interactive')"
                )
                if ready is True:
                    return target_id, session
            except FrameError:
                pass
            if session is not None:
                session.close()
            time.sleep(0.25)
        try:
            self._close_target(target_id)
        except FrameError:
            raise FrameError(
                "the new Claude chat tab did not become ready and cleanup of its "
                "exact target was not confirmed"
            ) from None
        raise FrameError("the new Claude chat tab did not become ready")

    def _close_target(self, target_id: str) -> None:
        """Close only the exact CDP target created by this publisher."""

        if not isinstance(target_id, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,256}", target_id
        ):
            raise FrameError("refusing to close an invalid Chrome target identifier")
        rejected = False
        try:
            result = self._browser_command("Target.closeTarget", {"targetId": target_id})
            rejected = result.get("success") is not True
        except FrameError:
            rejected = True
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
                rejected = True
            time.sleep(0.1)
        suffix = " after Chrome rejected the close request" if rejected else ""
        raise FrameError("controlled Claude tab cleanup was not confirmed" + suffix)

    def _require_identity(self, session: CdpSession) -> str:
        if self.expected_email_sha256 is None or self.organization_uuid is None:
            raise FrameError(
                "live conversation publishing requires exact account and organization binding"
            )
        value = session.evaluate(
            """
(async (EXPECTED_ORG) => {
  const response = await fetch('/api/account', {
    credentials:'same-origin', cache:'no-store', signal:AbortSignal.timeout(20000)
  });
  let payload = null;
  try { payload = await response.json(); } catch {}
  const email = typeof payload?.email_address === 'string'
    ? payload.email_address.toLowerCase() : '';
  const bytes = new Uint8Array(await crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode(email)
  ));
  const digest = [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
  const member = Array.isArray(payload?.memberships)
    && payload.memberships.some(item => item?.organization?.uuid === EXPECTED_ORG);
  return {status:response.status, loggedIn:Boolean(email), digest, member};
})(%s)
"""
            % json.dumps(self.organization_uuid)
        )
        if (
            not isinstance(value, dict)
            or value.get("status") != 200
            or value.get("loggedIn") is not True
        ):
            raise FrameError("the controlled Chrome profile is not signed in to Claude")
        if value.get("digest") != self.expected_email_sha256:
            raise FrameError("the controlled Chrome profile is signed in to a different account")
        if value.get("member") is not True:
            raise FrameError(
                "the controlled Chrome profile is not a member of the required organization"
            )
        digest = value.get("digest")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise FrameError("Claude returned an invalid account identity digest")
        return digest

    def _require_chat_location(self, session: CdpSession, expected_url: str) -> None:
        current = session.evaluate("location.href")
        if current != expected_url:
            raise FrameError("the controlled chat target changed before publication")

    def _wait_for_editor(self, session: CdpSession) -> None:
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            value = session.evaluate(
                r"""
(() => [...document.querySelectorAll('[data-testid="chat-input"]')]
  .filter(element => element instanceof HTMLElement
    && element.getClientRects().length > 0).length)()
"""
            )
            if value == 1:
                return
            time.sleep(0.25)
        raise FrameError("Claude's new-chat editor did not become ready")

    def _send_prompt(self, session: CdpSession, prompt: str) -> None:
        prepared = session.evaluate(
            """
(() => {
  const editors = [...document.querySelectorAll('[data-testid="chat-input"]')]
    .filter(element => element instanceof HTMLElement
      && element.getClientRects().length > 0);
  if (editors.length !== 1) return {ok:false, reason:'editor_count'};
  const editor = editors[0];
  if (editor.innerText.trim() !== '') return {ok:false, reason:'editor_not_empty'};
  editor.focus();
  const selection = window.getSelection();
  const range = document.createRange();
  range.selectNodeContents(editor);
  selection.removeAllRanges();
  selection.addRange(range);
  return {ok:true};
})()
""",
            user_gesture=True,
        )
        if not isinstance(prepared, dict) or prepared.get("ok") is not True:
            raise FrameError("Claude's chat editor was not empty and ready")
        session.command("Input.insertText", {"text": prompt})
        verified = session.evaluate(
            """
(() => {
  const editor = [...document.querySelectorAll('[data-testid="chat-input"]')]
    .find(element => element instanceof HTMLElement
      && element.getClientRects().length > 0);
  return Boolean(editor && [%s, %s].includes(editor.innerText));
})()
"""
            % (json.dumps(prompt), json.dumps(composer_form(prompt))),
            user_gesture=True,
        )
        if verified is not True:
            raise FrameError("Claude's chat editor did not retain the exact publish request")
        session.command(
            "Input.dispatchKeyEvent",
            {
                "type": "keyDown",
                "key": "Enter",
                "code": "Enter",
                "text": "\r",
                "unmodifiedText": "\r",
                "windowsVirtualKeyCode": 13,
                "nativeVirtualKeyCode": 13,
            },
        )
        session.command(
            "Input.dispatchKeyEvent",
            {
                "type": "keyUp",
                "key": "Enter",
                "code": "Enter",
                "windowsVirtualKeyCode": 13,
                "nativeVirtualKeyCode": 13,
            },
        )

    def _wait_for_exact_file(
        self,
        session: CdpSession,
        source: str,
        prompt: str,
        output_path: str,
        *,
        on_conversation_binding: Callable[[ChatConversationBinding], None] | None = None,
    ) -> ChatFileBinding:
        """Stably bind exactly one ordered create_file/present_files request pair."""

        if self.organization_uuid is None:
            raise FrameError("conversation publishing requires an exact organization UUID")
        if (
            not OUTPUT_PATH_RE.fullmatch(output_path)
            or "/../" in output_path
            or output_path.endswith("/..")
        ):
            raise FrameError("generated-file path escaped /mnt/user-data/outputs")
        deadline = time.monotonic() + self.timeout
        last_state = "waiting_for_conversation"
        consecutive_matches = 0
        stable_conversation_uuid: str | None = None
        journaled_conversation_uuid: str | None = None
        while time.monotonic() < deadline:
            raw_url = session.evaluate("location.href")
            parts = urlsplit(raw_url) if isinstance(raw_url, str) else None
            match = CHAT_PATH_RE.fullmatch(parts.path) if parts else None
            if not (
                parts
                and parts.scheme == "https"
                and parts.hostname == "claude.ai"
                and parts.port is None
                and parts.username is None
                and parts.password is None
                and not parts.query
                and not parts.fragment
                and match
            ):
                consecutive_matches = 0
                stable_conversation_uuid = None
                time.sleep(0.5)
                continue
            conversation_uuid = match.group(1)
            if (
                on_conversation_binding is not None
                and journaled_conversation_uuid != conversation_uuid
            ):
                conversation_binding = ChatConversationBinding(
                    chat_url=raw_url,
                    organization_uuid=self.organization_uuid,
                    conversation_uuid=conversation_uuid,
                )
                try:
                    on_conversation_binding(conversation_binding)
                except Exception:
                    raise FrameError(
                        "the new conversation was bound but its durable callback failed; "
                        f"organization={self.organization_uuid}, "
                        f"conversation={conversation_uuid}"
                    ) from None
                journaled_conversation_uuid = conversation_uuid
            value = session.evaluate(
                r"""
(async (ORG, CONVERSATION, PROMPT, SOURCE, OUTPUT_PATH) => {
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const ownKeys = value => value && typeof value === 'object' && !Array.isArray(value)
    ? Object.keys(value).sort() : [];
  const sameKeys = (value, expected) => {
    const actual = ownKeys(value);
    return actual.length === expected.length
      && actual.every((key, index) => key === expected[index]);
  };
  if (location.href !== `https://claude.ai/chat/${CONVERSATION}`
      || !UUID.test(ORG) || !UUID.test(CONVERSATION)
      || !/^\/mnt\/user-data\/outputs\/[A-Za-z0-9._\/-]+$/.test(OUTPUT_PATH)
      || OUTPUT_PATH.includes('/../') || OUTPUT_PATH.endsWith('/..')) {
    return {ok:false, state:'preflight'};
  }
  let response;
  try {
    response = await fetch(
      `/api/organizations/${ORG}/chat_conversations/${CONVERSATION}`
        + '?tree=True&rendering_mode=messages&render_all_tools=true&consistency=strong',
      {credentials:'same-origin', cache:'no-store', redirect:'error',
        signal:AbortSignal.timeout(20000)}
    );
  } catch { return {ok:false, state:'conversation_network'}; }
  let payload = null;
  try { payload = await response.json(); } catch {}
  if (!response.ok || payload?.uuid !== CONVERSATION
      || !Array.isArray(payload?.chat_messages)) {
    return {ok:false, state:'conversation_fetch', status:response.status};
  }
  const messages = payload.chat_messages;
%s
  const humans = messages
    .map((message, index) => ({message, index}))
    .filter(item => exactHumanText(item.message) === PROMPT);
  const allHumans = messages.filter(
    message => ['human', 'user'].includes(message?.sender)
  );
  if (humans.length !== 1 || allHumans.length !== 1) {
    return {ok:false, state:'human_prompt', count:humans.length};
  }
  const tools = [];
  messages.forEach((message, messageIndex) => {
    if (message?.sender !== 'assistant' || !Array.isArray(message.content)) return;
    message.content.forEach((block, blockIndex) => {
      if (block?.type === 'tool_use') tools.push({block, messageIndex, blockIndex});
    });
  });
  if (tools.length !== 2
      || tools[0].messageIndex <= humans[0].index
      || tools[0].block?.name !== 'create_file'
      || tools[1].block?.name !== 'present_files'
      || tools[0].messageIndex > tools[1].messageIndex
      || (tools[0].messageIndex === tools[1].messageIndex
        && tools[0].blockIndex >= tools[1].blockIndex)) {
    return {ok:false, state:'tool_order', count:tools.length};
  }
  const create = tools[0].block.input;
  const present = tools[1].block.input;
  if (!sameKeys(create, ['description', 'file_text', 'path'])
      || typeof create.description !== 'string'
      || create.description.length < 1 || create.description.length > 1000
      || create.file_text !== SOURCE || create.path !== OUTPUT_PATH) {
    return {ok:false, state:'create_file_binding'};
  }
  if (!sameKeys(present, ['filepaths']) || !Array.isArray(present.filepaths)
      || present.filepaths.length !== 1 || present.filepaths[0] !== OUTPUT_PATH) {
    return {ok:false, state:'present_files_binding'};
  }
  const visible = element => element instanceof HTMLElement
    && element.getClientRects().length > 0;
  const stopLabels = new Set(['stop response', 'stop generating', 'stop generation']);
  const stopControls = [...document.querySelectorAll('button, [role="button"]')]
    .filter(element => {
      if (!visible(element)) return false;
      const testId = (element.getAttribute('data-testid') || '').toLowerCase();
      const label = (element.getAttribute('aria-label') || element.textContent || '')
        .trim().toLowerCase();
      return testId === 'stop-button' || testId === 'stop-response'
        || testId === 'stop-generating' || stopLabels.has(label);
    });
  if (stopControls.length !== 0) {
    return {ok:false, state:'generation_active', count:stopControls.length};
  }
  return {ok:true};
})(%s)
"""
                % (
                    _EXACT_HUMAN_TEXT_JS,
                    ", ".join(
                        json.dumps(item)
                        for item in (
                            self.organization_uuid,
                            conversation_uuid,
                            prompt,
                            source,
                            output_path,
                        )
                    ),
                )
            )
            if isinstance(value, dict):
                last_state = str(value.get("state", "waiting"))
                if value.get("ok") is True:
                    if stable_conversation_uuid == conversation_uuid:
                        consecutive_matches += 1
                    else:
                        stable_conversation_uuid = conversation_uuid
                        consecutive_matches = 1
                    last_state = f"stable_match_{consecutive_matches}_of_3"
                    if consecutive_matches >= 3:
                        return ChatFileBinding(
                            chat_url=raw_url,
                            organization_uuid=self.organization_uuid,
                            conversation_uuid=conversation_uuid,
                            output_path=output_path,
                        )
                else:
                    consecutive_matches = 0
                    stable_conversation_uuid = None
            time.sleep(1.0)
        raise FrameError(
            "Claude did not stably expose the exact generated-file tool requests before the "
            f"timeout (last state: {last_state})"
        )

    def _convert_file_to_artifact(
        self,
        session: CdpSession,
        file_binding: ChatFileBinding,
        source: str,
        prompt: str,
        on_binding: Callable[[ChatArtifactBinding], None] | None = None,
        on_published_uuid: Callable[[ChatArtifactBinding, str], None] | None = None,
    ) -> ChatArtifactBinding:
        """Convert one stably bound file request and force internal visibility private."""

        if (
            self.expected_email_sha256 is None
            or self.organization_uuid is None
            or file_binding.organization_uuid != self.organization_uuid
            or not re.fullmatch(UUID, file_binding.conversation_uuid)
            or not OUTPUT_PATH_RE.fullmatch(file_binding.output_path)
            or "/../" in file_binding.output_path
            or file_binding.output_path.endswith("/..")
        ):
            raise FrameError("generated-file conversion lacked an exact local binding")
        arguments = ", ".join(
            json.dumps(item)
            for item in (
                self.expected_email_sha256,
                self.organization_uuid,
                file_binding.conversation_uuid,
                file_binding.chat_url,
                file_binding.output_path,
                prompt,
                source,
            )
        )
        value = session.evaluate(
            r"""
(async (EXPECTED_DIGEST, ORG, CONVERSATION, CHAT_URL, OUTPUT_PATH, PROMPT, SOURCE) => {
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
  const keysAre = (value, keys) => value && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).sort().join('\x00') === [...keys].sort().join('\x00');
  const safeText = (value, allowEmpty=false) => typeof value === 'string'
    && value.length <= 1000 && (allowEmpty || value.length > 0)
    && !/[\x00-\x1f\x7f]/.test(value);
  const readCookie = name => {
    let text;
    try { text = document.cookie; } catch { return null; }
    const prefix = name + '=';
    const part = text.split(';').map(value => value.trim())
      .find(value => value.startsWith(prefix));
    if (!part) return null;
    try { return decodeURIComponent(part.slice(prefix.length)); } catch { return null; }
  };
  const printable = value => typeof value === 'string'
    ? value.replace(/[^\x20-\x7e]/g, '').trim() : '';
  const stripOuterQuotes = value => typeof value === 'string'
    && value.length >= 2 && value[0] === '"' && value[value.length - 1] === '"'
    ? value.slice(1, -1) : value;
  const anonymousId = stripOuterQuotes(readCookie('ajs_anonymous_id'));
  const dataset = document.documentElement?.dataset || {};
  const deviceId = readCookie('anthropic-device-id');
  const apiHeaders = typeof anonymousId === 'string'
    && /^[A-Za-z0-9_.-]{1,128}$/.test(anonymousId) ? {
      'Content-Type':'application/json',
      'anthropic-anonymous-id':anonymousId,
      'anthropic-device-id':deviceId === null ? 'unknown' : (printable(deviceId) || 'invalid'),
      'anthropic-client-platform':'web_claude_ai',
      'anthropic-client-sha':dataset.gitHash ?? 'unknown',
      'anthropic-client-version':dataset.version ?? 'unknown',
      'anthropic-client-build':dataset.buildTimestamp ?? 'unknown',
    } : null;
  const activityRaw = readCookie('activitySessionId');
  if (apiHeaders && activityRaw) {
    apiHeaders['x-activity-session-id'] = printable(activityRaw) || 'invalid';
  }
  const boundedText = async (response, limit=2000000) => {
    const reader = response.body?.getReader();
    if (!reader) return null;
    const decoder = new TextDecoder();
    let size = 0;
    let text = '';
    while (true) {
      let item;
      try { item = await reader.read(); } catch { return null; }
      if (item.done) {
        try { return text + decoder.decode(); } catch { return null; }
      }
      size += item.value.byteLength;
      if (size > limit) {
        try { await reader.cancel(); } catch {}
        return null;
      }
      try { text += decoder.decode(item.value, {stream:true}); } catch { return null; }
    }
  };
  const apiJson = async (path, init={}) => {
    let response;
    try {
      response = await fetch(path, {
        ...init,
        headers:{...apiHeaders, ...(init.headers || {})},
        credentials:'same-origin', cache:'no-store', redirect:'error',
        signal:AbortSignal.timeout(init.method && init.method !== 'GET' ? 30000 : 20000)
      });
    } catch { return {kind:'network'}; }
    const text = await boundedText(response);
    if (text === null) return {kind:'malformed', status:response.status};
    let body = null;
    try { body = text === '' ? null : JSON.parse(text); } catch {
      return {kind:'malformed', status:response.status};
    }
    return response.ok
      ? {kind:'ok', status:response.status, value:body}
      : {kind:'http', status:response.status, value:body};
  };
  const apiStatus = async (path, init={}) => {
    let response;
    try {
      response = await fetch(path, {
        ...init,
        headers:{...apiHeaders, ...(init.headers || {})},
        credentials:'same-origin', cache:'no-store', redirect:'error',
        signal:AbortSignal.timeout(init.method && init.method !== 'GET' ? 30000 : 20000)
      });
    } catch { return {kind:'network'}; }
    return response.ok
      ? {kind:'ok', status:response.status}
      : {kind:'http', status:response.status};
  };
  const identity = async () => {
    const result = await apiJson('/api/account');
    if (result.kind !== 'ok') return false;
    const account = result.value;
    const email = typeof account?.email_address === 'string'
      ? account.email_address.toLowerCase() : '';
    const digestBytes = new Uint8Array(await crypto.subtle.digest(
      'SHA-256', new TextEncoder().encode(email)
    ));
    const digest = [...digestBytes]
      .map(byte => byte.toString(16).padStart(2, '0')).join('');
    return digest === EXPECTED_DIGEST && Array.isArray(account?.memberships)
      && account.memberships.some(item => item?.organization?.uuid === ORG);
  };
  const exactFile = async () => {
    const result = await apiJson(
      `/api/organizations/${ORG}/chat_conversations/${CONVERSATION}`
        + '?tree=True&rendering_mode=messages&render_all_tools=true&consistency=strong'
    );
    const payload = result.value;
    if (result.kind !== 'ok' || payload?.uuid !== CONVERSATION
        || !Array.isArray(payload?.chat_messages)) return false;
    const messages = payload.chat_messages;
%s
    const humanIndexes = messages.map((message, index) => ({message, index}))
      .filter(item => exactHumanText(item.message) === PROMPT);
    if (humanIndexes.length !== 1
        || messages.filter(message => ['human', 'user'].includes(message?.sender)).length !== 1) {
      return false;
    }
    const tools = [];
    messages.forEach((message, messageIndex) => {
      if (message?.sender !== 'assistant' || !Array.isArray(message.content)) return;
      message.content.forEach((block, blockIndex) => {
        if (block?.type === 'tool_use') tools.push({block, messageIndex, blockIndex});
      });
    });
    if (tools.length !== 2 || tools[0].messageIndex <= humanIndexes[0].index
        || tools[0].block?.name !== 'create_file'
        || tools[1].block?.name !== 'present_files'
        || tools[0].messageIndex > tools[1].messageIndex
        || (tools[0].messageIndex === tools[1].messageIndex
          && tools[0].blockIndex >= tools[1].blockIndex)) return false;
    const create = tools[0].block.input;
    const present = tools[1].block.input;
    return keysAre(create, ['description', 'file_text', 'path'])
      && safeText(create.description)
      && create.file_text === SOURCE && create.path === OUTPUT_PATH
      && keysAre(present, ['filepaths']) && Array.isArray(present.filepaths)
      && present.filepaths.length === 1 && present.filepaths[0] === OUTPUT_PATH;
  };
  const resolveCatalog = async (artifactUuid, versionUuid, publishedUuid) => {
    let limit = 30;
    while (true) {
      const result = await apiJson(
        `/api/organizations/${ORG}/user_artifacts?limit=${limit}`
          + '&offset=0&include_latest_published_artifact_uuid=true'
      );
      const list = result.value?.artifacts;
      if (result.kind !== 'ok' || !Array.isArray(list) || list.length > limit) {
        return {ok:false};
      }
      const matches = list.filter(item => item?.uuid === artifactUuid);
      if (matches.length > 1) return {ok:false};
      if (matches.length === 1) {
        const item = matches[0];
        const valid = item.latest_artifact_version_uuid === versionUuid
          && item.chat_conversation_uuid === CONVERSATION
          && safeText(item.artifact_identifier) && safeText(item.artifact_type)
          && (item.code_language === null || safeText(item.code_language, true))
          && safeText(item.title) && own(item, 'latest_published_artifact_uuid')
          && item.latest_published_artifact_uuid === publishedUuid;
        return valid ? {ok:true, item} : {ok:false};
      }
      if (list.length < limit || limit === 10000) return {ok:false};
      limit = Math.min(10000, limit + 30);
    }
  };
  const resolveVersion = async (catalog, binding, publishedUuid) => {
    const result = await apiJson(
      `/api/organizations/${ORG}/artifacts/${CONVERSATION}/versions`
    );
    const list = result.value?.artifact_versions;
    if (result.kind !== 'ok' || !Array.isArray(list)) return {ok:false};
    const matches = list.filter(item => item?.uuid === binding.versionUuid);
    if (matches.length !== 1) return {ok:false};
    const row = matches[0];
    const valid = row.artifact_uuid === binding.artifactUuid
      && row.message_uuid === binding.messageUuid
      && row.result_state === SOURCE
      && row.artifact_type === catalog.artifact_type
      && row.code_language === catalog.code_language
      && row.title === catalog.title
      && own(row, 'published_artifact_uuid')
      && row.published_artifact_uuid === publishedUuid
      && own(row, 'published_artifact_deleted_at')
      && row.published_artifact_deleted_at === null;
    return valid ? {ok:true, row} : {ok:false};
  };

  if (location.href !== CHAT_URL || location.origin !== 'https://claude.ai'
      || !UUID.test(ORG) || !UUID.test(CONVERSATION)
      || CHAT_URL !== `https://claude.ai/chat/${CONVERSATION}`
      || !/^\/mnt\/user-data\/outputs\/[A-Za-z0-9._\/-]+$/.test(OUTPUT_PATH)
      || OUTPUT_PATH.includes('/../') || OUTPUT_PATH.endsWith('/..')) {
    return {stage:'preflight_binding', mutationAttempted:false};
  }
  if (apiHeaders === null) {
    return {stage:'preflight_headers', mutationAttempted:false};
  }
  if (!(await identity())) return {stage:'preflight_identity', mutationAttempted:false};
  if (!(await exactFile())) return {stage:'preflight_file', mutationAttempted:false};
  if (!(await identity())) return {stage:'pre_convert_identity', mutationAttempted:false};

  const converted = await apiJson(
    `/api/organizations/${ORG}/conversations/${CONVERSATION}`
      + '/wiggle/convert-file-to-artifact',
    {method:'POST', body:JSON.stringify({path:OUTPUT_PATH, operation:'share'})}
  );
  if (converted.kind !== 'ok' || converted.status !== 200) {
    return {stage:'convert_' + converted.kind, status:converted.status,
      mutationAttempted:true};
  }
  const artifactUuid = converted.value?.artifact_uuid;
  const versionUuid = converted.value?.artifact_version_uuid;
  const messageUuid = converted.value?.message_uuid;
  const responsePublished = converted.value?.published_artifact_uuid;
  const responseKeys = converted.value && typeof converted.value === 'object'
      && !Array.isArray(converted.value)
    ? Object.keys(converted.value)
      .filter(key => /^[A-Za-z0-9_]{1,64}$/.test(key)).sort().slice(0, 32)
    : [];
  if (!UUID.test(artifactUuid || '') || !UUID.test(versionUuid || '')
      || !UUID.test(messageUuid || '')
      || !(responsePublished === undefined || responsePublished === null
        || UUID.test(responsePublished || ''))) {
    return {stage:'convert_shape', mutationAttempted:true, responseKeys};
  }
  const publishedUuid = UUID.test(responsePublished || '') ? responsePublished : null;
  const ids = {artifactUuid, versionUuid, messageUuid, conversationUuid:CONVERSATION,
    ...(publishedUuid === null ? {} : {publishedUuid})};
  if (!(await identity())) return {stage:'post_convert_identity', ...ids};
  const catalogResult = await resolveCatalog(artifactUuid, versionUuid, publishedUuid);
  if (!catalogResult.ok) return {stage:'catalog_verify', ...ids};
  const catalog = catalogResult.item;
  const versionResult = await resolveVersion(
    catalog, {artifactUuid, versionUuid, messageUuid}, publishedUuid
  );
  if (!versionResult.ok) return {stage:'version_verify', ...ids};
  if (!(await identity())) return {stage:'pre_privacy_identity', ...ids};
  const visibility = await apiStatus(
    `/api/organizations/${ORG}/artifact-versions/${versionUuid}/visibility`,
    {method:'POST', body:JSON.stringify({visibility:'private'})}
  );
  if (visibility.kind !== 'ok') {
    return {stage:'privacy_' + visibility.kind, status:visibility.status, ...ids};
  }
  const visibilityCheck = await apiJson(
    `/api/organizations/${ORG}/artifact-versions/${versionUuid}/visibility`
  );
  if (visibilityCheck.kind !== 'ok'
      || visibilityCheck.value?.visibility !== 'private') {
    return {stage:'privacy_verify', ...ids};
  }
  if (!(await exactFile())) return {stage:'final_file_binding', ...ids};
  if (!(await identity())) return {stage:'final_identity', ...ids};
  if (location.href !== CHAT_URL) return {stage:'final_location', ...ids};
  return {
    stage:publishedUuid === null ? 'complete' : 'unexpected_public', ...ids,
    artifactIdentifier:catalog.artifact_identifier,
    artifactType:catalog.artifact_type,
    codeLanguage:catalog.code_language,
    title:catalog.title,
  };
})(%s)
"""
            % (_EXACT_HUMAN_TEXT_JS, arguments)
        )
        if isinstance(value, dict) and value.get("stage") in {
            "complete",
            "unexpected_public",
        }:
            required = (
                "artifactUuid",
                "versionUuid",
                "messageUuid",
                "conversationUuid",
            )
            if (
                all(
                    isinstance(value.get(key), str)
                    and re.fullmatch(UUID, value[key])
                    for key in required
                )
                and value["conversationUuid"] == file_binding.conversation_uuid
                and isinstance(value.get("artifactIdentifier"), str)
                and isinstance(value.get("artifactType"), str)
                and (
                    value.get("codeLanguage") is None
                    or isinstance(value.get("codeLanguage"), str)
                )
                and isinstance(value.get("title"), str)
            ):
                binding = ChatArtifactBinding(
                    chat_url=file_binding.chat_url,
                    organization_uuid=self.organization_uuid,
                    conversation_uuid=file_binding.conversation_uuid,
                    artifact_uuid=value["artifactUuid"],
                    version_uuid=value["versionUuid"],
                    message_uuid=value["messageUuid"],
                    artifact_identifier=value["artifactIdentifier"],
                    artifact_type=value["artifactType"],
                    code_language=value["codeLanguage"],
                    title=value["title"],
                )
                if value.get("stage") == "unexpected_public":
                    unexpected_uuid = value.get("publishedUuid")
                    if not isinstance(unexpected_uuid, str) or not re.fullmatch(
                        UUID, unexpected_uuid
                    ):
                        raise FrameError(
                            "conversion returned an invalid unexpected public mapping; "
                            f"cleanup identifiers: artifact={binding.artifact_uuid}, "
                            f"version={binding.version_uuid}, message={binding.message_uuid}, "
                            f"conversation={binding.conversation_uuid}"
                        )
                    if on_binding is not None:
                        try:
                            on_binding(binding)
                        except Exception:
                            raise FrameError(
                                "conversion created an unexpected public mapping after "
                                "exact binding, but the durable Artifact callback failed; "
                                "cleanup identifiers: "
                                f"organization={binding.organization_uuid}, "
                                f"artifact={binding.artifact_uuid}, "
                                f"version={binding.version_uuid}, "
                                f"message={binding.message_uuid}, "
                                f"conversation={binding.conversation_uuid}, "
                                f"published={unexpected_uuid}"
                            ) from None
                    if on_published_uuid is not None:
                        try:
                            on_published_uuid(binding, unexpected_uuid)
                        except Exception:
                            raise FrameError(
                                "conversion created an unexpected public mapping but its "
                                "durable callback failed; cleanup identifiers: "
                                f"organization={binding.organization_uuid}, "
                                f"artifact={binding.artifact_uuid}, "
                                f"version={binding.version_uuid}, "
                                f"message={binding.message_uuid}, "
                                f"conversation={binding.conversation_uuid}, "
                                f"published={unexpected_uuid}"
                            ) from None
                    raise FrameError(
                        "conversion unexpectedly created a public mapping; it was not "
                        "accepted as success; cleanup identifiers: "
                        f"organization={binding.organization_uuid}, "
                        f"artifact={binding.artifact_uuid}, version={binding.version_uuid}, "
                        f"message={binding.message_uuid}, "
                        f"conversation={binding.conversation_uuid}, "
                        f"published={unexpected_uuid}"
                    )
                return binding
        if isinstance(value, dict) and value.get("mutationAttempted") is False:
            raise FrameError(
                "generated-file conversion preflight failed before provider mutation "
                f"(stage: {value.get('stage', 'unknown')}); cleanup identifiers: "
                f"organization={self.organization_uuid}, "
                f"conversation={file_binding.conversation_uuid}"
            )
        identifiers = [f"organization={self.organization_uuid}"]
        if isinstance(value, dict):
            for remote, label in (
                ("artifactUuid", "artifact"),
                ("versionUuid", "version"),
                ("messageUuid", "message"),
                ("conversationUuid", "conversation"),
                ("publishedUuid", "published"),
            ):
                candidate = value.get(remote)
                if isinstance(candidate, str) and re.fullmatch(UUID, candidate):
                    identifiers.append(f"{label}={candidate}")
        suffix = "; cleanup identifiers: " + ", ".join(identifiers) if identifiers else ""
        response_keys = value.get("responseKeys") if isinstance(value, dict) else None
        if (
            isinstance(response_keys, list)
            and len(response_keys) <= 32
            and all(
                isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_]{1,64}", key)
                for key in response_keys
            )
        ):
            suffix += "; response-keys=" + ",".join(response_keys)
        stage = value.get("stage", "invalid_result") if isinstance(value, dict) else "invalid_result"
        raise FrameError(
            "generated-file conversion remote state is unknown after a non-retried "
            f"operation (stage: {stage}){suffix}"
        )

    def _verify_public_mapping(
        self,
        session: CdpSession,
        binding: ChatArtifactBinding,
        source: str,
        published_uuid: str,
    ) -> None:
        """Bind one direct public mapping to catalog, version, active row, and shell."""

        deadline = time.monotonic() + 60.0
        last_state = "waiting"
        while time.monotonic() < deadline:
            value = session.evaluate(
                r"""
(async () => {
  const expected = %s;
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
  const safeText = (value, allowEmpty=false) => typeof value === 'string'
    && value.length <= 1000 && (allowEmpty || value.length > 0)
    && !/[\x00-\x1f\x7f]/.test(value);
  const readCookie = name => {
    let text;
    try { text = document.cookie; } catch { return null; }
    const prefix = name + '=';
    const part = text.split(';').map(value => value.trim())
      .find(value => value.startsWith(prefix));
    if (!part) return null;
    try { return decodeURIComponent(part.slice(prefix.length)); } catch { return null; }
  };
  const printable = value => typeof value === 'string'
    ? value.replace(/[^\x20-\x7e]/g, '').trim() : '';
  const stripOuterQuotes = value => typeof value === 'string'
    && value.length >= 2 && value[0] === '"' && value[value.length - 1] === '"'
    ? value.slice(1, -1) : value;
  const anonymousId = stripOuterQuotes(readCookie('ajs_anonymous_id'));
  const dataset = document.documentElement?.dataset || {};
  const deviceId = readCookie('anthropic-device-id');
  const apiHeaders = typeof anonymousId === 'string'
    && /^[A-Za-z0-9_.-]{1,128}$/.test(anonymousId) ? {
      'Content-Type':'application/json',
      'anthropic-anonymous-id':anonymousId,
      'anthropic-device-id':deviceId === null ? 'unknown' : (printable(deviceId) || 'invalid'),
      'anthropic-client-platform':'web_claude_ai',
      'anthropic-client-sha':dataset.gitHash ?? 'unknown',
      'anthropic-client-version':dataset.version ?? 'unknown',
      'anthropic-client-build':dataset.buildTimestamp ?? 'unknown',
    } : null;
  const activityRaw = readCookie('activitySessionId');
  if (apiHeaders && activityRaw) {
    apiHeaders['x-activity-session-id'] = printable(activityRaw) || 'invalid';
  }
  const boundedBody = async (response, limit=2000000) => {
    const reader = response.body?.getReader();
    if (!reader) return false;
    let size = 0;
    while (true) {
      const item = await reader.read();
      if (item.done) return true;
      size += item.value.byteLength;
      if (size > limit) {
        try { await reader.cancel(); } catch {}
        return false;
      }
    }
  };
  if (!UUID.test(expected.organizationUuid) || !UUID.test(expected.conversationUuid)
      || !UUID.test(expected.artifactUuid) || !UUID.test(expected.versionUuid)
      || !UUID.test(expected.messageUuid) || !UUID.test(expected.publishedUuid)) {
    return {ok:false, state:'expected_shape'};
  }
  if (apiHeaders === null) return {ok:false, state:'preflight_headers'};

  let catalog = null;
  let limit = 30;
  while (true) {
    const response = await fetch(
      `/api/organizations/${expected.organizationUuid}/user_artifacts?limit=${limit}`
        + '&offset=0&include_latest_published_artifact_uuid=true',
      {headers:apiHeaders, credentials:'same-origin', cache:'no-store', redirect:'error',
        signal:AbortSignal.timeout(20000)}
    );
    let payload = null;
    try { payload = await response.json(); } catch {}
    const list = payload?.artifacts;
    if (!response.ok || !Array.isArray(list) || list.length > limit) {
      return {ok:false, state:'catalog_fetch', status:response.status};
    }
    const matches = list.filter(item => item?.uuid === expected.artifactUuid);
    if (matches.length > 1) return {ok:false, state:'catalog_ambiguous'};
    if (matches.length === 1) { catalog = matches[0]; break; }
    if (list.length < limit || limit === 10000) {
      return {ok:false, state:'catalog_missing'};
    }
    limit = Math.min(10000, limit + 30);
  }
  if (catalog.latest_artifact_version_uuid !== expected.versionUuid
      || catalog.latest_published_artifact_uuid !== expected.publishedUuid
      || catalog.chat_conversation_uuid !== expected.conversationUuid
      || catalog.artifact_identifier !== expected.artifactIdentifier
      || catalog.artifact_type !== expected.artifactType
      || catalog.code_language !== expected.codeLanguage
      || catalog.title !== expected.title) {
    return {ok:false, state:'catalog_binding'};
  }

  const activeResponse = await fetch(
    `/api/organizations/${expected.organizationUuid}/published_artifacts`
      + '?include_deleted_artifacts=false',
    {headers:apiHeaders, credentials:'same-origin', cache:'no-store', redirect:'error',
      signal:AbortSignal.timeout(20000)}
  );
  let active = null;
  try { active = await activeResponse.json(); } catch {}
  if (!activeResponse.ok || !Array.isArray(active)) {
    return {ok:false, state:'active_fetch', status:activeResponse.status};
  }
  const publicMatches = active.filter(
    item => item?.published_artifact_uuid === expected.publishedUuid
  );
  if (publicMatches.length !== 1) {
    return {ok:false, state:'active_match', count:publicMatches.length};
  }
  const publicRow = publicMatches[0];
  if (!own(publicRow, 'published_artifact_uuid')
      || !own(publicRow, 'deleted') || publicRow.deleted !== false
      || !own(publicRow, 'created_at') || !safeText(publicRow.created_at)
      || publicRow.artifact_identifier !== expected.artifactIdentifier
      || publicRow.artifact_type !== expected.artifactType
      || publicRow.chat_conversation_uuid !== expected.conversationUuid
      || publicRow.code_language !== expected.codeLanguage
      || publicRow.message_uuid !== expected.messageUuid
      || publicRow.title !== expected.title
      || !(publicRow.artifact_version_uuid === null
        || publicRow.artifact_version_uuid === expected.versionUuid)) {
    return {ok:false, state:'active_binding'};
  }

  const versionResponse = await fetch(
    `/api/organizations/${expected.organizationUuid}/artifacts/`
      + `${expected.conversationUuid}/versions`,
    {headers:apiHeaders, credentials:'same-origin', cache:'no-store', redirect:'error',
      signal:AbortSignal.timeout(20000)}
  );
  let versionPayload = null;
  try { versionPayload = await versionResponse.json(); } catch {}
  const versions = versionPayload?.artifact_versions;
  if (!versionResponse.ok || !Array.isArray(versions)) {
    return {ok:false, state:'versions_fetch', status:versionResponse.status};
  }
  const versionMatches = versions.filter(item => item?.uuid === expected.versionUuid);
  if (versionMatches.length !== 1) {
    return {ok:false, state:'version_match', count:versionMatches.length};
  }
  const version = versionMatches[0];
  if (version.artifact_uuid !== expected.artifactUuid
      || version.message_uuid !== expected.messageUuid
      || version.result_state !== expected.source
      || version.artifact_type !== expected.artifactType
      || version.code_language !== expected.codeLanguage
      || version.title !== expected.title
      || version.published_artifact_uuid !== expected.publishedUuid
      || version.published_artifact_deleted_at !== null) {
    return {ok:false, state:'version_binding'};
  }

  const shellResponse = await fetch(
    `https://claude.ai/public/artifacts/${expected.publishedUuid}`,
    {credentials:'omit', cache:'no-store', redirect:'error', referrerPolicy:'no-referrer',
      signal:AbortSignal.timeout(20000)}
  );
  const contentType = (shellResponse.headers.get('content-type') || '').toLowerCase();
  if (shellResponse.status !== 200 || !/^text\/html(?:\s*;|$)/i.test(contentType)
      || !(await boundedBody(shellResponse))) {
    return {ok:false, state:'public_shell', status:shellResponse.status};
  }
  return {ok:true};
})()
"""
                % json.dumps(
                    {
                        "organizationUuid": binding.organization_uuid,
                        "conversationUuid": binding.conversation_uuid,
                        "artifactUuid": binding.artifact_uuid,
                        "versionUuid": binding.version_uuid,
                        "messageUuid": binding.message_uuid,
                        "publishedUuid": published_uuid,
                        "artifactIdentifier": binding.artifact_identifier,
                        "artifactType": binding.artifact_type,
                        "codeLanguage": binding.code_language,
                        "title": binding.title,
                        "source": source,
                    }
                )
            )
            if isinstance(value, dict):
                last_state = str(value.get("state", "waiting"))
                if value.get("ok") is True:
                    return
            time.sleep(0.5)
        raise FrameError(
            "the public link could not be bound to the exact Artifact version "
            f"(last state: {last_state})"
        )

    def _publish_direct(
        self,
        session: CdpSession,
        binding: ChatArtifactBinding,
        source: str,
        initial_identity_digest: str,
        on_published_uuid: Callable[[ChatArtifactBinding, str], None] | None = None,
    ) -> tuple[str, str]:
        """Publish one exact private version without opening its executable preview."""

        if (
            self.expected_email_sha256 is None
            or self.organization_uuid is None
            or initial_identity_digest != self.expected_email_sha256
            or binding.organization_uuid != self.organization_uuid
        ):
            raise FrameError("direct publication lacked an exact identity binding")
        expected = {
            "digest": self.expected_email_sha256,
            "organizationUuid": binding.organization_uuid,
            "conversationUuid": binding.conversation_uuid,
            "artifactUuid": binding.artifact_uuid,
            "versionUuid": binding.version_uuid,
            "messageUuid": binding.message_uuid,
            "artifactIdentifier": binding.artifact_identifier,
            "artifactType": binding.artifact_type,
            "codeLanguage": binding.code_language,
            "title": binding.title,
            "source": source,
            "chatUrl": binding.chat_url,
        }
        identifier_text = (
            f"organization={binding.organization_uuid}, "
            f"artifact={binding.artifact_uuid}, version={binding.version_uuid}, "
            f"message={binding.message_uuid}, conversation={binding.conversation_uuid}"
        )
        value = session.evaluate(
            r"""
(async EXPECTED => {
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
  const safeText = (value, allowEmpty=false) => typeof value === 'string'
    && value.length <= 1000 && (allowEmpty || value.length > 0)
    && !/[\x00-\x1f\x7f]/.test(value);
  const readCookie = name => {
    let text;
    try { text = document.cookie; } catch { return null; }
    const prefix = name + '=';
    const part = text.split(';').map(value => value.trim())
      .find(value => value.startsWith(prefix));
    if (!part) return null;
    try { return decodeURIComponent(part.slice(prefix.length)); } catch { return null; }
  };
  const printable = value => typeof value === 'string'
    ? value.replace(/[^\x20-\x7e]/g, '').trim() : '';
  const stripOuterQuotes = value => typeof value === 'string'
    && value.length >= 2 && value[0] === '"' && value[value.length - 1] === '"'
    ? value.slice(1, -1) : value;
  const anonymousId = stripOuterQuotes(readCookie('ajs_anonymous_id'));
  const dataset = document.documentElement?.dataset || {};
  const deviceId = readCookie('anthropic-device-id');
  const apiHeaders = typeof anonymousId === 'string'
    && /^[A-Za-z0-9_.-]{1,128}$/.test(anonymousId) ? {
      'Content-Type':'application/json',
      'anthropic-anonymous-id':anonymousId,
      'anthropic-device-id':deviceId === null ? 'unknown' : (printable(deviceId) || 'invalid'),
      'anthropic-client-platform':'web_claude_ai',
      'anthropic-client-sha':dataset.gitHash ?? 'unknown',
      'anthropic-client-version':dataset.version ?? 'unknown',
      'anthropic-client-build':dataset.buildTimestamp ?? 'unknown',
    } : null;
  const activityRaw = readCookie('activitySessionId');
  if (apiHeaders && activityRaw) {
    apiHeaders['x-activity-session-id'] = printable(activityRaw) || 'invalid';
  }
  const boundedText = async (response, limit=2000000) => {
    const reader = response.body?.getReader();
    if (!reader) return null;
    const decoder = new TextDecoder();
    let size = 0;
    let text = '';
    while (true) {
      let item;
      try { item = await reader.read(); } catch { return null; }
      if (item.done) {
        try { return text + decoder.decode(); } catch { return null; }
      }
      size += item.value.byteLength;
      if (size > limit) {
        try { await reader.cancel(); } catch {}
        return null;
      }
      try { text += decoder.decode(item.value, {stream:true}); } catch { return null; }
    }
  };
  const apiJson = async (path, init={}) => {
    let response;
    try {
      response = await fetch(path, {
        ...init,
        headers:{...apiHeaders, ...(init.headers || {})},
        credentials:'same-origin', cache:'no-store', redirect:'error',
        signal:AbortSignal.timeout(init.method && init.method !== 'GET' ? 30000 : 20000)
      });
    } catch { return {kind:'network'}; }
    const text = await boundedText(response);
    if (text === null) return {kind:'malformed', status:response.status};
    let body = null;
    try { body = text === '' ? null : JSON.parse(text); } catch {
      return {kind:'malformed', status:response.status};
    }
    return response.ok
      ? {kind:'ok', status:response.status, value:body}
      : {kind:'http', status:response.status, value:body};
  };
  const identity = async () => {
    const result = await apiJson('/api/account');
    if (result.kind !== 'ok') return false;
    const email = typeof result.value?.email_address === 'string'
      ? result.value.email_address.toLowerCase() : '';
    const bytes = new Uint8Array(await crypto.subtle.digest(
      'SHA-256', new TextEncoder().encode(email)
    ));
    const digest = [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
    return digest === EXPECTED.digest && Array.isArray(result.value?.memberships)
      && result.value.memberships.some(
        item => item?.organization?.uuid === EXPECTED.organizationUuid
      );
  };
  const resolveCatalog = async () => {
    let limit = 30;
    while (true) {
      const result = await apiJson(
        `/api/organizations/${EXPECTED.organizationUuid}/user_artifacts?limit=${limit}`
          + '&offset=0&include_latest_published_artifact_uuid=true'
      );
      const list = result.value?.artifacts;
      if (result.kind !== 'ok' || !Array.isArray(list) || list.length > limit) {
        return null;
      }
      const matches = list.filter(item => item?.uuid === EXPECTED.artifactUuid);
      if (matches.length > 1) return null;
      if (matches.length === 1) return matches[0];
      if (list.length < limit || limit === 10000) return null;
      limit = Math.min(10000, limit + 30);
    }
  };
  const resolveVersion = async () => {
    const result = await apiJson(
      `/api/organizations/${EXPECTED.organizationUuid}/artifacts/`
        + `${EXPECTED.conversationUuid}/versions`
    );
    const list = result.value?.artifact_versions;
    if (result.kind !== 'ok' || !Array.isArray(list)) return null;
    const matches = list.filter(item => item?.uuid === EXPECTED.versionUuid);
    return matches.length === 1 ? matches[0] : null;
  };
  if (location.href !== EXPECTED.chatUrl
      || EXPECTED.chatUrl !== `https://claude.ai/chat/${EXPECTED.conversationUuid}`
      || !UUID.test(EXPECTED.organizationUuid)
      || !UUID.test(EXPECTED.conversationUuid)
      || !UUID.test(EXPECTED.artifactUuid) || !UUID.test(EXPECTED.versionUuid)
      || !UUID.test(EXPECTED.messageUuid)) {
    return {stage:'preflight_binding', mutationAttempted:false};
  }
  if (apiHeaders === null) {
    return {stage:'preflight_headers', mutationAttempted:false};
  }
  if (!(await identity())) return {stage:'preflight_identity', mutationAttempted:false};
  const catalog = await resolveCatalog();
  const version = await resolveVersion();
  const visibility = await apiJson(
    `/api/organizations/${EXPECTED.organizationUuid}/artifact-versions/`
      + `${EXPECTED.versionUuid}/visibility`
  );
  if (!catalog || !version
      || visibility.kind !== 'ok' || visibility.value?.visibility !== 'private'
      || catalog.latest_artifact_version_uuid !== EXPECTED.versionUuid
      || catalog.latest_published_artifact_uuid !== null
      || catalog.chat_conversation_uuid !== EXPECTED.conversationUuid
      || catalog.artifact_identifier !== EXPECTED.artifactIdentifier
      || catalog.artifact_type !== EXPECTED.artifactType
      || catalog.code_language !== EXPECTED.codeLanguage
      || catalog.title !== EXPECTED.title
      || !safeText(catalog.artifact_identifier) || !safeText(catalog.artifact_type)
      || !(catalog.code_language === null || safeText(catalog.code_language, true))
      || !safeText(catalog.title)
      || version.artifact_uuid !== EXPECTED.artifactUuid
      || version.message_uuid !== EXPECTED.messageUuid
      || version.result_state !== EXPECTED.source
      || version.artifact_type !== EXPECTED.artifactType
      || version.code_language !== EXPECTED.codeLanguage
      || version.title !== EXPECTED.title
      || !own(version, 'published_artifact_uuid')
      || version.published_artifact_uuid !== null
      || !own(version, 'published_artifact_deleted_at')
      || version.published_artifact_deleted_at !== null) {
    return {stage:'preflight_provenance', mutationAttempted:false};
  }
  if (!(await identity())) return {stage:'pre_publish_identity', mutationAttempted:false};
  const publication = await apiJson(
    `/api/organizations/${EXPECTED.organizationUuid}/publish_artifact`,
    {method:'POST', body:JSON.stringify({
      title:catalog.title,
      artifact_type:catalog.artifact_type,
      code_language:catalog.code_language,
      message_uuid:version.message_uuid,
      conversation_uuid:EXPECTED.conversationUuid,
      artifact_identifier:catalog.artifact_identifier,
      content:version.result_state,
      artifact_version_uuid:version.uuid,
    })}
  );
  if (publication.kind !== 'ok' || publication.status !== 200) {
    return {stage:'publish_' + publication.kind, status:publication.status,
      mutationAttempted:true};
  }
  const publishedUuid = publication.value?.published_artifact_uuid;
  if (!UUID.test(publishedUuid || '')) {
    return {stage:'publish_shape', mutationAttempted:true};
  }
  return {stage:'published', mutationAttempted:true, publishedUuid};
})(%s)
"""
            % json.dumps(expected)
        )
        if not isinstance(value, dict) or value.get("stage") != "published":
            if isinstance(value, dict) and value.get("mutationAttempted") is False:
                raise FrameError(
                    "direct publication preflight failed before provider mutation "
                    f"(stage: {value.get('stage', 'unknown')}); "
                    f"cleanup identifiers: {identifier_text}"
                )
            raise FrameError(
                "public mapping remote state is unknown after one non-retried "
                f"operation (stage: {value.get('stage', 'invalid_result') if isinstance(value, dict) else 'invalid_result'}); "
                f"cleanup identifiers: {identifier_text}"
            )
        published_uuid = value.get("publishedUuid")
        if not isinstance(published_uuid, str) or not re.fullmatch(UUID, published_uuid):
            raise FrameError(
                "public mapping returned an invalid identifier after one non-retried "
                f"operation; cleanup identifiers: {identifier_text}"
            )
        if on_published_uuid is not None:
            try:
                on_published_uuid(binding, published_uuid)
            except Exception:
                raise FrameError(
                    "public mapping was created but its durable binding callback failed; "
                    f"cleanup identifiers: organization={binding.organization_uuid}, "
                    f"artifact={binding.artifact_uuid}, "
                    f"version={binding.version_uuid}, message={binding.message_uuid}, "
                    f"conversation={binding.conversation_uuid}, published={published_uuid}"
                ) from None
        try:
            self._verify_public_mapping(session, binding, source, published_uuid)
            if self._require_identity(session) != initial_identity_digest:
                raise FrameError("the Claude account changed after publication")
            self._require_chat_location(session, binding.chat_url)
        except FrameError as error:
            raise FrameError(
                f"{error}; public mapping state is unknown; cleanup identifiers: "
                f"organization={binding.organization_uuid}, "
                f"artifact={binding.artifact_uuid}, version={binding.version_uuid}, "
                f"message={binding.message_uuid}, conversation={binding.conversation_uuid}, "
                f"published={published_uuid}"
            ) from None
        return validate_public_url(
            f"{CHAT_ORIGIN}/public/artifacts/{published_uuid}", published_uuid
        ), published_uuid

    def publish(
        self,
        source: str,
        title: str,
        *,
        public: bool = False,
        acknowledge_preview_execution: bool = False,
        on_conversation_binding: Callable[[ChatConversationBinding], None] | None = None,
        on_file_binding: Callable[[ChatFileBinding], None] | None = None,
        on_conversion_intent: Callable[[], None] | None = None,
        on_binding: Callable[[ChatArtifactBinding], None] | None = None,
        on_published_uuid: Callable[[ChatArtifactBinding, str], None] | None = None,
    ) -> ChatPublishResult:
        if type(public) is not bool:
            raise FrameError("conversation public mode must be a boolean")
        if acknowledge_preview_execution:
            raise FrameError(
                "preview execution acknowledgement is obsolete because the direct "
                "conversation publisher never opens an Artifact preview"
            )
        if on_file_binding is not None and not callable(on_file_binding):
            raise FrameError("on_file_binding must be callable")
        if on_conversion_intent is not None and not callable(on_conversion_intent):
            raise FrameError("on_conversion_intent must be callable")
        if on_conversation_binding is not None and not callable(
            on_conversation_binding
        ):
            raise FrameError("on_conversation_binding must be callable")
        if on_binding is not None and not callable(on_binding):
            raise FrameError("on_binding must be callable")
        if on_published_uuid is not None and not callable(on_published_uuid):
            raise FrameError("on_published_uuid must be callable")
        if self.expected_email_sha256 is None or self.organization_uuid is None:
            raise FrameError(
                "live conversation publishing requires exact account and organization binding"
            )
        output_path = generated_output_path(source, title)
        prompt = build_prompt(source, title, output_path)
        target_id, session = self._create_chat_target()
        submission_attempted = False
        outcome: ChatPublishResult | None = None
        failure: BaseException | None = None
        try:
            initial_identity_digest = self._require_identity(session)
            self._wait_for_editor(session)
            if self._require_identity(session) != initial_identity_digest:
                raise FrameError("the Claude account changed before prompt submission")
            submission_attempted = True
            self._send_prompt(session, prompt)
            file_binding = self._wait_for_exact_file(
                session,
                source,
                prompt,
                output_path,
                on_conversation_binding=on_conversation_binding,
            )
            if on_file_binding is not None:
                try:
                    on_file_binding(file_binding)
                except Exception:
                    raise FrameError(
                        "the generated-file requests were stably bound but their "
                        "durable callback failed; cleanup identifiers: "
                        f"organization={file_binding.organization_uuid}, "
                        f"conversation={file_binding.conversation_uuid}"
                    ) from None
            if on_conversion_intent is not None:
                try:
                    on_conversion_intent()
                except Exception:
                    raise FrameError(
                        "the generated-file requests were bound but conversion intent "
                        "could not be recorded durably; no conversion was attempted; "
                        "cleanup identifiers: "
                        f"organization={file_binding.organization_uuid}, "
                        f"conversation={file_binding.conversation_uuid}"
                    ) from None
            binding = self._convert_file_to_artifact(
                session,
                file_binding,
                source,
                prompt,
                on_binding=on_binding,
                on_published_uuid=on_published_uuid,
            )
            if on_binding is not None:
                try:
                    on_binding(binding)
                except Exception:
                    raise FrameError(
                        "the private Artifact was verified but its durable binding "
                        "callback failed; cleanup identifiers: "
                        f"organization={binding.organization_uuid}, "
                        f"artifact={binding.artifact_uuid}, version={binding.version_uuid}, "
                        f"message={binding.message_uuid}, "
                        f"conversation={binding.conversation_uuid}"
                    ) from None
            published_uuid = None
            if public:
                url, published_uuid = self._publish_direct(
                    session,
                    binding,
                    source,
                    initial_identity_digest,
                    on_published_uuid=on_published_uuid,
                )
            else:
                url = binding.chat_url
            outcome = ChatPublishResult(
                url=url,
                chat_url=binding.chat_url,
                artifact_uuid=binding.artifact_uuid,
                version_uuid=binding.version_uuid,
                public=public,
                source_sha256=sha256_text(source),
                published_uuid=published_uuid,
                organization_uuid=binding.organization_uuid,
                conversation_uuid=binding.conversation_uuid,
                message_uuid=binding.message_uuid,
                artifact_identifier=binding.artifact_identifier,
                artifact_type=binding.artifact_type,
                code_language=binding.code_language,
                title=binding.title,
                output_path=output_path,
                prompt_sha256=sha256_text(prompt),
            )
        except BaseException as error:
            if isinstance(error, FrameError) and submission_attempted:
                failure = FrameError(
                    f"{error}; the exact new conversation may already contain a "
                    "generated file or converted Artifact"
                )
            else:
                failure = error
        finally:
            try:
                session.close()
            except Exception:
                pass
            close_error = None
            try:
                self._close_target(target_id)
            except FrameError as error:
                close_error = error
            if close_error is not None:
                suffix = "; cleanup of the exact controlled Claude tab was not confirmed"
                if isinstance(failure, FrameError):
                    failure = FrameError(f"{failure}{suffix}")
                elif failure is None:
                    identifiers = ""
                    if outcome is not None:
                        identifiers = (
                            "; cleanup identifiers: "
                            f"organization={outcome.organization_uuid}, "
                            f"artifact={outcome.artifact_uuid}, "
                            f"version={outcome.version_uuid}, "
                            f"message={outcome.message_uuid}, "
                            f"conversation={outcome.conversation_uuid}"
                        )
                        if outcome.published_uuid:
                            identifiers += f", published={outcome.published_uuid}"
                    failure = FrameError(f"{close_error}{identifiers}")
        if failure is not None:
            raise failure
        if outcome is None:
            raise FrameError("conversation publisher returned no result")
        return outcome

    def _binding_from_result(
        self, result: ChatPublishResult, source: str
    ) -> ChatArtifactBinding:
        """Validate a durable result before any lifecycle browser is opened."""

        if not isinstance(result, ChatPublishResult):
            raise FrameError("chat lifecycle operation requires a ChatPublishResult")
        if not isinstance(source, str) or not source or len(source) > MAX_CHAT_SOURCE_CHARS:
            raise FrameError("chat lifecycle source is invalid")
        if result.source_sha256 != sha256_text(source):
            raise FrameError("chat lifecycle source did not match the durable source digest")
        if self.expected_email_sha256 is None or self.organization_uuid is None:
            raise FrameError("chat lifecycle requires exact account and organization binding")
        if result.organization_uuid != self.organization_uuid:
            raise FrameError("chat lifecycle result belongs to a different organization")
        identifiers = (
            result.organization_uuid,
            result.conversation_uuid,
            result.artifact_uuid,
            result.version_uuid,
            result.message_uuid,
        )
        if not all(isinstance(value, str) and re.fullmatch(UUID, value) for value in identifiers):
            raise FrameError("chat lifecycle result contains an invalid provider identifier")
        parts = urlsplit(result.chat_url) if isinstance(result.chat_url, str) else None
        if not (
            parts
            and parts.scheme == "https"
            and parts.hostname == "claude.ai"
            and parts.port is None
            and parts.username is None
            and parts.password is None
            and parts.path == f"/chat/{result.conversation_uuid}"
            and not parts.query
            and not parts.fragment
        ):
            raise FrameError("chat lifecycle result contains an invalid conversation URL")

        def safe_text(value: Any, *, allow_empty: bool = False) -> bool:
            return (
                isinstance(value, str)
                and len(value) <= 1000
                and (allow_empty or bool(value))
                and re.search(r"[\x00-\x1f\x7f]", value) is None
            )

        if not safe_text(result.artifact_identifier):
            raise FrameError("chat lifecycle result contains an invalid Artifact identifier")
        if not safe_text(result.artifact_type):
            raise FrameError("chat lifecycle result contains an invalid Artifact type")
        if result.code_language is not None and not safe_text(
            result.code_language, allow_empty=True
        ):
            raise FrameError("chat lifecycle result contains an invalid code language")
        if not safe_text(result.title):
            raise FrameError("chat lifecycle result contains an invalid Artifact title")
        if type(result.public) is not bool:
            raise FrameError("chat lifecycle result contains an invalid public flag")
        if type(result.published_deleted) is not bool:
            raise FrameError("chat lifecycle result contains an invalid tombstone flag")
        if result.public:
            if not isinstance(result.published_uuid, str) or not re.fullmatch(
                UUID, result.published_uuid
            ):
                raise FrameError("public chat lifecycle result has no exact public UUID")
            if result.published_deleted:
                raise FrameError("active public lifecycle result cannot be tombstoned")
            validate_public_url(result.url, result.published_uuid)
        elif result.published_uuid is not None:
            if (
                not result.published_deleted
                or not isinstance(result.published_uuid, str)
                or not re.fullmatch(UUID, result.published_uuid)
            ):
                raise FrameError("private chat lifecycle result contains a live mapping")
            if result.url != result.chat_url:
                raise FrameError("tombstoned chat lifecycle result has a public URL")
        elif result.published_deleted or result.url != result.chat_url:
            raise FrameError("private chat lifecycle result contains invalid public state")
        return ChatArtifactBinding(
            chat_url=result.chat_url,
            organization_uuid=result.organization_uuid,
            conversation_uuid=result.conversation_uuid,
            artifact_uuid=result.artifact_uuid,
            version_uuid=result.version_uuid,
            message_uuid=result.message_uuid,
            artifact_identifier=result.artifact_identifier,
            artifact_type=result.artifact_type,
            code_language=result.code_language,
            title=result.title,
        )

    @staticmethod
    def _lifecycle_identifiers(
        binding: ChatArtifactBinding, published_uuid: str | None
    ) -> str:
        values = (
            f"organization={binding.organization_uuid}",
            f"conversation={binding.conversation_uuid}",
            f"artifact={binding.artifact_uuid}",
            f"version={binding.version_uuid}",
            f"message={binding.message_uuid}",
        )
        suffix = ", ".join(values)
        if published_uuid is not None:
            suffix += f", published={published_uuid}"
        return suffix

    @staticmethod
    def _require_lifecycle_completion(
        value: Any,
        *,
        stage: str,
        binding: ChatArtifactBinding,
        published_uuid: str | None,
    ) -> bool:
        """Validate the complete browser result before advancing a receipt."""

        expected = {
            "stage": stage,
            "mutationAttempted": None,
            "artifactUuid": binding.artifact_uuid,
            "versionUuid": binding.version_uuid,
            "messageUuid": binding.message_uuid,
            "conversationUuid": binding.conversation_uuid,
        }
        if published_uuid is not None:
            expected["publishedUuid"] = published_uuid
        if not isinstance(value, dict):
            return False
        allowed = set(expected)
        if value.get("reconciled") is True:
            allowed.add("reconciled")
        if set(value) != allowed or value.get("stage") != stage:
            return False
        if type(value.get("mutationAttempted")) is not bool:
            return False
        if value["mutationAttempted"] is False and value.get("reconciled") is not True:
            return False
        if value["mutationAttempted"] is True and "reconciled" in value:
            return False
        return all(
            value.get(key) == expected_value
            for key, expected_value in expected.items()
            if key not in {"stage", "mutationAttempted"}
        )

    def _run_lifecycle_transaction(
        self,
        binding: ChatArtifactBinding | ChatPreconversionBinding,
        source: str,
        *,
        action: str,
        published_uuid: str | None,
        output_path: str | None = None,
        prompt_sha256: str | None = None,
        expected_prompt: str | None = None,
        allow_mutation: bool = False,
        on_result: Callable[[Any], None] | None = None,
    ) -> tuple[Any, bool]:
        """Run one bounded lifecycle transaction and close its exact auth tab."""

        target_id = None
        session = None
        value: Any = None
        cleanup_failed = False
        try:
            target_id, session = self._create_chat_target()
            try:
                value = self._lifecycle_transaction(
                    session,
                    binding,
                    source,
                    action=action,
                    published_uuid=published_uuid,
                    output_path=output_path,
                    prompt_sha256=prompt_sha256,
                    expected_prompt=expected_prompt,
                    allow_mutation=allow_mutation,
                )
            except FrameError:
                value = {
                    "stage": "transport_unknown",
                    "mutationAttempted": action
                    not in {"reconcile_public", "reconcile_conversion_pending"},
                }
            if on_result is not None:
                on_result(value)
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
                    cleanup_failed = True
        return value, cleanup_failed

    def _lifecycle_transaction(
        self,
        session: CdpSession,
        binding: ChatArtifactBinding | ChatPreconversionBinding,
        source: str,
        *,
        action: str,
        published_uuid: str | None,
        output_path: str | None,
        prompt_sha256: str | None,
        expected_prompt: str | None = None,
        allow_mutation: bool = False,
    ) -> Any:
        if action not in {
            "reconcile_public",
            "unpublish",
            "delete_conversation",
            "delete_preconversion_conversation",
            "reconcile_conversion_pending",
            "complete_conversion_privacy",
        }:
            raise FrameError("unsupported chat lifecycle action")
        if type(allow_mutation) is not bool:
            raise FrameError("lifecycle mutation intent must be a boolean")
        expected = {
            "digest": self.expected_email_sha256,
            "organizationUuid": binding.organization_uuid,
            "conversationUuid": binding.conversation_uuid,
            "artifactUuid": getattr(binding, "artifact_uuid", None),
            "versionUuid": getattr(binding, "version_uuid", None),
            "messageUuid": getattr(binding, "message_uuid", None),
            "artifactIdentifier": getattr(binding, "artifact_identifier", None),
            "artifactType": getattr(binding, "artifact_type", None),
            "codeLanguage": getattr(binding, "code_language", None),
            "title": getattr(binding, "title", None),
            "publishedUuid": published_uuid,
            "chatUrl": binding.chat_url,
            "outputPath": output_path,
            "promptSha256": prompt_sha256,
            "sourceSha256": getattr(binding, "source_sha256", None),
            "preconversionStage": getattr(binding, "receipt_stage", None),
            "requestTitle": getattr(binding, "request_title", None),
            "expectedPrompt": expected_prompt,
            "allowMutation": allow_mutation,
        }
        return session.evaluate(
            r"""
(async (EXPECTED, SOURCE, ACTION) => {
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
  const safeText = (value, allowEmpty=false) => typeof value === 'string'
    && value.length <= 1000 && (allowEmpty || value.length > 0)
    && !/[\x00-\x1f\x7f]/.test(value);
  const keysAre = (value, keys) => value && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).sort().join('\x00') === [...keys].sort().join('\x00');
  const readCookie = name => {
    let text;
    try { text = document.cookie; } catch { return null; }
    const prefix = name + '=';
    const part = text.split(';').map(value => value.trim())
      .find(value => value.startsWith(prefix));
    if (!part) return null;
    try { return decodeURIComponent(part.slice(prefix.length)); } catch { return null; }
  };
  const printable = value => typeof value === 'string'
    ? value.replace(/[^\x20-\x7e]/g, '').trim() : '';
  const stripOuterQuotes = value => typeof value === 'string'
    && value.length >= 2 && value[0] === '"' && value[value.length - 1] === '"'
    ? value.slice(1, -1) : value;
  const anonymousId = stripOuterQuotes(readCookie('ajs_anonymous_id'));
  const dataset = document.documentElement?.dataset || {};
  const deviceId = readCookie('anthropic-device-id');
  const apiHeaders = typeof anonymousId === 'string'
    && /^[A-Za-z0-9_.-]{1,128}$/.test(anonymousId) ? {
      'Content-Type':'application/json',
      'anthropic-anonymous-id':anonymousId,
      'anthropic-device-id':deviceId === null ? 'unknown' : (printable(deviceId) || 'invalid'),
      'anthropic-client-platform':'web_claude_ai',
      'anthropic-client-sha':dataset.gitHash ?? 'unknown',
      'anthropic-client-version':dataset.version ?? 'unknown',
      'anthropic-client-build':dataset.buildTimestamp ?? 'unknown',
    } : null;
  const activityRaw = readCookie('activitySessionId');
  if (apiHeaders && activityRaw) {
    apiHeaders['x-activity-session-id'] = printable(activityRaw) || 'invalid';
  }
  const boundedText = async (response, limit=2000000) => {
    const reader = response.body?.getReader();
    if (!reader) return null;
    const decoder = new TextDecoder();
    let size = 0;
    let text = '';
    while (true) {
      let item;
      try { item = await reader.read(); } catch { return null; }
      if (item.done) {
        try { return text + decoder.decode(); } catch { return null; }
      }
      size += item.value.byteLength;
      if (size > limit) {
        try { await reader.cancel(); } catch {}
        return null;
      }
      try { text += decoder.decode(item.value, {stream:true}); } catch { return null; }
    }
  };
  const apiJson = async (path, init={}) => {
    let response;
    try {
      response = await fetch(path, {
        ...init, headers:{...apiHeaders, ...(init.headers || {})},
        credentials:'same-origin', cache:'no-store', redirect:'error',
        signal:AbortSignal.timeout(init.method && init.method !== 'GET' ? 30000 : 20000)
      });
    } catch { return {kind:'network'}; }
    const text = await boundedText(response);
    if (text === null) return {kind:'malformed', status:response.status};
    let body = null;
    try { body = text === '' ? null : JSON.parse(text); } catch {
      return {kind:'malformed', status:response.status};
    }
    return response.ok
      ? {kind:'ok', status:response.status, value:body}
      : {kind:'http', status:response.status, value:body};
  };
  const apiStatus = async (path, init={}) => {
    let response;
    try {
      response = await fetch(path, {
        ...init, headers:{...apiHeaders, ...(init.headers || {})},
        credentials:'same-origin', cache:'no-store', redirect:'error',
        signal:AbortSignal.timeout(init.method && init.method !== 'GET' ? 30000 : 20000)
      });
    } catch { return {kind:'network'}; }
    return response.ok
      ? {kind:'ok', status:response.status}
      : {kind:'http', status:response.status};
  };
  const identity = async () => {
    const result = await apiJson('/api/account');
    if (result.kind !== 'ok') return false;
    const email = typeof result.value?.email_address === 'string'
      ? result.value.email_address.toLowerCase() : '';
    const bytes = new Uint8Array(await crypto.subtle.digest(
      'SHA-256', new TextEncoder().encode(email)
    ));
    const digest = [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
    return digest === EXPECTED.digest && Array.isArray(result.value?.memberships)
      && result.value.memberships.some(
        item => item?.organization?.uuid === EXPECTED.organizationUuid
      );
  };
  const resolveCatalog = async () => {
    let limit = 30;
    while (true) {
      const result = await apiJson(
        `/api/organizations/${EXPECTED.organizationUuid}/user_artifacts?limit=${limit}`
          + '&offset=0&include_latest_published_artifact_uuid=true'
      );
      const list = result.value?.artifacts;
      if (result.kind !== 'ok' || result.status !== 200
          || !Array.isArray(list) || list.length > limit) return null;
      const matches = list.filter(item => item?.uuid === EXPECTED.artifactUuid);
      if (matches.length > 1) return null;
      if (matches.length === 1) return matches[0];
      if (list.length < limit || limit === 10000) return null;
      limit = Math.min(10000, limit + 30);
    }
  };
  const catalogAbsent = async () => {
    let limit = 30;
    while (true) {
      const result = await apiJson(
        `/api/organizations/${EXPECTED.organizationUuid}/user_artifacts?limit=${limit}`
          + '&offset=0&include_latest_published_artifact_uuid=true'
      );
      const list = result.value?.artifacts;
      if (result.kind !== 'ok' || result.status !== 200
          || !Array.isArray(list) || list.length > limit) return false;
      if (list.some(item => item?.uuid === EXPECTED.artifactUuid)) return false;
      if (list.length < limit) return true;
      if (limit === 10000) return false;
      limit = Math.min(10000, limit + 30);
    }
  };
  const conversationCatalogRows = async () => {
    const limit = 30;
    let offset = 0;
    const matches = [];
    while (offset < 10000) {
      const result = await apiJson(
        `/api/organizations/${EXPECTED.organizationUuid}/user_artifacts?limit=${limit}`
          + `&offset=${offset}&include_latest_published_artifact_uuid=true`
      );
      const list = result.value?.artifacts;
      if (result.kind !== 'ok' || result.status !== 200
          || !Array.isArray(list) || list.length > limit) return null;
      if (list.some(item => !item || typeof item !== 'object'
          || !own(item, 'chat_conversation_uuid')
          || !(item.chat_conversation_uuid === null
            || UUID.test(item.chat_conversation_uuid || '')))) return null;
      matches.push(...list.filter(item =>
        item.chat_conversation_uuid === EXPECTED.conversationUuid));
      if (matches.length > 1) return matches;
      if (list.length < limit) return matches;
      offset += list.length;
    }
    return null;
  };
  const conversationCatalogAbsent = async () => {
    const matches = await conversationCatalogRows();
    return Array.isArray(matches) && matches.length === 0;
  };
  const resolveVersion = async () => {
    const result = await apiJson(
      `/api/organizations/${EXPECTED.organizationUuid}/artifacts/`
        + `${EXPECTED.conversationUuid}/versions`
    );
    const list = result.value?.artifact_versions;
    if (result.kind !== 'ok' || result.status !== 200 || !Array.isArray(list)) {
      return {ok:false, result};
    }
    const matches = list.filter(item => item?.uuid === EXPECTED.versionUuid);
    return matches.length === 1
      ? {ok:true, row:matches[0]} : {ok:false, result:{kind:'shape'}};
  };
  const exactCore = (catalog, row) => catalog?.uuid === EXPECTED.artifactUuid
    && catalog.latest_artifact_version_uuid === EXPECTED.versionUuid
    && catalog.chat_conversation_uuid === EXPECTED.conversationUuid
    && catalog.artifact_identifier === EXPECTED.artifactIdentifier
    && catalog.artifact_type === EXPECTED.artifactType
    && catalog.code_language === EXPECTED.codeLanguage
    && catalog.title === EXPECTED.title
    && safeText(catalog.artifact_identifier) && safeText(catalog.artifact_type)
    && (catalog.code_language === null || safeText(catalog.code_language, true))
    && safeText(catalog.title)
    && row?.uuid === EXPECTED.versionUuid
    && row.artifact_uuid === EXPECTED.artifactUuid
    && row.message_uuid === EXPECTED.messageUuid
    && row.result_state === SOURCE
    && row.artifact_type === EXPECTED.artifactType
    && row.code_language === EXPECTED.codeLanguage
    && row.title === EXPECTED.title
    && own(row, 'published_artifact_uuid')
    && own(row, 'published_artifact_deleted_at');
  const listPublished = async includeDeleted => {
    const result = await apiJson(
      `/api/organizations/${EXPECTED.organizationUuid}/published_artifacts`
        + `?include_deleted_artifacts=${includeDeleted ? 'true' : 'false'}`
    );
    return result.kind === 'ok' && result.status === 200
      && Array.isArray(result.value) && result.value.length <= 10000
      && result.value.every(item => item && typeof item === 'object'
        && own(item, 'chat_conversation_uuid')
        && (item.chat_conversation_uuid === null
          || UUID.test(item.chat_conversation_uuid || '')))
      ? {ok:true, list:result.value} : {ok:false};
  };
  const exactPublished = (item, deleted) => own(item, 'published_artifact_uuid')
    && item.published_artifact_uuid === EXPECTED.publishedUuid
    && own(item, 'artifact_identifier')
    && item.artifact_identifier === EXPECTED.artifactIdentifier
    && own(item, 'artifact_type') && item.artifact_type === EXPECTED.artifactType
    && own(item, 'artifact_version_uuid')
    && (item.artifact_version_uuid === null
      || item.artifact_version_uuid === EXPECTED.versionUuid)
    && own(item, 'chat_conversation_uuid')
    && item.chat_conversation_uuid === EXPECTED.conversationUuid
    && own(item, 'code_language') && item.code_language === EXPECTED.codeLanguage
    && own(item, 'created_at') && safeText(item.created_at)
    && own(item, 'deleted') && item.deleted === deleted
    && own(item, 'message_uuid') && item.message_uuid === EXPECTED.messageUuid
    && own(item, 'title') && item.title === EXPECTED.title;
  const verifyPublished = async deleted => {
    const listed = await listPublished(deleted);
    if (!listed.ok) return false;
    const matches = listed.list.filter(
      item => item?.published_artifact_uuid === EXPECTED.publishedUuid
    );
    return matches.length === 1 && exactPublished(matches[0], deleted);
  };
  const activeZero = async () => {
    const listed = await listPublished(false);
    return listed.ok && listed.list.filter(
      item => item?.published_artifact_uuid === EXPECTED.publishedUuid
    ).length === 0;
  };
  const noActiveBinding = async () => {
    const listed = await listPublished(false);
    return listed.ok && listed.list.filter(item =>
      item?.chat_conversation_uuid === EXPECTED.conversationUuid
    ).length === 0;
  };
  const noPublicHistoryBinding = async () => {
    const listed = await listPublished(true);
    return listed.ok && listed.list.filter(item =>
      item?.chat_conversation_uuid === EXPECTED.conversationUuid
    ).length === 0;
  };
  const waitFor = async check => {
    const deadline = Date.now() + 45000;
    do {
      if (await check()) return true;
      if (Date.now() >= deadline) return false;
      await new Promise(resolve => setTimeout(resolve, 500));
    } while (true);
  };
  const deleteConversationOnce = async () => apiStatus(
    `/api/organizations/${EXPECTED.organizationUuid}/chat_conversations/`
      + EXPECTED.conversationUuid,
    {method:'DELETE', body:'{}'}
  );
  const sha256 = async text => {
    const bytes = new Uint8Array(await crypto.subtle.digest(
      'SHA-256', new TextEncoder().encode(text)
    ));
    return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
  };
%s
  const exactConversation = async () => {
    const result = await apiJson(
      `/api/organizations/${EXPECTED.organizationUuid}/chat_conversations/`
        + `${EXPECTED.conversationUuid}`
        + '?tree=True&rendering_mode=messages&render_all_tools=true&consistency=strong'
    );
    const payload = result.value;
    if (result.kind !== 'ok' || payload?.uuid !== EXPECTED.conversationUuid
        || !Array.isArray(payload?.chat_messages)) return false;
    const messages = payload.chat_messages;
    const humans = messages.map((message, index) => ({message, index})).filter(item =>
      ['human', 'user'].includes(item.message?.sender)
    );
    if (humans.length !== 1) return false;
    const humanText = exactHumanText(humans[0].message);
    if (humanText === null
        || await sha256(humanText) !== EXPECTED.promptSha256) return false;
    const tools = [];
    messages.forEach((message, messageIndex) => {
      if (message?.sender !== 'assistant' || !Array.isArray(message.content)) return;
      message.content.forEach((block, blockIndex) => {
        if (block?.type === 'tool_use') tools.push({block, messageIndex, blockIndex});
      });
    });
    if (tools.length !== 2 || tools[0].messageIndex <= humans[0].index
        || tools[0].block?.name !== 'create_file'
        || tools[1].block?.name !== 'present_files'
        || tools[0].messageIndex > tools[1].messageIndex
        || (tools[0].messageIndex === tools[1].messageIndex
          && tools[0].blockIndex >= tools[1].blockIndex)) return false;
    const create = tools[0].block.input;
    const present = tools[1].block.input;
    return keysAre(create, ['description', 'file_text', 'path'])
      && typeof create.description === 'string'
      && create.description.length >= 1 && create.description.length <= 1000
      && create.file_text === SOURCE
      && create.path === EXPECTED.outputPath
      && keysAre(present, ['filepaths']) && Array.isArray(present.filepaths)
      && present.filepaths.length === 1
      && present.filepaths[0] === EXPECTED.outputPath;
  };

  const exactPreconversionConversation = async payload => {
    if (payload?.uuid !== EXPECTED.conversationUuid
        || !Array.isArray(payload?.chat_messages)) return false;
    const messages = payload.chat_messages;
    const humans = messages.map((message, index) => ({message, index})).filter(item =>
      ['human', 'user'].includes(item.message?.sender)
    );
    if (humans.length !== 1) return false;
    if (Array.isArray(humans[0].message?.content)
        && humans[0].message.content.some(block => block?.type !== 'text')) return false;
    const humanText = exactHumanText(humans[0].message);
    if (humanText === null || humanText !== EXPECTED.expectedPrompt
        || await sha256(humanText) !== EXPECTED.promptSha256) return false;
    if (EXPECTED.preconversionStage === 'conversation_bound') return true;
    if (!['file_bound', 'conversion_pending'].includes(
      EXPECTED.preconversionStage
    )) return false;
    const tools = [];
    messages.forEach((message, messageIndex) => {
      if (message?.sender !== 'assistant' || !Array.isArray(message.content)) return;
      message.content.forEach((block, blockIndex) => {
        if (block?.type === 'tool_use') tools.push({block, messageIndex, blockIndex});
      });
    });
    if (tools.length !== 2 || tools[0].messageIndex <= humans[0].index
        || tools[0].block?.name !== 'create_file'
        || tools[1].block?.name !== 'present_files'
        || tools[0].messageIndex > tools[1].messageIndex
        || (tools[0].messageIndex === tools[1].messageIndex
          && tools[0].blockIndex >= tools[1].blockIndex)) return false;
    const create = tools[0].block.input;
    const present = tools[1].block.input;
    return keysAre(create, ['description', 'file_text', 'path'])
      && typeof create.description === 'string'
      && create.description.length >= 1 && create.description.length <= 1000
      && create.file_text === SOURCE
      && create.path === EXPECTED.outputPath
      && keysAre(present, ['filepaths']) && Array.isArray(present.filepaths)
      && present.filepaths.length === 1
      && present.filepaths[0] === EXPECTED.outputPath;
  };

  const preconversion = ACTION === 'delete_preconversion_conversation';
  const conversionRecovery = ACTION === 'reconcile_conversion_pending';
  const preartifact = preconversion || conversionRecovery;
  const ids = preartifact
    ? {conversationUuid:EXPECTED.conversationUuid}
    : {
        artifactUuid:EXPECTED.artifactUuid, versionUuid:EXPECTED.versionUuid,
        messageUuid:EXPECTED.messageUuid, conversationUuid:EXPECTED.conversationUuid,
        ...(EXPECTED.publishedUuid === null
          ? {} : {publishedUuid:EXPECTED.publishedUuid})
      };
  if (location.origin !== 'https://claude.ai'
      || location.pathname.replace(/\/+$/, '') !== '/new'
      || location.search !== '' || location.hash !== '' || !apiHeaders
      || !UUID.test(EXPECTED.organizationUuid) || !UUID.test(EXPECTED.conversationUuid)
      || (!preartifact && (!UUID.test(EXPECTED.artifactUuid)
        || !UUID.test(EXPECTED.versionUuid) || !UUID.test(EXPECTED.messageUuid)
        || !(EXPECTED.publishedUuid === null || UUID.test(EXPECTED.publishedUuid))))) {
    return {stage:'preflight_binding', mutationAttempted:false, ...ids};
  }
  if (!(await identity())) {
    return {stage:'preflight_identity', mutationAttempted:false, ...ids};
  }
  if (conversionRecovery) {
    if (EXPECTED.preconversionStage !== 'conversion_pending'
        || EXPECTED.chatUrl !== `https://claude.ai/chat/${EXPECTED.conversationUuid}`
        || typeof EXPECTED.expectedPrompt !== 'string'
        || EXPECTED.expectedPrompt.length === 0
        || EXPECTED.expectedPrompt.length > 110000
        || !safeText(EXPECTED.requestTitle)
        || !/^[0-9a-f]{64}$/.test(EXPECTED.promptSha256 || '')
        || !/^[0-9a-f]{64}$/.test(EXPECTED.sourceSha256 || '')
        || await sha256(EXPECTED.expectedPrompt) !== EXPECTED.promptSha256
        || await sha256(SOURCE) !== EXPECTED.sourceSha256
        || !/^\/mnt\/user-data\/outputs\/[A-Za-z0-9._\/-]+$/.test(
          EXPECTED.outputPath || ''
        )
        || EXPECTED.outputPath.includes('/../')
        || EXPECTED.outputPath.endsWith('/..')) {
      return {stage:'conversion_reconcile_shape', mutationAttempted:false, ...ids};
    }
    const detail = await apiJson(
      `/api/organizations/${EXPECTED.organizationUuid}/chat_conversations/`
        + `${EXPECTED.conversationUuid}`
        + '?tree=True&rendering_mode=messages&render_all_tools=true&consistency=strong'
    );
    if (detail.kind !== 'ok' || detail.status !== 200
        || !(await exactPreconversionConversation(detail.value))) {
      return {stage:'conversion_reconcile_conversation',
        mutationAttempted:false, ...ids};
    }
    const catalogs = await conversationCatalogRows();
    if (!Array.isArray(catalogs) || catalogs.length !== 1) {
      return {stage:'conversion_reconcile_catalog_count',
        mutationAttempted:false, ...ids};
    }
    const catalog = catalogs[0];
    const artifactUuid = catalog?.uuid;
    const versionUuid = catalog?.latest_artifact_version_uuid;
    const expectedCatalogTitle = EXPECTED.outputPath.split('/').pop();
    if (!UUID.test(artifactUuid || '') || !UUID.test(versionUuid || '')
        || catalog.chat_conversation_uuid !== EXPECTED.conversationUuid
        || !safeText(catalog.artifact_identifier)
        || !safeText(catalog.artifact_type)
        || !(catalog.code_language === null
          || safeText(catalog.code_language, true))
        || catalog.title !== expectedCatalogTitle || !safeText(catalog.title)
        || !own(catalog, 'latest_published_artifact_uuid')
        || catalog.latest_published_artifact_uuid !== null) {
      return {stage:'conversion_reconcile_catalog',
        mutationAttempted:false, ...ids};
    }
    const versions = await apiJson(
      `/api/organizations/${EXPECTED.organizationUuid}/artifacts/`
        + `${EXPECTED.conversationUuid}/versions`
    );
    const rows = versions.value?.artifact_versions;
    if (versions.kind !== 'ok' || versions.status !== 200
        || !keysAre(versions.value, ['artifact_versions'])
        || !Array.isArray(rows) || rows.length !== 1) {
      return {stage:'conversion_reconcile_version_count',
        mutationAttempted:false, ...ids};
    }
    const row = rows[0];
    const messageUuid = row?.message_uuid;
    if (row?.uuid !== versionUuid || row.artifact_uuid !== artifactUuid
        || !UUID.test(messageUuid || '') || row.result_state !== SOURCE
        || row.artifact_type !== catalog.artifact_type
        || row.code_language !== catalog.code_language
        || row.title !== catalog.title
        || !own(row, 'published_artifact_uuid')
        || row.published_artifact_uuid !== null
        || !own(row, 'published_artifact_deleted_at')
        || row.published_artifact_deleted_at !== null) {
      return {stage:'conversion_reconcile_version',
        mutationAttempted:false, ...ids};
    }
    if (!(await noActiveBinding()) || !(await noPublicHistoryBinding())) {
      return {stage:'conversion_reconcile_public',
        mutationAttempted:false, ...ids};
    }
    const visibility = await apiJson(
      `/api/organizations/${EXPECTED.organizationUuid}/artifact-versions/`
        + `${versionUuid}/visibility`
    );
    if (visibility.kind !== 'ok' || visibility.status !== 200
        || !keysAre(visibility.value, ['visibility'])
        || !['private', 'shared'].includes(visibility.value.visibility)) {
      return {stage:'conversion_reconcile_visibility',
        mutationAttempted:false, ...ids};
    }
    for (let sample = 1; sample < 3; sample += 1) {
      await new Promise(resolve => setTimeout(resolve, 500));
      const currentDetail = await apiJson(
        `/api/organizations/${EXPECTED.organizationUuid}/chat_conversations/`
          + `${EXPECTED.conversationUuid}`
          + '?tree=True&rendering_mode=messages&render_all_tools=true&consistency=strong'
      );
      const currentCatalogs = await conversationCatalogRows();
      const currentVersions = await apiJson(
        `/api/organizations/${EXPECTED.organizationUuid}/artifacts/`
          + `${EXPECTED.conversationUuid}/versions`
      );
      const currentRows = currentVersions.value?.artifact_versions;
      const currentVisibility = await apiJson(
        `/api/organizations/${EXPECTED.organizationUuid}/artifact-versions/`
          + `${versionUuid}/visibility`
      );
      if (currentDetail.kind !== 'ok' || currentDetail.status !== 200
          || !(await exactPreconversionConversation(currentDetail.value))
          || !Array.isArray(currentCatalogs) || currentCatalogs.length !== 1
          || currentCatalogs[0]?.uuid !== artifactUuid
          || currentCatalogs[0].latest_artifact_version_uuid !== versionUuid
          || currentCatalogs[0].artifact_identifier !== catalog.artifact_identifier
          || currentCatalogs[0].artifact_type !== catalog.artifact_type
          || currentCatalogs[0].code_language !== catalog.code_language
          || currentCatalogs[0].title !== catalog.title
          || currentCatalogs[0].latest_published_artifact_uuid !== null
          || currentVersions.kind !== 'ok' || currentVersions.status !== 200
          || !keysAre(currentVersions.value, ['artifact_versions'])
          || !Array.isArray(currentRows) || currentRows.length !== 1
          || currentRows[0]?.uuid !== versionUuid
          || currentRows[0].artifact_uuid !== artifactUuid
          || currentRows[0].message_uuid !== messageUuid
          || currentRows[0].result_state !== SOURCE
          || currentRows[0].artifact_type !== catalog.artifact_type
          || currentRows[0].code_language !== catalog.code_language
          || currentRows[0].title !== catalog.title
          || currentRows[0].published_artifact_uuid !== null
          || currentRows[0].published_artifact_deleted_at !== null
          || !(await noActiveBinding()) || !(await noPublicHistoryBinding())
          || currentVisibility.kind !== 'ok' || currentVisibility.status !== 200
          || !keysAre(currentVisibility.value, ['visibility'])
          || currentVisibility.value.visibility !== visibility.value.visibility) {
        return {stage:'conversion_reconcile_unstable',
          mutationAttempted:false, ...ids};
      }
    }
    if (!(await identity())) {
      return {stage:'conversion_reconcile_final_identity',
        mutationAttempted:false, ...ids};
    }
    return {stage:'conversion_reconcile_complete', mutationAttempted:false,
      reconciled:true, conversationUuid:EXPECTED.conversationUuid,
      artifactUuid, versionUuid, messageUuid,
      artifactIdentifier:catalog.artifact_identifier,
      artifactType:catalog.artifact_type, codeLanguage:catalog.code_language,
      title:catalog.title, visibility:visibility.value.visibility};
  }
  if (preconversion) {
    if (!['conversation_bound', 'file_bound'].includes(EXPECTED.preconversionStage)
        || EXPECTED.chatUrl !== `https://claude.ai/chat/${EXPECTED.conversationUuid}`
        || typeof EXPECTED.expectedPrompt !== 'string'
        || EXPECTED.expectedPrompt.length === 0
        || EXPECTED.expectedPrompt.length > 110000
        || !/^[0-9a-f]{64}$/.test(EXPECTED.promptSha256 || '')
        || !/^[0-9a-f]{64}$/.test(EXPECTED.sourceSha256 || '')
        || await sha256(EXPECTED.expectedPrompt) !== EXPECTED.promptSha256
        || await sha256(SOURCE) !== EXPECTED.sourceSha256
        || !/^\/mnt\/user-data\/outputs\/[A-Za-z0-9._\/-]+$/.test(
          EXPECTED.outputPath || ''
        )
        || EXPECTED.outputPath.includes('/../')
        || EXPECTED.outputPath.endsWith('/..')) {
      return {stage:'preconversion_shape', mutationAttempted:false, ...ids};
    }
    const conversationPath =
      `/api/organizations/${EXPECTED.organizationUuid}/chat_conversations/`
        + `${EXPECTED.conversationUuid}`
        + '?tree=True&rendering_mode=messages&render_all_tools=true&consistency=strong';
    const versionsPath =
      `/api/organizations/${EXPECTED.organizationUuid}/artifacts/`
        + `${EXPECTED.conversationUuid}/versions`;
    const versionsAbsent = result =>
      (result.kind === 'http' && result.status === 404)
      || (result.kind === 'ok' && result.status === 200
        && keysAre(result.value, ['artifact_versions'])
        && Array.isArray(result.value.artifact_versions)
        && result.value.artifact_versions.length === 0);
    const clearOfArtifacts = async () => {
      const versions = await apiJson(versionsPath);
      return versionsAbsent(versions)
        && await conversationCatalogAbsent() && await noActiveBinding();
    };
    const detail = await apiJson(conversationPath);
    if (detail.kind === 'http' && detail.status === 404) {
      const missingDeadline = Date.now() + 45000;
      let missingSince = null;
      while (Date.now() <= missingDeadline) {
        const missing = await apiJson(conversationPath);
        if (missing.kind === 'http' && missing.status === 404
            && await clearOfArtifacts()) {
          missingSince ??= Date.now();
          if (Date.now() - missingSince >= 30000 && await identity()) {
            return {stage:'preconversion_delete_complete', mutationAttempted:false,
              reconciled:true, ...ids};
          }
        } else {
          missingSince = null;
        }
        await new Promise(resolve => setTimeout(resolve, 500));
      }
      return {stage:'preconversion_deleted_ambiguous', mutationAttempted:false, ...ids};
    }
    if (detail.kind !== 'ok' || detail.status !== 200
        || !(await exactPreconversionConversation(detail.value))) {
      return {stage:'preconversion_conversation_binding',
        mutationAttempted:false, ...ids};
    }
    const deadline = Date.now() + 45000;
    let absentSince = null;
    while (Date.now() <= deadline) {
      const current = await apiJson(conversationPath);
      const transcriptBound = current.kind === 'ok' && current.status === 200
        && await exactPreconversionConversation(current.value);
      if (!transcriptBound) {
        return {stage:'preconversion_conversation_changed',
          mutationAttempted:false, ...ids};
      }
      if (await clearOfArtifacts()) {
        absentSince ??= Date.now();
        if (Date.now() - absentSince >= 30000) break;
      } else {
        absentSince = null;
      }
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    if (absentSince === null || Date.now() - absentSince < 30000) {
      return {stage:'preconversion_artifact_absence',
        mutationAttempted:false, ...ids};
    }
    if (!(await identity())) {
      return {stage:'preconversion_pre_delete_identity',
        mutationAttempted:false, ...ids};
    }
    const finalDetail = await apiJson(conversationPath);
    if (finalDetail.kind !== 'ok' || finalDetail.status !== 200
        || !(await exactPreconversionConversation(finalDetail.value))
        || !(await clearOfArtifacts())) {
      return {stage:'preconversion_final_preflight',
        mutationAttempted:false, ...ids};
    }
    const removed = await deleteConversationOnce();
    if (removed.kind !== 'ok' || removed.status !== 204) {
      return {stage:'preconversion_delete_mutation', status:removed.status,
        mutationAttempted:true, ...ids};
    }
    const deletionVerified = await waitFor(async () => {
      const after = await apiJson(conversationPath);
      return after.kind === 'http' && after.status === 404
        && await clearOfArtifacts();
    });
    if (!deletionVerified) {
      return {stage:'preconversion_delete_readback',
        mutationAttempted:true, ...ids};
    }
    if (!(await identity())) {
      return {stage:'preconversion_delete_final_identity',
        mutationAttempted:true, ...ids};
    }
    return {stage:'preconversion_delete_complete', mutationAttempted:true, ...ids};
  }
  if (ACTION === 'delete_conversation') {
    if (!safeText(EXPECTED.promptSha256)
        || !/^[0-9a-f]{64}$/.test(EXPECTED.promptSha256)
        || !/^\/mnt\/user-data\/outputs\/[A-Za-z0-9._\/-]+$/.test(EXPECTED.outputPath || '')
        || EXPECTED.outputPath.includes('/../') || EXPECTED.outputPath.endsWith('/..')) {
      return {stage:'delete_preflight_shape', mutationAttempted:false, ...ids};
    }
    const detail = await apiJson(
      `/api/organizations/${EXPECTED.organizationUuid}/chat_conversations/`
        + `${EXPECTED.conversationUuid}`
        + '?tree=True&rendering_mode=messages&render_all_tools=true&consistency=strong'
    );
    const versions = await apiJson(
      `/api/organizations/${EXPECTED.organizationUuid}/artifacts/`
        + `${EXPECTED.conversationUuid}/versions`
    );
    const publicGone = EXPECTED.publishedUuid === null
      ? await noActiveBinding()
      : await activeZero() && await noActiveBinding() && await verifyPublished(true);
    if (detail.kind === 'http' && detail.status === 404
        && versions.kind === 'http' && versions.status === 404
        && await catalogAbsent() && publicGone && await identity()) {
      return {stage:'delete_complete', mutationAttempted:false,
        reconciled:true, ...ids};
    }
  }
  const catalog = await resolveCatalog();
  const versionResult = await resolveVersion();
  if (!catalog || !versionResult.ok || !exactCore(catalog, versionResult.row)) {
    return {stage:'preflight_provenance', mutationAttempted:false, ...ids};
  }
  const row = versionResult.row;

  if (ACTION === 'complete_conversion_privacy') {
    if (!safeText(EXPECTED.promptSha256)
        || !/^[0-9a-f]{64}$/.test(EXPECTED.promptSha256)
        || !/^\/mnt\/user-data\/outputs\/[A-Za-z0-9._\/-]+$/.test(
          EXPECTED.outputPath || ''
        )
        || EXPECTED.outputPath.includes('/../')
        || EXPECTED.outputPath.endsWith('/..')) {
      return {stage:'conversion_privacy_preflight',
        mutationAttempted:false, ...ids};
    }
    const visibilityPath =
      `/api/organizations/${EXPECTED.organizationUuid}/artifact-versions/`
        + `${EXPECTED.versionUuid}/visibility`;
    const readVisibility = async () => {
      const result = await apiJson(visibilityPath);
      return result.kind === 'ok' && result.status === 200
        && keysAre(result.value, ['visibility'])
        && ['private', 'shared'].includes(result.value.visibility)
        ? result.value.visibility : null;
    };
    const exactRecoveredState = async expectedVisibility => {
      const catalogs = await conversationCatalogRows();
      if (!Array.isArray(catalogs) || catalogs.length !== 1
          || catalogs[0]?.uuid !== EXPECTED.artifactUuid) return false;
      const versions = await apiJson(
        `/api/organizations/${EXPECTED.organizationUuid}/artifacts/`
          + `${EXPECTED.conversationUuid}/versions`
      );
      const rows = versions.value?.artifact_versions;
      if (versions.kind !== 'ok' || versions.status !== 200
          || !keysAre(versions.value, ['artifact_versions'])
          || !Array.isArray(rows) || rows.length !== 1
          || rows[0]?.uuid !== EXPECTED.versionUuid
          || !exactCore(catalogs[0], rows[0])
          || catalogs[0].latest_published_artifact_uuid !== null
          || rows[0].published_artifact_uuid !== null
          || rows[0].published_artifact_deleted_at !== null
          || !(await noActiveBinding()) || !(await noPublicHistoryBinding())
          || !(await exactConversation())) return false;
      return await readVisibility() === expectedVisibility;
    };
    const before = await readVisibility();
    if (before === 'private' && await exactRecoveredState('private')
        && await identity()) {
      return {stage:'conversion_privacy_complete', mutationAttempted:false,
        reconciled:true, ...ids};
    }
    if (before !== 'shared' || !(await exactRecoveredState('shared'))) {
      return {stage:'conversion_privacy_visibility',
        mutationAttempted:false, ...ids};
    }
    if (EXPECTED.allowMutation !== true) {
      return {stage:'conversion_privacy_retry_blocked',
        mutationAttempted:false, ...ids};
    }
    if (!(await identity())) {
      return {stage:'conversion_privacy_identity',
        mutationAttempted:false, ...ids};
    }
    if (!(await exactRecoveredState('shared'))) {
      return {stage:'conversion_privacy_final_preflight',
        mutationAttempted:false, ...ids};
    }
    const changed = await apiStatus(
      visibilityPath,
      {method:'POST', body:JSON.stringify({visibility:'private'})}
    );
    const privateVerified = await waitFor(
      async () => await exactRecoveredState('private')
    );
    if (!privateVerified) {
      return {stage:changed.kind === 'ok'
          ? 'conversion_privacy_readback' : 'conversion_privacy_mutation',
        status:changed.status,
        mutationAttempted:true, ...ids};
    }
    if (!(await identity())) {
      return {stage:'conversion_privacy_final_identity',
        mutationAttempted:true, ...ids};
    }
    return {stage:'conversion_privacy_complete', mutationAttempted:true, ...ids};
  }

  if (ACTION === 'reconcile_public') {
    if (EXPECTED.publishedUuid !== null) {
      return {stage:'reconcile_preflight', mutationAttempted:false, ...ids};
    }
    const deadline = Date.now() + 45000;
    let privateSince = null;
    while (Date.now() <= deadline) {
      const currentCatalog = await resolveCatalog();
      const currentVersion = await resolveVersion();
      const listed = await listPublished(false);
      if (!currentCatalog || !currentVersion.ok
          || !exactCore(currentCatalog, currentVersion.row) || !listed.ok) {
        return {stage:'reconcile_readback', mutationAttempted:false, ...ids};
      }
      const currentRow = currentVersion.row;
      const conversationRows = listed.list.filter(item =>
        item?.chat_conversation_uuid === EXPECTED.conversationUuid
      );
      const matches = conversationRows.filter(item =>
        item?.artifact_identifier === EXPECTED.artifactIdentifier
        && item?.message_uuid === EXPECTED.messageUuid
      );
      if (conversationRows.length !== matches.length || matches.length > 1) {
        return {stage:'reconcile_ambiguous', mutationAttempted:false, ...ids};
      }
      if (matches.length === 1) {
        const active = matches[0];
        const publishedUuid = active?.published_artifact_uuid;
        const uuidRows = listed.list.filter(
          item => item?.published_artifact_uuid === publishedUuid
        );
        if (!UUID.test(publishedUuid || '')
            || uuidRows.length !== 1 || uuidRows[0] !== active
            || active.deleted !== false || !safeText(active.created_at)
            || active.artifact_type !== EXPECTED.artifactType
            || active.code_language !== EXPECTED.codeLanguage
            || active.title !== EXPECTED.title
            || !(active.artifact_version_uuid === null
              || active.artifact_version_uuid === EXPECTED.versionUuid)
            || currentCatalog.latest_published_artifact_uuid !== publishedUuid
            || currentRow.published_artifact_uuid !== publishedUuid
            || currentRow.published_artifact_deleted_at !== null
            || !(await identity())) {
          return {stage:'reconcile_public_mismatch', mutationAttempted:false,
            ...(UUID.test(publishedUuid || '') ? {publishedUuid} : {}), ...ids};
        }
        return {stage:'reconcile_complete', publicState:'active', publishedUuid,
          mutationAttempted:false, reconciled:true, ...ids};
      }
      const allListed = await listPublished(true);
      if (!allListed.ok) {
        return {stage:'reconcile_history_fetch', mutationAttempted:false, ...ids};
      }
      const historyRows = allListed.list.filter(item =>
        item?.chat_conversation_uuid === EXPECTED.conversationUuid
      );
      const tombstones = historyRows.filter(item =>
        item?.artifact_identifier === EXPECTED.artifactIdentifier
        && item?.message_uuid === EXPECTED.messageUuid && item?.deleted === true
      );
      if (historyRows.length !== tombstones.length || tombstones.length > 1) {
        return {stage:'reconcile_history_ambiguous', mutationAttempted:false, ...ids};
      }
      if (tombstones.length === 1) {
        const tombstone = tombstones[0];
        const publishedUuid = tombstone?.published_artifact_uuid;
        const uuidRows = allListed.list.filter(
          item => item?.published_artifact_uuid === publishedUuid
        );
        if (!UUID.test(publishedUuid || '') || !safeText(tombstone.created_at)
            || uuidRows.length !== 1 || uuidRows[0] !== tombstone
            || tombstone.artifact_type !== EXPECTED.artifactType
            || tombstone.code_language !== EXPECTED.codeLanguage
            || tombstone.title !== EXPECTED.title
            || !(tombstone.artifact_version_uuid === null
              || tombstone.artifact_version_uuid === EXPECTED.versionUuid)
            || currentCatalog.latest_published_artifact_uuid !== null
            || currentRow.published_artifact_uuid !== publishedUuid
            || !safeText(currentRow.published_artifact_deleted_at)
            || !(await identity())) {
          return {stage:'reconcile_tombstone_mismatch', mutationAttempted:false,
            ...(UUID.test(publishedUuid || '') ? {publishedUuid} : {}), ...ids};
        }
        return {stage:'reconcile_complete', publicState:'deleted', publishedUuid,
          mutationAttempted:false, reconciled:true, ...ids};
      }
      const exactlyPrivate = currentCatalog.latest_published_artifact_uuid === null
        && currentRow.published_artifact_uuid === null
        && currentRow.published_artifact_deleted_at === null;
      if (exactlyPrivate) {
        privateSince ??= Date.now();
        if (Date.now() - privateSince >= 30000 && await identity()) {
          return {stage:'reconcile_no_mapping', mutationAttempted:false, ...ids};
        }
      } else {
        privateSince = null;
      }
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    return {stage:'reconcile_timeout', mutationAttempted:false, ...ids};
  }

  if (ACTION === 'unpublish') {
    if (UUID.test(EXPECTED.publishedUuid || '')
        && catalog.latest_published_artifact_uuid === null
        && row.published_artifact_uuid === EXPECTED.publishedUuid
        && safeText(row.published_artifact_deleted_at)
        && await activeZero() && await verifyPublished(true)
        && await identity()) {
      return {stage:'unpublish_complete', mutationAttempted:false,
        reconciled:true, ...ids};
    }
    if (!UUID.test(EXPECTED.publishedUuid || '')
        || catalog.latest_published_artifact_uuid !== EXPECTED.publishedUuid
        || row.published_artifact_uuid !== EXPECTED.publishedUuid
        || row.published_artifact_deleted_at !== null
        || !(await verifyPublished(false))) {
      return {stage:'unpublish_preflight', mutationAttempted:false, ...ids};
    }
    if (!(await identity())) {
      return {stage:'unpublish_pre_delete_identity', mutationAttempted:false, ...ids};
    }
    const removed = await apiStatus(
      `/api/organizations/${EXPECTED.organizationUuid}/published_artifacts/`
        + EXPECTED.publishedUuid,
      {method:'DELETE', body:'{}'}
    );
    if (removed.kind !== 'ok') {
      return {stage:'unpublish_delete', status:removed.status,
        mutationAttempted:true, ...ids};
    }
    const unpublished = await waitFor(async () => {
      if (!(await activeZero()) || !(await verifyPublished(true))) return false;
      const afterCatalog = await resolveCatalog();
      const after = await resolveVersion();
      return afterCatalog && after.ok && exactCore(afterCatalog, after.row)
        && afterCatalog.latest_published_artifact_uuid === null
        && after.row.published_artifact_uuid === EXPECTED.publishedUuid
        && safeText(after.row.published_artifact_deleted_at);
    });
    if (!unpublished) {
      return {stage:'unpublish_version', mutationAttempted:true, ...ids};
    }
    if (!(await identity())) {
      return {stage:'unpublish_final_identity', mutationAttempted:true, ...ids};
    }
    return {stage:'unpublish_complete', mutationAttempted:true, ...ids};
  }

  if (ACTION !== 'delete_conversation') {
    return {stage:'delete_preflight_shape', mutationAttempted:false, ...ids};
  }
  if (EXPECTED.publishedUuid === null) {
    if (catalog.latest_published_artifact_uuid !== null
        || row.published_artifact_uuid !== null
        || row.published_artifact_deleted_at !== null
        || !(await noActiveBinding())) {
      return {stage:'delete_public_absence', mutationAttempted:false, ...ids};
    }
  } else if (catalog.latest_published_artifact_uuid !== null
      || row.published_artifact_uuid !== EXPECTED.publishedUuid
      || !safeText(row.published_artifact_deleted_at)
      || !(await activeZero()) || !(await noActiveBinding())
      || !(await verifyPublished(true))) {
    return {stage:'delete_public_tombstone', mutationAttempted:false, ...ids};
  }
  if (!(await exactConversation())) {
    return {stage:'delete_conversation_binding', mutationAttempted:false, ...ids};
  }
  if (!(await identity())) {
    return {stage:'delete_pre_delete_identity', mutationAttempted:false, ...ids};
  }
  const deleted = await deleteConversationOnce();
  if (deleted.kind !== 'ok' || deleted.status !== 204) {
    return {stage:'delete_mutation', status:deleted.status,
      mutationAttempted:true, ...ids};
  }
  const deletionVerified = await waitFor(async () => {
    const detail = await apiJson(
      `/api/organizations/${EXPECTED.organizationUuid}/chat_conversations/`
        + `${EXPECTED.conversationUuid}`
        + '?tree=True&rendering_mode=messages&render_all_tools=true&consistency=strong'
    );
    if (detail.kind !== 'http' || detail.status !== 404) return false;
    if (!(await noActiveBinding()) || !(await catalogAbsent())) return false;
    const versions = await apiJson(
      `/api/organizations/${EXPECTED.organizationUuid}/artifacts/`
        + `${EXPECTED.conversationUuid}/versions`
    );
    return versions.kind === 'http' && versions.status === 404;
  });
  if (!deletionVerified) {
    return {stage:'delete_readback_verify', mutationAttempted:true, ...ids};
  }
  if (!(await identity())) {
    return {stage:'delete_final_identity', mutationAttempted:true, ...ids};
  }
  return {stage:'delete_complete', mutationAttempted:true, ...ids};
})(%s, %s, %s)
"""
            % (
                _EXACT_HUMAN_TEXT_JS,
                json.dumps(expected),
                json.dumps(source),
                json.dumps(action),
            )
        )

    def _validate_preconversion_binding(
        self,
        binding: ChatPreconversionBinding,
        source: str,
        prompt: str,
    ) -> ChatPreconversionBinding:
        """Validate receipt provenance before opening a lifecycle browser tab."""

        if not isinstance(binding, ChatPreconversionBinding):
            raise FrameError(
                "pre-conversion cleanup requires a ChatPreconversionBinding"
            )
        if self.expected_email_sha256 is None or self.organization_uuid is None:
            raise FrameError(
                "pre-conversion cleanup requires exact account and organization binding"
            )
        if binding.organization_uuid != self.organization_uuid:
            raise FrameError(
                "pre-conversion cleanup binding belongs to a different organization"
            )
        if binding.receipt_stage not in {
            "conversation_bound",
            "file_bound",
            "conversion_pending",
        }:
            raise FrameError(
                "pre-Artifact lifecycle binding has an unsupported receipt stage"
            )
        if not isinstance(source, str) or not source or len(source) > MAX_CHAT_SOURCE_CHARS:
            raise FrameError("pre-conversion cleanup source is invalid")
        if binding.source_sha256 != sha256_text(source):
            raise FrameError(
                "pre-conversion cleanup source did not match its durable digest"
            )
        if (
            not isinstance(binding.request_title, str)
            or not binding.request_title
            or len(binding.request_title) > 1000
            or re.search(r"[\x00-\x1f\x7f]", binding.request_title)
        ):
            raise FrameError("pre-conversion cleanup title binding is invalid")
        if (
            not isinstance(binding.output_path, str)
            or not OUTPUT_PATH_RE.fullmatch(binding.output_path)
            or "/../" in binding.output_path
            or binding.output_path.endswith("/..")
            or generated_output_path(source, binding.request_title)
            != binding.output_path
        ):
            raise FrameError("pre-conversion cleanup output-path binding is invalid")
        expected_prompt = build_prompt(source, binding.request_title, binding.output_path)
        if (
            not isinstance(prompt, str)
            or prompt != expected_prompt
            or not re.fullmatch(r"[0-9a-f]{64}", binding.prompt_sha256 or "")
            or binding.prompt_sha256 != sha256_text(prompt)
        ):
            raise FrameError("pre-conversion cleanup prompt binding is invalid")
        if not re.fullmatch(UUID, binding.conversation_uuid or ""):
            raise FrameError("pre-conversion cleanup conversation UUID is invalid")
        parts = urlsplit(binding.chat_url) if isinstance(binding.chat_url, str) else None
        if not (
            parts
            and parts.scheme == "https"
            and parts.hostname == "claude.ai"
            and parts.port is None
            and parts.username is None
            and parts.password is None
            and parts.path == f"/chat/{binding.conversation_uuid}"
            and not parts.query
            and not parts.fragment
        ):
            raise FrameError("pre-conversion cleanup conversation URL is invalid")
        return binding

    @staticmethod
    def _parse_conversion_reconciliation(
        value: Any, binding: ChatPreconversionBinding
    ) -> ChatPublishResult | None:
        """Parse one exact read-only binding recovered after conversion."""

        if not isinstance(value, dict):
            return None
        expected_keys = {
            "stage",
            "mutationAttempted",
            "reconciled",
            "conversationUuid",
            "artifactUuid",
            "versionUuid",
            "messageUuid",
            "artifactIdentifier",
            "artifactType",
            "codeLanguage",
            "title",
            "visibility",
        }
        if (
            set(value) != expected_keys
            or value.get("stage") != "conversion_reconcile_complete"
            or value.get("mutationAttempted") is not False
            or value.get("reconciled") is not True
            or value.get("conversationUuid") != binding.conversation_uuid
            or value.get("visibility") not in {"shared", "private"}
        ):
            return None
        for key in ("artifactUuid", "versionUuid", "messageUuid"):
            if not isinstance(value.get(key), str) or not re.fullmatch(
                UUID, value[key]
            ):
                return None

        def safe_text(item: Any, *, allow_empty: bool = False) -> bool:
            return (
                isinstance(item, str)
                and len(item) <= 1000
                and (allow_empty or bool(item))
                and re.search(r"[\x00-\x1f\x7f]", item) is None
            )

        if (
            not safe_text(value.get("artifactIdentifier"))
            or not safe_text(value.get("artifactType"))
            or (
                value.get("codeLanguage") is not None
                and not safe_text(value.get("codeLanguage"), allow_empty=True)
            )
            or value.get("title") != binding.output_path.rsplit("/", 1)[-1]
            or not safe_text(value.get("title"))
        ):
            return None
        return ChatPublishResult(
            url=binding.chat_url,
            chat_url=binding.chat_url,
            artifact_uuid=value["artifactUuid"],
            version_uuid=value["versionUuid"],
            public=False,
            source_sha256=binding.source_sha256,
            organization_uuid=binding.organization_uuid,
            conversation_uuid=binding.conversation_uuid,
            message_uuid=value["messageUuid"],
            artifact_identifier=value["artifactIdentifier"],
            artifact_type=value["artifactType"],
            code_language=value["codeLanguage"],
            title=value["title"],
            output_path=binding.output_path,
            prompt_sha256=binding.prompt_sha256,
        )

    def reconcile_conversion_pending(
        self,
        binding: ChatPreconversionBinding,
        source: str,
        prompt: str,
        *,
        on_reconciled: Callable[[ChatPublishResult], None] | None = None,
    ) -> ChatPublishResult:
        """Read back a unique converted binding without mutating its privacy."""

        binding = self._validate_preconversion_binding(binding, source, prompt)
        if binding.receipt_stage != "conversion_pending":
            raise FrameError(
                "conversion reconciliation requires a conversion_pending receipt"
            )
        if on_reconciled is not None and not callable(on_reconciled):
            raise FrameError("on_reconciled must be callable")
        identifiers = (
            f"organization={binding.organization_uuid}, "
            f"conversation={binding.conversation_uuid}"
        )

        def record_if_complete(value: Any) -> None:
            reconciled = self._parse_conversion_reconciliation(value, binding)
            if reconciled is not None and on_reconciled is not None:
                try:
                    on_reconciled(reconciled)
                except Exception:
                    raise FrameError(
                        "conversion binding was reconciled but its durable callback "
                        f"failed; cleanup identifiers: {identifiers}, "
                        f"artifact={reconciled.artifact_uuid}, "
                        f"version={reconciled.version_uuid}, "
                        f"message={reconciled.message_uuid}"
                    ) from None

        try:
            value, cleanup_failed = self._run_lifecycle_transaction(
                binding,
                source,
                action="reconcile_conversion_pending",
                published_uuid=None,
                output_path=binding.output_path,
                prompt_sha256=binding.prompt_sha256,
                expected_prompt=prompt,
                on_result=record_if_complete,
            )
        except FrameError as error:
            raise FrameError(f"{error}; cleanup identifiers: {identifiers}") from None
        result = self._parse_conversion_reconciliation(value, binding)
        if result is None:
            stage = (
                value.get("stage", "invalid_result")
                if isinstance(value, dict)
                else "invalid_result"
            )
            raise FrameError(
                "conversion reconciliation failed read-only exact verification "
                f"(stage: {stage}); cleanup identifiers: {identifiers}"
            )
        if cleanup_failed:
            raise FrameError(
                "conversion binding was reconciled but local tab cleanup failed; "
                f"cleanup identifiers: {identifiers}, "
                f"artifact={result.artifact_uuid}, version={result.version_uuid}, "
                f"message={result.message_uuid}"
            )
        return result

    def complete_conversion_privacy(
        self,
        result: ChatPublishResult,
        source: str,
        prompt: str,
        request_title: str,
        *,
        allow_mutation: bool = False,
        on_verified: Callable[[], None] | None = None,
    ) -> bool:
        """Make one durably bound recovered conversion private and verify it."""

        binding = self._binding_from_result(result, source)
        if type(allow_mutation) is not bool:
            raise FrameError("conversion privacy mutation intent must be a boolean")
        if (
            result.public
            or result.published_uuid is not None
            or result.published_deleted
            or not isinstance(result.output_path, str)
            or not OUTPUT_PATH_RE.fullmatch(result.output_path)
            or "/../" in result.output_path
            or result.output_path.endswith("/..")
            or not isinstance(prompt, str)
            or not isinstance(request_title, str)
            or not request_title
            or len(request_title) > 1000
            or re.search(r"[\x00-\x1f\x7f]", request_title)
            or generated_output_path(source, request_title) != result.output_path
            or result.prompt_sha256 != sha256_text(prompt)
            or prompt != build_prompt(source, request_title, result.output_path)
        ):
            raise FrameError(
                "conversion privacy completion requires exact private conversion provenance"
            )
        if on_verified is not None and not callable(on_verified):
            raise FrameError("on_verified must be callable")
        identifiers = self._lifecycle_identifiers(binding, None)

        def record_if_complete(value: Any) -> None:
            if on_verified is not None and self._require_lifecycle_completion(
                value,
                stage="conversion_privacy_complete",
                binding=binding,
                published_uuid=None,
            ):
                try:
                    on_verified()
                except Exception:
                    raise FrameError(
                        "conversion privacy was verified but its durable callback "
                        f"failed; cleanup identifiers: {identifiers}"
                    ) from None

        try:
            value, cleanup_failed = self._run_lifecycle_transaction(
                binding,
                source,
                action="complete_conversion_privacy",
                published_uuid=None,
                output_path=result.output_path,
                prompt_sha256=result.prompt_sha256,
                expected_prompt=prompt,
                allow_mutation=allow_mutation,
                on_result=record_if_complete,
            )
        except FrameError as error:
            raise FrameError(f"{error}; cleanup identifiers: {identifiers}") from None
        if self._require_lifecycle_completion(
            value,
            stage="conversion_privacy_complete",
            binding=binding,
            published_uuid=None,
        ):
            if cleanup_failed:
                raise FrameError(
                    "conversion privacy was verified but local tab cleanup failed; "
                    f"cleanup identifiers: {identifiers}"
                )
            return True
        stage = (
            value.get("stage", "invalid_result")
            if isinstance(value, dict)
            else "invalid_result"
        )
        attempted = isinstance(value, dict) and value.get("mutationAttempted") is True
        state = "remote state is unknown" if attempted else "exact preflight failed"
        raise FrameError(
            f"conversion privacy {state} after one non-retried operation "
            f"(stage: {stage}); cleanup identifiers: {identifiers}"
        )

    @staticmethod
    def _require_preconversion_cleanup_completion(
        value: Any, binding: ChatPreconversionBinding
    ) -> bool:
        if not isinstance(value, dict):
            return False
        expected = {
            "stage": "preconversion_delete_complete",
            "mutationAttempted": None,
            "conversationUuid": binding.conversation_uuid,
        }
        allowed = set(expected)
        if value.get("reconciled") is True:
            allowed.add("reconciled")
        if set(value) != allowed or value.get("stage") != expected["stage"]:
            return False
        if type(value.get("mutationAttempted")) is not bool:
            return False
        if value["mutationAttempted"] is False and value.get("reconciled") is not True:
            return False
        if value["mutationAttempted"] is True and "reconciled" in value:
            return False
        return value.get("conversationUuid") == binding.conversation_uuid

    def delete_preconversion_conversation(
        self,
        binding: ChatPreconversionBinding,
        source: str,
        prompt: str,
        *,
        on_verified: Callable[[], None] | None = None,
    ) -> bool:
        """Delete a receipt-bound conversation before conversion was attempted."""

        binding = self._validate_preconversion_binding(binding, source, prompt)
        if binding.receipt_stage not in {"conversation_bound", "file_bound"}:
            raise FrameError(
                "pre-conversion cleanup requires a conversation_bound or file_bound receipt"
            )
        if on_verified is not None and not callable(on_verified):
            raise FrameError("on_verified must be callable")
        identifiers = (
            f"organization={binding.organization_uuid}, "
            f"conversation={binding.conversation_uuid}"
        )

        def record_if_complete(value: Any) -> None:
            if on_verified is not None and self._require_preconversion_cleanup_completion(
                value, binding
            ):
                try:
                    on_verified()
                except Exception:
                    raise FrameError(
                        "pre-conversion conversation deletion was verified but its "
                        "durable callback failed; cleanup identifiers: " + identifiers
                    ) from None

        try:
            value, cleanup_failed = self._run_lifecycle_transaction(
                binding,
                source,
                action="delete_preconversion_conversation",
                published_uuid=None,
                output_path=binding.output_path,
                prompt_sha256=binding.prompt_sha256,
                expected_prompt=prompt,
                on_result=record_if_complete,
            )
        except FrameError as error:
            raise FrameError(f"{error}; cleanup identifiers: {identifiers}") from None
        cleanup = (
            "; cleanup of the exact controlled Claude tab was not confirmed"
            if cleanup_failed
            else ""
        )
        if self._require_preconversion_cleanup_completion(value, binding):
            if cleanup_failed:
                raise FrameError(
                    "pre-conversion conversation deletion was verified but local tab "
                    f"cleanup failed; cleanup identifiers: {identifiers}"
                )
            return True
        stage = (
            value.get("stage", "invalid_result")
            if isinstance(value, dict)
            else "invalid_result"
        )
        attempted = isinstance(value, dict) and value.get("mutationAttempted") is True
        state = "remote state is unknown" if attempted else "exact preflight failed"
        raise FrameError(
            f"pre-conversion conversation deletion {state} after one non-retried "
            f"operation (stage: {stage}); cleanup identifiers: {identifiers}{cleanup}"
        )

    def unpublish(
        self,
        result: ChatPublishResult,
        source: str,
        *,
        on_verified: Callable[[], None] | None = None,
    ) -> bool:
        """Delete and verify exactly the public mapping recorded in ``result``."""

        binding = self._binding_from_result(result, source)
        if (
            result.public is not True
            or result.published_deleted
            or not isinstance(result.published_uuid, str)
        ):
            raise FrameError("unpublish requires an exact public ChatPublishResult")
        if on_verified is not None and not callable(on_verified):
            raise FrameError("on_verified must be callable")
        identifiers = self._lifecycle_identifiers(binding, result.published_uuid)
        def record_if_complete(value: Any) -> None:
            if on_verified is not None and self._require_lifecycle_completion(
                value,
                stage="unpublish_complete",
                binding=binding,
                published_uuid=result.published_uuid,
            ):
                try:
                    on_verified()
                except Exception:
                    raise FrameError(
                        "public mapping removal was verified but its durable callback "
                        f"failed; cleanup identifiers: {identifiers}"
                    ) from None
        try:
            value, cleanup_failed = self._run_lifecycle_transaction(
                binding,
                source,
                action="unpublish",
                published_uuid=result.published_uuid,
                on_result=record_if_complete,
            )
        except FrameError as error:
            raise FrameError(
                f"{error}; cleanup identifiers: {identifiers}"
            ) from None
        cleanup = (
            "; cleanup of the exact controlled Claude tab was not confirmed"
            if cleanup_failed
            else ""
        )
        if self._require_lifecycle_completion(
            value,
            stage="unpublish_complete",
            binding=binding,
            published_uuid=result.published_uuid,
        ):
            if cleanup_failed:
                raise FrameError(
                    "public mapping removal was verified but local tab cleanup failed; "
                    f"cleanup identifiers: {identifiers}"
                )
            return True
        stage = value.get("stage", "invalid_result") if isinstance(value, dict) else "invalid_result"
        attempted = isinstance(value, dict) and value.get("mutationAttempted") is True
        state = "remote state is unknown" if attempted else "exact preflight failed"
        raise FrameError(
            f"unpublish {state} after one non-retried operation (stage: {stage}); "
            f"cleanup identifiers: {identifiers}{cleanup}"
        )

    @staticmethod
    def _parse_public_reconciliation(
        value: Any,
        *,
        original: ChatPublishResult,
        binding: ChatArtifactBinding,
    ) -> ChatPublishResult | None:
        """Return a strictly bound read-only public-state result, if complete."""

        if not isinstance(value, dict):
            return None
        common = {
            "stage": "reconcile_complete",
            "mutationAttempted": False,
            "reconciled": True,
            "artifactUuid": binding.artifact_uuid,
            "versionUuid": binding.version_uuid,
            "messageUuid": binding.message_uuid,
            "conversationUuid": binding.conversation_uuid,
        }
        state = value.get("publicState")
        allowed = set(common) | {"publicState"}
        if state in {"active", "deleted"}:
            allowed.add("publishedUuid")
        if (
            set(value) != allowed
            or value.get("mutationAttempted") is not False
            or value.get("reconciled") is not True
            or any(
                value.get(key) != expected
                for key, expected in common.items()
                if key not in {"mutationAttempted", "reconciled"}
            )
        ):
            return None
        published_uuid = value.get("publishedUuid")
        if state not in {"active", "deleted"} or not isinstance(
            published_uuid, str
        ) or not re.fullmatch(UUID, published_uuid):
            return None
        if state == "deleted":
            return replace(
                original,
                url=original.chat_url,
                public=False,
                published_uuid=published_uuid,
                published_deleted=True,
            )
        return replace(
            original,
            url=f"https://claude.ai/public/artifacts/{published_uuid}",
            public=True,
            published_uuid=published_uuid,
            published_deleted=False,
        )

    def reconcile_public(
        self,
        result: ChatPublishResult,
        source: str,
        *,
        on_reconciled: Callable[[ChatPublishResult], None] | None = None,
    ) -> ChatPublishResult:
        """Read back whether a conversion-bound version has a public mapping.

        This is a recovery operation. It performs no provider mutation and is
        intended for a durable ``converted`` receipt left by an interrupted
        public publication. Absence is not promoted to private state because
        the provider exposes no completion bound for an ambiguous publish POST.
        """

        binding = self._binding_from_result(result, source)
        if result.public or result.published_uuid is not None or result.published_deleted:
            raise FrameError(
                "public reconciliation requires an exact conversion-bound private result"
            )
        if on_reconciled is not None and not callable(on_reconciled):
            raise FrameError("on_reconciled must be callable")
        identifiers = self._lifecycle_identifiers(binding, None)

        def record_if_complete(value: Any) -> None:
            reconciled = self._parse_public_reconciliation(
                value, original=result, binding=binding
            )
            if reconciled is not None and on_reconciled is not None:
                try:
                    on_reconciled(reconciled)
                except Exception:
                    raise FrameError(
                        "public-state reconciliation was verified but its durable "
                        f"callback failed; cleanup identifiers: {identifiers}"
                    ) from None

        try:
            value, cleanup_failed = self._run_lifecycle_transaction(
                binding,
                source,
                action="reconcile_public",
                published_uuid=None,
                on_result=record_if_complete,
            )
        except FrameError as error:
            raise FrameError(f"{error}; cleanup identifiers: {identifiers}") from None
        reconciled = self._parse_public_reconciliation(
            value, original=result, binding=binding
        )
        if reconciled is None:
            stage = (
                value.get("stage", "invalid_result")
                if isinstance(value, dict)
                else "invalid_result"
            )
            candidate = value.get("publishedUuid") if isinstance(value, dict) else None
            candidate_text = (
                f", candidate-published={candidate}"
                if isinstance(candidate, str) and re.fullmatch(UUID, candidate)
                else ""
            )
            raise FrameError(
                "public-state reconciliation failed read-only exact verification "
                f"(stage: {stage}); cleanup identifiers: {identifiers}{candidate_text}"
            )
        if cleanup_failed:
            raise FrameError(
                "public-state reconciliation was verified but local tab cleanup failed; "
                f"cleanup identifiers: {identifiers}"
            )
        return reconciled

    def delete_conversation(
        self,
        result: ChatPublishResult,
        source: str,
        *,
        on_verified: Callable[[], None] | None = None,
    ) -> bool:
        """Delete one exact conversation after proving its public mapping absent."""

        binding = self._binding_from_result(result, source)
        if (
            not isinstance(result.output_path, str)
            or not OUTPUT_PATH_RE.fullmatch(result.output_path)
            or "/../" in result.output_path
            or result.output_path.endswith("/..")
            or not isinstance(result.prompt_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", result.prompt_sha256)
        ):
            raise FrameError(
                "conversation deletion requires exact generated-path and prompt provenance"
            )
        if on_verified is not None and not callable(on_verified):
            raise FrameError("on_verified must be callable")
        identifiers = self._lifecycle_identifiers(binding, result.published_uuid)
        def record_if_complete(value: Any) -> None:
            if on_verified is not None and self._require_lifecycle_completion(
                value,
                stage="delete_complete",
                binding=binding,
                published_uuid=result.published_uuid,
            ):
                try:
                    on_verified()
                except Exception:
                    raise FrameError(
                        "conversation deletion was verified but its durable callback "
                        f"failed; cleanup identifiers: {identifiers}"
                    ) from None
        try:
            value, cleanup_failed = self._run_lifecycle_transaction(
                binding,
                source,
                action="delete_conversation",
                published_uuid=result.published_uuid,
                output_path=result.output_path,
                prompt_sha256=result.prompt_sha256,
                on_result=record_if_complete,
            )
        except FrameError as error:
            raise FrameError(
                f"{error}; cleanup identifiers: {identifiers}"
            ) from None
        cleanup = (
            "; cleanup of the exact controlled Claude tab was not confirmed"
            if cleanup_failed
            else ""
        )
        if self._require_lifecycle_completion(
            value,
            stage="delete_complete",
            binding=binding,
            published_uuid=result.published_uuid,
        ):
            if cleanup_failed:
                raise FrameError(
                    "conversation deletion was verified but local tab cleanup failed; "
                    f"cleanup identifiers: {identifiers}"
                )
            return True
        stage = value.get("stage", "invalid_result") if isinstance(value, dict) else "invalid_result"
        attempted = isinstance(value, dict) and value.get("mutationAttempted") is True
        state = "remote state is unknown" if attempted else "exact preflight failed"
        raise FrameError(
            f"conversation deletion {state} after one non-retried operation "
            f"(stage: {stage}); cleanup identifiers: {identifiers}{cleanup}"
        )

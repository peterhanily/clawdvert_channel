"""Client for the Claude artifact API, which calls artifacts "frames".

Everything else in this repo sits on this module. It owns three things: finding
your OAuth token, keeping a connection open, and knowing the shapes the control
plane expects.

The transport is a pooled HTTPS connection rather than urllib. A polling node
makes a request every few seconds forever, and urllib opens a fresh TCP and TLS
connection for each one; reusing a single connection removes a handshake per
poll.
"""

import gzip
import hashlib
import http.client
import io
import json
import os
import re
import subprocess
import sys
import threading
import time

API_HOST = "api.anthropic.com"
API_BASE = f"https://{API_HOST}"
VIEWER = "https://claude.ai/code/artifact/"
CONTENT_HOST = "{slug}.frame.claudeusercontent.com"
UA = "claude-cli/2.1.223 (external, cli)"

# Enforced client side on the composed document, before any HTTP happens.
MAX_BYTES = 16777216

UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
SLUG_RE = re.compile(rf"^{UUID}$")
URL_RE = re.compile(
    rf"^https://(?:[a-z0-9-]+\.)?claude\.ai/code/(?:artifact|frame)/"
    rf"(?:[A-Za-z0-9_-]*-)?({UUID})(?:[/?#]|$)"
)

# The document the client composes around your markup. Reproduce it exactly or
# the published page differs from what Claude Code would have produced.
RESET = (
    "<style>:root{color-scheme:light}body{margin:0;padding:0;"
    "font:14px -apple-system,BlinkMacSystemFont,sans-serif;"
    "background:#faf9f5;color:#141413}img{max-width:100%}</style>"
)
SKELETON = (
    "<!doctype html><html><head><meta charset=utf8>"
    '<meta name=viewport content="width=device-width,initial-scale=1">'
    "{reset}</head><body>\n{body}\n</body></html>"
)

# 409 reasons meaning "this version is still being scanned", worth retrying.
# Everything else in the vocabulary is terminal.
RETRYABLE = {"missing_row", "incomplete", "generation_mismatch", "upload_window_open"}


class FrameError(Exception):
    """Anything the control plane refused, carrying its status and body."""

    def __init__(self, message, status=None, body=None):
        super().__init__(message)
        self.status = status
        self.body = body


# --- credentials -------------------------------------------------------------

def config_dir():
    return os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")


def keychain_service():
    """Claude Code suffixes the service name with a hash of a non-default dir."""
    override = os.environ.get("CLAUDE_SECURESTORAGE_CONFIG_DIR")
    if override is None and not os.environ.get("CLAUDE_CONFIG_DIR"):
        return "Claude Code-credentials"
    digest = hashlib.sha256((override or config_dir()).encode()).hexdigest()[:8]
    return f"Claude Code-credentials-{digest}"


def read_token():
    """Return (token, where_it_came_from), searching the three places the CLI does."""
    tok = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
    if tok:
        return tok, "CLAUDE_CODE_OAUTH_TOKEN"

    if sys.platform == "darwin":
        try:
            raw = subprocess.run(
                ["security", "find-generic-password", "-s", keychain_service(),
                 "-a", os.environ.get("USER", ""), "-w"],
                capture_output=True, text=True, check=True).stdout
            return json.loads(raw)["claudeAiOauth"]["accessToken"], "macOS Keychain"
        except (subprocess.CalledProcessError, KeyError, ValueError):
            pass

    path = os.path.join(config_dir(), ".credentials.json")
    try:
        with open(path) as fh:
            return json.load(fh)["claudeAiOauth"]["accessToken"], path
    except (OSError, KeyError, ValueError):
        pass

    raise FrameError(
        "no OAuth token found. Run `claude setup-token` and export "
        "CLAUDE_CODE_OAUTH_TOKEN, or log in with `claude` first.")


def org_uuid(session=None):
    """Resolution order copied from the CLI: env, config file, then the profile API."""
    env = os.environ.get("CLAUDE_CODE_ORGANIZATION_UUID")
    if env:
        return env
    for path in (os.path.join(config_dir(), ".claude.json"),
                 os.path.expanduser("~/.claude.json")):
        try:
            with open(path) as fh:
                uuid = json.load(fh).get("oauthAccount", {}).get("organizationUuid")
            if uuid:
                return uuid
        except (OSError, ValueError, AttributeError):
            continue
    if session is not None:
        status, data, _ = session.request(
            "GET", "/api/oauth/profile", headers={"Cache-Control": "no-cache"})
        if status == 200 and isinstance(data, dict):
            uuid = (data.get("organization") or {}).get("uuid")
            if uuid:
                return uuid
    raise FrameError("could not resolve the organization uuid; set "
                     "CLAUDE_CODE_ORGANIZATION_UUID")


# --- transport ---------------------------------------------------------------

class Session:
    """One keep-alive HTTPS connection to the control plane.

    Not thread safe by construction, so a lock guards the socket: the mailbox
    node polls on one thread and may publish from another.
    """

    def __init__(self, token=None, host=API_HOST, timeout=30):
        self.token, self.token_source = (token, "caller") if token else read_token()
        self.host = host
        self.timeout = timeout
        self._conn = None
        self._lock = threading.Lock()
        self.requests = 0
        self.reconnects = 0

    def headers(self, extra=None):
        h = {
            "Host": self.host,
            "User-Agent": UA,
            "Authorization": f"Bearer {self.token}",
            "anthropic-beta": "oauth-2025-04-20",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip",
            "Connection": "keep-alive",
            # The control plane answers 404 for every auth state without these.
            "X-Frame-CP": "go",
            "X-Frame-Surface": "code",
            "X-Frame-Platform": "cli",
        }
        if extra:
            h.update({k: v for k, v in extra.items() if v is not None})
        return h

    def _connect(self):
        if self._conn is None:
            self._conn = http.client.HTTPSConnection(self.host, timeout=self.timeout)
        return self._conn

    def close(self):
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None

    def request(self, method, path, body=None, headers=None, retries=2):
        """Return (status, parsed_body, response_headers).

        A dropped keep-alive connection is indistinguishable from a real failure
        until you retry, so one reconnect is always attempted before giving up.
        """
        payload = (json.dumps(body, ensure_ascii=False).encode("utf-8")
                   if body is not None else None)
        last = None
        for attempt in range(retries + 1):
            try:
                with self._lock:
                    conn = self._connect()
                    conn.request(method, path, body=payload, headers=self.headers(headers))
                    resp = conn.getresponse()
                    raw = resp.read()
                    status = resp.status
                    hdrs = {k.lower(): v for k, v in resp.getheaders()}
                    if resp.will_close:
                        self._conn = None
                self.requests += 1
                if hdrs.get("content-encoding") == "gzip" and raw:
                    raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
                text = raw.decode("utf-8", "replace")
                try:
                    return status, (json.loads(text) if text else {}), hdrs
                except ValueError:
                    return status, text, hdrs
            except (http.client.HTTPException, OSError) as exc:
                last = exc
                self.close()
                self.reconnects += 1
                if attempt < retries:
                    time.sleep(0.4 * (attempt + 1))
        raise FrameError(f"{method} {path} failed: {last}")


# --- frame operations --------------------------------------------------------

def compose(body_html):
    """Wrap markup the way Claude Code does, and enforce the same size ceiling."""
    page = SKELETON.format(reset=RESET, body=body_html)
    size = len(page.encode("utf-8"))
    if size > MAX_BYTES:
        raise FrameError(
            f"composed page is {size / 1048576:.1f}MB, over the "
            f"{MAX_BYTES // 1048576}MB limit")
    return page


def slug_from_url(url):
    m = URL_RE.match(url)
    if not m:
        raise FrameError(f"no artifact slug in {url!r}")
    return m.group(1)


def viewer_url(slug):
    """The API never returns this. Every client builds it from the slug."""
    return VIEWER + slug


def publish(session, page, title, favicon="\U0001f4c4", slug=None,
            description=None, label=None, retry_429=True):
    payload = {"title": title, "favicon": favicon, "entrypoint": "cli",
               "content": page}
    if slug:
        payload["slug"] = slug
    if description:
        payload["description"] = description
    if label:
        payload["label"] = label

    status, data, hdrs = session.request("POST", "/api/frame/deploy/direct", payload)
    if status == 429 and retry_429:
        try:
            wait = min(int(hdrs.get("retry-after", 2)), 30)
        except ValueError:
            wait = 2
        time.sleep(wait)
        status, data, hdrs = session.request("POST", "/api/frame/deploy/direct", payload)

    if "frame_daily_push_cap_reached" in str(data):
        raise FrameError("daily publish cap reached", status, data)
    if status == 401:
        raise FrameError("token expired; run any `claude` command, then retry", status, data)
    if not (200 <= status < 300):
        raise FrameError(f"publish failed: HTTP {status} {str(data)[:200]}", status, data)
    if not isinstance(data, dict) or not data.get("slug") or not data.get("version"):
        raise FrameError(f"incomplete deploy response: {str(data)[:200]}", status, data)
    return data


def boot(session, slug):
    """The frame record: ver, assetToken, perm, live, history, shared.

    This one call is the whole polling loop. It is roughly fifty times smaller
    than listing every frame, and it already carries the asset token needed to
    read content, so it replaces the list-then-read pair entirely.
    """
    status, data, _ = session.request("GET", f"/api/frame/{slug}?via=model_read")
    if status == 404:
        raise FrameError(f"no artifact {slug} on this account", status, data)
    if status != 200 or not isinstance(data, dict):
        raise FrameError(f"could not read {slug}: HTTP {status}", status, data)
    return data


def frames(session, limit=200):
    status, data, _ = session.request("GET", f"/api/frame/frames?limit={limit}")
    if status != 200 or not isinstance(data, dict):
        raise FrameError(f"could not list frames: HTTP {status}", status, data)
    return data.get("frames", [])


def delete(session, slug):
    status, data, _ = session.request("DELETE", f"/api/frame/{slug}")
    if status not in (200, 204):
        raise FrameError(f"delete failed: HTTP {status} {str(data)[:200]}", status, data)
    return True


def content(session, slug, ver, asset_token=None):
    """Fetch the served page from the content origin.

    A private frame needs the asset token, which is a bearer capability lasting
    about an hour. A public frame at its pinned version serves without one.
    """
    host = CONTENT_HOST.format(slug=slug)
    path = f"/_f/{ver}/"
    if asset_token:
        from urllib.parse import quote
        path += f"?__frame_t={quote(asset_token)}"
    conn = http.client.HTTPSConnection(host, timeout=session.timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": UA,
                                           "Accept-Encoding": "gzip",
                                           "Host": host})
        resp = conn.getresponse()
        raw = resp.read()
        if resp.getheader("Content-Encoding") == "gzip" and raw:
            raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
        if resp.status != 200:
            raise FrameError(f"content origin returned {resp.status}", resp.status)
        return raw.decode("utf-8", "replace")
    finally:
        conn.close()


def is_public(slug, ver):
    """Ask the content origin without credentials. This is the CLI's own test."""
    host = CONTENT_HOST.format(slug=slug)
    conn = http.client.HTTPSConnection(host, timeout=20)
    try:
        conn.request("GET", f"/_f/{ver}/", headers={"User-Agent": UA, "Host": host})
        return conn.getresponse().status == 200
    except (http.client.HTTPException, OSError):
        return False
    finally:
        conn.close()


def set_audience(session, slug, mode, attempts=5, on_wait=None):
    """Move a frame between owner-only and public.

    Publishing cannot do this: no deploy endpoint accepts a visibility field and
    the control plane rejects unknown ones. It is always a second request.

    `shared` is a version pin rather than a flag, so this also advances the pin
    whenever it lags the live version. Without that, a redeploy leaves readers
    on the old content and the new version unreadable to them.
    """
    record = boot(session, slug)
    perm = record.get("perm") or {}
    if perm.get("role") != "owner":
        raise FrameError(f"you are '{perm.get('role')}' here, not the owner")

    if mode == "public":
        allowed = perm.get("assignableReadModes")
        can = ("public" in allowed if isinstance(allowed, list)
               else perm.get("externalSharingEnabled") is True)
        if not can:
            raise FrameError("this account cannot share artifacts publicly "
                             f"(assignable: {', '.join(allowed or []) or 'none'})")
        if record.get("mcpDeclared"):
            raise FrameError("this artifact declares connectors and cannot be public")

    live = record.get("live") or record.get("ver")
    body = {}
    if perm.get("mode") != mode:
        body["read"] = {"mode": mode, "users": perm.get("users") or []}
    if mode == "public" and record.get("shared") != live:
        body["shared"] = live
    if not body:
        return live

    org = org_uuid(session)
    from urllib.parse import quote
    paths = [f"/api/frame/perm/{slug}?org={quote(org)}", f"/api/frame/perm/{slug}"]
    version = perm.get("version")

    for attempt in range(1, attempts + 1):
        status, data, _ = session.request(
            "PATCH", paths[0], body, headers={"If-Match": version or None})
        if status == 400 and len(paths) > 1:
            paths.pop(0)
            continue
        if 200 <= status < 300:
            return body.get("shared") or record.get("shared") or live
        if status == 412 and isinstance(data, dict) and data.get("version"):
            version = data["version"]
            continue
        reason = data.get("reason") if isinstance(data, dict) else None
        if status == 409 and reason in RETRYABLE and attempt < attempts:
            wait = min(3 * 2 ** (attempt - 1), 60)
            if on_wait:
                on_wait(reason, wait, attempt, attempts - 1)
            time.sleep(wait)
            continue
        if status == 409:
            raise FrameError(f"refused: {reason or str(data)[:200]}", status, data)
        raise FrameError(f"perm update failed: HTTP {status} {str(data)[:200]}", status, data)
    raise FrameError("gave up waiting for the artifact to become shareable")

"""Publish a file as a Claude Artifact.

    python3 -m clawdvert.publish page.html --favicon 📊
    python3 -m clawdvert.publish page.html --surface chat --browser-port 9222 \
      --account-email-sha256 <sha256> --organization-uuid <uuid> \
      --receipt standard-artifact.json
    python3 -m clawdvert.publish page.html --slug <uuid>      replace in place
    python3 -m clawdvert.publish --public --slug <uuid>       change who can read it
"""

import argparse
import fcntl
import hashlib
import html
import json
import os
import re
import stat
import sys

try:
    from . import frames
    from .frames import FrameError
except ImportError:  # invoked as a path rather than with -m
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from clawdvert import frames
    from clawdvert.frames import FrameError

# Claude Code reads only the first 8 KB, ignores comments, and stops at the
# first <svg> so an icon's accessibility title cannot win. Titles are collapsed
# and capped at 280 codepoints.
HEAD_BYTES = 8192
TITLE_MAX = 280


def normalise_title(s):
    if not s:
        return None
    s = "".join(" " if ord(c) <= 31 or 127 <= ord(c) <= 159 else c for c in s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:TITLE_MAX] if s else None


def document_title(body):
    head = re.sub(r"<!--[\s\S]*?(?:-->|$)", "", body[:HEAD_BYTES])
    svg = re.search(r"<svg", head, re.I)
    if svg:
        head = head[:svg.start()]
    m = re.search(r"<title[^>]*>([\s\S]*?)</title>", head, re.I)
    return normalise_title(html.unescape(m.group(1))) if m else None


def to_html(path):
    """HTML passes through. Markdown is rendered if the package is available."""
    try:
        with open(path, encoding="utf-8", newline="") as handle:
            text = handle.read()
    except UnicodeDecodeError:
        raise FrameError(f"{path} is not valid UTF-8")
    low = path.lower()
    if low.endswith((".html", ".htm")):
        return text
    if low.endswith((".md", ".markdown")):
        try:
            import markdown
        except ImportError:
            raise FrameError("markdown input needs `pip install markdown`, "
                             "or pre-render to HTML")
        return markdown.markdown(text, extensions=["fenced_code", "tables"])
    raise FrameError(f"unsupported extension: {path}")


def report_public(slug, ver):
    """Do not trust the PATCH. Ask the content origin with no credentials."""
    if ver and frames.is_public(slug, ver):
        print(f"public: anyone with the link can read version {ver}", file=sys.stderr)
    else:
        print(f"warning: audience changed but version {ver} is not served publicly "
              f"yet. Content review can lag. Re-check:\n"
              f"  curl -so /dev/null -w '%{{http_code}}\\n' "
              f"https://{slug}.frame.claudeusercontent.com/_f/{ver}/", file=sys.stderr)


def code_dry_run_headers():
    """Return the Code request headers without resolving any credentials."""

    return {
        "Host": frames.API_HOST,
        "User-Agent": frames.UA,
        "Authorization": "Bearer <REDACTED>",
        "anthropic-beta": "oauth-2025-04-20",
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip",
        "Connection": "keep-alive",
        "X-Frame-CP": "go",
        "X-Frame-Surface": "code",
        "X-Frame-Platform": "cli",
    }


def build_parser():
    p = argparse.ArgumentParser(
        prog="clawdvert.publish",
        description="Publish a file as a Claude Code or standard chat Artifact.")
    p.add_argument("file", nargs="?", help=".html or .md file to publish")
    p.add_argument(
        "--surface",
        choices=("code", "chat"),
        default="code",
        help="code uses the Frame API (default); chat creates a standard Artifact",
    )
    p.add_argument(
        "--browser-port",
        type=int,
        default=None,
        help="local Chrome debugging port for --surface chat (default: 9222)",
    )
    p.add_argument(
        "--account-email-sha256",
        help="lowercase email SHA-256; required for live chat operations",
    )
    p.add_argument(
        "--chat-adapter",
        choices=("conversation", "seeded-public", "native-share"),
        default=None,
        help=(
            "standard-Artifact adapter: verified generated-file conversation "
            "(default), experimental model-free seeded publication, or the "
            "experimental native Cowork share-from-content capability"
        ),
    )
    p.add_argument(
        "--organization-uuid",
        help="exact organization UUID required by live standard-Artifact operations",
    )
    p.add_argument(
        "--native-session-ref-file",
        help=(
            "mode-0600 file containing one registered native Cowork session "
            "reference; never printed"
        ),
    )
    p.add_argument(
        "--seed-file",
        help=(
            "seeded-public: exact original HTML of the active public seed; "
            "required for creation and lifecycle verification"
        ),
    )
    p.add_argument(
        "--seed-receipt",
        help=(
            "seeded-public creation: owner-only published conversation receipt "
            "for the seed"
        ),
    )
    p.add_argument(
        "--receipt",
        help=(
            "owner-only standard-Artifact lifecycle receipt; required for "
            "conversation and seeded-public lifecycle operations, and for "
            "native-share public/private operations"
        ),
    )
    p.add_argument(
        "--wait-seconds",
        type=float,
        default=None,
        help="maximum chat Artifact generation wait (default: 240)",
    )
    p.add_argument(
        "--acknowledge-chat-preview-executes",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    p.add_argument(
        "--acknowledge-experimental-seeded-public",
        action="store_true",
        help=(
            "confirm seeded-public's experimental public-only content model "
            "and at-most-once lifecycle"
        ),
    )
    p.add_argument("--title", help="overridden by a <title> in the document")
    p.add_argument("--description", default="", help="Code surface: gallery subtitle")
    p.add_argument("--favicon", default="\U0001f4c4", help="Code surface: one or two emoji")
    p.add_argument("--label", help="Code surface: version-picker label")
    p.add_argument("--url", help="Code surface: existing Artifact URL to replace")
    p.add_argument("--slug", help="Code surface: existing Artifact slug to replace")
    p.add_argument(
        "--public", action="store_true",
        help="create a public mapping and verify its surface-specific postconditions",
    )
    p.add_argument(
        "--private", action="store_true",
        help="revoke the exact public mapping bound by the selected surface",
    )
    p.add_argument(
        "--delete",
        action="store_true",
        help="delete a Code Artifact or the exact receipt-bound chat conversation",
    )
    p.add_argument("--dry-run", action="store_true",
                   help="print the request with the token redacted, send nothing")
    return p


def _read_native_session_ref(path):
    """Read one sensitive native reference without following a symlink."""

    if not path:
        raise FrameError("--chat-adapter native-share requires --native-session-ref-file")
    try:
        before = os.lstat(path)
    except OSError:
        raise FrameError("native session reference file is unavailable") from None
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise FrameError("native session reference must be an owner-only regular file")
    if before.st_uid != os.getuid() or before.st_mode & 0o077:
        raise FrameError("native session reference file must be owned by this user and mode 0600")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            after = os.fstat(descriptor)
            if (
                not stat.S_ISREG(after.st_mode)
                or before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or after.st_uid != os.getuid()
                or after.st_mode & 0o077
                or after.st_size > 512
            ):
                raise FrameError("native session reference file changed or is too large")
            raw = os.read(descriptor, 513)
        finally:
            os.close(descriptor)
    except FrameError:
        raise
    except OSError:
        raise FrameError("native session reference file could not be read safely") from None
    try:
        value = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError:
        raise FrameError("native session reference file is not valid UTF-8") from None
    if not value or any(character.isspace() for character in value):
        raise FrameError("native session reference file must contain exactly one reference")
    return value


NATIVE_RECEIPT_SCHEMA = "clawdvert.native-standard-public.v1"


def _read_native_receipt(path, expected_organization_uuid):
    """Read one owner-only public mapping receipt without following a symlink."""

    if not path:
        raise FrameError("native-share public lifecycle requires --receipt")
    try:
        before = os.lstat(path)
    except OSError:
        raise FrameError("native-share receipt is unavailable") from None
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise FrameError("native-share receipt must be an owner-only regular file")
    if before.st_uid != os.getuid() or before.st_mode & 0o077:
        raise FrameError("native-share receipt must be owned by this user and mode 0600")
    flags = os.O_RDONLY | (getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
        try:
            after = os.fstat(descriptor)
            if (
                not stat.S_ISREG(after.st_mode)
                or before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or after.st_uid != os.getuid()
                or after.st_mode & 0o077
                or after.st_size > 4096
            ):
                raise FrameError("native-share receipt changed or is too large")
            raw = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
    except FrameError:
        raise
    except OSError:
        raise FrameError("native-share receipt could not be read safely") from None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise FrameError("native-share receipt is not valid JSON") from None
    expected_keys = {
        "schema",
        "organization_uuid",
        "artifact_uuid",
        "version_uuid",
        "message_uuid",
        "published_uuid",
        "source_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise FrameError("native-share receipt has an unsupported shape")
    from . import chat_direct_publish

    if value.get("schema") != NATIVE_RECEIPT_SCHEMA:
        raise FrameError("native-share receipt has an unsupported schema")
    if value.get("organization_uuid") != expected_organization_uuid:
        raise FrameError("native-share receipt belongs to a different organization")
    for field in ("artifact_uuid", "version_uuid", "message_uuid", "published_uuid"):
        if not isinstance(value.get(field), str) or not chat_direct_publish.UUID_RE.fullmatch(
            value[field]
        ):
            raise FrameError("native-share receipt contains an invalid provider identifier")
    digest = value.get("source_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise FrameError("native-share receipt contains an invalid source digest")
    published_uuid = value["published_uuid"]
    return chat_direct_publish.NativeShareResult(
        url="https://claude.ai/public/artifacts/" + published_uuid,
        artifact_uuid=value["artifact_uuid"],
        version_uuid=value["version_uuid"],
        message_uuid=value["message_uuid"],
        source_sha256=digest,
        public=True,
        published_uuid=published_uuid,
    )


def _write_native_receipt(path, organization_uuid, result):
    """Create one non-overwriting, owner-only public lifecycle receipt."""

    if not path:
        raise FrameError("native-share --public requires --receipt")
    payload = json.dumps(
        {
            "schema": NATIVE_RECEIPT_SCHEMA,
            "organization_uuid": organization_uuid,
            "artifact_uuid": result.artifact_uuid,
            "version_uuid": result.version_uuid,
            "message_uuid": result.message_uuid,
            "published_uuid": result.published_uuid,
            "source_sha256": result.source_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if count <= 0:
                    raise OSError("short receipt write")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise FrameError(
            "public Artifact was created but its receipt could not be written; "
            "cleanup identifiers: artifact="
            + result.artifact_uuid
            + ", version="
            + result.version_uuid
            + ", message="
            + result.message_uuid
            + ", published="
            + str(result.published_uuid)
        ) from None


def _validate_new_native_receipt(path):
    if not path:
        raise FrameError("native-share --public requires --receipt")
    if os.path.lexists(path):
        raise FrameError("native-share receipt already exists; refusing to overwrite it")
    parent = os.path.dirname(os.path.abspath(path)) or os.curdir
    try:
        status = os.stat(parent)
    except OSError:
        raise FrameError("native-share receipt directory is unavailable") from None
    if not stat.S_ISDIR(status.st_mode):
        raise FrameError("native-share receipt parent is not a directory")


CONVERSATION_RECEIPT_SCHEMA = "clawdvert.conversation-standard.v2"
CONVERSATION_RECEIPT_MAX_BYTES = 65536


def _open_conversation_receipt_parent(path):
    """Pin the receipt's final parent directory without following it as a symlink."""

    absolute = os.path.abspath(path)
    parent = os.path.dirname(absolute) or os.curdir
    basename = os.path.basename(absolute)
    if not basename or basename in {".", ".."}:
        raise FrameError("conversation receipt filename is invalid")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = None
    try:
        descriptor = os.open(parent, flags)
        status = os.fstat(descriptor)
        if not stat.S_ISDIR(status.st_mode):
            raise OSError("not a directory")
    except OSError:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise FrameError("conversation receipt directory is unavailable") from None
    return absolute, descriptor, basename


class _ConversationReceiptJournal:
    """Durable owner-only state for a conversation-backed publication."""

    def __init__(
        self,
        path,
        *,
        organization_uuid,
        account_email_sha256,
        source,
        output_path,
        request_title,
        prompt_sha256,
        requested_public,
    ):
        if not path:
            raise FrameError("conversation operations require --receipt")
        if type(requested_public) is not bool:
            raise FrameError("conversation receipt publication intent is invalid")
        self.path, self._parent_descriptor, self._basename = (
            _open_conversation_receipt_parent(path)
        )
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_APPEND
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = None
        try:
            descriptor = os.open(
                self._basename,
                flags,
                0o600,
                dir_fd=self._parent_descriptor,
            )
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            os.close(self._parent_descriptor)
            raise FrameError(
                "conversation receipt already exists or could not be created safely"
            ) from None
        self._descriptor = descriptor
        created_status = os.fstat(self._descriptor)
        self._device = created_status.st_dev
        self._inode = created_status.st_ino
        source_bytes = source.encode("utf-8")
        self._value = {
            "schema": CONVERSATION_RECEIPT_SCHEMA,
            "stage": "prepared",
            "organization_uuid": organization_uuid,
            "account_email_sha256": account_email_sha256,
            "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "source_bytes": len(source_bytes),
            "output_path": output_path,
            "request_title": request_title,
            "prompt_sha256": prompt_sha256,
            "requested_public": requested_public,
            "chat_url": None,
            "conversation_uuid": None,
            "artifact_uuid": None,
            "version_uuid": None,
            "message_uuid": None,
            "artifact_identifier": None,
            "artifact_type": None,
            "code_language": None,
            "title": None,
            "published_uuid": None,
            "public_url": None,
        }
        try:
            self._flush()
            os.fsync(self._parent_descriptor)
        except Exception:
            os.close(self._descriptor)
            os.close(self._parent_descriptor)
            self._descriptor = None
            self._parent_descriptor = None
            raise

    def _flush(self):
        payload = (
            json.dumps(self._value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        if len(payload) > 8192:
            raise FrameError("conversation receipt exceeded its size limit")
        try:
            status = os.fstat(self._descriptor)
            path_status = os.stat(
                self._basename,
                dir_fd=self._parent_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_uid != os.getuid()
                or status.st_mode & 0o077
                or path_status.st_dev != self._device
                or path_status.st_ino != self._inode
                or stat.S_ISLNK(path_status.st_mode)
                or status.st_size + len(payload) > CONVERSATION_RECEIPT_MAX_BYTES
            ):
                raise FrameError("conversation receipt lost its owner-only boundary")
            os.lseek(self._descriptor, 0, os.SEEK_END)
            written = 0
            while written < len(payload):
                count = os.write(self._descriptor, payload[written:])
                if count <= 0:
                    raise OSError("short receipt write")
                written += count
            os.fsync(self._descriptor)
        except FrameError:
            raise
        except OSError:
            raise FrameError(
                "conversation receipt could not be durably updated"
            ) from None

    @staticmethod
    def _binding_fields(binding):
        return {
            "chat_url": binding.chat_url,
            "conversation_uuid": binding.conversation_uuid,
            "artifact_uuid": binding.artifact_uuid,
            "version_uuid": binding.version_uuid,
            "message_uuid": binding.message_uuid,
            "artifact_identifier": binding.artifact_identifier,
            "artifact_type": binding.artifact_type,
            "code_language": binding.code_language,
            "title": binding.title,
        }

    def record_conversation(self, conversation_binding):
        if (
            self._value["stage"] != "prepared"
            or conversation_binding.organization_uuid
            != self._value["organization_uuid"]
        ):
            raise FrameError("conversation receipt binding changed")
        self._value.update(
            {
                "stage": "conversation_bound",
                "chat_url": conversation_binding.chat_url,
                "conversation_uuid": conversation_binding.conversation_uuid,
            }
        )
        self._flush()

    def record_file(self, file_binding):
        if (
            self._value["stage"] != "conversation_bound"
            or file_binding.organization_uuid != self._value["organization_uuid"]
            or file_binding.output_path != self._value["output_path"]
            or file_binding.chat_url != self._value["chat_url"]
            or file_binding.conversation_uuid != self._value["conversation_uuid"]
        ):
            raise FrameError("conversation file receipt binding changed")
        self._value["stage"] = "file_bound"
        self._flush()

    def record_conversion_intent(self):
        """Durably close the pre-conversion cleanup window before the POST."""

        if self._value["stage"] != "file_bound":
            raise FrameError("conversation conversion intent was not file-bound")
        self._value["stage"] = "conversion_pending"
        self._flush()

    def record_binding(self, binding):
        if (
            self._value["stage"] != "conversion_pending"
            or binding.organization_uuid != self._value["organization_uuid"]
            or (
                self._value["conversation_uuid"] is not None
                and binding.conversation_uuid != self._value["conversation_uuid"]
            )
        ):
            raise FrameError("conversation Artifact receipt binding changed")
        self._value.update(self._binding_fields(binding))
        self._value["stage"] = "converted"
        self._flush()

    def record_published(self, binding, published_uuid):
        if self._value["stage"] != "converted":
            raise FrameError("conversation public receipt was not conversion-bound")
        for key, value in self._binding_fields(binding).items():
            if self._value[key] != value:
                raise FrameError("conversation public receipt binding changed")
        if not isinstance(published_uuid, str) or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            published_uuid,
        ):
            raise FrameError("conversation publisher returned an invalid public identifier")
        self._value.update(
            {
                "stage": "public_bound",
                "published_uuid": published_uuid,
                "public_url": "https://claude.ai/public/artifacts/" + published_uuid,
            }
        )
        self._flush()

    def record_complete(self, result):
        expected = self._binding_fields(result)
        for key, value in expected.items():
            if self._value[key] != value:
                raise FrameError("conversation completion receipt binding changed")
        if result.source_sha256 != self._value["source_sha256"]:
            raise FrameError("conversation completion source digest changed")
        if result.output_path != self._value["output_path"]:
            raise FrameError("conversation completion output path changed")
        if result.prompt_sha256 != self._value["prompt_sha256"]:
            raise FrameError("conversation completion prompt digest changed")
        if result.public:
            if (
                self._value["stage"] != "public_bound"
                or result.published_uuid != self._value["published_uuid"]
                or result.url != self._value["public_url"]
            ):
                raise FrameError("conversation public completion binding changed")
            self._value["stage"] = "published"
        else:
            if (
                self._value["stage"] != "converted"
                or result.published_uuid is not None
                or result.url != result.chat_url
            ):
                raise FrameError("conversation private completion binding changed")
            self._value["stage"] = "private"
        self._flush()

    def close(self):
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None
        if self._parent_descriptor is not None:
            os.close(self._parent_descriptor)
            self._parent_descriptor = None


_CONVERSATION_RECEIPT_KEYS = {
    "schema",
    "stage",
    "organization_uuid",
    "account_email_sha256",
    "source_sha256",
    "source_bytes",
    "output_path",
    "request_title",
    "prompt_sha256",
    "requested_public",
    "chat_url",
    "conversation_uuid",
    "artifact_uuid",
    "version_uuid",
    "message_uuid",
    "artifact_identifier",
    "artifact_type",
    "code_language",
    "title",
    "published_uuid",
    "public_url",
}
_CONVERSATION_CORE_STAGES = {
    "conversion_bound",
    "privacy_pending",
    "converted",
    "private",
    "public_bound",
    "published",
    "unpublished",
    "deleted",
}
_CONVERSATION_PRECONVERSION_STAGES = {"conversation_bound", "file_bound"}
_CONVERSATION_PUBLIC_STAGES = {"public_bound", "published", "unpublished"}
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


def _safe_receipt_text(value, *, allow_empty=False):
    return (
        isinstance(value, str)
        and len(value) <= 1000
        and (allow_empty or bool(value))
        and re.search(r"[\x00-\x1f\x7f]", value) is None
    )


class _ConversationReceiptLifecycle:
    """Hold and validate one owner-only receipt for a lifecycle mutation."""

    def __init__(
        self,
        path,
        *,
        organization_uuid,
        account_email_sha256,
        source,
        repair_partial_tail=True,
    ):
        if not path:
            raise FrameError("conversation lifecycle requires --receipt")
        self.path, self._parent_descriptor, self._basename = (
            _open_conversation_receipt_parent(path)
        )
        try:
            before = os.stat(
                self._basename,
                dir_fd=self._parent_descriptor,
                follow_symlinks=False,
            )
        except OSError:
            os.close(self._parent_descriptor)
            self._parent_descriptor = None
            raise FrameError("conversation receipt is unavailable") from None
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            os.close(self._parent_descriptor)
            self._parent_descriptor = None
            raise FrameError("conversation receipt must be an owner-only regular file")
        if before.st_uid != os.getuid() or before.st_mode & 0o077:
            os.close(self._parent_descriptor)
            self._parent_descriptor = None
            raise FrameError("conversation receipt must be owned by this user and mode 0600")
        flags = (
            (os.O_RDWR | os.O_APPEND)
            if repair_partial_tail
            else os.O_RDONLY
        ) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = None
        try:
            descriptor = os.open(
                self._basename,
                flags,
                dir_fd=self._parent_descriptor,
            )
            fcntl.flock(
                descriptor,
                (fcntl.LOCK_EX if repair_partial_tail else fcntl.LOCK_SH)
                | fcntl.LOCK_NB,
            )
        except OSError:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            os.close(self._parent_descriptor)
            self._parent_descriptor = None
            raise FrameError("conversation receipt could not be opened safely") from None
        self._descriptor = descriptor
        self._device = before.st_dev
        self._inode = before.st_ino
        try:
            after = os.fstat(descriptor)
            if (
                not stat.S_ISREG(after.st_mode)
                or before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or after.st_uid != os.getuid()
                or after.st_mode & 0o077
                or after.st_size > CONVERSATION_RECEIPT_MAX_BYTES
            ):
                raise FrameError("conversation receipt changed or is too large")
            raw = os.read(descriptor, CONVERSATION_RECEIPT_MAX_BYTES + 1)
            if len(raw) > CONVERSATION_RECEIPT_MAX_BYTES:
                raise FrameError("conversation receipt is too large")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise FrameError("conversation receipt is not valid JSON") from None
            records = []
            valid_size = 0
            for line in text.splitlines(keepends=True):
                if not line.endswith("\n"):
                    break
                valid_size += len(line.encode("utf-8"))
                try:
                    record = json.loads(line)
                except ValueError:
                    raise FrameError("conversation receipt journal is not valid JSON") from None
                records.append(
                    self._validate(
                        record,
                        organization_uuid=organization_uuid,
                        account_email_sha256=account_email_sha256,
                        source=source,
                    )
                )
            if not records or records[0]["stage"] != "prepared":
                raise FrameError("conversation receipt journal has no prepared record")
            self._validate_history(records)
            self._partial_tail_size = len(raw) - valid_size
            if valid_size != len(raw) and repair_partial_tail:
                os.ftruncate(descriptor, valid_size)
                os.fsync(descriptor)
                self._partial_tail_size = 0
            self._value = records[-1]
        except Exception:
            os.close(descriptor)
            os.close(self._parent_descriptor)
            self._descriptor = None
            self._parent_descriptor = None
            raise

    @property
    def has_partial_tail(self):
        return bool(getattr(self, "_partial_tail_size", 0))

    @staticmethod
    def _validate(value, *, organization_uuid, account_email_sha256, source):
        from . import chat_publish

        if not isinstance(value, dict) or set(value) != _CONVERSATION_RECEIPT_KEYS:
            raise FrameError("conversation receipt has an unsupported shape")
        if value.get("schema") != CONVERSATION_RECEIPT_SCHEMA:
            raise FrameError("conversation receipt has an unsupported schema")
        stages = {
            "prepared",
            *_CONVERSATION_PRECONVERSION_STAGES,
            "conversion_pending",
            *_CONVERSATION_CORE_STAGES,
        }
        stage = value.get("stage")
        if stage not in stages:
            raise FrameError("conversation receipt has an unsupported stage")
        if value.get("organization_uuid") != organization_uuid or not _UUID_RE.fullmatch(
            organization_uuid or ""
        ):
            raise FrameError("conversation receipt belongs to a different organization")
        if (
            not isinstance(account_email_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", account_email_sha256)
            or value.get("account_email_sha256") != account_email_sha256
        ):
            raise FrameError("conversation receipt belongs to a different account binding")
        source_bytes = source.encode("utf-8")
        if (
            value.get("source_bytes") != len(source_bytes)
            or value.get("source_sha256") != hashlib.sha256(source_bytes).hexdigest()
        ):
            raise FrameError("conversation receipt does not match the input source")
        request_title = value.get("request_title")
        if not _safe_receipt_text(request_title) or normalise_title(request_title) != request_title:
            raise FrameError("conversation receipt contains an invalid request title")
        output_path = value.get("output_path")
        if output_path != chat_publish.generated_output_path(source, request_title):
            raise FrameError("conversation receipt output path does not match the source")
        prompt = chat_publish.build_prompt(source, request_title, output_path)
        if value.get("prompt_sha256") != hashlib.sha256(prompt.encode("utf-8")).hexdigest():
            raise FrameError("conversation receipt prompt provenance is invalid")
        if type(value.get("requested_public")) is not bool:
            raise FrameError("conversation receipt publication intent is invalid")

        provider_fields = (
            "conversation_uuid",
            "artifact_uuid",
            "version_uuid",
            "message_uuid",
        )
        if stage == "prepared":
            nullable = provider_fields + (
                "chat_url",
                "artifact_identifier",
                "artifact_type",
                "code_language",
                "title",
                "published_uuid",
                "public_url",
            )
            if any(value.get(field) is not None for field in nullable):
                raise FrameError("prepared conversation receipt contains remote state")
            return value
        if not _UUID_RE.fullmatch(value.get("conversation_uuid") or ""):
            raise FrameError("conversation receipt contains an invalid conversation UUID")
        if value.get("chat_url") != (
            "https://claude.ai/chat/" + value["conversation_uuid"]
        ):
            raise FrameError("conversation receipt contains an invalid chat URL")
        if stage in {*_CONVERSATION_PRECONVERSION_STAGES, "conversion_pending"}:
            nullable = (
                "artifact_uuid",
                "version_uuid",
                "message_uuid",
                "artifact_identifier",
                "artifact_type",
                "code_language",
                "title",
                "published_uuid",
                "public_url",
            )
            if any(value.get(field) is not None for field in nullable):
                raise FrameError("conversation-bound receipt contains unbound Artifact state")
            return value
        if stage == "deleted" and value.get("artifact_uuid") is None:
            nullable = (
                "artifact_uuid",
                "version_uuid",
                "message_uuid",
                "artifact_identifier",
                "artifact_type",
                "code_language",
                "title",
                "published_uuid",
                "public_url",
            )
            if any(value.get(field) is not None for field in nullable):
                raise FrameError(
                    "pre-conversion deleted receipt contains Artifact state"
                )
            return value
        for field in provider_fields[1:]:
            if not _UUID_RE.fullmatch(value.get(field) or ""):
                raise FrameError("conversation receipt contains an invalid provider UUID")
        if not _safe_receipt_text(value.get("artifact_identifier")):
            raise FrameError("conversation receipt contains an invalid Artifact identifier")
        if not _safe_receipt_text(value.get("artifact_type")):
            raise FrameError("conversation receipt contains an invalid Artifact type")
        if value.get("code_language") is not None and not _safe_receipt_text(
            value.get("code_language"), allow_empty=True
        ):
            raise FrameError("conversation receipt contains an invalid code language")
        if not _safe_receipt_text(value.get("title")):
            raise FrameError("conversation receipt contains an invalid Artifact title")
        if stage in _CONVERSATION_PUBLIC_STAGES or (
            stage == "deleted" and value.get("published_uuid") is not None
        ):
            if not _UUID_RE.fullmatch(value.get("published_uuid") or ""):
                raise FrameError("conversation receipt contains an invalid public UUID")
            if value.get("public_url") != (
                "https://claude.ai/public/artifacts/" + value["published_uuid"]
            ):
                raise FrameError("conversation receipt contains an invalid public URL")
        elif value.get("published_uuid") is not None or value.get("public_url") is not None:
            raise FrameError("private conversation receipt contains a public mapping")
        return value

    @staticmethod
    def _validate_history(records):
        transitions = {
            "prepared": {"conversation_bound"},
            "conversation_bound": {"file_bound", "deleted"},
            "file_bound": {"conversion_pending", "deleted"},
            "conversion_pending": {"conversion_bound", "converted"},
            "conversion_bound": {"privacy_pending"},
            "privacy_pending": {"private"},
            "converted": {"private", "public_bound", "deleted"},
            "private": {"deleted"},
            "public_bound": {"published", "unpublished"},
            "published": {"unpublished"},
            "unpublished": {"deleted"},
            "deleted": set(),
        }
        immutable = {
            "schema",
            "organization_uuid",
            "account_email_sha256",
            "source_sha256",
            "source_bytes",
            "output_path",
            "request_title",
            "prompt_sha256",
            "requested_public",
        }
        progressive = _CONVERSATION_RECEIPT_KEYS - immutable - {"stage"}
        for before, after in zip(records, records[1:]):
            if after["stage"] not in transitions.get(before["stage"], set()):
                raise FrameError("conversation receipt journal has an invalid stage history")
            if any(before[key] != after[key] for key in immutable):
                raise FrameError("conversation receipt journal changed immutable provenance")
            for key in progressive:
                if before[key] is not None and before[key] != after[key]:
                    raise FrameError("conversation receipt journal changed a bound value")

    @property
    def stage(self):
        return self._value["stage"]

    @property
    def requested_public(self):
        return self._value["requested_public"]

    def preconversion_binding(self):
        from . import chat_publish

        if self.stage not in _CONVERSATION_PRECONVERSION_STAGES:
            raise FrameError(
                "conversation receipt is not safely pre-conversion; "
                f"current stage: {self.stage}"
            )
        return chat_publish.ChatPreconversionBinding(
            chat_url=self._value["chat_url"],
            organization_uuid=self._value["organization_uuid"],
            conversation_uuid=self._value["conversation_uuid"],
            output_path=self._value["output_path"],
            request_title=self._value["request_title"],
            source_sha256=self._value["source_sha256"],
            prompt_sha256=self._value["prompt_sha256"],
            receipt_stage=self.stage,
        )

    def conversion_pending_binding(self):
        from . import chat_publish

        if self.stage != "conversion_pending":
            raise FrameError(
                "conversation receipt is not pending conversion reconciliation"
            )
        return chat_publish.ChatPreconversionBinding(
            chat_url=self._value["chat_url"],
            organization_uuid=self._value["organization_uuid"],
            conversation_uuid=self._value["conversation_uuid"],
            output_path=self._value["output_path"],
            request_title=self._value["request_title"],
            source_sha256=self._value["source_sha256"],
            prompt_sha256=self._value["prompt_sha256"],
            receipt_stage=self.stage,
        )

    def result(self):
        from . import chat_publish

        if self.stage not in _CONVERSATION_CORE_STAGES or (
            self.stage == "deleted" and self._value["artifact_uuid"] is None
        ):
            raise FrameError(
                "conversation receipt has no exact converted Artifact binding; "
                f"current stage: {self.stage}"
            )
        public = self.stage in {"public_bound", "published"}
        published_deleted = self.stage in {"unpublished", "deleted"} and (
            self._value["published_uuid"] is not None
        )
        return chat_publish.ChatPublishResult(
            url=self._value["public_url"] if public else self._value["chat_url"],
            chat_url=self._value["chat_url"],
            artifact_uuid=self._value["artifact_uuid"],
            version_uuid=self._value["version_uuid"],
            public=public,
            source_sha256=self._value["source_sha256"],
            published_uuid=self._value["published_uuid"],
            organization_uuid=self._value["organization_uuid"],
            conversation_uuid=self._value["conversation_uuid"],
            message_uuid=self._value["message_uuid"],
            artifact_identifier=self._value["artifact_identifier"],
            artifact_type=self._value["artifact_type"],
            code_language=self._value["code_language"],
            title=self._value["title"],
            output_path=self._value["output_path"],
            prompt_sha256=self._value["prompt_sha256"],
            published_deleted=published_deleted,
        )

    def _append_current(self):
        payload = (
            json.dumps(self._value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        try:
            status = os.fstat(self._descriptor)
            path_status = os.stat(
                self._basename,
                dir_fd=self._parent_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_uid != os.getuid()
                or status.st_mode & 0o077
                or path_status.st_dev != self._device
                or path_status.st_ino != self._inode
                or stat.S_ISLNK(path_status.st_mode)
                or len(payload) > 8192
                or status.st_size + len(payload) > CONVERSATION_RECEIPT_MAX_BYTES
            ):
                raise FrameError("conversation receipt lost its owner-only boundary")
            os.lseek(self._descriptor, 0, os.SEEK_END)
            written = 0
            while written < len(payload):
                count = os.write(self._descriptor, payload[written:])
                if count <= 0:
                    raise OSError("short receipt write")
                written += count
            os.fsync(self._descriptor)
        except FrameError:
            raise
        except OSError:
            raise FrameError("conversation receipt could not be durably updated") from None

    def record_reconciled(self, result):
        """Persist one read-only public-state reconciliation from ``converted``."""

        if self.stage != "converted":
            raise FrameError(
                "conversation public reconciliation requires a converted receipt"
            )
        expected = self.result()
        stable_fields = (
            "chat_url",
            "organization_uuid",
            "conversation_uuid",
            "artifact_uuid",
            "version_uuid",
            "message_uuid",
            "artifact_identifier",
            "artifact_type",
            "code_language",
            "title",
            "source_sha256",
            "output_path",
            "prompt_sha256",
        )
        if any(
            getattr(result, field, None) != getattr(expected, field)
            for field in stable_fields
        ):
            raise FrameError("conversation public reconciliation binding changed")
        if result.public:
            if not self.requested_public:
                raise FrameError(
                    "a private-only conversation receipt cannot gain a public mapping"
                )
            if (
                result.published_deleted
                or not _UUID_RE.fullmatch(result.published_uuid or "")
                or result.url
                != "https://claude.ai/public/artifacts/" + result.published_uuid
            ):
                raise FrameError("conversation public reconciliation is invalid")
            self._value.update(
                {
                    "stage": "public_bound",
                    "published_uuid": result.published_uuid,
                    "public_url": result.url,
                }
            )
            self._append_current()
            return
        if result.published_deleted:
            if not self.requested_public:
                raise FrameError(
                    "a private-only conversation receipt cannot gain a public tombstone"
                )
            if (
                not _UUID_RE.fullmatch(result.published_uuid or "")
                or result.url != result.chat_url
            ):
                raise FrameError("conversation tombstone reconciliation is invalid")
            self._value.update(
                {
                    "stage": "public_bound",
                    "published_uuid": result.published_uuid,
                    "public_url": (
                        "https://claude.ai/public/artifacts/" + result.published_uuid
                    ),
                }
            )
            self._append_current()
            self._value["stage"] = "unpublished"
            self._append_current()
            return
        if (
            result.published_uuid is not None
            or result.url != result.chat_url
        ):
            raise FrameError("conversation private reconciliation is invalid")
        if self.requested_public:
            raise FrameError(
                "a public-intent receipt cannot infer private state from absence"
            )
        self._value["stage"] = "private"
        self._append_current()

    def record_conversion_reconciled(self, result):
        """Persist derived IDs before any recovered visibility mutation."""

        if self.stage != "conversion_pending":
            raise FrameError(
                "conversion binding reconciliation requires conversion_pending"
            )
        pending = self.conversion_pending_binding()
        stable = {
            "chat_url": pending.chat_url,
            "organization_uuid": pending.organization_uuid,
            "conversation_uuid": pending.conversation_uuid,
            "source_sha256": pending.source_sha256,
            "output_path": pending.output_path,
            "prompt_sha256": pending.prompt_sha256,
        }
        if any(getattr(result, key, None) != value for key, value in stable.items()):
            raise FrameError("reconciled conversion changed durable provenance")
        if (
            result.public
            or result.published_uuid is not None
            or result.published_deleted
            or result.url != result.chat_url
            or result.title != os.path.basename(pending.output_path)
        ):
            raise FrameError("reconciled conversion contains invalid public state")
        binding_fields = _ConversationReceiptJournal._binding_fields(result)
        provider_ids = (
            binding_fields["artifact_uuid"],
            binding_fields["version_uuid"],
            binding_fields["message_uuid"],
        )
        if not all(_UUID_RE.fullmatch(value or "") for value in provider_ids):
            raise FrameError("reconciled conversion contains invalid provider IDs")
        if not _safe_receipt_text(binding_fields["artifact_identifier"]):
            raise FrameError("reconciled conversion contains an invalid identifier")
        if not _safe_receipt_text(binding_fields["artifact_type"]):
            raise FrameError("reconciled conversion contains an invalid type")
        if binding_fields["code_language"] is not None and not _safe_receipt_text(
            binding_fields["code_language"], allow_empty=True
        ):
            raise FrameError("reconciled conversion contains an invalid language")
        if not _safe_receipt_text(binding_fields["title"]):
            raise FrameError("reconciled conversion contains an invalid title")
        self._value.update(binding_fields)
        self._value["stage"] = "conversion_bound"
        self._append_current()

    def mark_privacy_pending(self, result):
        """Record one at-most-once privacy mutation intent before its POST."""

        if self.stage != "conversion_bound" or self.result() != result:
            raise FrameError("conversion privacy intent binding changed")
        self._value["stage"] = "privacy_pending"
        self._append_current()

    def mark_conversion_private(self, result):
        """Advance a privacy-bound recovered conversion only after GET verification."""

        if self.stage != "privacy_pending" or self.result() != result:
            raise FrameError("conversion privacy receipt binding changed")
        self._value["stage"] = "private"
        self._append_current()

    def mark(self, stage):
        transitions = {
            "public_bound": {"unpublished"},
            "published": {"unpublished"},
            "converted": {"private", "deleted"},
            "private": {"deleted"},
            "unpublished": {"deleted"},
        }
        if stage not in transitions.get(self.stage, set()):
            raise FrameError(
                f"conversation receipt cannot move from {self.stage} to {stage}"
            )
        if stage == "private" and self.requested_public:
            raise FrameError(
                "a public-intent receipt cannot infer private state from absence"
            )
        self._value["stage"] = stage
        self._append_current()

    def mark_preconversion_deleted(self, binding):
        """Persist deletion only for the exact partial binding just verified."""

        if self.stage not in _CONVERSATION_PRECONVERSION_STAGES:
            raise FrameError(
                "pre-conversion deletion requires a conversation-bound receipt"
            )
        if binding != self.preconversion_binding():
            raise FrameError("pre-conversion deletion receipt binding changed")
        self._value["stage"] = "deleted"
        self._append_current()

    def close(self):
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None
        if self._parent_descriptor is not None:
            os.close(self._parent_descriptor)
            self._parent_descriptor = None


def _validate_new_conversation_receipt(path):
    if not path:
        raise FrameError("conversation operations require --receipt")
    _absolute, parent_descriptor, basename = _open_conversation_receipt_parent(path)
    try:
        try:
            os.stat(basename, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            raise FrameError("conversation receipt path could not be checked safely") from None
        raise FrameError("conversation receipt already exists; refusing to overwrite it")
    finally:
        os.close(parent_descriptor)


def _publish_seeded_public(args, target_source, browser_port):
    """Run the explicit public-only seed-backed Standard Artifact adapter."""

    from . import chat_seeded_publish
    from . import chat_seeded_receipt

    if not re.fullmatch(r"[0-9a-f]{64}", args.account_email_sha256 or ""):
        raise FrameError(
            "seeded-public operations require a lowercase email SHA-256 account binding"
        )
    chat_seeded_publish._validate_port(browser_port)
    seed_source = to_html(args.seed_file)
    chat_seeded_publish._source_bytes(seed_source, "seed source")
    chat_seeded_publish._source_bytes(target_source, "target source")

    target_receipt_exists = os.path.lexists(os.path.abspath(args.receipt))

    def record_unknown(receipt, error):
        clone_uuid = error.clone_conversation_uuid
        if error.clone is not None:
            clone_uuid = error.clone.conversation_uuid
        try:
            receipt.record_observations(
                clone_conversation_uuid=clone_uuid,
                published_uuid=(
                    error.observed_published_uuid or error.published_uuid
                ),
            )
        except FrameError as observation_error:
            try:
                error.add_note(str(observation_error))
            except AttributeError:
                pass

    def new_driver():
        return chat_seeded_publish.SeededPublicArtifactPublisher(
            browser_port,
            expected_email_sha256=args.account_email_sha256,
            organization_uuid=args.organization_uuid,
        )

    if args.public:
        seed = chat_seeded_receipt.load_seed_binding(
            args.seed_receipt,
            organization_uuid=args.organization_uuid,
            account_email_sha256=args.account_email_sha256,
            source=seed_source,
            read_only=args.dry_run,
        )
        existing = None
        if target_receipt_exists:
            existing = chat_seeded_receipt.SeededReceiptLifecycle(
                args.receipt,
                organization_uuid=args.organization_uuid,
                account_email_sha256=args.account_email_sha256,
                seed_source=seed_source,
                target_source=target_source,
            )
            if existing.seed != seed:
                existing.close()
                existing = None
                raise FrameError(
                    "seeded-public --seed-receipt does not match the target "
                    "receipt's durable seed binding"
                )
        else:
            chat_seeded_receipt.validate_new_receipt(args.receipt)
        try:
            if args.dry_run:
                stage = existing.stage if existing is not None else "new"
                plans = {
                    "new": ["clone_seed", "publish_exact_public_mapping"],
                    "prepared": ["clone_seed", "publish_exact_public_mapping"],
                    "remix_pending": ["reconcile_clone"],
                    "clone_bound": ["publish_exact_public_mapping"],
                    "publish_pending": ["reconcile_public_mapping"],
                    "publish_rejected": [
                        "no_publish_retry", "private_clone_retained"
                    ],
                    "public_bound": ["verify_public_mapping"],
                    "published": [],
                }
                print("DRY RUN, no browser opened and nothing sent.\n")
                print(json.dumps({
                    "surface": "chat",
                    "adapter": "seeded-public",
                    "operation": plans.get(stage, ["no_safe_public_resume"]),
                    "browserPort": browser_port,
                    "organizationUuidSha256": hashlib.sha256(
                        args.organization_uuid.encode("ascii")
                    ).hexdigest(),
                    "seedSourceBytes": len(seed_source.encode("utf-8")),
                    "seedSourceSha256": seed.source_sha256,
                    "targetSourceBytes": len(target_source.encode("utf-8")),
                    "targetSourceSha256": hashlib.sha256(
                        target_source.encode("utf-8")
                    ).hexdigest(),
                    "receipt": os.path.abspath(args.receipt),
                    "receiptStage": stage,
                    "seedReceiptPathSha256": hashlib.sha256(
                        os.path.abspath(args.seed_receipt).encode("utf-8")
                    ).hexdigest(),
                    "seedPreserved": True,
                }, indent=2, ensure_ascii=False))
                return

            if existing is not None and existing.has_partial_tail:
                raise FrameError(
                    "seeded-public receipt has a partial trailing record; "
                    "review and repair it explicitly before a live operation"
                )
            receipt = existing
            if receipt is None:
                receipt = chat_seeded_receipt.SeededReceiptJournal(
                    args.receipt, seed=seed, target_source=target_source
                )
            if receipt.stage == "publish_rejected":
                raise chat_seeded_publish.SeededCapabilityUnavailable(
                    "seeded-public publication was definitively rejected; the exact "
                    "private clone is retained and will not be republished automatically; "
                    "use --private to inspect it or --delete to remove it"
                )
            driver = new_driver()
            try:
                stage = receipt.stage
                if stage == "prepared":
                    result = driver.create_and_publish(
                        seed,
                        target_source,
                        on_remix_intent=receipt.mark_remix_pending,
                        on_clone_bound=receipt.record_clone,
                        on_publish_intent=receipt.mark_publish_pending,
                        on_publish_rejected=receipt.record_publish_rejected,
                        on_public_bound=receipt.record_public_bound,
                        on_published=receipt.mark_published,
                    )
                else:
                    if stage == "remix_pending":
                        observed = receipt.observed_clone_conversation_uuid
                        if observed is None:
                            raise FrameError(
                                "seeded-public remix is ambiguous and has no observed "
                                "clone conversation; preserve the receipt for manual review"
                            )
                        driver.reconcile_remix(
                            seed,
                            target_source,
                            observed,
                            on_clone_bound=receipt.record_clone,
                        )
                        stage = receipt.stage
                    if stage == "clone_bound":
                        result = driver.publish_clone(
                            receipt.clone_binding(),
                            target_source,
                            on_publish_intent=receipt.mark_publish_pending,
                            on_publish_rejected=receipt.record_publish_rejected,
                            on_public_bound=receipt.record_public_bound,
                            on_published=receipt.mark_published,
                        )
                    elif stage == "publish_pending":
                        result = driver.reconcile_publish(
                            receipt.clone_binding(),
                            target_source,
                            on_public_bound=receipt.record_public_bound,
                            on_published=receipt.mark_published,
                            on_unpublished=receipt.mark_unpublished,
                        )
                    elif stage == "public_bound":
                        result = driver.reconcile_publish(
                            receipt.clone_binding(),
                            target_source,
                            on_published=receipt.mark_published,
                            on_unpublished=receipt.mark_unpublished,
                        )
                    elif stage == "published":
                        result = receipt.result()
                    elif stage not in {"clone_bound"}:
                        raise FrameError(
                            "seeded-public receipt cannot resume publication from "
                            + stage
                        )
                if (
                    receipt.stage != "published"
                    or not result.public_verified
                    or result.published_deleted
                ):
                    raise chat_seeded_publish.SeededRemoteStateUnknown(
                        "seeded-public public mapping is bound but exact public content "
                        "is not verified",
                        stage=receipt.stage,
                        clone=result.clone,
                        published_uuid=result.published_uuid,
                    )
            except chat_seeded_publish.SeededRemoteStateUnknown as error:
                record_unknown(receipt, error)
                raise
            finally:
                if receipt is not existing:
                    receipt.close()
        finally:
            if existing is not None:
                existing.close()
        print(result.url)
        print("surface: chat", file=sys.stderr)
        print("adapter: seeded-public", file=sys.stderr)
        print("model-turn: none", file=sys.stderr)
        print("public-source: exact", file=sys.stderr)
        print("private-clone-source: seed", file=sys.stderr)
        print("seed: verified unchanged", file=sys.stderr)
        print(f"receipt: {os.path.abspath(args.receipt)}", file=sys.stderr)
        return

    lifecycle = chat_seeded_receipt.SeededReceiptLifecycle(
        args.receipt,
        organization_uuid=args.organization_uuid,
        account_email_sha256=args.account_email_sha256,
        seed_source=seed_source,
        target_source=target_source,
    )
    try:
        stage = lifecycle.stage
        if args.dry_run:
            if stage in {"prepared", "remix_pending", "publish_pending",
                         "unpublish_pending", "delete_pending"}:
                operations = ["read_only_reconciliation"]
            elif stage == "clone_bound":
                operations = [] if args.private else ["delete_private_clone"]
            elif stage == "publish_rejected":
                operations = (
                    ["retain_private_clone"]
                    if args.private
                    else ["delete_private_clone"]
                )
            elif stage in {"public_bound", "published"}:
                operations = ["unpublish"] + (
                    ["delete_clone_conversation"] if args.delete else []
                )
            elif stage == "unpublished":
                operations = [] if args.private else ["delete_clone_conversation"]
            else:
                operations = []
            print("DRY RUN, no browser opened and nothing sent.\n")
            print(json.dumps({
                "surface": "chat",
                "adapter": "seeded-public",
                "operation": operations,
                "receipt": lifecycle.path,
                "receiptStage": stage,
                "seedSourceSha256": lifecycle.seed.source_sha256,
                "targetSourceSha256": hashlib.sha256(
                    target_source.encode("utf-8")
                ).hexdigest(),
                "seedPreserved": True,
            }, indent=2, ensure_ascii=False))
            return
        if lifecycle.has_partial_tail:
            raise FrameError(
                "seeded-public receipt has a partial trailing record; "
                "review and repair it explicitly before a live operation"
            )
        if stage == "deleted":
            print("seeded-public clone already deleted", file=sys.stderr)
            return
        driver = new_driver()
        try:
            if stage == "remix_pending":
                observed = lifecycle.observed_clone_conversation_uuid
                if observed is None:
                    raise FrameError(
                        "seeded-public remix is ambiguous and has no observed clone "
                        "conversation; preserve the receipt for manual review"
                    )
                driver.reconcile_remix(
                    lifecycle.seed,
                    target_source,
                    observed,
                    on_clone_bound=lifecycle.record_clone,
                )
                stage = lifecycle.stage
            if stage == "publish_pending":
                driver.reconcile_publish(
                    lifecycle.clone_binding(),
                    target_source,
                    on_public_bound=lifecycle.record_public_bound,
                    on_published=lifecycle.mark_published,
                    on_unpublished=lifecycle.mark_unpublished,
                )
                stage = lifecycle.stage
            elif stage == "unpublish_pending":
                driver.reconcile_unpublish(
                    lifecycle.result(), on_verified=lifecycle.mark_unpublished
                )
                stage = lifecycle.stage
            elif stage == "delete_pending":
                driver.reconcile_delete(
                    lifecycle.clone_binding(),
                    target_source,
                    published_uuid=lifecycle.published_uuid,
                    on_verified=lifecycle.mark_deleted,
                )
                stage = lifecycle.stage
        except chat_seeded_publish.SeededRemoteStateUnknown as error:
            record_unknown(lifecycle, error)
            raise

        if stage == "prepared":
            raise FrameError(
                "seeded-public receipt has no remote clone; resume with the original "
                "--public command or retain the receipt as a local audit record"
            )
        if stage in {"clone_bound", "publish_rejected"}:
            if args.private:
                print(lifecycle.clone_binding().chat_url)
                print("surface: chat", file=sys.stderr)
                print("adapter: seeded-public", file=sys.stderr)
                print("public-mapping: none", file=sys.stderr)
                print("private-clone: retained", file=sys.stderr)
                print("seed: verified unchanged", file=sys.stderr)
                print(f"receipt: {lifecycle.path}", file=sys.stderr)
                return
            clone = lifecycle.clone_binding()
            driver.delete_private_clone(
                clone,
                target_source,
                on_intent=lambda _intent: lifecycle.mark_delete_pending(),
                on_verified=lifecycle.mark_deleted,
            )
            stage = lifecycle.stage
        elif stage in {"public_bound", "published"}:
            result = lifecycle.result()
            result = driver.unpublish(
                result,
                on_intent=lambda _intent: lifecycle.mark_unpublish_pending(result),
                on_verified=lifecycle.mark_unpublished,
            )
            stage = lifecycle.stage
        if args.private:
            if stage == "deleted":
                print("seeded-public clone already deleted", file=sys.stderr)
                return
            result = lifecycle.result()
            print(result.clone.chat_url)
            print("surface: chat", file=sys.stderr)
            print("adapter: seeded-public", file=sys.stderr)
            print("public-mapping: tombstone verified", file=sys.stderr)
            print("private-clone: retained", file=sys.stderr)
            print("seed: verified unchanged", file=sys.stderr)
            print(f"receipt: {lifecycle.path}", file=sys.stderr)
            return
        if stage == "unpublished":
            tombstone = lifecycle.result()
            driver.delete_container(
                tombstone,
                on_intent=lambda _intent: lifecycle.mark_delete_pending(tombstone),
                on_verified=lifecycle.mark_deleted,
            )
            stage = lifecycle.stage
        if stage != "deleted":
            raise FrameError(
                "seeded-public cleanup stopped at " + stage
                + "; preserve the receipt and rerun for read-only reconciliation"
            )
        print("surface: chat", file=sys.stderr)
        print("adapter: seeded-public", file=sys.stderr)
        print("public-mapping: absent or tombstoned", file=sys.stderr)
        print("private-clone-conversation: deleted", file=sys.stderr)
        print("seed: verified unchanged", file=sys.stderr)
        print(f"receipt: {lifecycle.path}", file=sys.stderr)
    finally:
        lifecycle.close()


def publish_chat(args):
    """Run the standard chat Artifact adapter after surface-specific checks."""

    adapter = args.chat_adapter or "conversation"
    unsupported = []
    for option, enabled in (
        ("--slug", bool(args.slug)),
        ("--url", bool(args.url)),
        ("--delete", args.delete and adapter == "native-share"),
        ("--title", bool(args.title) and adapter == "seeded-public"),
        ("--description", bool(args.description)),
        ("--label", bool(args.label)),
        ("--favicon", args.favicon != "\U0001f4c4"),
    ):
        if enabled:
            unsupported.append(option)
    if unsupported:
        raise FrameError(
            "--surface chat does not support " + ", ".join(unsupported)
            + "; standard chat Artifact replacement and lifecycle operations "
            "are separate from the Claude Code Frame API"
        )
    if args.delete and (args.public or args.private):
        raise FrameError("--delete cannot be combined with --public or --private")
    if adapter == "native-share":
        if args.acknowledge_chat_preview_executes:
            raise FrameError(
                "--acknowledge-chat-preview-executes is obsolete; neither chat "
                "adapter opens or executes an Artifact preview"
            )
        if args.wait_seconds is not None:
            raise FrameError("--wait-seconds is a conversation-adapter option")
        if args.seed_file or args.seed_receipt:
            raise FrameError(
                "--seed-file and --seed-receipt require --chat-adapter seeded-public"
            )
        if args.acknowledge_experimental_seeded_public:
            raise FrameError(
                "--acknowledge-experimental-seeded-public requires "
                "--chat-adapter seeded-public"
            )
        if not args.organization_uuid:
            raise FrameError(
                "--chat-adapter native-share requires --organization-uuid"
            )
        native_session_ref = _read_native_session_ref(args.native_session_ref_file)
        if args.public:
            _validate_new_native_receipt(args.receipt)
            native_receipt = None
        elif args.private:
            native_receipt = _read_native_receipt(
                args.receipt, args.organization_uuid
            )
        else:
            native_receipt = None
            if args.receipt:
                raise FrameError(
                    "--receipt is used with native-share --public or --private"
                )
    elif adapter == "seeded-public":
        native_session_ref = None
        native_receipt = None
        if args.acknowledge_chat_preview_executes:
            raise FrameError(
                "--acknowledge-chat-preview-executes is obsolete; seeded-public "
                "does not open or execute an Artifact preview"
            )
        if args.native_session_ref_file:
            raise FrameError(
                "--native-session-ref-file requires --chat-adapter native-share"
            )
        if args.wait_seconds is not None:
            raise FrameError("--wait-seconds is a conversation-adapter option")
        if not args.organization_uuid:
            raise FrameError(
                "--chat-adapter seeded-public requires --organization-uuid"
            )
        if not args.account_email_sha256:
            raise FrameError(
                "seeded-public operations require --account-email-sha256 to bind "
                "the target account"
            )
        if not args.receipt:
            raise FrameError(
                "seeded-public create/private/delete operations require --receipt"
            )
        if not args.seed_file:
            raise FrameError(
                "seeded-public operations require --seed-file with the seed's "
                "exact original HTML"
            )
        if args.public:
            if not args.acknowledge_experimental_seeded_public:
                raise FrameError(
                    "seeded-public creation requires "
                    "--acknowledge-experimental-seeded-public"
                )
            if not args.seed_receipt:
                raise FrameError(
                    "seeded-public creation requires --seed-receipt"
                )
            if os.path.abspath(args.seed_receipt) == os.path.abspath(args.receipt):
                raise FrameError("--seed-receipt and --receipt must be different files")
        elif args.private or args.delete:
            if args.seed_receipt:
                raise FrameError(
                    "--seed-receipt is create-only; lifecycle state is bound by --receipt"
                )
        else:
            raise FrameError(
                "seeded-public is public-only; choose --public, --private, or --delete"
            )
    else:
        native_session_ref = None
        native_receipt = None
        if args.acknowledge_chat_preview_executes:
            raise FrameError(
                "--acknowledge-chat-preview-executes is obsolete; the current "
                "conversation adapter does not open or execute the Artifact preview"
            )
        if args.native_session_ref_file:
            raise FrameError(
                "--native-session-ref-file requires --chat-adapter native-share"
            )
        if args.seed_file or args.seed_receipt:
            raise FrameError(
                "--seed-file and --seed-receipt require --chat-adapter seeded-public"
            )
        if args.acknowledge_experimental_seeded_public:
            raise FrameError(
                "--acknowledge-experimental-seeded-public requires "
                "--chat-adapter seeded-public"
            )
        if not args.organization_uuid:
            raise FrameError(
                "--chat-adapter conversation requires --organization-uuid"
            )
        if not args.account_email_sha256:
            raise FrameError(
                "conversation operations require --account-email-sha256 to bind "
                "the target account"
            )
        if not args.receipt:
            raise FrameError(
                "conversation create, public, private, and delete operations require "
                "--receipt to bind lifecycle and cleanup state"
            )
    if args.file is None:
        raise FrameError("--surface chat needs an HTML file")
    if not os.path.isfile(args.file):
        raise FrameError(f"no such file: {args.file}")
    if not args.file.lower().endswith((".html", ".htm")):
        raise FrameError("--surface chat currently accepts complete .html files only")
    if adapter == "seeded-public":
        if not os.path.isfile(args.seed_file):
            raise FrameError(f"no such seed file: {args.seed_file}")
        if not args.seed_file.lower().endswith((".html", ".htm")):
            raise FrameError("--seed-file must be a complete .html or .htm file")

    body = to_html(args.file)
    if adapter == "conversation" and "\r" in body:
        raise FrameError(
            "the conversation adapter requires LF line endings; convert CRLF before publishing"
        )
    title = (
        document_title(body)
        or normalise_title(args.title)
        or normalise_title(os.path.splitext(os.path.basename(args.file))[0])
        or "Artifact"
    )

    browser_port = args.browser_port if args.browser_port is not None else 9222
    if adapter == "native-share":
        from . import chat_direct_publish

        chat_direct_publish.validate_session_ref(native_session_ref)
        chat_direct_publish.validate_organization_uuid(args.organization_uuid)
        chat_direct_publish.validate_browser_port(browser_port)
        chat_direct_publish.validate_request(
            body, os.path.basename(args.file), title
        )
        if args.dry_run:
            print("DRY RUN, nothing sent.\n")
            print(
                json.dumps(
                    {
                        "surface": "chat",
                        "adapter": "native-share",
                        "driver": "same-origin fetch through local Chrome",
                        "browserPort": browser_port,
                        "organizationUuidSha256": hashlib.sha256(
                            args.organization_uuid.encode("ascii")
                        ).hexdigest(),
                        "title": title,
                        "operation": "unpublish" if args.private else "publish",
                        "public": bool(args.public),
                        "sourceBytes": len(body.encode("utf-8")),
                        "sourceSha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                        "nativeSessionRefSha256": (
                            chat_direct_publish.hash_session_ref(native_session_ref)
                        ),
                        **(
                            {"publishedArtifactUuid": native_receipt.published_uuid}
                            if native_receipt is not None
                            else {"receipt": os.path.abspath(args.receipt)}
                            if args.public
                            else {}
                        ),
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )
            return
        if not args.account_email_sha256:
            raise FrameError(
                "live --chat-adapter native-share requires "
                "--account-email-sha256 to bind the target account"
            )
        driver = chat_direct_publish.NativeShareArtifactPublisher(
            browser_port,
            expected_email_sha256=args.account_email_sha256,
            organization_uuid=args.organization_uuid,
            native_session_ref=native_session_ref,
        )
        if args.private:
            driver.unpublish(native_receipt, body)
            print(native_receipt.url)
            print("surface: chat", file=sys.stderr)
            print("adapter: native-share", file=sys.stderr)
            print(f"unpublished: {native_receipt.published_uuid}", file=sys.stderr)
            print("tombstone: verified", file=sys.stderr)
            return
        result = driver.publish(
            body,
            os.path.basename(args.file),
            title=title,
            public=args.public,
        )
        if args.public:
            if result.public is not True or not result.published_uuid:
                raise FrameError(
                    "native-share public publication returned no exact public binding"
                )
            _write_native_receipt(args.receipt, args.organization_uuid, result)
        print(result.url)
        print("surface: chat", file=sys.stderr)
        print("adapter: native-share", file=sys.stderr)
        print(f"artifact: {result.artifact_uuid}", file=sys.stderr)
        print(f"version: {result.version_uuid}", file=sys.stderr)
        print(f"source-sha256: {result.source_sha256}", file=sys.stderr)
        if result.published_uuid:
            print(f"published: {result.published_uuid}", file=sys.stderr)
            print(f"receipt: {os.path.abspath(args.receipt)}", file=sys.stderr)
        return

    if adapter == "seeded-public":
        _publish_seeded_public(args, body, browser_port)
        return

    from . import chat_publish

    output_path = chat_publish.generated_output_path(body, title)
    prompt = chat_publish.build_prompt(body, title, output_path)
    wait_seconds = args.wait_seconds if args.wait_seconds is not None else 240.0
    if not args.account_email_sha256 or not re.fullmatch(
        r"[0-9a-f]{64}", args.account_email_sha256
    ):
        raise FrameError(
            "conversation operations require --account-email-sha256 to bind the target account"
        )

    if args.private or args.delete:
        receipt = _ConversationReceiptLifecycle(
            args.receipt,
            organization_uuid=args.organization_uuid,
            account_email_sha256=args.account_email_sha256,
            source=body,
        )
        try:
            stage = receipt.stage
            if stage in _CONVERSATION_PRECONVERSION_STAGES:
                if args.private:
                    raise FrameError(
                        "conversation --private requires a converted receipt; "
                        f"current stage: {stage}; use --delete for pre-conversion cleanup"
                    )
                binding = receipt.preconversion_binding()
                if args.dry_run:
                    print("DRY RUN, nothing sent.\n")
                    print(
                        json.dumps(
                            {
                                "surface": "chat",
                                "adapter": "conversation",
                                "driver": "direct same-origin lifecycle APIs",
                                "browserPort": browser_port,
                                "operation": ["delete_preconversion_conversation"],
                                "receipt": receipt.path,
                                "receiptStage": stage,
                                "organizationUuidSha256": hashlib.sha256(
                                    args.organization_uuid.encode("ascii")
                                ).hexdigest(),
                                "conversationUuid": binding.conversation_uuid,
                                "outputPath": binding.output_path,
                                "sourceBytes": len(body.encode("utf-8")),
                                "sourceSha256": binding.source_sha256,
                                "promptSha256": binding.prompt_sha256,
                            },
                            indent=2,
                            ensure_ascii=False,
                        )
                    )
                    return
                driver = chat_publish.ChatArtifactPublisher(
                    browser_port,
                    expected_email_sha256=args.account_email_sha256,
                    organization_uuid=args.organization_uuid,
                    timeout=wait_seconds,
                )
                driver.delete_preconversion_conversation(
                    binding,
                    body,
                    prompt,
                    on_verified=lambda: receipt.mark_preconversion_deleted(binding),
                )
                print(binding.chat_url)
                print("surface: chat", file=sys.stderr)
                print("adapter: conversation", file=sys.stderr)
                print(
                    f"deleted-conversation: {binding.conversation_uuid}",
                    file=sys.stderr,
                )
                print("catalog-and-versions: absent", file=sys.stderr)
                print(f"receipt: {receipt.path}", file=sys.stderr)
                return
            if stage in {
                "conversion_pending",
                "conversion_bound",
                "privacy_pending",
            }:
                pending_binding = (
                    receipt.conversion_pending_binding()
                    if stage == "conversion_pending"
                    else None
                )
                plan = []
                if stage == "conversion_pending":
                    plan.append("reconcile_conversion_pending")
                plan.append("complete_conversion_privacy")
                if args.delete:
                    plan.append("delete_conversation")
                if args.dry_run:
                    pending_result = (
                        receipt.result()
                        if stage in {"conversion_bound", "privacy_pending"}
                        else None
                    )
                    print("DRY RUN, nothing sent.\n")
                    print(
                        json.dumps(
                            {
                                "surface": "chat",
                                "adapter": "conversation",
                                "driver": "direct same-origin lifecycle APIs",
                                "browserPort": browser_port,
                                "operation": plan,
                                "receipt": receipt.path,
                                "receiptStage": stage,
                                "organizationUuidSha256": hashlib.sha256(
                                    args.organization_uuid.encode("ascii")
                                ).hexdigest(),
                                "conversationUuid": (
                                    pending_binding.conversation_uuid
                                    if pending_binding is not None
                                    else pending_result.conversation_uuid
                                ),
                                "sourceBytes": len(body.encode("utf-8")),
                                "sourceSha256": (
                                    pending_binding.source_sha256
                                    if pending_binding is not None
                                    else pending_result.source_sha256
                                ),
                                "promptSha256": (
                                    pending_binding.prompt_sha256
                                    if pending_binding is not None
                                    else pending_result.prompt_sha256
                                ),
                                **(
                                    {
                                        "artifactUuid": pending_result.artifact_uuid,
                                        "versionUuid": pending_result.version_uuid,
                                    }
                                    if pending_result is not None
                                    else {}
                                ),
                            },
                            indent=2,
                            ensure_ascii=False,
                        )
                    )
                    return
                driver = chat_publish.ChatArtifactPublisher(
                    browser_port,
                    expected_email_sha256=args.account_email_sha256,
                    organization_uuid=args.organization_uuid,
                    timeout=wait_seconds,
                )
                if stage == "conversion_pending":
                    result = driver.reconcile_conversion_pending(
                        pending_binding,
                        body,
                        prompt,
                        on_reconciled=receipt.record_conversion_reconciled,
                    )
                else:
                    result = receipt.result()
                allow_privacy_mutation = receipt.stage == "conversion_bound"
                if allow_privacy_mutation:
                    receipt.mark_privacy_pending(result)
                driver.complete_conversion_privacy(
                    result,
                    body,
                    prompt,
                    title,
                    allow_mutation=allow_privacy_mutation,
                    on_verified=lambda: receipt.mark_conversion_private(result),
                )
                result = receipt.result()
                if args.private:
                    print(result.chat_url)
                    print("surface: chat", file=sys.stderr)
                    print("adapter: conversation", file=sys.stderr)
                    print("private: exact public mapping absent", file=sys.stderr)
                    print(f"receipt: {receipt.path}", file=sys.stderr)
                    return
                driver.delete_conversation(
                    result,
                    body,
                    on_verified=lambda: receipt.mark("deleted"),
                )
                print(result.chat_url)
                print("surface: chat", file=sys.stderr)
                print("adapter: conversation", file=sys.stderr)
                print(
                    f"deleted-conversation: {result.conversation_uuid}",
                    file=sys.stderr,
                )
                print("catalog-and-versions: absent", file=sys.stderr)
                print(f"receipt: {receipt.path}", file=sys.stderr)
                return
            result = receipt.result()
            if args.private:
                if stage == "converted":
                    plan = (
                        ["reconcile_public", "unpublish_if_active"]
                        if receipt.requested_public
                        else ["complete_verified_private_receipt"]
                    )
                elif stage in {"public_bound", "published"}:
                    plan = ["unpublish"]
                elif stage in {"private", "unpublished"}:
                    plan = ["already_private"]
                else:
                    raise FrameError(
                        "conversation --private requires a converted receipt; "
                        f"current stage: {stage}"
                    )
            elif stage == "converted":
                plan = (
                    [
                        "reconcile_public",
                        "unpublish_if_active",
                        "delete_conversation",
                    ]
                    if receipt.requested_public
                    else ["complete_verified_private_receipt", "delete_conversation"]
                )
            elif stage in {"public_bound", "published"}:
                plan = ["unpublish", "delete_conversation"]
            elif stage in {"private", "unpublished"}:
                plan = ["delete_conversation"]
            else:
                raise FrameError(
                    "conversation --delete requires an exact converted receipt; "
                    f"current stage: {stage}"
                )
            if args.dry_run:
                print("DRY RUN, nothing sent.\n")
                print(
                    json.dumps(
                        {
                            "surface": "chat",
                            "adapter": "conversation",
                            "driver": "direct same-origin lifecycle APIs",
                            "browserPort": browser_port,
                            "operation": plan,
                            "receipt": receipt.path,
                            "receiptStage": stage,
                            "organizationUuidSha256": hashlib.sha256(
                                args.organization_uuid.encode("ascii")
                            ).hexdigest(),
                            "sourceBytes": len(body.encode("utf-8")),
                            "sourceSha256": hashlib.sha256(
                                body.encode("utf-8")
                            ).hexdigest(),
                            "artifactUuid": result.artifact_uuid,
                            "versionUuid": result.version_uuid,
                            **(
                                {"publishedArtifactUuid": result.published_uuid}
                                if result.published_uuid
                                else {}
                            ),
                        },
                        indent=2,
                        ensure_ascii=False,
                    )
                )
                return
            driver = chat_publish.ChatArtifactPublisher(
                browser_port,
                expected_email_sha256=args.account_email_sha256,
                organization_uuid=args.organization_uuid,
                timeout=wait_seconds,
            )
            if stage == "converted":
                if receipt.requested_public:
                    driver.reconcile_public(
                        result,
                        body,
                        on_reconciled=receipt.record_reconciled,
                    )
                else:
                    receipt.mark("private")
                stage = receipt.stage
                result = receipt.result()
            if args.private:
                if stage in {"public_bound", "published"}:
                    driver.unpublish(
                        result,
                        body,
                        on_verified=lambda: receipt.mark("unpublished"),
                    )
                    result = receipt.result()
                print(result.chat_url)
                print("surface: chat", file=sys.stderr)
                print("adapter: conversation", file=sys.stderr)
                if result.published_deleted:
                    print(f"unpublished: {result.published_uuid}", file=sys.stderr)
                    print("tombstone: verified", file=sys.stderr)
                else:
                    print("private: exact public mapping absent", file=sys.stderr)
                print(f"receipt: {receipt.path}", file=sys.stderr)
                return
            if stage in {"public_bound", "published"}:
                driver.unpublish(
                    result,
                    body,
                    on_verified=lambda: receipt.mark("unpublished"),
                )
                result = receipt.result()
            driver.delete_conversation(
                result,
                body,
                on_verified=lambda: receipt.mark("deleted"),
            )
            print(result.chat_url)
            print("surface: chat", file=sys.stderr)
            print("adapter: conversation", file=sys.stderr)
            print(f"deleted-conversation: {result.conversation_uuid}", file=sys.stderr)
            print("catalog-and-versions: absent", file=sys.stderr)
            print(f"receipt: {receipt.path}", file=sys.stderr)
            return
        finally:
            receipt.close()

    _validate_new_conversation_receipt(args.receipt)
    if args.dry_run:
        print("DRY RUN, nothing sent.\n")
        print(
            json.dumps(
                {
                    "surface": "chat",
                    "adapter": "conversation",
                    "driver": "exact generated file plus direct same-origin Artifact APIs",
                    "browserPort": browser_port,
                    "organizationUuidSha256": hashlib.sha256(
                        args.organization_uuid.encode("ascii")
                    ).hexdigest(),
                    "title": title,
                    "public": bool(args.public),
                    "outputPath": output_path,
                    "sourceBytes": len(body.encode("utf-8")),
                    "sourceSha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                    "promptSha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                    "receipt": os.path.abspath(args.receipt),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return
    journal = None
    try:
        driver = chat_publish.ChatArtifactPublisher(
            browser_port,
            expected_email_sha256=args.account_email_sha256,
            organization_uuid=args.organization_uuid,
            timeout=wait_seconds,
        )
        journal = _ConversationReceiptJournal(
            args.receipt,
            organization_uuid=args.organization_uuid,
            account_email_sha256=args.account_email_sha256,
            source=body,
            output_path=output_path,
            request_title=title,
            prompt_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            requested_public=bool(args.public),
        )
        result = driver.publish(
            body,
            title,
            public=args.public,
            acknowledge_preview_execution=False,
            on_conversation_binding=journal.record_conversation if journal else None,
            on_file_binding=journal.record_file if journal else None,
            on_conversion_intent=journal.record_conversion_intent if journal else None,
            on_binding=journal.record_binding if journal else None,
            on_published_uuid=journal.record_published if journal else None,
        )
        journal.record_complete(result)
    finally:
        if journal is not None:
            journal.close()
    print(result.url)
    print("surface: chat", file=sys.stderr)
    print(f"artifact: {result.artifact_uuid}", file=sys.stderr)
    print(f"version: {result.version_uuid}", file=sys.stderr)
    print(f"source-sha256: {result.source_sha256}", file=sys.stderr)
    print(f"receipt: {os.path.abspath(args.receipt)}", file=sys.stderr)
    if result.published_uuid:
        print(f"published: {result.published_uuid}", file=sys.stderr)


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.public and args.private:
        raise FrameError("--public and --private are mutually exclusive")

    if args.surface == "chat":
        publish_chat(args)
        return

    if (
        args.browser_port is not None
        or args.account_email_sha256
        or args.chat_adapter is not None
        or args.organization_uuid
        or args.native_session_ref_file
        or args.seed_file
        or args.seed_receipt
        or args.receipt
        or args.wait_seconds is not None
        or args.acknowledge_chat_preview_executes
        or args.acknowledge_experimental_seeded_public
    ):
        raise FrameError(
            "chat adapter, browser, account, organization, and wait options are "
            "only valid with --surface chat"
        )
    if args.slug and not frames.SLUG_RE.match(args.slug):
        raise FrameError(f"not an artifact slug: {args.slug!r}")

    slug = args.slug or (frames.slug_from_url(args.url) if args.url else None)

    if args.delete:
        if not slug:
            raise FrameError("--delete needs --url or --slug")
        if args.dry_run:
            print("DRY RUN, credentials not loaded and nothing sent.\n")
            print(f"DELETE {frames.API_BASE}/api/frame/{slug}")
            return
        session = frames.Session()
        frames.delete(session, slug)
        print(f"deleted {slug}")
        return

    # Audience-only mode: no file, just change who can read an existing artifact.
    if args.file is None:
        if not (args.public or args.private):
            raise FrameError("nothing to do: give a file, or --public/--private "
                             "with --url")
        if not slug:
            raise FrameError("--public/--private needs --url or --slug")
        mode = "public" if args.public else "owner"
        if args.dry_run:
            import json

            print("DRY RUN, credentials not loaded and nothing sent.\n")
            print(f"GET {frames.API_BASE}/api/frame/{slug}?via=model_read")
            print(f"then PATCH {frames.API_BASE}/api/frame/perm/{slug}?org=<uuid>")
            body = {"read": {"mode": mode, "users": []}}
            if mode == "public":
                body["shared"] = "<live-version>"
            print(json.dumps(body, indent=2))
            return
        session = frames.Session()
        ver = frames.set_audience(
            session, slug, mode,
            on_wait=lambda r, w, a, n: print(
                f"not shareable yet ({r}); retrying in {w}s [{a}/{n}]", file=sys.stderr))
        print(frames.viewer_url(slug))
        if args.public:
            report_public(slug, ver)
        return

    if not os.path.isfile(args.file):
        raise FrameError(f"no such file: {args.file}")

    body = to_html(args.file)
    page = frames.compose(body)
    title = (document_title(body)
             or normalise_title(args.title)
             or os.path.splitext(os.path.basename(args.file))[0])

    if args.dry_run:
        import json
        preview = {"title": title, "favicon": args.favicon, "entrypoint": "cli",
                   "content": page[:400] + f"… [{len(page.encode())} bytes]"}
        if slug:
            preview["slug"] = slug
        if args.description:
            preview["description"] = args.description
        print("DRY RUN, credentials not loaded and nothing sent.\n")
        print(f"POST {frames.API_BASE}/api/frame/deploy/direct")
        for key, value in code_dry_run_headers().items():
            print(f"{key}: {value}")
        print("\n" + json.dumps(preview, indent=2, ensure_ascii=False))
        if args.public:
            print(f"\nthen PATCH {frames.API_BASE}/api/frame/perm/<slug>?org=<uuid>")
            print(json.dumps({"read": {"mode": "public", "users": []},
                              "shared": "<version>"}, indent=2))
        return

    session = frames.Session()
    data = frames.publish(session, page, title, favicon=args.favicon, slug=slug,
                          description=args.description or None, label=args.label)
    frames.verify_exact_published_content(
        session, data["slug"], data["version"], page
    )
    ver = data["version"]

    if args.public:
        ver = frames.set_audience(
            session, data["slug"], "public",
            on_wait=lambda r, w, a, n: print(
                f"not shareable yet ({r}); retrying in {w}s [{a}/{n}]",
                file=sys.stderr)) or ver
        frames.verify_exact_public_content(data["slug"], ver, page)
    elif args.private:
        frames.set_audience(session, data["slug"], "owner")

    print(frames.viewer_url(data["slug"]))
    print(f"version: {data['version']}", file=sys.stderr)
    if args.public:
        report_public(data["slug"], ver)


def cli():
    try:
        main()
    except FrameError as exc:
        sys.exit(f"error: {exc}")
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    cli()

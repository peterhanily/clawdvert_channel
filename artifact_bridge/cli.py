"""Command-line interface for read-only Claude Artifact retrieval."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable, List, Mapping, Optional, Sequence, TextIO

from .adapters import AnthropicComplianceAdapter, OwnerFrameAdapter
from .audit import audit_bundle
from .client import BridgeClient
from .errors import ArtifactBridgeError, UsageError, redact_text
from .models import safe_json_value
from .refs import parse_ref, require_resolvable
from .store import ArtifactStore, LOCK_NAME, default_output_name


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m artifact_bridge",
        description="Read and mirror exact versions of Claude artifacts without executing them.",
        epilog="Downloaded content is untrusted data. This tool never renders or executes it.",
    )
    parser.add_argument(
        "--adapter",
        choices=("auto", "owner", "compliance"),
        default="auto",
        help="authentication/provider surface (default: infer from reference)",
    )
    parser.add_argument(
        "--max-bytes",
        type=_positive_int,
        default=16 * 1024 * 1024,
        metavar="N",
        help="maximum bytes per downloaded representation",
    )
    parser.add_argument(
        "--max-total-bytes",
        type=_positive_int,
        default=64 * 1024 * 1024,
        metavar="N",
        help="maximum aggregate bytes retained in one operation/bundle",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    auth = commands.add_parser("auth", help="inspect configured credentials without printing them")
    auth_commands = auth.add_subparsers(dest="auth_command", required=True)
    auth_status = auth_commands.add_parser("status", help="show credential availability")
    _json_flag(auth_status)

    listing = commands.add_parser("list", help="list artifacts from one explicit provider")
    listing.add_argument("--limit", type=_positive_int, default=100)
    _json_flag(listing)

    inspect = commands.add_parser("inspect", help="show metadata for an artifact")
    inspect.add_argument("ref")
    _json_flag(inspect)

    versions = commands.add_parser("versions", help="list retained exact versions")
    versions.add_argument("ref")
    _json_flag(versions)

    pull = commands.add_parser("pull", help="download one exact version into a safe bundle")
    pull.add_argument("ref")
    pull.add_argument("--version", help="exact provider version ID")
    pull.add_argument("-o", "--output", type=Path, help="new or existing bridge bundle directory")
    _json_flag(pull)

    cat = commands.add_parser("cat", help="write one downloaded representation to stdout")
    cat.add_argument("ref")
    cat.add_argument("--version", help="exact provider version ID")
    cat.add_argument("--representation", help="representation label")

    diff = commands.add_parser("diff", help="diff two exact retained versions as inert text")
    diff.add_argument("ref")
    diff.add_argument("--from-version", required=True, metavar="ID")
    diff.add_argument("--to-version", required=True, metavar="ID")
    diff.add_argument("--representation", help="representation label")
    diff.add_argument("--context", type=_nonnegative_int, default=3)

    mirror = commands.add_parser("mirror", help="download retained versions into one safe bundle")
    mirror.add_argument("ref")
    mirror.add_argument(
        "--version",
        dest="versions",
        action="append",
        metavar="ID",
        help="exact version to mirror; repeat (default: all retained versions)",
    )
    mirror.add_argument("-o", "--output", type=Path, help="bridge bundle directory")
    _json_flag(mirror)

    audit = commands.add_parser(
        "audit", help="verify a local bundle and report bounded static content indicators"
    )
    audit.add_argument("path", type=Path)
    _json_flag(audit)

    return parser


def _json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="emit deterministic JSON")


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return parsed


def make_client(args: argparse.Namespace) -> BridgeClient:
    names = _required_adapter_names(args)
    adapters = []
    try:
        for name in names:
            if name == "owner":
                adapters.append(OwnerFrameAdapter(max_response_bytes=args.max_bytes))
            elif name == "compliance":
                adapters.append(
                    AnthropicComplianceAdapter(max_response_bytes=args.max_bytes)
                )
            else:
                raise UsageError("unsupported adapter: %s" % name)
        return BridgeClient(
            adapters,
            max_representation_bytes=args.max_bytes,
            max_total_bytes=args.max_total_bytes,
        )
    except Exception:
        for adapter in adapters:
            close = getattr(adapter, "close", None)
            if callable(close):
                close()
        raise


def _required_adapter_names(args: argparse.Namespace) -> List[str]:
    if args.command == "audit":
        return []
    if args.adapter != "auto":
        return [args.adapter]
    if args.command == "auth":
        return ["owner", "compliance"]
    if args.command == "list":
        raise UsageError(
            "list has no reference to identify an authority surface; "
            "choose --adapter owner or --adapter compliance"
        )
    ref = getattr(args, "ref", None)
    if ref is None:
        raise UsageError("could not infer an adapter for this command")
    resolved = require_resolvable(parse_ref(ref, default_provider="auto"))
    return [resolved.provider]


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    client: Optional[BridgeClient] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    """Run the CLI and return a process exit status.

    The injectable client/streams are intended for deterministic offline tests.
    """

    out = stdout or sys.stdout
    err = stderr or sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)
    owned_client = client is None
    active = client
    try:
        if active is None and args.command != "audit":
            active = make_client(args)
        return _run(args, active, out, err)
    except ArtifactBridgeError as exc:
        _print_safe("error: %s" % exc, err)
        return exc.exit_code
    except BrokenPipeError:
        return 0
    except (OSError, ValueError) as exc:
        _print_safe("error: %s" % exc, err)
        return 1
    finally:
        if owned_client and active is not None:
            active.close()


def _run(
    args: argparse.Namespace,
    client: Optional[BridgeClient],
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    provider = args.adapter
    if args.command == "audit":
        report = audit_bundle(
            args.path,
            max_representation_bytes=args.max_bytes,
            max_total_bytes=args.max_total_bytes,
        )
        if args.json:
            _print_json(report.to_dict(), stdout)
        else:
            state = "ok" if report.ok else "failed"
            _print_safe(
                "%s: %s (%d representations, %d bytes)"
                % (state, report.lockfile, report.representations, report.total_bytes),
                stdout,
            )
            for issue in report.issues:
                where = " [%s]" % issue.path if issue.path else ""
                _print_safe(
                    "%s %s%s: %s"
                    % (issue.severity, issue.code, where, issue.message),
                    stdout,
                )
        return 0 if report.ok else 1
    if client is None:
        raise UsageError("this command requires an artifact adapter")
    if args.command == "auth":
        statuses = client.auth_status(None if provider == "auto" else provider)
        if args.json:
            _print_json([status.to_dict() for status in statuses], stdout)
        else:
            for status in statuses:
                state = "configured" if status.authenticated else "not configured"
                detail = " - %s" % status.detail if status.detail else ""
                _print_safe("%s\t%s%s" % (status.provider, state, detail), stdout)
        return 0

    if args.command == "list":
        artifacts = client.list_artifacts(provider, args.limit)
        if args.json:
            _print_json([artifact.to_dict() for artifact in artifacts], stdout)
        else:
            for artifact in artifacts:
                _print_safe(
                    "%s\t%s\t%s\t%s"
                    % (
                        artifact.artifact_id,
                        artifact.live_version or artifact.published_version or "-",
                        artifact.visibility or "-",
                        artifact.title or "-",
                    ),
                    stdout,
                )
        return 0

    if args.command == "inspect":
        artifact = client.inspect(args.ref, provider)
        _print_json(artifact.to_dict(), stdout)
        return 0

    if args.command == "versions":
        versions = client.versions(args.ref, provider)
        if args.json:
            _print_json([version.to_dict() for version in versions], stdout)
        else:
            for version in versions:
                flags = []
                if version.is_live:
                    flags.append("live")
                if version.is_published:
                    flags.append("published")
                _print_safe(
                    "%s\t%s\t%s"
                    % (version.version_id, ",".join(flags) or "-", version.created_at or "-"),
                    stdout,
                )
        return 0

    if args.command == "cat":
        data = client.cat(args.ref, args.version, args.representation, provider)
        _write_bytes(data, stdout)
        return 0

    if args.command == "diff":
        text = client.diff(
            args.ref,
            args.from_version,
            args.to_version,
            args.representation,
            args.context,
            provider,
        )
        _write_inert_text(text, stdout)
        return 0

    if args.command == "pull":
        fetched = client.fetch(args.ref, args.version, provider)
        output = args.output or Path(default_output_name(fetched))
        store = ArtifactStore(
            max_representation_bytes=args.max_bytes,
            max_total_bytes=args.max_total_bytes,
        )
        lock = store.write([fetched], output)
        _print_write_result(output, lock, args.json, stdout)
        return 0

    if args.command == "mirror":
        fetched_items = client.mirror(args.ref, args.versions, provider)
        first = fetched_items[0]
        output = args.output or Path(default_output_name(first) + "-mirror")
        store = ArtifactStore(
            max_representation_bytes=args.max_bytes,
            max_total_bytes=args.max_total_bytes,
        )
        lock = store.write(fetched_items, output)
        _print_write_result(output, lock, args.json, stdout)
        return 0

    raise UsageError("unknown command: %s" % args.command)


def _print_write_result(
    output: Path, lock: Mapping[str, Any], as_json: bool, stdout: TextIO
) -> None:
    summary = {
        "output": str(output),
        "lockfile": str(output / LOCK_NAME),
        "provider": lock.get("artifact", {}).get("provider"),
        "artifact_id": lock.get("artifact", {}).get("artifact_id"),
        "versions": [item.get("version_id") for item in lock.get("versions", [])],
    }
    if as_json:
        _print_json(summary, stdout)
    else:
        _print_safe(summary["lockfile"], stdout)


def _print_json(value: Any, stream: TextIO) -> None:
    stream.write(
        json.dumps(
            safe_json_value(value),
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
    )
    stream.write("\n")


def _print_safe(value: object, stream: TextIO) -> None:
    text = _neutralize_terminal_text(redact_text(value), allow_newlines=False)
    stream.write(text + "\n")


def _write_bytes(data: bytes, stream: TextIO) -> None:
    binary = getattr(stream, "buffer", None)
    if binary is not None:
        binary.write(data)
        binary.flush()
    else:
        stream.write(data.decode("utf-8", "replace"))


def _write_inert_text(value: str, stream: TextIO) -> None:
    """Write diff text while neutralizing terminal control sequences."""

    text = _neutralize_terminal_text(value, allow_newlines=True)
    stream.write(text)
    if text and not text.endswith("\n"):
        stream.write("\n")


def _neutralize_terminal_text(value: str, *, allow_newlines: bool) -> str:
    safe = []
    for char in value:
        codepoint = ord(char)
        if char == "\t" or (allow_newlines and char == "\n"):
            safe.append(char)
        elif codepoint < 32 or 0x7F <= codepoint <= 0x9F:
            safe.append("\\x%02x" % codepoint if codepoint <= 0xFF else "\\u%04x" % codepoint)
        else:
            safe.append(char)
    return "".join(safe)


__all__ = ["build_parser", "main", "make_client"]

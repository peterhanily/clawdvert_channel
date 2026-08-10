"""Publish a file as a Claude artifact.

    python3 -m clawdvert.publish page.html --favicon 📊
    python3 -m clawdvert.publish page.html --slug <uuid>      replace in place
    python3 -m clawdvert.publish --public --slug <uuid>       change who can read it
"""

import argparse
import html
import os
import re
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
        text = open(path, encoding="utf-8").read()
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


def build_parser():
    p = argparse.ArgumentParser(
        prog="clawdvert.publish",
        description="Publish a file as a Claude artifact.")
    p.add_argument("file", nargs="?", help=".html or .md file to publish")
    p.add_argument("--title", help="overridden by a <title> in the document")
    p.add_argument("--description", default="", help="one-line gallery subtitle")
    p.add_argument("--favicon", default="\U0001f4c4", help="one or two emoji")
    p.add_argument("--label", help="short label shown in the version picker")
    p.add_argument("--url", help="existing artifact URL to replace in place")
    p.add_argument("--slug", help="existing artifact slug to replace in place")
    p.add_argument("--public", action="store_true",
                   help="anyone with the link can read it")
    p.add_argument("--private", action="store_true", help="revoke public access")
    p.add_argument("--delete", action="store_true", help="delete the artifact")
    p.add_argument("--dry-run", action="store_true",
                   help="print the request with the token redacted, send nothing")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.public and args.private:
        raise FrameError("--public and --private are mutually exclusive")
    if args.slug and not frames.SLUG_RE.match(args.slug):
        raise FrameError(f"not an artifact slug: {args.slug!r}")

    slug = args.slug or (frames.slug_from_url(args.url) if args.url else None)
    session = frames.Session()

    if args.delete:
        if not slug:
            raise FrameError("--delete needs --url or --slug")
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
        source = frames.credential_source_label(session.token_source)
        print(f"(token from {source})\nDRY RUN, nothing sent.\n")
        print(f"POST {frames.API_BASE}/api/frame/deploy/direct")
        for k, v in session.headers().items():
            print(f"{k}: {'Bearer <REDACTED>' if k == 'Authorization' else v}")
        print("\n" + json.dumps(preview, indent=2, ensure_ascii=False))
        if args.public:
            print(f"\nthen PATCH {frames.API_BASE}/api/frame/perm/<slug>?org=<uuid>")
            print(json.dumps({"read": {"mode": "public", "users": []},
                              "shared": "<version>"}, indent=2))
        return

    data = frames.publish(session, page, title, favicon=args.favicon, slug=slug,
                          description=args.description or None, label=args.label)
    ver = data["version"]

    if args.public:
        ver = frames.set_audience(
            session, data["slug"], "public",
            on_wait=lambda r, w, a, n: print(
                f"not shareable yet ({r}); retrying in {w}s [{a}/{n}]",
                file=sys.stderr)) or ver
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

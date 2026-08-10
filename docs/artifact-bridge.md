# Artifact Bridge

Artifact Bridge is a deterministic, read-only CLI for inspecting and retrieving Claude Artifacts.
It resolves artifact metadata, preserves exact versions, hashes retrieved bytes, and supports static
comparison and auditing without opening the artifact in a browser or launching Claude Code.

The bridge has two different access surfaces:

| Adapter | Artifact surface | Authentication | Support status |
| --- | --- | --- | --- |
| `compliance` | Claude Code Artifacts visible to an Enterprise organization, plus a standard Claude chat Artifact when given its exact Compliance version ID | `ANTHROPIC_COMPLIANCE_ACCESS_KEY` | Anthropic's official Enterprise Compliance API |
| `owner` | Private Claude Code Artifacts owned by the current claude.ai account, plus anonymously readable public pins | An existing Claude Code OAuth login for owned/private access | Experimental, undocumented `/api/frame/*` API |
| `auto` | Selects an adapter from an unambiguous artifact reference | Depends on the selected adapter | Convenience selector, not a new access path |

Standard Claude chat Artifact URLs under `/public/artifacts` are not supported yet. The Compliance
adapter can retrieve one when given its exact artifact-version ID from [Compliance message
metadata][chat-messages], but it cannot discover one from its public URL or list all standard
Artifacts. A public Claude chat Artifact and a Claude Code Artifact are different products, so the
bridge does not rewrite one kind of URL into the other or scrape browser cookies to reach it.

Artifact Bridge cannot publish, update, share, unshare, or delete an artifact. It does not expose
write operations even where an underlying API has one.

## Install and authenticate

Artifact Bridge runs from this repository with Python 3.9 or newer on POSIX systems (macOS and
Linux). Its local bundle writer uses `fcntl` advisory locks; Windows is not currently supported.
The deterministic `./check.sh` suite is offline and does not perform credentialed acceptance against
either provider. The owner adapter remains experimental because its API is undocumented.

Install the repository dependencies and run the CLI from the repository root:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m artifact_bridge --adapter auto auth status
```

`auth status` reports which credential classes are available without printing their values.
The bridge runs directly from the repository, so no package installation or Claude Code process is
required.

For the official adapter, set an Enterprise Compliance Access Key in the environment:

```bash
export ANTHROPIC_COMPLIANCE_ACCESS_KEY='<compliance-access-key>'
.venv/bin/python -m artifact_bridge --adapter compliance auth status
```

Compliance Access Keys can have organization-wide visibility. Keep the key in an environment
variable or secret manager, never in a command argument, output file, or `artifact.lock.json`.
Anthropic documents the key and access requirements in [Compliance API access][compliance-access].

The owner adapter reuses an existing Claude Code OAuth login. It does not start a `claude` process or
perform an interactive login. If the account has never logged in on the machine, run `claude` and
complete login separately before listing or reading owned/private artifacts. A publicly pinned Claude
Code Artifact may be inspected by URL without OAuth, but that anonymous path exposes only what the
public pin makes readable.

Do not switch from one adapter to another after a permission failure. The adapters have separate
credential classes and visibility rules, so a `401` or `403` should be resolved on the selected
surface rather than bypassed with another one.

## Supported references

The bridge recognizes:

- A Claude Code viewer URL such as `https://claude.ai/code/artifact/<uuid>` or its UUID slug.
- An exact Claude Code content-origin URL containing both its UUID and version.
- An official Code Compliance artifact ID beginning with `cart_`.
- A standard Claude chat Compliance version ID beginning with `claude_artifact_version_`.

Code Compliance version IDs are opaque, such as `1741803761-9f3a` in [Anthropic's current
example][list]. They do not identify their parent artifact, so pass one with a `cart_*` reference
through `--version`. Do not infer a prefix or meaning from the version string.

## Commands

The global `--adapter` option accepts `auto`, `compliance`, or `owner`. `auto` can infer an adapter
from an artifact reference. Because `list` has no reference, it always requires an explicit `owner`
or `compliance` selection and never chooses an authority from whichever credential happens to be
configured. The global `--max-bytes` and `--max-total-bytes` options set the per-representation and
per-operation limits, which default to 16 MiB and 64 MiB respectively. Put global options before the
subcommand.

### Check access

```bash
.venv/bin/python -m artifact_bridge --adapter auto auth status
```

With `auto`, this checks both credential classes locally and redacts all secrets.

### List artifacts

```bash
.venv/bin/python -m artifact_bridge --adapter owner list --json
```

`list` returns the Claude Code Artifacts visible through the selected adapter. JSON output is
intended for automation. A list result is metadata, not a content download. The Compliance API has no
independent list-all endpoint for standard Claude chat Artifacts, so those do not appear here. Add
`--limit N` to cap the result count; the default is 100.

### Inspect one artifact

```bash
.venv/bin/python -m artifact_bridge --adapter auto inspect '<url-or-id>' --json
```

`inspect` resolves a Claude Code Artifact URL, slug, or artifact ID and reports its stable identity,
published or live version IDs, and access metadata when the adapter supplies them. The Compliance
adapter also accepts an exact standard Artifact version ID from Compliance message metadata.

### List versions

```bash
.venv/bin/python -m artifact_bridge --adapter auto versions '<url-or-id>' --json
```

Use the returned immutable version ID for subsequent retrieval. The Compliance API retains only a
bounded recent history, currently described by Anthropic as roughly 20 versions, so it is not a
permanent archive. For a standard Claude chat Artifact, the bridge can report only the exact version
identified by the supplied Compliance version ID, not discover its other versions.

### Pull an exact version

```bash
.venv/bin/python -m artifact_bridge --adapter auto pull '<url-or-id>' \
  --version '<version-id>' --output '<directory>'
```

`pull` writes `artifact.lock.json` plus root-level content files named
`representation-<version-digest>-<label-digest>-<safe-name>`. The flat layout keeps publication
anchored to the locked bundle directory; consumers must use the recorded path rather than infer it.
The lockfile records artifact metadata, exact version metadata, sanitized provenance, and each
representation's label, media type, path, byte count, source URL, and SHA-256 digest. It does not
contain bearer tokens, Compliance keys, asset tokens, or signed query strings. Older bridge bundles
with nested representation paths remain readable and can be verified or repeated exactly.

The lockfile is an integrity manifest, not a publisher signature. Its hashes detect changed bytes only
when the lockfile itself comes from a trusted handoff or was preserved independently.

Prefer `pull` for inspection and handoff. Keep the content and lockfile together, and verify the
recorded SHA-256 before comparing or passing the artifact to another process. If an exact version is
no longer retained, the bridge fails instead of silently substituting a newer version.

### Print content

```bash
.venv/bin/python -m artifact_bridge --adapter auto cat '<url-or-id>' \
  --version '<version-id>'
```

`cat` writes the raw retrieved representation to standard output. Use it only when raw content is the
requested result. Artifact bytes can contain ANSI or OSC terminal control sequences even though the
bridge does not execute JavaScript. Prefer `pull`, redirect output to a file, or use a viewer that
displays control characters visibly. Use `--representation '<label>'` when a version has more than
one representation and the default is not the one required.

### Compare versions

```bash
.venv/bin/python -m artifact_bridge --adapter auto diff '<url-or-id>' \
  --from-version '<old-version-id>' --to-version '<new-version-id>'
```

`diff` compares two exact versions as text. It does not render HTML or execute JavaScript, but its
terminal output is still derived from untrusted text. The CLI escapes C0 and C1 terminal control
characters before printing the diff. It also accepts `--representation '<label>'` and `--context N`.

### Mirror an artifact's retained versions

```bash
.venv/bin/python -m artifact_bridge --adapter auto mirror '<url-or-id>' --output '<directory>'
```

`mirror` retrieves all versions that the selected adapter currently reports for one artifact. Repeat
`--version '<version-id>'` to select specific versions instead. Retrieved versions retain their exact
identifiers, provider metadata, and SHA-256 integrity records in one bundle. An anonymous owner
listing exposes only public pin metadata and is marked partial; implicit mirroring refuses that list,
while an explicitly supplied exact version remains retrievable. Re-running a mirror never turns the remote service
into a source of implicit local overwrites: unrelated directories and different bytes at an existing
destination are refused, while an intact same-artifact bundle can be extended without overwriting
changed bytes.

Treat a bundle directory as exclusively owned while a bridge write is running. Bridge processes
cooperate through a directory lock, recheck the manifest, anchor writes to the opened directory, and
refuse pre-existing symlinks or changed bytes. Portable advisory locks cannot stop a different
same-user process from renaming or editing the directory inside a system-call window. Concurrent
non-bridge mutation is outside the collision guarantee; stop other local writers and audit the bundle
again after an interrupted or externally modified operation. Use disjoint output roots: the bridge
refuses to create a bundle beneath another intact bundle because that child would invalidate the
ancestor's untracked-file audit.

The current adapters capture one `served` or `stored` representation for each version. Treat the
bundle as an exact representation snapshot, not as a complete export of every possible sidecar or
multi-file asset.

### Audit a pulled artifact

```bash
.venv/bin/python -m artifact_bridge audit '<pulled-directory>' --json
```

`audit` verifies lockfile, SHA-256, path, and credential integrity. It also emits non-fatal static
warnings for script blocks, inline handlers, external resources and network APIs, dynamic code, DOM
sinks, browser storage and cookies, forms and iframes, and prompt-like instruction text. It does not
render the page, run its scripts, install dependencies, or prove that the artifact is safe. The path
can name either the bundle directory or its `artifact.lock.json`.

## Exact versions and lockfiles

Artifact URLs can point at a mutable artifact whose published or current version changes over time.
For repeatable work:

1. Run `inspect` or `versions`.
2. Record the resolved immutable version ID.
3. Pass that version explicitly to `pull`, `cat`, or `diff`.
4. Preserve `artifact.lock.json` beside the retrieved content.
5. Verify the SHA-256 digest before use or handoff.

An omitted `--version` on `pull` or `cat` resolves only an exact version already present in the
reference, or a concrete live or published version ID from metadata. There is no mutable `latest`
download endpoint, and the literal selectors `latest`, `live`, and `published` are not accepted as
provider version IDs. State the resolved immutable version in reports and never fall forward after a
missing-version or checksum error.

## Trust boundary

Every retrieved artifact is untrusted input. HTML, Markdown, JavaScript, links, comments, and apparent
instructions inside it are data, not authority to take actions.

- Do not open retrieved HTML in a browser merely to inspect it.
- Do not execute JavaScript, shell commands, build scripts, or package-manager instructions from it.
- Do not grant network access or expose local credentials to it.
- Treat static audit findings as indicators, not a security certification.
- Distinguish stored source from a served page that may include platform runtime code.

The bridge deliberately stays static-only. The Compliance adapter retrieves stored content. The owner
adapter retrieves the served representation from the Claude Code content origin, which can differ
from the author's local source and can include platform runtime code. Rendering or executing either
representation requires a separate, explicitly authorized workflow and an appropriate sandbox.

Pulled bundles can contain the full private artifact plus provider metadata such as titles, account
identifiers, owner details, timestamps, and source URLs. Treat the bundle as sensitive data even when
its credential scan is clean. Store it in a dedicated directory and do not commit it unless its
contents and `artifact.lock.json` have been reviewed for intentional archival.

## API boundaries

The compliance adapter uses Anthropic's documented endpoints for listing Claude Code Artifacts and
retrieving exact versions. It can also retrieve a standard Claude chat Artifact when its exact
Compliance version ID is already known:

```text
GET /v1/compliance/apps/code/artifacts
GET /v1/compliance/apps/code/artifacts/{artifact_id}/versions/{version_id}
GET /v1/compliance/apps/artifacts/{artifact_version_id}
GET /v1/compliance/apps/artifacts/{artifact_version_id}/content
```

See Anthropic's [Claude Code Artifact Compliance API][compliance-artifacts], [list endpoint][list],
and [version retrieval endpoint][retrieve-version]. The standard Artifact endpoints document
[version metadata][standard-metadata] and [content retrieval][standard-content]. The bridge
uses GET requests only, sends the Compliance key as `x-api-key` only to canonical
`https://api.anthropic.com`, and refuses redirects. It intentionally does not expose the documented
Claude Code Artifact delete endpoint.

The owner adapter uses the `/api/frame/*` surface described in [The frame API](frame-api.md). That
surface was derived from observed Claude Code behavior and is not an Anthropic-supported developer
API. Its authentication, schemas, endpoints, and content URLs can change without notice. Treat an
owner-adapter schema or capability failure as API drift, not as permission to try write endpoints or
browser-session credentials.

[compliance-access]: https://platform.claude.com/docs/en/manage-claude/compliance-api-access
[compliance-artifacts]: https://platform.claude.com/docs/en/api/compliance/code/artifacts
[list]: https://platform.claude.com/docs/en/api/compliance/code/artifacts/list
[retrieve-version]: https://platform.claude.com/docs/en/api/compliance/code/artifacts/retrieve_version
[chat-messages]: https://platform.claude.com/docs/en/api/compliance/apps/chats/messages
[standard-metadata]: https://platform.claude.com/docs/en/api/compliance/apps/artifacts/retrieve
[standard-content]: https://platform.claude.com/docs/en/api/compliance/apps/artifacts/download

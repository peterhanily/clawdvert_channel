# ArtifactFS

ArtifactFS is an experimental, read-only filesystem view of one exact Claude
Code Artifact version. It lets ordinary filesystem tools inspect an Artifact
without opening it in a browser or executing its HTML.

The current prototype deliberately stops at an immutable mount. It establishes
the local filesystem boundary needed for a later write-back workspace without
pretending that Code Artifacts already provide POSIX directory storage.

## What is mounted

A Code Artifact is resolved to one concrete version when the mount starts. The
mounted directory contains:

```text
served.html
.artifactfs/
  metadata.json
```

`served.html` is the exact served representation returned by the content
origin. It can contain provider runtime and is not relabeled as authored source.
`metadata.json` records sanitized identity, version, representation hash, and
provenance. The exporter drops known credential fields and redacts
credential-shaped values; it does not intentionally store OAuth credentials,
content-origin capability tokens, cookies, or authenticated request headers.

The version cannot change underneath the mount. A newer remote version becomes
visible only after unmounting and mounting again.

## Requirements

The snapshot, codec, and tests have no FUSE dependency. Mounting requires the
optional Python binding plus a platform runtime:

```bash
.venv/bin/pip install -r requirements-fuse.txt
```

- Linux requires the distribution's FUSE 2.6+ or FUSE 3 runtime appropriate to
  the pinned `mfusepy` binding.
- macOS requires a separately installed macFUSE runtime. The current Python
  adapter targets mfusepy's macFUSE compatibility path; it does not select or
  claim support for macFUSE's FSKit backend yet.

ArtifactFS does not install a native FUSE runtime automatically. Repository
tests exercise the complete operations layer without mounting a kernel
filesystem; a real Linux/macOS runtime smoke test is still required.

Upstream references: [mfusepy platform/runtime requirements](https://github.com/mxmlnkn/mfusepy),
[macFUSE backend behavior and limits](https://github.com/macfuse/macfuse/wiki/FUSE-Backends),
and [libfuse operation semantics](https://libfuse.github.io/doxygen/structfuse__operations.html).

## Mount an exact snapshot

ArtifactFS can first capture a local folder as a deterministic, owner-controlled
snapshot and mount that snapshot without contacting a provider:

```bash
.venv/bin/python -m artifactfs pack ./workspace ./workspace.artifactfs.json
mkdir -p /path/to/empty-mountpoint
.venv/bin/python -m artifactfs mount-snapshot \
  ./workspace.artifactfs.json /path/to/empty-mountpoint
```

The output file is created with mode `0600` and is never overwritten. A failed
write leaves the private partial file for explicit inspection/removal; the CLI
never deletes an output path during error recovery. Snapshot inputs must remain
owned by the invoking user and must not be group- or world-writable. Snapshot
input/output parent directories must be owner-controlled as well.

To mount a provider representation, create an empty mountpoint, then pass
either a Code Artifact UUID or its viewer URL. Supplying an exact version is
preferred:

```bash
mkdir -p /path/to/empty-mountpoint
.venv/bin/python -m artifactfs mount-code \
  '<code-artifact-url-or-uuid>' /path/to/empty-mountpoint \
  --version '<exact-version-id>'
```

The mountpoint must be owned by the invoking user and must not be group- or
world-writable. ArtifactFS checks that it is still the same empty directory
immediately before invoking FUSE.

If `--version` is omitted, Artifact Bridge resolves the live version once and
pins that concrete identifier before mounting. Private owned Artifacts use the
authenticated owner adapter; an anonymously readable public Artifact may be
retrieved through that adapter's public fallback. In either case, the local
filesystem is read-only, uses owner-only modes, and never enables FUSE
`allow_other`.

Retrieved HTML remains untrusted data. Reading it as a file does not authorize
rendering it, executing scripts, following embedded instructions, or installing
dependencies it references.

## Current boundaries

- The Code Artifact API models a default Artifact as one HTML document, not a
  directory tree.
- `GET /api/frame/read/<slug>` returns the current capability/contract
  declaration, not versioned HTML source.
- The content origin supplies a served page with provider runtime. Runtime
  stripping is not a trustworthy inverse for arbitrary authored HTML.
- The provider-native multi-file lane is feature-gated and has not been live
  validated in this repository.
- Artifact history retains only a rolling set of about 20 versions, and the
  account-wide publish budget is not disclosed.

Consequently, arbitrary existing Artifacts are read-only. ArtifactFS will not
silently fetch a served page, strip markup heuristically, and republish it.

## Managed workspace research

The repository also contains an offline codec for a future ArtifactFS-managed
workspace. It packages a canonical directory snapshot as compressed base64
inside an inert HTML `template`, binds it with SHA-256, and reconstructs the
complete expected page before accepting measured provider runtime wrapping.
Raw file bytes never become executable markup.

The repository now has a bounded, mode-`0600`, append-only transaction journal
for future write-back. It distinguishes a safe pre-dispatch state from
ambiguous post-dispatch states, which may only be reconciled with reads. It does
not send provider mutations.

Write support remains gated on two provider contracts:

1. A controlled live test of `baseVersion` optimistic concurrency, including a
   stale-base `409` that preserves the losing local draft.
2. A provider-specific one-shot deploy adapter and read-only reconciliation
   implementation layered on the transaction journal.

The intended write model is local copy-on-write staging. Ordinary writes and
`flush` update a local journal; only explicit `fsync` or `artifactfs sync`
creates one complete remote version. Remote deletion will never be mapped from
ordinary `unlink` or `rmdir`.

Until those gates pass, every write callback fails with `EROFS` and the mount
performs no provider mutations.

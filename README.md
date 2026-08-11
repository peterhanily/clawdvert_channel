# clawdvert_channel

A research toolkit for working with Claude Artifacts: inspect and preserve exact
versions, publish controlled applications, test browser boundaries, and prototype
communication paths that operate within the Artifact environment.

For a project overview and demonstration, read the
[Caddy Labs article on clawdvert_channel](https://caddylabs.io/blog/clawdvert-channel/).

This is one toolkit, not one hosted service. Its command-line tools, browser
fixtures, relay, and research notes are separate instruments around the same
subject: how Claude Artifacts are created, served, isolated, and connected.
The browser/network research core is in `realm/`; the publisher, mailbox,
Artifact Bridge, API notes, and skills are companion tooling with separate trust
boundaries.

Anthropic reviewed the reported realm-scoped WebRTC behavior and metadata-channel
proof, not this repository as a whole. The automatic-answer application,
Artifact tooling, API notes, and agent skills are later work and are not
presented as reviewed or endorsed by Anthropic.

## Know which Artifact surface you are using

Claude has two distinct Artifact products. Their URLs, identifiers,
authentication, and permission models are not interchangeable.

| Surface | Typical URL | Support in this repository |
| --- | --- | --- |
| **Claude Code Artifact** | `claude.ai/code/artifact/<uuid>` | Direct publishing, owner inspection, version retrieval, mailbox transport, and the browser applications in `realm/` |
| **Standard Claude chat Artifact** | `claude.ai/public/artifacts/<uuid>` | Exact-HTML publication through model-backed and model-free seeded adapters, verified public/private/delete lifecycle, controlled demos, and Compliance retrieval from an exact version ID |

Commands should name or infer one surface and reject the other. The undocumented
Frame API used by the Code tooling is not a shortcut into standard chat Artifacts.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
./check.sh
```

`check.sh` is offline: it runs the deterministic test suite and structural checks
without reading Claude credentials or contacting Anthropic.

The supported Python range is 3.9 through 3.13 on macOS and Linux.

Most owner operations reuse an existing Claude Code OAuth login. The official
Compliance adapter instead uses `ANTHROPIC_COMPLIANCE_ACCESS_KEY`. Keep retrieved
private bundles and credentials out of source control.

## Choose a workflow

### Inspect an Artifact without running it

Artifact Bridge retrieves content as untrusted data, preserves exact versions,
records hashes and source metadata, and supports static comparison and audit. It
does not publish, share, delete, or render Artifact code.

```bash
.venv/bin/python -m artifact_bridge --adapter auto inspect '<url-or-id>' --json
.venv/bin/python -m artifact_bridge --adapter auto pull '<url-or-id>' \
  --version '<version-id>' --output '<directory>'
.venv/bin/python -m artifact_bridge audit '<directory>' --json
```

See [Artifact Bridge](docs/artifact-bridge.md).

### Publish a Claude Code Artifact

```bash
.venv/bin/python -m clawdvert.publish page.html --dry-run
.venv/bin/python -m clawdvert.publish page.html --favicon 📊
```

Publishing changes provider state. New Artifacts are private; public visibility is
a separate, version-specific operation. See the measured
[Frame API reference](docs/frame-api.md).

### Mount a Code Artifact without rendering it

ArtifactFS provides an experimental, locally private, read-only filesystem view
of one exact Code Artifact version. It exposes the provider-served page as
`served.html` plus sanitized version metadata, without opening or executing the
Artifact in a browser.

```bash
.venv/bin/pip install -r requirements-fuse.txt
.venv/bin/python -m artifactfs mount-code '<code-artifact-url-or-uuid>' \
  /path/to/empty-mountpoint --version '<exact-version-id>'
```

The reference may be an owned Artifact or an anonymously readable public
Artifact; the local mount remains readable only by the invoking user. The
current prototype intentionally does not write or delete remote Artifacts.
See [ArtifactFS](docs/artifactfs.md) for platform requirements, the mounted
layout, and the guarded path toward a versioned write-back workspace.

### Publish a standard chat Artifact

Standard chat Artifacts are separate from Claude Code Artifacts. This publisher
accepts complete HTML, verifies the selected account and organization, and does
not open or execute the Artifact preview.

| Adapter | Model use | Existing state required | Support status |
| --- | --- | --- | --- |
| `conversation` | One bounded model turn creates the file | None | Live validated; default |
| `seeded-public` | None | An active public Standard Artifact created by the `conversation` adapter | Live-proven provider contract; experimental adapter |
| `native-share` | None | An enabled native Cowork sharing capability | Contract tested offline; controlled accounts returned 404 |

The default `conversation` adapter creates a private Standard Artifact and can
optionally publish it:

```bash
.venv/bin/python -m clawdvert.publish page.html --surface chat \
  --browser-port 9223 --account-email-sha256 '<lowercase-email-sha256>' \
  --organization-uuid '<organization-uuid>' --receipt standard-artifact.jsonl \
  --public
```

The experimental `seeded-public` adapter publishes reviewed HTML without a
model turn or driving the chat interface:

```bash
.venv/bin/python -m clawdvert.publish page.html --surface chat \
  --chat-adapter seeded-public --public \
  --seed-file seed.html \
  --seed-receipt existing-conversation-artifact.jsonl \
  --receipt new-artifact.jsonl \
  --browser-port 9223 --account-email-sha256 '<lowercase-email-sha256>' \
  --organization-uuid '<organization-uuid>' \
  --acknowledge-experimental-seeded-public
```

Seeded publication requires an active public Standard Artifact already owned by
the selected account, its original HTML, and the `conversation` adapter receipt
that recorded its active publication. The seed is an input and is never modified
or deleted.

The resulting public mapping serves the supplied HTML exactly, while its
disposable private clone retains the seed content. Title, Artifact type, and
language are inherited from the seed. This mode therefore creates a public
Artifact only; it is not a general raw-content API for creating a matching
private Artifact.

“Without a chat turn” means no prompt submission or model generation. The
publisher still loads a controlled signed-in `/new` page as its same-origin API
wrapper, and the provider creates a disposable backend conversation and message
container for the private clone. An owner-only receipt records that state and
the distinct public mapping so they can be reconciled and cleaned up exactly.

Use the same target source, seed source, and lifecycle receipt with `--private`
to remove and verify the public mapping, or `--delete` to remove the mapping
when necessary and then delete the disposable conversation. Neither operation
affects the seed.

All standard-Artifact adapters use at-most-once mutations, never retry an
ambiguous write blindly, and limit cleanup to identifiers positively bound in
an owner-only receipt. The publisher does not export browser cookies, use the
Claude Code Frame API, or render the supplied HTML. Use only content and seed
Artifacts you own and have reviewed.

The provider interfaces are undocumented and may drift. The `seeded-public`
provider contract completed a bounded controlled-account acceptance test; the
repository adapter is covered by offline contract and recovery tests. It remains
experimental and has no automatic fallback to the model-backed adapter. See
[Standard Artifact publisher](docs/standard-artifact-publisher.md) for
requirements, observable lifecycle, recovery behavior, and limitations.

### Explore the communication prototypes

- The [private mailbox](docs/mailbox.md) exchanges messages between two machines
  signed into the same account by using private Code Artifacts as versioned blobs.
- [`realm/clawdvert_channel.html`](realm/clawdvert_channel.html) is the browser
  chat and file-transfer application.
- The [relay deployment guide](docs/deploy-relay.md) explains the signalling
  relay and the separate TURN media relay.

These are research prototypes, not a general messaging service.

## Research boundaries

- Artifact Bridge is provider-read-only; `clawdvert` publishing and mailbox
  commands are not.
- Retrieved HTML and JavaScript are untrusted. Audit them as text before choosing
  to render or execute them.
- Measurement fixtures use synthetic state, explicit user actions, and bounded
  cleanup; they do not contain real credentials or private Artifact data.
- Experimental surfaces may drift; see the detailed references for support limits.

## Documentation

- [Artifact Bridge command and trust model](docs/artifact-bridge.md)
- [ArtifactFS immutable filesystem mount](docs/artifactfs.md)
- [Standard Artifact publisher](docs/standard-artifact-publisher.md)
- [Claude Code Frame API observations](docs/frame-api.md)
- [Private Artifact mailbox protocol](docs/mailbox.md)
- [Browser automatic-answer flow](docs/auto-answer-return.md)
- [Rendezvous V2 contract](docs/rendezvous-v2.md)
- [Relay deployment and hardening](docs/deploy-relay.md)
- [Security policy](SECURITY.md) · [Canary privacy boundary](PRIVACY.md) ·
  [Apache-2.0 license](LICENSE)

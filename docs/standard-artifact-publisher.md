# Standard Artifact publisher

The Standard Artifact publisher accepts complete, reviewed HTML and creates or
publishes it on Claude's standard chat Artifact surface. It is separate from the
Claude Code Frame publisher and from the read-only Artifact Bridge.

The publisher verifies the selected account, organization, source digest, and
provider-returned identifiers. It treats HTML as inert text: it does not open an
Artifact preview, render the source, or export browser cookies.

## Choose an adapter

| Adapter | What it provides | Model use | Status |
| --- | --- | --- | --- |
| `conversation` | A matching private Standard Artifact, with optional public publication | One bounded turn | Live validated; default |
| `seeded-public` | An exact public Artifact backed by a disposable private clone | None | Live-proven provider contract; experimental adapter |
| `native-share` | Direct raw-content sharing when the account exposes the native capability | None | Offline contract tested; unavailable on the controlled accounts tested |

Adapters never silently fall back to another mode. A failure in an explicitly
selected adapter remains a failure in that adapter.

## Conversation-backed publication

The default adapter creates one exact output file through a bounded model turn,
then verifies the generated-file request and the converted Artifact source. The
new Standard Artifact starts private. With `--public`, the publisher creates and
verifies a separate public mapping.

This mode is the right choice when the private Artifact must contain the same
HTML that is being published. The HTML becomes part of the model prompt, so use
only source you control and have reviewed.

An owner-only lifecycle receipt binds the conversation, Artifact, version,
message, source digest, and public mapping. The same receipt supports verified
unpublish and deletion of the disposable conversation.

## Seeded public publication

The `seeded-public` adapter publishes exact HTML without model generation or
driving the chat interface. It requires an active public Standard Artifact
previously created by this repository's `conversation` adapter, owned by the
same account and organization. That existing Artifact is the seed.

The provider creates a private clone of the seed and a distinct public mapping:

| Object | Content | Lifecycle ownership |
| --- | --- | --- |
| Seed | Original seed HTML | Existing input; never modified or deleted |
| Private clone | Original seed HTML | Disposable container recorded in the new receipt |
| Public mapping | Requested target HTML | Exact published result recorded in the new receipt |

The target's title, Artifact type, and language are inherited from the seed.
The private clone intentionally does not contain the target HTML, so this mode
cannot produce a matching private target Artifact. It is designed for exact
public publication only.

“No chat turn” here means no prompt submission and no model generation. The
publisher still loads a controlled signed-in `/new` page as a same-origin API
wrapper, and Claude assigns a backend conversation and message container to the
private clone. The publisher records and later deletes that exact disposable
container without touching the seed.

Seeded publication requires:

- a dedicated Chrome profile already signed in to the intended account;
- the exact account email SHA-256 and organization UUID;
- complete HTML that has been reviewed as untrusted code;
- the seed's exact original HTML;
- an owner-only `conversation` adapter receipt for an active public seed;
- a new owner-only lifecycle receipt for the target; and
- explicit acknowledgement that the adapter uses an experimental provider
  contract.

The seed receipt and target receipt must be different files. The seed must stay
active and unchanged for the operation; every target mutation is bracketed by
exact seed verification. Cleanup identifiers are required to be distinct from
all seed identifiers.

## Lifecycle and cleanup

Standard Artifact state has several independent dimensions. The publisher
tracks them separately rather than treating a private version, a public mapping,
and a conversation as the same object.

For seeded publication, successful acceptance proves:

- the seed is still active, owned, and byte-exact;
- the private clone is uniquely bound to its returned conversation, Artifact,
  version, and message identifiers;
- the private clone still contains the seed source;
- the public mapping is uniquely bound to the clone;
- an anonymous read returns the target HTML exactly; and
- the public identifier is distinct from the seed's public identifier.

`--private` removes only the target's public mapping. Success requires active
mapping absence, the exact deleted tombstone, the clone version's deletion
timestamp, and anonymous API inaccessibility.

`--delete` first removes the public mapping when necessary, then deletes the
exact disposable clone conversation. Success requires conversation absence,
catalog absence, version absence, and a final unchanged-seed check. The seed is
never a cleanup target.

## Receipts and interruption recovery

Receipts are append-only, owner-only journals. They contain source hashes,
operation phases, and validated provider identifiers, but not browser cookies,
raw account email, or HTML source.

Every mutation is attempted at most once. The publisher writes its intent before
dispatch and never repeats an ambiguous mutation. Interrupted receipts are
retained for explicit read-only state reconciliation; the normal lifecycle
command refuses to repeat their pending mutation. Recovery may advance only
when a unique positive binding or tombstone is available. If ownership or
provenance cannot be proved, cleanup stops instead of guessing from titles,
timestamps, or list position.

If publication is definitively rejected, the receipt records that outcome and
retains the exact private clone. It will not retry publication automatically;
`--private` leaves the clone in place and `--delete` removes it after exact
revalidation.

Keep the target source, seed source, and receipt until cleanup has been verified.
The receipt is both the audit trail and the authority boundary for later
lifecycle operations; the source files supply the bytes that the receipt binds
by digest.

## Limitations

- `seeded-public` cannot bootstrap without an active, owned public seed.
- It does not create a private Artifact containing the target source.
- Target title, type, and language are inherited from the seed.
- The provider interfaces are undocumented and can change without notice.
- Availability may differ across account tiers and organizations.
- `native-share` remains capability-dependent and is not confirmed for general
  accounts.
- A provider transport failure after an at-most-once mutation may require
  read-only reconciliation before any cleanup can continue.

## Validation status

The conversation adapter has completed bounded live acceptance. The provider
contract used by `seeded-public` also completed a separate bounded
controlled-account acceptance: exact anonymous target-content readback, a
private clone retaining the seed source, verified public tombstoning, verified
clone-conversation deletion, and final seed integrity checks. The repository
adapter is a port of that contract and has been validated offline; it has not
been represented as a second live run of the integrated CLI.

The live seeded acceptance used a small inert HTML target derived from the seed.
The adapter validates other reviewed HTML within its documented size limit, but
that wider input space is an offline contract claim rather than a live test of
every possible document shape.

The repository's offline tests exercise request construction, identifier and
receipt binding, ambiguity handling, and cleanup routing without contacting
Claude. Passing offline tests demonstrates the implemented contract; it does not
guarantee that an undocumented provider interface remains available.

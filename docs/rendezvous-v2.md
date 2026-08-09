# Rendezvous V2 contract

Status: the complete room-repair contract is implemented in reviewable source
and remains dormant. Build `0.29.0-auto-answer` ships a deliberately narrower
subset: one full CC2 invitation is copied manually and only its compact
encrypted answer returns through rr2.

Rendezvous V2 uses the constrained TURN-address mailbox only to establish an
ordinary WebRTC data channel. It is a separate protocol from durable room
messages and from V1's append-only signalling log. It deliberately contains no
wall-clock appointment or append-only repost. A writer may repeat the same
byte-identical value as an idempotent latest-slot PUT; that refreshes one slot
and never creates a signalling event backlog.

The contract is written so the codec, attempt state machine, relay slot store,
browser adapter, and deferred interoperability suite can be reviewed
independently. A conforming implementation must satisfy every invariant in this
document before either full automatic repair or fully compact first pairing is
enabled. The shipped subset has its own narrower invariants below.

## Scope and non-goals

V2 provides:

- bounded, latest-value rendezvous state for late readers;
- an authenticated, replay-bounded offer/answer exchange;
- a candidate-free offer and candidate-bearing answer;
- IPv4, IPv6, UDP, and TCP candidate fidelity;
- independent per-peer attempts on one room-level repair bus;
- an explicit candidate fallback extension for browsers or networks that need
  an offerer candidate;
- a migration path from a room-wide key to pairwise repair keys; and
- reserved codec and relay routing for a future compact-bootstrap profile.

The canonical V2 token by itself does not provide:

- confidentiality for ICE credentials, fingerprints, candidates, identifiers,
  timing, or traffic volume;
- availability against a malicious or unavailable relay;
- endpoint security after a device or browser origin is compromised;
- proof that a room-wide MAC was produced by a particular room member;
- NAT/browser interoperability without the deferred browser/network matrix; or
- storage for chat, room state, files, or the full invitation.

These scope statements describe fully compact room repair and pairing. The
shipped automatic-answer profile is a transitional integration: its full CC2
invitation already carries the offer, room identity, channels, optional TURN
configuration, and a one-use answer-return descriptor. The joiner stages that
metadata provisionally, but authoritative membership and room state are not
accepted until the data channel passes `link-hello`.

## Shipped automatic-answer profile

The deployed profile does not publish an offer slot. The inviter gathers a
normal candidate-bearing WebRTC offer, adds an invitation-bound five-minute
descriptor, and gives that complete CC2 code to one intended joiner. The
joiner validates the descriptor and exact offer hash, removes and retains the
offer candidates before applying the SDP, gathers an answer, and returns one
compact answer through rr2.

That answer is a canonical V2 `bootstrap` answer with one or two candidates,
signed with HMAC-SHA-256 and then wrapped with AES-GCM. HKDF over the 256-bit
invitation secret derives independent token, wrapper, and private rr2-room
material. The descriptor binds the app, room, WebRTC session, invite ID, relay
profile, exact offer, absolute expiry, attempt, and secret. The AES-GCM
associated data additionally binds the answer's exact rr2 selectors.

The inviter verifies and applies a candidate-free reconstructed answer and its
separately verified candidates before ACKing the slot. The joiner treats
`ACKED` only as permission to release the offer candidates retained from the
invitation. DTLS and the application `link-hello`, not rr2 ACK, establish the
peer and room membership. The full flow, fallback, and privacy boundary are in
[auto-answer-return.md](auto-answer-return.md).

## Activation and rollback gates

The following logical flags are independent. Names in a deployment adapter may
be mechanically different, but their defaults and predicate must not be.

| Flag | Default | Meaning |
| --- | --- | --- |
| `ENABLE_LEGACY_AUTOMATIC_SIGNALLING` | `false` | Allows V1 short-code pairing and V1 rendezvous. It remains off. Manual invite/answer exchange is unaffected. |
| `RENDEZVOUS_V2_SLOTS` | `false` | Allows the relay to serve `rr2` ephemeral slots. Relay support may be deployed while unadvertised. |
| `AUTO_ANSWER_RETURN_ENABLED` | `true` in build `0.29.0-auto-answer` | Allows the narrow full-invite/compact-answer profile. It is independent of full repair and compact pairing. |
| `RENDEZVOUS_V2_CLIENT_BUNDLED` | `false` | Confirms the complete coordinator/keyring/adapter client, not merely shared primitives, is bundled for room repair. |
| `RENDEZVOUS_V2_AUTO_REPAIR_ENABLED` | `false` | Allows a mutually capable room to select V2 repair. |
| `RENDEZVOUS_V2_COMPACT_PAIRING_ENABLED` | `false` | Allows an explicit V2 bootstrap pairing flow. |

The automatic-answer build reproducibly bundles only the codec, SDP, slot
transport, TURN exchange, and answer-return module. Its true build gate does
not satisfy `RENDEZVOUS_V2_CLIENT_BUNDLED` and cannot select full repair. A new
relay still defaults rr2 off; the current canary explicitly enables the server
flag for this answer-return profile.

Automatic repair is selectable only when all of these are true:

```text
RENDEZVOUS_V2_CLIENT_BUNDLED
AND RENDEZVOUS_V2_AUTO_REPAIR_ENABLED
AND relay authenticated capability says rr2 slots are enabled
AND (for initiation) the intended peer advertised rv2 on an authenticated data channel
```

A locally enabled room listener still discovers and verifies directed offers
from a peer for which it has a derived pairwise verification key, even if the
final ready/capability message was lost. Such a peer cannot initiate locally;
a successfully verified offer authorizes only its bound answerer attempt.

Compact pairing additionally requires an explicit user action, the compact
pairing flag, and an approved bootstrap key profile. A health endpoint is useful
for operations but is not, by itself, an authenticated browser capability.

Failure after selecting full V2 repair returns to manual invite/answer
exchange. Failure in automatic answer reveals the ordinary answer plus its
explicit Start barrier; revealing that fallback does not cancel a still-live
automatic attempt, but actually starting either path atomically claims it. No
failure may silently enable V1 automatic signalling. Once two peers have recorded an
authenticated V2 capability, an automatic downgrade is rejected; a user may
still deliberately choose the manual exchange.

## Threat model

Assume the relay and network can observe, delay, drop, replay, reorder, replace,
or duplicate any slot operation. Assume another client can discover or guess a
six-character relay room and can invent its own relay actor identifier. The
authenticated token is the security boundary; routing metadata and transport
ACKs are hints.

Automatic answer does not use a six-character room: it derives a private
128-bit room credential from the invitation secret. It still treats the relay
as malicious and relies on wrapper authentication, token authentication, DTLS,
and `link-hello` rather than secrecy of relay behavior.

The 16-byte truncated HMAC-SHA-256 tag covers a domain separator and every
canonical body byte. It therefore binds:

- version and key profile;
- offer, answer, control, or fallback role;
- referenced role for acknowledgements and control messages;
- 128-bit attempt identifier;
- 96-bit application or bootstrap context identifier;
- sender and recipient routing selectors;
- issue time and lifetime;
- ICE credentials, DTLS setup role, and SHA-256 fingerprint; and
- every candidate field.

The MAC input is:

```text
ASCII("clawdvert/rendezvous-v2\0") || canonicalBody
```

No body field is parsed, trusted, returned, or allowed to mutate attempt state
before the tag verifies. Before returning a verified token, the codec also
enforces its canonical form, role shape, lifetime, and caller-supplied expected
profile/role/context/from/to/attempt context.

HMAC is integrity, not encryption. Anyone operating the relay can read an
unwrapped canonical token. The automatic-answer profile adds an AES-GCM layer,
so its relay sees routing selectors, timing, and ciphertext size but not the
answer token. A relay can always deny service by deleting a slot, returning
stale control data, or refusing packets; V2 bounds that failure but cannot
prevent it.

### Key profiles

| ID | API name | Key source and security property |
| ---: | --- | --- |
| 1 | `bootstrap` | A 128-bit-or-stronger random bearer secret delivered by a full invitation, QR/deep link, or output from an audited PAKE. A six-character locator alone is not a suitable HMAC key. |
| 2 | `pairwise` | A 256-bit per-device-pair repair key exchanged over the authenticated data channel and stored with the peer record. This is the normal repair profile. |
| 3 | `roomTransition` | A room-wide migration key. It authenticates room membership but cannot distinguish members or prevent one member impersonating another. Off by default and removable after pairwise keys exist. |

Raw HMAC keys accepted by the portable codec are 16-64 bytes. Deployments should
use 32 random bytes. A caller may instead supply a 128-512-bit non-extractable
Web Crypto HMAC/SHA-256 `CryptoKey` with `sign` usage; the codec enforces that
same strength range from the key's algorithm metadata.

Authentication profile selection is bound per peer and direction, not tried as
a global fallback list. A derived pairwise key is sufficient to verify; a
confirmed pairwise key is required to initiate. An answerer may sign within the
specific attempt created from a successfully verified pairwise offer, because
that offer proves the initiator derived the same key even if its final ready
message was lost. `roomTransition` is selected only by an explicit policy for a
peer that has not begun the pairwise upgrade. This prevents an automatic
downgrade by a room-key holder.

Profile policy selects only a new attempt. Once admitted, that attempt retains
its bound profile for every exact answer/control verification even if the peer
record upgrades concurrently. Keep the old verification key until the attempt
and its replay horizon drain; a migration cannot reinterpret an in-flight slot
under a new key.

Full repair uses authenticated 64-bit device routing identities, not public
keys. Automatic answer instead uses invitation-scoped random 64-bit rr2
selectors because the host does not know the joining application member ID
yet; that member is pinned later by `link-hello`.
Attempt IDs are fresh 128-bit values produced by a CSPRNG and are never reused,
including after an ICE restart.

The 96-bit `contextId` prevents a valid token made with a long-lived pairwise
key from being replayed through another room or bootstrap exchange. For an
established room it is the first 12 bytes of
`SHA-256("clawdvert/rendezvous-v2/room-context\0" || ASCII(canonicalRoomId))`.
This binds the room without exposing the raw application room ID in the token.
A bootstrap exchange generates or transcript-derives a separate 96-bit value
and includes it with the bootstrap secret. Relay routing metadata is not a
substitute for this signed field.

For a bootstrap offer only, recipient `0000000000000000` means “the first
holder of this bootstrap secret.” The accepted answer reverses the route and
uses both concrete device IDs. The offerer accepts one answer, binds that peer,
and rejects competing answers for the attempt.

## Canonical token format

The primary transport value is raw authenticated bytes. The `rr2` relay stores
those bytes directly and applies its own single base64url layer inside the TURN
username. Do not pass the diagnostic `~v2~...` text through `rr2`; double
base64url expansion wastes the 509-character TURN username budget.

The body uses network byte order. Integers are unsigned. All reserved bits and
unknown enum values are fatal.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 1 | Magic `0x52` (`R`) |
| 1 | 1 | Version `2` |
| 2 | 1 | Key profile: bootstrap `1`, pairwise `2`, room transition `3` |
| 3 | 1 | Role: offer `1`, answer `2`, ACK `3`, abort `4`, need-candidate `5`, candidate `6` |
| 4 | 1 | Flags described below |
| 5 | 1 | Referenced role, or zero |
| 6 | 2 | Lifetime in seconds, 15-300 |
| 8 | 4 | Unix issue time in seconds |
| 12 | 16 | Attempt ID |
| 28 | 12 | Application/bootstrap context ID |
| 40 | 8 | Sender routing selector |
| 48 | 8 | Recipient routing selector |
| 56 | variable | Optional ICE block, followed by zero to two candidates |
| final 16 | 16 | First 16 bytes of HMAC-SHA-256 |

Flags byte:

```text
bits 0-1  candidate count: 0, 1, or 2; 3 is invalid
bits 2-3  DTLS setup: none 0, actpass 1, active 2, passive 3
bit 4     ICE block present
bits 5-7  reserved and zero
```

When present, the ICE block is:

| Bytes | Field |
| ---: | --- |
| 1 | ICE username-fragment byte length |
| 1 | ICE password byte length |
| 4-32 | ICE username fragment, RFC ICE ASCII alphabet |
| 22-64 | ICE password, RFC ICE ASCII alphabet |
| 32 | Binary SHA-256 DTLS fingerprint |

The fixed 56-byte body includes context, both routing identities, and the attempt ID, so
the same authenticated bytes can be compared with the untrusted `rr2` routing
key after verification.

### Role shapes

| Role | Required shape |
| --- | --- |
| `offer` | ICE block, `actpass`, zero candidates, zero reference role |
| `answer` | ICE block, `active` or `passive`, one or two candidates, zero reference role |
| `ack` | No ICE/candidates; references offer, answer, or candidate |
| `abort` | No ICE/candidates; references the phase being aborted |
| `needCandidate` | No ICE/candidates; references the candidate-free offer |
| `candidate` | No repeated ICE block; one or two candidates; references need-candidate |

These constraints prevent relabelling a valid body as another protocol action.

### Time and replay rules

Issue time and expiry are rejection boundaries only. They never schedule ICE
or coordinate two clocks. An outbound attempt may create its peer connection,
offer, and gathered ICE material first; its authenticated token epoch starts
exactly once after that bounded preparation and immediately before key lookup,
HMAC, and slot publication. Retiming after publication is forbidden.

The codec requires the receiver's current Unix seconds and rejects a token that
is more than the configured clock tolerance in the future or at or beyond
`issuedAt + lifetime + tolerance`. The portable codec accepts tolerances through
300 seconds, but the established-room profile fixes both peers at 120 seconds;
it is not an independently tunable deployment value.

Clock tolerance permits authentication; it is not usable responder lifetime.
An inbound attempt must retain its complete minimum budget before raw signed
expiry, and a responder neither publishes nor consumes new signalling after
that boundary. The initiator may continue receiving through its codec-tolerance
horizon so a response sent within the conservative raw-expiry window is still
consumable under the allowed relative clock skew, but it also stops publishing
new offers and generic control at raw expiry. The sole role-specific exception
is a candidate response to an already verified `needCandidate`: the requester
reserved the entire reverse leg against its own deadline, so that bound response
may use the offerer's receive/skew horizon. A short completion grace may accept only an already-negotiating
authenticated data channel. Replay guards cover the complete authentication
horizon plus the configured replay skew and are persisted across reload. The
relay independently expires an active slot after at most 300 seconds.

After its general publish deadline an offerer may still poll for an answer,
signed abort, or `needCandidate` through the receive horizon. It cannot mint any
other late signalling, and the one candidate response still needs a complete
isolated PUT budget before that extended horizon.

The established-room defaults use the full 300-second signed/slot lifetime and
require at least 230 seconds of raw-expiry budget before admitting an inbound
offer. A later offer is authenticated for cleanup/replay handling but is not
allowed to create a peer connection that cannot finish the bounded normal path.
That admission split assumes the established listener performs at most one
discovery read at a time and begins the next read within one second plus 20%
jitter. Its pre-admission bound includes one already-running empty discovery
page, a maximum-size offer read, key lookup, and HMAC verification.
The established adapter caps ordinary polling at one second, key lookup and
HMAC at two seconds each, and logical PUT retries at one; wider values require
a separately versioned timing profile rather than unilateral configuration.

The codec exposes `issuedAt` and `expiresAtSeconds`. Coordinator timestamps use
JavaScript milliseconds. The coordinator acceptance boundary explicitly
multiplies verified seconds by 1,000; no component may compare the two units
directly.

## Candidate representation

Each candidate record consists of a descriptor, priority, port, and binary
address:

| Bytes | Field |
| ---: | --- |
| 1 | Candidate descriptor |
| 4 | Original candidate priority, 1 through 2^31-1 |
| 2 | Port, 1-65535 |
| 4 or 16 | IPv4 or IPv6 address |

Candidate descriptor:

```text
bit 0     family: IPv4 0, IPv6 1
bit 1     transport: UDP 0, TCP 1
bits 2-3  type: host 0, srflx 1, relay 2; 3 invalid
bits 4-5  tcptype: none 0, active 1, passive 2, so 3
bits 6-7  reserved and zero
```

UDP requires `tcptype=none`; TCP requires active, passive, or simultaneous-open.
Component is always 1. Foundation is regenerated locally. Related address and
port are not transported because they are not used for checks; reconstructed
server-reflexive and relay candidates use an address-family-appropriate masked
related address and port 9.

FQDN and mDNS candidates are intentionally outside V2. An adapter skips them
rather than changing their protocol or attempting to pack text into the address
field. Host candidates may be disabled as a privacy policy.

Select at most two candidates. Candidate selection is explicit and stable:

1. UDP relay;
2. TCP relay;
3. UDP server-reflexive;
4. TCP server-reflexive;
5. an allowed host candidate.

When two are carried, prefer route diversity over two near-identical addresses:
normally one UDP relay plus one TCP relay or server-reflexive candidate. Never
rewrite TCP to UDP, IPv6 to IPv4, or candidate priority.

The shipped automatic-answer profile excludes host candidates and chooses at
most two representable relay or server-reflexive routes. If no such complete
candidate fits, it exposes the manual fallback rather than weakening the
format or publishing a local address.

## Size budget

The current durable mailbox accepts at most 280 message characters. `rr2`
allows a 240-byte slot payload, but the codec deliberately uses the lower bound
needed for a 280-character diagnostic representation:

```text
maximum authenticated token = 207 bytes
established-profile offer    = 188 bytes
maximum canonical body       = 191 bytes
HMAC tag                     =  16 bytes
diagnostic text prefix       = "~v2~"
maximum diagnostic text      = 280 characters
```

For username fragment length `U`, password length `P`, and candidate address
lengths `A`:

```text
body = 56 + ICE?(2 + U + P + 32):0 + SUM(7 + A)
raw  = body + 16
raw <= 207
```

The codec fails closed when combined variable fields exceed the bound and never
truncates credentials. Before signing, the browser adapter measures the exact
token: it first tries both ranked candidates, then deterministically tries each
single candidate in rank order. It uses the first ranked single candidate that
fits and never truncates or rewrites a candidate; an answer that cannot fit any
complete candidate fails to the manual path.

The portable codec accepts any role through the 207-byte bound. The established
browser profile further caps a candidate-free offer at 188 raw bytes (combined
ufrag/password length at most 82 characters), so discovery needs no more than
ten six-lane pages. A browser producing longer credentials returns to manual
repair; it does not silently spend the responder's admission budget.

Deterministic fixture sizes are:

| Token | Body | Raw with tag | Diagnostic text |
| --- | ---: | ---: | ---: |
| Offer, 8-byte ufrag and 24-byte password | 122 bytes | 138 bytes | 188 chars |
| Answer plus one IPv4 and one IPv6 candidate | 156 bytes | 172 bytes | 234 chars |
| ACK control token | 56 bytes | 72 bytes | 100 chars |

The fixed no-ICE control size is 72 raw bytes. A candidate-only token carrying
two maximum IPv6 records is at most 118 raw bytes; the adapter uses these exact
role bounds when reserving fallback reads rather than charging the 207-byte
answer maximum twice.

The representative two-candidate answer therefore leaves 35 bytes below the
codec's raw bound and 68 bytes below the relay slot bound.

Automatic answer wraps the signed token in one magic byte, a 12-byte AES-GCM
nonce, and a 16-byte GCM tag. Even a maximum 207-byte token is therefore 236
bytes, leaving four bytes below the rr2 slot bound. One nonce and ciphertext
are created per invitation attempt and reused byte-for-byte for retries.

## Relay latest-value slots

`rr2` is separate from `RoomStore`. It never allocates a global message
sequence, never enters the chat event array, and never reaches JSONL message
persistence.

The logical key is:

```text
room / from / to / attempt / slot-role
```

The routing fields are observable and untrusted. After HMAC verification, the
client compares all of them with the signed profile, role, sender, recipient,
and attempt before dispatching the token.

Slot role letters are:

```text
o offer     a answer     n need-candidate
c candidate k signed ACK x signed abort
```

### Operations

- `put`: create revision 1 with caller revision 0, or compare-and-set an
  existing revision. Repeating byte-identical content is idempotent and does
  not increase revision or extend a logical event log.
- `get`: read an exact logical key. Supplying the current revision returns
  not-modified.
- `discover`: fetch the newest active offer for a route when the attempt ID is
  not yet known, or select an exact attempt with a wildcard sender. Automatic
  answer uses the latter to find the first answer for its pre-bound attempt.
  This reads current state, not “messages after my cursor,” so a late reader
  sees unexpired state.
- `ack`: untrusted storage acknowledgement for an exact slot revision. It
  replaces payload bytes with a bounded, payload-free terminal tombstone.
- `abort`: untrusted storage cleanup for an exact slot revision. Either known
  participant may tombstone the slot.

An active slot and its payload-free ACK/abort tombstones expire after no more
than 300 seconds. Per-room and global cardinality limits are mandatory. Payload
bytes are never logged, persisted, or included in health output.

The browser carrier has one bounded, paced scheduler for the room. PUTs use a
reserved high-priority queue and carry the attempt's local signalling deadline;
the adapter subtracts one isolated exchange budget for every remaining bounded
initial/retry attempt, and the scheduler rejects a write if allocation would
start at or after that latest safe-start boundary.
Reads are low priority and storage cleanup is normal priority. Capacity must
reserve at least one critical PUT per active attempt plus one read per active
attempt, a listener, and cleanup. This prevents terminal drains from rejecting
a new answer at admission without creating parallel allocation bursts. Timing
budgets are deliberately named isolated-service budgets: bounded multi-peer
contention can still consume a deadline, in which case the attempt fails to the
manual path rather than claiming a false latency guarantee.

### Two acknowledgement layers

Transport `ack` and `abort` operations are not HMAC-authenticated. They do not
establish a peer identity, mark a connection open, prove membership, accept
unauthenticated SDP, or otherwise cause a security transition. A malicious
relay can synthesize or suppress them, which remains an availability attack.

The automatic-answer profile uses `ACKED` for one narrower availability
transition: after the host has authenticated and applied the answer, its ACK
allows the joiner to release offer candidates retained from the invitation.
Premature release can make ICE fail, but it cannot make DTLS accept the wrong
fingerprint or make `link-hello` pass. The full room-repair coordinator retains
cleanup-only ACK semantics.

The codec and relay reserve a signed `ack` token (`k` slot) for a future
phase-specific extension, but the established-room coordinator deliberately
does not accept it: normal success is the authenticated link-hello on the open
data channel. A signed `abort` token (`x` slot) remains the authenticated peer
failure signal. An `rr2 ack` control response is never translated into peer
state.

Within its terminal tombstone lifetime, an acknowledged or aborted slot cannot
be resurrected under the same key. Full repair recovery creates a fresh attempt
ID. Automatic answer has a deliberately narrower resume rule: after an ACK
tombstone expires, a suspended writer may PUT the exact previously accepted
ciphertext again under the same invitation attempt. The host compares the
bytes, re-verifies the answer, and re-ACKs it until `link-hello` or capability
expiry. Changed or retimed content is rejected.

### Idempotency and equivocation

One logical token is published once. A retry caused by an ambiguous network
result uses the same key, same bytes, and compare-and-set revision; it never
generates a new request or attempt ID merely to repeat content.

The state machine permits each authenticated role only in its defined phase;
later valid observations of a consumed role are duplicate, deferred, or invalid
and cannot replace already-applied SDP. The relay's reader claim prevents paged
reads from splicing two revisions. V2 does not claim to detect two different
valid bodies minted by the same authorized HMAC-key holder before first
consumption; device-level non-equivocation would require signatures or a stored
per-role digest. The answerer never lets a stale attempt reserve the next one.

## Full room-repair state transitions (dormant)

All inputs named “verified” below have already passed the codec, expected-route
checks, expiry checks, and replay checks. The state machine itself
does not parse unauthenticated bytes.

### Offerer

```text
idle
  -> create candidate-free local offer and data channel
  -> gather local ICE for possible peer-reflexive/fallback use
  -> publish signed offer once
  -> wait for matching signed answer
  -> set remote answer
  -> add its one or two candidates immediately
  -> connecting
  -> data channel open
  -> authenticated link-hello binds attempt/from/to
  -> clear slots and send invitation/snapshot on the data channel
```

The offer carries no candidate. No action waits for an absolute timestamp.

### Answerer

```text
listen/discover current offer
  -> verify offer and reserve its fresh attempt
  -> reconstruct zero-candidate SDP offer
  -> set remote offer
  -> create and gather answer
  -> rank and publish one or two answer candidates once
  -> connecting
  -> learn offerer as peer-reflexive candidate from incoming check
  -> data channel open
  -> authenticated link-hello binds attempt/from/to
  -> clear slots and receive invitation/snapshot on the data channel
```

### Explicit candidate fallback

The normal path relies on the offerer's first check creating a peer-reflexive
candidate at the answerer. If deferred browser testing finds a conforming case
that needs an explicit offerer candidate:

```text
answerer: signed needCandidate referencing offer
offerer:  signed candidate token referencing needCandidate
answerer: add candidate to the existing remote description
```

The fallback occurs at most once per attempt. It is not a repost timer and does
not restart ICE silently. The adapter computes its isolated-service reserve
from bounded key lookups, HMAC operations, PUTs, and role-sized paged reads; it requests fallback
only after the full normal connectivity timeout and only while that whole
exchange still fits absent competing peers. An explicit pre-fallback ICE
`failed` event may request it immediately when the same reserve exists. Scheduler
contention remains bounded by the attempt deadline and may return to manual
repair. Both peers retain the failed transport
long enough for newly signalled checks to recover. Lack of connectivity after
fallback ends the attempt.

The isolated fallback reserve includes both baseline role-poll delays, their
20% jitter, the worst-positioned every-fourth signed-abort probe, and one
already-running empty expected-role GET before each role read. The successful answer read and need-candidate PUT reset their respective
poll-failure backoff before the next role is expected. A new relay failure may
still consume the deadline and fail safely; the budget does not pretend a
failing transport has zero retry cost.

The answerer's connectivity timer begins when its answer slot is stored, while
the offerer may still be paging, authenticating, and applying that answer. A
scheduled fallback therefore reserves the later of the connectivity timeout or
the complete isolated answer-consumption bound before charging the `n -> c`
exchange. An immediate local ICE failure reserves the entire answer-consumption
bound as well; it is not treated as proof that the offerer is ready for `n`.

### Collisions, replacement, and cleanup

For established peers, the member outside a connected component offers to that
component's elected repair listener. For a simple two-peer partition, the lower
device ID is a deterministic tie-breaker when both sides would otherwise offer.
A room-level coordinator maintains separate attempts per missing peer and bounds
concurrent attempts. If simultaneous valid attempts nevertheless arrive, both
sides first prefer the later authenticated `issuedAt`, then choose the
lexicographically smaller `(offererId, attemptId)` tuple and abort the other.
This is convergent on both peers. A reload that produces two offers in the same
Unix second uses the tuple tie-breaker; an integration may wait for the next
second before retrying if immediate same-second replacement is essential.

A peer with an active, unexpired attempt cannot be displaced by an older or
losing replay; only the canonical signed glare winner may replace it. Every
admitted active attempt reserves replay-cache capacity for its eventual
tombstone. Authenticated rejected attempt IDs are tombstoned too. If the bounded
cache cannot retain another rejected live ID, unknown attempts fail closed until
that token could no longer verify. Every unsuccessful terminal path closes its
RTCPeerConnection; successful OPEN clears rendezvous timers and slots before
transferring the PC/channel to the application. All terminal paths record their
replay guard. The coordinator exposes import/export hooks so the application can
persist both unexpired tombstones and the fail-closed saturation deadline across
a page reload.

The dormant full-repair adapter's data-channel `link-hello` includes the
attempt ID and both device IDs. Room data is not accepted until that hello
agrees with the completed rendezvous and the DTLS fingerprint carried in the
signed token.

The shipped automatic-answer integration uses the application's existing
bootstrap hello instead. It carries the app and protocol version, room ID,
WebRTC session, member, and room snapshot; it does not carry the rr2 attempt or
ephemeral selectors. It travels over DTLS whose remote fingerprint came from
the authenticated answer, rejects all room/control/binary traffic beforehand,
and pins the first accepted application member identity.

## Room repair (dormant)

The repair condition is a missing peer or disconnected graph component, not
`openLinks().length === 0`.

One elected member of each connected component holds a short repair-listener
lease and polls the room bus. Listener election is deterministic over recently
seen members and rotates after lease expiry or repeated failure. An isolated
member targets a reachable listener and rotates through ranked known members;
it does not retry the lowest identifier forever.

One room-level mailbox is multiplexed into bounded per-peer attempts. Opening a
new six-allocation mailbox for every remembered peer is prohibited.

## Fully compact initial pairing profile

Fully compact first pairing, where both offer and answer use the constrained
carrier, is reserved for Stage 5 and is not implemented by the current
established-room coordinator. The shipped automatic-answer profile is not this
feature: it sends a full CC2 invitation containing a strong bearer secret and
uses rr2 only for the answer. The approved future compact design uses the same
offer/answer mechanics but a different delivery and key source:

1. A short human code locates a relay slot; it is not treated as a strong
   authentication key.
2. Preferred QR/deep-link pairing carries a random 128-bit-or-stronger secret.
3. A human-only short-code mode requires an audited PAKE or an explicit
   user-verified short authentication string.
4. A bootstrap offer may use the broadcast recipient; the first valid answer
   binds a concrete device ID.
5. Bootstrap TURN access uses a public known profile or a short-lived opaque
   credential handle. Long-lived TURN credentials are not embedded.
6. After the channel opens, devices exchange the full invitation, room state,
   device identity material, and a new pairwise repair key.
7. Bootstrap slots and secrets are destroyed after success or expiry.

The room-wide transition profile is not a substitute for this bootstrap
authentication.

Bootstrap uses a small, separate coordinator. The established-room coordinator
requires a concrete recipient and uses connected-component listener roles;
those rules cannot admit a broadcast offer whose recipient is not known yet.
After the first answer binds a concrete peer, the bootstrap coordinator resumes
the same exact-route and attempt rules as normal V2.

## Portable codec API

`realm/src/rendezvous-v2-codec.js` exports pure candidate helpers and four token
interfaces.

The attempt layer's fixed protocol marker (`protocol: "rv2"`) is distinct from
the signed key profile (`bootstrap`, `pairwise`, or `roomTransition`). An adapter
must preserve both fields rather than replacing one with the other. Codec role
`needCandidate` maps mechanically to relay wire role `n`; the codec, state, and
browser adapter all retain the API spelling `needCandidate`.

Primary `rr2` APIs:

```js
const contextId = await deriveRendezvousV2RoomContextId(room.id, { subtle });
const raw = await encodeAndSignRendezvousV2Bytes(token, hmacKey, { subtle });

const verified = await verifyAndDecodeRendezvousV2Bytes(raw, hmacKey, {
  subtle,
  nowSeconds: Math.floor(Date.now() / 1000),
  expectedProfile: "pairwise",
  expectedRole: "answer",
  expectedAttemptId,
  expectedContextId: contextId,
  expectedFrom: peerId,
  expectedTo: localId,
});
```

Diagnostic/legacy text wrappers:

```js
const text = await encodeAndSignRendezvousV2Token(token, hmacKey, { subtle });
const rawAgain = rendezvousV2TextToBytes(text);
const inspected = rendezvousV2BytesToText(rawAgain);
```

Candidate helpers:

```js
const candidate = parseSdpCandidate(rtcIceCandidate.candidate);
const candidateAttribute = formatSdpCandidate(candidate);
const budget = measureRendezvousV2Token(token);
```

`verifyAndDecode...` deliberately requires `nowSeconds`; omitting a freshness
decision is an error. Passing expected routing context is mandatory at the
adapter boundary even though the low-level codec leaves it optional for fixture
and tooling use.

`realm/src/rendezvous-v2-fixtures.js` contains inert deterministic offer,
answer, ACK, key, and size fixtures. It performs no work when imported.

The reproducible automatic-answer bundle contains:

- `rendezvous-v2-codec.js` for canonical authenticated answer tokens;
- `rendezvous-v2-sdp.js` for candidate selection and candidate-free remote SDP;
- `rendezvous-v2-transport.js` and `rendezvous-v2-turn-exchange.js` for finite
  latest-value reads over six short-lived TURN allocations; and
- `auto-answer-return.js` for invitation binding, HKDF key separation,
  AES-GCM wrapping, and exact answer verification.

`realm/tools/build-auto-answer-bundle.mjs` is the only supported way to update
that generated HTML block; `--check` verifies freshness without writing.

The full-repair modules remain separate from the published artifact:

- `rendezvous-v2-state.js` and `rendezvous-v2-coordinator.js` own semantic
  transitions, glare arbitration, replay retention, and component repair;
- `rendezvous-v2-browser-adapter.js` executes effects sequentially and requires
  an authenticated attempt-bound link-hello before declaring repair success;
  and
- `rendezvous-v2-keyring.js` derives a per-peer key from two 256-bit
  contributions exchanged over an already authenticated data channel. General
  initiation requires the peer's ready confirmation. Verification is allowed
  as soon as both contributions derive the key, and a verified inbound offer
  narrowly authorizes its answer, closing the one-way ready-message race.

## Full room-repair invariants

The dormant full-repair implementation is incomplete if any invariant is
false:

1. All full-repair and fully compact-pairing selection flags default off.
2. V1 automatic signalling remains off; manual exchange remains available.
3. No interval or presence callback calls a message-producing mailbox send.
4. A normal attempt publishes one logical offer and one logical answer.
5. Retries are byte-identical idempotent slot upserts, never log appends.
6. A late reader can read the current unexpired offer without waiting for a
   repost.
7. The relay never places `rr2` state in `RoomStore`, JSONL persistence, or
   payload-bearing logs/health output.
8. Token authentication, canonical validation, expected-route validation, and
   expiry validation all precede attempt mutation or PC creation.
9. Every attempt ID is 128 random bits and every answer echoes it.
10. Context, role, reference role, from, to, profile, lifetime, ICE,
    fingerprint, and candidates are inside the MAC.
11. No handshake transition is scheduled from the peer's wall clock.
12. Offers have no candidate; answers have one or two faithfully encoded
    candidates.
13. TCP is never reconstructed as UDP; IPv6 is never truncated to IPv4.
14. Transport ACK/abort can only release storage in full repair and can never
    prove peer state in any profile.
15. Each queue, slot store, attempt map, replay cache, timer set, and
    RTCPeerConnection count has a hard bound and a terminal cleanup path.
16. A failure after V2 selection returns to manual exchange, not automatic V1.
17. Coordinator millisecond times and codec second times are converted
    explicitly at the coordinator acceptance boundary.
18. V2 source, fixtures, and repository documentation do not modify publishing
    or blog artifacts.

## Shipped automatic-answer invariants

The narrower enabled profile additionally requires all of these:

1. The full candidate-bearing offer is transferred only in the CC2 invitation;
   rr2 carries one logical answer and no offer slot.
2. The invitation descriptor expires within five minutes and binds the exact
   offer, app, room, session, invite, host route, attempt, and 256-bit secret.
3. HKDF produces independent non-extractable HMAC and AES-GCM keys plus a
   private rr2 room credential.
4. The joiner applies a candidate-free copy of the offer and retains its
   candidates behind a single atomic start claim.
5. One signed answer is AES-GCM-wrapped once; every retry uses the same attempt,
   nonce, ciphertext, and slot key.
6. The host verifies wrapper, HMAC, profile, role, context, route, attempt,
   expiry, ICE, fingerprint, and candidates before applying the answer or ACKing
   its slot.
7. ACKED may release retained candidates but never confirms identity,
   membership, or success.
8. Manual answer application and automatic answer application cannot both
   claim one invite. Revealing fallback leaves automatic polling alive; actual
   manual Start cancels it before the first candidate mutation.
9. Failed, expired, superseded, used, retried, or persisted invite state never
   retains the automatic-answer bearer secret.
10. A provisional join accepts no room/control/binary data and is discarded
    back to invite entry unless a matching data-channel `link-hello` succeeds.

## Deferred validation matrix

The full repair stack may reach “complete and dormant” before these tests run.
It must not be described as browser/network certified until all required cells
pass.

The shipped automatic-answer subset has a narrower evidence ledger. On
2026-08-09, build `0.29.0-auto-answer` passed repository checks, 34 relay and
protocol tests, Chromium and WebKit smoke tests, and a live desktop-to-iPhone
cellular pairing through TURN. The invite crossed once and the encrypted answer
returned automatically. This validates that canary path only; Firefox, native
Safari, IPv6, TURN/TCP, UDP-blocked networks, multi-peer repair, and the full
coordinator matrix below remain deferred.

### Codec and authentication

- deterministic offer, IPv4 answer, mixed IPv4/IPv6 answer, ACK, abort,
  need-candidate, and candidate vectors;
- maximum and one-byte-over-maximum body sizes;
- shortest/longest ICE values and invalid combined byte budgets;
- UDP/TCP, active/passive/so, host/srflx/relay round trips;
- compressed, uncompressed, and IPv4-suffix IPv6 forms;
- bit flips in every authenticated field and tag byte;
- non-canonical base64url, reserved bits, trailing bytes, bad role shapes, and
  unknown enum values;
- wrong key/profile/role/from/to/attempt and future/expired tokens;
- cross-room replay with the correct pairwise key but wrong context ID;
- verification instrumentation proving no decoded token is returned before
  HMAC success.
- loss of either final key-ready message: only a confirmed peer may initiate,
  while a verified pairwise offer authorizes its bound answer attempt.

### Relay slots

- late-reader discover before expiry;
- byte-identical put idempotency and compare-and-set conflicts;
- mixed same-revision `STORED`/`ACKED` lanes after an ambiguous consumed put;
- exact revision get/not-modified behavior;
- transport ACK/abort terminality and non-resurrection;
- reserved signed-ACK codec/relay shape and active signed-abort flow,
  independently of transport cleanup;
- active and terminal TTL pruning;
- per-room/global cardinality at and beyond bounds;
- two relay actors behind one public IP;
- payload never reaches durable events, persistence, logs, or health output;
- delayed, duplicated, reordered, dropped, and truncated six-lane frames;
- username length at maximum 207-byte raw token;
- disabled capability and mixed rr1/rr2 traffic.

### Pure state machine and coordinator

- all offerer and answerer transitions plus every terminal cleanup edge;
- duplicate, reordered, conflicting-role, unknown, and replaced attempts;
- late answer and restart replay;
- simultaneous/glare resolution;
- no-candidate offer and answer-only candidate normal flow;
- fallback requested once and only once;
- one open link plus a missing third member;
- lowest-ID member unavailable;
- two disconnected multi-member components;
- listener lease expiry and target rotation;
- attempt, failure, and replay-map cardinality bounds;
- second/millisecond adapter conversion.

### Browser and network interoperability

Run current stable Chromium, Firefox, and Safari in every meaningful combination
of offerer and answerer, not merely same-browser pairs.

- IPv4-only, IPv6-only, and dual-stack;
- direct same-LAN, server-reflexive, TURN/UDP, TURN/TCP, and UDP-blocked paths;
- asymmetric slow-channel delay exceeding the old 75-second appointment;
- renderer sleep/resume before offer, after offer, and after answer;
- answerer learning the offerer as peer-reflexive;
- fallback extension where forced;
- one and two candidates, with primary route failure;
- three- and four-member partial partitions;
- two clients sharing one NAT/public IP;
- relay restart, slot expiry, and client restart mid-attempt.

### Soak and acceptance

- no event-log or slot growth with elapsed time;
- no timer-driven token output while idle;
- no leaked RTCPeerConnections, TURN allocations, waiters, or timers;
- bounded request rate with multiple tabs and shared NAT;
- predictable median and tail reconnect latency;
- zero persisted signalling payloads or credential-bearing logs;
- feature-gate rollback to manual exchange without state migration.

The final acceptance signal is an authenticated data channel and matching
link-hello, not merely a stored slot or successful token decode.

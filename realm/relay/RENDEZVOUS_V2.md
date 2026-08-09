# Rendezvous V2 relay slots

Rendezvous V2 (`rr2`) is a memory-only latest-value transport for compact
WebRTC signalling values. It is separate from the `rr1` room event log: an
`rr2` operation never calls `RoomStore`, consumes a room sequence, emits a join
event, or reaches JSONL persistence.

The source default is disabled. The canary relay explicitly enables rr2 for
the encrypted automatic-answer profile in client build
`0.29.0-auto-answer`; complete room repair remains disabled. Enabling the slot
store is transport availability, not permission for a client to select every
V2 profile.

The server feature flag is off by default:

```text
RENDEZVOUS_V2_SLOTS=false
```

Enabling relay support does not select full repair in a client. Client
capability and selection flags remain separate rollout controls.

## Current automatic-answer consumer

The shipped profile does not store its offer in rr2. An existing member sends a
full CC2 invitation once. That invitation contains a five-minute one-use
256-bit bearer secret, from which both browsers derive independent HMAC,
AES-GCM, and private rr2 room material with HKDF.

Only the joiner's answer uses a slot. It is a canonical HMAC-signed V2 answer
inside an AES-GCM wrapper whose associated data binds the invitation, attempt,
role, sender selector, and recipient selector. The relay therefore observes
routing, timing, and ciphertext size, but not the answer's ICE credentials,
DTLS fingerprint, or candidate addresses. The ordinary copied invitation is a
separate bearer object and is visible to whoever receives it.

Every writer retry uses the same logical key and exact ciphertext. It refreshes
one latest-value slot and never appends a signalling event.

## Username envelope

Each authenticated TURN Allocate request carries this dot-delimited username:

```text
rr2.room.actor.from.to.attempt.role.operation.revision.chunk.payload
```

| Field | Encoding | Meaning |
| --- | --- | --- |
| `room` | 8–40 lowercase letters, digits or hyphens | Relay room and password for the TURN long-term authentication exchange; automatic answer derives a private value per invitation |
| `actor` | 12 lowercase hex characters | Ephemeral relay client ID for writer/reader pinning |
| `from`, `to` | 16 lowercase hex characters each | Client-bound routing selectors; full repair uses device IDs, while automatic answer uses ephemeral invitation-scoped values; all-zero has the restricted wildcard/broadcast meanings below |
| `attempt` | 32 lowercase hex characters | Non-zero 128-bit attempt ID; literal `0` selects any attempt only for `discover` |
| `role` | `o`, `a`, `n`, `c`, `k`, or `x` | Offer, answer, need-candidate, fallback candidate, signed acknowledgement, or signed abort |
| `operation` | `put`, `get`, `discover`, `ack`, or `abort` | Slot operation |
| `revision` | Base-36 unsigned 32-bit integer | Expected/current content revision |
| `chunk` | Base-36 integer from 0 through 255 | First five-byte response chunk requested on lane zero |
| `payload` | Unpadded canonical base64url or `0` | At most 240 binary bytes; present only for `put` |

`actor` is deliberately not equated with `from` or `to`. The relay pins the
first writer and first reader actor to make retries internally consistent, but
it cannot authenticate application device identity. The compact client
envelope must MAC at least its protocol version/profile, attempt, role, `from`,
`to`, expiry, and body. Pairwise device keys are required if one established
room member must not be able to impersonate another. Automatic answer instead
uses a private per-invitation room and wrapper key; application member identity
is accepted later through `link-hello` on the authenticated data channel.

## Slot identity and operations

A slot is keyed by:

```text
room + from + to + attempt + role
```

- `put` creates revision 1 with expected revision 0. `from` must be a concrete
  routing selector; `to` may be all-zero only for a bootstrap broadcast offer.
  Repeating the same bytes
  is idempotent and returns the existing revision. Replacing different bytes
  requires the exact current revision and increments it. The first successful
  writer `actor` owns subsequent puts and writer-side aborts. The value becomes
  immutable when a reader claims it, preventing a revision change from mixing
  two values during paged retrieval; publish a fresh attempt instead.
- `get` reads an exact attempt. Revision 0 retrieves revision 1; passing the
  current revision returns `NOT_MODIFIED`. A revision ahead of the server is a
  conflict.
- `discover` always uses `revision=0`. An all-zero `from` means any sender. An
  all-zero `attempt` means any attempt and is allowed only for offer role `o`.
  `to` is always matched literally: a concrete ID selects directed slots and
  all-zero selects bootstrap broadcast slots rather than every recipient.
  Supplying an exact attempt with wildcard `from` lets a bootstrap host find an
  answer before it knows the joiner's device ID. Supplying wildcard `from` and
  attempt lets a late answerer find the newest directed or broadcast offer.
  The signed payload supplies the concrete IDs and remains authoritative.
- The first discovery chunk pins the selected slot to its reader actor, so a
  newer offer cannot splice another slot into the remaining chunk pages. ACK
  or abort the selected slot before asking the same actor to discover a newer
  attempt. If signature verification fails, transport-abort that claimed slot
  and continue discovery; an unverified payload must never reach peer state.
- The first non-writer `get` or `discover` pins its relay `actor` as reader.
  Further reads and `ack` must use that actor. Each successful read refreshes a
  short reader lease. After the lease expires, another actor may take over,
  allowing reload recovery without letting concurrent joiners consume one
  broadcast offer. This is consistency and replay containment, not proof of
  application identity.
- `ack` requires the exact revision and the pinned reader. It erases the token
  bytes and leaves a bounded ACK tombstone for a suspended writer to observe.
- `abort` requires the exact revision and either the pinned writer or reader.
  It erases the token bytes and leaves a bounded abort tombstone.

The current automatic-answer profile uses only `a`: its offer remains in the
manually transferred CC2 invitation, and the host discovers an answer for one
exact attempt with a wildcard sender. Normal full repair would use `o` and `a`.
The `n` and `c` roles reserve a bounded,
attempt-scoped fallback when answer-only candidates do not work on a browser:
the answerer publishes `n`, then the offerer may publish `c`. Role `x` carries
the established coordinator's client-authenticated abort. Role `k` is reserved
on the codec and relay wire only; this coordinator intentionally has no signed
ACK transition because authenticated link-hello is the success proof.

The lowercase `ack` and `abort` operations are untrusted relay-storage
lifecycle hints against the role slot they target. They never authenticate a
peer, prove membership, or declare a WebRTC connection successful. A client
sends transport `ack` only after it has verified the retrieved slot payload.
Peer termination in the full repair protocol can come only from a successfully
verified signed `x` payload. A future protocol using `k` requires its own
explicitly versioned state transition.

The automatic-answer profile additionally uses `ACKED` as an
availability-only release signal. The host ACKs only after it has authenticated
and applied the answer; observing that state lets the joiner add the offer
candidates it retained from the invitation. A malicious relay can suppress or
prematurely synthesize that release, causing denial of service, but it cannot
create a valid answer, complete DTLS under the authenticated fingerprint, or
satisfy the application `link-hello`. ACKED is still not a security success
signal.

## Six-byte response frames

Every TURN response still encodes exactly six bytes in the synthetic
XOR-RELAYED-ADDRESS.

Control frames use the first byte below, a four-byte big-endian revision in
bytes 1–4, and reserved value 1 in byte 5:

| First byte | Status |
| ---: | --- |
| 50 | `EMPTY` |
| 51 | `STORED` |
| 52 | `NOT_MODIFIED` |
| 53 | `ACKED` |
| 54 | `ABORTED` |

Errors retain the shared `40 + code` frame convention. Their four-byte value
is the current revision when available:

| First byte | Error |
| ---: | --- |
| 43 | V2 disabled |
| 44 | Slot capacity reached |
| 45 | Actor forbidden |
| 46 | Slot missing |
| 47 | Revision conflict |
| 48 | Bad operation |
| 49 | Internal error |

Data frames retain the `20 + length` continuation and `30 + length` final
headers. Concatenating their one-to-five-byte payloads produces canonical,
unpadded base64url text. Decoding that text produces:

```text
8 bytes from | 8 bytes to | 16 bytes attempt ID | 1 byte role
4 bytes revision, big endian | 1–240 token bytes
```

The concrete selector in this header is authoritative for storage routing. A
wildcard reader uses it for exact follow-up GET/ACK/abort operations and must
compare it with the corresponding fields inside the verified client envelope.
It can therefore transport-abort a malformed wildcard result without trusting
claims made by that result's token.

The extra text encoding is necessary because bytes 4–5 of the synthetic
address are also a TURN port and port zero is invalid. It prevents binary token
bytes from being changed to avoid a zero port.

For a six-lane exchange, the server returns chunk indexes `chunk + lane`. A
client therefore requests bases `0, 6, 12, ...` until it receives a final data
frame, retaining lane order even when Allocate responses arrive out of order.
Each chunk is five bytes. The maximum 277-byte decoded response becomes 370
base64url bytes and uses 74 chunks, or thirteen six-lane exchanges. PUT, ACK
and abort require chunk 0; GET and discover use the chunk field only to page
their response. Keep revision 0 while paging the current value; after assembly,
its decoded revision can be used for ACK, abort, or a later `NOT_MODIFIED`
check.

If a later page fails, the same reader actor restarts from page zero. It must
not abort a slot based on an incomplete byte stream. Only a fully assembled
result supplies a receipt that the caller may abort after authentication fails;
otherwise the bounded reader lease releases an abandoned claim.

The browser carrier serializes exchanges and, for the standard six lanes,
spaces their start times by at least 250 ms plus jitter. Wider lane sets scale
that floor proportionally. This pacing applies to every page and PUT retry; it
is part of the transport contract, not an optional UI debounce. The relay uses a
refilling token bucket per public source address so the authentication retry,
two clients behind one NAT, and a bounded page burst do not collide with a
fixed one-second cliff.

The bounded client scheduler prioritizes deadline-bound PUTs over paged reads
and reserves queue entries for them; storage cleanup remains best effort. A PUT
queued before its attempt deadline is still rejected if the scheduler cannot
start its TURN allocation with one isolated service budget for every remaining
initial/retry attempt still available.
Thus cleanup from a terminal
attempt cannot exhaust the admission budget for a new logical token or publish
that token after its local signalling lifetime. Published duration estimates
are isolated-service budgets; multi-peer contention remains bounded by queue
capacity and token deadlines, not promised away as zero latency.

An ambiguous PUT may be consumed and storage-ACKed before its writer receives a
retry response. A same-revision response containing only the monotonic
`STORED`/`ACKED` states therefore completes the writer's storage step (with
`ACKED` taking precedence), without being treated as peer authentication. In
automatic answer, ACKED may also release retained candidates as described
above. The signed answer, DTLS negotiation, and authenticated data-channel
`link-hello` remain mandatory. `ABORTED` never completes a PUT.

Automatic answer generates one AES-GCM nonce and ciphertext per invitation
attempt. If a suspended writer returns after an ACK tombstone has expired, it
may PUT those exact cached bytes again under the same logical key. Until
`link-hello` or capability expiry, the host periodically looks up that exact
route, compares the bytes with the already accepted value, verifies it again,
and re-ACKs it. This narrow resume mechanism does not permit changed content,
new SDP, or a retimed token under the old attempt.

## Bounds, expiry, persistence, and metrics

Active slots expire a fixed time after their most recent successful put,
including an idempotent retry of identical bytes.
Reads do not extend the slot TTL. ACK/abort tombstones retain no payload and,
by default, remain for the same five-minute resume window as active slots.
Expired entries are pruned during operations and periodic maintenance.
Each request prunes only its bounded room; the maintenance timer performs the
global pass, avoiding a whole-relay scan for every one of six lane requests.

The defaults are:

```text
RENDEZVOUS_V2_MAX_SLOTS=1000
RENDEZVOUS_V2_MAX_SLOTS_PER_ROOM=64
RENDEZVOUS_V2_SLOT_TTL_MS=300000
RENDEZVOUS_V2_TERMINAL_TTL_MS=300000
RENDEZVOUS_V2_READER_LEASE_MS=60000
RELAY_RATE_PER_SECOND=120
RELAY_RATE_BURST=240
```

The signed V2 answer remains bounded at 207 bytes. Automatic answer wraps it as
one magic byte, a 12-byte AES-GCM nonce, the signed token, and a 16-byte GCM tag,
for at most 236 bytes inside the 240-byte slot.

An existing deployment's `.env` overrides these defaults. The current canary
still uses the older `RENDEZVOUS_V2_TERMINAL_TTL_MS=30000` value even though the
repository and container default is now `300000`. Client re-ACK recovery makes
that live setting survivable for suspended browsers, but a future approved
relay recreation should converge it to the five-minute default. Do not infer
the live value from this source-default block.

Capacity rejects new slots rather than evicting live state. Health output
contains aggregate counts only: slot states and request/outcome counters (each
TURN lane request counts separately). It never includes room IDs, actors,
device IDs, attempts, token bytes, ICE
credentials, candidates, or fingerprints.

Slots have no persistence option. This remains true when
`PERSIST_MESSAGES=true`; persistence belongs exclusively to the legacy room
event store.

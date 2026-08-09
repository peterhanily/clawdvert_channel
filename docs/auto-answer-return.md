# Automatic answer return

Status: shipped in browser build `0.29.0-auto-answer` and validated on
2026-08-09 between a desktop connection and an iPhone on cellular data.

The current pairing flow copies one full `CC2.` invite from an existing member
to a joining device. The joining device does not return a second code in the
normal path. It encrypts a compact WebRTC answer, stores it in one short-lived
`rr2` latest-value slot, and starts automatically after the inviter has applied
the answer.

The public build is:

<https://claude.ai/code/artifact/8617e844-efc1-4671-a9d3-343aef2b223c>

The manual answer and explicit Start button still exist inside a collapsed
fallback. They are recovery controls, not the ordinary workflow.

## The two relays have different jobs

The working cross-network path uses two complementary services:

| Service | Current ports | Purpose |
| --- | --- | --- |
| `rr2` mailbox relay | UDP 3478-3483 | Returns one encrypted compact answer and a payload-free acknowledgement |
| coturn | UDP/TCP 3488 plus a UDP allocation range | Carries WebRTC when a direct route cannot cross NAT |

The mailbox is a signalling plane. Coturn is a packet forwarding plane. A
successful cellular pairing can require both. Running one does not replace the
other.

```text
existing member                  joining device
      |                                |
      |  full candidate-bearing invite |
      | -----------------------------> |
      |                                |
      |       encrypted compact answer |
      | <--------- rr2 slot ---------- |
      |                                |
      | verify and apply answer routes |
      | ---------- rr2 ACK ----------> |
      |                                |
      | <== direct WebRTC or coturn ==>|
      |                                |
      | <== authenticated link-hello =>|
```

The relay ACK releases an ICE timing barrier. It is not proof that a peer
connected, joined the room, or has an accepted identity. Only the data-channel
`link-hello`, checked against the invitation's app, protocol version, room,
session, and member identity, confirms success.

## Why the candidate barrier is necessary

The first manual implementation put candidates in the offer. That gave the
joining browser everything it needed to begin ICE as soon as it created its
answer. On a phone, the checks could fail before a person copied the answer
back to the inviter.

A later implementation removed every candidate from the transported offer. It
kept the joining browser idle, but it failed when both peers needed TURN. A
TURN allocation silently drops peer traffic until its client installs a
permission for the peer address. With no remote candidate, the joining browser
could not create that reverse permission, so the offerer's checks never reached
its ICE agent.

The shipped design preserves both requirements:

1. The copied invite contains the inviter's gathered candidates.
2. The joiner extracts and retains those candidates before calling
   `setRemoteDescription()` with a candidate-free copy of the offer.
3. The joiner creates and gathers a normal answer while ICE remains idle.
4. The answer is reduced to ICE credentials, DTLS fingerprint, setup role, and
   one or two ranked candidates.
5. The compact answer is authenticated, encrypted, and stored once in `rr2`.
6. The inviter verifies it, sets a candidate-free remote answer, and adds the
   verified answer candidates.
7. Only after those operations succeed does the inviter ACK the slot.
8. The joiner observes `ACKED` and adds the retained offer candidates, which
   also installs any required TURN permissions.
9. ICE, DTLS, and SCTP complete, then the link-hello confirms membership.

This keeps the phone idle while the answer moves, while still giving both TURN
clients the candidate addresses needed to create permissions.

## Invitation capability

An automatic-return invitation contains a one-use descriptor bound to the
exact invitation and offer. It contains:

- protocol and transport versions;
- application, room, session, invitation, and inviter identifiers;
- a deployment route profile rather than an arbitrary relay URL;
- SHA-256 of the exact offer SDP;
- a fresh 128-bit attempt identifier;
- a fresh 256-bit secret;
- an absolute expiry no more than five minutes away; and
- a SHA-256 binding over the complete canonical descriptor.

The descriptor is a bearer capability. Anyone who receives the complete invite
can attempt to use it until it expires, just as anyone who receives the full
manual invite can attempt to answer it. The first valid answer wins.

The browser strips the descriptor from retry UI and persisted invite state
after deriving its keys. It also clears derived keys, ciphertext, transport
state, and the capability on success, failure, or expiry. Do not log the secret,
the derived relay room, plaintext token bytes, or ciphertext.

## Cryptographic envelope

`realm/src/auto-answer-return.js` derives independent material from the
descriptor with HKDF:

- a non-extractable HMAC-SHA-256 key for the compact V2 token;
- a non-extractable AES-GCM key for relay-observer confidentiality; and
- a high-entropy private `rr2` room credential.

The compact answer is first encoded as a canonical Rendezvous V2 answer token.
That token binds the attempt, context, role, sender, recipient, expiry, ICE
credentials, DTLS fingerprint, and candidates. The signed bytes are then
AES-GCM wrapped with a fresh 96-bit nonce and routing metadata as additional
authenticated data.

The largest permitted inner token is 207 bytes. The wrapper adds one version
byte, a 12-byte nonce, and a 16-byte GCM tag, for a maximum of 236 bytes. That
fits the relay's 240-byte slot limit.

The same logical answer reuses exactly the same cached ciphertext for every
ambiguous PUT retry. It never regenerates a nonce or a different answer under
the same slot identity.

## Latest-value and resume behavior

The answer uses one exact-attempt `a` slot. The joiner repeats a byte-identical
PUT until it observes `ACKED`; it does not append events or create new request
identities. The inviter wildcard-discovers the sender only for that exact
recipient and attempt, then binds every concrete receipt field to the decrypted
envelope before touching WebRTC state.

After applying and acknowledging the answer, the inviter retains a bounded
recovery reader until link-hello or capability expiry. Every 15 seconds it may
re-read and re-ACK only the exact ciphertext it already verified. This covers
an iPhone suspended long enough for a short relay tombstone to expire: the
phone can re-PUT its cached value and receive the same post-application release.
A changed value is aborted and cannot replace the accepted answer.

The source relay defaults active and terminal slots to five minutes. A deployed
relay with a shorter terminal TTL remains compatible because of exact-token
re-ACK, but should move to the five-minute value during its next approved
recreate. Recreating the relay clears every memory-only slot, so drain active
pairing attempts first.

## Failure and fallback

Automatic return fails closed to the existing manual controls when:

- the relay reports `rr2` disabled;
- the descriptor, binding, route, expiry, HMAC, or AES-GCM tag is invalid;
- the answer cannot fit one slot;
- TURN paging or acknowledgement exceeds its bounded deadline;
- a different answer already won; or
- either browser closes or expires the attempt.

The joining page always retains its full answer locally. Revealing the manual
fallback does not stop automatic ACK observation. Whichever path actually
claims candidate release first cancels the other path atomically. A terminal
initial-join failure clears the provisional room and returns the phone to the
fresh invite screen rather than leaving it stranded in an unconnected room.

## Deployment requirements

For the normal one-code path:

1. The browser build must contain the generated auto-answer bundle and have
   `AUTO_ANSWER_RETURN_ENABLED=true`.
2. The designated mailbox relay must have
   `RENDEZVOUS_V2_SLOTS=true` and six reachable UDP lanes.
3. Both clients' current public addresses must be admitted to those six lanes.
4. Cross-NAT sessions need reachable coturn listener and allocation ports for
   both clients.
5. Runtime TURN details must be configured on the inviter and shared in the
   invite, or independently configured on both devices.

The current client route profile maps to a reviewed, fixed relay endpoint. A
self-hosted deployment must change that mapping and rebuild the single-file
artifact; the descriptor does not allow an invite to select an arbitrary TURN
host.

See [deploy-relay.md](deploy-relay.md) for commands and port rules, and
[rendezvous-v2.md](rendezvous-v2.md) for the general compact token and relay
slot contracts.

## Validation record

The release gate for `0.29.0-auto-answer` included:

- repository checks: 22 of 22;
- relay, codec, transport, crypto, and HTML state tests: 34 of 34;
- current generated bundle equality;
- Chromium offline smoke with no page or console errors;
- WebKit offline smoke with no page or console errors;
- live `rr1` and `rr2` PUT, late DISCOVER, exact GET, not-modified, ACK, and
  aggregate health checks; and
- a successful real desktop-to-iPhone cellular session using the public
  mailbox relay and coturn.

The successful network test confirms the intended current path. It does not
complete the separate full automatic-repair matrix: Firefox, larger room
partitions, and every IPv6/TCP/browser combination remain follow-up work.

## Source map

| File | Responsibility |
| --- | --- |
| `realm/src/auto-answer-return.js` | Descriptor validation, HKDF, compact answer, AES-GCM wrapper, receipt verification |
| `realm/src/rendezvous-v2-codec.js` | Canonical signed compact token and candidate representation |
| `realm/src/rendezvous-v2-sdp.js` | Candidate extraction, ranking, candidate-free descriptions, reconstruction |
| `realm/src/rendezvous-v2-transport.js` | Bounded latest-value slot operations and paging |
| `realm/src/rendezvous-v2-turn-exchange.js` | Paced six-lane TURN allocation carrier |
| `realm/tools/build-auto-answer-bundle.mjs` | Reproducible single-file HTML bundle and freshness check |
| `realm/relay/lib/rendezvous-slots.mjs` | Memory-only latest-value slot store |
| `realm/relay/tools/relay-smoke.mjs` | Live `rr1`/`rr2` protocol smoke test |

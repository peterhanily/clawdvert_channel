# Rendezvous V2 client modules

This directory contains the reviewable source for two related integrations:

- the shipped automatic-answer profile, which returns one encrypted compact
  answer for a manually copied CC2 invitation; and
- the complete latest-value WebRTC room-repair design, which remains dormant.

Build `0.29.0-auto-answer` bundles the codec, SDP, slot transport, TURN
exchange, and `auto-answer-return.js` into `realm/clawdvert_channel.html`. The
full coordinator, pairwise keyring, repair listener, and compact-offer pairing
remain disabled. The ordinary answer plus explicit Start barrier remains a
collapsed manual fallback.

## Module boundaries

The shipped one-way profile is:

```text
full CC2 bearer invitation
          |
          v
auto-answer-return -> codec + SDP -> rr2 slot transport
                                         |
                                         v
                               six-lane TURN exchange
```

The dormant full room-repair stack is:

```text
pairwise keyring + authenticated capability
                 |
                 v
coordinator -> pure attempt state -> ordered browser adapter
                                      |            |
                                      v            v
                               SDP / WebRTC   rr2 slot transport
                                                   |
                                                   v
                                     six-lane TURN exchange
```

- `rendezvous-v2-codec.js`: canonical binary tokens and HMAC verification.
- `rendezvous-v2-state.js`: pure offer/answer/fallback state transitions.
- `rendezvous-v2-coordinator.js`: per-peer attempts, glare resolution,
  listener/target policy, and replay tombstones.
- `rendezvous-v2-sdp.js`: fixed candidate-free SDP plus faithful candidate
  selection/reconstruction.
- `rendezvous-v2-transport.js`: finite rr2 PUT/GET/discover/ACK/abort paging.
- `rendezvous-v2-turn-exchange.js`: short-lived browser TURN allocations.
- `auto-answer-return.js`: invitation-bound HKDF keys, HMAC-signed compact
  answer tokens, AES-GCM wrapping, and exact rr2 receipt verification.
- `rendezvous-v2-browser-adapter.js`: ordered effect execution and timers.
- `rendezvous-v2-keyring.js`: pairwise key contribution/confirmation over an
  already authenticated fast channel.
- `rendezvous-v2-fixtures.js`: inert deterministic deferred-test inputs.

## Shipped automatic-answer integration

The full offer is not published to rr2. The inviter gathers a normal offer,
adds a five-minute one-use descriptor, and sends the resulting CC2 invitation
once. The joiner validates that descriptor against the exact offer and invite,
retains the offer candidates without applying them, gathers an answer, and
publishes one encrypted logical answer value. Every PUT retry reuses the same
attempt, nonce, and ciphertext, so it refreshes one latest-value slot rather
than appending signalling events.

The inviter decrypts and verifies the complete answer before applying its
candidate-free reconstructed SDP and candidates. Only then does it ACK the rr2
slot. In this profile `ACKED` releases the joiner's retained offer candidates;
it is an availability signal, not peer authentication or membership proof.
Room, control, and binary data remain blocked until the DTLS data channel
delivers a matching application `link-hello`.

The generated bundle is maintained from source. Do not edit the HTML between
its bundle markers directly:

```bash
node realm/tools/build-auto-answer-bundle.mjs
node realm/tools/build-auto-answer-bundle.mjs --check
```

The detailed deployed-profile contract is in
[`docs/auto-answer-return.md`](../../docs/auto-answer-return.md).

## Full repair integration rules (dormant)

1. Derive `contextId` with `deriveRendezvousV2RoomContextId()`; never expose the
   raw room ID as the signed routing context.
2. Exchange keyring shares only after the existing data-channel link-hello has
   authenticated both device IDs. Persist confirmed pairwise keys and the
   coordinator's complete `exportReplayState()` (unexpired tombstones plus its
   fail-closed saturation deadline) in room-scoped local storage.
3. Advertise `rv2/rr2/pairwise` capability only after both peers confirm the
   same key ID. Initiating automatic repair requires that authenticated
   advertisement. An enabled listener still verifies directed offers from a
   peer for which `keyring.canVerify(peerId)` is true, so loss of the final
   ready message cannot strand the responder.
   Bind `profileForPeer(peerId, { direction })` to that record; never try
   `roomTransition` after a peer has a derived pairwise verify key, and sign only
   after pairwise confirmation. New policy applies only to new attempts; retain
   an in-flight attempt's bound verification key through its replay horizon. A key provider calls
   `keyring.keyFor(peerId, { direction, responseToVerifiedOffer })`:
   unconfirmed derived keys may verify, while only confirmed keys may initiate.
   An answerer may set `responseToVerifiedOffer` only for the attempt created
   from a successfully verified pairwise offer; that proof authorizes its
   response if the final ready message was lost. Repeat the idempotent
   share/ready exchange on the repaired authenticated channel so both records
   converge before either future initiation. Key replacement requires a
   coordinated reset message on an authenticated fast channel; there is
   deliberately no one-sided `rotate()` API.
4. Construct one room-level TURN exchange and slot transport, then multiplex
   bounded per-peer attempts through one coordinator and browser adapter. Keep
   the carrier's shared queue and 250 ms-plus-jitter exchange pacing enabled;
   individual peer loops must not create parallel allocation bursts. Reserve
   at least `maxActiveAttempts` high-priority entries for deadline-bound PUTs
   and at least `maxActiveAttempts + 2` normal/low entries for peer reads, the
   listener, and cleanup. Run no more than one listener discovery at once and
   begin its next read within one second plus 20% jitter while repair listening
   is required. Keep the established profile's two-second key/HMAC bounds and
   maximum one idempotent PUT retry; looser values require a new negotiated
   timing profile.
5. Execute every returned effect in array order even when an outcome is marked
   duplicate or invalid. `ignored` is only a compatibility hint for an empty
   semantic result.
6. Call the adapter's `authenticateChannel` hook to exchange and verify an
   attempt-bound link-hello. Returning `true` transfers the open connection to
   the application; room data must not be processed sooner.
7. Keep fully compact bootstrap pairing off. Relay wildcard routing exists,
   but the established-room coordinator rejects `bootstrap`; a separate
   high-entropy deep-link/QR or audited PAKE flow is still required. This does
   not disable the shipped one-way answer-return profile, whose strong bearer
   secret travels inside the full CC2 invitation.
8. On any V2 failure, show the ordinary answer plus explicit Start fallback.
   Never re-enable V1 automatic signalling as an implicit fallback.
9. Keep the established-room minimum budget at or above the adapter's bounded
   PC creation, five SDP/candidate operations across both peers, ICE gather,
   two key lookups, two HMAC operations, critical PUT, a maximum answer read,
   an already-running empty read, worst-positioned signed-abort polling,
   connectivity timeout, and safety margin. The outbound signed-token epoch
   starts once, after offer/ICE preparation and immediately before its bounded
   key lookup and HMAC; it must never be reset after publication. The adapter
   separately derives the optional isolated-service fallback reserve from four
   key lookups, four HMAC operations, two PUTs, role-sized paged reads,
   already-running empty reads, worst-positioned signed-abort polls, candidate
   application, and margin; it skips fallback
   when that exchange cannot fit after any still-outstanding bounded answer
   consumption. Multi-peer queue contention is bounded but is
   not counted as service time; a deadline exhausted by contention fails safely
   to manual repair.

The deferred validation matrix and wire contract live in
`docs/rendezvous-v2.md`. Relay-specific framing is in
`realm/relay/RENDEZVOUS_V2.md`.

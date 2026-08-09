# Rendezvous V2 staged rollout

Status: the rr2 foundation and a narrow encrypted automatic-answer profile are
active on the canary. Full room repair and fully compact first pairing remain
disabled.

Source defaults remain conservative: a new relay starts with
`RENDEZVOUS_V2_SLOTS=false`, and the full client flags remain false. The canary
deployment explicitly enables rr2 for build `0.29.0-auto-answer`; that deployed
exception must not be confused with changing the repository default.

## Capability ledger

| Capability | Source/build state | Canary state |
| --- | --- | --- |
| Legacy append-only short-code pairing and repair | Disabled | Disabled |
| rr2 memory-only latest-value slots | Disabled by default | Enabled |
| Encrypted automatic answer for a full CC2 invitation | Bundled and enabled | Published and live-tested |
| Complete pairwise-key room repair | Bundled primitives only; selection disabled | Disabled |
| Fully compact offer-and-answer bootstrap | Disabled | Disabled |
| Ordinary answer plus explicit Start fallback | Available | Available |

The automatic-answer profile is deliberately narrower than compact pairing.
The existing member still sends one full candidate-bearing CC2 invitation. Only
the joiner's compact answer returns through rr2, encrypted for that invitation.
See [auto-answer-return.md](auto-answer-return.md).

## Stage 0: containment foundation - complete

- V1 automatic signalling remains off.
- rr2 is isolated from the append-only room event log and persistence.
- Slot, room, queue, pacing, payload, and request-rate bounds are enforced.
- Manual answer exchange remains a terminal fallback.

This remains the logical rollback baseline even though the canary now enables
the narrower answer-return path.

## Stage 1: relay canary - complete

The existing canary relay was deployed with rr2 enabled. Its six lanes, rr1
compatibility, memory-only slot behavior, aggregate health counters, and live
PUT/discover/ACK path were checked. Health output contains counts only, never
slot selectors or payloads.

Repository and container defaults now retain both active slots and terminal
tombstones for five minutes. The already-running canary still has an older
`RENDEZVOUS_V2_TERMINAL_TTL_MS=30000` environment value. The client mitigates
that during its five-minute capability window by retaining one ciphertext and
having the host re-verify and re-ACK the same value after a suspended writer
returns. A later approved relay recreation should converge the deployed value
to `300000`; documentation must not claim that live mutation has happened.

## Stage 2: encrypted automatic-answer canary - complete

The reproducible bundle in `realm/clawdvert_channel.html` contains only the
shared modules required by answer return: codec, SDP, slot transport, TURN
exchange, and `auto-answer-return.js`. It does not activate the room-repair
coordinator or compact-offer bootstrap.

On 2026-08-09, build `0.29.0-auto-answer` passed repository checks, 34 relay and
protocol tests, Chromium and WebKit smoke tests, and a live desktop-to-iPhone
cellular pairing using TURN. The full invite was transferred once and the
encrypted answer returned automatically. That result validates this canary
profile, not every cell of the deferred full-repair matrix.

## Stage 3: stabilization and operations - next

- Recreate the canary with the five-minute terminal tombstone after an explicit
  deployment approval.
- Rotate the static TURN credential used during the canary and move toward
  short-lived TURN credentials before broader distribution.
- Exercise longer iOS suspend/resume windows, relay restart, slot expiry,
  shared public IPs, and repeated failed/retried invitations.
- Add Firefox and native Safari runs plus IPv6, TURN/TCP, and UDP-blocked paths.
- Continue checking that automatic-answer secrets are removed from retry UI,
  persistence, and terminal invite records.

## Stage 4: full room repair - future

Bundle and select the coordinator only after pairwise-key exchange,
authenticated capability confirmation, replay-state persistence, component
listener election, and target rotation are integrated. Run the complete codec,
state, relay, browser, and network matrix in `rendezvous-v2.md`, including
glare, partitions, reload, poisoned discovery, and multi-member rooms.

Automatic repair may begin with a small opt-in cohort only when the relay and
both peers advertise the exact capability over authenticated channels. Failure
returns to the ordinary answer and Start fallback, never to V1 signalling.

## Stage 5: fully compact pairing - future product decision

Do not reuse a six-character locator as an HMAC secret. Choose one of:

- QR/deep-link pairing with at least 128 random secret bits;
- an audited PAKE for human-only short codes; or
- a verified short-authentication-string ceremony.

Only then implement the separate broadcast bootstrap coordinator and enable
`RENDEZVOUS_V2_COMPACT_PAIRING_ENABLED` behind its own cohort. The current full
CC2 invitation already carries a strong one-use secret for answer return; that
does not make its offer compact.

## AWS checkpoint

The `canary` AWS profile is configured, and the existing relay and Route 53
deployment were reused for this canary. Deployment credentials and the PEM file
remain external to the repository and must never be copied into documentation
or artifacts. Any security-group widening, relay recreation, credential
rotation, or production promotion remains a separate approval checkpoint.

## Rollback

1. Republish the client with automatic answer return disabled, or disable rr2
   on the canary to force the existing manual fallback.
2. Keep the ordinary answer and explicit Start controls visible and actionable.
3. Drain active slots before setting `RENDEZVOUS_V2_SLOTS=false` when practical;
   disable immediately if availability or security requires it.
4. Keep full room repair, fully compact pairing, and V1 automatic signalling
   disabled.
5. Preserve aggregate diagnostics and the failed build for analysis. Never
   persist slot payloads or invitation secrets.

/*
 * Pure rendezvous-v2 attempt state machine.
 *
 * This module deliberately has no DOM, WebRTC, timer, storage, or transport
 * dependencies.  An adapter executes the returned effects and feeds the
 * resulting events back into transitionAttempt().  Keeping policy here makes
 * retries, expiry, and cleanup reviewable without starting a browser.
 */

export const RENDEZVOUS_V2_PROTOCOL = "rv2";

export const AUTH_PROFILE = Object.freeze({
  BOOTSTRAP: "bootstrap",
  PAIRWISE: "pairwise",
  ROOM_TRANSITION: "roomTransition",
});

export const ATTEMPT_ROLE = Object.freeze({
  OFFERER: "offerer",
  ANSWERER: "answerer",
});

export const ATTEMPT_STATE = Object.freeze({
  IDLE: "idle",
  CREATING_OFFER: "creating-offer",
  PUBLISHING_OFFER: "publishing-offer",
  WAITING_ANSWER: "waiting-answer",
  APPLYING_OFFER: "applying-offer",
  CREATING_ANSWER: "creating-answer",
  PUBLISHING_ANSWER: "publishing-answer",
  APPLYING_ANSWER: "applying-answer",
  CONNECTING: "connecting",
  CREATING_FALLBACK: "creating-fallback",
  PUBLISHING_FALLBACK: "publishing-fallback",
  PUBLISHING_NEED_CANDIDATE: "publishing-need-candidate",
  APPLYING_FALLBACK: "applying-fallback",
  OPEN: "open",
  FAILED: "failed",
  EXPIRED: "expired",
  ABORTED: "aborted",
});

export const ATTEMPT_EVENT = Object.freeze({
  START: "start",
  OUTBOUND_TOKEN_STARTED: "outbound-token-started",
  LOCAL_OFFER_READY: "local-offer-ready",
  LOCAL_ANSWER_READY: "local-answer-ready",
  LOCAL_FALLBACK_READY: "local-fallback-ready",
  SLOT_STORED: "slot-stored",
  REMOTE_OFFER_VERIFIED: "remote-offer-verified",
  REMOTE_ANSWER_VERIFIED: "remote-answer-verified",
  REMOTE_NEED_CANDIDATE_VERIFIED: "remote-need-candidate-verified",
  REMOTE_FALLBACK_VERIFIED: "remote-fallback-verified",
  REMOTE_ABORT_VERIFIED: "remote-abort-verified",
  REMOTE_DESCRIPTION_APPLIED: "remote-description-applied",
  REMOTE_FALLBACK_APPLIED: "remote-fallback-applied",
  CONNECTIVITY_TIMEOUT: "connectivity-timeout",
  CHANNEL_OPEN: "channel-open",
  FAIL: "fail",
  ABORT: "abort",
  EXPIRE: "expire",
});

export const ATTEMPT_EFFECT = Object.freeze({
  CREATE_OFFER: "create-offer-without-candidate",
  APPLY_OFFER: "apply-offer-without-candidate",
  CREATE_ANSWER: "create-answer-with-candidates",
  APPLY_ANSWER: "apply-answer-and-candidates",
  CREATE_FALLBACK: "create-fallback-candidate",
  APPLY_FALLBACK: "apply-fallback-candidate",
  PUT_SLOT: "put-slot",
  ACK_REMOTE_SLOT: "ack-remote-slot",
  ABORT_REMOTE_SLOT: "abort-remote-slot",
  CLEAR_LOCAL: "clear-local-slots",
  CLOSE_CONNECTION: "close-connection",
  RECORD_TERMINAL: "record-terminal",
});

export const ATTEMPT_DISPOSITION = Object.freeze({
  CONSUMED: "consumed",
  DUPLICATE: "duplicate",
  DEFERRED: "deferred",
  INVALID: "invalid",
});

export const SLOT_ROLE = Object.freeze({
  OFFER: "offer",
  ANSWER: "answer",
  NEED_CANDIDATE: "needCandidate",
  CANDIDATE: "candidate",
  ABORT: "abort",
});

const TERMINAL = new Set([
  ATTEMPT_STATE.OPEN,
  ATTEMPT_STATE.FAILED,
  ATTEMPT_STATE.EXPIRED,
  ATTEMPT_STATE.ABORTED,
]);

const DEVICE_ID = /^(?!0{16}$)[a-f0-9]{16}$/;
const ATTEMPT_ID = /^(?!0{32}$)[a-f0-9]{32}$/;
const CONTEXT_ID = /^(?!0{24}$)[a-f0-9]{24}$/;
const SLOT_WIRE_ROLE = Object.freeze({
  [SLOT_ROLE.OFFER]: "o",
  [SLOT_ROLE.ANSWER]: "a",
  [SLOT_ROLE.NEED_CANDIDATE]: "n",
  [SLOT_ROLE.CANDIDATE]: "c",
  [SLOT_ROLE.ABORT]: "x",
});
const MIN_TTL_MS = 5_000;
const MAX_TTL_MS = 5 * 60_000;

function invariant(condition, message) {
  if (!condition) throw new TypeError(message);
}

function finiteInteger(value, name) {
  invariant(Number.isSafeInteger(value), `${name} must be a safe integer`);
  return value;
}

function cloneAttempt(attempt, patch = {}) {
  return Object.freeze({ ...attempt, ...patch });
}

function effect(type, detail = {}) {
  return Object.freeze({ type, ...detail });
}

function result(attempt, effects = [], disposition = ATTEMPT_DISPOSITION.CONSUMED) {
  return Object.freeze({
    attempt,
    effects: Object.freeze(effects),
    disposition,
    // Compatibility only: semantic duplicates can still carry mandatory
    // lifecycle effects. Consumers must always execute a non-empty effect list.
    ignored: effects.length === 0 && disposition !== ATTEMPT_DISPOSITION.CONSUMED,
  });
}

function duplicate(attempt) {
  return result(attempt, [], ATTEMPT_DISPOSITION.DUPLICATE);
}

function deferred(attempt) {
  return result(attempt, [], ATTEMPT_DISPOSITION.DEFERRED);
}

function invalid(attempt) {
  return result(attempt, [], ATTEMPT_DISPOSITION.INVALID);
}

function next(attempt, state, now, patch = {}, effects = []) {
  const contextualEffects = effects.map(item => effect(item.type, {
    ...item,
    attemptId: attempt.attemptId,
    contextId: attempt.contextId,
    localId: attempt.localId,
    peerId: attempt.peerId,
  }));
  return result(cloneAttempt(attempt, {
    ...patch,
    state,
    revision: attempt.revision + 1,
    updatedAt: now,
  }), contextualEffects);
}

function terminal(attempt, state, now, reason, publishAbort) {
  const effects = [
    effect(ATTEMPT_EFFECT.CLOSE_CONNECTION, { reason }),
    effect(ATTEMPT_EFFECT.CLEAR_LOCAL, { attemptId: attempt.attemptId }),
    effect(ATTEMPT_EFFECT.RECORD_TERMINAL, { state, reason }),
  ];
  // A preparation failure precedes the only authenticated epoch and cannot
  // abort an offer no peer could have observed.
  if (publishAbort && now < attempt.publishDeadline
      && (attempt.role !== ATTEMPT_ROLE.OFFERER || attempt.tokenEpochStarted)) {
    // Effects are executed in order. Clear the attempt's old slots before
    // publishing its signed abort so cleanup cannot erase the abort itself.
    effects.splice(2, 0, effect(ATTEMPT_EFFECT.PUT_SLOT, {
      slotRole: SLOT_ROLE.ABORT,
      attemptId: attempt.attemptId,
      payload: { reason, referenceRole: abortReferenceRole(attempt) },
    }));
  }
  return next(attempt, state, now, {
    terminalAt: now,
    lastError: reason || null,
  }, effects);
}

function abortReferenceRole(attempt) {
  if (attempt.lastPublishedRole) return attempt.lastPublishedRole;
  if (attempt.state === ATTEMPT_STATE.CONNECTING && attempt.fallbackRequested) {
    return SLOT_ROLE.NEED_CANDIDATE;
  }
  if ([ATTEMPT_STATE.PUBLISHING_NEED_CANDIDATE,
    ATTEMPT_STATE.CREATING_FALLBACK].includes(attempt.state)) return SLOT_ROLE.NEED_CANDIDATE;
  if ([ATTEMPT_STATE.PUBLISHING_FALLBACK,
    ATTEMPT_STATE.APPLYING_FALLBACK].includes(attempt.state)) return SLOT_ROLE.CANDIDATE;
  if ([ATTEMPT_STATE.CREATING_ANSWER, ATTEMPT_STATE.PUBLISHING_ANSWER,
    ATTEMPT_STATE.APPLYING_ANSWER, ATTEMPT_STATE.CONNECTING].includes(attempt.state)) {
    return SLOT_ROLE.ANSWER;
  }
  return SLOT_ROLE.OFFER;
}

export function createAttempt({
  attemptId,
  contextId,
  localId,
  peerId,
  role,
  profile = AUTH_PROFILE.PAIRWISE,
  createdAt,
  offerIssuedAtSeconds = Math.floor(createdAt / 1000),
  ttlMs = 300_000,
  tokenExpiresAt = (offerIssuedAtSeconds + Math.floor(ttlMs / 1000)) * 1000,
  signallingDeadline = Math.min(createdAt + ttlMs, tokenExpiresAt),
  publishDeadline = signallingDeadline,
  completionGraceMs = 30_000,
}) {
  invariant(ATTEMPT_ID.test(String(attemptId)), "attemptId must be 128-bit lowercase hex");
  invariant(CONTEXT_ID.test(String(contextId)), "contextId must be 96-bit lowercase hex");
  invariant(DEVICE_ID.test(String(localId)), "localId must be a 64-bit lowercase hex device id");
  invariant(DEVICE_ID.test(String(peerId)), "peerId must be a 64-bit lowercase hex device id");
  invariant(localId !== peerId, "an attempt cannot target the local device");
  invariant(Object.values(ATTEMPT_ROLE).includes(role), "invalid attempt role");
  invariant(Object.values(AUTH_PROFILE).includes(profile), "invalid authentication profile");
  finiteInteger(createdAt, "createdAt");
  finiteInteger(offerIssuedAtSeconds, "offerIssuedAtSeconds");
  invariant(offerIssuedAtSeconds >= 0 && offerIssuedAtSeconds <= 0xffffffff,
    "offerIssuedAtSeconds is outside the token range");
  finiteInteger(ttlMs, "ttlMs");
  finiteInteger(tokenExpiresAt, "tokenExpiresAt");
  finiteInteger(signallingDeadline, "signallingDeadline");
  finiteInteger(publishDeadline, "publishDeadline");
  finiteInteger(completionGraceMs, "completionGraceMs");
  invariant(ttlMs >= MIN_TTL_MS && ttlMs <= MAX_TTL_MS, "ttlMs is outside the supported bounds");
  invariant(tokenExpiresAt >= (offerIssuedAtSeconds + 15) * 1000
    && tokenExpiresAt <= (offerIssuedAtSeconds + 300) * 1000,
  "tokenExpiresAt is outside the signed token profile");
  invariant(signallingDeadline > createdAt
    && signallingDeadline <= createdAt + ttlMs + 300_000
    && signallingDeadline <= tokenExpiresAt + 300_000,
  "signallingDeadline is outside the local acceptance window");
  invariant(publishDeadline > createdAt && publishDeadline <= signallingDeadline,
    "publishDeadline is outside the local signalling window");
  invariant(completionGraceMs >= 0 && completionGraceMs <= 60_000,
    "completionGraceMs is outside the supported bounds");

  return Object.freeze({
    protocol: RENDEZVOUS_V2_PROTOCOL,
    profile,
    attemptId,
    contextId,
    localId,
    peerId,
    role,
    state: ATTEMPT_STATE.IDLE,
    createdAt,
    offerIssuedAtSeconds,
    updatedAt: createdAt,
    expiresAt: signallingDeadline,
    publishDeadline,
    completionDeadline: signallingDeadline + completionGraceMs,
    tokenExpiresAt,
    tokenEpochStarted: role === ATTEMPT_ROLE.ANSWERER,
    revision: 0,
    fallbackPending: false,
    fallbackRequested: false,
    fallbackApplied: false,
    lastPublishedRole: null,
    terminalAt: null,
    lastError: null,
  });
}

export function isTerminalAttempt(attempt) {
  return Boolean(attempt && TERMINAL.has(attempt.state));
}

export function transitionAttempt(attempt, event, now) {
  invariant(attempt && attempt.protocol === RENDEZVOUS_V2_PROTOCOL, "invalid rendezvous attempt");
  invariant(event && Object.values(ATTEMPT_EVENT).includes(event.type), "invalid rendezvous event");
  finiteInteger(now, "now");

  if (isTerminalAttempt(attempt)) return duplicate(attempt);

  if (event.type === ATTEMPT_EVENT.CHANNEL_OPEN) {
    if (now >= attempt.completionDeadline) {
      return terminal(attempt, ATTEMPT_STATE.EXPIRED, now, "attempt expired", false);
    }
    const allowed = new Set([
      ATTEMPT_STATE.PUBLISHING_ANSWER,
      ATTEMPT_STATE.APPLYING_ANSWER,
      ATTEMPT_STATE.CONNECTING,
      ATTEMPT_STATE.CREATING_FALLBACK,
      ATTEMPT_STATE.PUBLISHING_FALLBACK,
      ATTEMPT_STATE.PUBLISHING_NEED_CANDIDATE,
      ATTEMPT_STATE.APPLYING_FALLBACK,
    ]);
    if (!allowed.has(attempt.state)) return deferred(attempt);
    return next(attempt, ATTEMPT_STATE.OPEN, now, { terminalAt: now }, [
      // This is storage cleanup only. It must be issued after the remote slot
      // payload was authenticated and must never be treated as peer identity.
      effect(ATTEMPT_EFFECT.CLEAR_LOCAL, { attemptId: attempt.attemptId }),
      effect(ATTEMPT_EFFECT.RECORD_TERMINAL, { state: ATTEMPT_STATE.OPEN, reason: "channel open" }),
    ]);
  }
  // The completion grace is exclusively for an already-negotiating channel to
  // finish its authenticated link-hello. No new signalling may be generated or
  // consumed once the local signed-token acceptance window closes.
  if (event.type === ATTEMPT_EVENT.EXPIRE || now >= attempt.expiresAt) {
    return terminal(attempt, ATTEMPT_STATE.EXPIRED, now, "attempt expired", false);
  }
  if (event.type === ATTEMPT_EVENT.FAIL) {
    return terminal(attempt, ATTEMPT_STATE.FAILED, now,
      String(event.reason || "attempt failed").slice(0, 160), true);
  }
  if (event.type === ATTEMPT_EVENT.ABORT) {
    return terminal(attempt, ATTEMPT_STATE.ABORTED, now,
      String(event.reason || "attempt aborted").slice(0, 160), true);
  }
  if (event.type === ATTEMPT_EVENT.REMOTE_ABORT_VERIFIED) {
    return terminal(attempt, ATTEMPT_STATE.ABORTED, now,
      String(event.reason || "peer aborted attempt").slice(0, 160), false);
  }

  return attempt.role === ATTEMPT_ROLE.OFFERER
    ? transitionOfferer(attempt, event, now)
    : transitionAnswerer(attempt, event, now);
}

function transitionOfferer(attempt, event, now) {
  if (attempt.state === ATTEMPT_STATE.IDLE && event.type === ATTEMPT_EVENT.START) {
    return next(attempt, ATTEMPT_STATE.CREATING_OFFER, now, {}, [
      effect(ATTEMPT_EFFECT.CREATE_OFFER, { attemptId: attempt.attemptId }),
    ]);
  }
  if (attempt.state === ATTEMPT_STATE.CREATING_OFFER
      && event.type === ATTEMPT_EVENT.OUTBOUND_TOKEN_STARTED) {
    if (attempt.tokenEpochStarted) return duplicate(attempt);
    const signedLifetimeMs = attempt.tokenExpiresAt
      - (attempt.offerIssuedAtSeconds * 1000);
    const receiveExtensionMs = attempt.expiresAt - attempt.tokenExpiresAt;
    const completionGraceMs = attempt.completionDeadline - attempt.expiresAt;
    const offerIssuedAtSeconds = Math.floor(now / 1000);
    const tokenExpiresAt = (offerIssuedAtSeconds * 1000) + signedLifetimeMs;
    invariant(signedLifetimeMs >= 15_000 && signedLifetimeMs <= 300_000,
      "outbound token lifetime is outside the signed profile");
    invariant(receiveExtensionMs >= 0 && receiveExtensionMs <= 300_000,
      "outbound receive extension is invalid");
    return next(attempt, ATTEMPT_STATE.CREATING_OFFER, now, {
      offerIssuedAtSeconds,
      tokenExpiresAt,
      publishDeadline: tokenExpiresAt,
      expiresAt: tokenExpiresAt + receiveExtensionMs,
      completionDeadline: tokenExpiresAt + receiveExtensionMs + completionGraceMs,
      tokenEpochStarted: true,
    });
  }
  if (attempt.state === ATTEMPT_STATE.CREATING_OFFER
      && event.type === ATTEMPT_EVENT.LOCAL_OFFER_READY) {
    invariant(attempt.tokenEpochStarted,
      "outbound token epoch must start after offer gathering and before signing");
    return next(attempt, ATTEMPT_STATE.PUBLISHING_OFFER, now, {}, [
      effect(ATTEMPT_EFFECT.PUT_SLOT, {
        slotRole: SLOT_ROLE.OFFER,
        attemptId: attempt.attemptId,
        payload: event.payload,
      }),
    ]);
  }
  if (attempt.state === ATTEMPT_STATE.PUBLISHING_OFFER
      && event.type === ATTEMPT_EVENT.SLOT_STORED
      && event.slotRole === SLOT_ROLE.OFFER) {
    return next(attempt, ATTEMPT_STATE.WAITING_ANSWER, now,
      { lastPublishedRole: SLOT_ROLE.OFFER });
  }
  if ([ATTEMPT_STATE.PUBLISHING_OFFER, ATTEMPT_STATE.WAITING_ANSWER].includes(attempt.state)
      && event.type === ATTEMPT_EVENT.REMOTE_ANSWER_VERIFIED) {
    return next(attempt, ATTEMPT_STATE.APPLYING_ANSWER, now, {}, [
      effect(ATTEMPT_EFFECT.APPLY_ANSWER, {
        attemptId: attempt.attemptId,
        envelope: event.envelope,
      }),
    ]);
  }
  if (attempt.state === ATTEMPT_STATE.APPLYING_ANSWER
      && event.type === ATTEMPT_EVENT.REMOTE_DESCRIPTION_APPLIED) {
    if (attempt.fallbackPending && !attempt.fallbackRequested) {
      return next(attempt, ATTEMPT_STATE.CREATING_FALLBACK, now,
        { fallbackPending: false, fallbackRequested: true }, [
          effect(ATTEMPT_EFFECT.CREATE_FALLBACK, { attemptId: attempt.attemptId }),
        ]);
    }
    return next(attempt, ATTEMPT_STATE.CONNECTING, now);
  }
  if ([ATTEMPT_STATE.PUBLISHING_OFFER, ATTEMPT_STATE.WAITING_ANSWER,
    ATTEMPT_STATE.APPLYING_ANSWER].includes(attempt.state)
      && event.type === ATTEMPT_EVENT.REMOTE_NEED_CANDIDATE_VERIFIED) {
    if (attempt.fallbackPending || attempt.fallbackRequested) return duplicate(attempt);
    return next(attempt, attempt.state, now, { fallbackPending: true });
  }
  if (attempt.state === ATTEMPT_STATE.CONNECTING
      && event.type === ATTEMPT_EVENT.REMOTE_NEED_CANDIDATE_VERIFIED) {
    if (attempt.fallbackRequested) return duplicate(attempt);
    return next(attempt, ATTEMPT_STATE.CREATING_FALLBACK, now,
      { fallbackRequested: true }, [
        effect(ATTEMPT_EFFECT.CREATE_FALLBACK, { attemptId: attempt.attemptId }),
      ]);
  }
  if (attempt.state === ATTEMPT_STATE.CREATING_FALLBACK
      && event.type === ATTEMPT_EVENT.LOCAL_FALLBACK_READY) {
    return next(attempt, ATTEMPT_STATE.PUBLISHING_FALLBACK, now, {}, [
      effect(ATTEMPT_EFFECT.PUT_SLOT, {
        slotRole: SLOT_ROLE.CANDIDATE,
        attemptId: attempt.attemptId,
        payload: event.payload,
      }),
    ]);
  }
  if (attempt.state === ATTEMPT_STATE.PUBLISHING_FALLBACK
      && event.type === ATTEMPT_EVENT.SLOT_STORED
      && event.slotRole === SLOT_ROLE.CANDIDATE) {
    return next(attempt, ATTEMPT_STATE.CONNECTING, now,
      { lastPublishedRole: SLOT_ROLE.CANDIDATE });
  }
  if (event.type === ATTEMPT_EVENT.REMOTE_ANSWER_VERIFIED) {
    if ([ATTEMPT_STATE.APPLYING_ANSWER, ATTEMPT_STATE.CONNECTING,
      ATTEMPT_STATE.CREATING_FALLBACK, ATTEMPT_STATE.PUBLISHING_FALLBACK].includes(attempt.state)) {
      return duplicate(attempt);
    }
    return deferred(attempt);
  }
  if (event.type === ATTEMPT_EVENT.REMOTE_NEED_CANDIDATE_VERIFIED) {
    if (attempt.fallbackPending || attempt.fallbackRequested) return duplicate(attempt);
    return deferred(attempt);
  }
  if (event.type === ATTEMPT_EVENT.SLOT_STORED) return duplicate(attempt);
  if ([ATTEMPT_EVENT.REMOTE_OFFER_VERIFIED, ATTEMPT_EVENT.REMOTE_FALLBACK_VERIFIED]
    .includes(event.type)) return invalid(attempt);
  throw new Error(`invalid offerer transition: ${attempt.state} + ${event.type}`);
}

function transitionAnswerer(attempt, event, now) {
  if (attempt.state === ATTEMPT_STATE.IDLE
      && event.type === ATTEMPT_EVENT.REMOTE_OFFER_VERIFIED) {
    return next(attempt, ATTEMPT_STATE.APPLYING_OFFER, now, {}, [
      effect(ATTEMPT_EFFECT.APPLY_OFFER, {
        attemptId: attempt.attemptId,
        envelope: event.envelope,
      }),
    ]);
  }
  if (attempt.state === ATTEMPT_STATE.APPLYING_OFFER
      && event.type === ATTEMPT_EVENT.REMOTE_DESCRIPTION_APPLIED) {
    return next(attempt, ATTEMPT_STATE.CREATING_ANSWER, now, {}, [
      effect(ATTEMPT_EFFECT.CREATE_ANSWER, { attemptId: attempt.attemptId }),
    ]);
  }
  if (attempt.state === ATTEMPT_STATE.CREATING_ANSWER
      && event.type === ATTEMPT_EVENT.LOCAL_ANSWER_READY) {
    return next(attempt, ATTEMPT_STATE.PUBLISHING_ANSWER, now, {}, [
      effect(ATTEMPT_EFFECT.PUT_SLOT, {
        slotRole: SLOT_ROLE.ANSWER,
        attemptId: attempt.attemptId,
        payload: event.payload,
      }),
    ]);
  }
  if (attempt.state === ATTEMPT_STATE.PUBLISHING_ANSWER
      && event.type === ATTEMPT_EVENT.SLOT_STORED
      && event.slotRole === SLOT_ROLE.ANSWER) {
    return next(attempt, ATTEMPT_STATE.CONNECTING, now,
      { lastPublishedRole: SLOT_ROLE.ANSWER });
  }
  if (attempt.state === ATTEMPT_STATE.CONNECTING
      && event.type === ATTEMPT_EVENT.CONNECTIVITY_TIMEOUT
      && !attempt.fallbackRequested) {
    return next(attempt, ATTEMPT_STATE.PUBLISHING_NEED_CANDIDATE, now,
      { fallbackRequested: true }, [
        effect(ATTEMPT_EFFECT.PUT_SLOT, {
          slotRole: SLOT_ROLE.NEED_CANDIDATE,
          attemptId: attempt.attemptId,
          payload: null,
        }),
      ]);
  }
  if (attempt.state === ATTEMPT_STATE.PUBLISHING_NEED_CANDIDATE
      && event.type === ATTEMPT_EVENT.SLOT_STORED
      && event.slotRole === SLOT_ROLE.NEED_CANDIDATE) {
    return next(attempt, ATTEMPT_STATE.CONNECTING, now,
      { lastPublishedRole: SLOT_ROLE.NEED_CANDIDATE });
  }
  if ([ATTEMPT_STATE.CONNECTING, ATTEMPT_STATE.PUBLISHING_NEED_CANDIDATE].includes(attempt.state)
      && event.type === ATTEMPT_EVENT.REMOTE_FALLBACK_VERIFIED) {
    if (!attempt.fallbackRequested) return invalid(attempt);
    if (attempt.fallbackApplied) return duplicate(attempt);
    return next(attempt, ATTEMPT_STATE.APPLYING_FALLBACK, now, {}, [
      effect(ATTEMPT_EFFECT.APPLY_FALLBACK, {
        attemptId: attempt.attemptId,
        envelope: event.envelope,
      }),
    ]);
  }
  if (attempt.state === ATTEMPT_STATE.APPLYING_FALLBACK
      && event.type === ATTEMPT_EVENT.REMOTE_FALLBACK_APPLIED) {
    return next(attempt, ATTEMPT_STATE.CONNECTING, now, { fallbackApplied: true });
  }
  if (event.type === ATTEMPT_EVENT.REMOTE_OFFER_VERIFIED) return duplicate(attempt);
  if (event.type === ATTEMPT_EVENT.REMOTE_FALLBACK_VERIFIED) {
    if (attempt.fallbackApplied || attempt.state === ATTEMPT_STATE.APPLYING_FALLBACK) {
      return duplicate(attempt);
    }
    return attempt.fallbackRequested ? deferred(attempt) : invalid(attempt);
  }
  if (event.type === ATTEMPT_EVENT.SLOT_STORED
      || (event.type === ATTEMPT_EVENT.CONNECTIVITY_TIMEOUT && attempt.fallbackRequested)) {
    return duplicate(attempt);
  }
  if ([ATTEMPT_EVENT.REMOTE_ANSWER_VERIFIED, ATTEMPT_EVENT.REMOTE_NEED_CANDIDATE_VERIFIED]
    .includes(event.type)) return invalid(attempt);
  throw new Error(`invalid answerer transition: ${attempt.state} + ${event.type}`);
}

/**
 * Verify and route a wire envelope without exposing an unauthenticated state
 * mutation boundary. `verify` must return null or a decoded envelope whose
 * canonical authentication tag has already been checked.
 */
export async function verifyAndTransition(attempt, wire, verify, now) {
  invariant(typeof verify === "function", "verify must be a function");
  const envelope = await verify(wire);
  invariant(envelope, "rendezvous envelope authentication failed");
  return transitionVerifiedEnvelope(attempt, envelope, now);
}

/**
 * Route an envelope returned by the canonical codec's authenticated decode.
 * Callers that still hold wire text must use verifyAndTransition() instead.
 */
export function transitionVerifiedEnvelope(attempt, envelope, now, receipt = null) {
  finiteInteger(now, "now");
  invariant(envelope.version === 2, "wrong rendezvous protocol version");
  invariant(envelope.profile === attempt.profile, "wrong rendezvous authentication profile");
  invariant(envelope.attemptId === attempt.attemptId, "unknown rendezvous attempt");
  invariant(envelope.contextId === attempt.contextId, "wrong rendezvous context");
  invariant(envelope.from === attempt.peerId, "wrong rendezvous sender");
  invariant(envelope.to === attempt.localId, "wrong rendezvous recipient");
  invariant(Number.isSafeInteger(envelope.expiresAtSeconds), "rendezvous envelope has no expiry");
  invariant(envelope.issuedAt === attempt.offerIssuedAtSeconds,
    "rendezvous envelope changed the attempt issue time");
  invariant(envelope.expiresAtSeconds * 1000 === attempt.tokenExpiresAt,
    "rendezvous envelope changed the attempt expiry");
  invariant(now < attempt.expiresAt, "rendezvous envelope expired locally");

  const byRole = {
    [SLOT_ROLE.OFFER]: ATTEMPT_EVENT.REMOTE_OFFER_VERIFIED,
    [SLOT_ROLE.ANSWER]: ATTEMPT_EVENT.REMOTE_ANSWER_VERIFIED,
    [SLOT_ROLE.NEED_CANDIDATE]: ATTEMPT_EVENT.REMOTE_NEED_CANDIDATE_VERIFIED,
    [SLOT_ROLE.CANDIDATE]: ATTEMPT_EVENT.REMOTE_FALLBACK_VERIFIED,
    [SLOT_ROLE.ABORT]: ATTEMPT_EVENT.REMOTE_ABORT_VERIFIED,
  };
  const type = byRole[envelope.role];
  invariant(type, "unknown rendezvous envelope role");
  const outcome = transitionAttempt(attempt, {
    type,
    envelope,
    reason: envelope.reason,
  }, now);
  if (receipt == null) return outcome;
  invariant(receipt && typeof receipt === "object", "invalid relay slot receipt");
  invariant(receipt.attemptId === envelope.attemptId,
    "relay slot attempt disagrees with authenticated token");
  invariant(receipt.from === envelope.from && receipt.to === envelope.to,
    "relay slot route disagrees with authenticated token");
  invariant(receipt.role === envelope.role || receipt.role === SLOT_WIRE_ROLE[envelope.role],
    "relay slot role disagrees with authenticated token");
  invariant(Number.isSafeInteger(receipt.revision) && receipt.revision >= 1,
    "invalid relay slot revision");

  if (outcome.disposition === ATTEMPT_DISPOSITION.DEFERRED) return outcome;
  const lifecycle = outcome.disposition === ATTEMPT_DISPOSITION.INVALID
    ? ATTEMPT_EFFECT.ABORT_REMOTE_SLOT
    : ATTEMPT_EFFECT.ACK_REMOTE_SLOT;
  // Relay lifecycle operations are untrusted storage hints. They are appended
  // after semantic effects so an ordered adapter cannot erase a valid token
  // before the corresponding SDP/candidate operation succeeds.
  return result(outcome.attempt, [...outcome.effects, effect(lifecycle, {
    attemptId: envelope.attemptId,
    contextId: attempt.contextId,
    receipt: Object.freeze({ ...receipt }),
  })], outcome.disposition);
}

/**
 * Select one listener from a caller-supplied connected component.  Membership
 * and graph discovery remain application concerns; this function only makes
 * the lease choice deterministic and excludes stale/incapable members.
 */
export function electRepairListener(members, now, staleAfterMs = 45_000) {
  finiteInteger(now, "now");
  finiteInteger(staleAfterMs, "staleAfterMs");
  const eligible = (Array.isArray(members) ? members : [])
    .filter(member => member && DEVICE_ID.test(String(member.id)))
    .filter(member => member.canListen !== false && member.connected === true)
    .filter(member => Number.isSafeInteger(member.lastSeen) && now - member.lastSeen <= staleAfterMs)
    .sort((left, right) => left.id.localeCompare(right.id));
  return eligible[0]?.id || null;
}

/**
 * Rank peers outside the local connected component.  Recently failed targets
 * move to the back, preventing one remembered low id from trapping repairs.
 */
export function rankRepairTargets(members, componentIds, now) {
  finiteInteger(now, "now");
  const localComponent = new Set(componentIds || []);
  return (Array.isArray(members) ? members : [])
    .filter(member => member && DEVICE_ID.test(String(member.id)) && !localComponent.has(member.id))
    .map(member => ({
      ...member,
      lastSeen: Number.isSafeInteger(member.lastSeen) ? member.lastSeen : 0,
      failedAt: Number.isSafeInteger(member.failedAt) ? member.failedAt : 0,
    }))
    .sort((left, right) => {
      const leftLive = now - left.lastSeen <= 45_000 ? 0 : 1;
      const rightLive = now - right.lastSeen <= 45_000 ? 0 : 1;
      if (leftLive !== rightLive) return leftLive - rightLive;
      if (left.failedAt !== right.failedAt) return left.failedAt - right.failedAt;
      return left.id.localeCompare(right.id);
    })
    .map(member => member.id);
}

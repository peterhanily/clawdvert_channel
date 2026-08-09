/*
 * Room-level coordinator for dormant rendezvous-v2 attempts.
 *
 * It owns attempt cardinality and per-peer replacement policy, but deliberately
 * does not execute WebRTC or relay effects.  The application adapter receives
 * the returned effects and dispatches completion events back here.
 */

import {
  ATTEMPT_DISPOSITION,
  ATTEMPT_EFFECT,
  ATTEMPT_EVENT,
  ATTEMPT_ROLE,
  AUTH_PROFILE,
  RENDEZVOUS_V2_PROTOCOL,
  SLOT_ROLE,
  createAttempt,
  electRepairListener,
  isTerminalAttempt,
  rankRepairTargets,
  transitionAttempt,
  transitionVerifiedEnvelope,
} from "./rendezvous-v2-state.js";

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
const DEFAULT_MAX_ACTIVE_ATTEMPTS = 12;
const DEFAULT_MAX_REPLAY_TOMBSTONES = 256;
const DEFAULT_TTL_MS = 300_000;
const DEFAULT_REPLAY_SKEW_MS = 120_000;
const DEFAULT_VERIFICATION_CLOCK_SKEW_MS = 120_000;
const DEFAULT_MINIMUM_INBOUND_BUDGET_MS = 230_000;

function requireCondition(condition, message) {
  if (!condition) throw new TypeError(message);
}

function attemptKey(peerId, attemptId) {
  return `${peerId}:${attemptId}`;
}

export class RendezvousV2Coordinator {
  constructor({
    localId,
    contextId,
    now = () => Date.now(),
    randomAttemptId,
    defaultProfile = AUTH_PROFILE.PAIRWISE,
    allowedProfiles = [AUTH_PROFILE.PAIRWISE],
    profileForPeer = () => defaultProfile,
    maxActiveAttempts = DEFAULT_MAX_ACTIVE_ATTEMPTS,
    maxReplayTombstones = DEFAULT_MAX_REPLAY_TOMBSTONES,
    replaySkewMs = DEFAULT_REPLAY_SKEW_MS,
    verificationClockSkewMs = DEFAULT_VERIFICATION_CLOCK_SKEW_MS,
    minimumInboundBudgetMs = DEFAULT_MINIMUM_INBOUND_BUDGET_MS,
    ttlMs = DEFAULT_TTL_MS,
    initialReplayTombstones = [],
    initialReplaySaturatedUntil = 0,
    onReplayTombstonesChanged = () => {},
  }) {
    requireCondition(DEVICE_ID.test(String(localId)), "invalid local device id");
    requireCondition(CONTEXT_ID.test(String(contextId)), "invalid rendezvous context id");
    requireCondition(typeof now === "function", "now must be a function");
    requireCondition(typeof randomAttemptId === "function", "randomAttemptId must be a function");
    requireCondition(Number.isSafeInteger(maxActiveAttempts)
      && maxActiveAttempts >= 1 && maxActiveAttempts <= 32,
    "maxActiveAttempts must be between 1 and 32");
    requireCondition(Number.isSafeInteger(maxReplayTombstones)
      && maxReplayTombstones >= 32 && maxReplayTombstones <= 4096,
    "maxReplayTombstones must be between 32 and 4096");
    requireCondition(Number.isSafeInteger(replaySkewMs)
      && replaySkewMs >= 0 && replaySkewMs <= 300_000,
    "replaySkewMs must be between zero and 300000");
    requireCondition(verificationClockSkewMs === DEFAULT_VERIFICATION_CLOCK_SKEW_MS,
      "the established-room profile fixes verificationClockSkewMs at 120000");
    requireCondition(Array.isArray(allowedProfiles) && allowedProfiles.length > 0,
      "allowedProfiles must contain at least one authentication profile");
    requireCondition(typeof profileForPeer === "function", "profileForPeer must be a function");
    const allowedProfileSet = new Set(allowedProfiles);
    requireCondition([...allowedProfileSet].every(profile => Object.values(AUTH_PROFILE).includes(profile)),
      "allowedProfiles contains an invalid authentication profile");
    requireCondition(!allowedProfileSet.has(AUTH_PROFILE.BOOTSTRAP),
      "bootstrap requires its separate broadcast coordinator");
    requireCondition(Object.values(AUTH_PROFILE).includes(defaultProfile), "invalid default authentication profile");
    requireCondition(allowedProfileSet.has(defaultProfile), "defaultProfile must be allowed");
    requireCondition(Number.isSafeInteger(ttlMs) && ttlMs >= 15_000 && ttlMs <= 300_000,
      "ttlMs is outside the supported bounds");
    requireCondition(Number.isSafeInteger(minimumInboundBudgetMs)
      && minimumInboundBudgetMs >= 15_000 && minimumInboundBudgetMs <= 300_000
      && ttlMs >= minimumInboundBudgetMs,
    "minimumInboundBudgetMs must fit inside ttlMs");
    requireCondition(typeof onReplayTombstonesChanged === "function",
      "onReplayTombstonesChanged must be a function");

    this.localId = localId;
    this.contextId = contextId;
    this.now = now;
    this.randomAttemptId = randomAttemptId;
    this.defaultProfile = defaultProfile;
    this.allowedProfiles = allowedProfileSet;
    this.profileForPeerPolicy = profileForPeer;
    this.maxActiveAttempts = maxActiveAttempts;
    this.maxReplayTombstones = maxReplayTombstones;
    this.replaySkewMs = replaySkewMs;
    this.verificationClockSkewMs = verificationClockSkewMs;
    this.minimumInboundBudgetMs = minimumInboundBudgetMs;
    this.ttlMs = ttlMs;
    this.attempts = new Map();
    this.activeByPeer = new Map();
    this.replayTombstones = new Map();
    const constructedAt = this.now();
    requireCondition(Number.isSafeInteger(constructedAt), "now must return an integer timestamp");
    const replayPersistenceHorizon = constructedAt + 300_000
      + (2 * this.verificationClockSkewMs) + this.replaySkewMs;
    this.replaySaturatedUntil = Number.isSafeInteger(initialReplaySaturatedUntil)
      && initialReplaySaturatedUntil > constructedAt
      && initialReplaySaturatedUntil <= replayPersistenceHorizon
      ? initialReplaySaturatedUntil : 0;
    this.failures = new Map();
    this.onReplayTombstonesChanged = onReplayTombstonesChanged;
    this.restoreReplayTombstones(initialReplayTombstones);
  }

  start(peerId, profile = null) {
    this.#validatePeer(peerId);
    const expectedProfile = this.authenticationProfileForPeer(peerId, "sign");
    if (profile == null) profile = expectedProfile;
    requireCondition(profile === expectedProfile,
      "requested authentication profile disagrees with this peer's confirmed profile");
    const existing = this.activeAttempt(peerId);
    if (existing) return Object.freeze({
      attempt: existing,
      effects: Object.freeze([]),
      disposition: ATTEMPT_DISPOSITION.DUPLICATE,
      ignored: true,
    });
    this.#makeRoom();

    const id = String(this.randomAttemptId());
    requireCondition(ATTEMPT_ID.test(id), "randomAttemptId must return 128-bit lowercase hex");
    const now = this.now();
    const offerIssuedAtSeconds = Math.floor(now / 1000);
    const tokenExpiresAt = (offerIssuedAtSeconds + Math.floor(this.ttlMs / 1000)) * 1000;
    // A responder is allowed to consume the configured codec clock tolerance,
    // so the initiator must remain available over that same local horizon.
    const signallingDeadline = Math.min(now + this.ttlMs + this.verificationClockSkewMs,
      tokenExpiresAt + this.verificationClockSkewMs);
    const attempt = createAttempt({
      attemptId: id,
      contextId: this.contextId,
      localId: this.localId,
      peerId,
      role: ATTEMPT_ROLE.OFFERER,
      profile,
      createdAt: now,
      offerIssuedAtSeconds,
      ttlMs: this.ttlMs,
      tokenExpiresAt,
      signallingDeadline,
      publishDeadline: tokenExpiresAt,
    });
    this.#store(attempt);
    return this.dispatch(peerId, id, { type: ATTEMPT_EVENT.START });
  }

  /**
   * Accept an envelope only after the canonical codec has authenticated it.
   * A new inbound attempt can be created solely by a correctly addressed offer.
   */
  receiveVerified({ token: envelope, receipt }) {
    requireCondition(envelope && receipt, "verified token and relay receipt are required");
    const now = this.now();
    this.#validateEnvelopeRoute(envelope, now);
    this.#validateReceipt(envelope, receipt);
    const key = attemptKey(envelope.from, envelope.attemptId);
    let attempt = this.attempts.get(key);

    if (!attempt && this.replayTombstones.has(key)) {
      return this.#discardReceiptOutcome(this.activeAttempt(envelope.from), receipt,
        "replayed terminal rendezvous attempt");
    }

    if (!attempt) {
      if (now < this.replaySaturatedUntil) {
        this.#saturateReplay(envelope.expiresAtSeconds * 1000
          + this.verificationClockSkewMs + this.replaySkewMs);
        return this.#discardReceiptOutcome(this.activeAttempt(envelope.from), receipt,
          "unknown rendezvous attempts are temporarily fail-closed");
      }
      if (envelope.role !== SLOT_ROLE.OFFER) {
        this.#rememberRejected(envelope);
        return this.#discardReceiptOutcome(this.activeAttempt(envelope.from), receipt,
          "unknown non-offer rendezvous attempt");
      }
      const active = this.activeAttempt(envelope.from);
      if (active) {
        if (!this.#incomingOfferWins(active, envelope)) {
          this.#rememberRejected(envelope);
          return this.#discardReceiptOutcome(active, receipt, "losing glare offer");
        }
        if (!this.#hasReplayCapacity()) {
          this.#rememberRejected(envelope);
          return this.#discardReceiptOutcome(active, receipt,
            "replay protection capacity cannot retain the replaced attempt");
        }
        let prepared;
        try {
          prepared = this.#buildInboundAttempt(envelope, now);
        } catch (error) {
          this.#rememberRejected(envelope);
          return this.#discardReceiptOutcome(active, receipt,
            `rejected authenticated offer: ${String(error?.message || error)}`);
        }
        const winnerTransition = transitionVerifiedEnvelope(prepared, envelope, now, receipt);
        const loser = this.#acceptOutcome(transitionAttempt(active, {
          type: ATTEMPT_EVENT.ABORT,
          reason: "replaced by canonical glare winner",
        }, now));
        const winner = this.#acceptOutcome(winnerTransition);
        return this.#combineOutcomes(loser, winner);
      }
      let prepared;
      try {
        prepared = this.#buildInboundAttempt(envelope, now);
      } catch (error) {
        this.#rememberRejected(envelope);
        return this.#discardReceiptOutcome(null, receipt,
          `rejected authenticated offer: ${String(error?.message || error)}`);
      }
      try {
        this.#makeRoom();
      } catch (error) {
        this.#rememberRejected(envelope);
        return this.#discardReceiptOutcome(null, receipt,
          `rejected authenticated offer: ${String(error?.message || error)}`);
      }
      attempt = prepared;
    }

    const outcome = transitionVerifiedEnvelope(attempt, envelope, now, receipt);
    return this.#acceptOutcome(outcome);
  }

  async receiveWire(readResult, verify) {
    requireCondition(typeof verify === "function", "verify must be a function");
    requireCondition(readResult?.tokenBytes && readResult?.receipt,
      "rr2 data and its receipt are required");
    const envelope = await verify(readResult.tokenBytes, readResult.receipt);
    requireCondition(envelope, "rendezvous envelope authentication failed");
    return this.receiveVerified({ token: envelope, receipt: readResult.receipt });
  }

  dispatch(peerId, id, event) {
    this.#validatePeer(peerId);
    requireCondition(ATTEMPT_ID.test(String(id)), "invalid attempt id");
    const attempt = this.attempts.get(attemptKey(peerId, id));
    requireCondition(attempt, "unknown rendezvous attempt");
    const outcome = transitionAttempt(attempt, event, this.now());
    return this.#acceptOutcome(outcome);
  }

  activeAttempt(peerId) {
    const id = this.activeByPeer.get(peerId);
    if (!id) return null;
    const attempt = this.attempts.get(attemptKey(peerId, id));
    if (!attempt || isTerminalAttempt(attempt)) {
      this.activeByPeer.delete(peerId);
      return null;
    }
    return attempt;
  }

  authenticationProfileForPeer(peerId, direction = "sign") {
    this.#validatePeer(peerId);
    requireCondition(direction === "sign" || direction === "verify",
      "authentication profile direction must be sign or verify");
    const profile = this.profileForPeerPolicy(peerId, Object.freeze({ direction }));
    requireCondition(this.allowedProfiles.has(profile),
      "peer authentication profile is not allowed here");
    requireCondition(profile !== AUTH_PROFILE.BOOTSTRAP,
      "bootstrap requires its separate broadcast coordinator");
    return profile;
  }

  expire(at = this.now()) {
    const outcomes = [];
    for (const attempt of this.attempts.values()) {
      if (!isTerminalAttempt(attempt) && at >= attempt.completionDeadline) {
        outcomes.push(this.#acceptOutcome(transitionAttempt(attempt,
          { type: ATTEMPT_EVENT.EXPIRE }, at)));
      }
    }
    this.prune(at);
    return outcomes;
  }

  prune(at = this.now()) {
    let changed = false;
    if (this.replaySaturatedUntil && at >= this.replaySaturatedUntil) {
      this.replaySaturatedUntil = 0;
      changed = true;
    }
    for (const [key, attempt] of this.attempts) {
      const tombstone = this.replayTombstones.get(key);
      if (isTerminalAttempt(attempt) && tombstone && at >= tombstone.expiresAt) {
        this.attempts.delete(key);
        this.replayTombstones.delete(key);
        changed = true;
      } else if (isTerminalAttempt(attempt) && !tombstone
          && at >= attempt.tokenExpiresAt + this.verificationClockSkewMs + this.replaySkewMs) {
        // A terminal attempt itself remains an exact replay guard if a caller
        // restored old state without its tombstone. It is safe to discard only
        // once every token for that attempt is outside the accepted skew.
        this.attempts.delete(key);
        changed = true;
      }
    }
    for (const [key, tombstone] of this.replayTombstones) {
      if (at >= tombstone.expiresAt && !this.attempts.has(key)) {
        this.replayTombstones.delete(key);
        changed = true;
      }
    }
    for (const [peerId, id] of this.activeByPeer) {
      const attempt = this.attempts.get(attemptKey(peerId, id));
      if (!attempt || isTerminalAttempt(attempt)) this.activeByPeer.delete(peerId);
    }
    if (changed) this.#tombstonesChanged();
  }

  exportReplayTombstones() {
    return Object.freeze([...this.replayTombstones.entries()].map(([key, value]) => {
      const [peerId, attemptId] = key.split(":");
      return Object.freeze({ peerId, attemptId, expiresAt: value.expiresAt });
    }));
  }

  exportReplayState() {
    return Object.freeze({
      tombstones: this.exportReplayTombstones(),
      saturatedUntil: this.replaySaturatedUntil,
    });
  }

  restoreReplayTombstones(entries) {
    requireCondition(Array.isArray(entries), "initial replay tombstones must be an array");
    const now = this.now();
    const maximum = now + 300_000
      + (2 * this.verificationClockSkewMs) + this.replaySkewMs;
    const candidates = entries
      .filter(entry => entry && DEVICE_ID.test(String(entry.peerId))
        && entry.peerId !== this.localId && ATTEMPT_ID.test(String(entry.attemptId))
        && Number.isSafeInteger(entry.expiresAt)
        && entry.expiresAt > now && entry.expiresAt <= maximum)
      .sort((left, right) => left.expiresAt - right.expiresAt);
    const accepted = candidates.slice(0, this.maxReplayTombstones);
    for (const entry of accepted) {
      this.replayTombstones.set(attemptKey(entry.peerId, entry.attemptId),
        Object.freeze({ expiresAt: entry.expiresAt }));
    }
    if (candidates.length > accepted.length) {
      this.#saturateReplay(candidates[candidates.length - 1].expiresAt);
    }
    this.#tombstonesChanged();
  }

  noteFailure(peerId, at = this.now()) {
    this.#validatePeer(peerId);
    this.failures.set(peerId, at);
    if (this.failures.size > 128) {
      const oldest = [...this.failures.entries()]
        .sort((left, right) => left[1] - right[1])
        .slice(0, this.failures.size - 96);
      for (const [id] of oldest) this.failures.delete(id);
    }
  }

  chooseListener(componentMembers, staleAfterMs = 45_000) {
    return electRepairListener(componentMembers, this.now(), staleAfterMs);
  }

  chooseTargets(knownMembers, componentIds) {
    const decorated = (Array.isArray(knownMembers) ? knownMembers : [])
      .filter(member => member?.id !== this.localId)
      .map(member => ({
        ...member,
        failedAt: this.failures.get(member?.id) || 0,
      }));
    return rankRepairTargets(decorated, componentIds, this.now());
  }

  snapshot() {
    return Object.freeze({
      protocol: RENDEZVOUS_V2_PROTOCOL,
      localId: this.localId,
      contextId: this.contextId,
      attempts: Object.freeze([...this.attempts.values()]),
      activePeers: Object.freeze([...this.activeByPeer.keys()]),
      replayTombstones: this.replayTombstones.size,
      replaySaturatedUntil: this.replaySaturatedUntil,
    });
  }

  #acceptOutcome(outcome) {
    this.#store(outcome.attempt);
    if (isTerminalAttempt(outcome.attempt)) {
      if (this.activeByPeer.get(outcome.attempt.peerId) === outcome.attempt.attemptId) {
        this.activeByPeer.delete(outcome.attempt.peerId);
      }
      this.#rememberReplay(outcome.attempt.peerId, outcome.attempt.attemptId,
        outcome.attempt.tokenExpiresAt + this.verificationClockSkewMs + this.replaySkewMs);
      if (outcome.attempt.state !== "open"
          && !this.activeByPeer.has(outcome.attempt.peerId)) {
        this.noteFailure(outcome.attempt.peerId);
      }
    }
    return outcome;
  }

  #store(attempt) {
    this.attempts.set(attemptKey(attempt.peerId, attempt.attemptId), attempt);
    if (!isTerminalAttempt(attempt)) this.activeByPeer.set(attempt.peerId, attempt.attemptId);
  }

  #makeRoom() {
    this.prune();
    if (this.now() < this.replaySaturatedUntil) {
      throw new Error("rendezvous replay protection is temporarily fail-closed");
    }
    if (!this.#hasReplayCapacity()) {
      throw new Error("rendezvous replay-tombstone capacity reached");
    }
    const active = this.#activeCount();
    if (active >= this.maxActiveAttempts) throw new Error("rendezvous active-attempt limit reached");
  }

  #buildInboundAttempt(envelope, now) {
    const timing = this.#inboundTiming(envelope, now);
    return createAttempt({
      attemptId: envelope.attemptId,
      contextId: this.contextId,
      localId: this.localId,
      peerId: envelope.from,
      role: ATTEMPT_ROLE.ANSWERER,
      profile: envelope.profile,
      createdAt: now,
      offerIssuedAtSeconds: envelope.issuedAt,
      ttlMs: timing.ttlMs,
      tokenExpiresAt: envelope.expiresAtSeconds * 1000,
      signallingDeadline: timing.signallingDeadline,
      publishDeadline: timing.signallingDeadline,
    });
  }

  #incomingOfferWins(active, envelope) {
    // Later signed offers recover a peer that reloaded while the other side
    // still retained its old attempt. For concurrent offers, both peers see
    // the same signed issue times and canonical tuple and choose one winner.
    if (envelope.issuedAt !== active.offerIssuedAtSeconds) {
      return envelope.issuedAt > active.offerIssuedAtSeconds;
    }
    const activeOfferer = active.role === ATTEMPT_ROLE.OFFERER ? active.localId : active.peerId;
    return `${envelope.from}:${envelope.attemptId}`
      < `${activeOfferer}:${active.attemptId}`;
  }

  #combineOutcomes(first, second) {
    return Object.freeze({
      attempt: second.attempt,
      effects: Object.freeze([...first.effects, ...second.effects]),
      disposition: second.disposition,
      ignored: second.ignored,
      replacedAttempt: first.attempt,
    });
  }

  #discardReceiptOutcome(attempt, receipt, reason) {
    return Object.freeze({
      attempt,
      effects: Object.freeze([Object.freeze({
        type: ATTEMPT_EFFECT.ABORT_REMOTE_SLOT,
        attemptId: receipt.attemptId,
        contextId: this.contextId,
        receipt: Object.freeze({ ...receipt }),
        reason,
      })]),
      disposition: ATTEMPT_DISPOSITION.INVALID,
      ignored: false,
    });
  }

  #rememberReplay(peerId, id, expiresAt) {
    const key = attemptKey(peerId, id);
    const current = this.replayTombstones.get(key);
    if (current) {
      if (expiresAt > current.expiresAt) {
        this.replayTombstones.set(key, Object.freeze({ expiresAt }));
        this.#tombstonesChanged();
      }
      return;
    }
    this.prune(this.now());
    // Every admitted active attempt reserves one tombstone. Reaching this
    // branch without room therefore means state was restored inconsistently;
    // retain the terminal attempt itself and fail closed for unknown IDs.
    if (this.replayTombstones.size >= this.maxReplayTombstones) {
      this.#saturateReplay(expiresAt);
      return false;
    }
    this.replayTombstones.set(key, Object.freeze({ expiresAt }));
    this.#tombstonesChanged();
    return true;
  }

  #rememberRejected(envelope) {
    const expiresAt = envelope.expiresAtSeconds * 1000
      + this.verificationClockSkewMs + this.replaySkewMs;
    if (this.#hasReplayCapacity()) {
      this.#rememberReplay(envelope.from, envelope.attemptId, expiresAt);
    } else {
      // Never evict a still-live replay guard merely to remember a different
      // rejected token. Quarantine every unknown attempt until the rejected
      // token is stale; existing known attempts continue normally.
      this.#saturateReplay(expiresAt);
    }
  }

  #saturateReplay(expiresAt) {
    if (expiresAt <= this.replaySaturatedUntil) return;
    this.replaySaturatedUntil = expiresAt;
    this.#tombstonesChanged();
  }

  #activeCount() {
    let count = 0;
    for (const attempt of this.attempts.values()) {
      if (!isTerminalAttempt(attempt)) count += 1;
    }
    return count;
  }

  #hasReplayCapacity() {
    return this.replayTombstones.size + this.#activeCount()
      < this.maxReplayTombstones;
  }

  #tombstonesChanged() {
    try {
      this.onReplayTombstonesChanged(this.exportReplayTombstones(), Object.freeze({
        saturatedUntil: this.replaySaturatedUntil,
      }));
    } catch {}
  }

  #validateReceipt(envelope, receipt) {
    requireCondition(receipt && receipt.attemptId === envelope.attemptId,
      "relay receipt attempt disagrees with authenticated token");
    requireCondition(receipt.from === envelope.from && receipt.to === envelope.to,
      "relay receipt route disagrees with authenticated token");
    requireCondition(receipt.role === envelope.role || receipt.role === SLOT_WIRE_ROLE[envelope.role],
      "relay receipt role disagrees with authenticated token");
    requireCondition(Number.isSafeInteger(receipt.revision) && receipt.revision >= 1,
      "relay receipt has an invalid revision");
  }

  #validatePeer(peerId) {
    requireCondition(DEVICE_ID.test(String(peerId)), "invalid peer device id");
    requireCondition(peerId !== this.localId, "local device cannot be its own peer");
  }

  #validateEnvelopeRoute(envelope, now) {
    requireCondition(envelope && envelope.version === 2,
      "wrong rendezvous protocol version");
    requireCondition(ATTEMPT_ID.test(String(envelope.attemptId)), "invalid envelope attempt id");
    requireCondition(envelope.contextId === this.contextId, "wrong rendezvous context");
    this.#validatePeer(envelope.from);
    const boundAttempt = this.attempts.get(attemptKey(envelope.from, envelope.attemptId));
    const expectedProfile = boundAttempt?.profile
      || this.authenticationProfileForPeer(envelope.from, "verify");
    requireCondition(envelope.profile === expectedProfile,
      "wrong authentication profile for this peer");
    requireCondition(envelope.to === this.localId, "wrong rendezvous recipient");
    requireCondition(Number.isSafeInteger(envelope.issuedAt), "rendezvous envelope has no issue time");
    requireCondition(Number.isSafeInteger(envelope.expiresAtSeconds), "rendezvous envelope has no expiry");
    requireCondition(now < envelope.expiresAtSeconds * 1000 + this.verificationClockSkewMs,
      "rendezvous envelope expired outside the configured clock tolerance");
  }

  #inboundTiming(envelope, now) {
    // Clock tolerance permits authentication; it is not usable responder
    // lifetime. In the worst allowed relative skew, raw signed expiry is the
    // latest local point guaranteed not to outlive the offerer's verifier.
    const signallingDeadline = Math.min(now + this.ttlMs,
      envelope.expiresAtSeconds * 1000);
    const remaining = signallingDeadline - now;
    requireCondition(remaining >= this.minimumInboundBudgetMs,
      "rendezvous offer has too little authenticated lifetime remaining");
    return Object.freeze({ ttlMs: remaining, signallingDeadline });
  }
}

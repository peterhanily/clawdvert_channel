/*
 * Ordered browser adapter for the dormant rendezvous V2 modules.
 *
 * This is the only layer that performs WebRTC operations. Every state-machine
 * effect is awaited in order. Public events are serialized, so a channel-open
 * callback cannot overtake an in-flight slot PUT and recreate state after
 * cleanup. The live single-file client does not import this module yet.
 */

import {
  RENDEZVOUS_V2,
  encodeAndSignRendezvousV2Bytes,
  measureRendezvousV2Token,
  verifyAndDecodeRendezvousV2Bytes,
} from "./rendezvous-v2-codec.js";
import {
  addRendezvousCandidates,
  buildRendezvousDataChannelSdp,
  extractRendezvousIce,
  selectRendezvousCandidates,
} from "./rendezvous-v2-sdp.js";
import {
  ATTEMPT_EFFECT,
  ATTEMPT_EVENT,
  ATTEMPT_ROLE,
  ATTEMPT_STATE,
  AUTH_PROFILE,
  SLOT_ROLE,
  isTerminalAttempt,
} from "./rendezvous-v2-state.js";

const WIRE_ROLE = Object.freeze({
  o: SLOT_ROLE.OFFER,
  a: SLOT_ROLE.ANSWER,
  n: SLOT_ROLE.NEED_CANDIDATE,
  c: SLOT_ROLE.CANDIDATE,
  x: SLOT_ROLE.ABORT,
});

function requireCondition(condition, message) {
  if (!condition) throw new TypeError(message);
}

function defaultWaitForIce(peerConnection, { timeoutMs = 20_000, signal } = {}) {
  if (peerConnection.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      peerConnection.removeEventListener("icegatheringstatechange", changed);
      signal?.removeEventListener?.("abort", aborted);
      resolve();
    };
    const changed = () => {
      if (peerConnection.iceGatheringState === "complete") finish();
    };
    const aborted = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      peerConnection.removeEventListener("icegatheringstatechange", changed);
      reject(signal.reason || new Error("ICE gathering aborted"));
    };
    const timer = setTimeout(finish, timeoutMs);
    peerConnection.addEventListener("icegatheringstatechange", changed);
    signal?.addEventListener?.("abort", aborted, { once: true });
    if (signal?.aborted) aborted();
  });
}

function connectionKey(attempt) {
  return `${attempt.peerId}:${attempt.attemptId}`;
}

export class RendezvousV2BrowserAdapter {
  constructor({
    coordinator,
    transport,
    createPeerConnection,
    keyProvider,
    authenticateChannel,
    waitForIce = defaultWaitForIce,
    onDataChannel = () => {},
    onTerminal = () => {},
    onError = () => {},
    dataChannelLabel = "clawdvert-v2",
    allowHostCandidates = false,
    pollDelayMs = 1000,
    connectivityTimeoutMs = 55_000,
    iceGatherTimeoutMs = 20_000,
    peerConnectionTimeoutMs = 10_000,
    rtcOperationTimeoutMs = 10_000,
    keyLookupTimeoutMs = 2_000,
    cryptoOperationTimeoutMs = 2_000,
    authenticateTimeoutMs = 12_000,
    putRetries = 1,
    maxQueuedEvents = 64,
    subtle,
  }) {
    requireCondition(coordinator && ["start", "activeAttempt", "dispatch"]
      .every(method => typeof coordinator[method] === "function")
      && coordinator.attempts instanceof Map
      && coordinator.allowedProfiles instanceof Set
      && typeof coordinator.authenticationProfileForPeer === "function"
      && typeof coordinator.now === "function"
      && Number.isSafeInteger(coordinator.maxActiveAttempts),
    "a complete rendezvous coordinator is required");
    requireCondition(transport && ["put", "get", "discover", "ack", "abort",
      "clearOwnedAttempt", "forgetAttempt", "close", "isolatedReadBudgetForTokenBytes"]
      .every(method => typeof transport[method] === "function"),
    "a complete slot transport is required");
    requireCondition(Number.isSafeInteger(transport.exchangeCapacity)
      && Number.isSafeInteger(transport.exchangeHighPriorityReserve)
      && transport.exchangeHighPriorityReserve >= coordinator.maxActiveAttempts
      && Number.isSafeInteger(transport.exchangeNormalCapacity)
      && transport.exchangeNormalCapacity >= coordinator.maxActiveAttempts + 2,
    "slot transport must reserve bounded critical writes plus one read per active peer");
    requireCondition(typeof createPeerConnection === "function", "createPeerConnection is required");
    requireCondition(typeof keyProvider === "function", "keyProvider is required");
    requireCondition(typeof authenticateChannel === "function",
      "authenticateChannel is required before room data can be accepted");
    requireCondition(typeof waitForIce === "function", "waitForIce must be a function");
    requireCondition(Number.isSafeInteger(pollDelayMs) && pollDelayMs >= 250 && pollDelayMs <= 1_000,
      "established-room pollDelayMs must be 250-1000");
    requireCondition(Number.isSafeInteger(connectivityTimeoutMs)
      && connectivityTimeoutMs >= 15_000 && connectivityTimeoutMs <= 120_000,
    "connectivityTimeoutMs is outside the supported range");
    requireCondition(Number.isSafeInteger(iceGatherTimeoutMs)
      && iceGatherTimeoutMs >= 5_000 && iceGatherTimeoutMs <= 30_000,
    "iceGatherTimeoutMs is outside the supported range");
    requireCondition(Number.isSafeInteger(peerConnectionTimeoutMs)
      && peerConnectionTimeoutMs >= 1_000 && peerConnectionTimeoutMs <= 30_000,
    "peerConnectionTimeoutMs is outside the supported range");
    requireCondition(Number.isSafeInteger(rtcOperationTimeoutMs)
      && rtcOperationTimeoutMs >= 1_000 && rtcOperationTimeoutMs <= 30_000,
    "rtcOperationTimeoutMs is outside the supported range");
    requireCondition(Number.isSafeInteger(keyLookupTimeoutMs)
      && keyLookupTimeoutMs >= 1_000 && keyLookupTimeoutMs <= 2_000,
    "established-room keyLookupTimeoutMs must be 1000-2000");
    requireCondition(Number.isSafeInteger(cryptoOperationTimeoutMs)
      && cryptoOperationTimeoutMs >= 1_000 && cryptoOperationTimeoutMs <= 2_000,
    "established-room cryptoOperationTimeoutMs must be 1000-2000");
    requireCondition(Number.isSafeInteger(putRetries) && putRetries >= 0 && putRetries <= 1,
      "putRetries must be zero or one");
    requireCondition(Number.isSafeInteger(transport.isolatedWriteBudgetMs)
      && transport.isolatedWriteBudgetMs >= 500,
    "slot transport must expose its bounded isolated write budget");
    const answerConsumptionBudgetMs = transport.isolatedReadBudgetForTokenBytes(207)
      + (2 * Math.ceil(pollDelayMs * 1.2))
      // One expected-role GET can already be in flight when the peer stores
      // its answer, followed by the worst-positioned signed-abort probe.
      + transport.isolatedWriteBudgetMs
      + transport.isolatedWriteBudgetMs
      + keyLookupTimeoutMs + cryptoOperationTimeoutMs
      + (2 * rtcOperationTimeoutMs);
    const normalCriticalPathMs = peerConnectionTimeoutMs
      + (3 * rtcOperationTimeoutMs) + iceGatherTimeoutMs + 1_000
      + keyLookupTimeoutMs + cryptoOperationTimeoutMs
      + ((putRetries + 1) * transport.isolatedWriteBudgetMs)
      + answerConsumptionBudgetMs
      + connectivityTimeoutMs + 15_000;
    requireCondition(coordinator.minimumInboundBudgetMs >= normalCriticalPathMs,
      "coordinator lifetime budget cannot cover bounded answer creation and connectivity");
    requireCondition(Number.isSafeInteger(authenticateTimeoutMs)
      && authenticateTimeoutMs >= 2_000 && authenticateTimeoutMs <= 30_000,
    "authenticateTimeoutMs is outside the supported range");
    requireCondition(Number.isSafeInteger(maxQueuedEvents)
      && maxQueuedEvents >= 8 && maxQueuedEvents <= 256,
    "maxQueuedEvents is outside the supported range");

    this.coordinator = coordinator;
    this.transport = transport;
    this.createPeerConnection = createPeerConnection;
    this.keyProvider = keyProvider;
    this.authenticateChannel = authenticateChannel;
    this.waitForIce = waitForIce;
    this.onDataChannel = onDataChannel;
    this.onTerminal = onTerminal;
    this.onError = onError;
    this.dataChannelLabel = dataChannelLabel;
    this.allowHostCandidates = Boolean(allowHostCandidates);
    this.pollDelayMs = pollDelayMs;
    this.connectivityTimeoutMs = connectivityTimeoutMs;
    this.iceGatherTimeoutMs = iceGatherTimeoutMs;
    this.peerConnectionTimeoutMs = peerConnectionTimeoutMs;
    this.rtcOperationTimeoutMs = rtcOperationTimeoutMs;
    this.keyLookupTimeoutMs = keyLookupTimeoutMs;
    this.cryptoOperationTimeoutMs = cryptoOperationTimeoutMs;
    this.isolatedWriteBudgetMs = transport.isolatedWriteBudgetMs;
    this.answerConsumptionBudgetMs = answerConsumptionBudgetMs;
    this.authenticateTimeoutMs = authenticateTimeoutMs;
    this.fallbackSignalBudgetMs = (4 * keyLookupTimeoutMs)
      + (4 * cryptoOperationTimeoutMs)
      + (2 * (putRetries + 1) * transport.isolatedWriteBudgetMs)
      + transport.isolatedReadBudgetForTokenBytes(RENDEZVOUS_V2.controlTokenBytes)
      + transport.isolatedReadBudgetForTokenBytes(RENDEZVOUS_V2.maxCandidateOnlyTokenBytes)
      // Each expected role can be preceded by the every-fourth signed-abort
      // probe and by an already-running empty expected-role GET.
      + (4 * Math.ceil(pollDelayMs * 1.2))
      + (2 * transport.isolatedWriteBudgetMs)
      + (2 * transport.isolatedWriteBudgetMs)
      + rtcOperationTimeoutMs + 5_000;
    this.putRetries = putRetries;
    this.maxQueuedEvents = maxQueuedEvents;
    this.subtle = subtle;
    this.connections = new Map();
    this.timers = new Map();
    this.queues = new Map();
    this.queuedEvents = 0;
    this.pendingPolls = new Map();
    this.controller = new AbortController();
    this.stopped = false;
  }

  start(peerId, profile) {
    return this.#enqueue(peerId, async () => {
      await this.#expirePeer(peerId);
      return this.#applySafely(this.coordinator.start(peerId, profile));
    });
  }

  receiveSlot(readResult) {
    requireCondition(readResult?.receipt?.from, "rr2 receipt is required");
    return this.#enqueueClaimed(readResult, async () => {
      await this.#expirePeer(readResult.receipt.from);
      return this.#receiveSlot(readResult);
    });
  }

  /** One latest-value discovery read; callers choose listener cadence. */
  discoverOffer(from = "0000000000000000") {
    return this.#enqueue("listener", async () => {
      const read = await this.transport.discover({
        from,
        to: this.coordinator.localId,
        attemptId: "0",
        role: SLOT_ROLE.OFFER,
      });
      if (read.status !== "data") return read;
      return this.#enqueueClaimed(read, async () => {
        await this.#expirePeer(read.receipt.from);
        return this.#receiveSlot(read);
      });
    });
  }

  poll(peerId, attemptId) {
    const key = `${peerId}:${attemptId}`;
    const existing = this.pendingPolls.get(key);
    if (existing) return existing;
    const task = this.#enqueue(peerId, async () => this.#pollAttempt(peerId, attemptId));
    this.pendingPolls.set(key, task);
    task.finally(() => this.pendingPolls.delete(key)).catch(() => {});
    return task;
  }

  notifyConnectivityTimeout(peerId, attemptId) {
    return this.#enqueue(peerId, async () => this.#applySafely(
      this.coordinator.dispatch(peerId, attemptId, { type: ATTEMPT_EVENT.CONNECTIVITY_TIMEOUT }),
    ));
  }

  async stop(reason = "rendezvous adapter stopped") {
    this.stopped = true;
    this.controller.abort(new Error(reason));
    this.transport.close?.();
    for (const timers of this.timers.values()) this.#clearTimerSet(timers);
    this.timers.clear();
    for (const entry of this.connections.values()) this.#closeEntry(entry, reason);
    this.connections.clear();
    await Promise.allSettled([...this.queues.values()]);
    for (const entry of this.connections.values()) this.#closeEntry(entry, reason);
    this.connections.clear();
  }

  #enqueue(key, operation, { critical = false } = {}) {
    const rejected = this.#queueRejection(critical);
    if (rejected) return Promise.reject(rejected);
    this.queuedEvents += 1;
    const previous = this.queues.get(key) || Promise.resolve();
    const task = previous.then(operation, operation);
    const tail = task.catch(() => {}).finally(() => {
      this.queuedEvents = Math.max(0, this.queuedEvents - 1);
      if (this.queues.get(key) === tail) this.queues.delete(key);
    });
    this.queues.set(key, tail);
    return task;
  }

  #enqueueClaimed(readResult, operation) {
    const rejected = this.#queueRejection(false);
    if (rejected) {
      this.transport.abort(readResult.receipt)
        .catch(error => this.#reportError(error,
          { phase: "claimed-slot-queue-cleanup", receipt: readResult.receipt }));
      return Promise.reject(rejected);
    }
    return this.#enqueue(readResult.receipt.from, operation);
  }

  #queueRejection(critical) {
    if (this.stopped) {
      const error = new Error("rendezvous adapter is stopped");
      error.code = "stopped";
      return error;
    }
    const criticalReserve = Math.min(32, this.coordinator.maxActiveAttempts || 12);
    const limit = this.maxQueuedEvents + (critical ? criticalReserve : 0);
    if (this.queuedEvents < limit) return null;
    const error = new Error("rendezvous adapter event queue is full");
    error.code = "queue-full";
    return error;
  }

  async #receiveSlot(readResult) {
    requireCondition(readResult?.status === "data" && readResult.tokenBytes && readResult.receipt,
      "a complete rr2 data result is required");
    let envelope;
    try {
      envelope = await this.#verifyToken(readResult);
    } catch (error) {
      // The transport selector is safe to use for cleanup even though token
      // claims are not. Abort the poisoned claimed slot so discovery can move
      // to another current value.
      await this.transport.abort(readResult.receipt).catch(() => {});
      this.#reportError(error, { phase: "verify", receipt: readResult.receipt });
      throw error;
    }
    let outcome;
    try {
      outcome = this.coordinator.receiveVerified({
        token: envelope,
        receipt: readResult.receipt,
      });
    } catch (error) {
      await this.transport.abort(readResult.receipt).catch(() => {});
      this.#reportError(error, { phase: "accept", receipt: readResult.receipt });
      throw error;
    }
    return this.#applySafely(outcome);
  }

  async #expirePeer(peerId) {
    const active = this.coordinator.activeAttempt(peerId);
    if (!active || this.coordinator.now() < active.completionDeadline) return;
    try {
      await this.#applySafely(this.coordinator.dispatch(peerId, active.attemptId, {
        type: ATTEMPT_EVENT.EXPIRE,
      }));
    } catch (error) {
      // Semantic expiry has already committed and ordered cleanup ran as far
      // as possible. A best-effort relay failure must not block a fresh repair.
      this.#reportError(error, { phase: "expiry-cleanup", attempt: active });
    }
  }

  async #verifyToken(readResult) {
    const receipt = readResult.receipt;
    const expectedRole = WIRE_ROLE[receipt.role];
    requireCondition(expectedRole, "rr2 receipt has an unknown role");
    const boundAttempt = this.coordinator.attempts.get(
      `${receipt.from}:${receipt.attemptId}`,
    );
    const profile = boundAttempt?.profile
      || this.coordinator.authenticationProfileForPeer(receipt.from, "verify");
    const key = await this.#awaitOperation(this.keyProvider({
      peerId: receipt.from,
      profile,
      direction: "verify",
      signal: this.controller.signal,
    }), "verification key lookup", this.keyLookupTimeoutMs);
    return this.#awaitOperation(verifyAndDecodeRendezvousV2Bytes(readResult.tokenBytes, key, {
      subtle: this.subtle,
      nowSeconds: Math.floor(this.coordinator.now() / 1000),
      maxClockSkewSeconds: this.coordinator.verificationClockSkewMs / 1000,
      expectedProfile: profile,
      expectedRole,
      expectedAttemptId: receipt.attemptId,
      expectedContextId: this.coordinator.contextId,
      expectedFrom: receipt.from,
      expectedTo: receipt.to,
    }), "rendezvous token authentication", this.cryptoOperationTimeoutMs);
  }

  async #applySafely(outcome) {
    try {
      return await this.#applyOutcome(outcome);
    } catch (error) {
      const attempt = outcome?.attempt;
      this.#reportError(error, { phase: "effect", attempt });
      if (attempt && !isTerminalAttempt(this.#currentAttempt(attempt) || attempt)) {
        try {
          const failed = this.coordinator.dispatch(attempt.peerId, attempt.attemptId, {
            type: ATTEMPT_EVENT.FAIL,
            reason: String(error?.message || error),
          });
          await this.#applyOutcome(failed);
        } catch (terminalError) {
          const entry = this.connections.get(connectionKey(attempt));
          if (entry) this.#closeEntry(entry, "terminal cleanup failed");
          this.#reportError(terminalError, { phase: "terminal-cleanup", attempt });
        }
      }
      throw error;
    }
  }

  async #applyOutcome(outcome) {
    requireCondition(outcome && Array.isArray(outcome.effects), "invalid state-machine outcome");
    const errors = [];
    try {
      if (outcome.attempt && isTerminalAttempt(outcome.attempt)) {
        for (const effect of outcome.effects) {
          try { await this.#executeEffect(effect); } catch (error) { errors.push(error); }
        }
      } else {
        for (const effect of outcome.effects) await this.#executeEffect(effect);
      }
    } finally {
      for (const represented of [outcome.attempt, outcome.replacedAttempt]) {
        const current = represented ? this.#currentAttempt(represented) : null;
        if (current) this.#syncTimers(current);
      }
    }
    if (errors.length) throw new AggregateError(errors, "rendezvous terminal cleanup was incomplete");
    return outcome;
  }

  async #executeEffect(effect) {
    if (effect.type === ATTEMPT_EFFECT.ACK_REMOTE_SLOT) {
      try { return await this.transport.ack(effect.receipt); }
      catch (error) { this.#reportError(error, { phase: "slot-ack", receipt: effect.receipt }); return undefined; }
    }
    if (effect.type === ATTEMPT_EFFECT.ABORT_REMOTE_SLOT) {
      try { return await this.transport.abort(effect.receipt); }
      catch (error) { this.#reportError(error, { phase: "slot-abort", receipt: effect.receipt }); return undefined; }
    }
    const attempt = this.#attemptForEffect(effect);
    switch (effect.type) {
      case ATTEMPT_EFFECT.CREATE_OFFER:
        return this.#createOffer(attempt);
      case ATTEMPT_EFFECT.APPLY_OFFER:
        return this.#applyOffer(attempt, effect.envelope);
      case ATTEMPT_EFFECT.CREATE_ANSWER:
        return this.#createAnswer(attempt);
      case ATTEMPT_EFFECT.APPLY_ANSWER:
        return this.#applyAnswer(attempt, effect.envelope);
      case ATTEMPT_EFFECT.CREATE_FALLBACK:
        return this.#createFallback(attempt);
      case ATTEMPT_EFFECT.APPLY_FALLBACK:
        return this.#applyFallback(attempt, effect.envelope);
      case ATTEMPT_EFFECT.PUT_SLOT:
        if (effect.slotRole !== SLOT_ROLE.ABORT) return this.#putSlot(attempt, effect);
        try { return await this.#putSlot(attempt, effect); }
        catch (error) {
          this.#reportError(error, { phase: "signed-abort-publish", attempt });
          return undefined;
        }
      case ATTEMPT_EFFECT.CLEAR_LOCAL:
        try {
          return await this.transport.clearOwnedAttempt({
            from: attempt.localId,
            to: attempt.peerId,
            attemptId: effect.attemptId,
          });
        }
        catch (error) {
          this.#reportError(error, { phase: "local-slot-cleanup", attempt });
          return undefined;
        }
      case ATTEMPT_EFFECT.CLOSE_CONNECTION: {
        const entry = this.connections.get(connectionKey(attempt));
        if (entry) this.#closeEntry(entry, effect.reason);
        return undefined;
      }
      case ATTEMPT_EFFECT.RECORD_TERMINAL:
        this.transport.forgetAttempt({
          from: attempt.localId,
          to: attempt.peerId,
          attemptId: attempt.attemptId,
        });
        this.#syncTimers(attempt);
        try { this.onTerminal(attempt, { state: effect.state, reason: effect.reason }); }
        catch (error) { this.#reportError(error, { phase: "terminal-observer", attempt }); }
        return undefined;
      default:
        throw new Error(`unknown rendezvous effect ${effect.type}`);
    }
  }

  async #createOffer(attempt) {
    const entry = await this.#ensureConnection(attempt);
    if (!entry.channel) {
      entry.channel = entry.pc.createDataChannel(this.dataChannelLabel, { ordered: true });
      this.#bindChannel(attempt, entry, entry.channel);
    }
    const offer = await this.#awaitOperation(entry.pc.createOffer(),
      "create rendezvous offer", this.rtcOperationTimeoutMs);
    await this.#awaitOperation(entry.pc.setLocalDescription(offer),
      "set local rendezvous offer", this.rtcOperationTimeoutMs);
    await this.#awaitOperation(this.waitForIce(entry.pc,
      { timeoutMs: this.iceGatherTimeoutMs, signal: this.controller.signal }),
    "ICE gathering", this.iceGatherTimeoutMs + 1_000);
    const sdp = entry.pc.localDescription?.sdp;
    const ice = extractRendezvousIce(sdp);
    entry.localCandidates = selectRendezvousCandidates(sdp, {
      allowHost: this.allowHostCandidates,
      maxCandidates: 2,
    });
    // WebRTC preparation is bounded separately and is not part of the signed
    // token lifetime. Start the authenticated 300-second epoch only after the
    // gathered offer material exists, immediately before key lookup/signing.
    const timed = await this.#applyOutcome(this.coordinator.dispatch(
      attempt.peerId, attempt.attemptId, {
        type: ATTEMPT_EVENT.OUTBOUND_TOKEN_STARTED,
      }));
    const publishingAttempt = timed.attempt;
    const payload = await this.#signToken(publishingAttempt,
      { role: SLOT_ROLE.OFFER, ice, candidates: [] });
    return this.#applyOutcome(this.coordinator.dispatch(
      publishingAttempt.peerId, publishingAttempt.attemptId, {
        type: ATTEMPT_EVENT.LOCAL_OFFER_READY,
        payload,
      }));
  }

  async #applyOffer(attempt, envelope) {
    const entry = await this.#ensureConnection(attempt);
    entry.remoteFingerprint = envelope.ice.fingerprint;
    await this.#awaitOperation(entry.pc.setRemoteDescription({
      type: "offer",
      sdp: buildRendezvousDataChannelSdp({ type: "offer", ice: envelope.ice }),
    }), "set remote rendezvous offer", this.rtcOperationTimeoutMs);
    return this.#applyOutcome(this.coordinator.dispatch(attempt.peerId, attempt.attemptId, {
      type: ATTEMPT_EVENT.REMOTE_DESCRIPTION_APPLIED,
    }));
  }

  async #createAnswer(attempt) {
    const entry = this.#requireConnection(attempt);
    const answer = await this.#awaitOperation(entry.pc.createAnswer(),
      "create rendezvous answer", this.rtcOperationTimeoutMs);
    await this.#awaitOperation(entry.pc.setLocalDescription(answer),
      "set local rendezvous answer", this.rtcOperationTimeoutMs);
    await this.#awaitOperation(this.waitForIce(entry.pc,
      { timeoutMs: this.iceGatherTimeoutMs, signal: this.controller.signal }),
    "ICE gathering", this.iceGatherTimeoutMs + 1_000);
    const sdp = entry.pc.localDescription?.sdp;
    const ice = extractRendezvousIce(sdp);
    entry.localCandidates = selectRendezvousCandidates(sdp, {
      allowHost: this.allowHostCandidates,
      maxCandidates: 2,
    });
    requireCondition(entry.localCandidates.length > 0,
      "the answerer gathered no representable rendezvous candidate");
    const payload = await this.#signToken(attempt, {
      role: SLOT_ROLE.ANSWER,
      ice,
      candidates: entry.localCandidates,
    });
    return this.#applyOutcome(this.coordinator.dispatch(attempt.peerId, attempt.attemptId, {
      type: ATTEMPT_EVENT.LOCAL_ANSWER_READY,
      payload,
    }));
  }

  async #applyAnswer(attempt, envelope) {
    const entry = this.#requireConnection(attempt);
    entry.remoteFingerprint = envelope.ice.fingerprint;
    await this.#awaitOperation(entry.pc.setRemoteDescription({
      type: "answer",
      sdp: buildRendezvousDataChannelSdp({ type: "answer", ice: envelope.ice }),
    }), "set remote rendezvous answer", this.rtcOperationTimeoutMs);
    await this.#awaitOperation(addRendezvousCandidates(entry.pc, envelope.candidates),
      "add rendezvous answer candidates", this.rtcOperationTimeoutMs);
    return this.#applyOutcome(this.coordinator.dispatch(attempt.peerId, attempt.attemptId, {
      type: ATTEMPT_EVENT.REMOTE_DESCRIPTION_APPLIED,
    }));
  }

  async #createFallback(attempt) {
    const entry = this.#requireConnection(attempt);
    requireCondition(entry.localCandidates?.length,
      "the offerer has no representable fallback candidate");
    const payload = await this.#signToken(attempt, {
      role: SLOT_ROLE.CANDIDATE,
      referenceRole: SLOT_ROLE.NEED_CANDIDATE,
      candidates: entry.localCandidates,
    });
    return this.#applyOutcome(this.coordinator.dispatch(attempt.peerId, attempt.attemptId, {
      type: ATTEMPT_EVENT.LOCAL_FALLBACK_READY,
      payload,
    }));
  }

  async #applyFallback(attempt, envelope) {
    const entry = this.#requireConnection(attempt);
    await this.#awaitOperation(addRendezvousCandidates(entry.pc, envelope.candidates),
      "add rendezvous fallback candidates", this.rtcOperationTimeoutMs);
    return this.#applyOutcome(this.coordinator.dispatch(attempt.peerId, attempt.attemptId, {
      type: ATTEMPT_EVENT.REMOTE_FALLBACK_APPLIED,
    }));
  }

  async #putSlot(attempt, effect) {
    let payload = effect.payload;
    if (!(payload instanceof Uint8Array)) {
      if (effect.slotRole === SLOT_ROLE.NEED_CANDIDATE) {
        payload = await this.#signToken(attempt, {
          role: SLOT_ROLE.NEED_CANDIDATE,
          referenceRole: SLOT_ROLE.OFFER,
          candidates: [],
        });
      } else if (effect.slotRole === SLOT_ROLE.ABORT) {
        payload = await this.#signToken(attempt, {
          role: SLOT_ROLE.ABORT,
          referenceRole: effect.payload?.referenceRole || SLOT_ROLE.OFFER,
          candidates: [],
        });
      } else {
        throw new Error(`slot ${effect.slotRole} has no authenticated payload`);
      }
    }
    let stored;
    let lastError;
    for (let retry = 0; retry <= this.putRetries; retry += 1) {
      try {
        const publicationDeadline = this.#publicationDeadline(attempt, effect.slotRole);
        const remainingWrites = this.putRetries - retry + 1;
        const allocationDeadline = publicationDeadline
          - (remainingWrites * this.isolatedWriteBudgetMs);
        requireCondition(this.coordinator.now() < allocationDeadline,
          "attempt has too little signalling lifetime for a bounded slot publication");
        stored = await this.transport.put({
          from: attempt.localId,
          to: attempt.peerId,
          attemptId: attempt.attemptId,
          role: effect.slotRole,
          tokenBytes: payload,
          revision: 0,
          deadline: allocationDeadline,
        });
        break;
      } catch (error) {
        lastError = error;
        if (error?.code && error.code !== "internal") break;
      }
    }
    if (!stored) throw lastError || new Error("rendezvous slot write failed");
    const timers = this.timers.get(connectionKey(attempt));
    if (timers) timers.pollFailures = 0;
    return this.#applyOutcome(this.coordinator.dispatch(attempt.peerId, attempt.attemptId, {
      type: ATTEMPT_EVENT.SLOT_STORED,
      slotRole: effect.slotRole,
      receipt: stored.receipt,
    }));
  }

  async #signToken(attempt, { role, referenceRole = null, ice = null, candidates = [] }) {
    const publicationDeadline = this.#publicationDeadline(attempt, role);
    requireCondition(this.coordinator.now() < publicationDeadline,
      "attempt signalling lifetime ended before token creation");
    const issuedAt = attempt.offerIssuedAtSeconds;
    const lifetimeSeconds = (attempt.tokenExpiresAt / 1000) - issuedAt;
    requireCondition(Number.isSafeInteger(lifetimeSeconds)
      && lifetimeSeconds >= 15 && lifetimeSeconds <= 300, "attempt token lifetime is invalid");
    const tokenBase = {
      version: 2,
      profile: attempt.profile,
      role,
      referenceRole,
      issuedAt,
      lifetimeSeconds,
      attemptId: attempt.attemptId,
      contextId: attempt.contextId,
      from: attempt.localId,
      to: attempt.peerId,
      ice,
    };
    const sourceCandidates = [...candidates];
    const variants = [sourceCandidates];
    if (sourceCandidates.length > 1) {
      for (const candidate of sourceCandidates) variants.push([candidate]);
    }
    let token = null;
    let sizeError = null;
    for (const variant of variants) {
      try {
        const candidateToken = { ...tokenBase, candidates: variant };
        const measurement = measureRendezvousV2Token(candidateToken);
        if (role === SLOT_ROLE.OFFER
            && measurement.tokenBytes > RENDEZVOUS_V2.maxOfferTokenBytes) {
          const error = new Error("offer exceeds the established discovery-time budget");
          error.code = "TOKEN_TOO_LARGE";
          throw error;
        }
        token = candidateToken;
        break;
      } catch (error) {
        if (error?.code !== "TOKEN_TOO_LARGE") throw error;
        sizeError = error;
      }
    }
    if (!token) {
      if (role === SLOT_ROLE.OFFER) {
        throw new Error("ICE credentials exceed the established compact offer budget",
          { cause: sizeError });
      }
      throw new Error("ICE credentials and the required candidate exceed the compact token budget",
        { cause: sizeError });
    }
    const key = await this.#awaitOperation(this.keyProvider({
      peerId: attempt.peerId,
      profile: attempt.profile,
      direction: "sign",
      // The only exception to confirmation-gated initiation is a response on
      // an attempt that exists because this adapter verified the peer's signed
      // pairwise offer. This closes the lost-final-ready race without granting
      // an unconfirmed peer permission to initiate a future repair.
      responseToVerifiedOffer: attempt.profile === AUTH_PROFILE.PAIRWISE
        && attempt.role === ATTEMPT_ROLE.ANSWERER,
      signal: this.controller.signal,
    }), "signing key lookup", this.keyLookupTimeoutMs);
    requireCondition(this.coordinator.now() < publicationDeadline,
      "attempt signalling lifetime ended during signing-key lookup");
    const encoded = await this.#awaitOperation(
      encodeAndSignRendezvousV2Bytes(token, key, { subtle: this.subtle }),
      "rendezvous token signing", this.cryptoOperationTimeoutMs);
    requireCondition(this.coordinator.now()
      + ((this.putRetries + 1) * this.isolatedWriteBudgetMs)
      < publicationDeadline,
    "attempt has too little signalling lifetime after token signing");
    return encoded;
  }

  async #pollAttempt(peerId, attemptId) {
    const key = `${peerId}:${attemptId}`;
    let timers = this.timers.get(key);
    if (!timers) {
      timers = { read: 0, connectivity: 0, expiry: 0, expiryAt: 0,
        pollCount: 0, pollFailures: 0 };
      this.timers.set(key, timers);
    }
    let succeeded = false;
    try {
      const attempt = this.coordinator.attempts.get(key);
      if (!attempt || isTerminalAttempt(attempt)) return null;
      if (this.coordinator.now() >= attempt.expiresAt) {
        succeeded = true;
        return Object.freeze({ status: "signalling-ended", receipt: null, tokenBytes: null });
      }
      timers.pollCount += 1;
      // Signed abort is peer state, unlike the relay's untrusted lifecycle
      // ACK. Interleave it so cancellation is observed without doubling every
      // poll's TURN allocation cost.
      const role = timers.pollCount % 4 === 0
        ? SLOT_ROLE.ABORT : this.#expectedPollRole(attempt);
      if (!role) {
        succeeded = true;
        return Object.freeze({ status: "idle", receipt: null, tokenBytes: null });
      }
      const read = await this.transport.get({
        from: peerId,
        to: this.coordinator.localId,
        attemptId,
        role,
        revision: 0,
      });
      if (read.status === "data") {
        const outcome = await this.#receiveSlot(read);
        succeeded = true;
        return outcome;
      }
      succeeded = true;
      return read;
    } catch (error) {
      timers.pollFailures = Math.min(6, timers.pollFailures + 1);
      throw error;
    } finally {
      if (succeeded) timers.pollFailures = 0;
      const current = this.coordinator.attempts.get(key);
      if (current) this.#syncTimers(current);
    }
  }

  #expectedPollRole(attempt) {
    if (attempt.role === ATTEMPT_ROLE.OFFERER
        && [ATTEMPT_STATE.PUBLISHING_OFFER, ATTEMPT_STATE.WAITING_ANSWER].includes(attempt.state)) {
      return SLOT_ROLE.ANSWER;
    }
    if (attempt.role === ATTEMPT_ROLE.OFFERER
        && !attempt.fallbackRequested
        && [ATTEMPT_STATE.CONNECTING, ATTEMPT_STATE.APPLYING_ANSWER].includes(attempt.state)) {
      return SLOT_ROLE.NEED_CANDIDATE;
    }
    if (attempt.role === ATTEMPT_ROLE.ANSWERER
        && attempt.fallbackRequested && !attempt.fallbackApplied) {
      return SLOT_ROLE.CANDIDATE;
    }
    return null;
  }

  #shouldPollAbort(attempt) {
    return attempt.role === ATTEMPT_ROLE.ANSWERER
      || ![ATTEMPT_STATE.IDLE, ATTEMPT_STATE.CREATING_OFFER].includes(attempt.state);
  }

  async #ensureConnection(attempt) {
    const key = connectionKey(attempt);
    const existing = this.connections.get(key);
    if (existing) return existing;
    const creating = Promise.resolve(this.createPeerConnection({
      attempt,
      role: attempt.role,
      signal: this.controller.signal,
    }));
    let created;
    try {
      created = await this.#awaitOperation(creating, "peer connection creation",
        this.peerConnectionTimeoutMs);
    } catch (error) {
      creating.then(late => {
        const latePc = late?.pc || late;
        try { late?.close?.("creation cancelled"); } catch {}
        try { latePc?.close?.(); } catch {}
      }).catch(() => {});
      throw error;
    }
    const pc = created?.pc || created;
    requireCondition(pc && typeof pc.setRemoteDescription === "function"
      && typeof pc.addEventListener === "function", "createPeerConnection returned an invalid peer connection");
    const entry = {
      pc,
      close: typeof created?.close === "function" ? created.close.bind(created) : null,
      channel: created?.channel || null,
      localCandidates: Object.freeze([]),
      remoteFingerprint: "",
      authenticationQueued: false,
      authenticating: false,
      authenticated: false,
      closed: false,
    };
    this.connections.set(key, entry);
    pc.addEventListener("datachannel", event => this.#bindChannel(attempt, entry, event.channel));
    pc.addEventListener("connectionstatechange", () => {
      if (["failed", "closed"].includes(pc.connectionState)) {
        this.#enqueue(attempt.peerId, async () => {
          const current = this.#currentAttempt(attempt);
          if (current && !isTerminalAttempt(current)) {
            if (pc.connectionState === "failed" && current.state === ATTEMPT_STATE.CONNECTING) {
              if (current.role === ATTEMPT_ROLE.ANSWERER && !current.fallbackRequested) {
                if (this.#canFallbackNow(current)) {
                  await this.#applySafely(this.coordinator.dispatch(
                    attempt.peerId, attempt.attemptId,
                    { type: ATTEMPT_EVENT.CONNECTIVITY_TIMEOUT },
                  ));
                  return;
                }
              } else {
                // The offerer must remain available for needCandidate, and a
                // peer that has begun the one-shot fallback must allow newly
                // signalled checks to recover an ICE transport already marked
                // failed. The bounded completion timer remains authoritative.
                this.#syncTimers(current);
                return;
              }
            }
            await this.#applySafely(this.coordinator.dispatch(attempt.peerId, attempt.attemptId, {
              type: ATTEMPT_EVENT.FAIL,
              reason: `peer connection ${pc.connectionState}`,
            }));
          }
        }).catch(error => this.#reportError(error, { phase: "connection-state", attempt }));
      }
    });
    if (entry.channel) this.#bindChannel(attempt, entry, entry.channel);
    return entry;
  }

  #bindChannel(attempt, entry, channel) {
    if (!channel || (entry.channel && entry.channel !== channel)) return;
    entry.channel = channel;
    const opened = () => {
      if (entry.authenticationQueued || entry.authenticating || entry.authenticated || entry.closed) return;
      entry.authenticationQueued = true;
      this.#enqueue(attempt.peerId, async () => {
        entry.authenticationQueued = false;
        if (entry.closed || entry.authenticated) return;
        entry.authenticating = true;
        try {
          const accepted = await this.#awaitOperation(this.authenticateChannel({
            attempt: this.#currentAttempt(attempt) || attempt,
            pc: entry.pc,
            channel,
            expectedRemoteFingerprint: entry.remoteFingerprint,
            signal: this.controller.signal,
          }), "data-channel authentication", this.authenticateTimeoutMs);
          requireCondition(accepted === true, "data-channel link hello was not authenticated");
          const current = this.#currentAttempt(attempt);
          if (current && !isTerminalAttempt(current)) {
            const outcome = await this.#applySafely(this.coordinator.dispatch(
              attempt.peerId, attempt.attemptId, {
                type: ATTEMPT_EVENT.CHANNEL_OPEN,
              }));
            const openedAttempt = this.#currentAttempt(attempt);
            requireCondition(outcome?.attempt?.state === ATTEMPT_STATE.OPEN
              && openedAttempt?.state === ATTEMPT_STATE.OPEN && !entry.closed,
            "authenticated channel was not accepted before the attempt deadline");
            entry.authenticated = true;
            try {
              this.onDataChannel({ attempt: openedAttempt,
                pc: entry.pc, channel });
            } catch (observerError) {
              this.#reportError(observerError, { phase: "channel-handoff", attempt });
            }
          }
        } catch (error) {
          const current = this.#currentAttempt(attempt);
          if (current && !isTerminalAttempt(current)) {
            await this.#applySafely(this.coordinator.dispatch(attempt.peerId, attempt.attemptId, {
              type: ATTEMPT_EVENT.FAIL,
              reason: `channel authentication failed: ${String(error?.message || error)}`,
            }));
          }
          throw error;
        } finally {
          entry.authenticating = false;
        }
      }, { critical: true }).catch(error => {
        entry.authenticationQueued = false;
        entry.authenticating = false;
        if (!entry.authenticated) this.#closeEntry(entry, "channel authentication could not be queued");
        this.#reportError(error, { phase: "channel-authentication", attempt });
      });
    };
    channel.addEventListener("open", opened, { once: true });
    if (channel.readyState === "open") opened();
  }

  #syncTimers(attempt) {
    let timers = this.timers.get(connectionKey(attempt));
    if (!timers) {
      timers = { read: 0, connectivity: 0, expiry: 0, expiryAt: 0,
        pollCount: 0, pollFailures: 0 };
      this.timers.set(connectionKey(attempt), timers);
    }
    clearTimeout(timers.read);
    timers.read = 0;
    if (isTerminalAttempt(attempt)) {
      this.#clearTimerSet(timers);
      this.timers.delete(connectionKey(attempt));
      this.connections.delete(connectionKey(attempt));
      return;
    }
    if (timers.expiry && timers.expiryAt !== attempt.completionDeadline) {
      clearTimeout(timers.expiry);
      timers.expiry = 0;
      timers.expiryAt = 0;
    }
    if (!timers.expiry) {
      timers.expiryAt = attempt.completionDeadline;
      timers.expiry = setTimeout(() => {
        timers.expiry = 0;
        timers.expiryAt = 0;
        this.#enqueue(attempt.peerId, async () => {
          const current = this.#currentAttempt(attempt);
          if (current && !isTerminalAttempt(current)) {
            await this.#applySafely(this.coordinator.dispatch(attempt.peerId, attempt.attemptId, {
              type: ATTEMPT_EVENT.EXPIRE,
            }));
          }
        }).catch(error => {
          this.#reportError(error, { phase: "expiry", attempt });
          const current = this.#currentAttempt(attempt);
          if (current && !isTerminalAttempt(current) && !timers.expiry) {
            timers.expiryAt = this.coordinator.now() + 1000;
            timers.expiry = setTimeout(() => {
              timers.expiry = 0;
              timers.expiryAt = 0;
              this.#syncTimers(current);
            }, 1000);
          }
        });
      }, Math.max(0, attempt.completionDeadline - this.coordinator.now()));
    }
    const signallingOpen = this.coordinator.now() < attempt.expiresAt;
    const shouldRead = signallingOpen
      && (Boolean(this.#expectedPollRole(attempt)) || this.#shouldPollAbort(attempt));
    if (shouldRead) {
      const backoff = Math.min(30_000,
        this.pollDelayMs * (2 ** Math.min(5, timers.pollFailures || 0)));
      const delay = backoff + Math.floor(Math.random() * Math.max(1, backoff * 0.2));
      timers.read = setTimeout(() => {
        timers.read = 0;
        this.poll(attempt.peerId, attempt.attemptId)
          .catch(error => {
            const currentTimers = this.timers.get(connectionKey(attempt));
            if (currentTimers && error?.code === "queue-full") {
              currentTimers.pollFailures = Math.min(6, currentTimers.pollFailures + 1);
            }
            this.#reportError(error, { phase: "poll", attempt });
          })
          .finally(() => {
            // Queue saturation can reject before #pollAttempt reaches its own
            // finally block. Restore the timer for the still-live attempt.
            const current = this.#currentAttempt(attempt);
            const currentTimers = this.timers.get(connectionKey(attempt));
            if (current && !isTerminalAttempt(current) && currentTimers && !currentTimers.read) {
              this.#syncTimers(current);
            }
          });
      }, delay);
    }
    if (attempt.role === ATTEMPT_ROLE.ANSWERER
        && attempt.state === ATTEMPT_STATE.CONNECTING && !attempt.fallbackRequested
        && signallingOpen) {
      if (!timers.connectivity) {
        const fallbackDelay = this.#fallbackDelayMs(attempt);
        if (fallbackDelay == null) return;
        timers.connectivity = setTimeout(() => {
          timers.connectivity = 0;
          this.notifyConnectivityTimeout(attempt.peerId, attempt.attemptId).catch(error => {
            this.#reportError(error, { phase: "connectivity-timeout", attempt });
            const current = this.#currentAttempt(attempt);
            if (current && !isTerminalAttempt(current)) this.#syncTimers(current);
          });
        }, fallbackDelay);
      }
    } else if (timers.connectivity) {
      clearTimeout(timers.connectivity);
      timers.connectivity = 0;
    }
  }

  #fallbackDelayMs(attempt) {
    const remaining = attempt.expiresAt - this.coordinator.now();
    // The answerer's timer begins when its answer is stored, not when the
    // offerer finishes paging, authenticating, and applying that answer. The
    // later of those two bounded paths must finish before the complete N -> C
    // reverse leg can be charged safely.
    const prerequisiteMs = Math.max(this.connectivityTimeoutMs,
      this.answerConsumptionBudgetMs);
    if (remaining < prerequisiteMs + this.fallbackSignalBudgetMs) return null;
    return this.connectivityTimeoutMs;
  }

  #canFallbackNow(attempt) {
    // An immediate local ICE failure provides no evidence that the offerer has
    // consumed the answer, so conservatively reserve that complete path too.
    return attempt.expiresAt - this.coordinator.now()
      >= this.answerConsumptionBudgetMs + this.fallbackSignalBudgetMs;
  }

  #publicationDeadline(attempt, role) {
    // A candidate is a response to an already authenticated needCandidate.
    // Its requester budgeted the complete reverse leg against its own raw
    // deadline, so the offerer may answer through its receive/skew horizon.
    if (role === SLOT_ROLE.CANDIDATE && attempt.role === ATTEMPT_ROLE.OFFERER
        && attempt.fallbackRequested) return attempt.expiresAt;
    return attempt.publishDeadline;
  }

  #clearTimerSet(timers) {
    clearTimeout(timers.read);
    clearTimeout(timers.connectivity);
    clearTimeout(timers.expiry);
    timers.read = timers.connectivity = timers.expiry = 0;
    timers.expiryAt = 0;
  }

  #attemptForEffect(effect) {
    requireCondition(effect?.peerId && effect?.localId,
      "semantic effect is missing its peer route");
    for (const attempt of this.coordinator.attempts.values()) {
      if (attempt.attemptId === effect.attemptId && attempt.contextId === effect.contextId
          && attempt.peerId === effect.peerId && attempt.localId === effect.localId) return attempt;
    }
    throw new Error("effect refers to an unknown rendezvous attempt");
  }

  #currentAttempt(attempt) {
    return this.coordinator.attempts.get(`${attempt.peerId}:${attempt.attemptId}`) || null;
  }

  #requireConnection(attempt) {
    const entry = this.connections.get(connectionKey(attempt));
    requireCondition(entry && !entry.closed, "rendezvous peer connection is unavailable");
    return entry;
  }

  #closeEntry(entry, reason) {
    if (entry.closed) return;
    entry.closed = true;
    try { entry.close?.(reason); } catch {}
    try { entry.pc.close(); } catch {}
  }

  #reportError(error, context) {
    try { this.onError(error, context); } catch {}
  }

  #awaitOperation(value, label, timeoutMs) {
    const operation = Promise.resolve(value);
    const signal = this.controller.signal;
    if (signal.aborted) return Promise.reject(signal.reason || new Error(`${label} aborted`));
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (callback, result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal.removeEventListener("abort", aborted);
        callback(result);
      };
      const aborted = () => finish(reject, signal.reason || new Error(`${label} aborted`));
      const timer = setTimeout(() => finish(reject, new Error(`${label} timed out`)), timeoutMs);
      signal.addEventListener("abort", aborted, { once: true });
      operation.then(valueResult => finish(resolve, valueResult), error => finish(reject, error));
    });
  }
}

export { defaultWaitForIce as waitForRendezvousV2IceGathering };

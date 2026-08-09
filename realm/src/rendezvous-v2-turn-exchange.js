/*
 * Six-lane TURN Allocate carrier for rr2.
 *
 * Each call creates one short-lived RTCPeerConnection per relay port, extracts
 * the synthetic six-byte XOR-RELAYED-ADDRESS, and closes every connection. It
 * has no heartbeat, repost, interval, or room-event behavior.
 */

const ROOM = /^[a-z0-9-]{8,40}$/;
const HOST = /^[A-Za-z0-9.-]{1,253}$/;

function requireCondition(condition, message) {
  if (!condition) throw new TypeError(message);
}

function abortableDelay(delayMs, signals) {
  const aborted = signals.find(signal => signal?.aborted);
  if (aborted) return Promise.reject(aborted.reason || new Error("TURN exchange aborted"));
  if (delayMs <= 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      for (const signal of signals) signal?.removeEventListener?.("abort", onAbort);
      callback(value);
    };
    const onAbort = event => finish(reject,
      event.target?.reason || new Error("TURN exchange aborted"));
    const timer = setTimeout(() => finish(resolve), delayMs);
    for (const signal of signals) signal?.addEventListener?.("abort", onAbort, { once: true });
  });
}

function candidateFrame(candidate) {
  const text = String(candidate?.candidate || "");
  const declaredType = String(candidate?.type || "").toLowerCase();
  const textIsRelay = /(?:^|\s)typ\s+relay(?:\s|$)/i.test(text);
  // Older WebKit builds do not always populate RTCIceCandidate.type, even
  // though the candidate text is complete. Preserve that standards-shaped
  // fallback without ever encoding a host/srflx address as a relay frame.
  if ((declaredType && declaredType !== "relay") || (!declaredType && !textIsRelay)) return null;
  let address = candidate?.address || "";
  let port = Number(candidate?.port);
  if (!address || !Number.isInteger(port)) {
    const match = text.match(
      /(?:^|\s)(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+typ\s+relay(?:\s|$)/i,
    );
    if (!match) return null;
    address = match[1];
    port = Number(match[2]);
  }
  const octets = String(address).split(".").map(Number);
  if (octets.length !== 4
      || octets.some(value => !Number.isInteger(value) || value < 0 || value > 255)
      || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return Uint8Array.of(...octets, (port >>> 8) & 0xff, port & 0xff);
}

export class RendezvousV2TurnExchangeError extends Error {
  constructor(message, causes = []) {
    super(message);
    this.name = "RendezvousV2TurnExchangeError";
    this.causes = Object.freeze(causes);
  }
}

export function createRendezvousV2TurnExchange({
  host,
  ports,
  room,
  getPeerConnectionConstructor = () => globalThis.RTCPeerConnection,
  timeoutMs = 4000,
  minimumExchangeIntervalMs = 250,
  exchangeJitterMs = 75,
  maxQueuedExchanges = 64,
  reservedHighPriorityExchanges = 32,
  now = () => Date.now(),
  random = Math.random,
  onUsage = () => {},
}) {
  requireCondition(HOST.test(String(host)), "invalid TURN relay host");
  requireCondition(ROOM.test(String(room)), "invalid TURN relay room");
  requireCondition(Array.isArray(ports) && ports.length >= 1 && ports.length <= 12,
    "TURN relay requires one to twelve ports");
  const lanePorts = ports.map(Number);
  requireCondition(lanePorts.every(port => Number.isSafeInteger(port) && port >= 1 && port <= 65535)
    && new Set(lanePorts).size === lanePorts.length, "TURN relay ports must be unique and valid");
  requireCondition(lanePorts.every((port, index) => index === 0 || port === lanePorts[index - 1] + 1),
    "TURN relay ports must be ascending and contiguous so lane order is canonical");
  requireCondition(typeof getPeerConnectionConstructor === "function",
    "getPeerConnectionConstructor must be a function");
  requireCondition(Number.isSafeInteger(timeoutMs) && timeoutMs >= 500 && timeoutMs <= 30_000,
    "TURN exchange timeout is outside the supported range");
  const requiredExchangeIntervalMs = Math.max(250,
    Math.ceil((lanePorts.length * 1000) / 24));
  requireCondition(Number.isSafeInteger(minimumExchangeIntervalMs)
    && minimumExchangeIntervalMs >= requiredExchangeIntervalMs
    && minimumExchangeIntervalMs <= 5000,
  `minimumExchangeIntervalMs must be ${requiredExchangeIntervalMs}-5000 for this lane count`);
  requireCondition(Number.isSafeInteger(exchangeJitterMs)
    && exchangeJitterMs >= 0 && exchangeJitterMs <= 1000,
  "exchangeJitterMs is outside the supported range");
  requireCondition(Number.isSafeInteger(maxQueuedExchanges)
    && maxQueuedExchanges >= 4 && maxQueuedExchanges <= 128,
  "maxQueuedExchanges is outside the supported range");
  requireCondition(Number.isSafeInteger(reservedHighPriorityExchanges)
    && reservedHighPriorityExchanges >= 1
    && reservedHighPriorityExchanges < maxQueuedExchanges,
  "reservedHighPriorityExchanges must fit inside the exchange queue");
  requireCondition(typeof now === "function" && typeof random === "function",
    "TURN scheduler clock and random source must be functions");
  requireCondition(typeof onUsage === "function", "onUsage must be a function");

  let closed = false;
  let queued = 0;
  let queuedHigh = 0;
  let queuedNonHigh = 0;
  let running = false;
  let lastStartedAt = Number.NEGATIVE_INFINITY;
  const active = new Set();
  const pending = { high: [], normal: [], low: [] };
  const schedulerController = new AbortController();

  const perform = async (username, { signal } = {}) => {
    requireCondition(!closed, "TURN exchange is closed");
    if (signal?.aborted) throw signal.reason || new Error("TURN exchange aborted");
    const PC = getPeerConnectionConstructor();
    requireCondition(typeof PC === "function", "RTCPeerConnection is unavailable");
    try { onUsage({ direction: "sent", bytes: username.length, lanes: lanePorts.length }); } catch {}
    const settled = await Promise.allSettled(lanePorts.map((port, lane) =>
      carrier({ PC, port, lane, username, signal })));
    const failures = settled.filter(item => item.status === "rejected").map(item => item.reason);
    if (failures.length) {
      throw new RendezvousV2TurnExchangeError(
        `${failures.length} of ${lanePorts.length} TURN lanes did not return an authenticated frame`,
        failures,
      );
    }
    const frames = settled.map(item => item.value);
    try { onUsage({ direction: "received", bytes: frames.length * 6, lanes: frames.length }); } catch {}
    return frames;
  };

  const deadlineError = () => {
    const error = new RendezvousV2TurnExchangeError(
      "TURN exchange deadline elapsed before allocation started");
    error.code = "deadline";
    return error;
  };

  const run = async ({ username, signal, deadline }) => {
    requireCondition(!closed, "TURN exchange is closed");
    if (signal?.aborted) throw signal.reason || new Error("TURN exchange aborted");
    let timestamp = Number(now());
    requireCondition(Number.isFinite(timestamp), "TURN scheduler clock returned an invalid time");
    if (timestamp >= deadline) throw deadlineError();
    const sample = Number(random());
    requireCondition(Number.isFinite(sample) && sample >= 0 && sample < 1,
      "TURN scheduler random source must return a value in [0, 1)");
    const jitter = Math.floor(sample * exchangeJitterMs);
    const dueAt = lastStartedAt + minimumExchangeIntervalMs + jitter;
    if (dueAt >= deadline) throw deadlineError();
    await abortableDelay(Math.max(0, dueAt - timestamp), [signal, schedulerController.signal]);
    requireCondition(!closed, "TURN exchange is closed");
    timestamp = Number(now());
    requireCondition(Number.isFinite(timestamp), "TURN scheduler clock returned an invalid time");
    if (timestamp >= deadline) throw deadlineError();
    lastStartedAt = timestamp;
    return perform(username, { signal });
  };

  const nextPending = () => pending.high.shift() || pending.normal.shift() || pending.low.shift();
  const pump = () => {
    if (closed || running) return;
    const item = nextPending();
    if (!item) return;
    running = true;
    run(item).then(item.resolve, item.reject).finally(() => {
      queued = Math.max(0, queued - 1);
      if (item.priority === "high") queuedHigh = Math.max(0, queuedHigh - 1);
      else queuedNonHigh = Math.max(0, queuedNonHigh - 1);
      running = false;
      pump();
    });
  };

  const exchange = (username, { signal, deadline = Number.POSITIVE_INFINITY,
    priority = "normal" } = {}) => {
    requireCondition(!closed, "TURN exchange is closed");
    requireCondition(typeof username === "string" && username.length >= 1 && username.length <= 509
      && !/[\s\u0000-\u001f\u007f]/.test(username), "invalid TURN username");
    requireCondition(["high", "normal", "low"].includes(priority),
      "TURN exchange priority must be high, normal, or low");
    requireCondition(deadline === Number.POSITIVE_INFINITY
      || (Number.isSafeInteger(deadline) && deadline >= 0),
    "TURN exchange deadline must be an integer timestamp");
    if (signal?.aborted) return Promise.reject(signal.reason || new Error("TURN exchange aborted"));
    const timestamp = Number(now());
    requireCondition(Number.isFinite(timestamp), "TURN scheduler clock returned an invalid time");
    if (timestamp >= deadline) return Promise.reject(deadlineError());
    if (queued >= maxQueuedExchanges) {
      return Promise.reject(new RendezvousV2TurnExchangeError(
        "TURN exchange queue is full; retry with backoff"));
    }
    if (priority === "high" && queuedHigh >= reservedHighPriorityExchanges) {
      return Promise.reject(new RendezvousV2TurnExchangeError(
        "TURN exchange high-priority quota is full; retry with backoff"));
    }
    if (priority !== "high"
        && queuedNonHigh >= maxQueuedExchanges - reservedHighPriorityExchanges) {
      return Promise.reject(new RendezvousV2TurnExchangeError(
        "TURN exchange normal-priority quota is full; retry with backoff"));
    }
    queued += 1;
    if (priority === "high") queuedHigh += 1;
    else queuedNonHigh += 1;
    return new Promise((resolve, reject) => {
      pending[priority].push({ username, signal, deadline, priority, resolve, reject });
      pump();
    });
  };

  Object.defineProperties(exchange, {
    laneCount: { value: lanePorts.length, enumerable: true },
    capacity: { value: maxQueuedExchanges, enumerable: true },
    highPriorityReserve: { value: reservedHighPriorityExchanges, enumerable: true },
    normalCapacity: {
      value: maxQueuedExchanges - reservedHighPriorityExchanges,
      enumerable: true,
    },
    timeoutMs: { value: timeoutMs, enumerable: true },
    minimumIntervalMs: { value: minimumExchangeIntervalMs, enumerable: true },
    maximumJitterMs: { value: exchangeJitterMs, enumerable: true },
    isolatedExchangeBudgetMs: {
      value: timeoutMs + minimumExchangeIntervalMs + exchangeJitterMs,
      enumerable: true,
    },
    queued: { get: () => queued, enumerable: true },
    queuedHigh: { get: () => queuedHigh, enumerable: true },
    queuedNonHigh: { get: () => queuedNonHigh, enumerable: true },
  });

  exchange.close = () => {
    if (closed) return;
    closed = true;
    const error = new Error("TURN exchange closed");
    schedulerController.abort(error);
    for (const queue of Object.values(pending)) {
      for (const item of queue.splice(0)) {
        queued = Math.max(0, queued - 1);
        if (item.priority === "high") queuedHigh = Math.max(0, queuedHigh - 1);
        else queuedNonHigh = Math.max(0, queuedNonHigh - 1);
        item.reject(error);
      }
    }
    for (const finish of [...active]) finish(error);
  };

  function carrier({ PC, port, lane, username, signal }) {
    return new Promise((resolve, reject) => {
      let pc = null;
      let timer = 0;
      let settled = false;
      let lastIceError = "";
      const finish = (error, frame = null) => {
        if (settled) return;
        settled = true;
        active.delete(cancel);
        clearTimeout(timer);
        signal?.removeEventListener?.("abort", aborted);
        if (pc) {
          pc.onicecandidate = null;
          pc.onicecandidateerror = null;
          pc.onicegatheringstatechange = null;
          try { pc.close(); } catch {}
          pc = null;
        }
        if (error) reject(error);
        else resolve(frame);
      };
      const cancel = error => finish(error || new Error("TURN lane cancelled"));
      const aborted = () => cancel(signal.reason || new Error("TURN exchange aborted"));
      active.add(cancel);
      signal?.addEventListener?.("abort", aborted, { once: true });
      try {
        pc = new PC({
          iceServers: [{
            urls: [`turn:${host}:${port}?transport=udp`],
            username,
            credential: room,
          }],
          iceTransportPolicy: "relay",
        });
        pc.onicecandidate = (event) => {
          if (!event.candidate) return;
          const frame = candidateFrame(event.candidate);
          if (frame) finish(null, frame);
        };
        pc.onicecandidateerror = (event) => {
          lastIceError = [event.errorCode, event.errorText].filter(Boolean).join(" ");
        };
        pc.onicegatheringstatechange = () => {
          if (pc?.iceGatheringState === "complete") {
            finish(new Error(lastIceError
              ? `TURN lane ${lane} completed without a frame (${lastIceError})`
              : `TURN lane ${lane} completed without a frame`));
          }
        };
        pc.createDataChannel("rr2", { ordered: false, maxRetransmits: 0 });
        Promise.resolve(pc.createOffer())
          .then(offer => pc && pc.setLocalDescription(offer))
          .catch(error => finish(error));
        timer = setTimeout(() => finish(new Error(lastIceError
          ? `TURN lane ${lane} timed out (${lastIceError})`
          : `TURN lane ${lane} timed out`)), timeoutMs);
      } catch (error) {
        finish(error);
      }
    });
  }

  return exchange;
}

/*
 * Portable rr2 latest-value transport.
 *
 * The caller injects one bounded, ordered lane-exchange function. It accepts a
 * TURN username, exposes laneCount/capacity, and resolves to one
 * Uint8Array-compatible frame per lane in canonical port order.
 * This module never creates a RTCPeerConnection and never interprets signed
 * token bytes; the codec remains the authentication boundary.
 */

const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const ROOM = /^[a-z0-9-]{8,40}$/;
const ACTOR = /^(?!0{12}$)[a-f0-9]{12}$/;
const DEVICE = /^[a-f0-9]{16}$/;
const ATTEMPT = /^(?!0{32}$)[a-f0-9]{32}$/;
const WILDCARD_DEVICE = "0000000000000000";
const MAX_SLOT_BYTES = 240;
const MAX_RESPONSE_BYTES = 277;
const MAX_RESPONSE_CHARS = 370;

const ROLE_TO_WIRE = Object.freeze({
  offer: "o",
  answer: "a",
  needCandidate: "n",
  candidate: "c",
  ack: "k",
  abort: "x",
});
const WIRE_TO_ROLE = Object.freeze(Object.fromEntries(
  Object.entries(ROLE_TO_WIRE).map(([name, wire]) => [wire, name]),
));

const STATUS = Object.freeze({
  50: "empty",
  51: "stored",
  52: "not-modified",
  53: "acked",
  54: "aborted",
});

const ERROR = Object.freeze({
  43: "disabled",
  44: "full",
  45: "forbidden",
  46: "missing",
  47: "conflict",
  48: "bad-operation",
  49: "internal",
});

function requireCondition(condition, message) {
  if (!condition) throw new TypeError(message);
}

function bytes(value, name) {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  throw new TypeError(`${name} must be bytes.`);
}

function uint32(frame) {
  return ((frame[1] * 0x1000000) + (frame[2] << 16) + (frame[3] << 8) + frame[4]) >>> 0;
}

function hex(value) {
  let output = "";
  for (const octet of value) output += octet.toString(16).padStart(2, "0");
  return output;
}

function base64UrlEncode(value) {
  const input = bytes(value, "base64url input");
  let output = "";
  for (let index = 0; index < input.length; index += 3) {
    const available = Math.min(3, input.length - index);
    const word = (input[index] << 16)
      | ((input[index + 1] || 0) << 8)
      | (input[index + 2] || 0);
    output += BASE64URL[(word >>> 18) & 63];
    output += BASE64URL[(word >>> 12) & 63];
    if (available >= 2) output += BASE64URL[(word >>> 6) & 63];
    if (available === 3) output += BASE64URL[word & 63];
  }
  return output;
}

function base64UrlDecode(value) {
  const source = String(value ?? "");
  requireCondition(source.length > 0 && source.length % 4 !== 1
    && /^[A-Za-z0-9_-]+$/.test(source), "invalid canonical base64url response");
  const output = new Uint8Array(Math.floor((source.length * 6) / 8));
  let bits = 0;
  let count = 0;
  let at = 0;
  for (const character of source) {
    const valueIndex = BASE64URL.indexOf(character);
    bits = (bits << 6) | valueIndex;
    count += 6;
    if (count >= 8) {
      count -= 8;
      output[at++] = (bits >>> count) & 0xff;
    }
  }
  requireCondition(base64UrlEncode(output) === source, "non-canonical base64url response");
  return output;
}

function roleWire(role) {
  const wire = ROLE_TO_WIRE[role] || (WIRE_TO_ROLE[role] ? role : "");
  requireCondition(Boolean(wire), "invalid rendezvous slot role");
  return wire;
}

function selectorKey(selector) {
  return `${selector.from}/${selector.to}/${selector.attemptId}/${selector.role}`;
}

function attemptRouteKey(selector) {
  return `${selector.from}/${selector.to}/${selector.attemptId}`;
}

export class RendezvousV2TransportError extends Error {
  constructor(code, message, revision = 0) {
    super(message);
    this.name = "RendezvousV2TransportError";
    this.code = code;
    this.revision = revision;
  }
}

export class RendezvousV2SlotTransport {
  constructor({
    room,
    actor,
    exchange,
    laneCount = 6,
    maxPages = null,
    maxTrackedAttempts = 32,
    maxOwnedSlotsPerAttempt = 6,
  }) {
    requireCondition(ROOM.test(String(room)), "invalid rr2 room");
    requireCondition(ACTOR.test(String(actor)), "invalid rr2 actor");
    requireCondition(typeof exchange === "function", "exchange must be a function");
    requireCondition(Number.isSafeInteger(laneCount) && laneCount >= 1 && laneCount <= 12,
      "laneCount must be between one and twelve");
    if (exchange.laneCount != null) {
      requireCondition(exchange.laneCount === laneCount,
        "exchange laneCount disagrees with the slot transport");
    }
    requireCondition(Number.isSafeInteger(exchange.capacity)
      && exchange.capacity >= 4 && exchange.capacity <= 128,
    "exchange must expose its bounded queue capacity");
    requireCondition(Number.isSafeInteger(exchange.highPriorityReserve)
      && exchange.highPriorityReserve >= 1
      && Number.isSafeInteger(exchange.normalCapacity)
      && exchange.normalCapacity >= 1
      && exchange.highPriorityReserve + exchange.normalCapacity === exchange.capacity,
    "exchange must expose compatible high- and normal-priority bounds");
    requireCondition(Number.isSafeInteger(exchange.isolatedExchangeBudgetMs)
      && exchange.isolatedExchangeBudgetMs >= 500
      && exchange.isolatedExchangeBudgetMs <= 40_000,
    "exchange must expose its bounded isolated-service duration");
    const requiredPages = Math.ceil(74 / laneCount);
    const boundedPages = maxPages == null ? requiredPages : maxPages;
    requireCondition(Number.isSafeInteger(boundedPages)
      && boundedPages >= requiredPages && boundedPages <= 256,
      "maxPages must be between one and 256");
    requireCondition(Number.isSafeInteger(maxTrackedAttempts)
      && maxTrackedAttempts >= 1 && maxTrackedAttempts <= 128,
    "maxTrackedAttempts must be between one and 128");
    requireCondition(Number.isSafeInteger(maxOwnedSlotsPerAttempt)
      && maxOwnedSlotsPerAttempt >= 1 && maxOwnedSlotsPerAttempt <= 12,
    "maxOwnedSlotsPerAttempt must be between one and twelve");
    this.room = room;
    this.actor = actor;
    this.exchange = exchange;
    this.exchangeCapacity = exchange.capacity;
    this.exchangeHighPriorityReserve = exchange.highPriorityReserve;
    this.exchangeNormalCapacity = exchange.normalCapacity;
    this.isolatedExchangeBudgetMs = exchange.isolatedExchangeBudgetMs;
    this.isolatedWriteBudgetMs = exchange.isolatedExchangeBudgetMs;
    this.laneCount = laneCount;
    this.maxPages = boundedPages;
    this.maxTrackedAttempts = maxTrackedAttempts;
    this.maxOwnedSlotsPerAttempt = maxOwnedSlotsPerAttempt;
    this.owned = new Map();
    this.generations = new Map();
    this.pendingAttempts = new Map();
    this.pendingSlots = new Map();
    this.forgottenAttempts = new Set();
    this.closed = false;
    this.controller = new AbortController();
  }

  isolatedReadBudgetForTokenBytes(tokenBytes) {
    requireCondition(Number.isSafeInteger(tokenBytes)
      && tokenBytes >= 1 && tokenBytes <= MAX_SLOT_BYTES,
    "token byte budget must fit one rr2 slot");
    const responseBytes = 37 + tokenBytes;
    const encodedChars = Math.ceil((responseBytes * 4) / 3);
    const chunks = Math.ceil(encodedChars / 5);
    const pages = Math.ceil(chunks / this.laneCount);
    requireCondition(pages <= this.maxPages, "token read exceeds configured page bound");
    return pages * this.isolatedExchangeBudgetMs;
  }

  async put({ from, to, attemptId, role, tokenBytes, revision = 0, deadline = null }) {
    const selector = this.#selector({ from, to, attemptId, role });
    requireCondition(selector.from !== WILDCARD_DEVICE, "a slot writer must be concrete");
    requireCondition(selector.to !== WILDCARD_DEVICE || selector.role === "o",
      "only a bootstrap offer may use the broadcast recipient");
    const routeKey = attemptRouteKey(selector);
    this.#assertTrackingCapacity(routeKey);
    const ownedKey = selectorKey(selector);
    const ownedForAttempt = [...this.owned.values()]
      .filter(receipt => attemptRouteKey(receipt) === routeKey).length;
    const pendingForAttempt = [...this.pendingSlots.values()]
      .filter(pending => pending.routeKey === routeKey).length;
    requireCondition(this.owned.has(ownedKey) || this.pendingSlots.has(ownedKey)
      || ownedForAttempt + pendingForAttempt < this.maxOwnedSlotsPerAttempt,
      "owned slot limit reached for this rendezvous attempt");
    const token = bytes(tokenBytes, "slot token");
    requireCondition(token.length > 0 && token.length <= MAX_SLOT_BYTES,
      `slot token must contain 1-${MAX_SLOT_BYTES} bytes`);
    requireCondition(deadline == null || (Number.isSafeInteger(deadline) && deadline >= 0),
      "slot write deadline must be an integer timestamp");
    const generation = this.#generation(routeKey);
    this.#beginPending(routeKey, ownedKey);
    try {
      const response = await this.#control(selector, "put", revision, 0,
        base64UrlEncode(token), { priority: "high", deadline });
      requireCondition(response.status === "stored" || response.status === "acked",
        `unexpected put status ${response.status}`);
      requireCondition(response.revision >= 1, "stored slot has an invalid revision");
      const receipt = Object.freeze({ ...selector, revision: response.revision });
      if (this.closed || generation !== this.#generation(routeKey)) {
        // Cleanup overtook an in-flight PUT. Erase the value as soon as its
        // revision becomes known so a stale async completion cannot resurrect it.
        await this.abort(receipt).catch(() => {});
        throw new RendezvousV2TransportError("cancelled", "slot write was cancelled by attempt cleanup");
      }
      // ACKED can be the convergent result of an ambiguous PUT whose response
      // was lost while the peer consumed the stored bytes. It proves storage
      // lifecycle only, never peer identity, but it is sufficient to continue
      // toward the authenticated link-hello. There is no live slot to own.
      if (response.status === "stored") this.owned.set(ownedKey, receipt);
      return Object.freeze({ status: response.status, receipt });
    } finally {
      this.#endPending(routeKey, ownedKey);
    }
  }

  get({ from, to, attemptId, role, revision = 0 }) {
    return this.#read(this.#selector({ from, to, attemptId, role }), "get", revision);
  }

  discover({ from = WILDCARD_DEVICE, to, attemptId = "0", role = "offer" }) {
    requireCondition(from === WILDCARD_DEVICE || DEVICE.test(String(from)), "invalid discovery sender");
    requireCondition(DEVICE.test(String(to)), "invalid discovery recipient");
    requireCondition(attemptId === "0" || ATTEMPT.test(String(attemptId)), "invalid discovery attempt");
    requireCondition(roleWire(role) === "o" || attemptId !== "0",
      "attempt wildcard discovery is offer-only");
    requireCondition(from === WILDCARD_DEVICE || from !== to,
      "a concrete discovery sender cannot equal its recipient");
    requireCondition(to !== WILDCARD_DEVICE || roleWire(role) === "o",
      "a broadcast recipient is offer-only");
    return this.#read({ from, to, attemptId, role: roleWire(role) }, "discover", 0);
  }

  ack(receipt) {
    return this.#lifecycle(receipt, "ack");
  }

  abort(receipt) {
    return this.#lifecycle(receipt, "abort");
  }

  async clearOwnedAttempt(route) {
    const normalized = this.#attemptRoute(route);
    const routeKey = attemptRouteKey(normalized);
    const known = this.generations.has(routeKey) || this.pendingAttempts.has(routeKey)
      || [...this.owned.values()].some(receipt => attemptRouteKey(receipt) === routeKey);
    if (!known) return Object.freeze([]);
    this.generations.set(routeKey, this.#generation(routeKey) + 1);
    const selected = [...this.owned.values()]
      .filter(receipt => attemptRouteKey(receipt) === routeKey);
    const outcomes = [];
    for (const receipt of selected) {
      try {
        outcomes.push(await this.abort(receipt));
      } catch (error) {
        outcomes.push(Object.freeze({ status: "cleanup-failed", receipt, error }));
      } finally {
        this.owned.delete(selectorKey(receipt));
      }
    }
    return Object.freeze(outcomes);
  }

  /** Drop bounded client bookkeeping after the final ordered effect. */
  forgetAttempt(route) {
    const normalized = this.#attemptRoute(route);
    const routeKey = attemptRouteKey(normalized);
    this.generations.set(routeKey, this.#generation(routeKey) + 1);
    for (const [key, receipt] of this.owned) {
      if (attemptRouteKey(receipt) === routeKey) this.owned.delete(key);
    }
    if (this.pendingAttempts.has(routeKey)) this.forgottenAttempts.add(routeKey);
    else this.generations.delete(routeKey);
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.controller.abort(new Error("rr2 transport closed"));
    this.exchange.close?.();
    this.owned.clear();
    this.generations.clear();
    this.pendingAttempts.clear();
    this.pendingSlots.clear();
    this.forgottenAttempts.clear();
  }

  async #lifecycle(receipt, operation) {
    const selector = this.#selector(receipt);
    requireCondition(Number.isSafeInteger(receipt?.revision)
      && receipt.revision >= 1 && receipt.revision <= 0xffffffff, "invalid slot receipt revision");
    const response = await this.#control(selector, operation, receipt.revision, 0, "0",
      { priority: "normal" });
    const expected = operation === "ack" ? new Set(["acked", "aborted"]) : new Set(["aborted", "acked"]);
    requireCondition(expected.has(response.status), `unexpected ${operation} status ${response.status}`);
    requireCondition(response.revision === receipt.revision,
      `${operation} response revision disagrees with its receipt`);
    this.owned.delete(selectorKey(selector));
    return Object.freeze({ status: response.status, receipt: Object.freeze({ ...selector, revision: response.revision }) });
  }

  async #read(selector, operation, revision) {
    requireCondition(Number.isSafeInteger(revision) && revision >= 0 && revision <= 0xffffffff,
      "invalid read revision");
    let encoded = "";
    for (let page = 0; page < this.maxPages; page += 1) {
      if (this.controller.signal.aborted) throw this.controller.signal.reason;
      const chunkBase = page * this.laneCount;
      requireCondition(chunkBase <= 255, "rr2 response exceeds the chunk index range");
      const frames = await this.#frames(
        this.#username(selector, operation, revision, chunkBase, "0"),
        { priority: "low" },
      );
      const parsedFrames = frames.map(frame => this.#frame(frame));
      const statuses = parsedFrames.filter(frame => frame.kind === "status");
      if (statuses.length) {
        if (page !== 0 || statuses.length !== parsedFrames.length
            || statuses.some(item => item.status !== statuses[0].status
              || item.revision !== statuses[0].revision)) {
          throw new RendezvousV2TransportError("inconsistent-page",
            "rr2 lanes disagreed while paging current state");
        }
        return Object.freeze({
          status: statuses[0].status,
          revision: statuses[0].revision,
          receipt: null,
          tokenBytes: null,
        });
      }
      for (const parsed of parsedFrames) {
        if (parsed.kind !== "data") {
          throw new RendezvousV2TransportError("truncated", "rr2 returned mixed data and control frames");
        }
        encoded += parsed.text;
        requireCondition(encoded.length <= MAX_RESPONSE_CHARS, "rr2 response exceeds its encoded bound");
        if (parsed.final) return this.#decodePayload(encoded, selector);
      }
    }
    // A page after the first can fail transiently even though the claimed slot
    // is valid. Never erase a value based on an incomplete byte stream: the
    // same reader actor can restart at page zero, while the bounded reader
    // lease releases a genuinely abandoned claim. Only callers holding a full
    // receipt may abort a token after authentication rejects it.
    throw new RendezvousV2TransportError("truncated", "rr2 response did not terminate");
  }

  #decodePayload(encoded, requested) {
    const decoded = base64UrlDecode(encoded);
    requireCondition(decoded.length >= 38 && decoded.length <= MAX_RESPONSE_BYTES,
      "rr2 response has an invalid decoded size");
    const from = hex(decoded.slice(0, 8));
    const to = hex(decoded.slice(8, 16));
    const attemptId = hex(decoded.slice(16, 32));
    const role = String.fromCharCode(decoded[32]);
    const revision = ((decoded[33] * 0x1000000)
      + (decoded[34] << 16) + (decoded[35] << 8) + decoded[36]) >>> 0;
    requireCondition(DEVICE.test(from) && from !== WILDCARD_DEVICE && DEVICE.test(to),
      "rr2 returned invalid device selectors");
    requireCondition(ATTEMPT.test(attemptId) && WIRE_TO_ROLE[role] && revision >= 1,
      "rr2 returned an invalid concrete selector");
    requireCondition((requested.from === WILDCARD_DEVICE || requested.from === from)
      && requested.to === to
      && (requested.attemptId === "0" || requested.attemptId === attemptId)
      && requested.role === role, "rr2 response disagrees with the requested selector");
    const tokenBytes = decoded.slice(37);
    requireCondition(tokenBytes.length >= 1 && tokenBytes.length <= MAX_SLOT_BYTES,
      "rr2 returned an invalid token size");
    return Object.freeze({
      status: "data",
      tokenBytes,
      receipt: Object.freeze({ from, to, attemptId, role, revision }),
    });
  }

  async #control(selector, operation, revision, chunkBase, payload, options = {}) {
    requireCondition(Number.isSafeInteger(revision) && revision >= 0 && revision <= 0xffffffff,
      "invalid control revision");
    const frames = await this.#frames(
      this.#username(selector, operation, revision, chunkBase, payload), options);
    const parsed = frames.map(frame => this.#frame(frame));
    const first = parsed[0];
    requireCondition(first.kind === "status", "rr2 control operation returned data");
    if (operation === "put") {
      requireCondition(parsed.every(item => item.kind === "status"
        && ["stored", "acked"].includes(item.status)
        && item.revision === first.revision),
      "rr2 PUT lane responses are not one monotonic stored/acked revision");
      return parsed.some(item => item.status === "acked")
        ? Object.freeze({ ...first, status: "acked" }) : first;
    }
    for (const item of parsed.slice(1)) {
      requireCondition(item.kind === "status" && item.status === first.status
        && item.revision === first.revision, "rr2 lane control responses disagree");
    }
    return first;
  }

  async #frames(username, { priority = "normal", deadline = null } = {}) {
    if (this.closed) throw new RendezvousV2TransportError("closed", "rr2 transport is closed");
    const response = await this.exchange(username, {
      signal: this.controller.signal,
      priority,
      ...(deadline == null ? {} : { deadline }),
    });
    requireCondition(Array.isArray(response) && response.length === this.laneCount,
      `exchange must return ${this.laneCount} lane frames`);
    return response.map((frame, lane) => {
      const value = bytes(frame, `lane ${lane} frame`);
      requireCondition(value.length === 6, `lane ${lane} did not return a six-byte frame`);
      return value;
    });
  }

  #frame(frame) {
    const header = frame[0];
    if (ERROR[header]) {
      requireCondition(frame[5] === 1, "rr2 error frame has an invalid version");
      throw new RendezvousV2TransportError(ERROR[header],
        `rr2 ${ERROR[header]} response`, uint32(frame));
    }
    if (STATUS[header]) {
      requireCondition(frame[5] === 1, "rr2 status frame has an invalid version");
      return Object.freeze({ kind: "status", status: STATUS[header], revision: uint32(frame) });
    }
    const continuation = header >= 20 && header <= 25;
    const final = header >= 30 && header <= 35;
    requireCondition(continuation || final, "rr2 returned an unknown frame header");
    const length = header - (final ? 30 : 20);
    requireCondition(length >= (final ? 0 : 1) && length <= 5,
      "rr2 returned an invalid data length");
    let text = "";
    for (let index = 0; index < length; index += 1) {
      const octet = frame[index + 1];
      requireCondition((octet >= 48 && octet <= 57)
        || (octet >= 65 && octet <= 90)
        || (octet >= 97 && octet <= 122)
        || octet === 45 || octet === 95, "rr2 data frame is not base64url text");
      text += String.fromCharCode(octet);
    }
    return Object.freeze({ kind: "data", final, text });
  }

  #selector({ from, to, attemptId, role }) {
    requireCondition(DEVICE.test(String(from)) && DEVICE.test(String(to)), "invalid rr2 device selector");
    requireCondition(ATTEMPT.test(String(attemptId)), "invalid rr2 attempt id");
    const wireRole = roleWire(role);
    requireCondition(from !== WILDCARD_DEVICE, "an exact rr2 sender must be concrete");
    requireCondition(from !== to, "an rr2 sender cannot equal its recipient");
    requireCondition(to !== WILDCARD_DEVICE || wireRole === "o",
      "a broadcast recipient is offer-only");
    return Object.freeze({ from, to, attemptId, role: wireRole });
  }

  #username(selector, operation, revision, chunkBase, payload) {
    const username = ["rr2", this.room, this.actor, selector.from, selector.to,
      selector.attemptId, selector.role, operation, revision.toString(36),
      chunkBase.toString(36), payload].join(".");
    requireCondition(username.length <= 509, "rr2 username exceeds the TURN limit");
    return username;
  }

  #generation(routeKey) {
    return this.generations.get(routeKey) || 0;
  }

  #assertTrackingCapacity(routeKey) {
    if (this.generations.has(routeKey)
        || this.pendingAttempts.has(routeKey)
        || [...this.owned.values()].some(receipt => attemptRouteKey(receipt) === routeKey)) return;
    const tracked = new Set(this.generations.keys());
    for (const key of this.pendingAttempts.keys()) tracked.add(key);
    for (const receipt of this.owned.values()) tracked.add(attemptRouteKey(receipt));
    requireCondition(tracked.size < this.maxTrackedAttempts,
      "rendezvous transport attempt-tracking limit reached");
  }

  #beginPending(routeKey, ownedKey) {
    this.pendingAttempts.set(routeKey, (this.pendingAttempts.get(routeKey) || 0) + 1);
    const pending = this.pendingSlots.get(ownedKey);
    this.pendingSlots.set(ownedKey, {
      routeKey,
      count: (pending?.count || 0) + 1,
    });
  }

  #endPending(routeKey, ownedKey) {
    const attemptCount = (this.pendingAttempts.get(routeKey) || 1) - 1;
    if (attemptCount > 0) this.pendingAttempts.set(routeKey, attemptCount);
    else this.pendingAttempts.delete(routeKey);
    const pending = this.pendingSlots.get(ownedKey);
    if (pending?.count > 1) this.pendingSlots.set(ownedKey,
      { routeKey, count: pending.count - 1 });
    else this.pendingSlots.delete(ownedKey);
    if (!this.pendingAttempts.has(routeKey) && this.forgottenAttempts.delete(routeKey)) {
      this.generations.delete(routeKey);
    }
  }

  #attemptRoute({ from, to, attemptId } = {}) {
    requireCondition(DEVICE.test(String(from)) && from !== WILDCARD_DEVICE
      && DEVICE.test(String(to)) && from !== to, "invalid rr2 cleanup route");
    requireCondition(ATTEMPT.test(String(attemptId)), "invalid rr2 cleanup attempt");
    return Object.freeze({ from, to, attemptId });
  }
}

export const RENDEZVOUS_V2_SLOT_ROLE = ROLE_TO_WIRE;
export const RENDEZVOUS_V2_WILDCARD_DEVICE = WILDCARD_DEVICE;

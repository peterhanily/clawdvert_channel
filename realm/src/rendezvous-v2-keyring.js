/*
 * Pairwise repair-key establishment over an already authenticated data channel.
 *
 * Callers must invoke receiveAuthenticated() only after the existing link-hello
 * has bound the channel to authenticatedPeerId. The messages are not safe on
 * the TURN mailbox. Each peer contributes 256 random bits; a domain-separated
 * digest derives the stored pairwise HMAC key and a short comparison ID.
 */

const DEVICE = /^(?!0{16}$)[a-f0-9]{16}$/;
const CONTEXT = /^(?!0{24}$)[a-f0-9]{24}$/;
const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const SHARE_CONTEXT = new TextEncoder().encode("clawdvert/rendezvous-v2/pairwise-share\0");
const KEY_ID_CONTEXT = new TextEncoder().encode("clawdvert/rendezvous-v2/key-id\0");

function requireCondition(condition, message) {
  if (!condition) throw new TypeError(message);
}

function bytesFromHex(value) {
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

function concat(...values) {
  const output = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

function encodeBase64Url(input) {
  let output = "";
  for (let index = 0; index < input.length; index += 3) {
    const count = Math.min(3, input.length - index);
    const word = (input[index] << 16)
      | ((input[index + 1] || 0) << 8)
      | (input[index + 2] || 0);
    output += BASE64URL[(word >>> 18) & 63] + BASE64URL[(word >>> 12) & 63];
    if (count > 1) output += BASE64URL[(word >>> 6) & 63];
    if (count > 2) output += BASE64URL[word & 63];
  }
  return output;
}

function decodeBase64Url(value, expectedBytes) {
  const source = String(value ?? "");
  requireCondition(/^[A-Za-z0-9_-]+$/.test(source) && source.length % 4 !== 1,
    "invalid pairwise share encoding");
  const output = new Uint8Array(Math.floor(source.length * 6 / 8));
  let bits = 0;
  let available = 0;
  let at = 0;
  for (const character of source) {
    bits = (bits << 6) | BASE64URL.indexOf(character);
    available += 6;
    if (available >= 8) {
      available -= 8;
      output[at++] = (bits >>> available) & 0xff;
    }
  }
  requireCondition(output.length === expectedBytes && encodeBase64Url(output) === source,
    "pairwise share has the wrong size or is not canonical");
  return output;
}

function equalText(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

export class RendezvousV2PairwiseKeyring {
  constructor({
    localId,
    contextId,
    storage,
    crypto = globalThis.crypto,
    now = () => Date.now(),
    prefix = "clawdvert.rv2",
  }) {
    requireCondition(DEVICE.test(String(localId)), "invalid local device id");
    requireCondition(CONTEXT.test(String(contextId)), "invalid pairwise context id");
    requireCondition(storage && typeof storage.getItem === "function"
      && typeof storage.setItem === "function" && typeof storage.removeItem === "function",
    "a Storage-compatible key store is required");
    requireCondition(crypto?.subtle?.digest && typeof crypto.getRandomValues === "function",
      "Web Crypto digest and random generation are required");
    requireCondition(typeof now === "function", "now must be a function");
    requireCondition(/^[A-Za-z0-9._-]{1,40}$/.test(prefix), "invalid storage prefix");
    this.localId = localId;
    this.contextId = contextId;
    this.storage = storage;
    this.crypto = crypto;
    this.now = now;
    this.prefix = prefix;
    this.sentShares = new Set();
  }

  begin(peerId) {
    this.#peer(peerId);
    const share = this.#localShare(peerId);
    this.sentShares.add(peerId);
    return Object.freeze({
      type: "rv2-key-share",
      version: 2,
      contextId: this.contextId,
      from: this.localId,
      to: peerId,
      share: encodeBase64Url(share),
    });
  }

  /**
   * Process a message received on an already authenticated peer channel.
   * Returns messages that should be sent back over that same fast channel.
   */
  async receiveAuthenticated(message, authenticatedPeerId) {
    this.#peer(authenticatedPeerId);
    requireCondition(message && message.version === 2
      && message.contextId === this.contextId
      && message.from === authenticatedPeerId && message.to === this.localId,
    "pairwise key message is outside the authenticated channel context");
    if (message.type === "rv2-key-share") {
      const remoteShare = decodeBase64Url(message.share, 32);
      const previous = this.storage.getItem(this.#remoteShareKey(authenticatedPeerId));
      if (previous && !equalText(previous, message.share)) {
        throw new Error("peer changed its pairwise contribution without a coordinated authenticated reset");
      }
      this.storage.setItem(this.#remoteShareKey(authenticatedPeerId), message.share);
      const localShare = this.#localShare(authenticatedPeerId);
      const derived = await this.#derive(authenticatedPeerId, localShare, remoteShare);
      this.#writeRecord(authenticatedPeerId, derived);
      const outbound = [];
      if (!this.sentShares.has(authenticatedPeerId)) outbound.push(this.begin(authenticatedPeerId));
      outbound.push(Object.freeze({
        type: "rv2-key-ready",
        version: 2,
        contextId: this.contextId,
        from: this.localId,
        to: authenticatedPeerId,
        keyId: derived.keyId,
        capability: Object.freeze({ protocol: "rv2", relay: "rr2", profile: "pairwise" }),
      }));
      return Object.freeze(outbound);
    }
    if (message.type === "rv2-key-ready") {
      requireCondition(message.capability?.protocol === "rv2"
        && message.capability?.relay === "rr2" && message.capability?.profile === "pairwise",
      "peer advertised an incompatible repair capability");
      const record = this.#readRecord(authenticatedPeerId);
      requireCondition(record && equalText(record.keyId, String(message.keyId || "")),
        "peer pairwise key confirmation does not match");
      record.ready = true;
      record.confirmedAt = this.now();
      this.storage.setItem(this.#recordKey(authenticatedPeerId), JSON.stringify(record));
      return Object.freeze([]);
    }
    throw new Error("unknown authenticated rendezvous capability message");
  }

  keyFor(peerId, { direction = "sign", responseToVerifiedOffer = false } = {}) {
    this.#peer(peerId);
    requireCondition(direction === "sign" || direction === "verify",
      "pairwise key direction must be sign or verify");
    requireCondition(typeof responseToVerifiedOffer === "boolean",
      "responseToVerifiedOffer must be boolean");
    requireCondition(direction === "sign" || responseToVerifiedOffer === false,
      "responseToVerifiedOffer applies only to signing");
    const record = this.#readRecord(peerId);
    requireCondition(record, "peer has no derived pairwise repair key");
    // A final ready message can be lost immediately before the fast channel
    // closes. A verified pairwise offer is itself proof that the peer derived
    // this key, so an answerer may sign only that verified inbound attempt.
    // General initiation remains confirmation-gated.
    if (direction === "sign") {
      requireCondition(record.ready === true || responseToVerifiedOffer,
        "peer has no confirmed pairwise repair key");
    }
    return decodeBase64Url(record.key, 32);
  }

  canRepair(peerId) {
    try { return this.#readRecord(peerId)?.ready === true; } catch { return false; }
  }

  canVerify(peerId) {
    try { return Boolean(this.#readRecord(peerId)?.key); } catch { return false; }
  }

  revoke(peerId) {
    this.#peer(peerId);
    this.sentShares.delete(peerId);
    this.storage.removeItem(this.#localShareKey(peerId));
    this.storage.removeItem(this.#remoteShareKey(peerId));
    this.storage.removeItem(this.#recordKey(peerId));
  }

  async #derive(peerId, localShare, remoteShare) {
    const localFirst = this.localId < peerId;
    const firstId = bytesFromHex(localFirst ? this.localId : peerId);
    const secondId = bytesFromHex(localFirst ? peerId : this.localId);
    const firstShare = localFirst ? localShare : remoteShare;
    const secondShare = localFirst ? remoteShare : localShare;
    const key = new Uint8Array(await this.crypto.subtle.digest("SHA-256", concat(
      SHARE_CONTEXT,
      bytesFromHex(this.contextId),
      firstId,
      secondId,
      firstShare,
      secondShare,
    )));
    const keyIdDigest = new Uint8Array(await this.crypto.subtle.digest("SHA-256",
      concat(KEY_ID_CONTEXT, key)));
    return Object.freeze({ key, keyId: encodeBase64Url(keyIdDigest.slice(0, 9)) });
  }

  #localShare(peerId) {
    const key = this.#localShareKey(peerId);
    const stored = this.storage.getItem(key);
    if (stored) return decodeBase64Url(stored, 32);
    const share = new Uint8Array(32);
    this.crypto.getRandomValues(share);
    this.storage.setItem(key, encodeBase64Url(share));
    return share;
  }

  #writeRecord(peerId, derived) {
    const existing = this.#readRecord(peerId);
    if (existing && !equalText(existing.keyId, derived.keyId)) {
      throw new Error("pairwise key derivation changed without a coordinated authenticated reset");
    }
    this.storage.setItem(this.#recordKey(peerId), JSON.stringify({
      version: 2,
      key: encodeBase64Url(derived.key),
      keyId: derived.keyId,
      ready: Boolean(existing?.ready),
      establishedAt: existing?.establishedAt || this.now(),
      confirmedAt: existing?.confirmedAt || 0,
    }));
  }

  #readRecord(peerId) {
    const text = this.storage.getItem(this.#recordKey(peerId));
    if (!text) return null;
    const value = JSON.parse(text);
    requireCondition(value?.version === 2 && typeof value.key === "string"
      && typeof value.keyId === "string", "stored pairwise key record is invalid");
    decodeBase64Url(value.key, 32);
    return value;
  }

  #peer(peerId) {
    requireCondition(DEVICE.test(String(peerId)) && peerId !== this.localId,
      "invalid pairwise peer id");
  }

  #scope(peerId) {
    return `${this.prefix}.${this.contextId}.${this.localId}.${peerId}`;
  }

  #localShareKey(peerId) { return `${this.#scope(peerId)}.local`; }
  #remoteShareKey(peerId) { return `${this.#scope(peerId)}.remote`; }
  #recordKey(peerId) { return `${this.#scope(peerId)}.key`; }
}

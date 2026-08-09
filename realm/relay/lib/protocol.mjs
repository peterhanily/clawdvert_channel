const BASE64URL = /^[A-Za-z0-9_-]*$/;

export const PROTOCOL_VERSION = "rr1";
export const RENDEZVOUS_PROTOCOL_VERSION = "rr2";
export const MAX_MESSAGE_CHARS = 280;
export const MAX_NAME_CHARS = 24;
export const CHUNK_BYTES = 5;
export const MAX_SLOT_PAYLOAD_BYTES = 240;
export const RENDEZVOUS_BROADCAST_DEVICE = "0000000000000000";

export const SLOT_CONTROL = Object.freeze({
  EMPTY: 50,
  STORED: 51,
  NOT_MODIFIED: 52,
  ACKED: 53,
  ABORTED: 54,
});

export const SLOT_ERROR = Object.freeze({
  DISABLED: 3,
  FULL: 4,
  FORBIDDEN: 5,
  MISSING: 6,
  CONFLICT: 7,
  BAD_OPERATION: 8,
  INTERNAL: 9,
});

const cleanText = (value, maxLength) =>
  String(value ?? "")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .trim()
    .slice(0, maxLength);

export function fromBase64Url(value, maxBytes = 512) {
  if (!BASE64URL.test(value) || value.length > Math.ceil((maxBytes * 4) / 3) + 4) return null;
  try {
    const decoded = Buffer.from(value, "base64url");
    return decoded.length <= maxBytes ? decoded.toString("utf8") : null;
  } catch {
    return null;
  }
}

export function toBase64Url(value) {
  return Buffer.from(value, "utf8").toString("base64url");
}

export function parseUsername(username) {
  if (typeof username !== "string" || username.length > 509) return null;
  const parts = username.split(".");
  if (parts.length !== 8 || parts[0] !== PROTOCOL_VERSION) return null;

  const [, room, clientId, requestId, encodedName, sequenceRaw, chunkRaw, encodedMessage] = parts;
  if (!/^[a-z0-9-]{8,40}$/.test(room)) return null;
  if (!/^[a-f0-9]{12}$/.test(clientId)) return null;
  if (!/^(0|[a-f0-9]{12})$/.test(requestId)) return null;
  if (!/^[0-9a-z]{1,8}$/.test(sequenceRaw) || !/^[0-9a-z]{1,3}$/.test(chunkRaw)) return null;

  const sequence = Number.parseInt(sequenceRaw, 36);
  const chunkBase = Number.parseInt(chunkRaw, 36);
  if (!Number.isSafeInteger(sequence) || sequence < 0 || sequence > 0xffffffff) return null;
  if (!Number.isSafeInteger(chunkBase) || chunkBase < 0 || chunkBase > 255) return null;

  const name = cleanText(fromBase64Url(encodedName, 96), MAX_NAME_CHARS);
  if (!name) return null;

  let message = "";
  if (encodedMessage !== "0") {
    const decoded = fromBase64Url(encodedMessage, 1024);
    if (decoded === null) return null;
    message = cleanText(decoded, MAX_MESSAGE_CHARS);
    if (!message) return null;
  }

  return { room, clientId, requestId, name, sequence, chunkBase, message };
}

// rr2 is a separate, ephemeral latest-value protocol. Its payload is binary
// and is never passed to RoomStore or encodeEvent(). The actor field makes the
// intended caller relationship explicit even though cryptographic device
// identity remains the client's responsibility inside the signed payload.
//
// rr2.room.actor.from.to.attempt.role.operation.revision.chunk.payload
export function parseRendezvousUsername(username) {
  if (typeof username !== "string" || username.length > 509) return null;
  const parts = username.split(".");
  if (parts.length !== 11 || parts[0] !== RENDEZVOUS_PROTOCOL_VERSION) return null;

  const [
    ,
    room,
    actor,
    from,
    to,
    attempt,
    role,
    operation,
    revisionRaw,
    chunkRaw,
    encodedPayload,
  ] = parts;
  if (!/^[a-z0-9-]{8,40}$/.test(room)) return null;
  if (!/^[a-f0-9]{12}$/.test(actor) || /^0{12}$/.test(actor)) return null;
  if (!/^[a-f0-9]{16}$/.test(from) || !/^[a-f0-9]{16}$/.test(to)) return null;
  if (!/^(?:[a-f0-9]{32}|0)$/.test(attempt)) return null;
  if (/^0{32}$/.test(attempt)) return null;
  if (!/^[oanckx]$/.test(role)) return null;
  if (!/^(put|get|discover|ack|abort)$/.test(operation)) return null;
  if (!/^[0-9a-z]{1,8}$/.test(revisionRaw) || !/^[0-9a-z]{1,3}$/.test(chunkRaw)) return null;

  const revision = Number.parseInt(revisionRaw, 36);
  const chunkBase = Number.parseInt(chunkRaw, 36);
  if (!Number.isSafeInteger(revision) || revision < 0 || revision > 0xffffffff) return null;
  if (!Number.isSafeInteger(chunkBase) || chunkBase < 0 || chunkBase > 255) return null;

  const wildcardFrom = from === RENDEZVOUS_BROADCAST_DEVICE;
  if (from === to && !(operation === "discover" && wildcardFrom)) return null;
  if (operation !== "discover" && wildcardFrom) return null;
  if (to === RENDEZVOUS_BROADCAST_DEVICE && role !== "o") return null;

  let payload = Buffer.alloc(0);
  if (encodedPayload !== "0") {
    payload = fromBase64UrlBytes(encodedPayload, MAX_SLOT_PAYLOAD_BYTES);
    if (!payload?.length) return null;
  }
  if (operation === "discover") {
    if ((attempt === "0" && role !== "o") || revision !== 0 || payload.length) return null;
  } else if (attempt === "0") {
    return null;
  }
  if (operation === "put") {
    if (!payload.length || chunkBase !== 0) return null;
  } else if (payload.length || ((operation === "ack" || operation === "abort") && chunkBase !== 0)) {
    return null;
  }

  return {
    version: RENDEZVOUS_PROTOCOL_VERSION,
    room,
    actor,
    from,
    to,
    attempt,
    role,
    operation,
    revision,
    chunkBase,
    payload,
  };
}

export function fromBase64UrlBytes(value, maxBytes = MAX_SLOT_PAYLOAD_BYTES) {
  if (!BASE64URL.test(value) || !value || value.length > Math.ceil((maxBytes * 4) / 3) + 2) return null;
  try {
    const decoded = Buffer.from(value, "base64url");
    if (decoded.length > maxBytes || decoded.toString("base64url") !== value) return null;
    return decoded;
  } catch {
    return null;
  }
}

export function encodeEvent(event) {
  return Buffer.from(
    JSON.stringify([
      event.kind === "message" ? "m" : "s",
      event.id,
      event.senderId,
      event.sender,
      event.text,
      event.timestamp,
    ]),
    "utf8",
  );
}

export function makeControlFrame(latestSequence, onlineCount) {
  const frame = Buffer.alloc(6);
  frame[0] = 10;
  frame.writeUInt32BE(latestSequence >>> 0, 1);
  frame[5] = Math.min(255, onlineCount);
  return frame;
}

export function makeDataFrame(payload, chunkIndex) {
  const start = chunkIndex * CHUNK_BYTES;
  const chunk = payload.subarray(start, start + CHUNK_BYTES);
  const final = start + chunk.length >= payload.length;
  const frame = Buffer.alloc(6);
  frame[0] = (final ? 30 : 20) + chunk.length;
  chunk.copy(frame, 1);
  if (frame.readUInt16BE(4) === 0) frame.writeUInt16BE(1, 4);
  return frame;
}

export function makeErrorFrame(code, value = 0) {
  const frame = Buffer.alloc(6);
  frame[0] = Math.max(41, Math.min(49, 40 + code));
  frame.writeUInt32BE(value >>> 0, 1);
  frame[5] = 1;
  return frame;
}

export function makeSlotControlFrame(status, revision = 0) {
  if (!Object.values(SLOT_CONTROL).includes(status)) throw new RangeError("Unknown rendezvous slot status.");
  const frame = Buffer.alloc(6);
  frame[0] = status;
  frame.writeUInt32BE(revision >>> 0, 1);
  // A zero TURN port is invalid. This byte is reserved as the rr2 control
  // frame version and deliberately remains non-zero.
  frame[5] = 1;
  return frame;
}

export function makeSlotPayload({ from, to, attempt, role, revision, payload }) {
  const fromBytes = typeof from === "string" && /^[a-f0-9]{16}$/.test(from)
    ? Buffer.from(from, "hex")
    : null;
  const toBytes = typeof to === "string" && /^[a-f0-9]{16}$/.test(to)
    ? Buffer.from(to, "hex")
    : null;
  const attemptBytes = typeof attempt === "string" && /^[a-f0-9]{32}$/.test(attempt)
    ? Buffer.from(attempt, "hex")
    : null;
  if (!fromBytes || /^0{16}$/.test(from) || !toBytes) {
    throw new RangeError("Concrete rendezvous device selectors are required.");
  }
  if (!attemptBytes || /^0{32}$/.test(attempt)) {
    throw new RangeError("A non-zero 128-bit rendezvous attempt ID is required.");
  }
  if (typeof role !== "string" || !/^[oanckx]$/.test(role)) {
    throw new RangeError("A rendezvous slot role is required.");
  }
  if (!Number.isInteger(revision) || revision < 0 || revision > 0xffffffff) {
    throw new RangeError("An unsigned 32-bit rendezvous revision is required.");
  }
  if (!Buffer.isBuffer(payload) || !payload.length || payload.length > MAX_SLOT_PAYLOAD_BYTES) {
    throw new RangeError("A bounded, non-empty rendezvous payload is required.");
  }
  const value = Buffer.allocUnsafe(37 + payload.length);
  fromBytes.copy(value, 0);
  toBytes.copy(value, 8);
  attemptBytes.copy(value, 16);
  value[32] = role.charCodeAt(0);
  value.writeUInt32BE(revision >>> 0, 33);
  payload.copy(value, 37);
  // makeDataFrame's final two address bytes form a TURN port, which must not
  // be zero. A canonical base64url layer guarantees that real five-byte data
  // chunks contain no zero octets, while short final-frame padding is ignored.
  return Buffer.from(value.toString("base64url"), "ascii");
}

export function frameAddress(frame) {
  if (!Buffer.isBuffer(frame) || frame.length !== 6) throw new TypeError("A six-byte mailbox frame is required.");
  return {
    ip: `${frame[0]}.${frame[1]}.${frame[2]}.${frame[3]}`,
    port: frame.readUInt16BE(4),
  };
}

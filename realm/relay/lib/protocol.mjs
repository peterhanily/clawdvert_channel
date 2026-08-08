const BASE64URL = /^[A-Za-z0-9_-]*$/;

export const PROTOCOL_VERSION = "rr1";
export const MAX_MESSAGE_CHARS = 280;
export const MAX_NAME_CHARS = 24;
export const CHUNK_BYTES = 5;

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

export function frameAddress(frame) {
  if (!Buffer.isBuffer(frame) || frame.length !== 6) throw new TypeError("A six-byte mailbox frame is required.");
  return {
    ip: `${frame[0]}.${frame[1]}.${frame[2]}.${frame[3]}`,
    port: frame.readUInt16BE(4),
  };
}


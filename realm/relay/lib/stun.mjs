import crypto from "node:crypto";

export const MAGIC_COOKIE = 0x2112a442;

export const MESSAGE = Object.freeze({
  BINDING_REQUEST: 0x0001,
  BINDING_SUCCESS: 0x0101,
  ALLOCATE_REQUEST: 0x0003,
  ALLOCATE_SUCCESS: 0x0103,
  ALLOCATE_ERROR: 0x0113,
});

export const ATTRIBUTE = Object.freeze({
  USERNAME: 0x0006,
  MESSAGE_INTEGRITY: 0x0008,
  ERROR_CODE: 0x0009,
  LIFETIME: 0x000d,
  REALM: 0x0014,
  NONCE: 0x0015,
  XOR_RELAYED_ADDRESS: 0x0016,
  REQUESTED_TRANSPORT: 0x0019,
  XOR_MAPPED_ADDRESS: 0x0020,
  SOFTWARE: 0x8022,
  FINGERPRINT: 0x8028,
});

const align4 = (length) => (length + 3) & ~3;

export function parseMessage(packet) {
  if (!Buffer.isBuffer(packet) || packet.length < 20) return null;
  if ((packet[0] & 0xc0) !== 0) return null;
  if (packet.readUInt32BE(4) !== MAGIC_COOKIE) return null;

  const length = packet.readUInt16BE(2);
  if (length % 4 !== 0 || length + 20 > packet.length) return null;

  const attributes = [];
  let offset = 20;
  const end = 20 + length;
  while (offset + 4 <= end) {
    const type = packet.readUInt16BE(offset);
    const attributeLength = packet.readUInt16BE(offset + 2);
    const valueStart = offset + 4;
    const valueEnd = valueStart + attributeLength;
    if (valueEnd > end) return null;
    attributes.push({
      type,
      offset,
      length: attributeLength,
      value: packet.subarray(valueStart, valueEnd),
    });
    offset = valueStart + align4(attributeLength);
  }
  if (offset !== end) return null;

  return {
    type: packet.readUInt16BE(0),
    length,
    transactionId: packet.subarray(8, 20),
    attributes,
    packet: packet.subarray(0, end),
  };
}

export function getAttribute(message, type) {
  return message?.attributes.find((attribute) => attribute.type === type) ?? null;
}

export function textAttribute(message, type) {
  const attribute = getAttribute(message, type);
  return attribute ? attribute.value.toString("utf8") : null;
}

export function longTermKey(username, realm, password) {
  return crypto.createHash("md5").update(`${username}:${realm}:${password}`, "utf8").digest();
}

export function verifyMessageIntegrity(message, key) {
  const integrity = getAttribute(message, ATTRIBUTE.MESSAGE_INTEGRITY);
  if (!integrity || integrity.length !== 20) return false;

  const signed = Buffer.from(message.packet.subarray(0, integrity.offset));
  signed.writeUInt16BE(integrity.offset + 24 - 20, 2);
  const expected = crypto.createHmac("sha1", key).update(signed).digest();
  return crypto.timingSafeEqual(expected, integrity.value);
}

function encodeAttribute(type, value) {
  const body = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const output = Buffer.alloc(4 + align4(body.length));
  output.writeUInt16BE(type, 0);
  output.writeUInt16BE(body.length, 2);
  body.copy(output, 4);
  return output;
}

export const attribute = Object.freeze({
  text(type, value) {
    return encodeAttribute(type, Buffer.from(value, "utf8"));
  },

  uint32(type, value) {
    const body = Buffer.alloc(4);
    body.writeUInt32BE(value >>> 0);
    return encodeAttribute(type, body);
  },

  error(code, reason) {
    const phrase = Buffer.from(reason, "utf8");
    const body = Buffer.alloc(4 + phrase.length);
    body[2] = Math.floor(code / 100);
    body[3] = code % 100;
    phrase.copy(body, 4);
    return encodeAttribute(ATTRIBUTE.ERROR_CODE, body);
  },

  xorAddress(type, ip, port, transactionId) {
    const octets = parseIpv4(ip);
    const body = Buffer.alloc(8);
    body[1] = 0x01;
    body.writeUInt16BE((port ^ (MAGIC_COOKIE >>> 16)) & 0xffff, 2);
    const cookie = Buffer.alloc(4);
    cookie.writeUInt32BE(MAGIC_COOKIE);
    for (let index = 0; index < 4; index += 1) body[4 + index] = octets[index] ^ cookie[index];
    return encodeAttribute(type, body);
  },
});

export function buildMessage({ type, transactionId, attributes = [], integrityKey = null, fingerprint = true }) {
  if (!Buffer.isBuffer(transactionId) || transactionId.length !== 12) {
    throw new TypeError("A 12-byte STUN transaction id is required.");
  }

  const beforeIntegrity = Buffer.concat(attributes);
  let integrityAttribute = Buffer.alloc(0);

  if (integrityKey) {
    const signedHeader = makeHeader(type, beforeIntegrity.length + 24, transactionId);
    const signature = crypto
      .createHmac("sha1", integrityKey)
      .update(Buffer.concat([signedHeader, beforeIntegrity]))
      .digest();
    integrityAttribute = encodeAttribute(ATTRIBUTE.MESSAGE_INTEGRITY, signature);
  }

  const beforeFingerprint = Buffer.concat([beforeIntegrity, integrityAttribute]);
  const fingerprintLength = fingerprint ? 8 : 0;
  const header = makeHeader(type, beforeFingerprint.length + fingerprintLength, transactionId);

  if (!fingerprint) return Buffer.concat([header, beforeFingerprint]);

  const checksum = (crc32(Buffer.concat([header, beforeFingerprint])) ^ 0x5354554e) >>> 0;
  const checksumBody = Buffer.alloc(4);
  checksumBody.writeUInt32BE(checksum);
  return Buffer.concat([header, beforeFingerprint, encodeAttribute(ATTRIBUTE.FINGERPRINT, checksumBody)]);
}

function makeHeader(type, length, transactionId) {
  const header = Buffer.alloc(20);
  header.writeUInt16BE(type, 0);
  header.writeUInt16BE(length, 2);
  header.writeUInt32BE(MAGIC_COOKIE, 4);
  transactionId.copy(header, 8);
  return header;
}

export function parseIpv4(value) {
  const octets = String(value).replace(/^::ffff:/, "").split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    throw new TypeError(`Expected an IPv4 address, received ${value}`);
  }
  return octets;
}

let crcTable;
function getCrcTable() {
  if (crcTable) return crcTable;
  crcTable = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    crcTable[index] = value >>> 0;
  }
  return crcTable;
}

export function crc32(buffer) {
  const table = getCrcTable();
  let value = 0xffffffff;
  for (const byte of buffer) value = table[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

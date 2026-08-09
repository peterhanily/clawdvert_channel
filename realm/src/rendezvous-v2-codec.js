/*
 * Clawdvert rendezvous V2 authenticated token codec.
 *
 * This module is intentionally browser-portable and side-effect free: it has
 * no dependency on the DOM, Node Buffer, timers, storage, or network APIs.
 * Callers supply the HMAC key, current wall-clock seconds, and (optionally) a
 * Web Crypto SubtleCrypto implementation.
 */

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const HEX = /^[0-9a-f]+$/;
const ICE_TEXT = /^[A-Za-z0-9+/]+$/;
const MAC_CONTEXT = Uint8Array.of(
  0x63, 0x6c, 0x61, 0x77, 0x64, 0x76, 0x65, 0x72, 0x74, 0x2f,
  0x72, 0x65, 0x6e, 0x64, 0x65, 0x7a, 0x76, 0x6f, 0x75, 0x73,
  0x2d, 0x76, 0x32, 0x00,
);
const ROOM_CONTEXT = Uint8Array.from(
  "clawdvert/rendezvous-v2/room-context\0",
  (character) => character.charCodeAt(0),
);

export const RENDEZVOUS_V2 = Object.freeze({
  magic: 0x52,
  version: 2,
  wirePrefix: "~v2~",
  tagBytes: 16,
  fixedBodyBytes: 56,
  maxWireChars: 280,
  maxTokenBytes: 207,
  maxBodyBytes: 191,
  controlTokenBytes: 72,
  maxOfferTokenBytes: 188,
  maxCandidateOnlyTokenBytes: 118,
  minLifetimeSeconds: 15,
  maxLifetimeSeconds: 300,
  defaultClockSkewSeconds: 120,
  maxClockSkewSeconds: 300,
  minUfragChars: 4,
  maxUfragChars: 32,
  minPasswordChars: 22,
  maxPasswordChars: 64,
  broadcastId: "0000000000000000",
});

export const RENDEZVOUS_PROFILE = Object.freeze({
  bootstrap: 1,
  pairwise: 2,
  roomTransition: 3,
});

export const RENDEZVOUS_ROLE = Object.freeze({
  offer: 1,
  answer: 2,
  ack: 3,
  abort: 4,
  needCandidate: 5,
  candidate: 6,
});

export const RENDEZVOUS_SETUP = Object.freeze({
  none: 0,
  actpass: 1,
  active: 2,
  passive: 3,
});

const CANDIDATE_FAMILY = Object.freeze({ ipv4: 0, ipv6: 1 });
const CANDIDATE_PROTOCOL = Object.freeze({ udp: 0, tcp: 1 });
const CANDIDATE_TYPE = Object.freeze({ host: 0, srflx: 1, relay: 2 });
const TCP_TYPE = Object.freeze({ none: 0, active: 1, passive: 2, so: 3 });

const PROFILE_NAME = invert(RENDEZVOUS_PROFILE);
const ROLE_NAME = invert(RENDEZVOUS_ROLE);
const SETUP_NAME = invert(RENDEZVOUS_SETUP);
const FAMILY_NAME = invert(CANDIDATE_FAMILY);
const PROTOCOL_NAME = invert(CANDIDATE_PROTOCOL);
const CANDIDATE_TYPE_NAME = invert(CANDIDATE_TYPE);
const TCP_TYPE_NAME = invert(TCP_TYPE);

export class RendezvousV2CodecError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "RendezvousV2CodecError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new RendezvousV2CodecError(code, message);
}

function invert(value) {
  return Object.freeze(
    Object.fromEntries(Object.entries(value).map(([name, number]) => [number, name])),
  );
}

function own(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function requireObject(value, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_FIELD", `${field} must be an object.`);
  }
  return value;
}

function enumValue(value, values, names, field, allowZero = false) {
  if (typeof value === "string" && own(values, value)) return values[value];
  if (Number.isInteger(value) && own(names, value) && (allowZero || value !== 0)) return value;
  fail("INVALID_FIELD", `${field} is not a supported value.`);
}

function uint(value, maximum, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    fail("INVALID_FIELD", `${field} must be an integer from 0 through ${maximum}.`);
  }
  return value;
}

function exactHex(value, byteLength, field) {
  const text = String(value ?? "").toLowerCase();
  if (text.length !== byteLength * 2 || !HEX.test(text)) {
    fail("INVALID_FIELD", `${field} must be ${byteLength * 2} lowercase hexadecimal characters.`);
  }
  const bytes = new Uint8Array(byteLength);
  for (let index = 0; index < byteLength; index += 1) {
    bytes[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  let result = "";
  for (const byte of bytes) result += byte.toString(16).padStart(2, "0");
  return result;
}

function asciiBytes(value, minimum, maximum, field, pattern) {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum || !pattern.test(value)) {
    fail("INVALID_FIELD", `${field} must contain ${minimum}-${maximum} permitted ASCII characters.`);
  }
  return Uint8Array.from(value, (character) => character.charCodeAt(0));
}

function bytesToAscii(bytes) {
  return String.fromCharCode(...bytes);
}

function concatBytes(...parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function copyBytes(value, field, code = "INVALID_KEY") {
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  fail(code, `${field} must be a BufferSource.`);
}

function base64UrlLength(byteLength) {
  const padded = Math.ceil(byteLength / 3) * 4;
  const padding = byteLength % 3 === 0 ? 0 : 3 - (byteLength % 3);
  return padded - padding;
}

function base64UrlEncode(bytes) {
  let result = "";
  for (let offset = 0; offset < bytes.length; offset += 3) {
    const remaining = bytes.length - offset;
    const value =
      (bytes[offset] << 16) |
      ((remaining > 1 ? bytes[offset + 1] : 0) << 8) |
      (remaining > 2 ? bytes[offset + 2] : 0);
    result += BASE64URL_ALPHABET[(value >>> 18) & 63];
    result += BASE64URL_ALPHABET[(value >>> 12) & 63];
    if (remaining > 1) result += BASE64URL_ALPHABET[(value >>> 6) & 63];
    if (remaining > 2) result += BASE64URL_ALPHABET[value & 63];
  }
  return result;
}

function base64UrlDecode(value) {
  if (typeof value !== "string" || !value || value.length % 4 === 1) {
    fail("INVALID_WIRE", "The rendezvous token is not canonical base64url.");
  }
  const output = [];
  let buffer = 0;
  let bits = 0;
  for (const character of value) {
    const decoded = BASE64URL_ALPHABET.indexOf(character);
    if (decoded < 0) fail("INVALID_WIRE", "The rendezvous token is not canonical base64url.");
    buffer = (buffer << 6) | decoded;
    bits += 6;
    while (bits >= 8) {
      bits -= 8;
      output.push((buffer >>> bits) & 0xff);
      buffer &= bits === 0 ? 0 : (1 << bits) - 1;
    }
  }
  if (buffer !== 0) fail("INVALID_WIRE", "The rendezvous token has non-canonical trailing bits.");
  const bytes = Uint8Array.from(output);
  if (base64UrlEncode(bytes) !== value) {
    fail("INVALID_WIRE", "The rendezvous token is not canonically encoded.");
  }
  return bytes;
}

class ByteWriter {
  constructor() {
    this.bytes = [];
  }

  u8(value) {
    this.bytes.push(value & 0xff);
  }

  u16(value) {
    this.bytes.push((value >>> 8) & 0xff, value & 0xff);
  }

  u32(value) {
    this.bytes.push(
      Math.floor(value / 0x1000000) & 0xff,
      Math.floor(value / 0x10000) & 0xff,
      Math.floor(value / 0x100) & 0xff,
      value & 0xff,
    );
  }

  append(bytes) {
    for (const byte of bytes) this.bytes.push(byte);
  }

  finish() {
    return Uint8Array.from(this.bytes);
  }
}

class ByteReader {
  constructor(bytes) {
    this.bytes = bytes;
    this.offset = 0;
  }

  need(length) {
    if (this.offset + length > this.bytes.length) fail("INVALID_TOKEN", "The authenticated token is truncated.");
  }

  u8() {
    this.need(1);
    return this.bytes[this.offset++];
  }

  u16() {
    this.need(2);
    const value = this.bytes[this.offset] * 0x100 + this.bytes[this.offset + 1];
    this.offset += 2;
    return value;
  }

  u32() {
    this.need(4);
    const value =
      this.bytes[this.offset] * 0x1000000 +
      this.bytes[this.offset + 1] * 0x10000 +
      this.bytes[this.offset + 2] * 0x100 +
      this.bytes[this.offset + 3];
    this.offset += 4;
    return value;
  }

  take(length) {
    this.need(length);
    const value = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }
}

function ipv4Bytes(address) {
  if (typeof address !== "string") fail("INVALID_CANDIDATE", "Candidate address must be text.");
  const parts = address.split(".");
  if (parts.length !== 4) fail("INVALID_CANDIDATE", "The candidate is not a valid IPv4 address.");
  return Uint8Array.from(
    parts.map((part) => {
      if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) fail("INVALID_CANDIDATE", "The candidate is not canonical IPv4.");
      const value = Number(part);
      if (value > 255) fail("INVALID_CANDIDATE", "The candidate is not a valid IPv4 address.");
      return value;
    }),
  );
}

function ipv4Text(bytes) {
  return [...bytes].join(".");
}

function ipv6Bytes(address) {
  if (typeof address !== "string" || !address || address.includes("%")) {
    fail("INVALID_CANDIDATE", "IPv6 zone identifiers and empty addresses are not supported.");
  }
  let source = address.toLowerCase();
  if (source.includes(".")) {
    const separator = source.lastIndexOf(":");
    if (separator < 0) fail("INVALID_CANDIDATE", "The candidate is not a valid IPv6 address.");
    const ipv4 = ipv4Bytes(source.slice(separator + 1));
    source = `${source.slice(0, separator)}:${((ipv4[0] << 8) | ipv4[1]).toString(16)}:${((ipv4[2] << 8) | ipv4[3]).toString(16)}`;
  }
  const halves = source.split("::");
  if (halves.length > 2) fail("INVALID_CANDIDATE", "The candidate is not a valid IPv6 address.");
  const parseHalf = (half) => {
    if (!half) return [];
    const groups = half.split(":");
    for (const group of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(group)) fail("INVALID_CANDIDATE", "The candidate is not a valid IPv6 address.");
    }
    return groups.map((group) => Number.parseInt(group, 16));
  };
  const left = parseHalf(halves[0]);
  const right = parseHalf(halves.length === 2 ? halves[1] : "");
  let groups;
  if (halves.length === 1) {
    if (left.length !== 8) fail("INVALID_CANDIDATE", "An uncompressed IPv6 address must contain eight groups.");
    groups = left;
  } else {
    if (left.length + right.length >= 8) fail("INVALID_CANDIDATE", "IPv6 :: must replace at least one group.");
    groups = [...left, ...Array(8 - left.length - right.length).fill(0), ...right];
  }
  const bytes = new Uint8Array(16);
  groups.forEach((group, index) => {
    bytes[index * 2] = group >>> 8;
    bytes[index * 2 + 1] = group & 0xff;
  });
  return bytes;
}

function ipv6Text(bytes) {
  const groups = [];
  for (let offset = 0; offset < 16; offset += 2) groups.push((bytes[offset] * 0x100 + bytes[offset + 1]).toString(16));
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < groups.length; ) {
    if (groups[start] !== "0") {
      start += 1;
      continue;
    }
    let end = start;
    while (end < groups.length && groups[end] === "0") end += 1;
    if (end - start > bestLength && end - start >= 2) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  if (bestStart < 0) return groups.join(":");
  const left = groups.slice(0, bestStart).join(":");
  const right = groups.slice(bestStart + bestLength).join(":");
  if (!left && !right) return "::";
  if (!left) return `::${right}`;
  if (!right) return `${left}::`;
  return `${left}::${right}`;
}

function addressBytes(address, family) {
  return family === CANDIDATE_FAMILY.ipv4 ? ipv4Bytes(address) : ipv6Bytes(address);
}

function addressText(bytes, family) {
  return family === CANDIDATE_FAMILY.ipv4 ? ipv4Text(bytes) : ipv6Text(bytes);
}

export function normalizeRendezvousCandidate(candidate) {
  const input = requireObject(candidate, "candidate");
  const inferredFamily = typeof input.address === "string" && input.address.includes(":") ? "ipv6" : "ipv4";
  const family = enumValue(input.family ?? inferredFamily, CANDIDATE_FAMILY, FAMILY_NAME, "candidate.family", true);
  const protocol = enumValue(String(input.protocol ?? "").toLowerCase(), CANDIDATE_PROTOCOL, PROTOCOL_NAME, "candidate.protocol", true);
  const type = enumValue(String(input.type ?? "").toLowerCase(), CANDIDATE_TYPE, CANDIDATE_TYPE_NAME, "candidate.type", true);
  const rawTcpType = input.tcpType == null ? "none" : String(input.tcpType).toLowerCase();
  const tcpType = enumValue(rawTcpType, TCP_TYPE, TCP_TYPE_NAME, "candidate.tcpType", true);
  if (protocol === CANDIDATE_PROTOCOL.udp && tcpType !== TCP_TYPE.none) {
    fail("INVALID_CANDIDATE", "UDP candidates cannot carry tcptype.");
  }
  if (protocol === CANDIDATE_PROTOCOL.tcp && tcpType === TCP_TYPE.none) {
    fail("INVALID_CANDIDATE", "TCP candidates must carry active, passive, or so tcptype.");
  }
  const bytes = addressBytes(input.address, family);
  const priority = uint(input.priority, 0x7fffffff, "candidate.priority");
  if (priority === 0) fail("INVALID_CANDIDATE", "Candidate priority must be positive.");
  const port = uint(input.port, 0xffff, "candidate.port");
  if (port === 0) fail("INVALID_CANDIDATE", "Candidate port zero is not valid.");
  return Object.freeze({
    family: FAMILY_NAME[family],
    protocol: PROTOCOL_NAME[protocol],
    type: CANDIDATE_TYPE_NAME[type],
    tcpType: tcpType === TCP_TYPE.none ? null : TCP_TYPE_NAME[tcpType],
    priority,
    address: addressText(bytes, family),
    port,
  });
}

export function parseSdpCandidate(value) {
  if (typeof value !== "string") fail("INVALID_CANDIDATE", "The SDP candidate must be text.");
  const source = value.trim().replace(/^a=/i, "");
  const fields = source.split(/\s+/);
  if (fields.length < 8 || !/^candidate:[A-Za-z0-9+/]{1,32}$/i.test(fields[0])) {
    fail("INVALID_CANDIDATE", "The SDP candidate has an invalid foundation.");
  }
  if (fields[1] !== "1") fail("INVALID_CANDIDATE", "Only RTP component 1 candidates are supported.");
  if (!/^[0-9]+$/.test(fields[3]) || !/^[0-9]+$/.test(fields[5]) || fields[6].toLowerCase() !== "typ") {
    fail("INVALID_CANDIDATE", "The SDP candidate has invalid numeric fields or lacks typ.");
  }
  let tcpType = null;
  for (let index = 8; index + 1 < fields.length; index += 2) {
    if (fields[index].toLowerCase() === "tcptype") tcpType = fields[index + 1].toLowerCase();
  }
  return normalizeRendezvousCandidate({
    protocol: fields[2].toLowerCase(),
    priority: Number(fields[3]),
    address: fields[4],
    port: Number(fields[5]),
    type: fields[7].toLowerCase(),
    tcpType,
  });
}

export function formatSdpCandidate(candidate, options = {}) {
  const value = normalizeRendezvousCandidate(candidate);
  const foundation = String(options.foundation ?? "1");
  if (!/^[A-Za-z0-9+/]{1,32}$/.test(foundation)) fail("INVALID_CANDIDATE", "Candidate foundation is invalid.");
  const parts = [
    `candidate:${foundation}`,
    "1",
    value.protocol,
    String(value.priority),
    value.address,
    String(value.port),
    "typ",
    value.type,
  ];
  if (value.type !== "host") {
    parts.push("raddr", value.family === "ipv4" ? "0.0.0.0" : "::", "rport", "9");
  }
  if (value.tcpType) parts.push("tcptype", value.tcpType);
  return parts.join(" ");
}

function fingerprintBytes(value) {
  const source = String(value ?? "");
  if (!/^(?:[0-9a-fA-F]{64}|(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2})$/.test(source)) {
    fail("INVALID_FIELD", "ice.fingerprint must be a canonical SHA-256 fingerprint.");
  }
  const compact = source.replace(/:/g, "").toLowerCase();
  return exactHex(compact, 32, "ice.fingerprint");
}

function fingerprintText(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0").toUpperCase()).join(":");
}

function normalizeToken(token) {
  const input = requireObject(token, "token");
  if (input.version != null && input.version !== RENDEZVOUS_V2.version) {
    fail("INVALID_FIELD", "Only rendezvous token version 2 can be encoded.");
  }
  const profile = enumValue(input.profile, RENDEZVOUS_PROFILE, PROFILE_NAME, "profile");
  const role = enumValue(input.role, RENDEZVOUS_ROLE, ROLE_NAME, "role");
  const referenceRole = input.referenceRole == null
    ? 0
    : enumValue(input.referenceRole, RENDEZVOUS_ROLE, ROLE_NAME, "referenceRole");
  const lifetimeSeconds = uint(input.lifetimeSeconds, RENDEZVOUS_V2.maxLifetimeSeconds, "lifetimeSeconds");
  if (lifetimeSeconds < RENDEZVOUS_V2.minLifetimeSeconds) {
    fail("INVALID_FIELD", `lifetimeSeconds must be at least ${RENDEZVOUS_V2.minLifetimeSeconds}.`);
  }
  const issuedAt = uint(input.issuedAt, 0xffffffff, "issuedAt");
  const attemptIdBytes = exactHex(input.attemptId, 16, "attemptId");
  const contextIdBytes = exactHex(input.contextId, 12, "contextId");
  const fromBytes = exactHex(input.from, 8, "from");
  const toBytes = exactHex(input.to, 8, "to");
  const from = bytesToHex(fromBytes);
  const to = bytesToHex(toBytes);
  if (bytesToHex(attemptIdBytes) === "0".repeat(32)) fail("INVALID_FIELD", "attemptId cannot be all zeroes.");
  if (bytesToHex(contextIdBytes) === "0".repeat(24)) fail("INVALID_FIELD", "contextId cannot be all zeroes.");
  if (from === RENDEZVOUS_V2.broadcastId) fail("INVALID_FIELD", "from cannot be the broadcast identifier.");
  if (from === to) fail("INVALID_FIELD", "from and to must identify different peers.");
  if (to === RENDEZVOUS_V2.broadcastId && !(profile === RENDEZVOUS_PROFILE.bootstrap && role === RENDEZVOUS_ROLE.offer)) {
    fail("INVALID_FIELD", "Only a bootstrap offer may use the broadcast recipient.");
  }

  if (input.candidates != null && !Array.isArray(input.candidates)) {
    fail("INVALID_FIELD", "candidates must be an array when present.");
  }
  const candidates = input.candidates == null ? [] : input.candidates.map(normalizeRendezvousCandidate);
  if (candidates.length > 2) fail("INVALID_FIELD", "A rendezvous token can carry at most two candidates.");

  let ice = null;
  if (input.ice != null) {
    const source = requireObject(input.ice, "ice");
    const setup = enumValue(source.setup, RENDEZVOUS_SETUP, SETUP_NAME, "ice.setup");
    if (setup === RENDEZVOUS_SETUP.none) fail("INVALID_FIELD", "An ICE block must carry a DTLS setup role.");
    const ufrag = asciiBytes(
      source.ufrag,
      RENDEZVOUS_V2.minUfragChars,
      RENDEZVOUS_V2.maxUfragChars,
      "ice.ufrag",
      ICE_TEXT,
    );
    const password = asciiBytes(
      source.password,
      RENDEZVOUS_V2.minPasswordChars,
      RENDEZVOUS_V2.maxPasswordChars,
      "ice.password",
      ICE_TEXT,
    );
    ice = Object.freeze({
      setup: SETUP_NAME[setup],
      ufrag: bytesToAscii(ufrag),
      password: bytesToAscii(password),
      fingerprint: fingerprintText(fingerprintBytes(source.fingerprint)),
    });
  }

  validateRoleShape(role, referenceRole, ice, candidates.length);
  return {
    version: RENDEZVOUS_V2.version,
    profile: PROFILE_NAME[profile],
    role: ROLE_NAME[role],
    referenceRole: referenceRole === 0 ? null : ROLE_NAME[referenceRole],
    issuedAt,
    lifetimeSeconds,
    attemptId: bytesToHex(attemptIdBytes),
    contextId: bytesToHex(contextIdBytes),
    from,
    to,
    ice,
    candidates,
  };
}

function validateRoleShape(role, referenceRole, ice, candidateCount) {
  const setup = ice ? RENDEZVOUS_SETUP[ice.setup] : RENDEZVOUS_SETUP.none;
  if (role === RENDEZVOUS_ROLE.offer) {
    if (!ice || setup !== RENDEZVOUS_SETUP.actpass || candidateCount !== 0 || referenceRole !== 0) {
      fail("INVALID_ROLE_SHAPE", "An offer requires actpass ICE data, no candidates, and no reference role.");
    }
    return;
  }
  if (role === RENDEZVOUS_ROLE.answer) {
    if (!ice || ![RENDEZVOUS_SETUP.active, RENDEZVOUS_SETUP.passive].includes(setup) || candidateCount < 1 || referenceRole !== 0) {
      fail("INVALID_ROLE_SHAPE", "An answer requires active/passive ICE data, one or two candidates, and no reference role.");
    }
    return;
  }
  if (role === RENDEZVOUS_ROLE.ack) {
    if (ice || candidateCount !== 0 || ![RENDEZVOUS_ROLE.offer, RENDEZVOUS_ROLE.answer, RENDEZVOUS_ROLE.candidate].includes(referenceRole)) {
      fail("INVALID_ROLE_SHAPE", "An acknowledgement must reference an offer, answer, or candidate and carry no ICE data.");
    }
    return;
  }
  if (role === RENDEZVOUS_ROLE.abort) {
    if (ice || candidateCount !== 0 || ![
      RENDEZVOUS_ROLE.offer,
      RENDEZVOUS_ROLE.answer,
      RENDEZVOUS_ROLE.needCandidate,
      RENDEZVOUS_ROLE.candidate,
    ].includes(referenceRole)) {
      fail("INVALID_ROLE_SHAPE", "An abort must identify the failed phase and carry no ICE data.");
    }
    return;
  }
  if (role === RENDEZVOUS_ROLE.needCandidate) {
    if (ice || candidateCount !== 0 || referenceRole !== RENDEZVOUS_ROLE.offer) {
      fail("INVALID_ROLE_SHAPE", "needCandidate must reference the candidate-free offer.");
    }
    return;
  }
  if (role === RENDEZVOUS_ROLE.candidate) {
    if (ice || candidateCount < 1 || referenceRole !== RENDEZVOUS_ROLE.needCandidate) {
      fail("INVALID_ROLE_SHAPE", "A candidate extension must answer needCandidate with one or two candidates.");
    }
    return;
  }
  fail("INVALID_ROLE_SHAPE", "Unsupported rendezvous role.");
}

function encodeCandidate(writer, candidate) {
  const value = normalizeRendezvousCandidate(candidate);
  const family = CANDIDATE_FAMILY[value.family];
  const protocol = CANDIDATE_PROTOCOL[value.protocol];
  const type = CANDIDATE_TYPE[value.type];
  const tcpType = value.tcpType == null ? TCP_TYPE.none : TCP_TYPE[value.tcpType];
  writer.u8(family | (protocol << 1) | (type << 2) | (tcpType << 4));
  writer.u32(value.priority);
  writer.u16(value.port);
  writer.append(addressBytes(value.address, family));
}

function decodeCandidate(reader) {
  const descriptor = reader.u8();
  if ((descriptor & 0xc0) !== 0) fail("INVALID_TOKEN", "Candidate descriptor reserved bits are set.");
  const family = descriptor & 1;
  const protocol = (descriptor >>> 1) & 1;
  const type = (descriptor >>> 2) & 3;
  const tcpType = (descriptor >>> 4) & 3;
  if (!own(FAMILY_NAME, family) || !own(PROTOCOL_NAME, protocol) || !own(CANDIDATE_TYPE_NAME, type) || !own(TCP_TYPE_NAME, tcpType)) {
    fail("INVALID_TOKEN", "Candidate descriptor contains an unsupported value.");
  }
  const priority = reader.u32();
  const port = reader.u16();
  const address = addressText(reader.take(family === CANDIDATE_FAMILY.ipv4 ? 4 : 16), family);
  return normalizeRendezvousCandidate({
    family: FAMILY_NAME[family],
    protocol: PROTOCOL_NAME[protocol],
    type: CANDIDATE_TYPE_NAME[type],
    tcpType: TCP_TYPE_NAME[tcpType],
    priority,
    address,
    port,
  });
}

function encodeBody(token) {
  const value = normalizeToken(token);
  const profile = RENDEZVOUS_PROFILE[value.profile];
  const role = RENDEZVOUS_ROLE[value.role];
  const referenceRole = value.referenceRole == null ? 0 : RENDEZVOUS_ROLE[value.referenceRole];
  const setup = value.ice == null ? RENDEZVOUS_SETUP.none : RENDEZVOUS_SETUP[value.ice.setup];
  const flags = value.candidates.length | (setup << 2) | (value.ice == null ? 0 : 0x10);
  const writer = new ByteWriter();
  writer.u8(RENDEZVOUS_V2.magic);
  writer.u8(RENDEZVOUS_V2.version);
  writer.u8(profile);
  writer.u8(role);
  writer.u8(flags);
  writer.u8(referenceRole);
  writer.u16(value.lifetimeSeconds);
  writer.u32(value.issuedAt);
  writer.append(exactHex(value.attemptId, 16, "attemptId"));
  writer.append(exactHex(value.contextId, 12, "contextId"));
  writer.append(exactHex(value.from, 8, "from"));
  writer.append(exactHex(value.to, 8, "to"));
  if (value.ice) {
    const ufrag = asciiBytes(
      value.ice.ufrag,
      RENDEZVOUS_V2.minUfragChars,
      RENDEZVOUS_V2.maxUfragChars,
      "ice.ufrag",
      ICE_TEXT,
    );
    const password = asciiBytes(
      value.ice.password,
      RENDEZVOUS_V2.minPasswordChars,
      RENDEZVOUS_V2.maxPasswordChars,
      "ice.password",
      ICE_TEXT,
    );
    writer.u8(ufrag.length);
    writer.u8(password.length);
    writer.append(ufrag);
    writer.append(password);
    writer.append(fingerprintBytes(value.ice.fingerprint));
  }
  value.candidates.forEach((candidate) => encodeCandidate(writer, candidate));
  const body = writer.finish();
  if (body.length > RENDEZVOUS_V2.maxBodyBytes) {
    fail(
      "TOKEN_TOO_LARGE",
      `The canonical body is ${body.length} bytes; the mailbox limit permits ${RENDEZVOUS_V2.maxBodyBytes}.`,
    );
  }
  return { body, value };
}

function decodeBody(body) {
  if (body.length < RENDEZVOUS_V2.fixedBodyBytes || body.length > RENDEZVOUS_V2.maxBodyBytes) {
    fail("INVALID_TOKEN", "The authenticated token body has an invalid length.");
  }
  const reader = new ByteReader(body);
  if (reader.u8() !== RENDEZVOUS_V2.magic || reader.u8() !== RENDEZVOUS_V2.version) {
    fail("INVALID_TOKEN", "The authenticated token has an unsupported magic or version.");
  }
  const profile = reader.u8();
  const role = reader.u8();
  const flags = reader.u8();
  const referenceRole = reader.u8();
  if ((flags & 0xe0) !== 0) fail("INVALID_TOKEN", "Token flag reserved bits are set.");
  const candidateCount = flags & 3;
  const setup = (flags >>> 2) & 3;
  const hasIce = Boolean(flags & 0x10);
  if (candidateCount === 3 || !own(PROFILE_NAME, profile) || !own(ROLE_NAME, role) || !own(SETUP_NAME, setup)) {
    fail("INVALID_TOKEN", "The authenticated token contains an unsupported enum value.");
  }
  if (referenceRole !== 0 && !own(ROLE_NAME, referenceRole)) fail("INVALID_TOKEN", "referenceRole is invalid.");
  const lifetimeSeconds = reader.u16();
  const issuedAt = reader.u32();
  const attemptId = bytesToHex(reader.take(16));
  const contextId = bytesToHex(reader.take(12));
  const from = bytesToHex(reader.take(8));
  const to = bytesToHex(reader.take(8));
  let ice = null;
  if (hasIce) {
    const ufragLength = reader.u8();
    const passwordLength = reader.u8();
    const ufrag = bytesToAscii(reader.take(ufragLength));
    const password = bytesToAscii(reader.take(passwordLength));
    ice = {
      setup: SETUP_NAME[setup],
      ufrag,
      password,
      fingerprint: fingerprintText(reader.take(32)),
    };
  } else if (setup !== RENDEZVOUS_SETUP.none) {
    fail("INVALID_TOKEN", "A token without ICE data cannot carry a DTLS setup role.");
  }
  const candidates = [];
  for (let index = 0; index < candidateCount; index += 1) candidates.push(decodeCandidate(reader));
  if (reader.offset !== body.length) fail("INVALID_TOKEN", "The authenticated token has trailing bytes.");
  return normalizeToken({
    version: RENDEZVOUS_V2.version,
    profile: PROFILE_NAME[profile],
    role: ROLE_NAME[role],
    referenceRole: referenceRole === 0 ? null : ROLE_NAME[referenceRole],
    issuedAt,
    lifetimeSeconds,
    attemptId,
    contextId,
    from,
    to,
    ice,
    candidates,
  });
}

function subtleCrypto(value) {
  const subtle = value ?? globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.importKey !== "function" || typeof subtle.sign !== "function") {
    fail("CRYPTO_UNAVAILABLE", "Web Crypto SubtleCrypto is required.");
  }
  return subtle;
}

function digestCrypto(value) {
  const subtle = value ?? globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.digest !== "function") {
    fail("CRYPTO_UNAVAILABLE", "Web Crypto SubtleCrypto.digest is required.");
  }
  return subtle;
}

export async function deriveRendezvousV2RoomContextId(roomId, options = {}) {
  const canonicalRoomId = bytesToHex(exactHex(roomId, 12, "roomId"));
  if (canonicalRoomId === "0".repeat(24)) fail("INVALID_FIELD", "roomId cannot be all zeroes.");
  const roomBytes = Uint8Array.from(canonicalRoomId, (character) => character.charCodeAt(0));
  const digest = new Uint8Array(
    await digestCrypto(options.subtle).digest("SHA-256", concatBytes(ROOM_CONTEXT, roomBytes)),
  );
  return bytesToHex(digest.slice(0, 12));
}

function isHmacCryptoKey(value) {
  return Boolean(
    value &&
    typeof value === "object" &&
    value.type === "secret" &&
    String(value.algorithm?.name).toUpperCase() === "HMAC" &&
    String(value.algorithm?.hash?.name).toUpperCase() === "SHA-256" &&
    Number.isSafeInteger(value.algorithm?.length) &&
    value.algorithm.length >= 128 && value.algorithm.length <= 512 &&
    Array.isArray(value.usages) &&
    value.usages.includes("sign"),
  );
}

async function signingKey(key, subtle) {
  if (isHmacCryptoKey(key)) return key;
  const bytes = copyBytes(key, "key");
  if (bytes.length < 16 || bytes.length > 64) fail("INVALID_KEY", "The raw HMAC key must contain 16-64 bytes.");
  return subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

async function hmacTag(body, key, subtle) {
  const imported = await signingKey(key, subtle);
  const signature = new Uint8Array(await subtle.sign("HMAC", imported, concatBytes(MAC_CONTEXT, body)));
  return signature.slice(0, RENDEZVOUS_V2.tagBytes);
}

function constantTimeEqual(left, right) {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (left[index % left.length] ?? 0) ^ (right[index % right.length] ?? 0);
  }
  return difference === 0;
}

export function measureRendezvousV2Token(token) {
  const { body } = encodeBody(token);
  const tokenBytes = body.length + RENDEZVOUS_V2.tagBytes;
  const wireChars = RENDEZVOUS_V2.wirePrefix.length + base64UrlLength(tokenBytes);
  return Object.freeze({
    bodyBytes: body.length,
    tagBytes: RENDEZVOUS_V2.tagBytes,
    tokenBytes,
    wireChars,
    remainingWireChars: RENDEZVOUS_V2.maxWireChars - wireChars,
  });
}

export async function encodeAndSignRendezvousV2Bytes(token, key, options = {}) {
  const { body } = encodeBody(token);
  const subtle = subtleCrypto(options.subtle);
  const tag = await hmacTag(body, key, subtle);
  const raw = concatBytes(body, tag);
  if (raw.length > RENDEZVOUS_V2.maxTokenBytes) fail("TOKEN_TOO_LARGE", "The authenticated token exceeds the mailbox limit.");
  return raw;
}

export async function encodeAndSignRendezvousV2Token(token, key, options = {}) {
  const raw = await encodeAndSignRendezvousV2Bytes(token, key, options);
  const wire = rendezvousV2BytesToText(raw);
  if (wire.length > RENDEZVOUS_V2.maxWireChars) fail("TOKEN_TOO_LARGE", "The encoded token exceeds the mailbox limit.");
  return wire;
}

function expectedEnum(value, values, names, field) {
  return value == null ? null : enumValue(value, values, names, field);
}

function requireExpectedMatch(token, options) {
  const profile = expectedEnum(options.expectedProfile, RENDEZVOUS_PROFILE, PROFILE_NAME, "expectedProfile");
  const role = expectedEnum(options.expectedRole, RENDEZVOUS_ROLE, ROLE_NAME, "expectedRole");
  const expectedAttemptId = options.expectedAttemptId == null
    ? null
    : bytesToHex(exactHex(options.expectedAttemptId, 16, "expectedAttemptId"));
  const expectedContextId = options.expectedContextId == null
    ? null
    : bytesToHex(exactHex(options.expectedContextId, 12, "expectedContextId"));
  const expectedFrom = options.expectedFrom == null ? null : bytesToHex(exactHex(options.expectedFrom, 8, "expectedFrom"));
  const expectedTo = options.expectedTo == null ? null : bytesToHex(exactHex(options.expectedTo, 8, "expectedTo"));
  if (
    (profile != null && RENDEZVOUS_PROFILE[token.profile] !== profile) ||
    (role != null && RENDEZVOUS_ROLE[token.role] !== role) ||
    (expectedAttemptId != null && token.attemptId !== expectedAttemptId) ||
    (expectedContextId != null && token.contextId !== expectedContextId) ||
    (expectedFrom != null && token.from !== expectedFrom) ||
    (expectedTo != null && token.to !== expectedTo)
  ) {
    fail("CONTEXT_MISMATCH", "The authenticated token does not match the expected routing context.");
  }
}

export function rendezvousV2BytesToText(value) {
  const raw = copyBytes(value, "token bytes", "INVALID_WIRE");
  if (raw.length < RENDEZVOUS_V2.fixedBodyBytes + RENDEZVOUS_V2.tagBytes || raw.length > RENDEZVOUS_V2.maxTokenBytes) {
    fail("INVALID_WIRE", "The rendezvous token has an invalid byte length.");
  }
  return RENDEZVOUS_V2.wirePrefix + base64UrlEncode(raw);
}

export function rendezvousV2TextToBytes(wire) {
  if (typeof wire !== "string" || wire.length > RENDEZVOUS_V2.maxWireChars || !wire.startsWith(RENDEZVOUS_V2.wirePrefix)) {
    fail("INVALID_WIRE", "The rendezvous token has an invalid prefix or length.");
  }
  const raw = base64UrlDecode(wire.slice(RENDEZVOUS_V2.wirePrefix.length));
  if (raw.length < RENDEZVOUS_V2.fixedBodyBytes + RENDEZVOUS_V2.tagBytes || raw.length > RENDEZVOUS_V2.maxTokenBytes) {
    fail("INVALID_WIRE", "The rendezvous token has an invalid byte length.");
  }
  return raw;
}

export async function verifyAndDecodeRendezvousV2Bytes(value, key, options = {}) {
  const raw = copyBytes(value, "token bytes", "INVALID_WIRE");
  if (raw.length < RENDEZVOUS_V2.fixedBodyBytes + RENDEZVOUS_V2.tagBytes || raw.length > RENDEZVOUS_V2.maxTokenBytes) {
    fail("INVALID_WIRE", "The rendezvous token has an invalid byte length.");
  }
  const body = raw.slice(0, -RENDEZVOUS_V2.tagBytes);
  const suppliedTag = raw.slice(-RENDEZVOUS_V2.tagBytes);
  const subtle = subtleCrypto(options.subtle);
  const calculatedTag = await hmacTag(body, key, subtle);
  if (!constantTimeEqual(suppliedTag, calculatedTag)) fail("AUTH_FAILED", "Rendezvous token authentication failed.");

  // No field from the token is parsed or returned before the MAC succeeds.
  const token = decodeBody(body);
  const nowSeconds = uint(options.nowSeconds, 0xffffffff, "nowSeconds");
  const clockSkewSeconds = options.maxClockSkewSeconds == null
    ? RENDEZVOUS_V2.defaultClockSkewSeconds
    : uint(options.maxClockSkewSeconds, RENDEZVOUS_V2.maxClockSkewSeconds, "maxClockSkewSeconds");
  if (token.issuedAt > nowSeconds + clockSkewSeconds) fail("NOT_YET_VALID", "The authenticated token is too far in the future.");
  if (nowSeconds >= token.issuedAt + token.lifetimeSeconds + clockSkewSeconds) fail("EXPIRED", "The authenticated token has expired.");
  requireExpectedMatch(token, options);
  return Object.freeze({
    ...token,
    expiresAtSeconds: token.issuedAt + token.lifetimeSeconds,
    ice: token.ice == null ? null : Object.freeze({ ...token.ice }),
    candidates: Object.freeze(token.candidates.map((candidate) => Object.freeze({ ...candidate }))),
  });
}

export async function verifyAndDecodeRendezvousV2Token(wire, key, options = {}) {
  return verifyAndDecodeRendezvousV2Bytes(rendezvousV2TextToBytes(wire), key, options);
}

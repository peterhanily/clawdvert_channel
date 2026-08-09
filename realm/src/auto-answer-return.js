/*
 * Encrypted, one-way return of a manual pairing answer over rr2.
 *
 * The ordinary CC2 offer remains the bearer invitation. Its optional
 * descriptor is bound to the exact offer and invitation metadata, expires in
 * at most five minutes, and derives invitation-specific HMAC, AES-GCM, and rr2
 * room material. This module does not decide when ICE candidates are applied:
 * the host must verify and apply the answer before acknowledging its rr2 slot.
 */

import {
  RENDEZVOUS_V2,
  encodeAndSignRendezvousV2Bytes,
  verifyAndDecodeRendezvousV2Bytes,
} from "./rendezvous-v2-codec.js";
import {
  buildRendezvousDataChannelSdp,
  extractRendezvousIce,
  selectRendezvousCandidates,
} from "./rendezvous-v2-sdp.js";

const DEVICE = /^(?!0{16}$)[a-f0-9]{16}$/;
const ROOM = /^(?!0{24}$)[a-f0-9]{24}$/;
const SESSION = /^(?!0{20}$)[a-f0-9]{20}$/;
const INVITE = /^(?!0{16}$)[a-f0-9]{16}$/;
const ATTEMPT = /^(?!0{32}$)[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const APP = /^[A-Za-z0-9._-]{1,64}$/;
const HOST_ROUTE = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;
const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const TEXT = new TextEncoder();
const DESCRIPTOR_FIELDS = new Set([
  "version", "transport", "app", "roomId", "session", "inviteId", "host",
  "hostRoute", "offerSha256", "expiresAt", "attemptId", "secret", "bindingSha256",
]);
const BINDING_DOMAIN = "clawdvert/auto-answer-return/v1/invite-binding\0";
const KEY_DOMAIN = "clawdvert/auto-answer-return/v1/";
const WRAPPER_DOMAIN = TEXT.encode("clawdvert/auto-answer-return/v1/wrapper\0");
const WRAP_MAGIC = 0xa1;
const NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;
const MIN_TOKEN_BYTES = RENDEZVOUS_V2.fixedBodyBytes + RENDEZVOUS_V2.tagBytes;
const MAX_WRAPPED_BYTES = 1 + NONCE_BYTES + RENDEZVOUS_V2.maxTokenBytes + GCM_TAG_BYTES;

export const AUTO_ANSWER_RETURN = Object.freeze({
  version: 1,
  transport: "rr2",
  defaultHostRoute: "canary-v1",
  secretBytes: 32,
  maxLifetimeMs: 5 * 60 * 1000,
  defaultTokenLifetimeSeconds: 240,
  maxWrappedBytes: MAX_WRAPPED_BYTES,
});

export class AutoAnswerReturnError extends Error {
  constructor(code, message, cause = null) {
    super(message, cause ? { cause } : undefined);
    this.name = "AutoAnswerReturnError";
    this.code = code;
  }
}

function fail(code, message, cause = null) {
  throw new AutoAnswerReturnError(code, message, cause);
}

function requireCondition(condition, code, message) {
  if (!condition) fail(code, message);
}

function bytes(value, field) {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  fail("INVALID_FIELD", `${field} must be bytes.`);
}

function concat(...parts) {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function toHex(value) {
  return [...value].map(octet => octet.toString(16).padStart(2, "0")).join("");
}

function hexBytes(value, pattern, field, code = "INVALID_DESCRIPTOR") {
  const text = String(value ?? "").toLowerCase();
  requireCondition(pattern.test(text), code, `${field} is invalid.`);
  const output = new Uint8Array(text.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

function encodeBase64Url(input) {
  const value = bytes(input, "base64url input");
  let output = "";
  for (let index = 0; index < value.length; index += 3) {
    const count = Math.min(3, value.length - index);
    const word = (value[index] << 16)
      | ((value[index + 1] || 0) << 8)
      | (value[index + 2] || 0);
    output += BASE64URL[(word >>> 18) & 63] + BASE64URL[(word >>> 12) & 63];
    if (count > 1) output += BASE64URL[(word >>> 6) & 63];
    if (count > 2) output += BASE64URL[word & 63];
  }
  return output;
}

function decodeSecret(value) {
  const source = String(value ?? "");
  requireCondition(source.length > 0 && source.length % 4 !== 1
    && /^[A-Za-z0-9_-]+$/.test(source), "INVALID_DESCRIPTOR",
  "The automatic-answer secret is not canonical base64url.");
  const output = new Uint8Array(Math.floor(source.length * 6 / 8));
  let accumulator = 0;
  let available = 0;
  let at = 0;
  for (const character of source) {
    accumulator = (accumulator << 6) | BASE64URL.indexOf(character);
    available += 6;
    if (available >= 8) {
      available -= 8;
      output[at++] = (accumulator >>> available) & 0xff;
    }
  }
  requireCondition(output.length === AUTO_ANSWER_RETURN.secretBytes
    && encodeBase64Url(output) === source && output.some(octet => octet !== 0),
  "INVALID_DESCRIPTOR", "The automatic-answer secret must be 32 non-zero bytes.");
  return output;
}

function cryptoSource(crypto) {
  requireCondition(crypto && typeof crypto.getRandomValues === "function",
    "CRYPTO_UNAVAILABLE", "Web Crypto random generation is required.");
  return crypto;
}

function subtleCrypto(subtle) {
  const value = subtle ?? globalThis.crypto?.subtle;
  requireCondition(value && typeof value.digest === "function"
    && typeof value.importKey === "function" && typeof value.deriveBits === "function"
    && typeof value.encrypt === "function" && typeof value.decrypt === "function",
  "CRYPTO_UNAVAILABLE", "Web Crypto SHA-256, HKDF, and AES-GCM are required.");
  return value;
}

function random(length, crypto) {
  const output = new Uint8Array(length);
  cryptoSource(crypto).getRandomValues(output);
  return output;
}

async function sha256(value, subtle) {
  return new Uint8Array(await subtleCrypto(subtle).digest("SHA-256", value));
}

function parseDescriptor(input) {
  requireCondition(input && typeof input === "object" && !Array.isArray(input),
    "INVALID_DESCRIPTOR", "The automatic-answer descriptor must be an object.");
  requireCondition(Object.keys(input).length === DESCRIPTOR_FIELDS.size
    && Object.keys(input).every(field => DESCRIPTOR_FIELDS.has(field)),
  "INVALID_DESCRIPTOR", "The automatic-answer descriptor has unknown or missing fields.");
  requireCondition(input.version === AUTO_ANSWER_RETURN.version
    && input.transport === AUTO_ANSWER_RETURN.transport,
  "INVALID_DESCRIPTOR", "The automatic-answer descriptor version is unsupported.");
  const descriptor = {
    version: input.version,
    transport: input.transport,
    app: String(input.app ?? ""),
    roomId: String(input.roomId ?? "").toLowerCase(),
    session: String(input.session ?? "").toLowerCase(),
    inviteId: String(input.inviteId ?? "").toLowerCase(),
    host: String(input.host ?? "").toLowerCase(),
    hostRoute: String(input.hostRoute ?? ""),
    offerSha256: String(input.offerSha256 ?? "").toLowerCase(),
    expiresAt: Number(input.expiresAt),
    attemptId: String(input.attemptId ?? "").toLowerCase(),
    secret: String(input.secret ?? ""),
    bindingSha256: String(input.bindingSha256 ?? "").toLowerCase(),
  };
  requireCondition(APP.test(descriptor.app), "INVALID_DESCRIPTOR", "app is invalid.");
  hexBytes(descriptor.roomId, ROOM, "roomId");
  hexBytes(descriptor.session, SESSION, "session");
  hexBytes(descriptor.inviteId, INVITE, "inviteId");
  hexBytes(descriptor.host, DEVICE, "host");
  requireCondition(HOST_ROUTE.test(descriptor.hostRoute), "INVALID_DESCRIPTOR",
    "hostRoute is invalid.");
  hexBytes(descriptor.offerSha256, HASH, "offerSha256");
  requireCondition(Number.isSafeInteger(descriptor.expiresAt) && descriptor.expiresAt > 0,
    "INVALID_DESCRIPTOR", "expiresAt must be an absolute millisecond timestamp.");
  hexBytes(descriptor.attemptId, ATTEMPT, "attemptId");
  decodeSecret(descriptor.secret);
  hexBytes(descriptor.bindingSha256, HASH, "bindingSha256");
  return Object.freeze(descriptor);
}

function bindingText(descriptor) {
  return JSON.stringify([
    BINDING_DOMAIN,
    descriptor.version,
    descriptor.transport,
    descriptor.app,
    descriptor.roomId,
    descriptor.session,
    descriptor.inviteId,
    descriptor.host,
    descriptor.hostRoute,
    descriptor.offerSha256,
    descriptor.expiresAt,
    descriptor.attemptId,
    descriptor.secret,
  ]);
}

function checkExpected(descriptor, expected) {
  if (expected == null) return;
  requireCondition(expected && typeof expected === "object" && !Array.isArray(expected),
    "WRONG_BINDING", "Expected invitation metadata must be an object.");
  for (const field of ["app", "roomId", "session", "inviteId", "host", "hostRoute", "expiresAt"]) {
    if (expected[field] === undefined) continue;
    const value = field === "expiresAt" ? Number(expected[field]) : String(expected[field]);
    requireCondition(value === descriptor[field], "WRONG_BINDING",
      `The automatic-answer descriptor does not match invite ${field}.`);
  }
}

/** Create a descriptor after the browser has produced the exact offer SDP. */
export async function createAutoAnswerInviteDescriptor({
  app,
  roomId,
  session,
  inviteId,
  host,
  hostRoute = AUTO_ANSWER_RETURN.defaultHostRoute,
  offerSdp,
  expiresAt,
  nowMs = Date.now(),
  crypto = globalThis.crypto,
  subtle,
}) {
  requireCondition(typeof offerSdp === "string" && offerSdp.startsWith("v=0"),
    "INVALID_DESCRIPTOR", "The exact WebRTC offer SDP is required.");
  requireCondition(Number.isSafeInteger(nowMs) && Number.isSafeInteger(expiresAt)
    && expiresAt > nowMs && expiresAt - nowMs <= AUTO_ANSWER_RETURN.maxLifetimeMs,
  "INVALID_EXPIRY", "Automatic answer return must expire within five minutes.");
  const draft = {
    version: AUTO_ANSWER_RETURN.version,
    transport: AUTO_ANSWER_RETURN.transport,
    app,
    roomId,
    session,
    inviteId,
    host,
    hostRoute,
    offerSha256: toHex(await sha256(TEXT.encode(offerSdp), subtle)),
    expiresAt,
    attemptId: toHex(random(16, crypto)),
    secret: encodeBase64Url(random(AUTO_ANSWER_RETURN.secretBytes, crypto)),
    bindingSha256: "0".repeat(64),
  };
  const shaped = parseDescriptor(draft);
  draft.bindingSha256 = toHex(await sha256(TEXT.encode(bindingText(shaped)), subtle));
  return parseDescriptor(draft);
}

/** Validate structure, absolute expiry, outer invite fields, exact SDP, and binding hash. */
export async function validateAutoAnswerInviteDescriptor(input, {
  offerSdp,
  expected = null,
  nowMs = Date.now(),
  subtle,
} = {}) {
  const descriptor = parseDescriptor(input);
  requireCondition(Number.isSafeInteger(nowMs) && descriptor.expiresAt > nowMs
    && descriptor.expiresAt - nowMs <= AUTO_ANSWER_RETURN.maxLifetimeMs,
  "EXPIRED", "The automatic-answer descriptor is expired or too far in the future.");
  requireCondition(typeof offerSdp === "string" && offerSdp.startsWith("v=0"),
    "WRONG_BINDING", "The exact invitation offer SDP is required for validation.");
  checkExpected(descriptor, expected);
  const offerHash = toHex(await sha256(TEXT.encode(offerSdp), subtle));
  requireCondition(offerHash === descriptor.offerSha256, "WRONG_BINDING",
    "The automatic-answer descriptor belongs to another WebRTC offer.");
  const bindingHash = toHex(await sha256(TEXT.encode(bindingText(descriptor)), subtle));
  requireCondition(bindingHash === descriptor.bindingSha256, "WRONG_BINDING",
    "The automatic-answer invitation binding is invalid.");
  return descriptor;
}

/** Derive independent non-extractable token/wrapping keys and a private rr2 room. */
export async function deriveAutoAnswerReturnKeys(input, options = {}) {
  const descriptor = await validateAutoAnswerInviteDescriptor(input, options);
  const subtle = subtleCrypto(options.subtle);
  const salt = concat(
    hexBytes(descriptor.bindingSha256, HASH, "bindingSha256"),
    hexBytes(descriptor.attemptId, ATTEMPT, "attemptId"),
  );
  const ikm = await subtle.importKey("raw", decodeSecret(descriptor.secret),
    "HKDF", false, ["deriveBits"]);
  const derive = async (purpose, bits) => new Uint8Array(await subtle.deriveBits({
    name: "HKDF",
    hash: "SHA-256",
    salt,
    info: TEXT.encode(`${KEY_DOMAIN}${purpose}\0${descriptor.hostRoute}`),
  }, ikm, bits));
  const [tokenBytes, wrappingBytes, roomBytes] = await Promise.all([
    derive("token-key", 256), derive("wrap-key", 256), derive("relay-room", 128),
  ]);
  const [tokenKey, wrappingKey] = await Promise.all([
    subtle.importKey("raw", tokenBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    subtle.importKey("raw", wrappingBytes, "AES-GCM", false, ["encrypt", "decrypt"]),
  ]);
  return Object.freeze({
    descriptor,
    contextId: descriptor.bindingSha256.slice(0, 24),
    tokenKey,
    wrappingKey,
    relayRoom: `cv${toHex(roomBytes)}`,
  });
}

function keyMaterial(keys, descriptor) {
  requireCondition(keys?.tokenKey && keys?.wrappingKey && keys?.contextId,
    "INVALID_KEY", "Validated automatic-answer key material is required.");
  const bound = parseDescriptor(keys.descriptor);
  requireCondition(DESCRIPTOR_FIELDS.size === Object.keys(descriptor).length
    && [...DESCRIPTOR_FIELDS].every(field => bound[field] === descriptor[field]),
  "INVALID_KEY", "The automatic-answer keys belong to another invitation.");
  return keys;
}

function answerRoute(input, descriptor, requireRevision = false) {
  requireCondition(input && typeof input === "object", "INVALID_RECEIPT",
    "An rr2 answer route is required.");
  const from = String(input.from ?? "").toLowerCase();
  const to = String(input.to ?? "").toLowerCase();
  const attemptId = String(input.attemptId ?? input.attempt ?? "").toLowerCase();
  requireCondition(DEVICE.test(from) && to === descriptor.host && from !== to,
    "INVALID_RECEIPT", "The rr2 answer route has invalid device selectors.");
  requireCondition(attemptId === descriptor.attemptId,
    "INVALID_RECEIPT", "The rr2 answer belongs to another invitation attempt.");
  requireCondition(input.role === "answer" || input.role === "a",
    "INVALID_RECEIPT", "The rr2 receipt is not an answer slot.");
  const revision = requireRevision ? Number(input.revision) : null;
  if (requireRevision) {
    requireCondition(Number.isSafeInteger(revision) && revision >= 1 && revision <= 0xffffffff,
      "INVALID_RECEIPT", "The rr2 answer revision is invalid.");
  }
  return Object.freeze({ from, to, attemptId, role: "answer", revision });
}

function wrapperAad(descriptor, selector) {
  return concat(
    WRAPPER_DOMAIN,
    Uint8Array.of(descriptor.version, "a".charCodeAt(0)),
    hexBytes(descriptor.bindingSha256, HASH, "bindingSha256"),
    hexBytes(selector.attemptId, ATTEMPT, "attemptId"),
    hexBytes(selector.from, DEVICE, "from", "INVALID_RECEIPT"),
    hexBytes(selector.to, DEVICE, "to", "INVALID_RECEIPT"),
  );
}

/** Encrypt a signed V2 answer. Even a maximum 207-byte token wraps to 236 bytes. */
export async function wrapAutoAnswerToken({
  descriptor: input,
  keys,
  route,
  tokenBytes,
  crypto = globalThis.crypto,
  subtle,
  nonce = null,
}) {
  const descriptor = parseDescriptor(input);
  const material = keyMaterial(keys, descriptor);
  const plaintext = bytes(tokenBytes, "signed answer token");
  requireCondition(plaintext.length >= MIN_TOKEN_BYTES
    && plaintext.length <= RENDEZVOUS_V2.maxTokenBytes,
  "TOKEN_SIZE", "The signed answer token is outside the V2 byte bound.");
  const selector = answerRoute(route, descriptor);
  const iv = nonce == null ? random(NONCE_BYTES, crypto) : bytes(nonce, "AES-GCM nonce");
  requireCondition(iv.length === NONCE_BYTES, "INVALID_FIELD",
    "The AES-GCM nonce must contain 12 bytes.");
  const ciphertext = new Uint8Array(await subtleCrypto(subtle).encrypt({
    name: "AES-GCM",
    iv,
    additionalData: wrapperAad(descriptor, selector),
    tagLength: 128,
  }, material.wrappingKey, plaintext));
  const wrapped = concat(Uint8Array.of(WRAP_MAGIC), iv, ciphertext);
  requireCondition(wrapped.length <= 240 && wrapped.length <= MAX_WRAPPED_BYTES,
    "TOKEN_SIZE", "The encrypted answer does not fit one rr2 slot.");
  return wrapped;
}

export async function unwrapAutoAnswerToken({ descriptor: input, keys, receipt, tokenBytes, subtle }) {
  const descriptor = parseDescriptor(input);
  const material = keyMaterial(keys, descriptor);
  const selector = answerRoute(receipt, descriptor, true);
  const wrapped = bytes(tokenBytes, "encrypted answer token");
  requireCondition(wrapped.length >= 1 + NONCE_BYTES + MIN_TOKEN_BYTES + GCM_TAG_BYTES
    && wrapped.length <= MAX_WRAPPED_BYTES && wrapped[0] === WRAP_MAGIC,
  "INVALID_WRAPPER", "The encrypted answer wrapper is invalid.");
  try {
    const plaintext = new Uint8Array(await subtleCrypto(subtle).decrypt({
      name: "AES-GCM",
      iv: wrapped.slice(1, 1 + NONCE_BYTES),
      additionalData: wrapperAad(descriptor, selector),
      tagLength: 128,
    }, material.wrappingKey, wrapped.slice(1 + NONCE_BYTES)));
    requireCondition(plaintext.length >= MIN_TOKEN_BYTES
      && plaintext.length <= RENDEZVOUS_V2.maxTokenBytes,
    "TOKEN_SIZE", "The decrypted answer has an invalid V2 size.");
    return plaintext;
  } catch (error) {
    if (error instanceof AutoAnswerReturnError) throw error;
    fail("AUTH_FAILED", "The encrypted answer did not authenticate.", error);
  }
}

function answerLifetime(descriptor, nowSeconds, requested) {
  requireCondition(Number.isSafeInteger(nowSeconds) && nowSeconds >= 0 && nowSeconds <= 0xffffffff,
    "INVALID_EXPIRY", "nowSeconds must be an unsigned 32-bit integer.");
  const remaining = Math.floor(descriptor.expiresAt / 1000) - nowSeconds;
  const lifetime = requested == null
    ? Math.min(AUTO_ANSWER_RETURN.defaultTokenLifetimeSeconds, remaining)
    : requested;
  requireCondition(Number.isSafeInteger(lifetime)
    && lifetime >= RENDEZVOUS_V2.minLifetimeSeconds
    && lifetime <= RENDEZVOUS_V2.maxLifetimeSeconds
    && lifetime <= remaining,
  "INVALID_EXPIRY", "The answer token lifetime does not fit the invitation expiry.");
  return lifetime;
}

/** Convert a gathered browser answer into one encrypted, authenticated rr2 value. */
export async function createAutoAnswerSlot({
  descriptor: input,
  keys,
  from,
  to,
  sdp,
  nowSeconds,
  lifetimeSeconds = null,
  allowHostCandidates = false,
  maxCandidates = 2,
  crypto = globalThis.crypto,
  subtle,
}) {
  const descriptor = parseDescriptor(input);
  const material = keyMaterial(keys, descriptor);
  requireCondition(to === descriptor.host && DEVICE.test(from) && from !== to,
    "INVALID_FIELD", "The compact answer must target the invitation host.");
  const candidates = selectRendezvousCandidates(sdp, {
    allowHost: allowHostCandidates,
    maxCandidates,
  });
  requireCondition(candidates.length > 0, "NO_CANDIDATE",
    "The gathered answer has no candidate representable by rendezvous V2.");
  const token = Object.freeze({
    profile: "bootstrap",
    role: "answer",
    attemptId: descriptor.attemptId,
    contextId: material.contextId,
    from,
    to,
    issuedAt: nowSeconds,
    lifetimeSeconds: answerLifetime(descriptor, nowSeconds, lifetimeSeconds),
    ice: extractRendezvousIce(sdp),
    candidates,
  });
  const signed = await encodeAndSignRendezvousV2Bytes(token, material.tokenKey, { subtle });
  const selector = Object.freeze({ from, to, attemptId: descriptor.attemptId, role: "answer" });
  const tokenBytes = await wrapAutoAnswerToken({
    descriptor,
    keys: material,
    route: selector,
    tokenBytes: signed,
    crypto,
    subtle,
  });
  return Object.freeze({ selector, tokenBytes, token });
}

/** Verify receipt binding and return a candidate-free remote answer description. */
export async function verifyAutoAnswerAnswerSlot({
  descriptor: input,
  keys,
  readResult,
  expectedFrom = null,
  nowSeconds,
  maxClockSkewSeconds = RENDEZVOUS_V2.defaultClockSkewSeconds,
  subtle,
}) {
  const descriptor = parseDescriptor(input);
  const material = keyMaterial(keys, descriptor);
  requireCondition(readResult?.status === "data" && readResult.receipt && readResult.tokenBytes,
    "INVALID_RECEIPT", "A complete rr2 answer result is required.");
  requireCondition(Number.isSafeInteger(nowSeconds)
    && nowSeconds < Math.floor(descriptor.expiresAt / 1000),
  "EXPIRED", "The automatic-answer invitation has expired.");
  const receipt = answerRoute(readResult.receipt, descriptor, true);
  if (expectedFrom != null) {
    requireCondition(receipt.from === expectedFrom, "INVALID_RECEIPT",
      "The rr2 answer has the wrong sender.");
  }
  const signed = await unwrapAutoAnswerToken({
    descriptor,
    keys: material,
    receipt: readResult.receipt,
    tokenBytes: readResult.tokenBytes,
    subtle,
  });
  const envelope = await verifyAndDecodeRendezvousV2Bytes(signed, material.tokenKey, {
    subtle,
    nowSeconds,
    maxClockSkewSeconds,
    expectedProfile: "bootstrap",
    expectedRole: "answer",
    expectedAttemptId: descriptor.attemptId,
    expectedContextId: material.contextId,
    expectedFrom: receipt.from,
    expectedTo: descriptor.host,
  });
  requireCondition((envelope.issuedAt + envelope.lifetimeSeconds)
    <= Math.floor(descriptor.expiresAt / 1000),
  "INVALID_EXPIRY", "The authenticated answer outlives its invitation.");
  return Object.freeze({
    envelope,
    receipt,
    candidates: envelope.candidates,
    remoteDescription: Object.freeze({
      type: "answer",
      sdp: buildRendezvousDataChannelSdp({ type: "answer", ice: envelope.ice }),
    }),
  });
}

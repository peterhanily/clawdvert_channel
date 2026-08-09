#!/usr/bin/env node

import crypto from "node:crypto";
import dgram from "node:dgram";
import { lookup } from "node:dns/promises";
import {
  ATTRIBUTE,
  MESSAGE,
  MAGIC_COOKIE,
  attribute,
  buildMessage,
  getAttribute,
  longTermKey,
  parseMessage,
  textAttribute,
  verifyMessageIntegrity,
} from "../lib/stun.mjs";
import { toBase64Url } from "../lib/protocol.mjs";

const DEFAULT_PORT = 3478;
const DEFAULT_LANES = 6;
const DEFAULT_TIMEOUT_MS = 2500;
const DEFAULT_PACE_MS = 180;
const MAX_PAGES = 43;
const RR2_STATUS = Object.freeze({
  empty: 50,
  stored: 51,
  notModified: 52,
  acked: 53,
});

class SmokeFailure extends Error {}

let options;
try {
  options = parseArguments(process.argv.slice(2));
} catch (error) {
  console.error(`RESULT FAIL: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 2;
}

if (options?.help) {
  printUsage();
} else if (options) {
  main(options).catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`RESULT FAIL: ${message}`);
    process.exitCode = 1;
  });
}

async function main(config) {
  const resolved = await lookup(config.host, { family: 4 });
  const transport = new RelayTransport({ ...config, address: resolved.address });
  const portRange = config.lanes === 1
    ? String(config.port)
    : `${config.port}-${config.port + config.lanes - 1}`;
  console.log(`Relay smoke target: ${config.host} UDP ${portRange} (${config.lanes} lanes)`);

  const healthBefore = config.healthUrl
    ? await optionalHealth(config.healthUrl, config.timeoutMs, "before")
    : null;
  if (healthBefore) validateHealth(healthBefore, config, {
    requireRr2: config.rr2,
    requireRr2Disabled: config.expectRr2Disabled,
  });

  const rr1 = await smokeRr1(transport);
  console.log(`PASS rr1: ${config.lanes}/${config.lanes} lanes authenticated; event ${rr1.eventId} published once and reconstructed`);

  let rr2 = null;
  if (config.rr2) {
    rr2 = await smokeRr2(transport);
    console.log(`PASS rr2: PUT, late DISCOVER, exact GET, not-modified, and ACK at revision ${rr2.revision}`);
  } else if (config.expectRr2Disabled) {
    await smokeRr2Disabled(transport);
    console.log(`PASS rr2 dark state: valid PUT returned disabled/code 3 on ${config.lanes}/${config.lanes} lanes`);
  }

  if (config.healthUrl) {
    const healthAfter = await optionalHealth(config.healthUrl, config.timeoutMs, "after");
    if (healthAfter) {
      validateHealth(healthAfter, config, {
        requireRr2: config.rr2,
        requireRr2Disabled: config.expectRr2Disabled,
      });
      if (config.rr2) validateHealthDeltas(healthBefore, healthAfter, config, rr2);
      console.log("PASS health: endpoint and relay counters are consistent with the smoke run");
    }
  }

  const mode = config.rr2 ? "rr1 + rr2" : config.expectRr2Disabled ? "rr1 + rr2-disabled" : "rr1";
  console.log(`RESULT PASS: ${mode} relay smoke completed`);
}

async function smokeRr1(transport) {
  const room = `smk-${randomHex(8)}`;
  const clientA = randomHex(6);
  let clientB = randomHex(6);
  while (clientB === clientA) clientB = randomHex(6);
  const requestId = randomHex(6);
  // Room messages with this protocol prefix are excluded from the optional
  // JSONL store. The random room also expires naturally from the memory store.
  const text = `~r2~relay-smoke-${randomHex(8)}`;
  const username = ({
    client,
    request = "0",
    name,
    sequence = 0,
    chunk = 0,
    message = "",
  }) => [
    "rr1",
    room,
    client,
    request,
    toBase64Url(name),
    sequence.toString(36),
    chunk.toString(36),
    message ? toBase64Url(message) : "0",
  ].join(".");

  const joinedA = await transport.exchangeAll(
    username({ client: clientA, name: "Smoke A" }), room,
  );
  expectRr1Control(joinedA, 1, 1, "first rr1 join");

  const joinedB = await transport.exchangeAll(
    username({ client: clientB, name: "Smoke B" }), room,
  );
  expectRr1Control(joinedB, 2, 2, "second rr1 join");

  const publishUsername = username({
    client: clientA,
    request: requestId,
    name: "Smoke A",
    message: text,
  });
  const published = await transport.exchangeAll(publishUsername, room);
  expectRr1Control(published, 3, 2, "rr1 publish");

  // Repeating one logical request across every lane must not append it again.
  const replayed = await transport.exchangeAll(publishUsername, room);
  expectRr1Control(replayed, 3, 2, "rr1 idempotent replay");

  const payload = await readPages(transport, (chunk) => username({
    client: clientB,
    name: "Smoke B",
    sequence: 3,
    chunk,
  }), room, "rr1 event");

  let event;
  try {
    event = JSON.parse(payload.toString("utf8"));
  } catch {
    throw new SmokeFailure("rr1 event was not valid JSON");
  }
  check(Array.isArray(event) && event.length === 6, "rr1 event has an invalid envelope");
  check(event[0] === "m", "rr1 read returned a non-message event");
  check(event[1] === 3, `rr1 event sequence was ${event[1]}, expected 3`);
  check(event[2] === clientA && event[3] === "Smoke A", "rr1 event sender changed in transit");
  check(event[4] === text, "rr1 event body changed in transit");
  check(Number.isFinite(event[5]), "rr1 event timestamp is invalid");

  return { eventId: event[1] };
}

async function smokeRr2(transport) {
  const room = `rv2-${randomHex(8)}`;
  const writer = randomHex(6);
  let reader = randomHex(6);
  while (reader === writer) reader = randomHex(6);
  const from = nonZeroHex(8);
  let to = nonZeroHex(8);
  while (to === from) to = nonZeroHex(8);
  const attempt = nonZeroHex(16);
  const payload = Buffer.concat([
    Buffer.from("rr2-smoke\0", "utf8"),
    crypto.randomBytes(85),
  ]);

  const username = ({
    actor,
    selectorFrom = from,
    selectorTo = to,
    selectorAttempt = attempt,
    role = "o",
    operation,
    revision = 0,
    chunk = 0,
    body = Buffer.alloc(0),
  }) => [
    "rr2",
    room,
    actor,
    selectorFrom,
    selectorTo,
    selectorAttempt,
    role,
    operation,
    revision.toString(36),
    chunk.toString(36),
    body.length ? body.toString("base64url") : "0",
  ].join(".");

  const stored = await transport.exchangeAll(username({
    actor: writer,
    operation: "put",
    body: payload,
  }), room);
  expectSlotControl(stored, RR2_STATUS.stored, 1, "rr2 PUT");

  // This actor has not touched the room before this call: it is a late reader
  // discovering the writer's current replaceable value rather than replaying
  // an append-only event log.
  const discovered = await readRr2(transport, (chunk) => username({
    actor: reader,
    selectorFrom: "0000000000000000",
    selectorAttempt: "0",
    operation: "discover",
    chunk,
  }), room, { from, to, attempt, role: "o", payload }, "rr2 DISCOVER");

  const exact = await readRr2(transport, (chunk) => username({
    actor: reader,
    operation: "get",
    chunk,
  }), room, { from, to, attempt, role: "o", payload }, "rr2 GET");
  check(exact.revision === discovered.revision, "rr2 DISCOVER and GET revisions disagree");

  const unchanged = await transport.exchangeAll(username({
    actor: reader,
    operation: "get",
    revision: discovered.revision,
  }), room);
  expectSlotControl(unchanged, RR2_STATUS.notModified, discovered.revision, "rr2 conditional GET");

  const acknowledged = await transport.exchangeAll(username({
    actor: reader,
    operation: "ack",
    revision: discovered.revision,
  }), room);
  expectSlotControl(acknowledged, RR2_STATUS.acked, discovered.revision, "rr2 ACK");

  return {
    revision: discovered.revision,
    pages: { discover: discovered.pages, get: exact.pages },
  };
}

async function smokeRr2Disabled(transport) {
  const room = `rv2-${randomHex(8)}`;
  const from = nonZeroHex(8);
  let to = nonZeroHex(8);
  while (to === from) to = nonZeroHex(8);
  const username = [
    "rr2",
    room,
    randomHex(6),
    from,
    to,
    nonZeroHex(16),
    "o",
    "put",
    "0",
    "0",
    Buffer.from("rr2-disabled-smoke", "utf8").toString("base64url"),
  ].join(".");
  const frames = await transport.exchangeAll(username, room);
  for (const frame of frames) {
    check(frame.kind === "error" && frame.code === 3,
      `rr2 dark-state probe lane ${frame.lane} returned ${frame.kind}${frame.code ? `/code ${frame.code}` : ""}, expected error/code 3`);
  }
}

async function readRr2(transport, makeUsername, room, expected, label) {
  const encoded = await readPages(transport, makeUsername, room, label);
  const ascii = encoded.toString("ascii");
  check(/^[A-Za-z0-9_-]+$/.test(ascii), `${label} was not base64url text`);
  const decoded = Buffer.from(ascii, "base64url");
  check(decoded.toString("base64url") === ascii, `${label} used non-canonical base64url`);
  check(decoded.length >= 38, `${label} response was shorter than its selector`);

  const actual = {
    from: decoded.subarray(0, 8).toString("hex"),
    to: decoded.subarray(8, 16).toString("hex"),
    attempt: decoded.subarray(16, 32).toString("hex"),
    role: String.fromCharCode(decoded[32]),
    revision: decoded.readUInt32BE(33),
    payload: decoded.subarray(37),
  };
  check(actual.from === expected.from && actual.to === expected.to,
    `${label} returned the wrong device route`);
  check(actual.attempt === expected.attempt && actual.role === expected.role,
    `${label} returned the wrong attempt or role`);
  check(actual.revision === 1, `${label} revision was ${actual.revision}, expected 1`);
  check(actual.payload.equals(expected.payload), `${label} payload changed in transit`);
  return { revision: actual.revision, pages: Math.ceil(ascii.length / (transport.lanes * 5)) };
}

async function readPages(transport, makeUsername, password, label) {
  const chunks = new Map();
  let finalIndex = null;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const chunkBase = page * transport.lanes;
    check(chunkBase <= 255, `${label} exceeded the protocol chunk range`);
    const frames = await transport.exchangeAll(makeUsername(chunkBase), password);
    for (const frame of frames) {
      if (frame.kind === "error") {
        throw new SmokeFailure(`${label} returned relay error ${frame.code} on lane ${frame.lane}`);
      }
      check(frame.kind === "data", `${label} returned ${frame.kind} on lane ${frame.lane}`);
      const index = chunkBase + frame.lane;
      chunks.set(index, frame.payload);
      if (frame.final && finalIndex === null) finalIndex = index;
    }
    if (finalIndex !== null) {
      const ordered = [];
      for (let index = 0; index <= finalIndex; index += 1) {
        check(chunks.has(index), `${label} is missing chunk ${index}`);
        ordered.push(chunks.get(index));
      }
      return Buffer.concat(ordered);
    }
  }
  throw new SmokeFailure(`${label} did not terminate within ${MAX_PAGES} pages`);
}

class RelayTransport {
  constructor({ address, port, lanes, timeoutMs, retries, paceMs }) {
    this.address = address;
    this.port = port;
    this.lanes = lanes;
    this.timeoutMs = timeoutMs;
    this.retries = retries;
    this.paceMs = paceMs;
  }

  async exchangeAll(username, password) {
    check(username.length <= 509, "generated TURN username exceeds 509 characters");
    const frames = await Promise.all(Array.from({ length: this.lanes }, async (_, lane) => {
      try {
        const frame = await allocate({
          address: this.address,
          port: this.port + lane,
          username,
          password,
          timeoutMs: this.timeoutMs,
          retries: this.retries,
        });
        return { ...frame, lane };
      } catch (error) {
        throw new SmokeFailure(`lane ${lane} (UDP ${this.port + lane}): ${error.message}`);
      }
    }));
    if (this.paceMs > 0) await delay(this.paceMs);
    return frames;
  }
}

async function allocate({ address, port, username, password, timeoutMs, retries }) {
  const transactionId = crypto.randomBytes(12);
  const request = buildMessage({
    type: MESSAGE.ALLOCATE_REQUEST,
    transactionId,
    attributes: [attribute.uint32(ATTRIBUTE.REQUESTED_TRANSPORT, 17 << 24)],
  });
  const challenge = parseMessage(await exchangeUdp({ address, port, packet: request, timeoutMs, retries }));
  check(challenge, "relay returned a malformed STUN challenge");
  check(challenge.transactionId.equals(transactionId), "STUN challenge transaction ID mismatch");
  check(challenge.type === MESSAGE.ALLOCATE_ERROR,
    `expected a TURN challenge, received STUN type 0x${challenge.type.toString(16)}`);
  const challengeCode = errorCode(challenge);
  check(challengeCode === 401, `expected TURN 401 challenge, received ${challengeCode ?? "no error code"}`);
  const realm = textAttribute(challenge, ATTRIBUTE.REALM);
  const nonce = textAttribute(challenge, ATTRIBUTE.NONCE);
  check(realm && nonce, "TURN challenge omitted realm or nonce");

  const authenticatedTransaction = crypto.randomBytes(12);
  const key = longTermKey(username, realm, password);
  const authenticated = buildMessage({
    type: MESSAGE.ALLOCATE_REQUEST,
    transactionId: authenticatedTransaction,
    attributes: [
      attribute.text(ATTRIBUTE.USERNAME, username),
      attribute.text(ATTRIBUTE.REALM, realm),
      attribute.text(ATTRIBUTE.NONCE, nonce),
      attribute.uint32(ATTRIBUTE.REQUESTED_TRANSPORT, 17 << 24),
    ],
    integrityKey: key,
  });
  const response = parseMessage(await exchangeUdp({
    address,
    port,
    packet: authenticated,
    timeoutMs,
    retries,
  }));
  check(response, "relay returned a malformed authenticated STUN response");
  check(response.transactionId.equals(authenticatedTransaction),
    "authenticated STUN transaction ID mismatch");
  if (response.type !== MESSAGE.ALLOCATE_SUCCESS) {
    throw new SmokeFailure(`authenticated TURN allocate failed with ${errorCode(response) ?? `type 0x${response.type.toString(16)}`}`);
  }
  check(verifyMessageIntegrity(response, key), "TURN response MESSAGE-INTEGRITY failed verification");
  return decodeFrame(getAttribute(response, ATTRIBUTE.XOR_RELAYED_ADDRESS));
}

async function exchangeUdp({ address, port, packet, timeoutMs, retries }) {
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      return await exchangeUdpOnce({ address, port, packet, timeoutMs });
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

function exchangeUdpOnce({ address, port, packet, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    let settled = false;
    const finish = (error, response) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.close();
      if (error) reject(error);
      else resolve(response);
    };
    const timer = setTimeout(() => finish(new Error(`UDP response timed out after ${timeoutMs} ms`)), timeoutMs);
    socket.once("error", (error) => finish(error));
    socket.once("message", (response) => finish(null, response));
    socket.send(packet, port, address, (error) => {
      if (error) finish(error);
    });
  });
}

function decodeFrame(attributeValue) {
  check(attributeValue?.value?.length === 8, "TURN response omitted its six-byte mailbox frame");
  const value = attributeValue.value;
  check(value[1] === 1, "TURN mailbox frame was not encoded as IPv4");
  const port = value.readUInt16BE(2) ^ (MAGIC_COOKIE >>> 16);
  const cookie = Buffer.alloc(4);
  cookie.writeUInt32BE(MAGIC_COOKIE);
  const bytes = Buffer.alloc(6);
  for (let index = 0; index < 4; index += 1) bytes[index] = value[4 + index] ^ cookie[index];
  bytes.writeUInt16BE(port, 4);
  const header = bytes[0];
  if (header === 10) {
    return { kind: "control", latest: bytes.readUInt32BE(1), peers: bytes[5] };
  }
  if (header >= 21 && header <= 25) {
    return { kind: "data", payload: bytes.subarray(1, 1 + header - 20), final: false };
  }
  if (header >= 30 && header <= 35) {
    return { kind: "data", payload: bytes.subarray(1, 1 + header - 30), final: true };
  }
  if (header >= 41 && header <= 49) {
    return { kind: "error", code: header - 40, value: bytes.readUInt32BE(1) };
  }
  if (header >= 50 && header <= 54) {
    return { kind: "slot-control", status: header, revision: bytes.readUInt32BE(1) };
  }
  throw new SmokeFailure(`relay returned unknown mailbox frame header ${header}`);
}

function expectRr1Control(frames, latest, minimumPeers, label) {
  check(frames.length > 0, `${label} returned no lane frames`);
  for (const frame of frames) {
    if (frame.kind === "error") {
      throw new SmokeFailure(`${label} returned relay error ${frame.code} on lane ${frame.lane}`);
    }
    check(frame.kind === "control", `${label} returned ${frame.kind} on lane ${frame.lane}`);
    check(frame.latest === latest,
      `${label} lane ${frame.lane} reported sequence ${frame.latest}, expected ${latest}`);
    check(frame.peers >= minimumPeers,
      `${label} lane ${frame.lane} reported ${frame.peers} peers, expected at least ${minimumPeers}`);
  }
}

function expectSlotControl(frames, status, revision, label) {
  for (const frame of frames) {
    if (frame.kind === "error") {
      const hint = frame.code === 3 ? " (rr2 is disabled on the relay)" : "";
      throw new SmokeFailure(`${label} returned relay error ${frame.code} on lane ${frame.lane}${hint}`);
    }
    check(frame.kind === "slot-control", `${label} returned ${frame.kind} on lane ${frame.lane}`);
    check(frame.status === status && frame.revision === revision,
      `${label} lane ${frame.lane} returned status ${frame.status}/revision ${frame.revision}`);
  }
}

function errorCode(message) {
  const item = getAttribute(message, ATTRIBUTE.ERROR_CODE);
  if (!item || item.value.length < 4) return null;
  return item.value[2] * 100 + item.value[3];
}

async function optionalHealth(url, timeoutMs, stage) {
  let response;
  try {
    response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  } catch (error) {
    console.warn(`WARN health ${stage}: unavailable (${error.message})`);
    return null;
  }
  check(response.ok, `health ${stage} returned HTTP ${response.status}`);
  try {
    return await response.json();
  } catch {
    throw new SmokeFailure(`health ${stage} did not return JSON`);
  }
}

function validateHealth(health, config, { requireRr2, requireRr2Disabled }) {
  check(health?.ok === true && health.stun === true, "health response does not describe a ready relay");
  check(health.lanes === config.lanes,
    `health reports ${health.lanes} lanes, smoke test expects ${config.lanes}`);
  if (requireRr2) check(health.rendezvousV2?.enabled === true, "health reports rr2 disabled");
  if (requireRr2Disabled) check(health.rendezvousV2?.enabled === false, "health reports rr2 enabled");
}

function validateHealthDeltas(before, after, config, rr2) {
  const final = after?.rendezvousV2;
  check(final?.enabled === true, "health omitted enabled rr2 counters");
  check(final.acked >= 1, "health did not report an acknowledged rr2 slot");
  if (!before?.rendezvousV2?.enabled) return;
  const initial = before.rendezvousV2;
  const delta = (name) => (final.operations?.[name] ?? 0) - (initial.operations?.[name] ?? 0);
  check(delta("put") >= config.lanes, "health PUT counter did not cover every lane");
  check(delta("discover") >= rr2.pages.discover * config.lanes,
    "health DISCOVER counter did not cover every reconstructed page");
  check(delta("get") >= (rr2.pages.get + 1) * config.lanes,
    "health GET counter did not cover reconstruction and conditional read");
  check(delta("ack") >= config.lanes, "health ACK counter did not cover every lane");
}

function parseArguments(args) {
  const config = {
    host: "127.0.0.1",
    port: DEFAULT_PORT,
    lanes: DEFAULT_LANES,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    retries: 1,
    paceMs: DEFAULT_PACE_MS,
    rr2: false,
    expectRr2Disabled: false,
    healthUrl: null,
    help: false,
  };
  let positionalHost = false;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--help" || argument === "-h") config.help = true;
    else if (argument === "--rr2") config.rr2 = true;
    else if (argument === "--expect-rr2-disabled") config.expectRr2Disabled = true;
    else if (argument === "--host") config.host = requiredValue(args, ++index, argument);
    else if (argument === "--port") config.port = integerValue(args, ++index, argument);
    else if (argument === "--lanes") config.lanes = integerValue(args, ++index, argument);
    else if (argument === "--timeout-ms") config.timeoutMs = integerValue(args, ++index, argument);
    else if (argument === "--retries") config.retries = integerValue(args, ++index, argument);
    else if (argument === "--pace-ms") config.paceMs = integerValue(args, ++index, argument);
    else if (argument === "--health-url") config.healthUrl = requiredValue(args, ++index, argument);
    else if (argument.startsWith("-")) throw new SmokeFailure(`unknown option ${argument}`);
    else if (!positionalHost) {
      config.host = argument;
      positionalHost = true;
    } else throw new SmokeFailure(`unexpected positional argument ${argument}`);
  }
  check(config.host && !config.host.includes("://"), "host must be a hostname or IPv4 address, not a URL");
  check(config.port >= 1 && config.port <= 65535, "port must be between 1 and 65535");
  check(config.lanes >= 1 && config.lanes <= 12, "lanes must be between 1 and 12");
  check(config.port + config.lanes - 1 <= 65535, "lane range exceeds UDP port 65535");
  check(config.timeoutMs >= 250 && config.timeoutMs <= 30_000,
    "timeout must be between 250 and 30000 milliseconds");
  check(config.retries >= 0 && config.retries <= 4, "retries must be between 0 and 4");
  check(config.paceMs >= 0 && config.paceMs <= 5000, "pace must be between 0 and 5000 milliseconds");
  check(!(config.rr2 && config.expectRr2Disabled),
    "--rr2 and --expect-rr2-disabled are mutually exclusive");
  if (config.healthUrl) {
    let parsed;
    try {
      parsed = new URL(config.healthUrl);
    } catch {
      throw new SmokeFailure("health URL is invalid");
    }
    check(parsed.protocol === "http:" || parsed.protocol === "https:",
      "health URL must use http or https");
  }
  return config;
}

function requiredValue(args, index, option) {
  const value = args[index];
  if (!value || value.startsWith("--")) throw new SmokeFailure(`${option} requires a value`);
  return value;
}

function integerValue(args, index, option) {
  const value = requiredValue(args, index, option);
  check(/^\d+$/.test(value), `${option} requires an integer`);
  return Number(value);
}

function printUsage() {
  console.log(`Usage: node tools/relay-smoke.mjs [host] [options]

Exercises authenticated rr1 over every relay lane. Add --rr2 to also verify
the ephemeral latest-value rendezvous protocol from PUT through ACK.

Options:
  --rr2                 Also exercise rr2 latest-value slots
  --expect-rr2-disabled Require a valid rr2 PUT to be disabled on every lane
  --host HOST           Relay hostname (positional host is also accepted)
  --port PORT           First UDP lane (default: ${DEFAULT_PORT})
  --lanes COUNT         Consecutive UDP lanes (default: ${DEFAULT_LANES})
  --timeout-ms MS       Per-packet timeout (default: ${DEFAULT_TIMEOUT_MS})
  --retries COUNT       UDP timeout retries, 0-4 (default: 1)
  --pace-ms MS          Delay after each six-lane exchange (default: ${DEFAULT_PACE_MS})
  --health-url URL      Optionally validate health and rr2 counter deltas
  -h, --help            Show this help

Examples:
  node tools/relay-smoke.mjs relay.example.com
  node tools/relay-smoke.mjs relay.example.com --expect-rr2-disabled
  node tools/relay-smoke.mjs relay.example.com --rr2
  node tools/relay-smoke.mjs --rr2 --health-url http://127.0.0.1:8080/health`);
}

function check(condition, message) {
  if (!condition) throw new SmokeFailure(message);
}

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString("hex");
}

function nonZeroHex(bytes) {
  let value = randomHex(bytes);
  while (/^0+$/.test(value)) value = randomHex(bytes);
  return value;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

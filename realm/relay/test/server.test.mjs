import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import dgram from "node:dgram";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
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

test("the UDP relay authenticates a room and delivers a multi-chunk message", { timeout: 15_000 }, async (context) => {
  const relayPort = await freeUdpPort();
  const healthPort = await freeTcpPort();
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      RELAY_BIND: "127.0.0.1",
      RELAY_START_PORT: String(relayPort),
      RELAY_LANES: "1",
      HEALTH_PORT: String(healthPort),
      NONCE_SECRET: "test-secret",
      PERSIST_MESSAGES: "false",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  context.after(() => child.kill("SIGTERM"));
  await waitForOutput(child, "Realm Relay lane 0");

  const room = "aabbccddeeff0011";
  const clientA = "001122334455";
  const clientB = "66778899aabb";
  const baseEnvelope = ({ client, request = "0", name, sequence = 0, chunk = 0, message = "" }) =>
    [
      "rr1",
      room,
      client,
      request,
      toBase64Url(name),
      sequence.toString(36),
      chunk.toString(36),
      message ? toBase64Url(message) : "0",
    ].join(".");

  const first = await allocate(relayPort, baseEnvelope({ client: clientA, name: "Alpha" }), room);
  assert.deepEqual(first, { kind: "control", latest: 1, peers: 1 });
  const second = await allocate(relayPort, baseEnvelope({ client: clientB, name: "Beta" }), room);
  assert.deepEqual(second, { kind: "control", latest: 2, peers: 2 });

  await allocate(
    relayPort,
    baseEnvelope({
      client: clientA,
      request: "abcdef123456",
      name: "Alpha",
      sequence: 2,
      message: "Hello from Alpha over ICE",
    }),
    room,
  );

  const chunks = [];
  for (let chunk = 0; chunk < 80; chunk += 1) {
    const frame = await allocate(
      relayPort,
      baseEnvelope({ client: clientB, name: "Beta", sequence: 3, chunk }),
      room,
    );
    assert.equal(frame.kind, "data");
    chunks.push(frame.payload);
    if (frame.final) break;
  }

  const event = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  assert.equal(event[0], "m");
  assert.equal(event[2], clientA);
  assert.equal(event[3], "Alpha");
  assert.equal(event[4], "Hello from Alpha over ICE");
});

test("the UDP relay also returns a standard STUN binding response", { timeout: 15_000 }, async (context) => {
  const relayPort = await freeUdpPort();
  const healthPort = await freeTcpPort();
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      RELAY_BIND: "127.0.0.1",
      RELAY_START_PORT: String(relayPort),
      RELAY_LANES: "1",
      HEALTH_PORT: String(healthPort),
      NONCE_SECRET: "test-secret",
      PERSIST_MESSAGES: "false",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  context.after(() => child.kill("SIGTERM"));
  await waitForOutput(child, "Realm Relay lane 0");

  const transactionId = crypto.randomBytes(12);
  const request = buildMessage({ type: MESSAGE.BINDING_REQUEST, transactionId });
  const response = parseMessage(await exchangeUdp(relayPort, request));
  assert.equal(response.type, MESSAGE.BINDING_SUCCESS);

  const mapped = decodeXorAddress(getAttribute(response, ATTRIBUTE.XOR_MAPPED_ADDRESS));
  assert.equal(mapped.ip, "127.0.0.1");
  assert.ok(mapped.port > 0);
});

test("rr2 is an explicit disabled frame unless the dormant flag is enabled", { timeout: 15_000 }, async (context) => {
  const relayPort = await freeUdpPort();
  const healthPort = await freeTcpPort();
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      RELAY_BIND: "127.0.0.1",
      RELAY_START_PORT: String(relayPort),
      RELAY_LANES: "1",
      HEALTH_PORT: String(healthPort),
      NONCE_SECRET: "test-secret",
      PERSIST_MESSAGES: "false",
      RENDEZVOUS_V2_SLOTS: "false",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  context.after(() => child.kill("SIGTERM"));
  await waitForOutput(child, "Realm Relay lane 0");

  const frame = await allocate(relayPort, rr2Username({ operation: "get" }), "aabbccddeeff0011");
  assert.deepEqual(frame, { kind: "error", code: 3, value: 0 });
});

test("rr2 serves late readers, acknowledges slots, and never enters persistence", { timeout: 20_000 }, async (context) => {
  const relayPort = await freeUdpPort();
  const healthPort = await freeTcpPort();
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "realm-relay-rr2-"));
  const persistenceFile = path.join(temporary, "events.jsonl");
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      RELAY_BIND: "127.0.0.1",
      RELAY_START_PORT: String(relayPort),
      RELAY_LANES: "1",
      HEALTH_PORT: String(healthPort),
      NONCE_SECRET: "test-secret",
      PERSIST_MESSAGES: "true",
      MESSAGE_STORE: persistenceFile,
      RENDEZVOUS_V2_SLOTS: "true",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  context.after(() => child.kill("SIGTERM"));
  context.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  await waitForOutput(child, "Realm Relay lane 0");

  const token = Buffer.from([0, 1, 2, 0, 0, 255, 17]);
  const stored = await allocate(relayPort, rr2Username({
    operation: "put",
    payload: token,
  }), "aabbccddeeff0011");
  assert.deepEqual(stored, { kind: "slot-control", status: 51, revision: 1 });

  const chunks = [];
  for (let chunk = 0; chunk < 100; chunk += 1) {
    const frame = await allocate(relayPort, rr2Username({
      actor: "66778899aabb",
      attempt: "0",
      operation: "discover",
      chunk,
    }), "aabbccddeeff0011");
    assert.equal(frame.kind, "data");
    chunks.push(frame.payload);
    if (frame.final) break;
  }
  const decoded = Buffer.from(Buffer.concat(chunks).toString("ascii"), "base64url");
  assert.equal(decoded.subarray(0, 8).toString("hex"), "0011223344556677");
  assert.equal(decoded.subarray(8, 16).toString("hex"), "8899aabbccddeeff");
  assert.equal(decoded.subarray(16, 32).toString("hex"), "0123456789abcdeffedcba9876543210");
  assert.equal(String.fromCharCode(decoded[32]), "o");
  assert.equal(decoded.readUInt32BE(33), 1);
  assert.deepEqual(decoded.subarray(37), token);

  const acknowledged = await allocate(relayPort, rr2Username({
    actor: "66778899aabb",
    operation: "ack",
    revision: 1,
  }), "aabbccddeeff0011");
  assert.deepEqual(acknowledged, { kind: "slot-control", status: 53, revision: 1 });

  const health = await fetch(`http://127.0.0.1:${healthPort}/health`).then((response) => response.json());
  assert.equal(health.rooms, 0);
  assert.equal(health.events, 0);
  assert.equal(health.rendezvousV2.enabled, true);
  assert.equal(health.rendezvousV2.acked, 1);
  assert.equal(fs.existsSync(persistenceFile), false);
});

function rr2Username({
  actor = "001122334455",
  from = "0011223344556677",
  to = "8899aabbccddeeff",
  attempt = "0123456789abcdeffedcba9876543210",
  role = "o",
  operation,
  revision = 0,
  chunk = 0,
  payload = Buffer.alloc(0),
}) {
  return [
    "rr2",
    "aabbccddeeff0011",
    actor,
    from,
    to,
    attempt,
    role,
    operation,
    revision.toString(36),
    chunk.toString(36),
    payload.length ? payload.toString("base64url") : "0",
  ].join(".");
}

async function allocate(port, username, password) {
  const transactionId = crypto.randomBytes(12);
  const request = buildMessage({
    type: MESSAGE.ALLOCATE_REQUEST,
    transactionId,
    attributes: [attribute.uint32(ATTRIBUTE.REQUESTED_TRANSPORT, 17 << 24)],
  });
  const challenge = parseMessage(await exchangeUdp(port, request));
  assert.equal(challenge.type, MESSAGE.ALLOCATE_ERROR);
  const realm = textAttribute(challenge, ATTRIBUTE.REALM);
  const nonce = textAttribute(challenge, ATTRIBUTE.NONCE);
  assert.ok(realm && nonce);

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
  const response = parseMessage(await exchangeUdp(port, authenticated));
  assert.equal(response.type, MESSAGE.ALLOCATE_SUCCESS);
  assert.equal(verifyMessageIntegrity(response, key), true);
  return decodeFrame(getAttribute(response, ATTRIBUTE.XOR_RELAYED_ADDRESS));
}

function decodeFrame(attributeValue) {
  assert.ok(attributeValue && attributeValue.value.length === 8);
  const value = attributeValue.value;
  const port = value.readUInt16BE(2) ^ (MAGIC_COOKIE >>> 16);
  const cookie = Buffer.alloc(4);
  cookie.writeUInt32BE(MAGIC_COOKIE);
  const bytes = Buffer.alloc(6);
  for (let index = 0; index < 4; index += 1) bytes[index] = value[4 + index] ^ cookie[index];
  bytes.writeUInt16BE(port, 4);
  const header = bytes[0];
  if (header === 10) return { kind: "control", latest: bytes.readUInt32BE(1), peers: bytes[5] };
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
  return { kind: "other", header };
}

function decodeXorAddress(attributeValue) {
  assert.ok(attributeValue && attributeValue.value.length === 8);
  const value = attributeValue.value;
  const port = value.readUInt16BE(2) ^ (MAGIC_COOKIE >>> 16);
  const cookie = Buffer.alloc(4);
  cookie.writeUInt32BE(MAGIC_COOKIE);
  const octets = [];
  for (let index = 0; index < 4; index += 1) octets.push(value[4 + index] ^ cookie[index]);
  return { ip: octets.join("."), port };
}

function exchangeUdp(port, packet) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error("UDP response timed out"));
    }, 1500);
    socket.once("message", (response) => {
      clearTimeout(timer);
      socket.close();
      resolve(response);
    });
    socket.send(packet, port, "127.0.0.1", (error) => {
      if (!error) return;
      clearTimeout(timer);
      socket.close();
      reject(error);
    });
  });
}

function freeUdpPort() {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    socket.once("error", reject);
    socket.bind(0, "127.0.0.1", () => {
      const { port } = socket.address();
      socket.close(() => resolve(port));
    });
  });
}

function freeTcpPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

function waitForOutput(child, text) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Relay did not start: ${text}`)), 5000);
    const inspect = (chunk) => {
      if (!String(chunk).includes(text)) return;
      clearTimeout(timer);
      child.stdout.off("data", inspect);
      resolve();
    };
    child.stdout.on("data", inspect);
    child.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`Relay exited before startup with code ${code}`));
    });
  });
}

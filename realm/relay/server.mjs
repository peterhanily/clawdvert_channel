import crypto from "node:crypto";
import dgram from "node:dgram";
import http from "node:http";
import {
  ATTRIBUTE,
  MESSAGE,
  attribute,
  buildMessage,
  getAttribute,
  longTermKey,
  parseMessage,
  textAttribute,
  verifyMessageIntegrity,
} from "./lib/stun.mjs";
import {
  frameAddress,
  makeControlFrame,
  makeDataFrame,
  makeErrorFrame,
  parseUsername,
} from "./lib/protocol.mjs";
import { RoomStore } from "./lib/rooms.mjs";

const REALM = process.env.RELAY_REALM || "realm-relay";
const HOST = process.env.RELAY_BIND || "0.0.0.0";
const START_PORT = numberEnv("RELAY_START_PORT", 3478, 1, 65529);
const LANES = numberEnv("RELAY_LANES", 6, 1, 12);
const HEALTH_PORT = numberEnv("HEALTH_PORT", 8080, 1, 65535);
const NONCE_SECRET = process.env.NONCE_SECRET || crypto.randomBytes(32).toString("hex");
const persistencePath = process.env.PERSIST_MESSAGES === "true"
  ? process.env.MESSAGE_STORE || "/data/events.jsonl"
  : null;

const rooms = new RoomStore({ persistencePath });
const sockets = [];
const limits = new Map();

for (let lane = 0; lane < LANES; lane += 1) {
  const socket = dgram.createSocket("udp4");
  const port = START_PORT + lane;
  socket.on("error", (error) => console.error(`UDP ${port}:`, error));
  socket.on("message", (packet, remote) => handlePacket(socket, lane, packet, remote));
  socket.bind(port, HOST, () => console.log(`Realm Relay lane ${lane} listening on udp://${HOST}:${port}`));
  sockets.push(socket);
}

const health = http.createServer((request, response) => {
  if (request.url !== "/health") {
    response.writeHead(404).end("not found\n");
    return;
  }
  response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(JSON.stringify({ ok: true, lanes: LANES, stun: true, persistence: Boolean(persistencePath), ...rooms.stats() }));
});
health.listen(HEALTH_PORT, HOST, () => console.log(`Health check listening on http://${HOST}:${HEALTH_PORT}/health`));

const maintenance = setInterval(() => {
  rooms.pruneAll();
  const cutoff = Date.now() - 60_000;
  for (const [key, value] of limits) if (value.window < cutoff) limits.delete(key);
}, 10_000);
maintenance.unref();

function handlePacket(socket, lane, packet, remote) {
  if (!allow(remote.address)) return;
  const message = parseMessage(packet);
  if (!message) return;

  // The same UDP endpoint doubles as a conventional STUN server for the
  // direct WebRTC data channel. Binding responses carry the client's real
  // server-reflexive address; TURN Allocate responses below remain the
  // authenticated, synthetic-address mailbox used for signalling/fallback.
  if (message.type === MESSAGE.BINDING_REQUEST) {
    const response = buildMessage({
      type: MESSAGE.BINDING_SUCCESS,
      transactionId: message.transactionId,
      attributes: [
        attribute.xorAddress(
          ATTRIBUTE.XOR_MAPPED_ADDRESS,
          normaliseRemoteAddress(remote.address),
          remote.port,
          message.transactionId,
        ),
        attribute.text(ATTRIBUTE.SOFTWARE, "realm-relay/2"),
      ],
    });
    socket.send(response, remote.port, remote.address);
    return;
  }

  if (message.type !== MESSAGE.ALLOCATE_REQUEST) return;

  const username = textAttribute(message, ATTRIBUTE.USERNAME);
  const nonce = textAttribute(message, ATTRIBUTE.NONCE);
  const realm = textAttribute(message, ATTRIBUTE.REALM);

  if (!username || !nonce || realm !== REALM || !validNonce(nonce, remote.address)) {
    const challenge = buildMessage({
      type: MESSAGE.ALLOCATE_ERROR,
      transactionId: message.transactionId,
      attributes: [
        attribute.error(401, "Unauthorised"),
        attribute.text(ATTRIBUTE.REALM, REALM),
        attribute.text(ATTRIBUTE.NONCE, makeNonce(remote.address)),
        attribute.text(ATTRIBUTE.SOFTWARE, "realm-relay/2"),
      ],
    });
    socket.send(challenge, remote.port, remote.address);
    return;
  }

  const envelope = parseUsername(username);
  if (!envelope) {
    sendError(socket, message, remote, 400, "Bad mailbox envelope");
    return;
  }

  const key = longTermKey(username, REALM, envelope.room);
  if (!verifyMessageIntegrity(message, key)) return;

  const requestedTransport = getAttribute(message, ATTRIBUTE.REQUESTED_TRANSPORT);
  if (!requestedTransport || requestedTransport.value[0] !== 17) {
    sendAuthenticatedError(socket, message, remote, key, 442, "Unsupported transport");
    return;
  }

  const touched = rooms.touch(envelope);
  let frame;
  if (touched.error === "room-full") {
    frame = makeErrorFrame(1, touched.room.sequence);
  } else {
    const result = rooms.response(touched.room, envelope.sequence);
    if (result.kind === "control") {
      frame = makeControlFrame(result.latestSequence, result.online);
    } else if (result.kind === "missing") {
      frame = makeErrorFrame(2, result.oldest);
    } else {
      frame = makeDataFrame(result.event.payload, envelope.chunkBase + lane);
    }
  }

  const encoded = frameAddress(frame);
  const response = buildMessage({
    type: MESSAGE.ALLOCATE_SUCCESS,
    transactionId: message.transactionId,
    attributes: [
      attribute.xorAddress(ATTRIBUTE.XOR_RELAYED_ADDRESS, encoded.ip, encoded.port, message.transactionId),
      attribute.uint32(ATTRIBUTE.LIFETIME, 60),
      attribute.xorAddress(
        ATTRIBUTE.XOR_MAPPED_ADDRESS,
        normaliseRemoteAddress(remote.address),
        remote.port,
        message.transactionId,
      ),
      attribute.text(ATTRIBUTE.SOFTWARE, "realm-relay/2"),
    ],
    integrityKey: key,
  });
  socket.send(response, remote.port, remote.address);
}

function sendError(socket, message, remote, code, reason) {
  const response = buildMessage({
    type: MESSAGE.ALLOCATE_ERROR,
    transactionId: message.transactionId,
    attributes: [attribute.error(code, reason), attribute.text(ATTRIBUTE.SOFTWARE, "realm-relay/2")],
  });
  socket.send(response, remote.port, remote.address);
}

function sendAuthenticatedError(socket, message, remote, key, code, reason) {
  const response = buildMessage({
    type: MESSAGE.ALLOCATE_ERROR,
    transactionId: message.transactionId,
    attributes: [attribute.error(code, reason), attribute.text(ATTRIBUTE.SOFTWARE, "realm-relay/2")],
    integrityKey: key,
  });
  socket.send(response, remote.port, remote.address);
}

function makeNonce(address) {
  const bucket = Math.floor(Date.now() / 60_000).toString(36);
  const signature = crypto.createHmac("sha256", NONCE_SECRET).update(`${address}|${bucket}`).digest("base64url").slice(0, 18);
  return `${bucket}.${signature}`;
}

function validNonce(value, address) {
  const [bucket] = String(value).split(".");
  const numeric = Number.parseInt(bucket, 36);
  const current = Math.floor(Date.now() / 60_000);
  if (!Number.isInteger(numeric) || Math.abs(current - numeric) > 2) return false;
  for (let offset = -2; offset <= 2; offset += 1) {
    const candidateBucket = (current + offset).toString(36);
    const signature = crypto.createHmac("sha256", NONCE_SECRET).update(`${address}|${candidateBucket}`).digest("base64url").slice(0, 18);
    const candidate = `${candidateBucket}.${signature}`;
    if (candidate.length === value.length && crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(value))) return true;
  }
  return false;
}

function allow(address) {
  const timestamp = Date.now();
  let value = limits.get(address);
  if (!value || timestamp - value.window >= 1000) value = { window: timestamp, count: 0 };
  value.count += 1;
  limits.set(address, value);
  return value.count <= 80;
}

function normaliseRemoteAddress(value) {
  const address = String(value).replace(/^::ffff:/, "");
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(address) ? address : "127.0.0.1";
}

function numberEnv(name, fallback, minimum, maximum) {
  const value = Number.parseInt(process.env[name] || "", 10);
  return Number.isInteger(value) && value >= minimum && value <= maximum ? value : fallback;
}

function shutdown() {
  clearInterval(maintenance);
  for (const socket of sockets) socket.close();
  health.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1000).unref();
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

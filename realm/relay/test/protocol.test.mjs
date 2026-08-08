import assert from "node:assert/strict";
import test from "node:test";
import {
  ATTRIBUTE,
  MESSAGE,
  attribute,
  buildMessage,
  crc32,
  getAttribute,
  longTermKey,
  parseMessage,
  verifyMessageIntegrity,
} from "../lib/stun.mjs";
import {
  frameAddress,
  makeControlFrame,
  makeDataFrame,
  parseUsername,
  toBase64Url,
} from "../lib/protocol.mjs";
import { RoomStore } from "../lib/rooms.mjs";

test("verifies the RFC 5769 long-term credential vector", () => {
  const packet = Buffer.from(
    "000100602112a44278ad3433c6ad72c029da412e" +
      "00060012e3839ee38388e383aae38383e382afe382b90000" +
      "0015001c662f2f3439396b39353464364f4c33346f4c39465354767936347341" +
      "0014000b6578616d706c652e6f726700" +
      "00080014f67024656dd64a3e02b8e0712e85c9a28ca89666",
    "hex",
  );
  const message = parseMessage(packet);
  const key = longTermKey("マトリックス", "example.org", "TheMatrIX");
  assert.ok(message);
  assert.equal(verifyMessageIntegrity(message, key), true);
  assert.equal(message.attributes.at(-1).type, ATTRIBUTE.MESSAGE_INTEGRITY);
});

test("builds a response with valid integrity and fingerprint fields", () => {
  const transactionId = Buffer.from("00112233445566778899aabb", "hex");
  const key = longTermKey("tester", "realm-relay", "room-secret");
  const packet = buildMessage({
    type: MESSAGE.ALLOCATE_SUCCESS,
    transactionId,
    attributes: [
      attribute.xorAddress(ATTRIBUTE.XOR_RELAYED_ADDRESS, "25.1.2.3", 12000, transactionId),
      attribute.uint32(ATTRIBUTE.LIFETIME, 60),
    ],
    integrityKey: key,
  });
  const message = parseMessage(packet);
  assert.equal(verifyMessageIntegrity(message, key), true);
  const fingerprint = getAttribute(message, ATTRIBUTE.FINGERPRINT);
  assert.ok(fingerprint);
  assert.equal(fingerprint.value.readUInt32BE(), (crc32(packet.subarray(0, fingerprint.offset)) ^ 0x5354554e) >>> 0);
});

test("parses bounded mailbox usernames", () => {
  const username = [
    "rr1",
    "aabbccddeeff0011",
    "001122334455",
    "abcdef123456",
    toBase64Url("Peter"),
    "1z",
    "a",
    toBase64Url("Hello room"),
  ].join(".");
  assert.deepEqual(parseUsername(username), {
    room: "aabbccddeeff0011",
    clientId: "001122334455",
    requestId: "abcdef123456",
    name: "Peter",
    sequence: 71,
    chunkBase: 10,
    message: "Hello room",
  });
});

test("encodes control and data into valid candidate addresses", () => {
  const control = frameAddress(makeControlFrame(42, 3));
  assert.equal(control.ip, "10.0.0.0");
  assert.equal(control.port, 10755);

  const payload = Buffer.from("hello world", "utf8");
  const first = frameAddress(makeDataFrame(payload, 0));
  const final = frameAddress(makeDataFrame(payload, 2));
  assert.equal(first.ip, "25.104.101.108");
  assert.equal(first.port, 27759);
  assert.equal(final.ip, "31.100.0.0");
  assert.equal(final.port, 1);
});

test("deduplicates multi-lane sends and emits a room event", () => {
  const store = new RoomStore();
  const packet = {
    room: "aabbccddeeff0011",
    clientId: "001122334455",
    requestId: "abcdef123456",
    name: "Peter",
    sequence: 0,
    chunkBase: 0,
    message: "Hello",
  };
  const first = store.touch(packet);
  const second = store.touch(packet);
  assert.equal(first.room.events.filter((event) => event.kind === "message").length, 1);
  assert.equal(second.room.events.filter((event) => event.kind === "message").length, 1);
  assert.equal(store.response(first.room, first.room.sequence).kind, "event");
});

import assert from "node:assert/strict";
import test from "node:test";
import {
  MAX_SLOT_PAYLOAD_BYTES,
  SLOT_CONTROL,
  makeDataFrame,
  makeSlotControlFrame,
  makeSlotPayload,
  parseRendezvousUsername,
} from "../lib/protocol.mjs";
import { RendezvousSlotStore } from "../lib/rendezvous-slots.mjs";

const ROOM = "aabbccddeeff0011";
const WRITER = "001122334455";
const READER = "66778899aabb";
const OTHER_READER = "ccddee112233";
const FROM = "0011223344556677";
const TO = "8899aabbccddeeff";
const ATTEMPT = "0123456789abcdeffedcba9876543210";
const ZERO_DEVICE = "0000000000000000";

function envelope(overrides = {}) {
  return {
    version: "rr2",
    room: ROOM,
    actor: WRITER,
    from: FROM,
    to: TO,
    attempt: ATTEMPT,
    role: "o",
    operation: "put",
    revision: 0,
    chunkBase: 0,
    payload: Buffer.from("offer-token"),
    ...overrides,
  };
}

function username(overrides = {}) {
  const value = envelope(overrides);
  return [
    "rr2",
    value.room,
    value.actor,
    value.from,
    value.to,
    value.attempt,
    value.role,
    value.operation,
    value.revision.toString(36),
    value.chunkBase.toString(36),
    value.payload.length ? value.payload.toString("base64url") : "0",
  ].join(".");
}

test("parses bounded rr2 slot operations without accepting rr1-shaped identities", () => {
  const parsed = parseRendezvousUsername(username());
  assert.ok(parsed);
  assert.equal(parsed.actor, WRITER);
  assert.equal(parsed.from, FROM);
  assert.equal(parsed.to, TO);
  assert.deepEqual(parsed.payload, Buffer.from("offer-token"));

  const largest = parseRendezvousUsername(username({
    room: "r".repeat(40),
    role: "c",
    payload: Buffer.alloc(MAX_SLOT_PAYLOAD_BYTES, 0xab),
  }));
  assert.equal(largest.payload.length, MAX_SLOT_PAYLOAD_BYTES);

  assert.equal(parseRendezvousUsername(username({ from: FROM.slice(0, 12) })), null);
  assert.equal(parseRendezvousUsername(username({ actor: FROM })), null);
  assert.equal(parseRendezvousUsername(username({ payload: Buffer.alloc(MAX_SLOT_PAYLOAD_BYTES + 1) })), null);
  assert.equal(parseRendezvousUsername(username({ actor: "000000000000" })), null);
  assert.equal(parseRendezvousUsername(username({ attempt: "0".repeat(32) })), null);
  assert.ok(parseRendezvousUsername(username({ to: ZERO_DEVICE })));
  assert.equal(parseRendezvousUsername(username({ from: ZERO_DEVICE })), null);
});

test("parses late-offer discovery and all attempt-scoped fallback roles", () => {
  const discovery = parseRendezvousUsername(username({
    actor: READER,
    attempt: "0",
    operation: "discover",
    payload: Buffer.alloc(0),
  }));
  assert.ok(discovery);
  assert.equal(discovery.attempt, "0");
  assert.equal(discovery.role, "o");

  for (const role of ["o", "a", "n", "c", "k", "x"]) {
    assert.ok(parseRendezvousUsername(username({ role })));
  }
  assert.equal(parseRendezvousUsername(username({
    attempt: "0",
    role: "a",
    operation: "discover",
    payload: Buffer.alloc(0),
  })), null);
  assert.ok(parseRendezvousUsername(username({
    actor: READER,
    from: ZERO_DEVICE,
    to: ZERO_DEVICE,
    attempt: "0",
    operation: "discover",
    payload: Buffer.alloc(0),
  })));
  assert.ok(parseRendezvousUsername(username({
    actor: READER,
    from: ZERO_DEVICE,
    attempt: ATTEMPT,
    role: "a",
    operation: "discover",
    payload: Buffer.alloc(0),
  })));
});

test("put is idempotent, pins its relay writer, and replaces only by revision", () => {
  const slots = new RendezvousSlotStore();
  assert.deepEqual(slots.execute(envelope()), { kind: "stored", revision: 1, unchanged: false });
  assert.deepEqual(slots.execute(envelope()), { kind: "stored", revision: 1, unchanged: true });

  assert.equal(slots.execute(envelope({ actor: READER })).error, "forbidden");
  assert.equal(slots.execute(envelope({ payload: Buffer.from("changed") })).error, "conflict");
  assert.deepEqual(slots.execute(envelope({
    revision: 1,
    payload: Buffer.from("changed"),
  })), { kind: "stored", revision: 2, unchanged: false });
});

test("discover returns the latest directed offer and pins a distinct relay reader", () => {
  let timestamp = 1000;
  const slots = new RendezvousSlotStore({ clock: () => timestamp });
  slots.execute(envelope());
  timestamp += 1;
  const newestAttempt = "11111111111111111111111111111111";
  slots.execute(envelope({ attempt: newestAttempt, payload: Buffer.from("new offer") }));

  const discovery = envelope({
    actor: READER,
    attempt: "0",
    operation: "discover",
    payload: Buffer.alloc(0),
  });
  const found = slots.execute(discovery);
  assert.equal(found.kind, "data");
  assert.equal(found.attempt, newestAttempt);
  assert.equal(found.revision, 1);
  assert.deepEqual(found.payload, Buffer.from("new offer"));
  assert.equal(slots.execute(envelope({
    attempt: newestAttempt,
    revision: 1,
    payload: Buffer.from("cannot change after read"),
  })).error, "conflict");

  assert.equal(slots.execute({ ...discovery, actor: OTHER_READER }).error, "forbidden");
  timestamp += 1;
  const laterAttempt = "33333333333333333333333333333333";
  slots.execute(envelope({ attempt: laterAttempt, payload: Buffer.from("later offer") }));
  assert.equal(slots.execute(discovery).attempt, newestAttempt);
  assert.equal(slots.execute({ ...discovery, actor: OTHER_READER }).attempt, laterAttempt);
  assert.equal(slots.execute(envelope({
    actor: READER,
    attempt: newestAttempt,
    operation: "get",
    revision: 1,
    payload: Buffer.alloc(0),
  })).kind, "not-modified");
});

test("wildcard discovery supports one-consumer bootstrap offers and unknown answer senders", () => {
  const slots = new RendezvousSlotStore();
  slots.execute(envelope({ to: ZERO_DEVICE, payload: Buffer.from("broadcast offer") }));
  const offer = slots.execute(envelope({
    actor: READER,
    from: ZERO_DEVICE,
    to: ZERO_DEVICE,
    attempt: "0",
    operation: "discover",
    payload: Buffer.alloc(0),
  }));
  assert.equal(offer.kind, "data");
  assert.equal(offer.attempt, ATTEMPT);
  assert.deepEqual(offer.payload, Buffer.from("broadcast offer"));
  assert.equal(slots.execute(envelope({
    actor: OTHER_READER,
    from: ZERO_DEVICE,
    to: ZERO_DEVICE,
    attempt: "0",
    operation: "discover",
    payload: Buffer.alloc(0),
  })).error, "forbidden");

  const joiner = "abcdefabcdefabcd";
  const host = FROM;
  slots.execute(envelope({
    actor: READER,
    from: joiner,
    to: host,
    role: "a",
    payload: Buffer.from("directed answer"),
  }));
  const answer = slots.execute(envelope({
    actor: WRITER,
    from: ZERO_DEVICE,
    to: host,
    role: "a",
    operation: "discover",
    payload: Buffer.alloc(0),
  }));
  assert.equal(answer.kind, "data");
  assert.deepEqual(answer.payload, Buffer.from("directed answer"));
});

test("reader claims recover after a bounded lease and idempotent puts refresh slot TTL", () => {
  let timestamp = 1000;
  const slots = new RendezvousSlotStore({
    clock: () => timestamp,
    slotTtlMs: 100,
    readerLeaseMs: 10,
  });
  slots.execute(envelope());
  const read = envelope({ actor: READER, operation: "get", payload: Buffer.alloc(0) });
  assert.equal(slots.execute(read).kind, "data");
  assert.equal(slots.execute({ ...read, actor: OTHER_READER }).error, "forbidden");
  timestamp += 10;
  assert.equal(slots.execute({ ...read, actor: OTHER_READER }).kind, "data");

  timestamp = 1090;
  slots.execute(envelope());
  timestamp = 1101;
  slots.pruneAll();
  assert.equal(slots.stats().slots, 1);
});

test("ack and abort erase payloads and leave bounded idempotent tombstones", () => {
  let timestamp = 1000;
  const slots = new RendezvousSlotStore({
    clock: () => timestamp,
    slotTtlMs: 100,
    terminalTtlMs: 20,
  });
  slots.execute(envelope());
  slots.execute(envelope({
    actor: READER,
    operation: "get",
    payload: Buffer.alloc(0),
  }));
  const ack = envelope({
    actor: READER,
    operation: "ack",
    revision: 1,
    payload: Buffer.alloc(0),
  });
  assert.equal(slots.execute(ack).kind, "acked");
  assert.equal(slots.execute(ack).kind, "acked");
  assert.equal(slots.execute(envelope()).kind, "acked");

  timestamp += 20;
  slots.pruneAll();
  assert.equal(slots.stats().slots, 0);

  const secondAttempt = "22222222222222222222222222222222";
  slots.execute(envelope({ attempt: secondAttempt }));
  assert.equal(slots.execute(envelope({
    attempt: secondAttempt,
    operation: "abort",
    revision: 1,
    payload: Buffer.alloc(0),
  })).kind, "aborted");
});

test("the default ACK tombstone survives the full five-minute resume window", () => {
  let timestamp = 1000;
  const slots = new RendezvousSlotStore({ clock: () => timestamp });
  slots.execute(envelope());
  slots.execute(envelope({ actor: READER, operation: "get", payload: Buffer.alloc(0) }));
  const ack = envelope({
    actor: READER,
    operation: "ack",
    revision: 1,
    payload: Buffer.alloc(0),
  });
  assert.equal(slots.execute(ack).kind, "acked");
  timestamp += 299_999;
  slots.pruneAll();
  assert.equal(slots.execute(envelope()).kind, "acked");
  timestamp += 1;
  slots.pruneAll();
  assert.equal(slots.stats().slots, 0);
});

test("role slots are independent and cardinality is bounded without live eviction", () => {
  const slots = new RendezvousSlotStore({ maxSlots: 2, maxSlotsPerRoom: 2 });
  assert.equal(slots.execute(envelope({ role: "n" })).kind, "stored");
  assert.equal(slots.execute(envelope({ role: "c" })).kind, "stored");
  assert.equal(slots.execute(envelope({ role: "a" })).error, "full");
  assert.deepEqual(slots.stats(), {
    rooms: 1,
    slots: 2,
    active: 2,
    acked: 0,
    aborted: 0,
    operations: {
      put: 3,
      get: 0,
      discover: 0,
      ack: 0,
      abort: 0,
      idempotent: 0,
      conflicts: 0,
      rejected: 1,
      expired: 0,
    },
  });
});

test("slot data framing carries attempt and revision before bounded token bytes", () => {
  const token = Buffer.from("token");
  const payload = makeSlotPayload({ from: FROM, to: TO, attempt: ATTEMPT, role: "o", revision: 7, payload: token });
  const decoded = Buffer.from(payload.toString("ascii"), "base64url");
  assert.equal(decoded.subarray(0, 8).toString("hex"), FROM);
  assert.equal(decoded.subarray(8, 16).toString("hex"), TO);
  assert.equal(decoded.subarray(16, 32).toString("hex"), ATTEMPT);
  assert.equal(String.fromCharCode(decoded[32]), "o");
  assert.equal(decoded.readUInt32BE(33), 7);
  assert.deepEqual(decoded.subarray(37), token);

  const chunks = [];
  for (let index = 0; index < 20; index += 1) {
    const frame = makeDataFrame(payload, index);
    const final = frame[0] >= 30;
    const length = frame[0] - (final ? 30 : 20);
    chunks.push(frame.subarray(1, 1 + length));
    if (final) break;
  }
  assert.deepEqual(Buffer.concat(chunks), payload);

  const control = makeSlotControlFrame(SLOT_CONTROL.STORED, 7);
  assert.equal(control[0], 51);
  assert.equal(control.readUInt32BE(1), 7);
  assert.equal(control[5], 1);
});

test("maximum binary slot payload survives every five-byte address chunk", () => {
  const token = Buffer.alloc(MAX_SLOT_PAYLOAD_BYTES);
  for (let index = 0; index < token.length; index += 1) token[index] = index % 17 === 0 ? 0 : index;
  const payload = makeSlotPayload({
    from: FROM,
    to: TO,
    attempt: ATTEMPT,
    role: "c",
    revision: 0xffffffff,
    payload: token,
  });
  assert.equal(payload.length, 370);

  const chunks = [];
  for (let index = 0; index < 100; index += 1) {
    const frame = makeDataFrame(payload, index);
    const final = frame[0] >= 30;
    const length = frame[0] - (final ? 30 : 20);
    chunks.push(frame.subarray(1, 1 + length));
    if (final) break;
  }
  const reconstructed = Buffer.concat(chunks);
  assert.deepEqual(reconstructed, payload);
  const decoded = Buffer.from(reconstructed.toString("ascii"), "base64url");
  assert.equal(decoded.subarray(0, 8).toString("hex"), FROM);
  assert.equal(decoded.subarray(8, 16).toString("hex"), TO);
  assert.equal(decoded.subarray(16, 32).toString("hex"), ATTEMPT);
  assert.equal(String.fromCharCode(decoded[32]), "c");
  assert.equal(decoded.readUInt32BE(33), 0xffffffff);
  assert.deepEqual(decoded.subarray(37), token);
});

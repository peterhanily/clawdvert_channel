import assert from "node:assert/strict";
import test from "node:test";

import { RendezvousV2SlotTransport } from "../../src/rendezvous-v2-transport.js";

const FROM = "1021324354657687";
const TO = "98a9bacbdcedfe0f";
const ATTEMPT = "00112233445566778899aabbccddeeff";
const LANES = 6;

function dataFrame(encoded, chunkIndex) {
  const start = chunkIndex * 5;
  const chunk = encoded.slice(start, start + 5);
  const final = start + chunk.length >= encoded.length;
  const frame = new Uint8Array(6);
  frame[0] = (final ? 30 : 20) + chunk.length;
  for (let index = 0; index < chunk.length; index += 1) {
    frame[index + 1] = chunk.charCodeAt(index);
  }
  if (frame[4] === 0 && frame[5] === 0) frame[5] = 1;
  return frame;
}

function responsePayload(tokenBytes) {
  const route = Buffer.alloc(37);
  Buffer.from(FROM, "hex").copy(route, 0);
  Buffer.from(TO, "hex").copy(route, 8);
  Buffer.from(ATTEMPT, "hex").copy(route, 16);
  route[32] = "a".charCodeAt(0);
  route.writeUInt32BE(1, 33);
  return Buffer.concat([route, Buffer.from(tokenBytes)]).toString("base64url");
}

function boundedExchange(handler) {
  const exchange = handler;
  Object.defineProperties(exchange, {
    laneCount: { value: LANES },
    capacity: { value: 8 },
    highPriorityReserve: { value: 4 },
    normalCapacity: { value: 4 },
    isolatedExchangeBudgetMs: { value: 1000 },
  });
  exchange.close = () => {};
  return exchange;
}

test("a transient later-page failure leaves the claimed value retryable", async () => {
  const tokenBytes = Uint8Array.from({ length: 80 }, (_, index) => index + 1);
  const encoded = responsePayload(tokenBytes);
  let failSecondPage = true;
  let abortCalls = 0;
  const exchange = boundedExchange(async username => {
    const parts = username.split(".");
    const operation = parts[7];
    const chunkBase = Number.parseInt(parts[9], 36);
    if (operation === "abort") {
      abortCalls += 1;
      throw new Error("a partial read must not issue abort");
    }
    assert.equal(operation, "discover");
    if (chunkBase === LANES && failSecondPage) {
      failSecondPage = false;
      throw new Error("transient TURN page failure");
    }
    return Array.from({ length: LANES }, (_, lane) => dataFrame(encoded, chunkBase + lane));
  });
  const transport = new RendezvousV2SlotTransport({
    room: "cv0123456789abcdef0123456789abcdef",
    actor: "abcdef012345",
    exchange,
    laneCount: LANES,
    maxTrackedAttempts: 2,
    maxOwnedSlotsPerAttempt: 2,
  });
  const selector = { from: "0000000000000000", to: TO, attemptId: ATTEMPT, role: "answer" };

  await assert.rejects(transport.discover(selector), /transient TURN page failure/);
  assert.equal(abortCalls, 0);
  const retried = await transport.discover(selector);
  assert.equal(retried.status, "data");
  assert.deepEqual(retried.tokenBytes, tokenBytes);
  assert.deepEqual(retried.receipt, {
    from: FROM,
    to: TO,
    attemptId: ATTEMPT,
    role: "a",
    revision: 1,
  });
  assert.equal(abortCalls, 0);
  transport.close();
});

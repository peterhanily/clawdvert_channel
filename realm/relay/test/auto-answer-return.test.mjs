import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

import {
  AUTO_ANSWER_RETURN,
  createAutoAnswerInviteDescriptor,
  createAutoAnswerSlot,
  deriveAutoAnswerReturnKeys,
  unwrapAutoAnswerToken,
  validateAutoAnswerInviteDescriptor,
  verifyAutoAnswerAnswerSlot,
  wrapAutoAnswerToken,
} from "../../src/auto-answer-return.js";
import { RENDEZVOUS_V2 } from "../../src/rendezvous-v2-codec.js";

const HOST = "1021324354657687";
const JOINER = "98a9bacbdcedfe0f";
const NOW_MS = 1_786_293_600_000;
const NOW = NOW_MS / 1000;
const META = Object.freeze({
  app: "clawdvert_channel",
  roomId: "0123456789abcdef01234567",
  session: "00112233445566778899",
  inviteId: "89abcdef01234567",
  host: HOST,
  hostRoute: "canary-v1",
});
const OFFER_SDP = [
  "v=0", "o=- 1 2 IN IP4 127.0.0.1", "s=-", "t=0 0",
  "m=application 9 UDP/DTLS/SCTP webrtc-datachannel", "a=mid:0",
  "a=ice-ufrag:Offer123", "a=ice-pwd:abcdefghijklmnopqrstuvwx",
  `a=fingerprint:sha-256 ${Array(32).fill("AA").join(":")}`,
  "a=setup:actpass", "a=sctp-port:5000",
].join("\r\n") + "\r\n";
const ANSWER_SDP = [
  "v=0", "o=- 3 4 IN IP4 127.0.0.1", "s=-", "t=0 0",
  "m=application 9 UDP/DTLS/SCTP webrtc-datachannel", "c=IN IP4 0.0.0.0",
  "a=ice-ufrag:Answer12", "a=ice-pwd:zyxwvutsrqponmlkjihgfedc",
  `a=fingerprint:sha-256 ${Array(32).fill("BB").join(":")}`,
  "a=setup:active", "a=mid:0", "a=sctp-port:5000",
  "a=candidate:1 1 udp 1677730815 192.0.2.44 49152 typ relay raddr 0.0.0.0 rport 9",
  "a=candidate:2 1 tcp 1518280447 2001:db8:1234::44 443 typ relay raddr :: rport 9 tcptype passive",
  "a=end-of-candidates",
].join("\r\n") + "\r\n";

async function fixture(expiresAt = NOW_MS + 240_000) {
  const descriptor = await createAutoAnswerInviteDescriptor({
    ...META,
    offerSdp: OFFER_SDP,
    expiresAt,
    nowMs: NOW_MS,
    crypto: webcrypto,
    subtle: webcrypto.subtle,
  });
  const validation = { offerSdp: OFFER_SDP, expected: META, nowMs: NOW_MS,
    subtle: webcrypto.subtle };
  const keys = await deriveAutoAnswerReturnKeys(descriptor, validation);
  return { descriptor, keys, validation };
}

function readResult(slot, revision = 1) {
  return {
    status: "data",
    receipt: { ...slot.selector, role: "a", revision },
    tokenBytes: slot.tokenBytes,
  };
}

test("descriptor binds the canonical invite, exact offer, route, and absolute expiry", async () => {
  const { descriptor, validation } = await fixture();
  assert.equal(descriptor.host, HOST);
  assert.equal(descriptor.hostRoute, "canary-v1");
  assert.equal(descriptor.expiresAt, NOW_MS + 240_000);
  assert.match(descriptor.offerSha256, /^[a-f0-9]{64}$/);
  assert.match(descriptor.bindingSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(await validateAutoAnswerInviteDescriptor(descriptor, validation), descriptor);

  await assert.rejects(validateAutoAnswerInviteDescriptor(descriptor, {
    ...validation,
    offerSdp: OFFER_SDP.replace("Offer123", "Changed1"),
  }), error => error.code === "WRONG_BINDING");
  await assert.rejects(validateAutoAnswerInviteDescriptor(descriptor, {
    ...validation,
    expected: { ...META, roomId: "ffffffffffffffffffffffff" },
  }), error => error.code === "WRONG_BINDING");
  await assert.rejects(validateAutoAnswerInviteDescriptor({
    ...descriptor,
    hostRoute: "changed-route",
  }, validation), error => error.code === "WRONG_BINDING");
});

test("descriptor rejects expiry, future extension, and creation beyond five minutes", async () => {
  const { descriptor, validation } = await fixture();
  await assert.rejects(validateAutoAnswerInviteDescriptor(descriptor, {
    ...validation,
    nowMs: descriptor.expiresAt,
  }), error => error.code === "EXPIRED");
  await assert.rejects(validateAutoAnswerInviteDescriptor({
    ...descriptor,
    expiresAt: NOW_MS + 600_000,
  }, validation), error => ["EXPIRED", "WRONG_BINDING"].includes(error.code));
  await assert.rejects(createAutoAnswerInviteDescriptor({
    ...META,
    offerSdp: OFFER_SDP,
    expiresAt: NOW_MS + 300_001,
    nowMs: NOW_MS,
    crypto: webcrypto,
    subtle: webcrypto.subtle,
  }), error => error.code === "INVALID_EXPIRY");
});
test("derives stable non-extractable keys and private rr2 room from the full binding", async () => {
  const { descriptor, keys, validation } = await fixture();
  const again = await deriveAutoAnswerReturnKeys(descriptor, validation);
  assert.equal(keys.relayRoom, again.relayRoom);
  assert.match(keys.relayRoom, /^cv[a-f0-9]{32}$/);
  assert.equal(keys.contextId, descriptor.bindingSha256.slice(0, 24));
  assert.equal(keys.tokenKey.extractable, false);
  assert.equal(keys.wrappingKey.extractable, false);
});

test("AES-GCM wrapper is receipt-bound and remains below the rr2 240-byte limit", async () => {
  const { descriptor, keys } = await fixture();
  const plaintext = Uint8Array.from({ length: RENDEZVOUS_V2.maxTokenBytes }, (_, index) => index);
  const route = { from: JOINER, to: HOST, attemptId: descriptor.attemptId, role: "answer" };
  const wrapped = await wrapAutoAnswerToken({
    descriptor,
    keys,
    route,
    tokenBytes: plaintext,
    nonce: new Uint8Array(12).fill(7),
    subtle: webcrypto.subtle,
  });
  assert.equal(wrapped.length, AUTO_ANSWER_RETURN.maxWrappedBytes);
  assert.equal(wrapped.length, 236);
  const opened = await unwrapAutoAnswerToken({
    descriptor,
    keys,
    receipt: { ...route, revision: 1 },
    tokenBytes: wrapped,
    subtle: webcrypto.subtle,
  });
  assert.deepEqual(opened, plaintext);
  await assert.rejects(unwrapAutoAnswerToken({
    descriptor,
    keys,
    receipt: { ...route, from: "1111111111111111", revision: 1 },
    tokenBytes: wrapped,
    subtle: webcrypto.subtle,
  }), error => error.code === "AUTH_FAILED");
});

test("answer token fits the descriptor expiry and is bound to its rr2 receipt", async () => {
  const { descriptor, keys } = await fixture(NOW_MS + 180_000);
  const slot = await createAutoAnswerSlot({
    descriptor,
    keys,
    from: JOINER,
    to: HOST,
    sdp: ANSWER_SDP,
    nowSeconds: NOW,
    crypto: webcrypto,
    subtle: webcrypto.subtle,
  });
  assert.equal(slot.token.issuedAt + slot.token.lifetimeSeconds,
    Math.floor(descriptor.expiresAt / 1000));
  assert.ok(slot.tokenBytes.length <= 240);
  const verified = await verifyAutoAnswerAnswerSlot({
    descriptor,
    keys,
    readResult: readResult(slot),
    nowSeconds: NOW + 1,
    subtle: webcrypto.subtle,
  });
  assert.equal(verified.envelope.from, JOINER);
  assert.equal(verified.candidates.length, 2);
  assert.doesNotMatch(verified.remoteDescription.sdp, /^a=candidate:/m);

  const wrong = readResult(slot);
  wrong.receipt.from = "1111111111111111";
  await assert.rejects(verifyAutoAnswerAnswerSlot({
    descriptor,
    keys,
    readResult: wrong,
    nowSeconds: NOW + 1,
    subtle: webcrypto.subtle,
  }), error => error.code === "AUTH_FAILED");
  await assert.rejects(verifyAutoAnswerAnswerSlot({
    descriptor,
    keys,
    readResult: readResult(slot),
    nowSeconds: Math.floor(descriptor.expiresAt / 1000),
    subtle: webcrypto.subtle,
  }), error => error.code === "EXPIRED");
});

test("answer creation refuses any lifetime extending beyond the absolute descriptor expiry", async () => {
  const { descriptor, keys } = await fixture(NOW_MS + 60_000);
  await assert.rejects(createAutoAnswerSlot({
    descriptor,
    keys,
    from: JOINER,
    to: HOST,
    sdp: ANSWER_SDP,
    nowSeconds: NOW,
    lifetimeSeconds: 61,
    crypto: webcrypto,
    subtle: webcrypto.subtle,
  }), error => error.code === "INVALID_EXPIRY");
});

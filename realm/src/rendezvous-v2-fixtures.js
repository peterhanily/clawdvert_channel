/*
 * Deterministic, inert fixture definitions for the rendezvous V2 codec.
 * They deliberately do not invoke Web Crypto or execute assertions at import.
 */

export const RENDEZVOUS_V2_FIXTURE_KEY = Uint8Array.of(
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
);

const ICE = Object.freeze({
  ufrag: "AbcD1234",
  password: "abcdefghijklmnopqrstuvwx",
  fingerprint: [
    "00", "11", "22", "33", "44", "55", "66", "77",
    "88", "99", "AA", "BB", "CC", "DD", "EE", "FF",
    "10", "21", "32", "43", "54", "65", "76", "87",
    "98", "A9", "BA", "CB", "DC", "ED", "FE", "0F",
  ].join(":"),
});

const BASE = Object.freeze({
  profile: "pairwise",
  attemptId: "00112233445566778899aabbccddeeff",
  contextId: "c0dec0dec0dec0dec0dec0de",
  from: "1021324354657687",
  to: "98a9bacbdcedfe0f",
  issuedAt: 1786233600,
  lifetimeSeconds: 180,
});

export const RENDEZVOUS_V2_FIXTURES = Object.freeze({
  offer: Object.freeze({
    ...BASE,
    role: "offer",
    ice: Object.freeze({ ...ICE, setup: "actpass" }),
    candidates: Object.freeze([]),
  }),
  answer: Object.freeze({
    ...BASE,
    role: "answer",
    from: BASE.to,
    to: BASE.from,
    ice: Object.freeze({ ...ICE, setup: "active" }),
    candidates: Object.freeze([
      Object.freeze({
        family: "ipv4",
        protocol: "udp",
        type: "relay",
        tcpType: null,
        priority: 1677730815,
        address: "192.0.2.44",
        port: 49152,
      }),
      Object.freeze({
        family: "ipv6",
        protocol: "tcp",
        type: "relay",
        tcpType: "passive",
        priority: 1518280447,
        address: "2001:db8:1234::44",
        port: 443,
      }),
    ]),
  }),
  acknowledgeOffer: Object.freeze({
    ...BASE,
    role: "ack",
    referenceRole: "offer",
    from: BASE.to,
    to: BASE.from,
    candidates: Object.freeze([]),
  }),
  expectedMeasurements: Object.freeze({
    offer: Object.freeze({ bodyBytes: 122, tokenBytes: 138, wireChars: 188 }),
    answer: Object.freeze({ bodyBytes: 156, tokenBytes: 172, wireChars: 234 }),
    acknowledgeOffer: Object.freeze({ bodyBytes: 56, tokenBytes: 72, wireChars: 100 }),
  }),
});

import assert from "node:assert/strict";
import test from "node:test";

import { createRendezvousV2TurnExchange } from "../../src/rendezvous-v2-turn-exchange.js";

test("the TURN carrier accepts WebKit relay text when RTCIceCandidate.type is absent", async () => {
  class LegacyWebKitPeerConnection {
    constructor() {
      this.iceGatheringState = "new";
    }

    createDataChannel() {}

    async createOffer() {
      return { type: "offer", sdp: "v=0\r\n" };
    }

    async setLocalDescription() {
      queueMicrotask(() => this.onicecandidate?.({
        candidate: {
          candidate: "candidate:1 1 udp 1677730815 192.0.2.44 49152 typ relay raddr 0.0.0.0 rport 9",
        },
      }));
    }

    close() {}
  }

  const exchange = createRendezvousV2TurnExchange({
    host: "127.0.0.1",
    ports: [3478],
    room: "cv0123456789abcdef0123456789abcdef",
    getPeerConnectionConstructor: () => LegacyWebKitPeerConnection,
    timeoutMs: 500,
    minimumExchangeIntervalMs: 250,
    exchangeJitterMs: 0,
    maxQueuedExchanges: 4,
    reservedHighPriorityExchanges: 1,
  });
  const frames = await exchange("rr2-test");
  assert.equal(frames.length, 1);
  assert.deepEqual(frames[0], Uint8Array.of(192, 0, 2, 44, 192, 0));
  exchange.close();
});

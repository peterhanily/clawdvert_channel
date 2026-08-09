/*
 * Browser-portable SDP helpers for rendezvous V2.
 *
 * Offers and reconstructed answers intentionally contain no candidates.  The
 * offerer adds the verified answer candidates only after setRemoteDescription,
 * allowing the answerer's first peer-reflexive pair to be learned from the
 * incoming ICE check.  No function in this module schedules a wall-clock start.
 */

import {
  formatSdpCandidate,
  normalizeRendezvousCandidate,
  parseSdpCandidate,
} from "./rendezvous-v2-codec.js";

const ICE_TEXT = /^[A-Za-z0-9+/]+$/;
const FINGERPRINT = /^(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}$/;
const SETUP = new Set(["actpass", "active", "passive"]);

function fail(message) {
  throw new TypeError(message);
}

function firstAttribute(sdp, name) {
  const prefix = `a=${name}:`;
  for (const line of String(sdp ?? "").split(/\r?\n/)) {
    if (line.startsWith(prefix)) return line.slice(prefix.length).trim();
  }
  return "";
}

function canonicalFingerprint(value) {
  const fingerprint = String(value ?? "").trim().toUpperCase();
  if (!FINGERPRINT.test(fingerprint)) fail("A SHA-256 DTLS fingerprint is required.");
  return fingerprint;
}

function canonicalIceText(value, minimum, maximum, name) {
  const text = String(value ?? "");
  if (text.length < minimum || text.length > maximum || !ICE_TEXT.test(text)) {
    fail(`${name} is outside the rendezvous V2 ICE profile.`);
  }
  return text;
}

/** Extract only the non-derivable ICE and DTLS fields from a local SDP. */
export function extractRendezvousIce(sdp) {
  const setup = firstAttribute(sdp, "setup").toLowerCase();
  if (!SETUP.has(setup)) fail("The SDP has no supported DTLS setup role.");
  const fingerprintLine = firstAttribute(sdp, "fingerprint");
  const match = fingerprintLine.match(/^sha-256\s+(.+)$/i);
  if (!match) fail("The SDP has no SHA-256 DTLS fingerprint.");
  return Object.freeze({
    ufrag: canonicalIceText(firstAttribute(sdp, "ice-ufrag"), 4, 32, "ICE ufrag"),
    password: canonicalIceText(firstAttribute(sdp, "ice-pwd"), 22, 64, "ICE password"),
    fingerprint: canonicalFingerprint(match[1]),
    setup,
  });
}

function candidateRank(candidate) {
  if (candidate.type === "relay" && candidate.protocol === "udp") return 0;
  if (candidate.type === "relay" && candidate.protocol === "tcp") return 1;
  if (candidate.type === "srflx" && candidate.protocol === "udp") return 2;
  if (candidate.type === "srflx" && candidate.protocol === "tcp") return 3;
  if (candidate.type === "host" && candidate.protocol === "udp") return 4;
  if (candidate.type === "host" && candidate.protocol === "tcp") return 5;
  return 99;
}

function routeKey(candidate) {
  return [candidate.family, candidate.protocol, candidate.type, candidate.tcpType || "",
    candidate.address, candidate.port].join("|");
}

function diversityRank(left, right) {
  if (left.protocol !== right.protocol) return 0;
  if (left.family !== right.family) return 1;
  if (left.type !== right.type) return 2;
  if (left.address !== right.address) return 3;
  return 4;
}

/**
 * Select up to two stable, route-diverse candidates. FQDN/mDNS and prflx input
 * are skipped because their text cannot be represented by the binary profile.
 */
export function selectRendezvousCandidates(sdp, {
  allowHost = false,
  maxCandidates = 2,
} = {}) {
  if (!Number.isSafeInteger(maxCandidates) || maxCandidates < 1 || maxCandidates > 2) {
    fail("maxCandidates must be one or two.");
  }
  const candidates = [];
  const seen = new Set();
  for (const line of String(sdp ?? "").split(/\r?\n/)) {
    if (!line.startsWith("a=candidate:")) continue;
    try {
      const candidate = parseSdpCandidate(line);
      if (!allowHost && candidate.type === "host") continue;
      const key = routeKey(candidate);
      if (seen.has(key)) continue;
      seen.add(key);
      candidates.push(candidate);
    } catch {
      // Unsupported candidate types and text addresses are excluded, never
      // silently rewritten as another family or transport.
    }
  }
  candidates.sort((left, right) => candidateRank(left) - candidateRank(right)
    || right.priority - left.priority
    || routeKey(left).localeCompare(routeKey(right)));
  if (candidates.length <= maxCandidates) return Object.freeze(candidates);
  const selected = [candidates[0]];
  if (maxCandidates === 2) {
    const fallback = candidates.slice(1).sort((left, right) =>
      diversityRank(selected[0], left) - diversityRank(selected[0], right)
      || candidateRank(left) - candidateRank(right)
      || right.priority - left.priority
      || routeKey(left).localeCompare(routeKey(right)))[0];
    selected.push(fallback);
  }
  return Object.freeze(selected);
}

/** Rebuild the fixed one-data-channel SDP without remote candidates. */
export function buildRendezvousDataChannelSdp({ type, ice }) {
  if (type !== "offer" && type !== "answer") fail("SDP type must be offer or answer.");
  if (!ice || typeof ice !== "object") fail("ICE parameters are required.");
  const setup = String(ice.setup ?? "").toLowerCase();
  if ((type === "offer" && setup !== "actpass")
      || (type === "answer" && setup !== "active" && setup !== "passive")) {
    fail(`The DTLS setup role is not valid for a WebRTC ${type}.`);
  }
  const ufrag = canonicalIceText(ice.ufrag, 4, 32, "ICE ufrag");
  const password = canonicalIceText(ice.password, 22, 64, "ICE password");
  const fingerprint = canonicalFingerprint(ice.fingerprint);
  return [
    "v=0",
    "o=- 0 0 IN IP4 127.0.0.1",
    "s=-",
    "t=0 0",
    "a=group:BUNDLE 0",
    "a=extmap-allow-mixed",
    "a=msid-semantic: WMS",
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
    "c=IN IP4 0.0.0.0",
    `a=ice-ufrag:${ufrag}`,
    `a=ice-pwd:${password}`,
    "a=ice-options:trickle",
    `a=fingerprint:sha-256 ${fingerprint}`,
    `a=setup:${setup}`,
    "a=mid:0",
    "a=sctp-port:5000",
    "a=max-message-size:262144",
  ].join("\r\n") + "\r\n";
}

/** Convert a verified binary candidate record into the browser API shape. */
export function candidateToIceCandidateInit(candidate, index = 0) {
  if (!Number.isSafeInteger(index) || index < 0) fail("candidate index must be a non-negative integer.");
  const normalized = normalizeRendezvousCandidate(candidate);
  return Object.freeze({
    candidate: formatSdpCandidate(normalized, { foundation: String(index + 1) }),
    sdpMid: "0",
    sdpMLineIndex: 0,
  });
}

/** Apply one finite verified candidate batch and close remote trickle input. */
export async function addRendezvousCandidates(peerConnection, candidates) {
  if (!peerConnection || typeof peerConnection.addIceCandidate !== "function") {
    fail("A peer connection with addIceCandidate() is required.");
  }
  if (!Array.isArray(candidates) || !candidates.length || candidates.length > 2) {
    fail("A verified batch of one or two candidates is required.");
  }
  for (let index = 0; index < candidates.length; index += 1) {
    await peerConnection.addIceCandidate(candidateToIceCandidateInit(candidates[index], index));
  }
  // The zero-candidate SDP must not contain end-of-candidates. Signal it only
  // after every authenticated candidate in this finite trickle batch applied.
  await peerConnection.addIceCandidate(null);
}

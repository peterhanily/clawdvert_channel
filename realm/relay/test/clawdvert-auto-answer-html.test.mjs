import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const html = fs.readFileSync(new URL("../../clawdvert_channel.html", import.meta.url), "utf8");

function functionSource(name, nextName) {
  const declaration = candidate => {
    const regular = html.indexOf(`  function ${candidate}(`);
    return regular >= 0 ? regular : html.indexOf(`  async function ${candidate}(`);
  };
  const start = declaration(name);
  const end = declaration(nextName);
  assert.notEqual(start, -1, `${name} is missing`);
  assert.notEqual(end, -1, `${nextName} boundary is missing`);
  return html.slice(start, end);
}

test("a successful early data channel cannot reopen failed automatic-answer UI", () => {
  const source = functionSource("autoAnswerJoinerFailed", "startManualAnswerConnection");
  for (const guard of [
    "conn.manualRemoteCandidatesStarted",
    "conn.openedAt",
    "conn.peerId",
    "state.membershipConfirmed",
  ]) assert.ok(source.includes(guard), `missing successful-join guard: ${guard}`);
});

test("revealing fallback does not cancel automatic ACK observation", () => {
  const source = functionSource("revealJoinManualFallback", "showManualAnswerFallback");
  assert.doesNotMatch(source, /stopAutoAnswerReturn/);
  assert.match(source, /manualRemoteCandidatesStarted/);
});

test("candidate release atomically claims start before its first ICE mutation", () => {
  const source = functionSource("startManualAnswerConnection", "autoHost");
  const claim = source.indexOf("conn.manualRemoteCandidatesStarted=true");
  const cancelOtherPath = source.indexOf("stopAutoAnswerReturn(conn)");
  const firstCandidate = source.indexOf("await conn.pc.addIceCandidate(candidate)");
  assert.ok(claim >= 0 && cancelOtherPath > claim && firstCandidate > cancelOtherPath);
});

test("only a validated link participates in room traffic", () => {
  const control = functionSource("handleControl", "handleLinkHello");
  assert.ok(control.indexOf("!conn.helloValidated") < control.indexOf('value.t === "mesh"'));
  assert.match(html, /function openLinks\(\)\{[^\n]*conn\.helloValidated/);
});

test("manual fallback cannot overwrite an automatic answer claim", () => {
  const source = functionSource("acceptMemberAnswer", "armInviteConnectionTimer");
  const claimGuard = source.indexOf("if(invite.answerClaim)");
  const identityMutation = source.indexOf("conn.expectedPeerId=answer.id");
  assert.ok(claimGuard >= 0 && identityMutation > claimGuard);
  assert.match(source, /button\.disabled=!invite\|\|invite\.status!=="pending"\|\|Boolean\(invite\.answerClaim\)/);
});

test("post-channel peer verification tolerates a suspended phone", () => {
  const source = functionSource("onChannelOpen", "onDataMessage");
  assert.match(source, /Math\.max\(ANSWER_CONNECT_TIMEOUT_MS/);
  assert.match(html, /const ANSWER_CONNECT_TIMEOUT_MS = 90 \* 1000/);
  assert.doesNotMatch(html, /LINK_HELLO_TIMEOUT_MS/);
});

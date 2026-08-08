#!/usr/bin/env python3
"""Offline tests for frame_relay. No network, no credentials, no publishing.

    python3 test_relay.py

Covers the parts that can be wrong without talking to anything: the codec round
trip, payload extraction from a page that carries the server's preamble, the
contiguous-ack watermark, and budget rollover.
"""
import base64
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from clawdvert import mailbox as R

FAILED = []


def check(name, cond, detail=""):
    print(f"  {'pass' if cond else 'FAIL'}  {name}" + (f"  {detail}" if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def envelope(msgs, node="a", ack=0):
    return {"v": R.WIRE, "node": node, "sent": 0, "ack": ack, "msgs": msgs}


print("codec")
KEY = secrets.token_bytes(32)
CHAN = "abc123"
msgs = [{"seq": 1, "ts": 0, "body": "hello"},
        {"seq": 2, "ts": 0, "body": "unicode: éü中文 \U0001f4e1"},
        {"seq": 3, "ts": 0, "body": "x" * 5000}]
page, raw, packed, b64 = R.encode(envelope(msgs), KEY, CHAN)

check("encode produces a full HTML document", page.startswith("<!doctype html>"))
check("gzip actually shrinks a repetitive payload", packed < raw, f"{raw} -> {packed}")
back = R.decode(page, KEY, CHAN)
check("round trip preserves every message", back["msgs"] == msgs)
check("round trip preserves unicode", back["msgs"][1]["body"] == msgs[1]["body"])

# The content origin prepends roughly 12KB of its own runtime ahead of the
# document. If extraction assumed the payload was the whole body, this breaks.
served = "<!-- frame-runtime -->" + ("<div>preamble</div>" * 700) + page
check("payload survives a 12KB server preamble", R.decode(served, KEY, CHAN)["msgs"] == msgs)

# base64 padding must not be truncated by the extraction regex.
padded = [{"seq": 1, "ts": 0, "body": "a" * n} for n in (1, 2, 3)]
ok = True
for m in padded:
    p, *_ = R.encode(envelope([m]), KEY, CHAN)
    if R.decode(p, KEY, CHAN)["msgs"] != [m]:
        ok = False
check("payloads of every base64 padding length survive", ok)

print("crypto")
try:
    R.decode(page, secrets.token_bytes(32), CHAN)
    check("a wrong key is rejected", False, "decoded with the wrong key")
except Exception:
    check("a wrong key is rejected", True)

try:
    R.decode(page, KEY, "different-channel")
    check("a wrong channel is rejected (AAD binding)", False, "decoded with wrong AAD")
except Exception:
    check("a wrong channel is rejected (AAD binding)", True)

tampered = page.replace('<template id="relay-v1">', '<template id="relay-v1">A')
try:
    R.decode(tampered, KEY, CHAN)
    check("tampering is detected", False, "accepted a modified payload")
except Exception:
    check("tampering is detected", True)

try:
    R.decode("<html>nothing here</html>", KEY, CHAN)
    check("a page with no payload raises", False, "returned instead of raising")
except Exception:
    check("a page with no payload raises", True)

print("ack watermark")


def deliver(seqs, start_ack=0, seen=()):
    """Run poll's watermark logic over a set of arriving sequence numbers."""
    state = dict(R.blank_state(), ack_through=start_ack, seen=sorted(seen))
    s = set(state["seen"])
    for q in sorted(seqs):
        s.add(q)
        state["seen"] = sorted(s)[-256:]
        while state["ack_through"] + 1 in s:
            state["ack_through"] += 1
    return state["ack_through"]


check("contiguous run acks fully", deliver([1, 2, 3]) == 3, f"got {deliver([1, 2, 3])}")
check("a gap holds the ack below it", deliver([1, 2, 5]) == 2, f"got {deliver([1, 2, 5])}")
check("filling the gap releases the ack", deliver([1, 2, 5, 3, 4]) == 5)
check("out of order arrival still acks correctly", deliver([3, 1, 2]) == 3)
check("a leading gap acks nothing", deliver([2, 3, 4]) == 0, f"got {deliver([2, 3, 4])}")

print("epoch (peer restart detection)")


def apply_envelope(state, env):
    """The epoch and ack half of poll(), isolated."""
    pe = env.get("epoch", "")
    if pe and pe != state["peer_epoch"]:
        state["peer_epoch"] = pe
        state["seen"] = []
        state["ack_through"] = 0
    if env.get("ack_epoch") == state["epoch"]:
        state["peer_acked"] = max(state["peer_acked"], int(env.get("ack", 0)))
        state["outbox"] = [m for m in state["outbox"] if m["seq"] > state["peer_acked"]]
    seen = set(state["seen"])
    fresh = [m for m in env.get("msgs", []) if m["seq"] not in seen]
    for m in sorted(fresh, key=lambda m: m["seq"]):
        seen.add(m["seq"])
        state["seen"] = sorted(seen)
        while state["ack_through"] + 1 in seen:
            state["ack_through"] += 1
    return [m["body"] for m in sorted(fresh, key=lambda m: m["seq"])]


st = dict(R.blank_state(), epoch="mine")
m1 = [{"seq": 1, "ts": 0, "body": "first"}]
got1 = apply_envelope(st, {"v": R.WIRE, "epoch": "peerA", "ack_epoch": "mine",
                           "ack": 0, "msgs": m1})
check("first message from a peer is delivered", got1 == ["first"])

dup = apply_envelope(st, {"v": R.WIRE, "epoch": "peerA", "ack_epoch": "mine",
                          "ack": 0, "msgs": m1})
check("the same message is not delivered twice", dup == [])

# Peer loses its state file: new epoch, sequence restarts at 1, different body.
restart = apply_envelope(st, {"v": R.WIRE, "epoch": "peerB", "ack_epoch": "mine",
                              "ack": 0, "msgs": [{"seq": 1, "ts": 0, "body": "after restart"}]})
check("a restarted peer's seq 1 is delivered, not deduped", restart == ["after restart"],
      f"got {restart}")
check("the restart resets the inbound watermark", st["ack_through"] == 1)

# An ack computed against a previous epoch of OURS must not trim our outbox.
st2 = dict(R.blank_state(), epoch="new", peer_epoch="p",
           outbox=[{"seq": n, "ts": 0, "body": str(n)} for n in (1, 2, 3)])
apply_envelope(st2, {"v": R.WIRE, "epoch": "p", "ack_epoch": "OLD", "ack": 3, "msgs": []})
check("a stale-epoch ack does not trim the outbox", len(st2["outbox"]) == 3,
      f"outbox {len(st2['outbox'])}")
apply_envelope(st2, {"v": R.WIRE, "epoch": "p", "ack_epoch": "new", "ack": 2, "msgs": []})
check("a current-epoch ack does trim the outbox", [m["seq"] for m in st2["outbox"]] == [3])

print("backpressure")
st3 = dict(R.blank_state(), peer_acked=0,
           outbox=[{"seq": n, "ts": 0, "body": "x"} for n in range(1, 33)])
unacked = [m for m in st3["outbox"] if m["seq"] > st3["peer_acked"]]
check("a full window is detected before appending", len(unacked) >= 32)
st4 = dict(R.blank_state(), peer_acked=30,
           outbox=[{"seq": n, "ts": 0, "body": "x"} for n in range(1, 33)])
unacked4 = [m for m in st4["outbox"] if m["seq"] > st4["peer_acked"]]
check("acked messages free window space", len(unacked4) == 2)

print("liveness")
cfg = {"heartbeat_seconds": 1800, "poll_seconds": 15, "peer": "server", "window": 32}

st = dict(R.blank_state(), peer_hb=600)
check("timeout follows the peer's announced cadence, not ours",
      R.peer_timeout(cfg, st) == 1800, f"got {R.peer_timeout(cfg, st)}")

st = dict(R.blank_state(), peer_hb=0)
check("a peer that does not heartbeat yields no timeout",
      R.peer_timeout(cfg, st) == 0)

fast = {"heartbeat_seconds": 10, "poll_seconds": 15, "peer": "p", "window": 32}
check("a floor stops a fast poll from tripping the timeout",
      R.peer_timeout(fast, dict(R.blank_state(), peer_hb=10)) == 90)

import time as _t
st = dict(R.blank_state(), peer_hb=60, peer_last_seen=int(_t.time()) - 1000,
          peer_alive=True)
R.check_peer(cfg, st)
check("a long-silent peer is marked dead", st["peer_alive"] is False)
R.check_peer(cfg, st)
check("the death is reported once, not every cycle", st["peer_alive"] is False)

st2 = dict(R.blank_state(), peer_hb=60, peer_last_seen=int(_t.time()) - 10,
           peer_alive=True)
R.check_peer(cfg, st2)
check("a recently heard peer stays alive", st2["peer_alive"] is True)

st3 = dict(R.blank_state(), peer_hb=60, peer_last_seen=0, peer_alive=True)
R.check_peer(cfg, st3)
check("a peer never heard from is not declared dead", st3["peer_alive"] is True)

print("budget")
st = dict(R.blank_state(), day="1999-01-01", publishes=999)
left = R.budget_left(st, 200)
check("a new UTC day resets the counter", left == 200 and st["publishes"] == 0)
st2 = dict(R.blank_state(), day=R.today(), publishes=200)
check("an exhausted budget reports zero", R.budget_left(st2, 200) == 0)

print()
if FAILED:
    print(f"{len(FAILED)} failed: {', '.join(FAILED)}")
    sys.exit(1)
print("all passed")

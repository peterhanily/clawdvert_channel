"""A message channel between hosts, carried by artifacts.

Each node owns one artifact it writes and reads the one its peer writes. A
message is compressed, sealed, base64'd and published as a new version; the peer
notices because the version string changed.

    python3 -m clawdvert.mailbox init --node laptop --peer server
    python3 -m clawdvert.mailbox adopt
    python3 -m clawdvert.mailbox chat

Nothing is ever made public. That matters for more than privacy: the review gate
and the version pin apply only to public serving, so the private path has
neither, and a redeploy is visible to the peer immediately.
"""

import argparse
import base64
import binascii
import gzip
import json
import os
import re
import secrets
import select
import sys
import time
from datetime import datetime, timezone

try:
    from . import frames
    from .frames import FrameError
except ImportError:  # invoked as a path rather than with -m
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from clawdvert import frames
    from clawdvert.frames import FrameError

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    ChaCha20Poly1305 = None

CONFIG = "relay.json"
STATE = ".relay-state.json"
WIRE = 2
MARKER = "relay-v1"
PAYLOAD_RE = re.compile(rf'<template id="{MARKER}">([A-Za-z0-9+/=]*)</template>')
MAX_FILE = 8 * 1024 * 1024

DEFAULTS = {"poll_seconds": 5, "window": 32, "ack_seconds": 300,
            "heartbeat_seconds": 1800, "daily_cap": 500, "inbox": "inbox"}


def log(msg):
    print(f"{datetime.now().strftime('%H:%M:%S')} {msg}", file=sys.stderr)


def today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# --- config and state --------------------------------------------------------

def load(path, default=None):
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        if default is None:
            raise FrameError(f"no {path}. Run `init` first.")
        return default
    except ValueError as exc:
        raise FrameError(f"{path} is not valid JSON: {exc}")


def save(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh, indent=2)
    os.replace(tmp, path)
    if path == CONFIG:
        os.chmod(path, 0o600)


def blank_state():
    # `epoch` identifies this state file's lifetime. Sequence numbers only mean
    # anything within one epoch: a node that loses its state restarts at seq 1,
    # and without an epoch the peer would dedupe those against sequences it has
    # already seen and discard them forever.
    return {"day": "", "publishes": 0, "outbox": [], "next_seq": 1,
            "peer_ver": "", "seen": [], "peer_acked": 0, "ack_through": 0,
            "bad_version": "", "epoch": secrets.token_hex(8), "peer_epoch": "",
            "owed": 0, "last_publish": 0, "peer_last_seen": 0, "peer_hb": None,
            "peer_alive": True}


def hydrate(cfg, state):
    for k, v in DEFAULTS.items():
        cfg.setdefault(k, v)
    for k, v in blank_state().items():
        state.setdefault(k, v)
    return cfg, state


# --- codec -------------------------------------------------------------------
# Compress, then seal. The other order leaves gzip nothing to find, because
# ciphertext is incompressible by construction.

def need_crypto():
    if ChaCha20Poly1305 is None:
        raise FrameError("encryption needs `pip install cryptography`")


def encode(envelope, key, channel):
    raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    packed = gzip.compress(raw, 9)
    nonce = secrets.token_bytes(12)
    sealed = nonce + ChaCha20Poly1305(key).encrypt(nonce, packed, channel.encode())
    b64 = base64.b64encode(sealed).decode("ascii")
    # The base64 alphabet has no '<' or '&', so the payload survives HTML
    # parsing with no escaping and no size penalty.
    page = frames.compose(f'<template id="{MARKER}">{b64}</template>')
    return page, len(raw), len(packed), len(b64)


def decode(served_html, key, channel):
    """The content origin prepends its own runtime, so extract by marker."""
    m = PAYLOAD_RE.search(served_html)
    if not m:
        raise ValueError("no payload in this artifact")
    try:
        sealed = base64.b64decode(m.group(1), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"corrupt base64: {exc}") from exc
    if len(sealed) < 13:
        raise ValueError("ciphertext too short")
    packed = ChaCha20Poly1305(key).decrypt(sealed[:12], sealed[12:], channel.encode())
    return json.loads(gzip.decompress(packed))


# --- budget and liveness -----------------------------------------------------

def budget_left(state, cap):
    if state["day"] != today():
        state["day"], state["publishes"] = today(), 0
    return cap - state["publishes"]


def peer_timeout(cfg, state):
    """Sized from the cadence the peer announces, not our own.

    Two nodes configured differently would otherwise disagree about when the
    other is late. Three missed beats, floored so a fast poll never trips it.
    """
    hb = state.get("peer_hb")
    if hb is None:
        hb = cfg["heartbeat_seconds"]
    if hb <= 0:
        return 0
    return max(3 * hb, 6 * cfg["poll_seconds"])


def check_peer(cfg, state):
    timeout = peer_timeout(cfg, state)
    if not timeout or not state["peer_last_seen"]:
        return
    late = int(time.time()) - state["peer_last_seen"]
    if late > timeout and state["peer_alive"]:
        state["peer_alive"] = False
        log(f"'{cfg['peer']}' silent for {late}s. Queued messages are safe; "
            f"sends refuse once the window fills.")


# --- the loop ----------------------------------------------------------------

def flush(session, cfg, state, force=False):
    """Publish the outbox as one version.

    Many sends become one publish. That is the point: the cap counts publishes,
    not messages, so a chatty exchange costs the same as a single message.
    """
    pending = [m for m in state["outbox"] if m["seq"] > state["peer_acked"]]
    if not pending and not force:
        return False
    if budget_left(state, cfg["daily_cap"]) <= 0:
        log(f"local cap of {cfg['daily_cap']}/day reached, holding {len(pending)}")
        return False

    envelope = {"v": WIRE, "node": cfg["node"], "sent": int(time.time()),
                "epoch": state["epoch"],
                # The highest CONTIGUOUS sequence, never the maximum. Acking a
                # maximum with a gap below it tells the peer to discard messages
                # that never arrived.
                "ack": state["ack_through"], "ack_epoch": state["peer_epoch"],
                "hb": cfg["heartbeat_seconds"], "msgs": pending}
    page, raw, packed, b64 = encode(envelope, base64.b64decode(cfg["key"]),
                                    cfg["channel"])
    try:
        data = frames.publish(session, page, f"relay {cfg['node']}",
                              favicon="\U0001f4e1", slug=cfg.get("out_slug"))
    except FrameError as exc:
        if "daily publish cap" in str(exc):
            state["publishes"] = cfg["daily_cap"]
            log(f"server reports its daily cap; holding {len(pending)} until "
                f"the UTC day rolls over")
        else:
            log(f"publish failed: {exc}")
        return False

    cfg["out_slug"] = data["slug"]
    state["publishes"] += 1
    state["owed"] = 0
    state["last_publish"] = int(time.time())
    ratio = f"{raw / packed:.1f}x" if packed else "n/a"
    log(f"sent {len(pending)} msg(s), {raw}B -> {packed}B ({ratio}) -> {b64}B b64, "
        f"{budget_left(state, cfg['daily_cap'])}/{cfg['daily_cap']} left today")
    return True


def resolve_peer(session, cfg):
    """Find the peer's mailbox by title, once.

    Both hosts are the same account, so pairing needs a one-way config copy
    rather than an exchange of slugs. After this the node never lists again.
    """
    if cfg.get("in_slug"):
        return cfg["in_slug"]
    want = f"relay {cfg['peer']}"
    found = [f["slug"] for f in frames.frames(session)
             if f.get("title") == want and f["slug"] != cfg.get("out_slug")]
    if len(found) > 1:
        log(f"{len(found)} mailboxes titled {want!r}; set in_slug by hand")
        return None
    if not found:
        return None
    cfg["in_slug"] = found[0]
    save(CONFIG, cfg)
    log(f"paired with '{cfg['peer']}' at {found[0]}")
    return found[0]


def poll(session, cfg, state, deliver_fn):
    """One request detects change and carries everything needed to read it.

    Listing every frame costs about fifty times the bytes and does not include
    the asset token, so it needed a second request anyway. The boot record has
    `ver` and `assetToken` together, which makes the steady state a single call.
    """
    in_slug = resolve_peer(session, cfg)
    if not in_slug:
        return

    try:
        record = frames.boot(session, in_slug)
    except FrameError as exc:
        log(f"poll failed: {exc}")
        return

    ver = record.get("ver")
    if not ver or ver == state["peer_ver"] or ver == state.get("bad_version"):
        return

    try:
        html_text = frames.content(session, in_slug, ver, record.get("assetToken"))
    except FrameError as exc:
        log(f"content fetch failed: {exc}")
        return

    try:
        envelope = decode(html_text, base64.b64decode(cfg["key"]), cfg["channel"])
    except Exception as exc:                                      # noqa: BLE001
        state["bad_version"] = ver
        log(f"undecodable payload, wrong key or channel? {exc}")
        return
    if envelope.get("v") != WIRE:
        state["bad_version"] = ver
        log(f"unknown wire version {envelope.get('v')}")
        return

    state["peer_last_seen"] = int(time.time())
    state["peer_hb"] = int(envelope.get("hb", 0) or 0)
    if not state["peer_alive"]:
        state["peer_alive"] = True
        log(f"'{cfg['peer']}' is back")

    peer_epoch = envelope.get("epoch", "")
    if peer_epoch and peer_epoch != state["peer_epoch"]:
        if state["peer_epoch"]:
            log(f"peer restarted; resetting inbound sequence tracking")
        state["peer_epoch"] = peer_epoch
        state["seen"] = []
        state["ack_through"] = 0

    # Honour an ack only if it was computed against our current epoch. A stale
    # one would trim messages the peer never saw.
    if envelope.get("ack_epoch") == state["epoch"]:
        state["peer_acked"] = max(state["peer_acked"], int(envelope.get("ack", 0)))
        state["outbox"] = [m for m in state["outbox"]
                           if m["seq"] > state["peer_acked"]]

    seen = set(state["seen"])
    fresh = sorted((m for m in envelope.get("msgs", []) if m["seq"] not in seen),
                   key=lambda m: m["seq"])
    for m in fresh:
        # Deliver first. If this raises, peer_ver stays put so the next poll
        # refetches and redelivers whatever did not get through.
        deliver_fn(envelope.get("node", "?"), m)
        seen.add(m["seq"])
        state["seen"] = sorted(seen)[-256:]
        state["owed"] += 1
        while state["ack_through"] + 1 in seen:
            state["ack_through"] += 1

    state["peer_ver"] = ver


def deliver(cfg, who, m):
    if m.get("kind") != "file":
        print(f"[{who}] {m['body']}", flush=True)
        return
    inbox = cfg.get("inbox", "inbox")
    os.makedirs(inbox, exist_ok=True)
    name = os.path.basename(m.get("name") or "unnamed")
    dest = os.path.join(inbox, name)
    n = 1
    while os.path.exists(dest):
        stem, ext = os.path.splitext(name)
        dest = os.path.join(inbox, f"{stem}.{n}{ext}")
        n += 1
    data = base64.b64decode(m["body"])
    with open(dest, "wb") as fh:
        fh.write(data)
    print(f"[{who}] file {name} ({len(data)} bytes) -> {dest}", flush=True)


def queue(cfg, state, body, kind=None, name=None):
    """Refuse rather than discard when the window is full.

    A full window means the peer has acknowledged nothing for `window` messages,
    so it is gone or badly behind. Dropping the oldest would lose data silently
    at the moment the operator could still have acted on it.
    """
    unacked = [m for m in state["outbox"] if m["seq"] > state["peer_acked"]]
    if len(unacked) >= cfg["window"]:
        save(STATE, state)
        raise FrameError(
            f"outbox full: {len(unacked)} message(s) unacknowledged by "
            f"'{cfg['peer']}'. Nothing was dropped and nothing queued. Check the "
            f"peer is running, then retry, or raise --window if it is just slow.")
    m = {"seq": state["next_seq"], "ts": int(time.time()), "body": body}
    if kind:
        m["kind"], m["name"] = kind, name
    state["outbox"].append(m)
    state["next_seq"] += 1
    state["outbox"] = [x for x in state["outbox"] if x["seq"] > state["peer_acked"]]
    return m


def read_file_payload(path):
    if not os.path.isfile(path):
        raise FrameError(f"no such file: {path}")
    raw = open(path, "rb").read()
    if len(raw) > MAX_FILE:
        raise FrameError(f"{path} is {len(raw) // 1048576}MB; keep files under "
                         f"{MAX_FILE // 1048576}MB so the page stays under 16MB "
                         f"after base64")
    return base64.b64encode(raw).decode("ascii"), os.path.basename(path)


def due(cfg, state):
    """Should we publish even with nothing new to say?"""
    now = int(time.time())
    owed = state["owed"] >= max(1, cfg["window"] // 2) or (
        state["owed"] > 0 and now - state["last_publish"] > cfg["ack_seconds"])
    beat = cfg["heartbeat_seconds"] > 0 and (
        now - state["last_publish"] >= cfg["heartbeat_seconds"])
    return owed or beat


# --- commands ----------------------------------------------------------------

def cmd_init(args):
    need_crypto()
    if os.path.exists(CONFIG) and not args.force:
        raise FrameError(f"{CONFIG} exists. Use --force to overwrite.")
    session = frames.Session()
    cfg = {"node": args.node, "peer": args.peer,
           "channel": secrets.token_hex(8),
           "key": base64.b64encode(secrets.token_bytes(32)).decode(),
           "out_slug": None, "in_slug": None,
           "poll_seconds": args.poll, "window": args.window,
           "ack_seconds": args.ack_seconds,
           "heartbeat_seconds": args.heartbeat_seconds,
           "daily_cap": args.daily_cap, "inbox": args.inbox}
    page, *_ = encode({"v": WIRE, "node": args.node, "sent": int(time.time()),
                       "epoch": "", "ack": 0, "ack_epoch": "",
                       "hb": cfg["heartbeat_seconds"], "msgs": []},
                      base64.b64decode(cfg["key"]), cfg["channel"])
    data = frames.publish(session, page, f"relay {args.node}", favicon="\U0001f4e1")
    cfg["out_slug"] = data["slug"]
    save(CONFIG, cfg)
    save(STATE, blank_state())

    peer_cfg = dict(cfg, node=args.peer, peer=args.node,
                    out_slug=None, in_slug=cfg["out_slug"])
    print(f"created {CONFIG}; this node's mailbox is {cfg['out_slug']}\n")
    print("Save this on the other host as relay.json, then run `adopt`:\n")
    print(json.dumps(peer_cfg, indent=2))


def cmd_adopt(args):
    need_crypto()
    cfg = load(CONFIG)
    if cfg.get("out_slug"):
        print(f"already adopted: '{cfg['node']}' owns {cfg['out_slug']}")
        return
    session = frames.Session()
    page, *_ = encode({"v": WIRE, "node": cfg["node"], "sent": int(time.time()),
                       "epoch": "", "ack": 0, "ack_epoch": "",
                       "hb": cfg.get("heartbeat_seconds", 1800), "msgs": []},
                      base64.b64decode(cfg["key"]), cfg["channel"])
    data = frames.publish(session, page, f"relay {cfg['node']}", favicon="\U0001f4e1")
    cfg["out_slug"] = data["slug"]
    save(CONFIG, cfg)
    save(STATE, blank_state())
    print(f"this node is '{cfg['node']}', mailbox {cfg['out_slug']}")
    print("Run `chat` on both hosts; they find each other by title.")


def cmd_send(args):
    need_crypto()
    if not args.message and not args.file:
        raise FrameError("nothing to send: give a message or --file")
    cfg, state = hydrate(load(CONFIG), load(STATE, blank_state()))
    session = frames.Session()
    if args.file:
        body, name = read_file_payload(args.file)
        queue(cfg, state, body, "file", name)
    else:
        queue(cfg, state, args.message)
    if not args.queue:
        flush(session, cfg, state)
    save(STATE, state)
    save(CONFIG, cfg)
    if args.queue:
        print(f"queued ({len(state['outbox'])} pending)")


def cmd_recv(args):
    need_crypto()
    cfg, state = hydrate(load(CONFIG), load(STATE, blank_state()))
    session = frames.Session()
    poll(session, cfg, state, lambda who, m: deliver(cfg, who, m))
    save(STATE, state)
    save(CONFIG, cfg)


def cmd_run(args):
    need_crypto()
    cfg = load(CONFIG)
    session = frames.Session()
    log(f"'{cfg['node']}' <-> '{cfg['peer']}', polling every "
        f"{cfg.get('poll_seconds', 5)}s")
    while True:
        cfg, state = hydrate(cfg, load(STATE, blank_state()))
        try:
            poll(session, cfg, state, lambda who, m: deliver(cfg, who, m))
            flush(session, cfg, state, force=due(cfg, state))
            check_peer(cfg, state)
        except KeyboardInterrupt:
            save(STATE, state)
            session.close()
            log("stopped")
            return
        except Exception as exc:                                  # noqa: BLE001
            log(f"cycle error: {exc}")
        save(STATE, state)
        save(CONFIG, cfg)
        time.sleep(cfg["poll_seconds"])


def cmd_chat(args):
    """Type to send, incoming prints as it lands.

    One thread on purpose: select() on stdin with the poll interval as its
    timeout keeps the prompt responsive without a second thread racing over the
    state file.
    """
    need_crypto()
    cfg = load(CONFIG)
    session = frames.Session()
    print(f"chat as '{cfg['node']}' with '{cfg['peer']}'. "
          f"Type to send, /file <path> to send a file, Ctrl-D to quit.")
    while True:
        cfg, state = hydrate(cfg, load(STATE, blank_state()))
        try:
            poll(session, cfg, state, lambda who, m: deliver(cfg, who, m))
            flush(session, cfg, state, force=due(cfg, state))
            check_peer(cfg, state)
        except Exception as exc:                                  # noqa: BLE001
            log(f"cycle error: {exc}")
        save(STATE, state)
        save(CONFIG, cfg)

        try:
            ready, _, _ = select.select([sys.stdin], [], [], cfg["poll_seconds"])
        except KeyboardInterrupt:
            print()
            session.close()
            return
        if not ready:
            continue
        line = sys.stdin.readline()
        if not line:
            print("bye")
            session.close()
            return
        line = line.rstrip("\n")
        if not line:
            continue

        cfg, state = hydrate(cfg, load(STATE, blank_state()))
        try:
            if line.startswith("/file "):
                body, name = read_file_payload(line[6:].strip())
                queue(cfg, state, body, "file", name)
                print(f"sending {name}")
            else:
                queue(cfg, state, line)
            flush(session, cfg, state)
        except FrameError as exc:
            print(f"error: {exc}")
        save(STATE, state)
        save(CONFIG, cfg)


def cmd_status(args):
    cfg, state = hydrate(load(CONFIG), load(STATE, blank_state()))
    pending = [m for m in state["outbox"] if m["seq"] > state["peer_acked"]]
    print(f"node        {cfg['node']} <-> {cfg['peer']}")
    print(f"out         {cfg.get('out_slug')}")
    print(f"in          {cfg.get('in_slug') or '(unpaired)'}")
    print(f"publishes   {state['publishes']}/{cfg['daily_cap']} today")
    print(f"pending     {len(pending)} unacked")
    print(f"acked       through seq {state['peer_acked']}")
    if not state["peer_last_seen"]:
        print("peer        never heard from")
    else:
        late = int(time.time()) - state["peer_last_seen"]
        timeout = peer_timeout(cfg, state)
        verdict = ("unknown (peer does not heartbeat)" if not timeout
                   else f"SILENT, {late}s > {timeout}s" if late > timeout
                   else f"alive, {timeout - late}s of slack")
        print(f"peer        last heard {late}s ago: {verdict}")
    hb = cfg["heartbeat_seconds"]
    print(f"heartbeat   {'every ' + str(hb) + 's' if hb else 'disabled'}"
          + (f" (~{86400 // hb}/day)" if hb else ""))


def build_parser():
    p = argparse.ArgumentParser(prog="clawdvert.mailbox",
                                description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="create the config and this node's mailbox")
    i.add_argument("--node", required=True)
    i.add_argument("--peer", required=True)
    i.add_argument("--poll", type=int, default=DEFAULTS["poll_seconds"])
    i.add_argument("--window", type=int, default=DEFAULTS["window"])
    i.add_argument("--ack-seconds", type=int, default=DEFAULTS["ack_seconds"])
    i.add_argument("--heartbeat", type=int, default=DEFAULTS["heartbeat_seconds"],
                   dest="heartbeat_seconds", help="0 disables")
    i.add_argument("--daily-cap", type=int, default=DEFAULTS["daily_cap"])
    i.add_argument("--inbox", default=DEFAULTS["inbox"])
    i.add_argument("--force", action="store_true")
    i.set_defaults(fn=cmd_init)

    sub.add_parser("adopt", help="second host: claim a mailbox from a pasted config"
                   ).set_defaults(fn=cmd_adopt)

    s = sub.add_parser("send", help="send a message or a file")
    s.add_argument("message", nargs="?")
    s.add_argument("--file")
    s.add_argument("--queue", action="store_true", help="queue without publishing")
    s.set_defaults(fn=cmd_send)

    sub.add_parser("chat", help="interactive").set_defaults(fn=cmd_chat)
    sub.add_parser("recv", help="poll once").set_defaults(fn=cmd_recv)
    sub.add_parser("run", help="daemon").set_defaults(fn=cmd_run)
    sub.add_parser("status", help="pairing, budget, peer liveness"
                   ).set_defaults(fn=cmd_status)
    return p


def cli():
    try:
        args = build_parser().parse_args()
        args.fn(args)
    except FrameError as exc:
        sys.exit(f"error: {exc}")
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    cli()

#!/usr/bin/env python3
"""Verify a TURN relay end to end, including the checks people skip.

Answers four questions in order, and stops at the first that fails:

  1. Does the hostname resolve at all?
  2. Does an unauthenticated Allocate draw a 401 challenge?
  3. Does an authenticated Allocate succeed, and is the relayed address public?
  4. Does the relay REFUSE to forward into private address space?

Question 4 is the one that gets skipped. A relay without denied-peer-ip rules
is a route into the operator's own network and, on a cloud host, to the
instance metadata service.
"""

import argparse
import hashlib
import hmac
import ipaddress
import secrets
import socket
import struct
import sys

MAGIC = 0x2112A442
ALLOCATE, ALLOCATE_OK = 0x0003, 0x0103
CREATE_PERMISSION, CREATE_PERMISSION_OK = 0x0008, 0x0108
USERNAME, MESSAGE_INTEGRITY, ERROR_CODE = 0x0006, 0x0008, 0x0009
REALM, NONCE, XOR_RELAYED, XOR_PEER, REQUESTED_TRANSPORT = 0x0014, 0x0015, 0x0016, 0x0012, 0x0019

# Anything a relay must never be willing to forward to.
FORBIDDEN = [
    ("169.254.169.254", "cloud instance metadata"),
    ("10.0.0.1", "private 10/8"),
    ("192.168.1.1", "private 192.168/16"),
    ("127.0.0.1", "loopback"),
]


def attr(kind, value):
    return struct.pack("!HH", kind, len(value)) + value + b"\x00" * (-len(value) % 4)


def message(kind, txid, attrs, key=None):
    body = b"".join(attrs)
    if key:
        header = struct.pack("!HHI", kind, len(body) + 24, MAGIC) + txid
        body += attr(MESSAGE_INTEGRITY, hmac.new(key, header + body, hashlib.sha1).digest())
    return struct.pack("!HHI", kind, len(body), MAGIC) + txid + body


def parse(packet):
    out, offset = {}, 20
    end = 20 + struct.unpack("!H", packet[2:4])[0]
    while offset + 4 <= end:
        kind, length = struct.unpack("!HH", packet[offset:offset + 4])
        out[kind] = packet[offset + 4:offset + 4 + length]
        offset += 4 + length + (-length % 4)
    return out


def xor_address(raw):
    port = struct.unpack("!H", raw[2:4])[0] ^ (MAGIC >> 16)
    cookie = struct.pack("!I", MAGIC)
    host = ".".join(str(a ^ b) for a, b in zip(raw[4:8], cookie))
    return host, port


def peer_attr(host, port=9999):
    octets = bytes(int(part) for part in host.split("."))
    cookie = struct.pack("!I", MAGIC)
    return (b"\x00\x01" + struct.pack("!H", port ^ (MAGIC >> 16))
            + bytes(a ^ b for a, b in zip(octets, cookie)))


def error_of(packet):
    body = parse(packet).get(ERROR_CODE, b"")
    if len(body) < 4:
        return "unknown"
    return f"{body[2] * 100 + body[3]} {body[4:].decode('utf-8', 'replace')}"


def main():
    ap = argparse.ArgumentParser(description="Verify a TURN relay end to end.")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=3478)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--timeout", type=float, default=6.0)
    args = ap.parse_args()

    failures = 0

    try:
        address = socket.gethostbyname(args.host)
    except OSError as exc:
        print(f"FAIL  dns          {args.host} does not resolve ({exc})")
        print("\nEvery STUN and TURN server failing at once is a DNS or network block,")
        print("not a NAT problem. That is ICE error 701 in the browser.")
        return 1
    print(f"ok    dns          {args.host} -> {address}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    target = (address, args.port)

    transport = attr(REQUESTED_TRANSPORT, b"\x11\x00\x00\x00")
    try:
        sock.sendto(message(ALLOCATE, secrets.token_bytes(12), [transport]), target)
        challenge = parse(sock.recvfrom(2048)[0])
    except socket.timeout:
        print(f"FAIL  reachable    no answer on {args.host}:{args.port}/udp")
        print("\nThe port is closed, filtered, or your address is not allowed in.")
        return 1

    nonce, realm = challenge.get(NONCE), challenge.get(REALM)
    if not nonce or not realm:
        print("FAIL  challenge    no 401 challenge returned; this may not be a TURN server")
        return 1
    print(f"ok    challenge    realm={realm.decode()}")

    key = hashlib.md5(f"{args.user}:{realm.decode()}:{args.password}".encode()).digest()
    auth = [attr(USERNAME, args.user.encode()), attr(REALM, realm), attr(NONCE, nonce)]

    sock.sendto(message(ALLOCATE, secrets.token_bytes(12), [transport] + auth, key), target)
    reply = sock.recvfrom(2048)[0]
    if struct.unpack("!H", reply[:2])[0] != ALLOCATE_OK:
        print(f"FAIL  allocate     {error_of(reply)}")
        print("\nUsually a wrong or expired credential.")
        return 1

    relayed_host, relayed_port = xor_address(parse(reply)[XOR_RELAYED])
    print(f"ok    allocate     relayed address {relayed_host}:{relayed_port}")

    if ipaddress.ip_address(relayed_host).is_private:
        print("FAIL  external-ip  the relayed address is PRIVATE, so no peer can reach it")
        print("\nSet external-ip=PUBLIC/PRIVATE in turnserver.conf and restart.")
        failures += 1

    print()
    for host, label in FORBIDDEN:
        sock.sendto(message(CREATE_PERMISSION, secrets.token_bytes(12),
                            [attr(XOR_PEER, peer_attr(host))] + auth, key), target)
        answer = sock.recvfrom(2048)[0]
        if struct.unpack("!H", answer[:2])[0] == CREATE_PERMISSION_OK:
            print(f"FAIL  refuses      {label} ({host}) is REACHABLE through this relay")
            failures += 1
        else:
            print(f"ok    refuses      {label} ({host}) blocked")

    if failures:
        print(f"\n{failures} problem(s). A relay that forwards into private address space is a")
        print("route into your own network. Add the denied-peer-ip block from docs/deploy-relay.md.")
        return 1

    print("\nRelay is working and correctly fenced.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# Deploying the browser relays

The browser channel uses two independent network services. They solve different
problems and a cellular-to-home connection commonly needs both.

| Service | Purpose | Listener ports | Sees |
| --- | --- | --- | --- |
| **rr2 signalling relay** | Returns the joining browser's small encrypted answer automatically | UDP 3478–3483 | Routing metadata, timing, volume, and ciphertext |
| **coturn WebRTC relay** | Carries DTLS/SCTP traffic when direct ICE cannot cross the two NATs | UDP/TCP 3488, then UDP 49160–49200 | Addresses, timing, and encrypted traffic volume |

The inviter still copies one complete invite to the joining device. The answer
normally returns through rr2, after which WebRTC uses either a direct candidate
pair or coturn. If rr2 is unavailable, the app exposes the ordinary answer-code
fallback. If coturn is unavailable and direct ICE cannot find a route, automatic
answer return can succeed while the WebRTC connection still fails.

Do not bind coturn to 3478 on a host that also runs the six-lane signalling
relay. Those ports belong to rr2. The examples below use 3488 for coturn.

## 1. Determine whether TURN is required

Some home and office networks can establish a direct WebRTC route. Carrier-grade
and symmetric NAT commonly cannot. Direct traffic is preferred by default, but
configure TURN before testing across cellular or unrelated networks.

The rr2 signalling relay is still useful when the eventual WebRTC route is
direct: it removes the second manual code transfer. The two decisions are
therefore complementary rather than an ordered list of fallbacks.

## 2. Deploy coturn for the WebRTC path

A TURN relay is a machine on the public internet that forwards packets when two
peers cannot reach each other. It sees addresses, timing, and volume. It does
not see application messages, because the data channel is encrypted with DTLS.

You need a host with a public IP. Anything with 1 GB of memory is ample for a
small deployment.

### Install

```bash
sudo apt-get update
sudo apt-get install -y coturn
```

### Configure

Generate the credential on the host. Never put its resulting value in this
repository, a documentation example, or the published HTML. Keep the terminal
private while generating it and store it in an appropriate secret manager.
Replace `PUBLIC_IP` and `PRIVATE_IP` below with the host's addresses. They differ
on most cloud hosts because the provider maps a public address onto a private
interface. On bare metal with the public address directly on the interface, use
the same value twice.

```bash
TURN_PASS=$(openssl rand -hex 24)
echo "Save this credential securely: $TURN_PASS"

sudo tee /etc/turnserver.conf >/dev/null <<CONF
listening-port=3488
min-port=49160
max-port=49200
external-ip=PUBLIC_IP/PRIVATE_IP

realm=turn.example.com
server-name=turn.example.com
fingerprint
lt-cred-mech
user=clawdvert:$TURN_PASS

no-tls
no-dtls

denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.0.0.0-192.0.0.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=224.0.0.0-255.255.255.255
no-multicast-peers
no-tcp-relay

user-quota=12
total-quota=100
max-bps=2000000

no-cli
syslog
simple-log
CONF

sudo systemctl enable --now coturn
systemctl is-active coturn
```

**The `denied-peer-ip` block is not optional.** A TURN relay forwards to the
address a credential holder requests. Without those rules it can be used to
reach your private network and, on a cloud host, the instance metadata service.

Two addresses remain reachable despite the deny rules: the relay's own public
and private addresses. Coturn deliberately permits that so two clients using the
same relay can reach one another.

### Open the ports

The listener must be reachable over UDP and TCP, and the allocation range must
be reachable over UDP:

```bash
# ufw, when it is the active ingress control
sudo ufw allow 3488/udp
sudo ufw allow 3488/tcp
sudo ufw allow 49160:49200/udp
```

On AWS, security groups are normally the effective gate. Docker-published ports
can bypass host-firewall assumptions, so verify the cloud rule rather than
trusting UFW alone. A source-IP-restricted example is:

```bash
aws --profile canary ec2 authorize-security-group-ingress \
  --group-id sg-REPLACE_ME --ip-permissions \
  'IpProtocol=udp,FromPort=3488,ToPort=3488,IpRanges=[{CidrIp=CLIENT_IP/32}]' \
  'IpProtocol=tcp,FromPort=3488,ToPort=3488,IpRanges=[{CidrIp=CLIENT_IP/32}]' \
  'IpProtocol=udp,FromPort=49160,ToPort=49200,IpRanges=[{CidrIp=CLIENT_IP/32}]'
```

Repeat or combine the rules for both clients' current public addresses. A
phone's carrier address can rotate between tests, so an old `/32` can make a
healthy relay appear broken. Do not widen to `0.0.0.0/0` casually: a globally
reachable relay protected only by one static password will eventually be found
and used for someone else's traffic. Prefer short-lived TURN credentials before
broad exposure; otherwise rotate the static credential after testing.

### Configure the browser

Enter a placeholder-shaped object like this in the app, substituting the real
hostname and credential only at runtime:

```json
{
  "iceServers": [
    {
      "urls": [
        "turn:turn.example.com:3488?transport=udp",
        "turn:turn.example.com:3488?transport=tcp"
      ],
      "username": "clawdvert",
      "credential": "YOUR_PASSWORD"
    }
  ]
}
```

Enable **Put these details in invites** if the joining device should work
without its own TURN setup. The resulting invite contains the relay credential;
treat that invite as bearer-sensitive and do not post it publicly. The
credential is runtime data and must never be embedded into the HTML artifact.

Press **Test relay**. Green means the browser gathered a relay candidate. A red
result usually means the credential is wrong, UDP/TCP 3488 is blocked, the
allocation range is blocked, or `external-ip` is wrong.

From the repository, verify the complete coturn chain without printing the
credential into documentation:

```bash
python3 skills/clawdvert/scripts/relay_check.py \
  --host turn.example.com --port 3488 \
  --user clawdvert --password YOUR_PASSWORD
```

That checks DNS, the unauthenticated 401 challenge, an authenticated allocation,
and refusal to forward into private address space.

### Managed TURN alternative

If you use a managed TURN provider, prefer credentials with a short lifetime.
Paste the provider's complete `iceServers` response into the same app field and
enable invite sharing only for the session that needs it. Consult the provider's
current documentation for its credential-generation endpoint and TTL limits.

## 3. Deploy rr2 for automatic answer return

The repository relay is not coturn and does not forward application traffic. It
uses authenticated TURN-shaped requests and synthetic address responses as a
constrained signalling carrier. The current browser stores one encrypted answer
as an rr2 latest-value slot rather than appending repeated chat events.

Deploy it independently of coturn:

```bash
cd realm
KEY=/path/to/deploy-key.pem ./deploy-relay.sh ubuntu@relay.example.com
```

The script copies `realm/relay`, builds its container, publishes UDP 3478–3483,
and binds the health endpoint to `127.0.0.1:8080`. It deliberately excludes the
remote `.env` from rsync. If `.env` already exists it is preserved byte-for-byte:
a code deployment does **not** enable rr2 or update an explicitly configured TTL.

The repository default remains conservative. A relay serving the published
automatic-answer client needs these non-secret settings in its private remote
`.env`:

```dotenv
PERSIST_MESSAGES=false
RENDEZVOUS_V2_SLOTS=true
RENDEZVOUS_V2_SLOT_TTL_MS=300000
RENDEZVOUS_V2_TERMINAL_TTL_MS=300000
RENDEZVOUS_V2_READER_LEASE_MS=60000
```

`NONCE_SECRET` is also required, but it must be generated and retained on the
host rather than copied into a command or guide. `deploy-relay.sh` creates it
only when no `.env` exists.

After an approved configuration change, recreate the service so Compose passes
the new values into the container:

```bash
ssh ubuntu@relay.example.com \
  'cd ~/realm-relay && docker compose up -d --build --force-recreate'
```

All rr1 rooms and rr2 slots are in memory. Replacing or restarting the container
clears active pairing state, so make this change when nobody is pairing or be
prepared to create a fresh invite. The five-minute terminal TTL in current
source matches the browser's automatic-answer capability window. An older
deployment may explicitly retain a shorter value until its `.env` is changed;
do not infer live configuration from `compose.yaml` defaults.

Deployment note, 2026-08-09: the canary relay still explicitly uses a 30-second
terminal tombstone. The current browser checks the accepted slot every 15
seconds and can verify and re-ACK an identical re-PUT after a suspended phone
resumes, so that canary remains usable. The next separately approved relay
recreate should align its private `.env` with the five-minute source default.

Open UDP 3478–3483 from both clients' current public addresses. These rules are
separate from coturn's 3488 and allocation-range rules:

```bash
aws --profile canary ec2 authorize-security-group-ingress \
  --group-id sg-REPLACE_ME --ip-permissions \
  'IpProtocol=udp,FromPort=3478,ToPort=3483,IpRanges=[{CidrIp=CLIENT_IP/32}]'
```

The relay has a shared-source token bucket, not an IP authorization policy.
Cloud security-group rules remain the access boundary. Two clients behind one
NAT also share that source bucket, which is why the default burst is larger than
the sustained rate.

### Health and protocol smoke tests

The health endpoint is loopback-only. Inspect it over SSH:

```bash
ssh ubuntu@relay.example.com \
  'curl -fsS http://127.0.0.1:8080/health' | python3 -m json.tool
```

For an automatic-answer deployment, confirm at least:

```json
{
  "ok": true,
  "lanes": 6,
  "persistence": false,
  "rendezvousV2": {
    "enabled": true,
    "internalErrors": 0
  }
}
```

The remaining rr2 fields are aggregate slot and operation counters. Health
never returns room IDs, device IDs, attempts, candidates, credentials, or token
bytes.

From a client address admitted by the security group, exercise all six lanes and
the rr2 PUT/discover/GET/ACK lifecycle:

```bash
node realm/relay/tools/relay-smoke.mjs \
  --host relay.example.com --rr2
```

If rr2 is intentionally dark, use `--expect-rr2-disabled` instead. To correlate
the smoke operation with health counters, run it on the host:

```bash
ssh ubuntu@relay.example.com \
  'cd ~/realm-relay && node tools/relay-smoke.mjs --host 127.0.0.1 \
    --rr2 --health-url http://127.0.0.1:8080/health'
```

Smoke values are random, ephemeral protocol fixtures. They contain no production
credential material.

### Automatic-answer diagnostics

| Browser symptom | Meaning | Check |
| --- | --- | --- |
| `Automatic answer return ... disabled` or rr2 response 43 | The relay source is reachable but `RENDEZVOUS_V2_SLOTS` is false in the running container | Inspect `/health`, update the private `.env`, then recreate at a safe time |
| `Answer sent · waiting for acknowledgement` does not advance | The phone wrote its encrypted answer but the inviter has not read and ACKed it | Keep both pages foregrounded; confirm both source IPs can reach UDP 3478–3483 and both use the current artifact |
| `Automatic answer return unavailable` | The five-minute capability expired, the relay was unreachable, or repeated rr2 operations failed | Use the visible manual fallback, then create a fresh invite after fixing relay access |
| Automatic return succeeds, then `No route found` or ICE fails | Signalling worked; the separate WebRTC path did not | Check coturn credentials, 3488 UDP/TCP, 49160–49200 UDP, both source allowlists, and `external-ip` |
| `701 TURN host lookup received error` | The browser could not resolve the configured TURN hostname | Check DNS and captive-network policy; this is not an rr2 slot failure |

The joining browser caches exactly one encrypted answer for the invitation. If a
mobile browser resumes after a short relay tombstone has expired, it can PUT the
same bytes again and the inviter can verify and re-ACK that exact value. This
resume bridge does not make a relay ACK proof of peer identity: the authenticated
data-channel `link-hello` remains the final success signal.

## Related

- [Automatic answer return](auto-answer-return.md)
- [Rendezvous V2 contract](rendezvous-v2.md)
- [Rendezvous V2 relay slots](../realm/relay/RENDEZVOUS_V2.md)
- [Repository overview](../README.md)

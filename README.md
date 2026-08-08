# clawdvert_channel

Claude Code publishes HTML pages as hosted artifacts on claude.ai. It does that through an internal
API that turns out to be a single HTTP request. This repository is a client for that API, a browser
chat client that runs as one of those artifacts, and the relay that introduces two browsers to each
other.

| Component | What it does | Where it runs |
| --- | --- | --- |
| `clawdvert.publish` | Publishes a file as an artifact, replaces one in place, changes who can read it | anywhere with your Claude login |
| `clawdvert.mailbox` | A message channel between two hosts, using private artifacts as mailboxes | two machines on one account |
| `realm/clawdvert_channel.html` | Peer to peer chat over WebRTC: files, rooms, an arcade | a browser on each device |
| `realm/relay/` | A STUN server that carries pairing messages, alongside a TURN relay | a host with a public IP |
| `skills/clawdvert/` | Deploy, test and operate the above, for an agent | Claude Code |

## Install

```bash
git clone https://github.com/peterhanily/clawdvert_channel.git && cd clawdvert_channel
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python tests/test_mailbox.py
```

Use the virtualenv. The one dependency is `cryptography`, a compiled extension with a hard ABI
contract, and installing it into a system Python breaks anything pinned against an older build. On a
machine with mitmproxy or pyopenssl present, that means breaking TLS in both.

Authentication is your existing claude.ai OAuth login rather than an API key. The client looks in the
three places Claude Code looks: `CLAUDE_CODE_OAUTH_TOKEN`, then the macOS Keychain, then
`~/.claude/.credentials.json`. If a host has never logged in, run `claude` once there first.

## Publishing

```bash
.venv/bin/python -m clawdvert.publish page.html --favicon 📊
# https://claude.ai/code/artifact/<uuid>
```

The URL goes to stdout and the version to stderr, so `URL=$(... publish page.html)` captures the URL
alone. To replace an existing artifact, name it. The file can be a completely different file, because
the slug decides which artifact receives the new version.

```bash
.venv/bin/python -m clawdvert.publish other.html --slug <uuid>
.venv/bin/python -m clawdvert.publish page.html --dry-run     # prints the request, sends nothing
```

Artifacts are private to your account and publishing cannot change that. No deploy endpoint accepts a
visibility field, so sharing is always a second call to a permissions route.

```bash
.venv/bin/python -m clawdvert.publish --public  --slug <uuid>
.venv/bin/python -m clawdvert.publish --private --slug <uuid>
```

Two things about that will surprise you, and the second bites hardest.

A freshly published version is not immediately shareable. It goes through an asynchronous review, and
the permissions call returns 409 until that clears. Four of the thirteen refusal reasons are worth
retrying, and the client retries only those.

**`shared` is a version pin rather than a flag.**

![How the public version pin works](docs/img/pin.svg)

Public readability is granted to one reviewed version, not to the artifact. Redeploy a public artifact
and readers keep seeing the old content while the new version returns 403 to them. Running `--public`
again moves the pin, which also revokes the previous version, so exactly one version is public at any
moment. Everything here is measured rather than inferred, and the evidence is in
[docs/frame-api.md](docs/frame-api.md).

To check rather than trust, ask the content origin with no credentials at all:

```bash
curl -so /dev/null -w '%{http_code}\n' https://<slug>.frame.claudeusercontent.com/_f/<version>/
# 200 means public, 403 means not
```

## The mailbox channel

Two hosts signed into the same account. Each owns one artifact it writes to, and reads the one its
peer writes to. Nothing is ever made public, which is not only a privacy preference: the review gate
and the version pin apply solely to public serving, so the private path has neither and a redeploy is
visible to the peer at once.

![Two nodes exchanging messages through two private artifacts](docs/img/mailbox.svg)

On the first host:

```bash
.venv/bin/python -m clawdvert.mailbox init --node laptop --peer server
```

That mints this node's mailbox and prints a config block. Save it verbatim on the second host as
`relay.json`, `chmod 600` it, and claim a mailbox there:

```bash
.venv/bin/python -m clawdvert.mailbox adopt
```

Pairing is finished. Neither side needed the other's slug, because both are on the same account and
each finds its peer by mailbox title on the first poll. Then, on both:

```bash
.venv/bin/python -m clawdvert.mailbox chat
```

Type a line to send it. `/file <path>` transfers a file into the peer's `inbox/`. `Ctrl-D` quits.
`run` is the same loop without a prompt, `send` and `recv` are one-shot, and `status` reports pairing,
budget and whether the peer is alive.

`relay.json` holds the channel's symmetric key. Move it the way you would move any other secret. It is
gitignored here.

The protocol, its flow control, and why each piece exists are in [docs/mailbox.md](docs/mailbox.md).

## The browser channel

`realm/clawdvert_channel.html` is published as an artifact and opened as a link. Two people exchange a
code, and from then on their browsers talk directly: chat, file transfer, a room mesh and a peer
synced arcade, at native WebRTC throughput.

![How the browser channel reaches the network](docs/img/realm.svg)

The interesting part is how they are introduced at all.

A published artifact runs under a Content Security Policy whose `connect-src 'self'` forbids the page
from reaching any external host. There is no signalling server it can call, because it cannot make an
HTTP request to anything. The policy does not govern WebRTC, so the page can still send UDP to a STUN
or TURN server it names, and that is the only door left open.

`realm/relay/` walks through it. It speaks enough STUN to be reachable from a page that cannot make
requests, carrying messages inside the address fields of allocation responses: five bytes per lane
across six ports. It is a data channel assembled out of protocol metadata that was only ever meant to
carry addresses. Throughput is around twelve bytes per second, which is enough to introduce two
browsers and nothing more, which is what it is for.

The same host also runs coturn as an ordinary TURN relay. That is the one carrying the conversation
once the two browsers have found each other, and between two carrier grade NATs it is not optional.
The two roles are easy to conflate and worth keeping apart: one exists because the sandbox forbids
every normal channel, the other because most networks cannot route to each other.

### The part that took longest to find

Pairing failed repeatedly between a phone on cellular and a desktop at home, and the obvious suspect
was NAT traversal. It was not.

The side that answers holds both descriptions the moment it produces its answer, so it begins
connectivity checks immediately, aimed at a peer that has not received that answer and cannot reply.
Chrome gives up after roughly fifteen seconds. Measured across eight attempts the window was 15, 15,
15, 17, 17 and 19 seconds, which is less time than it takes a person to carry a code between two
devices. The connection was dead before the paste landed.

The fix is not a faster human or a longer timeout. **The clock is started by the first remote
candidate, not by creating the answer.** With both descriptions applied and no remote candidates, ICE
sits idle rather than failing. So the offer now travels without candidates: the joining side has
nothing to check against, its ICE never starts, and its answer stays valid for as long as it takes.
The host is discovered peer reflexively once its checks arrive.

Verified across two networks. The joining side's selected route reads `host → prflx`, which is the
mechanism showing its work.

This channel exists because of a finding reported to Anthropic and closed as Informative. The runtime
makes `RTCPeerConnection` unavailable on the artifact's own window, and that mutation applies to a
single JavaScript realm rather than to the child contexts the same page is permitted to create.
Anthropic considers the measure best effort defence in depth rather than a boundary the sandbox's
isolation model relies on. Nothing here is an open vulnerability, and this repository documents the
mechanism rather than presenting it as a live one.

## Running a relay

Most networks cannot connect two peers directly, and the client says so before you try.
[docs/deploy-relay.md](docs/deploy-relay.md) is the ordered list of what to do about it, from nothing
at all through a TURN relay to the slow text fallback, with the commands for each.

```bash
cd realm
KEY=~/path/to/key.pem ./deploy-relay.sh ubuntu@your-host
```

Read the hardening section before exposing anything. A TURN server forwards to whatever address a
caller names, so without the `denied-peer-ip` rules it is a route into your own network and, on a
cloud host, to the instance metadata service that hands out credentials.

```bash
python3 skills/clawdvert/scripts/relay_check.py --host your-host --port 3478 \
  --user clawdvert --password YOUR_PASSWORD
```

That verifies the whole chain in one command: name resolution, the authentication challenge, an
allocation, and that the relay refuses to forward into private address space.

## Layout

```
clawdvert/          the Python package
  frames.py         auth, pooled HTTPS transport, publish/read/perm/delete
  publish.py        CLI for publishing and visibility
  mailbox.py        CLI for the artifact-backed channel
realm/
  clawdvert_channel.html  the browser client, published as an artifact
  relay/            the STUN relay, its tests and container
  deploy-relay.sh   ships the relay to a host over one SSH connection
docs/               the API reference and the deployment guide
skills/clawdvert/   deploy, test and operate, for an agent
tests/              offline tests, no network and no credentials
```

`check.sh` runs everything that needs no network: the Python suite, a syntax and structure pass over
the browser client, and a check that every element id the JavaScript reaches for exists in the markup.

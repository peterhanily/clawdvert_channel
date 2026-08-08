# Deploying a relay

Two devices can only talk directly when at least one of their networks allows it. Most home
connections do. Most mobile networks do not. This page is what to do when they do not.

Work down the list. Stop at the first one that connects.

| | Needs | Speed | Carries |
| --- | --- | --- | --- |
| **1. Direct** | Nothing | Full | Everything |
| **2. TURN relay** | A host you control, 15 minutes | Full | Everything |
| **3. Text relay** | A host you control, 5 minutes | About 12 bytes a second | Text only |

The app checks your network and tells you which one you are in. You do not have to guess.

## 1. Direct

Nothing to deploy. If the network check says direct pairing will work, create a room and send
someone the code. Skip the rest of this page.

## 2. TURN relay

A TURN relay is a machine on the public internet that forwards packets when two peers cannot
reach each other. It sees addresses, timing and volume. It does not see your messages, because
what it forwards is already encrypted by DTLS.

You need a host with a public IP. Anything with 1 GB of memory will do.

### Install

```bash
sudo apt-get update
sudo apt-get install -y coturn
```

### Configure

Generate a password and write the config. Replace `PUBLIC_IP` and `PRIVATE_IP` with your own. On a
cloud host they differ, because the provider maps the public address onto a private interface, and
coturn cannot work that out for itself. On a bare metal host with a real public address on the
interface, use the same value twice.

```bash
TURN_PASS=$(openssl rand -hex 24)
echo "password: $TURN_PASS"

sudo tee /etc/turnserver.conf >/dev/null <<CONF
listening-port=3478
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

**The `denied-peer-ip` block is not optional.** A relay forwards to whatever address a caller asks
for. Without those lines anyone holding the credential can use your relay to reach your private
network and, on a cloud host, the instance metadata service that hands out credentials. Deleting
them turns a chat relay into a way into your infrastructure.

Two addresses stay reachable no matter what you deny: the relay's own public and private address.
That is deliberate on coturn's part, so two clients on the same relay can reach each other.

### Open the ports

Three things must be reachable: the listener on UDP and TCP, and the relay allocation range on UDP.

```bash
# ufw
sudo ufw allow 3478/udp
sudo ufw allow 3478/tcp
sudo ufw allow 49160:49200/udp
```

On AWS the security group is the only gate that matters, and Docker publishing on `0.0.0.0`
bypasses host firewalls entirely.

```bash
aws ec2 authorize-security-group-ingress --group-id sg-... --ip-permissions \
  'IpProtocol=udp,FromPort=3478,ToPort=3478,IpRanges=[{CidrIp=YOUR_IP/32}]' \
  'IpProtocol=tcp,FromPort=3478,ToPort=3478,IpRanges=[{CidrIp=YOUR_IP/32}]' \
  'IpProtocol=udp,FromPort=49160,ToPort=49200,IpRanges=[{CidrIp=YOUR_IP/32}]'
```

Prefer specific addresses over `0.0.0.0/0`. A world reachable relay whose only protection is one
static password will eventually be found and used to move someone else's traffic.

### Use it

Paste this into the app's relay box on both devices, with your own host and password:

```json
{"iceServers":[{"urls":["turn:turn.example.com:3478?transport=udp",
"turn:turn.example.com:3478?transport=tcp"],
"username":"clawdvert","credential":"YOUR_PASSWORD"}]}
```

Then press **Test relay**. Green means ICE produced a route through it. If it stays red the
credential is wrong, the ports are shut, or `external-ip` is wrong.

### If you would rather not run one

Cloudflare gives out TURN credentials that expire every 24 hours. Create a key under **Realtime**,
then:

```bash
curl -X POST \
  "https://rtc.live.cloudflare.com/v1/turn/keys/$KEY_ID/credentials/generate-ice-servers" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ttl": 86400}'
```

Paste the whole response into the same box.

## 3. Text relay

When TURN is not an option, the text relay carries a conversation through STUN attributes on a
server that never holds an allocation. Measured throughput is around twelve bytes a second, so it carries
short text and nothing else. No files, no arcade.

```bash
cd realm
./deploy-relay.sh ubuntu@your-host
```

That ships the relay, builds its container and starts it. It publishes UDP 3478 to 3483 and binds
its health endpoint to localhost only. Open those six UDP ports to the addresses that need them.

Both devices then enter the same hostname and the same room code.

**Understand what you are choosing.** The room code is the credential, it travels in cleartext in
every packet, and messages pass through the relay in plaintext. It is a fallback for getting words
between two machines that otherwise cannot talk, not a private channel.

## Checking a relay from the command line

```bash
# Does it answer at all
nc -zvu your-host 3478

# Does it allocate (needs the credential)
turnutils_uclient -T -u clawdvert -w YOUR_PASSWORD your-host -p 3478
```

## Related

- [how-it-works.md](how-it-works.md) for how the channel works

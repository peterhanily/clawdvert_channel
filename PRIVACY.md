# Canary privacy boundary

This document covers `realm/clawdcanary.html` and the relay's optional canary
log. It is not a privacy notice for any deployment. A person or organization that
arms and deploys the canary becomes responsible for its use and must publish a
notice suited to that deployment and jurisdiction.

## Public checkout: measurement without repository-controlled recording

The checked-in canary is inert as a logger:

- its `RELAY` value is `null`;
- relay logging defaults to `CANARY_LOG=false`; and
- this repository operates no public canary relay for users of the code.

The page still sends WebRTC/STUN traffic to the public STUN services named in its
source. Those services necessarily receive network metadata such as the source IP
address and port and may process it under their own terms. "Inert" means that the
checkout does not direct a request to a repository-controlled logger or retain a
visit in this relay; it does not mean that no network service observes the packet.

## Armed canary: data collected

An operator arms the canary only by both pointing the page at infrastructure it
controls and enabling `CANARY_LOG=true` on that relay. The in-memory sighting
record contains:

- UTC timestamp;
- normalized source IP address and UDP source port;
- relay lane; and
- an optional room/token value for authenticated allocation traffic (plain STUN
  canary requests store `null`).

An IP address is an online identifier that can be personal data, as explained by
the Irish [Data Protection Commission's definition of key terms](https://www.dataprotection.ie/en/organisations/data-protection-basics/definition-key-terms).

## Requirements for an operator

Before collecting any sighting, the operator must:

1. Define a specific, necessary purpose, such as a disclosed, controlled security
   test. Do not silently repurpose the canary for general tracking.
2. Give affected people a clear notice identifying the operator, the fields and
   purpose, recipients, retention period, contact route, and applicable rights.
3. Determine and document an appropriate legal basis. The repository does not
   supply one; consent or another basis must not be assumed merely because the
   source is available.
4. Minimize collection, restrict the relay to intended participants and networks,
   and avoid combining sightings with unrelated identifiers.

## Retention, access, and deletion

The source keeps a bounded memory-only ring: `CANARY_KEEP` defaults to 500
sightings. It has no time-based expiry and no per-record deletion endpoint. A
process or container restart clears all sightings.

The operator must set and disclose the shortest practical retention period,
choose an appropriately small `CANARY_KEEP`, and schedule deletion when that
period expires. If selective deletion or a data-subject request cannot be handled
with the all-record restart behavior, modify the service before collecting data.

The `/canary` endpoint is bound to loopback by the supplied Compose file. Keep it
there; limit host and SSH access to authorized people, protect credentials, and
do not copy results into ordinary logs, tickets, or analytics systems without a
separate retention and access decision.

## Hosting and processors

Even though the application ring is memory-only, a hosting or network provider
can observe traffic metadata and may capture process memory, diagnostics, or
backups under its own configuration. The operator must identify its processors
and subprocessors, contractual terms, storage locations, transfers, and deletion
behavior in the deployment notice. Repository maintainers do not receive or
control sightings from third-party deployments.

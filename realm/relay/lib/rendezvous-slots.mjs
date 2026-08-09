const defaultClock = () => Date.now();
const OPERATIONS = new Set(["put", "get", "discover", "ack", "abort"]);
const WILDCARD_DEVICE = "0000000000000000";
const MAX_PAYLOAD_BYTES = 240;

// Rendezvous slots are deliberately independent of RoomStore. They are
// replaceable, short-lived protocol state, never room events and never
// candidates for JSONL persistence.
export class RendezvousSlotStore {
  constructor({
    maxSlots = 1000,
    maxSlotsPerRoom = 64,
    slotTtlMs = 5 * 60 * 1000,
    terminalTtlMs = 5 * 60 * 1000,
    readerLeaseMs = 60 * 1000,
    clock = defaultClock,
  } = {}) {
    this.maxSlots = maxSlots;
    this.maxSlotsPerRoom = maxSlotsPerRoom;
    this.slotTtlMs = slotTtlMs;
    this.terminalTtlMs = terminalTtlMs;
    this.readerLeaseMs = readerLeaseMs;
    this.clock = clock;
    this.rooms = new Map();
    this.slotCount = 0;
    this.counters = {
      put: 0,
      get: 0,
      discover: 0,
      ack: 0,
      abort: 0,
      idempotent: 0,
      conflicts: 0,
      rejected: 0,
      expired: 0,
    };
  }

  execute(envelope) {
    const operation = envelope.operation;
    if (!OPERATIONS.has(operation)) return this.reject("bad-operation");
    this.counters[operation] += 1;

    // The server performs global maintenance periodically. Per-request work is
    // bounded to this room so six-lane polling cannot amplify into a scan of
    // every slot on the relay.
    this.pruneRoom(envelope.room);
    if (operation === "put") return this.put(envelope);
    if (operation === "get") return this.get(envelope);
    if (operation === "discover") return this.discover(envelope);
    if (operation === "ack") return this.ack(envelope);
    return this.abort(envelope);
  }

  put(envelope) {
    if (!Buffer.isBuffer(envelope.payload)
      || !envelope.payload.length
      || envelope.payload.length > MAX_PAYLOAD_BYTES) {
      return this.reject("bad-operation");
    }
    const existing = this.lookup(envelope);
    if (existing) {
      if (existing.ownerActor !== envelope.actor) return this.reject("forbidden");
      if (existing.state === "aborted") return { kind: "aborted", revision: existing.revision };
      if (existing.state === "acked") return { kind: "acked", revision: existing.revision };
      if (existing.payload.equals(envelope.payload)) {
        const timestamp = this.clock();
        existing.updatedAt = timestamp;
        existing.expiresAt = timestamp + this.slotTtlMs;
        this.counters.idempotent += 1;
        return { kind: "stored", revision: existing.revision, unchanged: true };
      }
      // Once a reader starts paging a value, make the byte stream immutable.
      // The writer can abort it and publish a fresh attempt instead.
      if (existing.readerActor) return this.conflict(existing.revision);
      if (envelope.revision !== existing.revision || existing.revision === 0xffffffff) {
        return this.conflict(existing.revision);
      }

      existing.payload = Buffer.from(envelope.payload);
      existing.revision += 1;
      existing.updatedAt = this.clock();
      existing.expiresAt = existing.updatedAt + this.slotTtlMs;
      return { kind: "stored", revision: existing.revision, unchanged: false };
    }

    if (envelope.revision !== 0) return this.conflict(0);
    let room = this.rooms.get(envelope.room);
    if (!room) {
      room = new Map();
      this.rooms.set(envelope.room, room);
    }
    if (this.slotCount >= this.maxSlots || room.size >= this.maxSlotsPerRoom) {
      if (!room.size) this.rooms.delete(envelope.room);
      return this.reject("full");
    }

    const timestamp = this.clock();
    room.set(slotKey(envelope), {
      ownerActor: envelope.actor,
      readerActor: null,
      readerSeenAt: 0,
      from: envelope.from,
      to: envelope.to,
      attempt: envelope.attempt,
      role: envelope.role,
      state: "active",
      revision: 1,
      payload: Buffer.from(envelope.payload),
      createdAt: timestamp,
      updatedAt: timestamp,
      expiresAt: timestamp + this.slotTtlMs,
    });
    this.slotCount += 1;
    return { kind: "stored", revision: 1, unchanged: false };
  }

  get(envelope) {
    const slot = this.lookup(envelope);
    if (!slot) return { kind: "empty", revision: 0 };
    return this.read(slot, envelope);
  }

  discover(envelope) {
    const room = this.rooms.get(envelope.room);
    if (!room) return { kind: "empty", revision: 0 };
    const candidates = [...room.values()]
      .filter((candidate) => candidate.state === "active"
        && (envelope.from === WILDCARD_DEVICE || candidate.from === envelope.from)
        && candidate.to === envelope.to
        && (envelope.attempt === "0" || candidate.attempt === envelope.attempt)
        && candidate.role === envelope.role)
      .sort((left, right) => right.createdAt - left.createdAt
        || right.attempt.localeCompare(left.attempt));
    // A discovery response spans several six-lane exchanges. Prefer the slot
    // this actor claimed on its first chunk so a newer offer cannot splice a
    // different token into the middle of the stream.
    const slot = candidates.find((candidate) => candidate.readerActor === envelope.actor)
      || candidates[0];
    if (!slot) return { kind: "empty", revision: 0 };
    return this.read(slot, envelope);
  }

  read(slot, envelope) {
    if (slot.state === "acked") return { kind: "acked", revision: slot.revision };
    if (slot.state === "aborted") return { kind: "aborted", revision: slot.revision };
    if (envelope.revision > slot.revision) return this.conflict(slot.revision);
    const timestamp = this.clock();
    if (slot.readerActor && slot.readerActor !== envelope.actor && slot.ownerActor !== envelope.actor) {
      if (slot.readerSeenAt + this.readerLeaseMs > timestamp) return this.reject("forbidden");
      slot.readerActor = null;
      slot.readerSeenAt = 0;
    }
    if (envelope.actor !== slot.ownerActor) {
      if (!slot.readerActor) slot.readerActor = envelope.actor;
      slot.readerSeenAt = timestamp;
    }
    if (envelope.revision === slot.revision) {
      return { kind: "not-modified", revision: slot.revision };
    }
    return {
      kind: "data",
      from: slot.from,
      to: slot.to,
      revision: slot.revision,
      attempt: slot.attempt,
      role: slot.role,
      payload: slot.payload,
    };
  }

  ack(envelope) {
    const slot = this.lookup(envelope);
    if (!slot) return this.reject("missing");
    if (!slot.readerActor || slot.readerActor !== envelope.actor) return this.reject("forbidden");
    if (envelope.revision !== slot.revision) return this.conflict(slot.revision);
    if (slot.state === "aborted") return { kind: "aborted", revision: slot.revision };
    if (slot.state === "acked") {
      this.counters.idempotent += 1;
      return { kind: "acked", revision: slot.revision };
    }
    this.makeTerminal(slot, "acked");
    return { kind: "acked", revision: slot.revision };
  }

  abort(envelope) {
    const slot = this.lookup(envelope);
    if (!slot) return this.reject("missing");
    if (envelope.actor !== slot.ownerActor && envelope.actor !== slot.readerActor) {
      return this.reject("forbidden");
    }
    if (envelope.revision !== slot.revision) return this.conflict(slot.revision);
    if (slot.state === "acked") return { kind: "acked", revision: slot.revision };
    if (slot.state === "aborted") {
      this.counters.idempotent += 1;
      return { kind: "aborted", revision: slot.revision };
    }
    this.makeTerminal(slot, "aborted");
    return { kind: "aborted", revision: slot.revision };
  }

  makeTerminal(slot, state) {
    const timestamp = this.clock();
    slot.state = state;
    // Once the reader has acknowledged a token, or either side has aborted
    // it, retaining the ICE material provides no protocol value.
    slot.payload = Buffer.alloc(0);
    slot.updatedAt = timestamp;
    slot.expiresAt = timestamp + this.terminalTtlMs;
  }

  lookup(envelope) {
    return this.rooms.get(envelope.room)?.get(slotKey(envelope)) ?? null;
  }

  reject(error) {
    this.counters.rejected += 1;
    return { kind: "error", error, revision: 0 };
  }

  conflict(revision) {
    this.counters.conflicts += 1;
    return { kind: "error", error: "conflict", revision };
  }

  pruneAll() {
    const timestamp = this.clock();
    for (const roomId of this.rooms.keys()) this.pruneRoom(roomId, timestamp);
  }

  pruneRoom(roomId, timestamp = this.clock()) {
    const room = this.rooms.get(roomId);
    if (!room) return;
    for (const [key, slot] of room) {
      if (slot.expiresAt > timestamp) continue;
      room.delete(key);
      this.slotCount -= 1;
      this.counters.expired += 1;
    }
    if (!room.size) this.rooms.delete(roomId);
  }

  stats() {
    this.pruneAll();
    let active = 0;
    let acked = 0;
    let aborted = 0;
    for (const room of this.rooms.values()) {
      for (const slot of room.values()) {
        if (slot.state === "active") active += 1;
        else if (slot.state === "acked") acked += 1;
        else if (slot.state === "aborted") aborted += 1;
      }
    }
    return {
      rooms: this.rooms.size,
      slots: this.slotCount,
      active,
      acked,
      aborted,
      operations: { ...this.counters },
    };
  }
}

function slotKey(envelope) {
  return `${envelope.from}/${envelope.to}/${envelope.attempt}/${envelope.role}`;
}

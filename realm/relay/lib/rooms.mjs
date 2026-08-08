import fs from "node:fs";
import path from "node:path";
import { encodeEvent } from "./protocol.mjs";

const now = () => Date.now();

export class RoomStore {
  constructor({
    maxRooms = 250,
    maxEventsPerRoom = 200,
    maxClientsPerRoom = 12,
    clientTtlMs = 18_000,
    persistencePath = null,
  } = {}) {
    this.maxRooms = maxRooms;
    this.maxEventsPerRoom = maxEventsPerRoom;
    this.maxClientsPerRoom = maxClientsPerRoom;
    this.clientTtlMs = clientTtlMs;
    this.persistencePath = persistencePath;
    this.rooms = new Map();
    if (persistencePath) this.load();
  }

  touch(packet) {
    let room = this.rooms.get(packet.room);
    if (!room) {
      if (this.rooms.size >= this.maxRooms) this.evictRoom();
      room = { sequence: 0, events: [], clients: new Map(), seenRequests: new Map(), touchedAt: now() };
      this.rooms.set(packet.room, room);
    }

    room.touchedAt = now();
    this.pruneClients(room);
    const existing = room.clients.get(packet.clientId);
    if (!existing && room.clients.size >= this.maxClientsPerRoom) {
      return { error: "room-full", room };
    }

    room.clients.set(packet.clientId, { name: packet.name, seenAt: now() });
    if (!existing) {
      this.append(room, packet.room, {
        kind: "system",
        senderId: "system",
        sender: "Relay",
        text: `${packet.name} joined the room`,
        timestamp: now(),
      });
    }

    if (packet.message && packet.requestId !== "0") {
      const seenAt = room.seenRequests.get(packet.requestId);
      if (!seenAt) {
        room.seenRequests.set(packet.requestId, now());
        this.append(room, packet.room, {
          kind: "message",
          senderId: packet.clientId,
          sender: packet.name,
          text: packet.message,
          timestamp: now(),
        });
      }
    }

    this.pruneRequests(room);
    return { room, joined: !existing };
  }

  response(room, requestedSequence) {
    this.pruneClients(room);
    const online = room.clients.size;
    if (requestedSequence === 0 || requestedSequence > room.sequence) {
      return { kind: "control", latestSequence: room.sequence, online };
    }

    const event = room.events.find((candidate) => candidate.id === requestedSequence);
    if (!event) {
      const oldest = room.events[0]?.id ?? room.sequence + 1;
      return { kind: "missing", latestSequence: room.sequence, oldest, online };
    }
    return { kind: "event", event, online };
  }

  pruneAll() {
    for (const [roomId, room] of this.rooms) {
      this.pruneClients(room);
      if (!room.clients.size && now() - room.touchedAt > 60 * 60 * 1000) this.rooms.delete(roomId);
    }
  }

  stats() {
    let clients = 0;
    let events = 0;
    for (const room of this.rooms.values()) {
      this.pruneClients(room);
      clients += room.clients.size;
      events += room.events.length;
    }
    return { rooms: this.rooms.size, clients, events };
  }

  append(room, roomId, value) {
    const event = { ...value, id: (room.sequence + 1) >>> 0 };
    room.sequence = event.id || 1;
    event.payload = encodeEvent(event);
    room.events.push(event);
    if (room.events.length > this.maxEventsPerRoom) room.events.shift();

    if (this.persistencePath && event.kind === "message" && !String(event.text).startsWith("~r2~")) {
      const record = JSON.stringify({ room: roomId, ...value, id: event.id });
      fs.appendFile(this.persistencePath, `${record}\n`, () => {});
    }
    return event;
  }

  pruneClients(room) {
    const cutoff = now() - this.clientTtlMs;
    for (const [clientId, client] of room.clients) {
      if (client.seenAt < cutoff) room.clients.delete(clientId);
    }
  }

  pruneRequests(room) {
    const cutoff = now() - 5 * 60 * 1000;
    for (const [requestId, seenAt] of room.seenRequests) {
      if (seenAt < cutoff) room.seenRequests.delete(requestId);
    }
  }

  evictRoom() {
    const oldest = [...this.rooms.entries()].sort((left, right) => left[1].touchedAt - right[1].touchedAt)[0];
    if (oldest) this.rooms.delete(oldest[0]);
  }

  load() {
    try {
      fs.mkdirSync(path.dirname(this.persistencePath), { recursive: true });
      if (!fs.existsSync(this.persistencePath)) return;
      const lines = fs.readFileSync(this.persistencePath, "utf8").split("\n").filter(Boolean).slice(-10_000);
      for (const line of lines) {
        const record = JSON.parse(line);
        if (!record.room || record.kind !== "message") continue;
        let room = this.rooms.get(record.room);
        if (!room) {
          room = { sequence: 0, events: [], clients: new Map(), seenRequests: new Map(), touchedAt: now() };
          this.rooms.set(record.room, room);
        }
        const event = {
          id: Number(record.id) || room.sequence + 1,
          kind: "message",
          senderId: String(record.senderId ?? "unknown"),
          sender: String(record.sender ?? "Unknown").slice(0, 24),
          text: String(record.text ?? "").slice(0, 1200),
          timestamp: Number(record.timestamp) || now(),
        };
        event.payload = encodeEvent(event);
        room.sequence = Math.max(room.sequence, event.id);
        room.events.push(event);
        if (room.events.length > this.maxEventsPerRoom) room.events.shift();
      }
    } catch (error) {
      console.error("Unable to restore persisted room messages:", error.message);
    }
  }
}

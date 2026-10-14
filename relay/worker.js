// Rescriva Share signaling relay (PROTOCOL.md §2).
// Passes small JSON connection set-up messages between peers in a room. Never sees files.
import { DurableObject } from "cloudflare:workers";

const MAX_PEERS = 32;
// Peers one public address (an IPv4 address, or an IPv6 /64) may hold in a pairing room, so a
// single host can't fill it (M3). Auto rooms aren't capped this way: an IPv4 auto room is one
// public address by construction (networkRoomKey), so the cap would be the room's real limit.
const MAX_PEERS_PER_IP = 4;
const MAX_MESSAGE_BYTES = 64 * 1024;
// Clients ping every 25 s. A peer silent for this long is dropped when someone else joins,
// so a device that vanished without closing its socket doesn't linger as a ghost.
const STALE_MS = 120_000;
const ROLES = new Set(["app", "web"]);
const DEVICES = new Set(["iphone", "ipad", "mac", "phone", "tablet", "computer"]);
const ROOM_ID = /^[A-Za-z0-9_-]{22}$/;
const LOCAL_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?$/;
// C0/C1 control characters, plus bidi overrides/isolates that could disguise a name.
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g;
const PING = '{"t":"ping"}';
const PONG = '{"t":"pong"}';

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    if (origin !== null && !originAllowed(origin, env)) return text("origin not allowed\n", 403);

    const { pathname } = new URL(request.url);
    const get = request.method === "GET" || request.method === "HEAD";
    if (pathname === "/ws" && request.method === "GET") return connect(request, env);
    if (get && pathname === "/") return text("Rescriva Share relay\n");
    return text("not found\n", 404);
  },
};

async function connect(request, env) {
  if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
    return text("expected a WebSocket upgrade\n", 426);
  }
  const q = new URL(request.url).searchParams;
  const room = q.get("room") || "";
  const role = q.get("role") || "";
  const device = q.get("device") || "computer";
  if (room !== "auto" && !ROOM_ID.test(room)) return text("bad room\n", 400);
  if (!ROLES.has(role)) return text("bad role\n", 400);
  if (!DEVICES.has(device)) return text("bad device\n", 400);
  const name = cleanName(q.get("name") || "");

  // New connections per address are budgeted by the WS_LIMIT binding (wrangler.toml): each one
  // is a Worker and a Durable Object request, so a loop of them would use up the daily quota.
  // The budget is per IPv4 address or IPv6 /64 (`addressKey`): an IPv6 host can give itself any
  // number of addresses in its /64, so keying on the whole address would hand it a fresh budget
  // each time. The binding is optional, so `wrangler dev` without it (and the Python stand-in)
  // still work.
  if (env.WS_LIMIT && !(await withinLimit(env.WS_LIMIT, addressKey(request)))) {
    return text("too many connections, try again in a minute\n", 429, { "Retry-After": "60" });
  }

  const auto = room === "auto";
  const key = auto ? await networkRoomKey(request, env) : "p:" + room;
  const stub = env.ROOMS.get(env.ROOMS.idFromName(key));
  const inner = new URL("https://room/ws");
  inner.search = new URLSearchParams({ role, name, device, auto: auto ? "1" : "0" }).toString();
  return stub.fetch(inner.toString(), { headers: request.headers });
}

export class ShareRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    // Answered by the runtime without waking (or billing) the object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair(PING, PONG));
    // Ids already announced as gone; close and error can both fire for one socket.
    this.gone = new Set();
  }

  async fetch(request) {
    if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
      return text("expected a WebSocket upgrade\n", 426);
    }
    const q = new URL(request.url).searchParams;
    const [client, server] = Object.values(new WebSocketPair());

    this.sweepStale();
    const others = this.peers();
    if (others.length >= MAX_PEERS) return this.refuse(client, server, "room full");
    // The outer Worker forwards the original headers, so CF-Connecting-IP is the client's real
    // address. `wrangler dev` may not set it; then every local client counts as one address.
    // Pairing rooms only (PROTOCOL.md §2): an auto room already is one address.
    const ip = addressKey(request);
    if (q.get("auto") !== "1" && others.filter((p) => p.info.ip === ip).length >= MAX_PEERS_PER_IP) {
      return this.refuse(client, server, "too many connections");
    }

    const me = { id: newId(), role: q.get("role"), name: q.get("name"), device: q.get("device") };
    this.ctx.acceptWebSocket(server);
    // `ip` lives only in the attachment; publicInfo never shows it to other peers.
    server.serializeAttachment({ ...me, ip, joined: Date.now(), seen: 0 });
    server.send(JSON.stringify({ t: "welcome", id: me.id, peers: others.map((p) => publicInfo(p.info)) }));
    const join = JSON.stringify({ t: "join", peer: me });
    for (const p of others) safeSend(p.ws, join);
    return new Response(null, { status: 101, webSocket: client });
  }

  // Tells the client why, then closes. Accepted through the hibernation API too, but with no
  // attachment, so it never counts as a peer.
  refuse(client, server, reason) {
    this.ctx.acceptWebSocket(server);
    server.send(JSON.stringify({ t: "error", message: reason }));
    server.close(1008, reason);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    const me = ws.deserializeAttachment();
    if (!me || me.left || this.gone.has(me.id)) return;
    const now = Date.now();
    if (now - me.seen > 10_000) ws.serializeAttachment({ ...me, seen: now });

    if (typeof message !== "string") return;
    // UTF-16 length never exceeds the UTF-8 byte length, so the first test is a cheap shortcut.
    if (message.length > MAX_MESSAGE_BYTES) return;
    if (new TextEncoder().encode(message).byteLength > MAX_MESSAGE_BYTES) return;

    let msg;
    try {
      msg = JSON.parse(message);
    } catch {
      return;
    }
    if (!msg || typeof msg !== "object") return;
    if (msg.t === "ping") return safeSend(ws, PONG); // a ping the auto-response didn't match exactly
    if (msg.t !== "signal" || typeof msg.to !== "string") return;
    if (!msg.data || typeof msg.data !== "object" || Array.isArray(msg.data)) return;
    const target = this.peers(me.id).find((p) => p.info.id === msg.to);
    // Only web <-> app (PROTOCOL.md §2): pages never signal pages, apps never signal apps.
    if (!target || target.info.role === me.role) return;
    safeSend(target.ws, JSON.stringify({ t: "signal", from: me.id, data: msg.data }));
  }

  async webSocketClose(ws) {
    this.leave(ws, 1000, "");
  }

  async webSocketError(ws) {
    this.leave(ws, 1011, "error");
  }

  // Live peers, optionally excluding one id.
  peers(exceptId) {
    const out = [];
    for (const ws of this.ctx.getWebSockets()) {
      const info = ws.deserializeAttachment();
      if (!info || info.left || this.gone.has(info.id) || info.id === exceptId) continue;
      out.push({ ws, info });
    }
    return out;
  }

  // Closes the socket (if it isn't already) and broadcasts `leave` exactly once.
  leave(ws, code, reason) {
    const me = ws.deserializeAttachment();
    try {
      ws.close(code, reason);
    } catch {
      // Already closed.
    }
    if (!me || me.left || this.gone.has(me.id)) return;
    this.gone.add(me.id);
    try {
      ws.serializeAttachment({ ...me, left: true });
    } catch {
      // The in-memory set above still covers this socket.
    }
    const msg = JSON.stringify({ t: "leave", id: me.id });
    const rest = this.peers();
    for (const p of rest) safeSend(p.ws, msg);
    if (rest.length === 0) this.gone.clear();
  }

  sweepStale() {
    const now = Date.now();
    for (const { ws, info } of this.peers()) {
      const auto = this.ctx.getWebSocketAutoResponseTimestamp(ws);
      const last = Math.max(info.joined || 0, info.seen || 0, auto ? auto.getTime() : 0);
      if (now - last > STALE_MS) this.leave(ws, 4408, "stale");
    }
  }
}

function originAllowed(origin, env) {
  if (origin === "https://share.rescriva.com" || LOCAL_ORIGIN.test(origin)) return true;
  return (env.EXTRA_ORIGINS || "")
    .split(",")
    .map((s) => s.trim().replace(/\/+$/, "").toLowerCase())
    .filter((s) => s !== "") // an unset list or a trailing comma must not admit an empty Origin
    .includes(origin.toLowerCase());
}

// True when the address still has budget. The limiter is best effort (counted per Cloudflare
// location, eventually consistent), and if it errors the connection goes through rather than
// the relay going down; the WAF rule in the README is the backstop.
async function withinLimit(limiter, key) {
  try {
    const { success } = await limiter.limit({ key });
    return success !== false;
  } catch {
    return true;
  }
}

function clientIP(request) {
  return (request.headers.get("CF-Connecting-IP") || "").trim();
}

// What the per-address limits count by: the IPv4 address, or the IPv6 /64 (an IPv6 host can
// use any address in its /64, so the prefix is the host as far as the relay can tell); "local"
// when there's no address (`wrangler dev`).
function addressKey(request) {
  const ip = clientIP(request);
  return ip ? (networkPrefix(ip) ?? ip) : "local";
}

function cleanName(raw) {
  return Array.from(raw.replace(UNSAFE_CHARS, "")).slice(0, 64).join("");
}

async function networkRoomKey(request, env) {
  const ip = clientIP(request);
  // `wrangler dev` may not set CF-Connecting-IP; then every local client shares one room.
  const prefix = ip ? (networkPrefix(ip) ?? ip) : "local";
  const salt = env.ROOM_SALT || "rescriva-share";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(salt + "|" + prefix));
  const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
  return "net:" + hex.slice(0, 24);
}

// IPv4: the whole address. IPv6: the /64, as four zero-padded lower-case hextets.
function networkPrefix(ip) {
  const v4 = parseIPv4(ip);
  if (v4) return v4.join(".");
  const g = parseIPv6(ip);
  if (!g) return null;
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    return [g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255].join("."); // IPv4-mapped
  }
  return g.slice(0, 4).map((x) => x.toString(16).padStart(4, "0")).join(":");
}

function parseIPv4(s) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return null;
  const o = s.split(".").map(Number);
  return o.every((n) => n <= 255) ? o : null;
}

// Returns eight 16-bit numbers, expanding "::" and a trailing dotted IPv4 part.
function parseIPv6(s) {
  s = s.split("%")[0];
  const tail4 = s.match(/^(.*:)([^:]+\.[^:]+)$/);
  if (tail4) {
    const o = parseIPv4(tail4[2]);
    if (!o) return null;
    s = tail4[1] + ((o[0] << 8) | o[1]).toString(16) + ":" + ((o[2] << 8) | o[3]).toString(16);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const split = (h) => (h === "" ? [] : h.split(":"));
  const head = split(halves[0]);
  const tail = halves.length === 2 ? split(halves[1]) : [];
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 1 : fill !== 0) return null;
  const groups = [...head, ...Array(halves.length === 2 ? fill : 0).fill("0"), ...tail];
  if (!groups.every((h) => /^[0-9a-fA-F]{1,4}$/.test(h))) return null;
  return groups.map((h) => parseInt(h, 16));
}

function newId() {
  const bytes = crypto.getRandomValues(new Uint8Array(9)); // 9 bytes = 12 base64url chars
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_");
}

function publicInfo({ id, role, name, device }) {
  return { id, role, name, device };
}

function safeSend(ws, data) {
  try {
    ws.send(data);
  } catch {
    // The socket closed underneath us; its close handler will announce the leave.
  }
}

function text(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}

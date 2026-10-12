#!/usr/bin/env python3
"""Local stand-in for the Rescriva Share relay (worker.js), for testing without Cloudflare.

    python3 dev_relay.py [--host 127.0.0.1] [--port 8787] [--max-peers 32] [--stale-after 120]

Python 3.9+, standard library only. Same URL, query parameters, messages and limits as the
Worker. Every room=auto client lands in one room, since everything here is localhost.
EXTRA_ORIGINS (comma-separated) works as an environment variable, like the Worker's.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import struct
import sys
import time
from urllib.parse import parse_qs, urlsplit

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_MESSAGE_BYTES = 64 * 1024
ROLES = {"app", "web"}
DEVICES = {"iphone", "ipad", "mac", "phone", "tablet", "computer"}
ROOM_ID = re.compile(r"[A-Za-z0-9_-]{22}")
LOCAL_ORIGIN = re.compile(r"http://(localhost|127\.0\.0\.1)(:\d{1,5})?")
# C0/C1 control characters, plus bidi overrides/isolates that could disguise a name.
UNSAFE_CHARS = re.compile("[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]")
PING = '{"t":"ping"}'
PONG = '{"t":"pong"}'
REASONS = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 426: "Upgrade Required"}

OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA


def accept_for(key):
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


assert accept_for("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="  # RFC 6455 §1.3


def log(*parts):
    print(time.strftime("%H:%M:%S"), *parts, flush=True)


def clean_name(raw):
    return UNSAFE_CHARS.sub("", raw)[:64]


def new_id():
    return base64.urlsafe_b64encode(secrets.token_bytes(9)).decode()  # 12 chars


def unmask(data, mask):
    if not data:
        return data
    key = (mask * (len(data) // 4 + 1))[: len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(key, "big")).to_bytes(len(data), "big")


def frame(opcode, payload):
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", 0x80 | opcode, n)
    elif n < 1 << 16:
        head = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        head = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    return head + payload


def _reject_constant(_):
    raise ValueError("not JSON")  # NaN/Infinity aren't JSON (JS's JSON.parse refuses them too)


def dumps(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


class ProtocolError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Peer:
    def __init__(self, reader, writer, room_key, role, name, device):
        self.reader, self.writer = reader, writer
        self.room_key = room_key
        self.id = new_id()
        self.role, self.name, self.device = role, name, device
        self.seen = time.monotonic()
        self.left = False
        self.closed = False
        self.lock = asyncio.Lock()  # Python 3.9 can't run two drain()s on one stream at once

    def info(self):
        return {"id": self.id, "role": self.role, "name": self.name, "device": self.device}

    async def send(self, opcode, payload):
        if self.closed:
            return
        async with self.lock:
            try:
                self.writer.write(frame(opcode, payload))
                await asyncio.wait_for(self.writer.drain(), 10)
            except (ConnectionError, asyncio.TimeoutError, RuntimeError):
                self.abort()

    async def send_text(self, text):
        await self.send(OP_TEXT, text.encode())

    async def close(self, code, reason=""):
        await self.send(OP_CLOSE, struct.pack("!H", code) + reason.encode())
        self.abort()

    def abort(self):
        self.closed = True
        try:
            self.writer.close()
        except Exception:
            pass


class Relay:
    def __init__(self, max_peers, stale_after, extra_origins):
        self.max_peers = max_peers
        self.stale_after = stale_after
        self.extra_origins = {o.strip().rstrip("/").lower() for o in extra_origins.split(",") if o.strip()}
        self.rooms = {}  # room key -> {peer id: Peer}

    def origin_allowed(self, origin):
        if origin == "https://share.rescriva.com" or LOCAL_ORIGIN.fullmatch(origin):
            return True
        return origin.lower() in self.extra_origins

    # ---- HTTP ----

    async def handle(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            method, target, headers = parse_request(head)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError,
                ConnectionError, ValueError):
            writer.close()
            return
        try:
            await self.route(reader, writer, method, target, headers)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    async def route(self, reader, writer, method, target, headers):
        origin = headers.get("origin")
        if origin is not None and not self.origin_allowed(origin):
            return respond(writer, method, 403, "origin not allowed\n")
        url = urlsplit(target)
        get = method in ("GET", "HEAD")
        if url.path == "/ws" and method == "GET":
            return await self.connect(reader, writer, url.query, headers)
        if get and url.path == "/":
            return respond(writer, method, 200, "Rescriva Share relay\n")
        if get and url.path == "/health":
            extra = [f"Access-Control-Allow-Origin: {origin}", "Vary: Origin"] if origin else []
            return respond(writer, method, 200, "ok", extra)
        return respond(writer, method, 404, "not found\n")

    async def connect(self, reader, writer, query, headers):
        if headers.get("upgrade", "").lower() != "websocket":
            return respond(writer, "GET", 426, "expected a WebSocket upgrade\n")
        if headers.get("sec-websocket-version") != "13":
            return respond(writer, "GET", 426, "unsupported WebSocket version\n", ["Sec-WebSocket-Version: 13"])
        key = headers.get("sec-websocket-key", "")
        try:
            if len(base64.b64decode(key, validate=True)) != 16:
                raise ValueError
        except ValueError:
            return respond(writer, "GET", 400, "bad Sec-WebSocket-Key\n")

        q = {k: v[0] for k, v in parse_qs(query, keep_blank_values=True, errors="replace").items()}
        room = q.get("room", "")
        role = q.get("role", "")
        device = q.get("device") or "computer"
        if room != "auto" and not ROOM_ID.fullmatch(room):
            return respond(writer, "GET", 400, "bad room\n")
        if role not in ROLES:
            return respond(writer, "GET", 400, "bad role\n")
        if device not in DEVICES:
            return respond(writer, "GET", 400, "bad device\n")
        name = clean_name(q.get("name", ""))
        room_key = "net:local" if room == "auto" else "p:" + room

        writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Accept: {accept_for(key)}\r\n\r\n").encode())
        await writer.drain()

        peer = Peer(reader, writer, room_key, role, name, device)
        await self.sweep_stale(room_key)
        members = self.rooms.setdefault(room_key, {})  # no awaits from here until the peer is added
        if len(members) >= self.max_peers:
            log("full ", short_room(room_key), f"refused {role}/{device}")
            await peer.send_text(dumps({"t": "error", "message": "room full"}))
            await peer.close(1008, "room full")
            return

        others = list(members.values())
        members[peer.id] = peer
        log("join ", short_room(room_key), peer.id, f"{role}/{device}", repr(name), f"({len(members)} in room)")
        await peer.send_text(dumps({"t": "welcome", "id": peer.id, "peers": [p.info() for p in others]}))
        join = dumps({"t": "join", "peer": peer.info()})
        for p in others:
            await p.send_text(join)
        try:
            await self.read_loop(peer)
        except ProtocolError as e:
            await peer.close(e.code)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            peer.abort()
            await self.leave(peer)

    # ---- WebSocket ----

    async def read_loop(self, peer):
        reader = peer.reader
        msg_op = None  # opcode of the message being assembled from fragments
        parts, size, too_big = [], 0, False
        while True:
            b1, b2 = await reader.readexactly(2)
            fin, rsv, op = b1 & 0x80, b1 & 0x70, b1 & 0x0F
            masked, n = b2 & 0x80, b2 & 0x7F
            if n == 126:
                (n,) = struct.unpack("!H", await reader.readexactly(2))
            elif n == 127:
                (n,) = struct.unpack("!Q", await reader.readexactly(8))
                if n >> 63:
                    raise ProtocolError(1002)
            if rsv or not masked:
                raise ProtocolError(1002)
            mask = await reader.readexactly(4)

            if op >= 0x8:  # control frames: never fragmented, may sit between fragments
                if not fin or n > 125:
                    raise ProtocolError(1002)
                payload = unmask(await reader.readexactly(n), mask)
                if op == OP_CLOSE:
                    await self.on_close(peer, payload)
                    return
                if op == OP_PING:
                    await peer.send(OP_PONG, payload)
                elif op != OP_PONG:
                    raise ProtocolError(1002)
                continue

            if op == OP_CONT:
                if msg_op is None:
                    raise ProtocolError(1002)
            elif op in (OP_TEXT, OP_BINARY):
                if msg_op is not None:
                    raise ProtocolError(1002)
                msg_op, parts, size, too_big = op, [], 0, False
            else:
                raise ProtocolError(1002)

            size += n
            if too_big or size > MAX_MESSAGE_BYTES:
                too_big, parts = True, []
                await discard(reader, n)  # oversized messages are dropped, not buffered
            else:
                parts.append(unmask(await reader.readexactly(n), mask))

            if fin:
                peer.seen = time.monotonic()
                if msg_op == OP_TEXT and not too_big:
                    try:
                        text = b"".join(parts).decode("utf-8")
                    except UnicodeDecodeError:
                        raise ProtocolError(1007)
                    await self.on_text(peer, text)
                msg_op, parts = None, []

    async def on_close(self, peer, payload):
        code = 1000
        if len(payload) >= 2:
            (code,) = struct.unpack("!H", payload[:2])
            if code < 1000 or code in (1004, 1005, 1006, 1015) or 1016 <= code < 3000 or code >= 5000:
                code = 1002
        elif len(payload) == 1:
            code = 1002
        await peer.close(code)

    async def on_text(self, peer, text):
        if peer.left:
            return
        if text == PING:
            return await peer.send_text(PONG)
        try:
            msg = json.loads(text, parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            return
        if not isinstance(msg, dict):
            return
        t = msg.get("t")
        if t == "ping":
            return await peer.send_text(PONG)
        to, data = msg.get("to"), msg.get("data")
        if t != "signal" or not isinstance(to, str) or not isinstance(data, dict):
            return
        target = self.rooms.get(peer.room_key, {}).get(to)
        if target is None or target is peer or target.left:
            return
        log("signal", short_room(peer.room_key), f"{peer.id} -> {target.id}", signal_kind(data))
        await target.send_text(dumps({"t": "signal", "from": peer.id, "data": data}))

    async def leave(self, peer):
        if peer.left:
            return
        peer.left = True
        members = self.rooms.get(peer.room_key, {})
        members.pop(peer.id, None)
        log("leave", short_room(peer.room_key), peer.id, f"({len(members)} in room)")
        msg = dumps({"t": "leave", "id": peer.id})
        for p in list(members.values()):
            await p.send_text(msg)
        if not members:
            self.rooms.pop(peer.room_key, None)

    async def sweep_stale(self, room_key):
        now = time.monotonic()
        for p in list(self.rooms.get(room_key, {}).values()):
            if now - p.seen > self.stale_after:
                log("stale", short_room(p.room_key), p.id)
                await p.close(4408, "stale")
                await self.leave(p)


def parse_request(head):
    lines = head.decode("latin-1").split("\r\n")
    method, target, version = lines[0].split(" ")
    if not version.startswith("HTTP/1."):
        raise ValueError(version)
    headers = {}
    for line in lines[1:]:
        if line:
            k, _, v = line.partition(":")
            headers.setdefault(k.strip().lower(), v.strip())
    return method, target, headers


def respond(writer, method, status, body, extra=()):
    data = body.encode()
    lines = [f"HTTP/1.1 {status} {REASONS[status]}", "Content-Type: text/plain; charset=utf-8",
             f"Content-Length: {len(data)}", "Cache-Control: no-store", "Connection: close", *extra]
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode() + (b"" if method == "HEAD" else data))


async def discard(reader, n):
    while n:
        chunk = await reader.read(min(n, 1 << 16))
        if not chunk:
            raise asyncio.IncompleteReadError(b"", n)
        n -= len(chunk)


def short_room(key):
    # A private room id works as an invitation, so only log the start of it.
    return key if key.startswith("net:") else key[:6] + "…"


def signal_kind(data):
    sdp = data.get("sdp")
    if isinstance(sdp, dict):
        return sdp.get("type") if sdp.get("type") in ("offer", "answer", "pranswer", "rollback") else "sdp"
    return "candidate" if "candidate" in data else "other"


async def main():
    ap = argparse.ArgumentParser(description="Local Rescriva Share relay (no Cloudflare needed).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--max-peers", type=int, default=int(os.environ.get("RELAY_MAX_PEERS", "32")),
                    help="peer cap per room (default 32; lower it to test the 'room full' path)")
    ap.add_argument("--stale-after", type=float, default=120.0,
                    help="seconds of silence before a peer is dropped when someone joins (default 120)")
    args = ap.parse_args()
    if args.max_peers < 1:
        ap.error("--max-peers must be at least 1")
    relay = Relay(args.max_peers, args.stale_after, os.environ.get("EXTRA_ORIGINS", ""))
    server = await asyncio.start_server(relay.handle, args.host, args.port)
    log(f"Rescriva Share dev relay on ws://{args.host}:{args.port}/ws (max {args.max_peers} peers a room)")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)

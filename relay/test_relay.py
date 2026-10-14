#!/usr/bin/env python3
"""Black-box tests for the Rescriva Share relay (worker.js under `wrangler dev`, or dev_relay.py).

    python3 test_relay.py [ws://127.0.0.1:8787/ws] [--cap N] [--per-ip N] [--stale-after S]
                          [--rate N] [--extra-origin ORIGIN] [-k NAME]

Python 3.9+, standard library only. --cap N runs the "room full" case against a relay whose
cap is N (start dev_relay.py with --max-peers N to keep it small). --per-ip N is the relay's
per-address cap (default 4; dev_relay.py --max-per-ip N). --stale-after S runs the ghost-peer
case against a relay that drops peers silent for S seconds (dev_relay.py --stale-after S).
--rate N runs only the connection-budget case, against a relay that allows N new connections a
minute per address (dev_relay.py --connections-per-minute N); the other cases would use up that
budget. --extra-origin ORIGIN checks that an EXTRA_ORIGINS entry is allowed while an empty Origin
still isn't (start dev_relay.py with EXTRA_ORIGINS="ORIGIN," to include a trailing empty entry).

The per-address cases act as several addresses by sending CF-Connecting-IP, which dev_relay.py
honours (and `wrangler dev` does if it passes the header through). Cloudflare overwrites it on
the real relay, which also budgets new connections per address, so against
wss://relay.rescriva.com run a few cases at a time with -k rather than the whole suite.
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urlencode, urlsplit

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
ID_RE = re.compile(r"[A-Za-z0-9_-]{12}")


def accept_for(key):
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


assert accept_for("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="  # RFC 6455 §1.3


class Closed(Exception):
    def __init__(self, code, reason):
        super().__init__(f"closed {code} {reason!r}")
        self.code, self.reason = code, reason


class Fail(Exception):
    pass


class WS:
    """A minimal blocking WebSocket client: masked frames, 16/64-bit lengths, fragmentation."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""
        self.frags = []
        self.frag_op = None

    @staticmethod
    def open(url, params=None, origin=None, timeout=5.0, headers=None):
        """Returns (status, body, ws). ws is None unless the server answered 101."""
        u = urlsplit(url)
        port = u.port or (443 if u.scheme == "wss" else 80)
        sock = socket.create_connection((u.hostname, port), timeout=timeout)
        if u.scheme == "wss":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname)
        query = urlencode(params or {})
        path = (u.path or "/") + ("?" + query if query else "")
        key = base64.b64encode(os.urandom(16)).decode()
        lines = [f"GET {path} HTTP/1.1", f"Host: {u.netloc}", "Upgrade: websocket", "Connection: Upgrade",
                 f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13"]
        if origin is not None:
            lines.append(f"Origin: {origin}")
        for k, v in (headers or {}).items():
            lines.append(f"{k}: {v}")
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        ws = WS(sock)
        head = ws._read_until(b"\r\n\r\n", time.monotonic() + timeout)
        status_line, *header_lines = head.decode("latin-1").split("\r\n")
        status = int(status_line.split(" ")[1])
        headers = {}
        for line in header_lines:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        if status != 101:
            body = ws.buf
            n = int(headers.get("content-length", "0") or 0)
            try:
                while len(body) < n:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    body += chunk
            except socket.timeout:
                pass
            sock.close()
            return status, body.decode("utf-8", "replace"), None
        if headers.get("sec-websocket-accept") != accept_for(key):
            sock.close()
            raise Fail("bad Sec-WebSocket-Accept")
        return status, "", ws

    def _read_until(self, marker, deadline):
        while marker not in self.buf:
            self._fill(deadline)
        i = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out

    def _fill(self, deadline):
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout()
        self.sock.settimeout(left)
        chunk = self.sock.recv(65536)
        if not chunk:
            raise Closed(1006, "connection dropped")
        self.buf += chunk

    def _parse(self):
        """One complete frame from the buffer, or None if it isn't all here yet."""
        b = self.buf
        if len(b) < 2:
            return None
        fin, op, masked, n, i = b[0] & 0x80, b[0] & 0x0F, b[1] & 0x80, b[1] & 0x7F, 2
        if n == 126:
            if len(b) < 4:
                return None
            (n,), i = struct.unpack("!H", b[2:4]), 4
        elif n == 127:
            if len(b) < 10:
                return None
            (n,), i = struct.unpack("!Q", b[2:10]), 10
        if masked:
            raise Fail("server sent a masked frame")
        if len(b) < i + n:
            return None
        self.buf = b[i + n:]
        return bool(fin), op, b[i:i + n]

    def send_frame(self, op, payload, fin=True):
        n = len(payload)
        b0 = (0x80 if fin else 0) | op
        if n < 126:
            head = struct.pack("!BB", b0, 0x80 | n)
        elif n < 1 << 16:
            head = struct.pack("!BBH", b0, 0x80 | 126, n)
        else:
            head = struct.pack("!BBQ", b0, 0x80 | 127, n)
        mask = os.urandom(4)
        key = (mask * (n // 4 + 1))[:n]
        body = (int.from_bytes(payload, "big") ^ int.from_bytes(key, "big")).to_bytes(n, "big") if n else b""
        self.sock.sendall(head + mask + body)

    def send_text(self, text, pieces=1):
        data = text.encode()
        if pieces == 1:
            return self.send_frame(0x1, data)
        step = -(-len(data) // pieces)
        chunks = [data[i:i + step] for i in range(0, len(data), step)]
        for k, chunk in enumerate(chunks):
            self.send_frame(0x1 if k == 0 else 0x0, chunk, fin=k == len(chunks) - 1)

    def send_json(self, obj):
        self.send_text(json.dumps(obj, separators=(",", ":")))

    def recv(self, timeout=3.0):
        """Next data message as ('text'|'binary'|'pong', payload); None on timeout. Raises Closed."""
        deadline = time.monotonic() + timeout
        while True:
            f = self._parse()
            if f is None:
                try:
                    self._fill(deadline)
                except socket.timeout:
                    return None
                continue
            fin, op, payload = f
            if op == 0x8:
                code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
                try:
                    self.send_frame(0x8, payload[:2])
                except OSError:
                    pass
                self.sock.close()
                raise Closed(code, payload[2:].decode("utf-8", "replace"))
            if op == 0x9:
                self.send_frame(0xA, payload)
                continue
            if op == 0xA:
                return "pong", payload
            if op in (0x1, 0x2):
                self.frag_op, self.frags = op, []
            self.frags.append(payload)
            if fin:
                data = b"".join(self.frags)
                kind = "text" if self.frag_op == 0x1 else "binary"
                self.frags, self.frag_op = [], None
                return kind, data

    def recv_json(self, timeout=3.0):
        while True:
            m = self.recv(timeout)
            if m is None:
                return None
            if m[0] == "text":
                return json.loads(m[1])

    def expect(self, pred, timeout=3.0, what="message"):
        deadline = time.monotonic() + timeout
        seen = []
        while True:
            m = self.recv_json(max(0.01, deadline - time.monotonic()))
            if m is None:
                raise Fail(f"timed out waiting for {what}; got {seen}")
            if pred(m):
                return m
            seen.append(m)

    def expect_silence(self, timeout=1.0, what="nothing"):
        m = self.recv_json(timeout)
        if m is not None:
            raise Fail(f"expected {what}, got {m}")

    def close(self, code=1000):
        try:
            self.send_frame(0x8, struct.pack("!H", code))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if self.recv(deadline - time.monotonic()) is None:
                    break
        except (Closed, OSError, Fail):
            pass
        finally:
            self.sock.close()

    def drop(self):
        """Vanish without a close frame."""
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


# ---- helpers ----

URL = "ws://127.0.0.1:8787/ws"
OPEN = []


def room():
    return base64.urlsafe_b64encode(secrets.token_bytes(17)).decode()[:22]


def as_ip(ip):
    """Headers that make a local relay treat the connection as coming from `ip`."""
    return {"CF-Connecting-IP": ip} if ip else None


def local_relay():
    """A local relay honours CF-Connecting-IP; Cloudflare replaces it with the real address."""
    return urlsplit(URL).scheme == "ws"


def join(room_id, role="web", name=None, device="computer", origin=None, ip=None):
    params = {"room": room_id, "role": role}
    if name is not None:
        params["name"] = name
    if device is not None:
        params["device"] = device
    status, body, ws = WS.open(URL, params, origin, headers=as_ip(ip))
    if ws is None:
        raise Fail(f"expected 101 for {params}, got {status} {body.strip()!r}")
    OPEN.append(ws)
    welcome = ws.expect(lambda m: m.get("t") == "welcome", what="welcome")
    if not ID_RE.fullmatch(welcome.get("id", "")):
        raise Fail(f"bad peer id {welcome.get('id')!r}")
    ws.id = welcome["id"]
    ws.welcome = welcome
    return ws


def status_of(params, origin=None, ip=None):
    status, _, ws = WS.open(URL, params, origin, headers=as_ip(ip))
    if ws:
        OPEN.append(ws)
        ws.close()
    return status


def check(cond, msg):
    if not cond:
        raise Fail(msg)


def http_get(path, origin=None):
    u = urlsplit(URL)
    cls = http.client.HTTPSConnection if u.scheme == "wss" else http.client.HTTPConnection
    conn = cls(u.hostname, u.port or (443 if u.scheme == "wss" else 80), timeout=5)
    conn.request("GET", path, headers={"Origin": origin} if origin else {})
    r = conn.getresponse()
    out = r.status, r.read().decode(), {k.lower(): v for k, v in r.getheaders()}
    conn.close()
    return out


def offer(text="v=0"):
    return {"sdp": {"type": "offer", "sdp": text}}


# ---- cases ----

def t_http_routes():
    s, body, _ = http_get("/")
    check(s == 200 and "Rescriva Share relay" in body, f"GET / -> {s} {body!r}")
    s, body, _ = http_get("/", origin="http://localhost:3000")
    check(s == 200, f"GET / with an allowed Origin -> {s}")
    for path in ["/nope", "/health"]:  # /health was removed; nothing probes it
        s, _, _ = http_get(path)
        check(s == 404, f"GET {path} -> {s}")
    s, _, _ = http_get("/ws?room=auto&role=web")
    check(s in (400, 426), f"GET /ws without Upgrade -> {s}")


def t_welcome_join_leave():
    r = room()
    a = join(r, "web", "Chrome on Mac", "computer")
    check(a.welcome["peers"] == [], f"first welcome should be empty: {a.welcome}")
    b = join(r, "app", "Mike's iPhone", "iphone")
    check(b.welcome["peers"] == [{"id": a.id, "role": "web", "name": "Chrome on Mac", "device": "computer"}],
          f"second welcome: {b.welcome}")
    j = a.expect(lambda m: m.get("t") == "join", what="join")
    check(j["peer"] == {"id": b.id, "role": "app", "name": "Mike's iPhone", "device": "iphone"}, f"join: {j}")
    b.close()
    lv = a.expect(lambda m: m.get("t") == "leave", what="leave")
    check(lv == {"t": "leave", "id": b.id}, f"leave: {lv}")
    a.expect_silence(1.0, "a single leave")


def t_name_and_device():
    r = room()
    a = join(r, "web")
    long_name = "\u202eA\x00B\x1fC\x7f\x85" + "x" * 80
    b = join(r, "app", long_name, None)
    j = a.expect(lambda m: m.get("t") == "join", what="join")
    want = ("ABC" + "x" * 80)[:64]
    check(j["peer"]["name"] == want, f"name not cleaned/clipped: {j['peer']['name']!r}")
    check(j["peer"]["device"] == "computer", f"default device: {j['peer']}")
    c = join(r, "web", "\U0001F642" * 70, "phone")
    check(b.expect(lambda m: m.get("t") == "join")["peer"]["name"] == "\U0001F642" * 64, "64 code points, not UTF-16 units")
    c.close()


def t_signal_both_ways():
    r = room()
    web = join(r, "web")
    app = join(r, "app", device="iphone")
    web.expect(lambda m: m.get("t") == "join")
    web.send_json({"t": "signal", "to": app.id, "data": offer("o")})
    m = app.expect(lambda m: m.get("t") == "signal", what="offer at app")
    check(m == {"t": "signal", "from": web.id, "data": offer("o")}, f"offer: {m}")
    cand = {"candidate": {"candidate": "candidate:1 1 udp 1 192.168.1.2 5000 typ host", "sdpMid": "0",
                          "sdpMLineIndex": 0}}
    app.send_json({"t": "signal", "to": web.id, "data": {"sdp": {"type": "answer", "sdp": "a"}}})
    app.send_json({"t": "signal", "to": web.id, "data": cand})
    m = web.expect(lambda m: m.get("t") == "signal", what="answer at web")
    check(m == {"t": "signal", "from": app.id, "data": {"sdp": {"type": "answer", "sdp": "a"}}}, f"answer: {m}")
    m = web.expect(lambda m: m.get("t") == "signal", what="candidate at web")
    check(m == {"t": "signal", "from": app.id, "data": cand}, f"candidate: {m}")


def t_signal_roles():
    # Signals pass only between a web peer and an app peer; web->web and app->app are dropped.
    r = room()
    web1 = join(r, "web")
    web2 = join(r, "web")
    app1 = join(r, "app", device="iphone")
    app2 = join(r, "app", device="ipad")
    for p in (web1, web2, app1):  # read the joins that piled up
        while p.recv_json(0.2) is not None:
            pass
    web1.send_json({"t": "signal", "to": web2.id, "data": offer("web to web")})
    app1.send_json({"t": "signal", "to": app2.id, "data": offer("app to app")})
    web2.expect_silence(1.0, "nothing at the other web peer")
    app2.expect_silence(0.2, "nothing at the other app peer")
    web1.send_json({"t": "signal", "to": app2.id, "data": offer("web to app")})
    m = app2.expect(lambda m: m.get("t") == "signal", what="web->app signal")
    check(m == {"t": "signal", "from": web1.id, "data": offer("web to app")}, f"web->app: {m}")
    app2.send_json({"t": "signal", "to": web1.id, "data": {"sdp": {"type": "answer", "sdp": "app to web"}}})
    m = web1.expect(lambda m: m.get("t") == "signal", what="app->web signal")
    check(m["from"] == app2.id and m["data"]["sdp"]["sdp"] == "app to web", f"app->web: {m}")
    web2.expect_silence(0.2, "the dropped signals never arrive late")


def t_unknown_target_ignored():
    r = room()
    a = join(r, "web")
    b = join(r, "app")
    a.expect(lambda m: m.get("t") == "join")
    a.send_json({"t": "signal", "to": "AAAAAAAAAAAA", "data": offer()})
    a.send_json({"t": "signal", "to": a.id, "data": offer()})  # itself
    a.send_text("{not json")
    a.send_json({"t": "hello", "to": b.id, "data": offer()})  # unknown type
    a.send_json({"t": "signal", "to": b.id})  # no data
    a.send_json({"t": "signal", "to": b.id, "data": "text"})  # data not an object
    a.send_json([1, 2, 3])
    a.send_frame(0x2, b"\x00\x01binary")
    b.expect_silence(1.0, "nothing at b")
    a.expect_silence(0.2, "nothing at a")
    a.send_text('{"t":"ping"}')
    check(a.expect(lambda m: True) == {"t": "pong"}, "a should still be connected")
    a.send_json({"t": "signal", "to": b.id, "data": offer("still works")})
    b.expect(lambda m: m.get("t") == "signal", what="signal after junk")


def t_bad_room_rejected():
    for bad in [None, "", "short", "A" * 21, "A" * 23, "A" * 21 + "+", "A" * 21 + ".", "AUTO", "auto2"]:
        params = {"role": "web"} if bad is None else {"room": bad, "role": "web"}
        s = status_of(params)
        check(400 <= s < 500, f"room={bad!r} -> {s}")
    check(status_of({"room": "A" * 21 + "-", "role": "web"}) == 101, "valid 22-char room refused")


def t_bad_role_rejected():
    for bad in [None, "", "admin", "APP", "web "]:
        params = {"room": room()} if bad is None else {"room": room(), "role": bad}
        s = status_of(params)
        check(400 <= s < 500, f"role={bad!r} -> {s}")


def t_bad_device_rejected():
    s = status_of({"room": room(), "role": "web", "device": "toaster"})
    check(400 <= s < 500, f"device=toaster -> {s}")
    for d in ["iphone", "ipad", "mac", "phone", "tablet", "computer"]:
        check(status_of({"room": room(), "role": "app", "device": d}) == 101, f"device={d} refused")


def t_disallowed_origin_403():
    # "" is the empty Origin that an unset EXTRA_ORIGINS once let through ("".split(",") is [""]).
    for o in ["https://evil.example", "null", "", "https://share.rescriva.com.evil.com",
              "http://share.rescriva.com", "https://share.rescriva.com:8443", "http://localhost.evil.com",
              "https://localhost:3000", "http://127.0.0.2:8000", "http://localhost:abc"]:
        s = status_of({"room": room(), "role": "web"}, origin=o)
        check(s == 403, f"Origin {o!r} -> {s}")
    s, _, _ = http_get("/", origin="https://evil.example")
    check(s == 403, f"GET / with bad Origin -> {s}")


def t_allowed_origin_ok():
    for o in [None, "https://share.rescriva.com", "http://localhost:5173", "http://127.0.0.1:8000"]:
        s = status_of({"room": room(), "role": "web"}, origin=o)
        check(s == 101, f"Origin {o} -> {s}")


def t_ping_pong():
    a = join(room(), "web")
    a.send_text('{"t":"ping"}')
    check(a.expect(lambda m: True, what="pong") == {"t": "pong"}, "exact ping")
    a.send_text('{ "t" : "ping" }')
    check(a.expect(lambda m: True, what="pong") == {"t": "pong"}, "spaced ping")
    a.send_frame(0x9, b"hi")
    m = a.recv(3)
    check(m == ("pong", b"hi"), f"protocol-level ping -> {m}")


def t_message_size_limit():
    r = room()
    a = join(r, "web")
    b = join(r, "app")
    a.expect(lambda m: m.get("t") == "join")
    for size, delivered in [(65536, True), (65537, False), (300_000, False)]:
        prefix = '{"t":"signal","to":"%s","data":{"sdp":{"type":"offer","sdp":"' % b.id
        text = prefix + "x" * (size - len(prefix) - 4) + '"}}}'
        assert len(text.encode()) == size
        a.send_text(text)
        if delivered:
            m = b.expect(lambda m: m.get("t") == "signal", 5, f"{size}-byte signal")
            check(len(m["data"]["sdp"]["sdp"]) == size - len(prefix) - 4, "payload changed")
        else:
            b.expect_silence(1.0, f"{size}-byte message dropped")
    a.send_text('{"t":"ping"}')
    check(a.expect(lambda m: True) == {"t": "pong"}, "sender still connected after oversize message")


def t_fragmented_message():
    r = room()
    a = join(r, "web")
    b = join(r, "app")
    a.expect(lambda m: m.get("t") == "join")
    text = json.dumps({"t": "signal", "to": b.id, "data": offer("frag-" + "y" * 300)})
    data = text.encode()
    third = len(data) // 3
    a.send_frame(0x1, data[:third], fin=False)
    a.send_frame(0x9, b"mid")  # control frame between fragments
    a.send_frame(0x0, data[third:2 * third], fin=False)
    a.send_frame(0x0, data[2 * third:], fin=True)
    check(a.recv(3) == ("pong", b"mid"), "pong for the ping between fragments")
    m = b.expect(lambda m: m.get("t") == "signal", what="reassembled signal")
    check(m["data"] == offer("frag-" + "y" * 300), "reassembled payload differs")


def t_auto_room():
    a = join("auto", "web", "auto-web-" + secrets.token_hex(3))
    b = join("auto", "app", "auto-app-" + secrets.token_hex(3), "iphone")
    check(any(p["id"] == a.id for p in b.welcome["peers"]), f"b should see a in auto room: {b.welcome}")
    a.expect(lambda m: m.get("t") == "join" and m["peer"]["id"] == b.id, what="join in auto room")
    p = join(room(), "web")
    check(p.welcome["peers"] == [], "private room should not see auto-room peers")
    a.close()
    b.expect(lambda m: m.get("t") == "leave" and m["id"] == a.id, what="leave in auto room")
    b.close()


def t_abrupt_disconnect():
    r = room()
    a = join(r, "web")
    b = join(r, "app")
    a.expect(lambda m: m.get("t") == "join")
    b.drop()
    a.expect(lambda m: m == {"t": "leave", "id": b.id}, 10, "leave after dropped connection")
    a.expect_silence(1.5, "a single leave")


def expect_refusal(ws, reason):
    """The relay accepted the socket only to say `reason` and close it with 1008."""
    m = ws.recv_json(3)
    check(m == {"t": "error", "message": reason}, f"{reason} message: {m}")
    try:
        ws.recv(3)
        raise Fail(f"expected a close after {reason}")
    except Closed as c:
        check(c.code == 1008 and c.reason == reason, f"close {c.code} {c.reason!r}, want 1008 {reason!r}")


def t_peer_cap(cap, per_ip):
    r = room()
    # Spread the peers over addresses so the per-address cap doesn't fire before the room cap.
    peers = [join(r, "web" if i % 2 else "app", ip=f"198.51.100.{i // per_ip}") for i in range(cap)]
    for p in peers:  # read the joins that piled up
        while p.recv_json(0.2) is not None:
            pass
    status, _, extra = WS.open(URL, {"room": r, "role": "web"}, headers=as_ip("198.51.100.250"))
    check(status == 101, f"over-cap upgrade -> {status}")
    OPEN.append(extra)
    expect_refusal(extra, "room full")
    peers[0].expect_silence(0.5, "no join for the refused peer")
    peers[-1].close()
    peers[0].expect(lambda m: m.get("t") == "leave", what="leave")
    again = join(r, "web", ip="198.51.100.250")
    check(len(again.welcome["peers"]) == cap - 1, "room should accept a peer again after one left")


def t_per_ip_cap(per_ip):
    r = room()
    ip, other_ip = "203.0.113.4", "203.0.113.5"
    peers = [join(r, "web" if i % 2 else "app", ip=ip) for i in range(per_ip)]
    for p in peers:  # read the joins that piled up
        while p.recv_json(0.2) is not None:
            pass
    status, _, extra = WS.open(URL, {"room": r, "role": "app"}, headers=as_ip(ip))
    check(status == 101, f"over-cap upgrade -> {status}")
    OPEN.append(extra)
    expect_refusal(extra, "too many connections")
    peers[0].expect_silence(0.5, "no join for the refused peer")
    if local_relay():
        other = join(r, "web", ip=other_ip)
        check(len(other.welcome["peers"]) == per_ip, f"another address should still get in: {other.welcome}")
        peers[0].expect(lambda m: m.get("t") == "join" and m["peer"]["id"] == other.id, what="join from the other address")
        # The cap is per room: the same address starts fresh in another room.
        elsewhere = join(room(), "web", ip=ip)
        check(elsewhere.welcome["peers"] == [], "the cap must not leak across rooms")
    peers[-1].close()
    peers[0].expect(lambda m: m == {"t": "leave", "id": peers[-1].id}, what="leave")
    again = join(r, "web", ip=ip)
    check(any(p["id"] == peers[0].id for p in again.welcome["peers"]), "the address should get its slot back after one left")


def t_connection_rate(rate):
    ip, other_ip = "203.0.113.9", "203.0.113.10"
    for i in range(rate):
        s = status_of({"room": room(), "role": "web"}, ip=ip)
        check(s == 101, f"connection {i + 1} of {rate} -> {s}")
    status, body, ws = WS.open(URL, {"room": room(), "role": "web"}, headers=as_ip(ip))
    check(status == 429 and ws is None, f"connection {rate + 1} -> {status} {body.strip()!r}")
    check(status_of({"room": room(), "role": "web"}, ip=other_ip) == 101, "another address should still connect")
    s = status_of({"room": "nope", "role": "web"}, ip=ip)
    check(s == 400, f"bad parameters are refused before the budget is checked -> {s}")
    if local_relay():
        # IPv6: every address in one /64 is one host, and shares the budget.
        for i in range(rate):
            s = status_of({"room": room(), "role": "web"}, ip=f"2001:db8:5:6::{i + 1:x}")
            check(s == 101, f"IPv6 connection {i + 1} of {rate} -> {s}")
        status, body, ws = WS.open(URL, {"room": room(), "role": "web"}, headers=as_ip("2001:db8:5:6:abcd:ef01::9"))
        check(status == 429 and ws is None, f"another address in the same /64 -> {status} {body.strip()!r}")
        check(status_of({"room": room(), "role": "web"}, ip="2001:db8:5:7::1") == 101, "another /64 should still connect")


def t_ipv6_prefix_cap(per_ip):
    # Two IPv6 addresses in one /64 count as one address; another /64 is another address.
    r = room()
    peers = [join(r, "web" if i % 2 else "app", ip=f"2001:db8:9:1::{i + 1:x}") for i in range(per_ip)]
    for p in peers:  # read the joins that piled up
        while p.recv_json(0.2) is not None:
            pass
    status, _, extra = WS.open(URL, {"room": r, "role": "app"}, headers=as_ip("2001:db8:9:1:dead:beef::1"))
    check(status == 101, f"over-cap upgrade -> {status}")
    OPEN.append(extra)
    expect_refusal(extra, "too many connections")
    other = join(r, "web", ip="2001:db8:9:2::1")
    check(len(other.welcome["peers"]) == per_ip, f"another /64 should still get in: {other.welcome}")


def t_auto_room_not_capped_per_address(per_ip):
    # An IPv4 auto room is one public address by construction, so it takes more than per_ip
    # sockets from that address; only the room cap applies.
    tag = secrets.token_hex(3)
    peers = [join("auto", "web" if i % 2 else "app", f"auto-{tag}-{i}", ip="198.51.100.77") for i in range(per_ip + 2)]
    for p in peers:
        while p.recv_json(0.2) is not None:
            pass
    ids = {p.id for p in peers}
    last = join("auto", "web", f"auto-{tag}-last", ip="198.51.100.77")
    seen = {p["id"] for p in last.welcome["peers"]}
    check(ids <= seen, f"every socket from the one address should be in the auto room: missing {ids - seen}")


def t_extra_origin(extra):
    check(status_of({"room": room(), "role": "web"}, origin=extra) == 101, f"EXTRA_ORIGINS entry {extra} refused")
    check(status_of({"room": room(), "role": "web"}, origin="") == 403, "an empty Origin must not pass via EXTRA_ORIGINS")


def t_stale_peer(stale_after):
    r = room()
    a = join(r, "web")
    ghost = join(r, "app")
    a.expect(lambda m: m.get("t") == "join")
    deadline = time.monotonic() + stale_after + 2
    while time.monotonic() < deadline:  # a keeps pinging; the ghost stays silent
        a.send_text('{"t":"ping"}')
        a.expect(lambda m: m == {"t": "pong"}, what="pong")
        time.sleep(min(stale_after / 4, 20.0, max(0.0, deadline - time.monotonic())))
    c = join(r, "web")
    check([p["id"] for p in c.welcome["peers"]] == [a.id], f"ghost still listed: {c.welcome}")
    a.expect(lambda m: m == {"t": "leave", "id": ghost.id}, what="leave for the ghost")


def main():
    global URL
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", default=URL)
    ap.add_argument("--cap", type=int, help="the relay's peer cap; runs the room-full case")
    ap.add_argument("--per-ip", type=int, default=4, help="the relay's per-address cap (default 4)")
    ap.add_argument("--stale-after", type=float, help="the relay's stale timeout; runs the ghost-peer case")
    ap.add_argument("--rate", type=int, help="the relay's new connections a minute per address; runs the budget case")
    ap.add_argument("--extra-origin", help="an origin the relay was started with in EXTRA_ORIGINS; runs that case")
    ap.add_argument("-k", help="only run cases whose name contains this")
    args = ap.parse_args()
    URL = args.url
    if args.rate and not args.k:
        print("--rate: running only the connection_rate case (the others would use up the budget)")
        args.k = "connection_rate"

    optional = ("t_signal_roles", "t_peer_cap", "t_per_ip_cap", "t_ipv6_prefix_cap", "t_auto_room_not_capped_per_address",
                "t_stale_peer", "t_connection_rate", "t_extra_origin")
    cases = [(n[2:], f) for n, f in globals().items() if n.startswith("t_") and n not in optional]
    # Four peers share one room here, so a room cap under 4 would fill the room first.
    cases.append(("signal_roles", t_signal_roles if not args.cap or args.cap >= 4 else None))
    cases.append(("peer_cap", (lambda: t_peer_cap(args.cap, args.per_ip)) if args.cap else None))
    # With a room cap at or under the per-address cap, "room full" would fire first.
    room_for_cap = not args.cap or args.cap > args.per_ip
    cases.append(("per_ip_cap", (lambda: t_per_ip_cap(args.per_ip)) if room_for_cap else None))
    # These act as several addresses, which only a local relay lets a client do.
    local = urlsplit(args.url).scheme == "ws"
    cases.append(("ipv6_prefix_cap", (lambda: t_ipv6_prefix_cap(args.per_ip)) if room_for_cap and local else None))
    cases.append(("auto_room_not_capped_per_address",
                  (lambda: t_auto_room_not_capped_per_address(args.per_ip)) if local and (not args.cap or args.cap > args.per_ip + 3) else None))
    cases.append(("stale_peer", (lambda: t_stale_peer(args.stale_after)) if args.stale_after else None))
    cases.append(("connection_rate", (lambda: t_connection_rate(args.rate)) if args.rate else None))
    cases.append(("extra_origin", (lambda: t_extra_origin(args.extra_origin)) if args.extra_origin else None))
    print(f"Testing {URL}")
    failed = 0
    for name, fn in cases:
        if args.k and args.k not in name:
            continue
        if fn is None:
            print(f"SKIP {name}")
            continue
        try:
            fn()
            print(f"PASS {name}")
        except Exception as e:
            failed += 1
            print(f"FAIL {name}: {type(e).__name__}: {e}")
        finally:
            for ws in OPEN:
                ws.drop()
            OPEN.clear()
            time.sleep(0.1)
    print("all passed" if not failed else f"{failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

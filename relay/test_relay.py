#!/usr/bin/env python3
"""Black-box tests for the Rescriva Share relay (worker.js under `wrangler dev`, or dev_relay.py).

    python3 test_relay.py [ws://127.0.0.1:8787/ws] [--cap N] [--stale-after S]

Python 3.9+, standard library only. --cap N runs the "room full" case against a relay whose
cap is N (start dev_relay.py with --max-peers N to keep it small). --stale-after S runs the
ghost-peer case against a relay that drops peers silent for S seconds (dev_relay.py --stale-after S).
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
    def open(url, params=None, origin=None, timeout=5.0):
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


def join(room_id, role="web", name=None, device="computer", origin=None):
    params = {"room": room_id, "role": role}
    if name is not None:
        params["name"] = name
    if device is not None:
        params["device"] = device
    status, body, ws = WS.open(URL, params, origin)
    if ws is None:
        raise Fail(f"expected 101 for {params}, got {status} {body.strip()!r}")
    OPEN.append(ws)
    welcome = ws.expect(lambda m: m.get("t") == "welcome", what="welcome")
    if not ID_RE.fullmatch(welcome.get("id", "")):
        raise Fail(f"bad peer id {welcome.get('id')!r}")
    ws.id = welcome["id"]
    ws.welcome = welcome
    return ws


def status_of(params, origin=None):
    status, _, ws = WS.open(URL, params, origin)
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
    s, body, h = http_get("/health")
    check(s == 200 and body.strip() == "ok", f"GET /health -> {s} {body!r}")
    s, body, h = http_get("/health", origin="http://localhost:3000")
    check(h.get("access-control-allow-origin") == "http://localhost:3000", f"/health CORS header {h}")
    s, _, _ = http_get("/nope")
    check(s == 404, f"GET /nope -> {s}")
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
    for o in ["https://evil.example", "null", "https://share.rescriva.com.evil.com", "http://share.rescriva.com",
              "https://share.rescriva.com:8443", "http://localhost.evil.com", "https://localhost:3000",
              "http://127.0.0.2:8000", "http://localhost:abc"]:
        s = status_of({"room": room(), "role": "web"}, origin=o)
        check(s == 403, f"Origin {o} -> {s}")
    s, _, _ = http_get("/health", origin="https://evil.example")
    check(s == 403, f"/health with bad Origin -> {s}")


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


def t_peer_cap(cap):
    r = room()
    peers = [join(r, "web" if i % 2 else "app") for i in range(cap)]
    for p in peers:  # read the joins that piled up
        while p.recv_json(0.2) is not None:
            pass
    status, _, extra = WS.open(URL, {"room": r, "role": "web"})
    check(status == 101, f"over-cap upgrade -> {status}")
    OPEN.append(extra)
    m = extra.recv_json(3)
    check(m == {"t": "error", "message": "room full"}, f"room full message: {m}")
    try:
        extra.recv(3)
        raise Fail("expected a close after room full")
    except Closed as c:
        check(c.code == 1008, f"close code {c.code}")
    peers[0].expect_silence(0.5, "no join for the refused peer")
    peers[-1].close()
    peers[0].expect(lambda m: m.get("t") == "leave", what="leave")
    again = join(r, "web")
    check(len(again.welcome["peers"]) == cap - 1, "room should accept a peer again after one left")


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
    ap.add_argument("--stale-after", type=float, help="the relay's stale timeout; runs the ghost-peer case")
    ap.add_argument("-k", help="only run cases whose name contains this")
    args = ap.parse_args()
    URL = args.url

    cases = [(n[2:], f) for n, f in globals().items() if n.startswith("t_") and n not in ("t_peer_cap", "t_stale_peer")]
    cases.append(("peer_cap", (lambda: t_peer_cap(args.cap)) if args.cap else None))
    cases.append(("stale_peer", (lambda: t_stale_peer(args.stale_after)) if args.stale_after else None))
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

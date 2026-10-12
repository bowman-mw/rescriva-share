# Rescriva Share protocol (v1)

Rescriva Share moves files between the Rescriva app (iPhone, iPad, Mac) and a web page
(`https://share.rescriva.com`, served by GitHub Pages). Files always travel over a direct,
encrypted WebRTC data channel between the two devices. Nothing else ever sees them.

Before a WebRTC connection can open, the two ends must swap a short "hello" (an SDP offer and an
SDP answer). A static web page has no server to carry it, so there are two ways to do that:

| Path | How the hello travels | When it's used |
|---|---|---|
| **Relay** | Through a tiny WebSocket relay (`relay/`, a Cloudflare Worker you own). The relay sees only connection set-up text, never files. | Normally. Devices on the same network find each other on their own. |
| **No relay** | Inside a QR code the app scans on the web page. If the computer can't be reached that way, the app shows a short code to type on the page. | When the relay can't be reached (no internet, blocked at work), or as a manual pairing. |

## 1. Shared building blocks

All strings are UTF-8. `base64url` is RFC 4648 §5 **without padding**; `base64` is the standard
alphabet **without padding**.

### 1.1 Secrets and derivations

A *secret* is 16 random bytes. It is shared only through a QR code or link fragment (`#…`), never
through the relay.

```
roomId(secret)  = base64url( SHA-256( "rescriva-share/room/v1" || secret ) )[0..<22]
h               = HMAC-SHA256( key: secret, data: "rescriva-share/ice/v1" )
iceUfrag(secret)= base64( h[0..<6] )      // 8 characters
icePwd(secret)  = base64( h[6..<24] )     // 24 characters
proof(secret, role, fpOffer, fpAnswer)
                = base64url( HMAC-SHA256( key: secret,
                    data: "rescriva-share/proof/v1|" + role + "|" + fpOffer + "|" + fpAnswer ) )
```

- `role` is `"web"` or `"app"`: the role of the side **sending** the proof.
- `fpOffer` / `fpAnswer` are the SHA-256 DTLS fingerprints from the offer and answer SDPs
  (`a=fingerprint:sha-256 AB:CD:…`), as upper-case hex pairs joined by `:`. Each side uses the
  descriptions it actually applied, so a relay that swapped fingerprints can't produce a valid proof.

Test vectors (secret = bytes `01 02 … 10`, base64url `AQIDBAUGBwgJCgsMDQ4PEA`):

| Value | Result |
|---|---|
| `roomId` | `8o2MFZXsZ_-zenK5lVG13R` |
| `iceUfrag` / `icePwd` | `JtdLkDQk` / `ZQTXo83Ch4FIONXev/7A54ci` |
| `proof(web, "AA:"×31+"AA", "BB:"×31+"BB")` | `EpXFwY-xYQ-Pv7kuSqaHTPV91p-Nb4n2AtMQU9ZLUGk` |
| `proof(app, same)` | `NuogRNgcibvc8iD5AZFpJUq_MdvVGuhpw622Z3WAd3M` |

### 1.2 Trust: key or PIN

A web page that holds the session's secret (because it was opened from the app's QR code, or
because the app scanned the page's QR code) is **trusted**: every shared document is unlocked
for it. It proves this with `proof` in its `hello`. Every other page (found through the relay's
same-network room) sees document names but must type each document's **PIN** to download it.

### 1.3 PINs

Each shared document gets its own 6-digit PIN when the Share screen opens. PINs are unique within
the session and are replaced when the Share screen closes or the app leaves the foreground.
Five wrong tries on a document replaces that document's PIN and refuses tries on it for
30 s, doubling each time it happens again. The app shows the new PIN.

## 2. Relay

`wss://relay.rescriva.com/ws?room=<room>&role=<app|web>&name=<name>&device=<device>`

- `room`: `auto` (the relay puts you in a room for your public network: the IPv4 address,
  or the /64 of an IPv6 address), or a 22-character `roomId(secret)`.
- `role`: `app` or `web`. `name`: up to 64 characters. `device`: `iphone`, `ipad`, `mac`, `phone`,
  `tablet` or `computer`.

Server → client (JSON text frames):

```
{"t":"welcome","id":"<yourId>","peers":[{"id","role","name","device"}, …]}
{"t":"join","peer":{"id","role","name","device"}}
{"t":"leave","id":"<peerId>"}
{"t":"signal","from":"<peerId>","data":{…}}
{"t":"pong"}
{"t":"error","message":"…"}
```

Client → server:

```
{"t":"signal","to":"<peerId>","data":{…}}
{"t":"ping"}                         // every 25 s
```

Signal `data` is one of:

```
{"sdp":{"type":"offer"|"answer","sdp":"…"}}
{"candidate":{"candidate":"…","sdpMid":"0","sdpMLineIndex":0}}
```

**The web page always makes the offer**: it connects to every `app` peer in its room (from
`welcome` and later `join`s). The app answers. Web pages never connect to each other; apps never
connect to each other. Limits: 32 peers a room, 64 KB a message. Origins other than
`https://share.rescriva.com` and `http://localhost:*` / `http://127.0.0.1:*` are refused; native
clients send no Origin.

## 3. No-relay pairing (the page's QR code)

The page makes an RTCPeerConnection with no ICE servers and one negotiated data channel (§4),
creates an offer, waits for ICE gathering (≤ 3 s), and applies a **made-up answer** as if from the app:

```
v=0
o=- 1 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE <mid>
a=msid-semantic: WMS
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=ice-ufrag:<iceUfrag(secret)>
a=ice-pwd:<icePwd(secret)>
a=ice-options:trickle
a=fingerprint:sha-256 <APP_FIXED_FINGERPRINT>
a=setup:active
a=mid:<mid>
a=sctp-port:5000
a=max-message-size:262144
```

`APP_FIXED_FINGERPRINT` belongs to a certificate built into the app
(`C8:7F:82:09:B8:EF:F6:FB:92:37:13:91:BD:28:85:F1:50:E7:03:8D:3E:BB:DA:99:2A:78:3C:9F:DB:E1:95:CB`).
It is public on purpose. It doesn't stop anyone pretending to be the app, so the app's
`proof` does (§4). The app checks the page's real fingerprint, which comes in the QR code.

The page shows this QR code:

```
openscanner://share?p=<base64url(payload)>
```

`payload` is binary:

| Bytes | Field |
|---|---|
| 1 | version = 1 |
| 16 | secret |
| 1 + n | ICE ufrag length, then ASCII |
| 1 + n | ICE pwd length, then ASCII |
| 32 | SHA-256 fingerprint of the page's certificate |
| 1 + n | mid length, then ASCII |
| 1 | candidate count (≤ 8; UDP only) |
| per candidate: 1 | kind: `4` IPv4, `6` IPv6, `109` (`m`) mDNS name `<uuid>.local` |
| 4 / 16 / 16 | address; for mDNS the UUID's 16 bytes |
| 2 | port, big-endian |

The page also joins the relay room `roomId(secret)` (as `web`) when the relay is reachable, so
an app that scanned the code can connect either way. The first to open wins.

The app, after scanning:

1. Rebuilds the page's offer from the payload (same shape as the answer above, with the page's
   ufrag, pwd, fingerprint, mid, `a=setup:actpass` and one `a=candidate` line per candidate),
   applies it, creates an answer, **replaces its `a=ice-ufrag`/`a=ice-pwd` with
   `iceUfrag(secret)`/`icePwd(secret)`**, and applies that. Its RTCConfiguration uses the built-in
   certificate.
2. ICE then checks run from the app to the page's candidates; the page learns the app's address from
   them.
3. If the data channel hasn't opened after 4 s, the app shows a **connection code** for its
   best local IPv4 candidate, so the page can start the checks itself (some laptops refuse
   incoming connections until they've sent something).

### 3.1 Connection code

Crockford base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`; on input `O`→`0`, `I`/`L`→`1`, ignore
`-` and spaces, any case).

| tag | address | payload bits | data chars |
|---|---|---|---|
| 0 | `172.20.10.1` (iPhone Personal Hotspot) | port (16) | 4 |
| 1 | `192.168.a.b` | a, b, port (32) | 7 |
| 2 | `10.a.b.c` | a, b, c, port (40) | 9 |
| 3 | any other IPv4 | address, port (48) | 10 |

`value = tag << (5·n − 2) | payload` (payload in the low bits, big-endian byte order inside it),
written as `n` base32 digits, most significant first, then one check digit
`Σ (i+1)·digit[i] mod 32` over the `n` data digits. Shown in groups of four (`80JB-N1HG`).

| Address | Code |
|---|---|
| 172.20.10.1:52453 | `1K75G` |
| 192.168.1.37:54321 | `80JBN1HG` |
| 10.0.12.200:61000 | `G006CHVJ8Z` |
| 172.16.5.9:50000 | `XC202GKGTGM` |

The page adds `candidate:1 1 udp 2122260223 <ip> <port> typ host` (sdpMid = the offer's mid) to
its no-relay connection.

## 4. Data channel

One **negotiated** data channel, `id: 0`, label `rescriva`, ordered and reliable, on every
connection (relay or not). Text frames are JSON; binary frames are file bytes (≤ 64 KiB each).

Both sides send `hello` as soon as the channel opens:

```
{"t":"hello","v":1,"role":"web"|"app","name":"Chrome on Mac","device":"computer","proof":"…"?}
```

The app's `hello` also carries `"session"`, 8 random bytes in base64url that are new each time the
Share screen opens. A page that reaches the same app two ways (the same-network room and a
pairing) keeps one connection per session and prefers the trusted one.

`proof` is present when the sender holds a secret for this connection (§1.1). The receiver
checks it. A wrong proof means the receiver sends `{"t":"bye"}` and closes. The page does nothing
until the app's `hello` arrives. The app sends nothing but its `hello` until the page's `hello`
arrives.

App → page:

```
{"t":"docs","docs":[{"id","name","size","type","unlocked":bool}, …]}   // whenever the list or a lock changes; [] when sharing ends
{"t":"unlocked","id"}
{"t":"denied","id","reason":"wrong"|"cooldown"|"locked"|"gone","retryIn":seconds?,"left":tries?}
{"t":"file","id","xfer","name","size","type"}  // then binary chunks, then {"t":"end","xfer"}
{"t":"accept","xfer"} | {"t":"decline","xfer","reason"?} | {"t":"saved","xfer","ok":bool}
```

Page → app:

```
{"t":"unlock","id","pin"}
{"t":"get","id"}                               // only for unlocked documents
{"t":"send","xfer","name","size","type"}       // asks to send a file; wait for accept
                                               // after accept: binary chunks, then {"t":"end","xfer"}
```

Either side: `{"t":"cancel","xfer"}`, `{"t":"bye"}`.

One transfer per direction at a time. Binary frames from the app always belong to the current
`file`, and binary frames from the page always belong to the current accepted `send`. Senders
keep `bufferedAmount` under 1 MiB. The app accepts PDFs and images (`application/pdf`, `image/*`)
and asks its user before every `send`.

When the app's Share screen closes or the app leaves the foreground, it sends `docs: []` and
`bye`, then closes every connection and leaves the relay. The page removes that device.

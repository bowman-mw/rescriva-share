# Rescriva Share protocol (v1)

Rescriva Share moves files between the Rescriva app (iPhone, iPad, Mac) and a web page
(`https://share.rescriva.com`, served by GitHub Pages). Files always travel over a direct,
encrypted WebRTC data channel between the two devices. The relay carries only the text that
sets a connection up, never a file; what that leaves it able to do is in §1.2.

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

A connection with no secret has no `proof`. It gets a **check number** instead, from the same
two fingerprints, which both ends show (§1.2):

```
checkNumber(fpOffer, fpAnswer)
                = SHA-256( "rescriva-share/check/v1|" + fpOffer + "|" + fpAnswer )
                  [0..<8] as a big-endian uint64, mod 1 000 000 000
```

- Shown as nine digits, zero-padded, in three groups of three: `424 561 948`.
- Nine digits, not six, because the number has no commitment in it: the side that answers
  (the app, or anything playing it) sees `fpOffer` before it picks its own certificate, and
  could try certificates until the number came out as it wanted. A million tries fits a
  connection's window on a laptop; a billion doesn't.

Test vectors (secret = bytes `01 02 … 10`, base64url `AQIDBAUGBwgJCgsMDQ4PEA`):

| Value | Result |
|---|---|
| `roomId` | `8o2MFZXsZ_-zenK5lVG13R` |
| `iceUfrag` / `icePwd` | `JtdLkDQk` / `ZQTXo83Ch4FIONXev/7A54ci` |
| `proof(web, "AA:"×31+"AA", "BB:"×31+"BB")` | `EpXFwY-xYQ-Pv7kuSqaHTPV91p-Nb4n2AtMQU9ZLUGk` |
| `proof(app, same)` | `NuogRNgcibvc8iD5AZFpJUq_MdvVGuhpw622Z3WAd3M` |
| `checkNumber("AA:"×31+"AA", "BB:"×31+"BB")` | `424561948` |
| `checkNumber`, fingerprints swapped | `576993692` |

### 1.2 Trust: key or PIN

A web page that holds the session's secret (because it was opened from the app's QR code, or
because the app scanned the page's QR code) is **trusted**: every shared document is unlocked
for it. It proves this with `proof` in its `hello`. Every other page (found through the relay's
same-network room) sees document names but must type each document's **PIN** to download it.

The PIN proves the page to the app, not the app to the page. Anything that joins the
same-network room as `app` can call itself "iPhone" and list the same document names, and a
PIN typed into it would unlock the real device for it. So on a connection with no secret both
ends show the connection's **check number** (§1.1): the app next to the connected computer, the
page on the device's card. Matching numbers mean the two ends almost certainly see the same
connection; a mismatch means they don't. The person compares them before typing a PIN. The
number is a check for a person to make, not an authentication: a page that never shows it to
anyone is no safer, and a determined attacker on the same network, who can connect to the
real app as a page and to the real page as an app, can still try certificates until a short
number matched (nine digits make that take a billion tries, which is why it isn't six). With
such an attacker in the room, the app's "more than one computer" warning and the page's
second card for the same device are the signs to look for.

A session with no secret also trusts the relay. With no `proof` to check, a relay that swapped
fingerprints and put in its own candidates would sit between the two ends, reading document
names, the typed PIN and every file. The check number would not match then either, which is
the other reason to compare it. With a secret, `proof` binds the fingerprints each end applied,
so the relay can only pass messages or drop them.

The eventual fix for both is to replace `unlock {pin}` with a PAKE (SPAKE2 or CPace) keyed on
the PIN and bound to `fpOffer|fpAnswer`, so an impostor learns at most that one guess was wrong
and nothing it saw can be replayed. The check number is the interim.

### 1.3 PINs

Each shared document gets its own 6-digit PIN when the Share screen opens. PINs are unique within
the session and are replaced when the Share screen closes or the app leaves the foreground.
Wrong tries are counted per connection, so one page can't lock everyone out: five wrong from one
connection refuse that connection for 30 s (`denied` with `left: 0` and `retryIn`); other
connections carry on. Only when wrong tries across every connection reach 15, or three
connections have each been refused, is the document's PIN replaced and every connection refused
for 30 s, doubling each time it happens again up to 32 minutes. The app shows the new PIN.

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
connect to each other, and the relay enforces that: a `signal` is delivered only between a `web`
peer and an `app` peer; one addressed to a peer of the sender's own role is dropped without a
reply. Limits: 32 peers a room, 64 KB a message (bigger messages are dropped). Origins other than
`https://share.rescriva.com` and `http://localhost:*` / `http://127.0.0.1:*` are refused; native
clients send no Origin.

Refusals a client has to expect, and back off from rather than retry at once:

- **Room full.** The 33rd socket into a room is accepted only to be told
  `{"t":"error","message":"room full"}` and closed with code 1008 and that reason.
- **Too many connections.** In a pairing room (`roomId(secret)`), one public address may hold
  4 peers; the fifth is told `{"t":"error","message":"too many connections"}` and closed with
  code 1008 and that reason, the same shape as "room full". A public address is an IPv4
  address, or for IPv6 the /64. The `auto` room has no per-address cap: an IPv4 auto room is one
  public address by construction, so only the 32-peer cap applies there.
- **Connection budget.** New connections are budgeted per public address (again an IPv4 address
  or an IPv6 /64): 20 a minute, plus an edge rule at the relay's host. Over that the WebSocket
  upgrade fails with HTTP 429 and `Retry-After: 60`; both clients keep their exponential
  back-off, so they recover by themselves.

`GET /` answers `Rescriva Share relay`; there is no `/health` (anything else is 404).

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
pairing) keeps one connection per session. But `session` goes to every page in the room in clear,
so to the page it's a hint, not an identity, and the only thing it ever decides is
trusted-over-untrusted: a connection whose `hello` carried a valid `proof` replaces an untrusted
one with the same `session` (that relay peer isn't dialed again until the trusted connection is
gone, or the relay says the peer left and came back). Two untrusted connections that claim one
`session` are both kept, each with its own check number: closing either would let whichever
connected first keep the other off the page, which is exactly what an impostor copying a
`session` would want.

`proof` is present when the sender holds a secret for this connection (§1.1). The receiver
checks it. A wrong proof means the receiver sends `{"t":"bye"}` and closes. The page does nothing
until the app's `hello` arrives. The app sends nothing but its `hello` until the page's `hello`
arrives.

App → page:

```
{"t":"docs","docs":[{"id","name","size","type","unlocked":bool}, …]}   // whenever the list or a lock changes; [] when sharing ends; at most 200 (the page ignores the rest)
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

The page saves a `file` under the name from its `docs` entry, never the `name` in `file`. The
name is cleaned first: path separators and control characters become `_`, bidi overrides and
isolates (U+202A–202E, U+2066–2069) are dropped, leading dots and spaces go (so nothing lands
as a hidden file), and it's clipped to 200 characters including any extension added. From a
connection with no secret it takes only `application/pdf`, the plain image types it knows
(`image/png`, `image/jpeg`, `image/heic`, `image/heif`, `image/gif`, `image/webp`,
`image/tiff`) and the app's own export formats
(`application/vnd.openxmlformats-officedocument.wordprocessingml.document` → `.docx`,
`application/vnd.openxmlformats-officedocument.presentationml.presentation` → `.pptx`,
`text/markdown` → `.md`, `text/plain` → `.txt`), saved under an extension that matches the
type (added when the name lacks it, so a "Scan.pdf.exe" sent as a PDF lands as
"Scan.pdf.exe.pdf"); any other type is refused on the page before `get` is sent, and a `file`
of another type is answered with `cancel`. From such a connection the size is the `docs`
entry's too: a `file` whose `size` differs from it, or is over what the app itself accepts
(1 GiB for a PDF, 128 MiB for anything else), is answered with `cancel`; and a `size` that
isn't a whole number of bytes is refused on every connection. Either side gives up on a
transfer with nothing moving for 30 s, and the page stops a download the moment more bytes
arrive than `size` said, with `cancel` both times.

When the app's Share screen closes or the app leaves the foreground, it sends `docs: []` and
`bye`, then closes every connection and leaves the relay. The page removes that device.

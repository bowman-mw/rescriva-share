# Rescriva Share relay

A tiny WebSocket relay that lets the Rescriva app and the share page swap their WebRTC
"hello" (PROTOCOL.md §2). It only passes small JSON set-up messages between devices in a room.
Files never go through it.

- `worker.js`, `wrangler.toml`: the Cloudflare Worker (one Durable Object per room).
- `dev_relay.py`: the same relay in plain Python, for testing with no Cloudflare account.
- `test_relay.py`: tests that run against either one.

## Deploy to Cloudflare (first time)

1. **Make a free account** at <https://dash.cloudflare.com/sign-up>. The free plan is enough,
   and no card is needed.
2. **Add the domain.** The relay answers only at `relay.rescriva.com` (`workers_dev = false` in
   `wrangler.toml`, so there is no second address on `workers.dev`). In the dashboard choose
   **Add a domain**, enter `rescriva.com`, pick the Free plan, and change the domain's
   nameservers at your registrar to the two that Cloudflare shows. Before you switch, check that
   Cloudflare copied your existing DNS records (for example the `share` CNAME that points at
   GitHub Pages, and any mail records).
3. **Install Node.js** (LTS) from <https://nodejs.org> so you have `npx`.
4. **Log in and deploy** from this folder:
   ```sh
   cd relay
   npx wrangler login     # opens the browser once to connect Wrangler to your account
   npx wrangler deploy
   ```
   The `routes` entry in `wrangler.toml` attaches `relay.rescriva.com` as a custom domain;
   Cloudflare creates the DNS record and the certificate. (Tested with Wrangler 4.142.0; the
   rate-limit binding needs 4.36 or later. To use exactly that version, run
   `npx wrangler@4.142.0 …`.) If you would rather do it by hand: **Workers & Pages** →
   `rescriva-share-relay` → **Settings** → **Domains & Routes** → **Add** → **Custom domain**.
5. **Set the room salt** before anyone uses the relay (see Settings):
   ```sh
   npx wrangler secret put ROOM_SALT    # paste a long random string, e.g. from: openssl rand -base64 32
   ```
6. **Check it:** `https://relay.rescriva.com/` should show `Rescriva Share relay`.
7. **Add the WAF rule** described under Abuse limits.

### Point the clients at it

The relay address is the `wss://` form of the address above, with `/ws` on the end, for example
`wss://relay.rescriva.com/ws`.

- Website: `assets/config.js`, constant `RELAY_URL`.
- App: `scanner/Share/NearbyShareConfig.swift`.

### Settings

- `ROOM_SALT` (**required before production**): mixed into the hash that turns a public IP
  address into a room name, so room names don't reveal addresses. The code falls back to a
  fixed string so local runs work, but with that default anyone can work out which room an
  address maps to. Set it once with `npx wrangler secret put ROOM_SALT`; it is a secret, not a
  `[vars]` entry. Changing it later only renames the automatic rooms, which matters only to
  sessions open at that moment.
- `EXTRA_ORIGINS` (optional): more web origins to allow, comma-separated (for example a staging
  site). Set it under `[vars]` in `wrangler.toml`. `https://share.rescriva.com` and any
  `http://localhost:<port>` or `http://127.0.0.1:<port>` are always allowed. Native apps send no
  `Origin` and are always allowed. Empty entries (an unset value, a trailing comma) are ignored,
  so an empty `Origin:` header is never allowed.

### Abuse limits

Each connection is one Worker request and one Durable Object request, so the relay bounds what
a single address can do:

- **32 peers a room, and 4 peers per address a pairing room** (`MAX_PEERS` and
  `MAX_PEERS_PER_IP` in `worker.js`). An address is Cloudflare's `CF-Connecting-IP`, which a
  client can't forge: an IPv4 address, or for IPv6 the /64 (a host can give itself any address
  in its /64, so the prefix is what counts as one host). The fifth socket from one address into
  a pairing room is accepted only to be told `{"t":"error","message":"too many connections"}`
  and closed with code 1008 and that reason (a full room says `room full` the same way). A
  device holds one socket per room, so four covers a phone, a tablet and a couple of browsers
  behind one NAT; raise the constant if that proves tight. Same-network (`auto`) rooms aren't
  capped per address: an IPv4 auto room *is* one public address, so the cap would have been the
  room's real limit (five devices behind one office NAT would have failed), and whoever shares
  that address is on the same network anyway. Only the 32-peer cap applies there.
- **20 new connections a minute per address** (again an IPv4 address or an IPv6 /64), through
  the Workers rate-limiting binding `WS_LIMIT` (`[[ratelimits]]` in `wrangler.toml`). Above
  that the upgrade is refused with HTTP 429 and `Retry-After: 60`. Both clients already
  reconnect with exponential back-off, so they recover by themselves. The count is per
  Cloudflare location and approximate (Cloudflare describes the binding as permissive and
  eventually consistent), so treat it as a stop for loops, not a meter. The Worker skips the
  check when the binding is absent (`wrangler dev` with the table removed, or `dev_relay.py`,
  which has `--connections-per-minute` to turn it on) and lets the connection through if the
  limiter itself errors.
- **One entry point:** `workers_dev = false`, so the Worker answers at `relay.rescriva.com`
  only.
- **Signals pass web ↔ app only.** A `signal` addressed to a peer with the sender's own role is
  dropped without a reply, as are messages over 64 KB.

**Belt and braces: a WAF rate-limiting rule.** It runs at Cloudflare's edge before the Worker,
so a flood never reaches the Worker or the Durable Object and never counts against the daily
quota. The free plan includes one rule, counting by IP over a 10-second window with a 10-second
block. In the dashboard: `rescriva.com` → **Security** → **WAF** → **Rate limiting rules** →
**Create rule**:

- Name: `relay ws`
- When incoming requests match: field **URI Path**, operator **equals**, value `/ws`
  (the share page on `share.rescriva.com` has no `/ws`, so only the relay is affected).
- With the same characteristics: **IP** (if the plan offers it, choose the option that counts
  IPv6 by /64, so a host can't dodge the rule by rotating addresses). Period: **10 seconds**.
  Requests: **10**.
- Action: **Block**. Duration: **10 seconds**.

A real page or phone opens a handful of sockets at once and then nothing, so it never comes
near 10 in 10 seconds; a script in a loop does, and is blocked at the edge for 10 seconds at a
time. On a paid plan prefer a longer window and the expression
`http.host eq "relay.rescriva.com" and http.request.uri.path eq "/ws"`.

### Free plan limits

The free plan allows 100,000 Worker requests a day, and its Durable Objects get 100,000 requests
and 13,000 GB-s of run time a day, reset at 00:00 UTC. Each connection is one request, incoming
messages count 20 to 1, and the 25-second `ping`s are answered without waking the room, so idle
connections cost almost nothing. If a limit is reached, new connections fail until the reset;
nothing is charged. The limits above keep one misbehaving address from getting there.

## Run it locally

No Cloudflare account and no installs needed, just the Python 3 that comes with macOS:

```sh
python3 dev_relay.py                 # ws://127.0.0.1:8787/ws
python3 test_relay.py                # in another terminal
```

Set `RELAY_URL` (and the app's setting) to `ws://127.0.0.1:8787/ws` while testing. The dev
relay puts every `room=auto` client in one room. Use `--host 0.0.0.0` to reach it from a phone
on the same Wi-Fi (then use the Mac's LAN address). It logs joins, leaves, refusals and the type
of each forwarded signal, never their contents or addresses.

The per-address checks need several addresses, so the dev relay takes a client's
`CF-Connecting-IP` header at its word and the tests send one (the Worker reads the same header,
so under `npx wrangler dev` this works as long as Wrangler passes it through). Never expose the
dev relay beyond your own network. The default run covers the per-address cap (4) in a pairing
room, that two IPv6 addresses in one /64 share it, and that an auto room takes more than four
sockets from one address. To test the "room full" and idle-peer paths quickly, lower the limits
and tell the tests:

```sh
python3 dev_relay.py --max-peers 6 --stale-after 3
python3 test_relay.py --cap 6 --stale-after 3
```

(`--cap` at or under the per-address cap skips the per-address case, since "room full" would
fire first.) The connection budget is tested on its own, because the rest of the suite would
use it up:

```sh
python3 dev_relay.py --connections-per-minute 10
python3 test_relay.py --rate 10
```

To check an `EXTRA_ORIGINS` entry, including that a trailing comma admits nothing:

```sh
EXTRA_ORIGINS="https://staging.example," python3 dev_relay.py
python3 test_relay.py --extra-origin https://staging.example
```

To run the real Worker on your Mac (no login needed): `npx wrangler dev`, then
`python3 test_relay.py`. The tests also take a deployed address, for example
`python3 test_relay.py wss://relay.rescriva.com/ws -k signal`, but run a few cases at a time:
the whole suite opens far more than 20 connections a minute and the deployed relay would start
answering 429.

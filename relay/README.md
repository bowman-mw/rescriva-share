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
2. **Choose an address.**
   - Easiest: use the free `workers.dev` address Cloudflare gives you. Nothing else to set up.
   - For `relay.rescriva.com`: in the dashboard choose **Add a domain**, enter `rescriva.com`,
     pick the Free plan, and change the domain's nameservers at your registrar to the two that
     Cloudflare shows. Before you switch, check that Cloudflare copied your existing DNS records
     (for example the `share` CNAME that points at GitHub Pages, and any mail records).
3. **Install Node.js** (LTS) from <https://nodejs.org> so you have `npx`.
4. **Log in and deploy** from this folder:
   ```sh
   cd relay
   npx wrangler login     # opens the browser once to connect Wrangler to your account
   npx wrangler deploy
   ```
   The first deploy may ask you to pick a `workers.dev` subdomain. It prints the address,
   for example `https://rescriva-share-relay.<you>.workers.dev`. (Tested with Wrangler 4.142.0.
   To use exactly that version, run `npx wrangler@4.142.0 …`.)
5. **Attach the custom domain** (only if you did the domain step): **Workers & Pages** →
   `rescriva-share-relay` → **Settings** → **Domains & Routes** → **Add** → **Custom domain**
   → `relay.rescriva.com`. Cloudflare creates the DNS record and certificate for you. (You can
   instead uncomment the `routes` lines in `wrangler.toml` and deploy again.)
6. **Check it:** `https://relay.rescriva.com/health` (or your `workers.dev` address) should
   show `ok`.

### Point the clients at it

The relay address is the `wss://` form of the address above, with `/ws` on the end, for example
`wss://relay.rescriva.com/ws`.

- Website: `assets/config.js`, constant `RELAY_URL`.
- App: `scanner/Share/NearbyShareConfig.swift`.

### Optional settings

- `EXTRA_ORIGINS`: more web origins to allow, comma-separated (for example a staging site).
  Set it under `[vars]` in `wrangler.toml`. `https://share.rescriva.com` and any
  `http://localhost:<port>` or `http://127.0.0.1:<port>` are always allowed. Native apps send no
  `Origin` and are always allowed.
- `ROOM_SALT`: mixed into the hash that turns a public IP address into a room name, so the room
  names don't reveal addresses. Set it with `npx wrangler secret put ROOM_SALT`.

### Free plan limits

The free plan allows 100,000 Worker requests a day, and its Durable Objects get 100,000 requests
and 13,000 GB-s of run time a day, reset at 00:00 UTC. Each connection is one request, incoming
messages count 20 to 1, and the 25-second `ping`s are answered without waking the room, so idle
connections cost almost nothing. If a limit is reached, new connections fail until the reset;
nothing is charged.

## Run it locally

No Cloudflare account and no installs needed, just the Python 3 that comes with macOS:

```sh
python3 dev_relay.py                 # ws://127.0.0.1:8787/ws
python3 test_relay.py                # in another terminal
```

Set `RELAY_URL` (and the app's setting) to `ws://127.0.0.1:8787/ws` while testing. The dev
relay puts every `room=auto` client in one room. Use `--host 0.0.0.0` to reach it from a phone
on the same Wi-Fi (then use the Mac's LAN address). It logs joins, leaves and the type of each
forwarded signal, never their contents.

To test the "room full" and idle-peer paths quickly, lower the limits and tell the tests:

```sh
python3 dev_relay.py --max-peers 4 --stale-after 3
python3 test_relay.py --cap 4 --stale-after 3
```

To run the real Worker on your Mac (no login needed): `npx wrangler dev`, then
`python3 test_relay.py`. The tests also take a deployed address, for example
`python3 test_relay.py wss://relay.rescriva.com/ws`.

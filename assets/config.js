// Where the relay lives (see relay/README.md). If you move it, also update the
// connect-src line in index.html's Content-Security-Policy.
export const RELAY_URL = "wss://relay.rescriva.com/ws";

// The certificate built into the Rescriva app for no-relay pairing (PROTOCOL.md §3).
export const APP_FINGERPRINT =
  "C8:7F:82:09:B8:EF:F6:FB:92:37:13:91:BD:28:85:F1:50:E7:03:8D:3E:BB:DA:99:2A:78:3C:9F:DB:E1:95:CB";

const isLocalPage = ["localhost", "127.0.0.1"].includes(location.hostname);

// The relay to use, or null for none. Only a page served from this computer may
// point somewhere else (`?relay=ws://127.0.0.1:8787/ws`, or `?relay=off`), so a
// link can't send real visitors to someone else's relay.
export function relayURL() {
  const override = isLocalPage ? new URLSearchParams(location.search).get("relay") : null;
  if (override === "off") return null;
  return override || RELAY_URL;
}

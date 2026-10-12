// Encodings shared with the Rescriva app: base64 flavours, the pairing payload
// and the connection code (PROTOCOL.md §1, §3, §3.1).

export function b64url(bytes) {
  return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_");
}

export function b64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=+$/, "");
}

/** Throws on anything that isn't base64url. */
export function fromB64url(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("not base64url");
  const standard = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(standard + "=".repeat((4 - (standard.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

// MARK: Fingerprints and addresses

/** "AB:CD:…" → 32 bytes. */
export function fingerprintBytes(text) {
  const bytes = text.split(":").map((pair) => parseInt(pair, 16));
  if (bytes.length !== 32 || bytes.some((b) => !(b >= 0 && b <= 255))) throw new Error("bad fingerprint");
  return Uint8Array.from(bytes);
}

function ipv6Bytes(text) {
  const [head, tail = null] = text.split("%")[0].split("::");
  const groups = (part) => (part ? part.split(":") : []);
  const left = groups(head);
  const right = tail === null ? [] : groups(tail);
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (tail === null && missing !== 0)) throw new Error("bad IPv6 address");
  const all = [...left, ...Array(missing).fill("0"), ...right];
  const bytes = new Uint8Array(16);
  all.forEach((group, i) => {
    const value = parseInt(group, 16);
    if (!(value >= 0 && value <= 0xffff)) throw new Error("bad IPv6 address");
    bytes[i * 2] = value >> 8;
    bytes[i * 2 + 1] = value & 0xff;
  });
  return bytes;
}

const MDNS_NAME = /^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\.local$/i;

/** A candidate address as the payload stores it, or null when it can't. */
function encodeAddress(address) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(address)) return [4, Uint8Array.from(address.split(".").map(Number))];
  const mdns = address.match(MDNS_NAME);
  if (mdns) {
    const hex = mdns.slice(1).join("");
    return [109, Uint8Array.from(hex.match(/../g), (pair) => parseInt(pair, 16))];
  }
  if (address.includes(":")) {
    try {
      return [6, ipv6Bytes(address)];
    } catch {
      return null;
    }
  }
  return null;
}

// MARK: Pairing payload (the page's QR code)

/**
 * {secret, ufrag, pwd, fingerprint, mid, candidates: [{address, port}]} → bytes.
 * IPv4 and mDNS candidates go first; at most eight fit.
 */
export function pairingPayload({ secret, ufrag, pwd, fingerprint, mid, candidates }) {
  const ascii = (text) => Uint8Array.from(text, (c) => c.charCodeAt(0));
  const parts = [Uint8Array.of(1), secret];
  for (const text of [ufrag, pwd]) parts.push(Uint8Array.of(text.length), ascii(text));
  parts.push(fingerprintBytes(fingerprint));
  parts.push(Uint8Array.of(mid.length), ascii(mid));
  const encoded = candidates
    .map((c) => ({ address: encodeAddress(c.address), port: c.port }))
    .filter((c) => c.address)
    .sort((a, b) => (a.address[0] === 6) - (b.address[0] === 6))
    .slice(0, 8);
  parts.push(Uint8Array.of(encoded.length));
  for (const { address: [kind, bytes], port } of encoded) {
    parts.push(Uint8Array.of(kind), bytes, Uint8Array.of(port >> 8, port & 0xff));
  }
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

// MARK: Connection code

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DATA_DIGITS = [4, 7, 9, 10];
const PAYLOAD_BITS = [16, 32, 40, 48];

/** The address and port in a code the app shows, or null if it's mistyped. */
export function decodeConnectionCode(text) {
  const clean = text.toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
  const digits = [...clean].map((c) => CROCKFORD.indexOf(c));
  if (digits.length < 5 || digits.includes(-1)) return null;
  const tag = digits[0] >> 3;
  const n = DATA_DIGITS[tag];
  if (digits.length !== n + 1) return null;
  const data = digits.slice(0, n);
  if (data.reduce((sum, d, i) => sum + (i + 1) * d, 0) % 32 !== digits[n]) return null;

  let value = 0n;
  for (const d of data) value = (value << 5n) | BigInt(d);
  const bits = BigInt(PAYLOAD_BITS[tag]);
  if (value >> bits !== BigInt(tag) << BigInt(5 * n - 2 - PAYLOAD_BITS[tag])) return null;
  const payload = value & ((1n << bits) - 1n);
  const port = Number(payload & 0xffffn);
  const rest = payload >> 16n;
  const byte = (shift) => Number((rest >> BigInt(shift)) & 0xffn);
  const ip = [
    "172.20.10.1",
    `192.168.${byte(8)}.${byte(0)}`,
    `10.${byte(16)}.${byte(8)}.${byte(0)}`,
    `${byte(24)}.${byte(16)}.${byte(8)}.${byte(0)}`,
  ][tag];
  return port ? { ip, port } : null;
}

/** The app's side of the code; here for the tests. */
export function encodeConnectionCode(ip, port) {
  const a = ip.split(".").map(Number);
  let tag;
  let payload;
  if (ip === "172.20.10.1") [tag, payload] = [0, BigInt(port)];
  else if (a[0] === 192 && a[1] === 168) [tag, payload] = [1, (BigInt(a[2]) << 24n) | (BigInt(a[3]) << 16n) | BigInt(port)];
  else if (a[0] === 10) [tag, payload] = [2, (BigInt(a[1]) << 32n) | (BigInt(a[2]) << 24n) | (BigInt(a[3]) << 16n) | BigInt(port)];
  else [tag, payload] = [3, (a.reduce((v, b) => (v << 8n) | BigInt(b), 0n) << 16n) | BigInt(port)];
  const n = DATA_DIGITS[tag];
  const value = (BigInt(tag) << BigInt(5 * n - 2)) | payload;
  const digits = Array.from({ length: n }, (_, i) => Number((value >> BigInt(5 * (n - 1 - i))) & 31n));
  digits.push(digits.reduce((sum, d, i) => sum + (i + 1) * d, 0) % 32);
  return digits.map((d) => CROCKFORD[d]).join("");
}

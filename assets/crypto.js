// Secrets and what's derived from them (PROTOCOL.md §1.1). WebCrypto needs a
// secure context, which GitHub Pages (https) and localhost both are.

import { b64, b64url } from "./codes.js";

const text = (s) => new TextEncoder().encode(s);

function join(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function hmac(key, data) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

export const newSecret = () => crypto.getRandomValues(new Uint8Array(16));

export async function roomId(secret) {
  return b64url(await sha256(join(text("rescriva-share/room/v1"), secret))).slice(0, 22);
}

export async function iceCredentials(secret) {
  const h = await hmac(secret, text("rescriva-share/ice/v1"));
  return { ufrag: b64(h.slice(0, 6)), pwd: b64(h.slice(6, 24)) };
}

/** `role` is the sender's. Fingerprints are the offer's and the answer's, as applied. */
export async function proof(secret, role, fpOffer, fpAnswer) {
  return b64url(await hmac(secret, text(`rescriva-share/proof/v1|${role}|${fpOffer}|${fpAnswer}`)));
}

/**
 * The nine-digit check number for a connection with no secret (PROTOCOL.md §1.1): the
 * app shows it next to the connected computer, the page on the device card, and the
 * person compares them before typing a PIN. Fingerprints as `proof` takes them. Nine
 * digits (the first eight digest bytes as a big-endian number, mod 10⁹), zero-padded;
 * `formatCheckNumber` puts the spaces in. Nine rather than six because the side that
 * answers picks its certificate after seeing the offer's fingerprint, so a short number
 * could be ground into a match; a billion tries won't fit a connection's window.
 */
export async function checkNumber(fpOffer, fpAnswer) {
  const digest = await sha256(text(`rescriva-share/check/v1|${fpOffer}|${fpAnswer}`));
  const n = new DataView(digest.buffer, digest.byteOffset, 8).getBigUint64(0) % 1_000_000_000n;
  return String(n).padStart(9, "0");
}

/** "424561948" → "424 561 948", the way both sides show it. */
export function formatCheckNumber(digits) {
  return `${digits.slice(0, 3)} ${digits.slice(3, 6)} ${digits.slice(6)}`;
}

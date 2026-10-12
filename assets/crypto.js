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

// Keeps a copy of the page so it still opens with no internet (an iPhone hotspot
// with no signal, say), where QR pairing works without the relay. Always tries
// the network first, so updates show up straight away.

const CACHE = "rescriva-share-v1";
const FILES = [
  "./",
  "index.html",
  "assets/style.css",
  "assets/icon.svg",
  "assets/main.js",
  "assets/config.js",
  "assets/codes.js",
  "assets/crypto.js",
  "assets/sdp.js",
  "assets/relay.js",
  "assets/peer.js",
  "assets/pairing.js",
  "assets/qr.js",
  "assets/vendor/qrcode.js",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== location.origin) return;
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response.ok) {
          const copy = response.clone();
          caches.open(CACHE).then((cache) => cache.put(event.request, copy));
        }
        return response;
      })
      .catch(() => caches.match(event.request, { ignoreSearch: true })),
  );
});

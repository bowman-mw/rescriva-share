// Reading the few SDP lines pairing needs, and writing the made-up answer for
// no-relay pairing (PROTOCOL.md §3).

export function sdpValue(sdp, key) {
  const match = sdp.match(new RegExp(`^a=${key}:(.*)$`, "m"));
  return match ? match[1].trim() : null;
}

/** The SHA-256 fingerprint, upper case, as the proof uses it. */
export function fingerprint(sdp) {
  const match = sdp.match(/^a=fingerprint:sha-256 ([0-9A-Fa-f:]+)/m);
  return match ? match[1].toUpperCase() : null;
}

/** UDP host candidates: [{address, port}]. */
export function hostCandidates(sdp) {
  return [...sdp.matchAll(/^a=candidate:(.*)$/gm)]
    .map((m) => m[1].trim().split(/\s+/))
    .filter((f) => f[1] === "1" && f[2].toLowerCase() === "udp" && f[7] === "host")
    .map((f) => ({ address: f[4], port: Number(f[5]) }));
}

export function syntheticAnswer({ mid, ufrag, pwd, fingerprint }) {
  return [
    "v=0",
    "o=- 1 2 IN IP4 127.0.0.1",
    "s=-",
    "t=0 0",
    `a=group:BUNDLE ${mid}`,
    "a=msid-semantic: WMS",
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
    "c=IN IP4 0.0.0.0",
    `a=ice-ufrag:${ufrag}`,
    `a=ice-pwd:${pwd}`,
    "a=ice-options:trickle",
    `a=fingerprint:sha-256 ${fingerprint}`,
    "a=setup:active",
    `a=mid:${mid}`,
    "a=sctp-port:5000",
    "a=max-message-size:262144",
    "",
  ].join("\r\n");
}

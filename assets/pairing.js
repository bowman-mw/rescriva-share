// No-relay pairing (PROTOCOL.md §3): a connection that waits for a Rescriva app to
// scan this page's QR code, plus the connection code for when the app can't reach
// this computer on its own.

import { APP_FINGERPRINT } from "./config.js";
import { b64url, decodeConnectionCode, pairingPayload } from "./codes.js";
import { iceCredentials, newSecret, roomId } from "./crypto.js";
import { AppConnection } from "./peer.js";
import { fingerprint, hostCandidates, sdpValue, syntheticAnswer } from "./sdp.js";

const GATHER_TIMEOUT = 3_000;

export class Pairing {
  static async create(me) {
    const secret = newSecret();
    const pc = new RTCPeerConnection({ iceServers: [] });
    const dc = pc.createDataChannel("rescriva", { negotiated: true, id: 0 });
    await pc.setLocalDescription(await pc.createOffer());
    await gathered(pc);

    const sdp = pc.localDescription.sdp;
    const mid = sdpValue(sdp, "mid") ?? "0";
    const candidates = hostCandidates(sdp);
    const answer = syntheticAnswer({ mid, ...(await iceCredentials(secret)), fingerprint: APP_FINGERPRINT });
    await pc.setRemoteDescription({ type: "answer", sdp: answer });

    const payload = pairingPayload({
      secret,
      ufrag: sdpValue(sdp, "ice-ufrag"),
      pwd: sdpValue(sdp, "ice-pwd"),
      fingerprint: fingerprint(sdp),
      mid,
      candidates,
    });
    const pairing = new Pairing();
    pairing.secret = secret;
    pairing.mid = mid;
    pairing.room = await roomId(secret);
    pairing.link = `openscanner://share?p=${b64url(payload)}`;
    // No candidates usually means the browser has been told not to make direct
    // connections (an organization's WebRtcIPHandling policy, or an extension).
    pairing.blocked = candidates.length === 0;
    pairing.connection = new AppConnection({ pc, dc, secret, via: "direct", me });
    return pairing;
  }

  /** Points the waiting connection at the address in a code from the app. False if it's mistyped. */
  async enterCode(text) {
    const target = decodeConnectionCode(text);
    if (!target) return false;
    await this.connection.pc.addIceCandidate({
      candidate: `candidate:1 1 udp 2122260223 ${target.ip} ${target.port} typ host`,
      sdpMid: this.mid,
    });
    return true;
  }
}

function gathered(pc) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === "complete") return resolve();
    const done = () => {
      clearTimeout(timer);
      pc.removeEventListener("icegatheringstatechange", check);
      resolve();
    };
    const check = () => pc.iceGatheringState === "complete" && done();
    const timer = setTimeout(done, GATHER_TIMEOUT);
    pc.addEventListener("icegatheringstatechange", check);
  });
}

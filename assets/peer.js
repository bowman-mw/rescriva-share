// One connection to a Rescriva app over a WebRTC data channel (PROTOCOL.md §4):
// hellos, the document list, PINs, downloads and uploads.
//
// Events: "ready" (the app said hello and, when there's a secret, proved it),
// "docs", "transfer" (detail: the transfer that changed), "closed" (detail: {reason, wasReady}).

import { proof } from "./crypto.js";
import { fingerprint } from "./sdp.js";

const CHUNK = 64 * 1024;
const HIGH_WATER = 1024 * 1024;
const LOW_WATER = 256 * 1024;
const REPLY_TIMEOUT = 15_000;
/** Someone has to tap Accept on the device. */
const ANSWER_TIMEOUT = 120_000;
const HELLO_TIMEOUT = 10_000;
/** A relay connection that hasn't opened by now isn't going to (different networks, or blocked). */
const CONNECT_TIMEOUT = 25_000;

let serial = 0;

export class AppConnection extends EventTarget {
  #relay = null;
  #pendingCandidates = [];
  #waiting = new Map();
  #inbox = Promise.resolve();
  #incoming = null;
  #downloads = Promise.resolve();
  #uploads = Promise.resolve();
  #timers = [];

  /** For a page that reached the app through the relay. Call `offer()` next. */
  static viaRelay(relay, peer, secret, me) {
    const pc = new RTCPeerConnection({ iceServers: [] });
    const dc = pc.createDataChannel("rescriva", { negotiated: true, id: 0 });
    const connection = new AppConnection({ pc, dc, secret, via: "relay", me, app: peer });
    connection.#relay = relay;
    connection.relayPeerId = peer.id;
    pc.onicecandidate = (event) => {
      if (event.candidate) relay.signal(peer.id, { candidate: event.candidate.toJSON() });
    };
    connection.#later(() => connection.state === "connecting" && connection.close("unreachable"), CONNECT_TIMEOUT);
    return connection;
  }

  constructor({ pc, dc, secret = null, via, me, app = null }) {
    super();
    this.key = `c${++serial}`;
    this.pc = pc;
    this.dc = dc;
    this.secret = secret;
    this.via = via;
    this.me = me;
    this.state = "connecting";
    this.app = app ? { name: app.name, device: app.device } : null;
    this.trusted = false;
    this.docs = [];
    this.transfers = [];

    dc.binaryType = "arraybuffer";
    dc.bufferedAmountLowThreshold = LOW_WATER;
    dc.onopen = () => this.#opened();
    dc.onclose = () => this.close("closed");
    dc.onmessage = (event) => {
      this.#inbox = this.#inbox.then(() => this.#receive(event.data)).catch((error) => console.warn("Rescriva Share:", error));
    };
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === "failed") this.close("failed");
    };
  }

  async offer() {
    await this.pc.setLocalDescription(await this.pc.createOffer());
    this.#relay.signal(this.relayPeerId, { sdp: { type: "offer", sdp: this.pc.localDescription.sdp } });
  }

  /** A relay message from the app: its answer or an ICE candidate. */
  async signal(data) {
    try {
      if (data.sdp?.type === "answer" && this.pc.signalingState === "have-local-offer") {
        await this.pc.setRemoteDescription(data.sdp);
        for (const candidate of this.#pendingCandidates.splice(0)) {
          await this.pc.addIceCandidate(candidate).catch(() => {});
        }
      } else if (data.candidate) {
        if (this.pc.remoteDescription) await this.pc.addIceCandidate(data.candidate);
        else this.#pendingCandidates.push(data.candidate);
      }
    } catch (error) {
      console.warn("Rescriva Share: a connection message didn't apply", error);
    }
  }

  // MARK: Documents

  /** {ok} or {ok: false, reason: "wrong" | "cooldown" | "locked" | "gone" | "timeout", left, retryIn}. */
  async unlock(doc, pin) {
    this.#send({ t: "unlock", id: doc.id, pin });
    const reply = await this.#wait(`unlock:${doc.id}`, REPLY_TIMEOUT);
    if (!reply) return { ok: false, reason: "timeout" };
    if (reply.t === "unlocked") return { ok: true };
    return { ok: false, reason: reply.reason, left: reply.left, retryIn: reply.retryIn };
  }

  /** Queues a download; returns its transfer, which "transfer" events report on. */
  download(doc) {
    const transfer = this.#track({ direction: "down", docId: doc.id, name: doc.name, size: doc.size, done: 0, state: "waiting" });
    this.#downloads = this.#downloads.then(() => this.#runDownload(transfer));
    return transfer;
  }

  upload(file) {
    const transfer = this.#track({ direction: "up", name: file.name, size: file.size, done: 0, state: "waiting", file });
    this.#uploads = this.#uploads.then(() => this.#runUpload(transfer)).catch((error) => {
      console.warn("Rescriva Share: upload failed", error);
      this.#update(transfer, { state: "failed" });
    });
    return transfer;
  }

  /** Ends the connection; `reason` is kept for the page to explain. */
  close(reason = "closed") {
    if (this.state === "closed") return;
    const wasReady = this.state === "ready";
    this.state = "closed";
    this.closeReason = reason;
    if (reason !== "bye" && this.dc.readyState === "open") {
      try {
        this.dc.send('{"t":"bye"}');
      } catch {}
    }
    this.dc.close();
    this.pc.close();
    this.#timers.forEach(clearTimeout);
    for (const resolve of this.#waiting.values()) resolve(null);
    this.#waiting.clear();
    for (const transfer of this.transfers) {
      if (!["done", "saved", "declined", "failed"].includes(transfer.state)) this.#update(transfer, { state: "failed" });
    }
    this.#emit("closed", { reason, wasReady });
  }

  /** Lets go of downloaded files kept for "Save again". */
  discard() {
    for (const transfer of this.transfers) if (transfer.url) URL.revokeObjectURL(transfer.url);
  }

  // MARK: Receiving

  async #opened() {
    this.fpOffer = fingerprint(this.pc.localDescription?.sdp ?? "");
    this.fpAnswer = fingerprint(this.pc.remoteDescription?.sdp ?? "");
    const hello = { t: "hello", v: 1, role: "web", name: this.me.name, device: this.me.device };
    if (this.secret) hello.proof = await proof(this.secret, "web", this.fpOffer, this.fpAnswer);
    this.#send(hello);
    this.#later(() => this.state === "connecting" && this.close("no-hello"), HELLO_TIMEOUT);
  }

  async #receive(data) {
    if (this.state === "closed") return;
    if (typeof data !== "string") return this.#receiveChunk(data);
    let message;
    try {
      message = JSON.parse(data);
    } catch {
      return;
    }
    if (this.state !== "ready" && message.t !== "hello" && message.t !== "bye") return;
    switch (message.t) {
      case "hello":
        return this.#hello(message);
      case "docs":
        this.docs = (Array.isArray(message.docs) ? message.docs : []).filter((d) => d && typeof d.id === "string" && typeof d.name === "string");
        this.#emit("docs");
        break;
      case "unlocked":
        this.#resolve(`unlock:${message.id}`, message);
        break;
      case "denied":
        if (!this.#resolve(`unlock:${message.id}`, message)) this.#refused(message);
        break;
      case "file":
        return this.#fileStarts(message);
      case "end":
        return this.#fileEnds(message);
      case "accept":
      case "decline":
        this.#resolve(`answer:${message.xfer}`, message);
        break;
      case "saved":
        this.#resolve(`saved:${message.xfer}`, message);
        break;
      case "cancel":
        this.#cancelled(message.xfer);
        break;
      case "bye":
        this.close("bye");
        break;
    }
  }

  async #hello(message) {
    if (this.state !== "connecting") return;
    if (this.secret) {
      const expected = await proof(this.secret, "app", this.fpOffer, this.fpAnswer);
      if (message.proof !== expected) return this.close("bad-proof");
    }
    this.app = {
      name: String(message.name || this.app?.name || "Rescriva").slice(0, 64),
      device: message.device || this.app?.device || "iphone",
      session: typeof message.session === "string" ? message.session : null,
    };
    this.trusted = Boolean(this.secret);
    this.state = "ready";
    this.#emit("ready");
  }

  #fileStarts(message) {
    const transfer = this.transfers.find((t) => t.direction === "down" && t.state === "requested" && t.docId === message.id);
    if (!transfer) {
      this.#send({ t: "cancel", xfer: message.xfer });
      return;
    }
    this.#incoming = { transfer, xfer: message.xfer, parts: [], type: message.type || "application/octet-stream" };
    this.#update(transfer, { state: "moving", name: message.name || transfer.name, size: Number(message.size) || transfer.size, done: 0 });
  }

  #receiveChunk(buffer) {
    const incoming = this.#incoming;
    if (!incoming) return;
    incoming.parts.push(buffer);
    this.#update(incoming.transfer, { done: incoming.transfer.done + buffer.byteLength });
  }

  #fileEnds(message) {
    const incoming = this.#incoming;
    if (!incoming || incoming.xfer !== message.xfer) return;
    this.#incoming = null;
    const { transfer } = incoming;
    if (transfer.done !== transfer.size) {
      this.#update(transfer, { state: "failed" });
    } else {
      const url = URL.createObjectURL(new Blob(incoming.parts, { type: incoming.type }));
      this.#update(transfer, { state: "done", url });
      saveFile(url, transfer.name);
    }
    transfer.finish?.();
  }

  #refused(message) {
    const transfer = this.transfers.find((t) => t.direction === "down" && t.state === "requested" && t.docId === message.id);
    if (!transfer) return;
    this.#update(transfer, { state: "failed", note: message.reason });
    transfer.finish?.();
  }

  #cancelled(xfer) {
    if (this.#incoming?.xfer === xfer) {
      const { transfer } = this.#incoming;
      this.#incoming = null;
      this.#update(transfer, { state: "failed" });
      transfer.finish?.();
    }
    const upload = this.transfers.find((t) => t.direction === "up" && t.xfer === xfer);
    if (upload) upload.cancelled = true;
  }

  // MARK: Transfers

  #runDownload(transfer) {
    if (this.state !== "ready") return;
    return new Promise((resolve) => {
      transfer.finish = resolve;
      this.#update(transfer, { state: "requested" });
      this.#send({ t: "get", id: transfer.docId });
      this.#later(() => {
        if (transfer.state !== "requested") return;
        this.#update(transfer, { state: "failed", note: "timeout" });
        resolve();
      }, REPLY_TIMEOUT);
    });
  }

  async #runUpload(transfer) {
    if (this.state !== "ready") return;
    transfer.xfer = `u${++serial}`;
    this.#send({ t: "send", xfer: transfer.xfer, name: transfer.name, size: transfer.size, type: transfer.file.type || typeFor(transfer.name) });
    this.#update(transfer, { state: "asking" });
    const answer = await this.#wait(`answer:${transfer.xfer}`, ANSWER_TIMEOUT);
    if (!answer || answer.t !== "accept") {
      if (!answer && this.state === "ready") this.#send({ t: "cancel", xfer: transfer.xfer });
      return this.#update(transfer, { state: answer ? "declined" : "failed", note: answer?.reason });
    }
    this.#update(transfer, { state: "moving" });
    for (let offset = 0; offset < transfer.size; offset += CHUNK) {
      if (this.state !== "ready" || transfer.cancelled) return this.#update(transfer, { state: "failed" });
      const chunk = await transfer.file.slice(offset, offset + CHUNK).arrayBuffer();
      await this.#roomToSend();
      if (this.state !== "ready") return;
      this.dc.send(chunk);
      this.#update(transfer, { done: Math.min(transfer.size, offset + CHUNK) });
    }
    this.#send({ t: "end", xfer: transfer.xfer });
    this.#update(transfer, { state: "finishing" });
    const saved = await this.#wait(`saved:${transfer.xfer}`, ANSWER_TIMEOUT);
    this.#update(transfer, { state: saved?.ok ? "saved" : "failed" });
  }

  #roomToSend() {
    if (this.dc.bufferedAmount <= HIGH_WATER) return Promise.resolve();
    return new Promise((resolve) => {
      const done = () => {
        this.dc.removeEventListener("bufferedamountlow", done);
        this.dc.removeEventListener("close", done);
        resolve();
      };
      this.dc.addEventListener("bufferedamountlow", done);
      this.dc.addEventListener("close", done);
    });
  }

  #track(transfer) {
    transfer.id = `t${++serial}`;
    this.transfers.push(transfer);
    this.#emit("transfer", transfer);
    return transfer;
  }

  #update(transfer, changes) {
    Object.assign(transfer, changes);
    this.#emit("transfer", transfer);
  }

  // MARK: Plumbing

  #send(message) {
    if (this.dc.readyState === "open") this.dc.send(JSON.stringify(message));
  }

  #wait(key, ms) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.#waiting.delete(key);
        resolve(null);
      }, ms);
      this.#waiting.set(key, (value) => {
        clearTimeout(timer);
        resolve(value);
      });
    });
  }

  #resolve(key, value) {
    const resolve = this.#waiting.get(key);
    if (!resolve) return false;
    this.#waiting.delete(key);
    resolve(value);
    return true;
  }

  #later(work, ms) {
    this.#timers.push(setTimeout(work, ms));
  }

  #emit(type, detail) {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }
}

export function saveFile(url, name) {
  const link = Object.assign(document.createElement("a"), { href: url, download: name, rel: "noopener" });
  document.body.append(link);
  link.click();
  link.remove();
}

function typeFor(name) {
  const ext = name.split(".").pop().toLowerCase();
  return { pdf: "application/pdf", jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", heic: "image/heic", gif: "image/gif", webp: "image/webp", tif: "image/tiff", tiff: "image/tiff" }[ext] || "application/octet-stream";
}

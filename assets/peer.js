// One connection to a Rescriva app over a WebRTC data channel (PROTOCOL.md §4):
// hellos, the document list, PINs, downloads and uploads.
//
// Events: "ready" (the app said hello and, when there's a secret, proved it),
// "docs", "transfer" (detail: the transfer that changed), "closed" (detail: {reason, wasReady}).

import { checkNumber, proof } from "./crypto.js";
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
/** A transfer with nothing moving for this long is given up on. */
const STALL_TIMEOUT = 30_000;
const STALL_POLL = 5_000;
/** The browser calling a connection "disconnected" for this long means it's gone; the page then dials again. */
const DISCONNECT_TIMEOUT = 10_000;
/** How long a download collected in memory stays around for "Save again". */
const KEEP_DOWNLOAD = 10 * 60_000;
/** Finished transfers remembered per connection; older ones go, with their bytes. */
const KEEP_TRANSFERS = 20;
/** The app shares at most this many documents (its maxDocuments); anything past it is ignored. */
const MAX_DOCS = 200;
/** After `bye`, the transport stays up this long so the word gets out before it goes. */
const BYE_LINGER = 300;

const FINAL = new Set(["done", "saved", "declined", "failed"]);

/**
 * What the page saves from a device it hasn't paired with (PROTOCOL.md §4): PDFs, images,
 * MP4 and QuickTime videos and the app's own export formats (Word, PowerPoint, Markdown,
 * plain text), under an extension that matches the type. The first extension is the one
 * added when the name lacks one; the rest count as already having it. A paired device's
 * files are saved whatever their type. The app keeps a copy of this list
 * (ShareLimits.unpairedPageTypes) to say which of its files only a paired page can take.
 */
const SAVED_TYPES = {
  "application/pdf": [".pdf"],
  "image/png": [".png"],
  "image/jpeg": [".jpg", ".jpeg"],
  "image/heic": [".heic"],
  "image/heif": [".heif"],
  "image/gif": [".gif"],
  "image/webp": [".webp"],
  "image/tiff": [".tiff", ".tif"],
  "video/mp4": [".mp4"],
  "video/quicktime": [".mov"],
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [".docx"],
  "application/vnd.openxmlformats-officedocument.presentationml.presentation": [".pptx"],
  "text/markdown": [".md", ".markdown"],
  "text/plain": [".txt"],
};

/**
 * The most the page takes from an unpaired device in one file, by type, so a fake device
 * can't stream into memory or onto the disk without end. Paired devices are trusted with
 * any size. The app keeps a copy (ShareLimits.unpairedPageMaxPDFBytes and
 * unpairedPageMaxBytes).
 */
const MAX_UNTRUSTED_BYTES = { "application/pdf": 1 << 30, "image/": 128 << 20, "": 128 << 20 };

let serial = 0;

export class AppConnection extends EventTarget {
  #relay = null;
  #pendingCandidates = [];
  #waiting = new Map();
  #inbox = Promise.resolve();
  #incoming = null;
  #downloads = Promise.resolve();
  #uploads = Promise.resolve();
  #timers = new Set();
  #stall = null;
  #open = false;

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
    /** Six digits for a connection with no secret, once the app has said hello; null otherwise. */
    this.checkNumber = null;
    this.docs = [];
    this.transfers = [];

    dc.binaryType = "arraybuffer";
    dc.bufferedAmountLowThreshold = LOW_WATER;
    dc.onopen = () => this.#channelOpened();
    dc.onclose = () => this.close("closed");
    dc.onmessage = (event) => {
      // A frame means the channel is open, even if the browser hasn't said so yet.
      if (!this.#open) this.#channelOpened();
      this.#inbox = this.#inbox.then(() => this.#receive(event.data)).catch((error) => console.warn("Rescriva Share:", error));
    };
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === "failed") this.close("failed");
      // "disconnected" can be a blip. Still disconnected a while later, it's a drop.
      if (pc.connectionState === "disconnected") {
        this.#later(() => this.pc.connectionState === "disconnected" && this.close("dropped"), DISCONNECT_TIMEOUT);
      }
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

  /**
   * Queues a download; returns its transfer, which "transfer" events report on. Call it
   * from the click: where the browser can write straight to disk it asks where to save
   * now, while the click still counts, so the file never has to be held whole. Elsewhere
   * the file is collected into a Blob and saved at the end.
   */
  download(doc) {
    const name = this.#savedName(doc.name, doc.type);
    const transfer = this.#track({ direction: "down", docId: doc.id, name, size: doc.size, done: 0, state: "waiting" });
    // From a device this page hasn't paired with, a type it won't save is refused here,
    // before any save dialog opens (which would leave an empty file) and before `get`.
    if (!this.trusted && savedName(doc.name, doc.type) === null) {
      this.#update(transfer, { state: "failed", note: "type" });
      return transfer;
    }
    // The save dialog's promise lives in `picker`, which nothing clears: a download that
    // ends while its dialog is still up has to abort the writable the dialog then makes.
    transfer.picker = openSink(name, doc.type);
    this.#downloads = this.#downloads.then(() => this.#runDownload(transfer));
    return transfer;
  }

  upload(file) {
    const transfer = this.#track({ direction: "up", name: file.name, size: file.size, done: 0, state: "waiting", file });
    this.#uploads = this.#uploads.then(() => this.#runUpload(transfer)).catch((error) => {
      console.warn("Rescriva Share: upload failed", error);
      this.#uploadFailed(transfer, error?.name === "StallError" ? "stalled" : undefined);
    });
    return transfer;
  }

  /** Ends the connection; `reason` is kept for the page to explain. */
  close(reason = "closed") {
    if (this.state === "closed") return;
    const wasReady = this.state === "ready";
    this.state = "closed";
    this.closeReason = reason;
    let saidBye = false;
    if (reason !== "bye" && this.dc.readyState === "open") {
      try {
        this.dc.send('{"t":"bye"}');
        saidBye = true;
      } catch {}
    }
    // Closing the transport right behind "bye" can lose it, and then the app keeps the
    // page until its connection fails. So the transport goes a moment later.
    const stop = () => {
      this.dc.close();
      this.pc.close();
    };
    if (saidBye) setTimeout(stop, BYE_LINGER);
    else stop();
    this.#timers.forEach(clearTimeout);
    this.#timers.clear();
    clearTimeout(this.#stall);
    for (const resolve of this.#waiting.values()) resolve(null);
    this.#waiting.clear();
    for (const transfer of this.transfers) {
      if (FINAL.has(transfer.state)) continue;
      if (transfer.direction === "down") this.#downloadEnded(transfer, { state: "failed" });
      else this.#update(transfer, { state: "failed" });
    }
    this.#emit("closed", { reason, wasReady });
  }

  /** Lets go of downloaded files kept for "Save again". */
  discard() {
    for (const transfer of this.transfers) this.#forget(transfer);
  }

  // MARK: Receiving

  #channelOpened() {
    if (this.#open) return;
    this.#open = true;
    this.#opened().catch((error) => console.warn("Rescriva Share: couldn't say hello", error));
  }

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
        // A size that isn't a whole number of bytes is no size: the entry is listed but
        // never downloaded from an unpaired device (`#fileStarts` checks against it).
        this.docs = (Array.isArray(message.docs) ? message.docs : [])
          .filter((d) => d && typeof d.id === "string" && typeof d.name === "string")
          .slice(0, MAX_DOCS)
          .map((d) => ({ ...d, size: byteCount(d.size) }));
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
    } else if (this.fpOffer && this.fpAnswer) {
      // Nothing proves this is the device it says it is. The person compares this number
      // with the one Rescriva shows next to this computer (PROTOCOL.md §1.2).
      this.checkNumber = await checkNumber(this.fpOffer, this.fpAnswer);
    }
    if (this.state !== "connecting") return;
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
    if (!transfer) return this.#send({ t: "cancel", xfer: message.xfer });
    const type = String(message.type || "application/octet-stream");
    const refuse = (note) => {
      this.#send({ t: "cancel", xfer: message.xfer });
      return this.#downloadEnded(transfer, { state: "failed", note });
    };
    // The name comes from the document list, never from here. From a device this page
    // hasn't paired with, only a type it knows is taken, saved under an extension that
    // matches the type it says it's sending; and the size comes from the list too, so the
    // overflow check in `#receiveChunk` is against a number the device gave before it
    // was asked for anything, and it has to be within what the app itself would take.
    let name = transfer.name;
    let size = byteCount(message.size);
    if (size === null) return refuse("listed");
    if (!this.trusted) {
      const forced = savedName(name, type);
      // Already open on disk under one name, the file can't change to another.
      if (!forced || (transfer.sink && forced !== name)) return refuse("type");
      name = forced;
      if (size !== transfer.size || size > maxUntrustedBytes(type)) return refuse("listed");
    }
    this.#incoming = { transfer, xfer: message.xfer, parts: [], type };
    this.#update(transfer, { state: "moving", name, size, done: 0 });
    this.#stallSoon(transfer);
  }

  async #receiveChunk(buffer) {
    const incoming = this.#incoming;
    if (!incoming) return;
    const { transfer } = incoming;
    const done = transfer.done + buffer.byteLength;
    if (done > transfer.size) {
      // More than the device said there'd be: stop taking it.
      this.#send({ t: "cancel", xfer: incoming.xfer });
      return this.#downloadEnded(transfer, { state: "failed", note: "size" });
    }
    if (transfer.sink) {
      try {
        await transfer.sink.write(buffer);
      } catch (error) {
        console.warn("Rescriva Share: couldn't write the file", error);
        if (this.#incoming !== incoming) return;
        this.#send({ t: "cancel", xfer: incoming.xfer });
        return this.#downloadEnded(transfer, { state: "failed", note: "disk" });
      }
      if (this.#incoming !== incoming) return;
    } else {
      incoming.parts.push(buffer);
    }
    this.#update(transfer, { done });
    this.#stallSoon(transfer);
  }

  async #fileEnds(message) {
    const incoming = this.#incoming;
    if (!incoming || incoming.xfer !== message.xfer) return;
    const { transfer } = incoming;
    if (transfer.done !== transfer.size) return this.#downloadEnded(transfer, { state: "failed" });
    if (transfer.sink) {
      const sink = transfer.sink;
      transfer.sink = null;
      try {
        await sink.close();
      } catch (error) {
        console.warn("Rescriva Share: couldn't finish writing the file", error);
        return this.#downloadEnded(transfer, { state: "failed", note: "disk" });
      }
      return this.#downloadEnded(transfer, { state: "done" });
    }
    const url = URL.createObjectURL(new Blob(incoming.parts, { type: incoming.type }));
    this.#downloadEnded(transfer, { state: "done", url });
    saveFile(url, transfer.name);
    // The bytes stay for "Save again" a while, then go.
    this.#later(() => this.#forget(transfer), KEEP_DOWNLOAD);
  }

  #refused(message) {
    const transfer = this.transfers.find((t) => t.direction === "down" && t.state === "requested" && t.docId === message.id);
    if (transfer) this.#downloadEnded(transfer, { state: "failed", note: message.reason });
  }

  #cancelled(xfer) {
    if (this.#incoming?.xfer === xfer) this.#downloadEnded(this.#incoming.transfer, { state: "failed", note: "cancelled" });
    const upload = this.transfers.find((t) => t.direction === "up" && t.xfer === xfer);
    if (upload) upload.cancelled = true;
  }

  // MARK: Transfers

  async #runDownload(transfer) {
    const sink = await transfer.picker;
    transfer.picker = null;
    const writable = sink && sink !== "cancelled" ? sink : null;
    if (transfer.state !== "waiting" || this.state !== "ready") {
      // Closed while the save dialog was up.
      writable?.abort().catch(() => {});
      if (transfer.state === "waiting") this.#update(transfer, { state: "failed" });
      return;
    }
    transfer.sink = writable;
    if (sink === "cancelled") return this.#downloadEnded(transfer, { state: "failed", note: "cancelled" });
    return new Promise((resolve) => {
      transfer.finish = resolve;
      this.#update(transfer, { state: "requested" });
      this.#send({ t: "get", id: transfer.docId });
      this.#later(() => {
        if (transfer.state === "requested") this.#downloadEnded(transfer, { state: "failed", note: "timeout" });
      }, REPLY_TIMEOUT);
    });
  }

  /** A download is over, one way or the other: a part-written file goes, and the next download may start. */
  #downloadEnded(transfer, changes) {
    if (this.#incoming?.transfer === transfer) this.#incoming = null;
    clearTimeout(this.#stall);
    const sink = transfer.sink;
    transfer.sink = null;
    if (sink && typeof sink.abort === "function") sink.abort().catch(() => {});
    this.#update(transfer, changes);
    transfer.finish?.();
    transfer.finish = null;
  }

  /** Restarts the download's clock: nothing for STALL_TIMEOUT and it's given up. */
  #stallSoon(transfer) {
    clearTimeout(this.#stall);
    this.#stall = setTimeout(() => {
      if (this.#incoming?.transfer !== transfer) return;
      this.#send({ t: "cancel", xfer: this.#incoming.xfer });
      this.#downloadEnded(transfer, { state: "failed", note: "stalled" });
    }, STALL_TIMEOUT);
  }

  async #runUpload(transfer) {
    if (this.state !== "ready") return this.#update(transfer, { state: "failed" });
    transfer.xfer = `u${++serial}`;
    this.#send({ t: "send", xfer: transfer.xfer, name: transfer.name, size: transfer.size, type: transfer.file.type || typeFor(transfer.name) });
    this.#update(transfer, { state: "asking" });
    const answer = await this.#wait(`answer:${transfer.xfer}`, ANSWER_TIMEOUT);
    if (!answer) return this.#uploadFailed(transfer, "timeout");
    if (answer.t !== "accept") return this.#update(transfer, { state: "declined", note: answer.reason });
    this.#update(transfer, { state: "moving" });
    for (let offset = 0; offset < transfer.size; offset += CHUNK) {
      if (transfer.cancelled) return this.#update(transfer, { state: "failed", note: "cancelled" });
      if (this.state !== "ready") return this.#update(transfer, { state: "failed" });
      const chunk = await transfer.file.slice(offset, offset + CHUNK).arrayBuffer();
      await this.#roomToSend();
      if (this.state !== "ready") return this.#update(transfer, { state: "failed" });
      this.dc.send(chunk);
      this.#update(transfer, { done: Math.min(transfer.size, offset + CHUNK) });
    }
    this.#send({ t: "end", xfer: transfer.xfer });
    this.#update(transfer, { state: "finishing" });
    const saved = await this.#wait(`saved:${transfer.xfer}`, ANSWER_TIMEOUT);
    if (!saved) return this.#uploadFailed(transfer, "timeout");
    this.#update(transfer, { state: saved.ok ? "saved" : "failed", note: saved.ok ? undefined : "not-saved" });
  }

  /** An upload is over without the app saying so: tell it, so it frees its slot for the next one. */
  #uploadFailed(transfer, note) {
    if (transfer.xfer && !transfer.cancelled && this.state === "ready") this.#send({ t: "cancel", xfer: transfer.xfer });
    this.#update(transfer, { state: "failed", note });
  }

  /** Resolves when the send buffer has room. Rejects when it hasn't drained at all in STALL_TIMEOUT. */
  #roomToSend() {
    if (this.dc.bufferedAmount <= HIGH_WATER) return Promise.resolve();
    return new Promise((resolve, reject) => {
      let last = this.dc.bufferedAmount;
      let idle = 0;
      const done = (error) => {
        clearInterval(poll);
        this.dc.removeEventListener("bufferedamountlow", ok);
        this.dc.removeEventListener("close", ok);
        if (error) reject(error);
        else resolve();
      };
      const ok = () => done();
      const poll = setInterval(() => {
        const now = this.dc.bufferedAmount;
        idle = now < last ? 0 : idle + STALL_POLL;
        last = now;
        if (idle >= STALL_TIMEOUT) done(Object.assign(new Error("nothing sent for 30 s"), { name: "StallError" }));
      }, STALL_POLL);
      this.dc.addEventListener("bufferedamountlow", ok);
      this.dc.addEventListener("close", ok);
    });
  }

  #track(transfer) {
    transfer.id = `t${++serial}`;
    this.transfers.push(transfer);
    // Only the last few finished ones are kept; their bytes go with them.
    const finished = this.transfers.filter((t) => FINAL.has(t.state));
    for (const old of finished.slice(0, Math.max(0, finished.length - KEEP_TRANSFERS))) {
      this.#forget(old);
      this.transfers.splice(this.transfers.indexOf(old), 1);
    }
    this.#emit("transfer", transfer);
    return transfer;
  }

  #update(transfer, changes) {
    Object.assign(transfer, changes);
    this.#emit("transfer", transfer);
  }

  /** Lets go of a finished download's bytes; its row loses "Save again". */
  #forget(transfer) {
    if (!transfer.url) return;
    URL.revokeObjectURL(transfer.url);
    this.#update(transfer, { url: null });
  }

  /** What a download is saved as. From a device this page hasn't paired with, the extension follows the type. */
  #savedName(name, type) {
    const clean = cleanFileName(name);
    return this.trusted ? clean : savedName(clean, type) || clean;
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
    const timer = setTimeout(() => {
      this.#timers.delete(timer);
      work();
    }, ms);
    this.#timers.add(timer);
  }

  #emit(type, detail) {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }
}

// MARK: Saving

export function saveFile(url, name) {
  const link = Object.assign(document.createElement("a"), { href: url, download: name, rel: "noopener" });
  document.body.append(link);
  link.click();
  link.remove();
}

/**
 * `name` with the extension its `type` calls for, added when it's missing, or null when
 * the type isn't one the page saves from an unpaired device. "Scan.pdf.exe" sent as a PDF
 * is saved as "Scan.pdf.exe.pdf". Never longer than `cleanFileName` allows.
 */
export function savedName(name, type) {
  const extensions = SAVED_TYPES[mediaType(type)];
  if (!extensions) return null;
  const clean = cleanFileName(name);
  const lower = clean.toLowerCase();
  if (extensions.some((ext) => lower.endsWith(ext))) return clean;
  return clean.slice(0, MAX_NAME_LENGTH - extensions[0].length) + extensions[0];
}

const MAX_NAME_LENGTH = 200;

/**
 * A name fit to hand the browser: no path parts or control characters (each becomes "_"),
 * no bidi overrides or isolates (which could turn "Scan‮fdp.exe" into "Scanexe.pdf" on
 * screen; they go, like the relay and the app drop them from device names), no leading
 * dots or spaces (so nothing lands as a hidden file), trimmed, and clipped.
 */
export function cleanFileName(name) {
  const clean = String(name ?? "")
    .replace(/[\\/\u0000-\u001f\u007f-\u009f]/g, "_")
    .replace(/[‪-‮⁦-⁩]/g, "")
    .trim()
    .replace(/^[.\s]+/, "")
    .trim()
    .slice(0, MAX_NAME_LENGTH)
    .trim();
  return clean || "Rescriva file";
}

/** The media type without its parameters, lower-case: "image/PNG; x=y" → "image/png". */
function mediaType(type) {
  return String(type ?? "").split(";")[0].trim().toLowerCase();
}

/** `value` as a count of bytes, or null when it isn't a finite whole number of them. */
export function byteCount(value) {
  const n = typeof value === "string" && value.trim() !== "" ? Number(value) : value;
  return Number.isInteger(n) && n >= 0 && n <= Number.MAX_SAFE_INTEGER ? n : null;
}

/** The most the page takes from an unpaired device in one file of `type` (PROTOCOL.md §4). */
export function maxUntrustedBytes(type) {
  const mime = mediaType(type);
  if (mime === "application/pdf") return MAX_UNTRUSTED_BYTES["application/pdf"];
  if (mime.startsWith("image/")) return MAX_UNTRUSTED_BYTES["image/"];
  return MAX_UNTRUSTED_BYTES[""];
}

/**
 * Where the browser can write a download straight to disk (Chrome and Edge), asks where to
 * put it. Resolves to the writable stream; to "cancelled" when the person closed the dialog;
 * or to null when the file has to be collected in memory instead (other browsers, or the
 * ask came too long after the click to count).
 */
async function openSink(name, type) {
  if (typeof window.showSaveFilePicker !== "function") return null;
  const mime = mediaType(type);
  const options = { suggestedName: name, id: "rescriva-share" };
  if (SAVED_TYPES[mime]) options.types = [{ accept: { [mime]: SAVED_TYPES[mime] } }];
  try {
    const handle = await window.showSaveFilePicker(options);
    return await handle.createWritable();
  } catch (error) {
    if (error?.name === "AbortError") return "cancelled";
    console.warn("Rescriva Share: can't write straight to disk here, so the file is collected first", error);
    return null;
  }
}

function typeFor(name) {
  const ext = name.split(".").pop().toLowerCase();
  return { pdf: "application/pdf", jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", heic: "image/heic", heif: "image/heif", gif: "image/gif", webp: "image/webp", tif: "image/tiff", tiff: "image/tiff", mov: "video/quicktime", mp4: "video/mp4", m4v: "video/x-m4v" }[ext] || "application/octet-stream";
}

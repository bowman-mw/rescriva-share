// Rescriva Share: the page. Finds Rescriva devices through the relay (or a QR
// pairing), shows what they share, and moves files both ways. PROTOCOL.md has the details.

import { relayURL } from "./config.js";
import { fromB64url } from "./codes.js";
import { formatCheckNumber, roomId } from "./crypto.js";
import { Pairing } from "./pairing.js";
import { AppConnection, saveFile } from "./peer.js";
import { qrSVG } from "./qr.js";
import { RelayClient } from "./relay.js";

// Inside another site's frame the page shows nothing and does nothing: a meta CSP can't
// set frame-ancestors, and a hidden frame could be clicked through.
if (top !== self) {
  document.documentElement.hidden = true;
  throw new Error("Rescriva Share doesn't run inside another page");
}

const me = describeBrowser();
const RELAY = relayURL();

/** Every connection to an app, by key (a relay peer id, or "direct:<room>"). */
const connections = new Map();
/**
 * Relay peers held back as duplicates: peer id → the connection they lost to. An entry
 * goes when that connection closes or the peer leaves the room, so nobody is shut out
 * for good (see `dedupe`).
 */
const retired = new Map();
/** Relay peers whose connection dropped: peer id → {tries, timer} for the next try. */
const redials = new Map();
/** How to dial a peer in each relay room the page watches. */
const dialers = new Map();
const cards = new Map();

const REDIAL_TRIES = 10;
/** Closings that a fresh offer might get past. */
const REDIAL_REASONS = new Set(["unreachable", "no-hello", "failed", "closed", "dropped"]);

let mode = "nearby"; // "nearby" | "link"
let autoRelay = null;
let linkRelay = null;
let pairRelay = null;
let pairing = null;
let pairingNote = "";

const $ = (id) => document.getElementById(id);

// MARK: Start

async function start() {
  if (!window.RTCPeerConnection || !window.crypto?.subtle) {
    $("status").textContent = "This browser can't make direct connections. Try a current Chrome, Edge, Safari or Firefox.";
    document.body.classList.add("unsupported");
    return;
  }
  const key = linkKey();
  if (key) {
    mode = "link";
    document.body.classList.add("link-mode");
    if (RELAY) linkRelay = watch(new RelayClient(RELAY, await roomId(key), me), key).start();
  } else {
    if (RELAY) autoRelay = watch(new RelayClient(RELAY, "auto", me), null).start();
    newPairing();
  }
  wireCodeForm();
  addEventListener("pagehide", () => connections.forEach((c) => c.close("page closed")));
  render();
}

/** The secret in a link from the app's QR code (#k=…), which is then dropped from the address bar. */
function linkKey() {
  const value = new URLSearchParams(location.hash.slice(1)).get("k");
  if (!value) return null;
  history.replaceState(null, "", location.pathname + location.search);
  try {
    const key = fromB64url(value);
    return key.length === 16 ? key : null;
  } catch {
    return null;
  }
}

// MARK: Relay

function watch(relay, secret) {
  const dial = (peer) => {
    if (peer.role !== "app" || connections.has(peer.id) || retired.has(peer.id)) return;
    const connection = AppConnection.viaRelay(relay, peer, secret, me);
    adopt(peer.id, connection);
    connection.addEventListener("closed", (e) => retry(relay, peer, connection, e.detail));
    connection.offer().catch((error) => {
      console.warn("Rescriva Share: couldn't start a connection", error);
      connection.close("failed");
    });
  };
  dialers.set(relay, dial);
  // Who's in the room changes the status line and the "Connecting…" cards, so render after each change.
  relay.addEventListener("peers", (e) => {
    e.detail.forEach(dial);
    render();
  });
  relay.addEventListener("join", (e) => {
    dial(e.detail);
    render();
  });
  relay.addEventListener("leave", (e) => {
    // A connection that's open carries on without the relay; the app says bye when it stops.
    const connection = connections.get(e.detail.id);
    if (connection && connection.state === "connecting") connection.close("left");
    forgetPeer(e.detail.id);
    render();
  });
  relay.addEventListener("signal", (e) => connections.get(e.detail.from)?.signal(e.detail.data));
  relay.addEventListener("status", render);
  return relay;
}

function unwatch(relay) {
  if (!relay) return;
  relay.stop();
  dialers.delete(relay);
  relay.peers.forEach((peer) => forgetPeer(peer.id));
  relay.peers.clear();
}

/** A relay peer is gone: nothing to hold against its id, nothing to retry. */
function forgetPeer(id) {
  retired.delete(id);
  clearTimeout(redials.get(id)?.timer);
  redials.delete(id);
}

/**
 * A relay connection ended. When the drop looked transient and the device is still in
 * the room, dial it again after a pause that doubles each time (2 s, 4 s … 30 s), up to
 * REDIAL_TRIES. Neither side restarts ICE, so a fresh offer is the only way back. A
 * device that isn't in the room any more can't be redialed: a paired one left its
 * pairing room on purpose (both ends do, once paired), so its code has to be scanned
 * again; a same-network one is dialed afresh when the relay lists it again. "Stopped
 * sharing" is only ever said for the app's own `bye` (see `adopt`).
 */
function retry(relay, peer, connection, { reason, wasReady }) {
  const name = peer.name || "the device";
  if (!REDIAL_REASONS.has(reason)) return;
  if (!relay.peers.has(peer.id)) {
    if (wasReady && connection.trusted) toast(`Lost the connection to ${name}. Scan its code again to reconnect.`);
    else if (wasReady) toast(`Lost the connection to ${name}.`);
    return;
  }
  const tries = (redials.get(peer.id)?.tries ?? 0) + 1;
  if (tries > REDIAL_TRIES) {
    redials.delete(peer.id);
    toast(`Couldn't connect to ${name}. Check that both are on the same Wi‑Fi, or pair with the code.`);
    return;
  }
  if (tries === 1) toast(wasReady ? `Lost the connection to ${name}. Trying again…` : `Couldn't connect to ${name}. Trying again…`);
  const timer = setTimeout(() => {
    redials.set(peer.id, { tries, timer: null });
    const current = relay.peers.get(peer.id);
    if (current) dialers.get(relay)?.(current);
    render();
  }, Math.min(30_000, 2_000 * 2 ** (tries - 1)));
  redials.set(peer.id, { tries, timer });
}

// MARK: Pairing

async function newPairing() {
  unwatch(pairRelay);
  pairRelay = null;
  let next;
  try {
    next = await Pairing.create(me);
  } catch (error) {
    console.warn("Rescriva Share: couldn't make a pairing code", error);
    pairingNote = "Couldn't make a pairing code in this browser.";
    render();
    return;
  }
  pairing = next;
  adopt(`direct:${next.room}`, next.connection);
  if (RELAY) pairRelay = watch(new RelayClient(RELAY, next.room, me), next.secret).start();
  $("code").value = "";
  render();
}

/** The app paired one way or the other: retire the other way, and make a fresh code for the next device. */
function pairingUsed(winner) {
  const used = pairing;
  pairing = null;
  unwatch(pairRelay);
  pairRelay = null;
  if (used.connection !== winner) used.connection.close("superseded");
  pairingNote = "";
  newPairing();
}

function wireCodeForm() {
  $("code-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = $("code");
    if (!pairing || !input.value.trim()) return;
    const tried = pairing;
    if (!(await tried.enterCode(input.value))) {
      pairingNote = "That code doesn't look right. Check it against Rescriva.";
      render();
      return;
    }
    pairingNote = "Connecting…";
    render();
    setTimeout(() => {
      if (pairing === tried && tried.connection.state === "connecting") {
        pairingNote = "Still not connected. Check that both are on the same Wi-Fi or hotspot.";
        render();
      }
    }, 8_000);
  });
}

// MARK: Connections

function adopt(key, connection) {
  connections.set(key, connection);
  connection.addEventListener("ready", () => {
    if (connection.relayPeerId) redials.delete(connection.relayPeerId);
    if (pairing && connection.secret === pairing.secret) pairingUsed(connection);
    dedupe(connection);
    if (connection.state === "ready") toast(`${connection.app.name} connected`);
    render();
  });
  connection.addEventListener("docs", render);
  connection.addEventListener("transfer", (e) => cards.get(connection)?.transfer(e.detail));
  connection.addEventListener("closed", (e) => {
    connections.delete(key);
    connection.discard();
    const { reason, wasReady } = e.detail;
    const name = connection.app?.name || "The device";
    if (wasReady && reason === "bye") toast(`${name} stopped sharing`);
    if (wasReady && connection.via !== "relay" && REDIAL_REASONS.has(reason)) toast(`Lost the connection to ${name}.`);
    if (reason === "bad-proof") toast("A device couldn't prove it was the one you paired with, so it was disconnected.");
    release(connection);
    if (pairing && connection === pairing.connection) {
      // The waiting connection gave up (a wrong code can do it): make another.
      pairingNote = "That didn't connect. Here's a fresh code. Scan it again.";
      pairing = null;
      setTimeout(newPairing, 600);
    }
    render();
  });
}

/**
 * One card per device, as far as that can be told. The app's `session` says two
 * connections reach the same Share screen, but anyone in the same room can copy it into a
 * hello, so it's a hint, not an identity: the only thing it decides is that a trusted
 * connection (one that proved it holds the secret) replaces an untrusted one with the same
 * session. Two untrusted connections that claim one session are both kept, each with its
 * own check number, which is what the number is for: closing either would let an
 * impostor that connected first, or that is up when the real device redials, keep the
 * real device off the page. The loser's relay peer is held back only while the winner lives.
 */
function dedupe(connection) {
  const session = connection.app?.session;
  if (!session) return;
  for (const other of connections.values()) {
    if (other === connection || other.state !== "ready" || other.app?.session !== session) continue;
    if (!connection.trusted || other.trusted) continue;
    if (other.relayPeerId) retired.set(other.relayPeerId, connection);
    other.close("duplicate");
  }
}

/** The connection is gone, so the peers it beat may be dialed again. */
function release(connection) {
  for (const [id, winner] of [...retired]) {
    if (winner !== connection) continue;
    retired.delete(id);
    for (const [relay, dial] of dialers) {
      const peer = relay.peers.get(id);
      if (peer) dial(peer);
    }
  }
}

// MARK: Rendering

function render() {
  renderStatus();
  renderDevices();
  renderPairing();
}

function renderStatus() {
  const count = [...connections.values()].filter((c) => c.state === "ready").length;
  let text;
  if (mode === "link") {
    if (!RELAY) text = "This link needs the relay, which is turned off here.";
    else if (linkRelay.status === "unavailable") text = "Can't reach the relay. Check this device's internet connection, then reload.";
    else if (count) text = "Connected. Files go straight between the two devices.";
    else if (linkRelay.status === "open" && ![...linkRelay.peers.values()].some((p) => p.role === "app")) {
      text = "Waiting for the device. If its Share screen was closed, scan the new code it shows.";
    } else text = "Connecting to the device that showed you the code…";
  } else if (!RELAY) {
    text = count ? "Paired. Files go straight between the two devices." : "Relay off. Pair with the code.";
  } else {
    text = nearbyStatus(autoRelay.status, count);
  }
  $("status").textContent = text;
  $("status").dataset.tone = mode === "nearby" && autoRelay?.status === "unavailable" ? "warn" : "";
}

/** The status line on the nearby page, with `count` devices connected. */
function nearbyStatus(relayStatus, count) {
  const connected = count === 1 ? "Connected to 1 device." : `Connected to ${count} devices.`;
  if (relayStatus === "open") {
    return count ? `${connected} Others on this network show up here too.` : "Looking for Rescriva on this network.";
  }
  if (relayStatus === "unavailable") {
    return count
      ? `${connected} Can't reach the relay, so others won't appear on their own. Pair them with the code.`
      : "Can't reach the relay, so devices won't appear on their own. Pair with the code instead.";
  }
  return count ? connected : "Connecting…";
}

function renderDevices() {
  const visible = [...connections.values()].filter((c) => c.state === "ready" || (c.via === "relay" && c.state === "connecting"));
  for (const [connection, card] of cards) {
    if (!visible.includes(connection)) {
      card.el.remove();
      cards.delete(connection);
    }
  }
  const list = $("device-list");
  for (const connection of visible) {
    let card = cards.get(connection);
    if (!card) {
      card = new DeviceCard(connection);
      cards.set(connection, card);
      list.append(card.el);
    }
    card.update();
  }
  $("empty").hidden = visible.length > 0;
  $("empty-link").hidden = mode !== "link" || visible.length > 0;
  $("empty-nearby").hidden = mode !== "nearby";
}

function renderPairing() {
  if (mode !== "nearby") return;
  const qr = $("qr");
  if (pairing && qr.dataset.link !== pairing.link) {
    qr.innerHTML = qrSVG(pairing.link, "Pairing code for Rescriva");
    qr.dataset.link = pairing.link;
    $("pair-link").href = pairing.link;
  }
  qr.classList.toggle("waiting", !pairing);
  $("pair-blocked").hidden = !pairing?.blocked;
  $("code-note").textContent = pairingNote;
}

// MARK: Device card

class DeviceCard {
  constructor(connection) {
    this.connection = connection;
    this.rows = new Map();
    this.uploads = new Map();
    this.noted = new Set();
    this.icon = h("span", { class: "device-icon", "aria-hidden": "true" });
    this.name = h("h2", { class: "device-name" });
    this.badge = h("span", { class: "badge" });
    this.check = h("p", { class: "check small", hidden: true });
    this.docList = h("ul", { class: "docs" });
    this.noDocs = h("p", { class: "muted small" }, "Nothing shared right now.");
    this.uploadList = h("ul", { class: "uploads" });
    this.picker = h("input", { type: "file", multiple: true, accept: "application/pdf,image/*", hidden: true, onchange: () => this.send(this.picker.files) });
    this.sendButton = h("button", { class: "button quiet", type: "button", onclick: () => this.picker.click() }, icon("upload"), h("span", {}, "Send files"));
    this.el = h("article", { class: "device card" },
      h("header", { class: "device-head" }, this.icon, h("div", {}, this.name, this.badge)),
      this.check,
      this.docList,
      this.noDocs,
      h("div", { class: "send" }, this.sendButton, this.picker, h("span", { class: "muted small" }, "PDFs and images, or drop them here")),
      this.uploadList,
    );
    this.el.addEventListener("dragover", (e) => {
      if (this.connection.state !== "ready") return;
      e.preventDefault();
      this.el.classList.add("dropping");
    });
    this.el.addEventListener("dragleave", () => this.el.classList.remove("dropping"));
    this.el.addEventListener("drop", (e) => {
      e.preventDefault();
      this.el.classList.remove("dropping");
      this.send(e.dataTransfer.files);
    });
  }

  update() {
    const c = this.connection;
    const device = c.app?.device || "iphone";
    if (this.icon.dataset.device !== device) {
      this.icon.dataset.device = device;
      this.icon.innerHTML = ICONS[device === "mac" ? "mac" : device === "ipad" || device === "tablet" ? "tablet" : "phone"];
    }
    this.name.textContent = c.app?.name || "Rescriva";
    const ready = c.state === "ready";
    this.badge.textContent = !ready ? "Connecting…" : c.trusted ? "Paired: no PINs needed" : "A PIN unlocks each file";
    this.badge.dataset.tone = ready && c.trusted ? "good" : "";
    this.renderCheck(ready && !c.trusted);
    this.el.classList.toggle("connecting", !ready);
    this.sendButton.disabled = !ready;
    this.sendButton.lastChild.textContent = `Send to ${c.app?.name || "Rescriva"}`;

    const ids = new Set(c.docs.map((d) => d.id));
    for (const [id, row] of this.rows) {
      if (!ids.has(id)) {
        row.el.remove();
        this.rows.delete(id);
      }
    }
    for (const doc of c.docs) {
      let row = this.rows.get(doc.id);
      if (!row) {
        row = new DocRow(this, doc);
        this.rows.set(doc.id, row);
      }
      this.docList.append(row.el); // keeps the app's order
      row.update(doc);
    }
    this.noDocs.hidden = !ready || c.docs.length > 0;
  }

  /**
   * On a connection with no secret, nothing proves the card is the person's own device: the
   * PIN only lets this page download. So the card carries the connection's check number, and
   * Rescriva shows the same number next to this computer. The person compares them: a match
   * means the two ends almost certainly see the same connection, a mismatch means they don't.
   */
  renderCheck(shown) {
    this.check.hidden = !shown;
    if (!shown) return;
    const number = this.connection.checkNumber;
    const key = number ?? "none";
    if (this.check.dataset.number === key) return;
    this.check.dataset.number = key;
    if (number) {
      this.check.replaceChildren(
        "Check number ", h("b", { class: "check-number" }, formatCheckNumber(number)),
        ". Before typing a PIN, find this computer in Rescriva's Connected list and check its number: matching numbers mean the card and that row are the same connection. If they differ, this card isn't your device.",
      );
    } else {
      this.check.textContent = "This connection has no check number, so there's no way to tell it's really your device. Don't type a PIN into it.";
    }
  }

  send(files) {
    if (this.connection.state !== "ready") return;
    for (const file of files) this.connection.upload(file);
    this.picker.value = "";
  }

  transfer(t) {
    if (t.direction === "down") {
      this.rows.get(t.docId)?.transfer(t);
      return;
    }
    let row = this.uploads.get(t.id);
    if (!row) {
      row = { el: h("li", { class: "upload" }), name: h("span", { class: "upload-name" }), state: h("span", { class: "muted small" }), bar: progressBar() };
      row.el.append(icon("doc"), h("div", { class: "upload-body" }, row.name, row.bar.el, row.state));
      this.uploads.set(t.id, row);
      this.uploadList.append(row.el);
    }
    row.name.textContent = t.name;
    const who = this.connection.app?.name || "the device";
    row.state.textContent = {
      waiting: "Waiting…",
      asking: `Waiting for someone to tap Accept on ${who}…`,
      moving: `Sending · ${percent(t)}`,
      finishing: "Saving…",
      saved: `Saved in Rescriva on ${who}`,
      declined: {
        type: "Not sent: Rescriva takes PDFs and images",
        busy: `Not sent: ${who} is still receiving another file. Try again in a moment.`,
        size: "Not sent: too big. Rescriva takes PDFs up to 1 GB and images up to 128 MB.",
      }[t.note] || `Not accepted on ${who}`,
      failed: {
        stalled: "Stopped: nothing moved for 30 seconds",
        cancelled: `Cancelled on ${who}`,
        timeout: `No answer from ${who}`,
        "not-saved": `${who} couldn't save it`,
      }[t.note] || "Didn't send",
    }[t.state] || "";
    this.noteStall(t);
    row.bar.set(t.state === "moving" ? t.done / t.size : t.state === "saved" || t.state === "finishing" ? 1 : 0, t.state === "moving" || t.state === "finishing");
    row.el.dataset.state = t.state;
  }

  /** A stalled transfer gets one toast, since its row may be out of view. */
  noteStall(t) {
    if (t.state !== "failed" || t.note !== "stalled" || this.noted.has(t.id)) return;
    this.noted.add(t.id);
    toast(`Nothing moved for 30 seconds, so “${t.name}” was stopped.`);
  }
}

class DocRow {
  constructor(card, doc) {
    this.card = card;
    this.doc = doc;
    this.name = h("span", { class: "doc-name" });
    this.meta = h("span", { class: "muted small" });
    this.action = h("button", { class: "button", type: "button", onclick: () => this.act() });
    this.message = h("p", { class: "doc-message small", "aria-live": "polite" });
    this.bar = progressBar();
    this.pin = h("input", {
      class: "pin-input", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "7", placeholder: "000 000",
      "aria-label": `PIN for ${doc.name}`,
      oninput: () => {
        const digits = this.pin.value.replace(/\D/g, "").slice(0, 6);
        this.pin.value = digits.length > 3 ? `${digits.slice(0, 3)} ${digits.slice(3)}` : digits;
        if (digits.length === 6) this.unlock();
      },
    });
    this.pinForm = h("form", { class: "pin-form", hidden: true, onsubmit: (e) => { e.preventDefault(); this.unlock(); } },
      this.pin,
      h("button", { class: "button", type: "submit" }, "Unlock"),
      h("button", { class: "button quiet", type: "button", onclick: () => this.closePin() }, "Cancel"),
    );
    this.el = h("li", { class: "doc" },
      h("div", { class: "doc-line" }, icon("doc"), h("div", { class: "doc-text" }, this.name, this.meta), this.action),
      this.pinForm, this.bar.el, this.message,
    );
  }

  update(doc) {
    this.doc = doc;
    this.name.textContent = doc.name;
    this.meta.textContent = formatBytes(doc.size);
    const busy = this.transferState && !["done", "failed"].includes(this.transferState);
    this.action.replaceChildren(icon(doc.unlocked ? "download" : "lock"), h("span", {}, doc.unlocked ? "Download" : "Enter PIN"));
    this.action.disabled = busy || this.card.connection.state !== "ready";
    this.action.hidden = !this.pinForm.hidden;
    this.el.dataset.locked = doc.unlocked ? "false" : "true";
  }

  act() {
    if (this.doc.unlocked) this.card.connection.download(this.doc);
    else this.openPin();
  }

  openPin() {
    this.pinForm.hidden = false;
    this.action.hidden = true;
    this.message.textContent = `Type the PIN shown next to “${this.doc.name}” in Rescriva, once the check number above matches.`;
    this.pin.focus();
  }

  closePin() {
    this.pinForm.hidden = true;
    this.action.hidden = false;
    this.pin.value = "";
    this.message.textContent = "";
  }

  async unlock() {
    const pin = this.pin.value.replace(/\D/g, "");
    if (pin.length !== 6 || this.unlocking) return;
    this.unlocking = true;
    this.message.textContent = "Checking…";
    const result = await this.card.connection.unlock(this.doc, pin);
    this.unlocking = false;
    if (result.ok) {
      this.closePin();
      this.doc = { ...this.doc, unlocked: true };
      this.card.connection.download(this.doc);
      return;
    }
    this.pin.value = "";
    this.pin.focus();
    this.message.textContent = {
      wrong: result.left > 0
        ? `That's not it. ${result.left} ${result.left === 1 ? "try" : "tries"} left before the PIN changes.`
        : `That's not it. The PIN has changed. Check Rescriva for the new one, then try again in ${result.retryIn || 30} seconds.`,
      cooldown: `Too many wrong PINs. Try again in ${result.retryIn || 30} seconds, using the new PIN in Rescriva.`,
      locked: "This file isn't shared any more.",
      gone: "This file isn't shared any more.",
      timeout: "No answer from the device. Is Rescriva still open?",
    }[result.reason] || "That didn't work.";
  }

  transfer(t) {
    // The row follows its latest download; an older one being forgotten doesn't speak for it.
    if (t.state === "waiting") this.transferId = t.id;
    if (t.id !== this.transferId) return;
    this.transferState = t.state;
    this.bar.set(t.size ? t.done / t.size : 0, t.state === "moving");
    if (t.state === "requested" || t.state === "waiting") this.message.textContent = "Starting…";
    else if (t.state === "moving") this.message.textContent = `Downloading · ${percent(t)}`;
    else if (t.state === "failed") {
      this.message.textContent = {
        locked: "Locked. Enter the PIN first.",
        gone: "This file isn't shared any more.",
        timeout: "No answer from the device. Is Rescriva still open?",
        stalled: "The download stopped: nothing arrived for 30 seconds. Try again.",
        size: "The device sent more than it said it would, so the download was stopped.",
        type: "Not downloaded: this device isn't paired, so only PDFs, images, Word, PowerPoint, Markdown and text files are taken from it.",
        listed: "Not downloaded: the file isn't the size this device listed, or it's bigger than the page takes from a device it isn't paired with.",
        disk: "Couldn't write the file here. Try again.",
        cancelled: "Cancelled.",
      }[t.note] || "The download stopped. Try again.";
      this.card.noteStall(t);
    } else if (t.state === "done" && t.url) {
      this.message.replaceChildren(
        "Downloaded. ",
        h("a", { href: t.url, download: t.name, onclick: (e) => { e.preventDefault(); saveFile(t.url, t.name); } }, "Save again"),
      );
    } else if (t.state === "done") this.message.textContent = "Downloaded.";
    this.update(this.doc);
  }
}

// MARK: Bits

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value == null || value === false) continue;
    if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else if (key === "hidden") el.hidden = true;
    else el.setAttribute(key, value === true ? "" : value);
  }
  el.append(...children.filter((c) => c != null && c !== false));
  return el;
}

function progressBar() {
  const fill = h("span", { class: "progress-fill" });
  const el = h("div", { class: "progress", hidden: true, role: "progressbar", "aria-valuemin": "0", "aria-valuemax": "100" }, fill);
  return {
    el,
    set(fraction, visible) {
      el.hidden = !visible;
      const value = Math.round(Math.max(0, Math.min(1, fraction)) * 100);
      fill.style.width = `${value}%`;
      el.setAttribute("aria-valuenow", value);
    },
  };
}

function percent(t) {
  return t.size ? `${Math.floor((t.done / t.size) * 100)}%` : "";
}

/** Like the app's sizes (Apple's file sizes): 1 KB is 1,000 bytes, so both show "731 KB". */
function formatBytes(bytes) {
  if (bytes == null || !(bytes >= 0)) return "";
  if (bytes < 1000) return `${bytes} bytes`;
  if (Math.round(bytes / 1e3) < 1000) return `${Math.round(bytes / 1e3)} KB`;
  if (bytes < 1e9) return `${(bytes / 1e6).toFixed(1)} MB`;
  return `${(bytes / 1e9).toFixed(2)} GB`;
}

let toastTimer;
function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.classList.add("shown");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("shown"), 3_500);
}

function describeBrowser() {
  const ua = navigator.userAgent;
  const browser = /Edg(e|A|iOS)?\//.test(ua) ? "Edge"
    : /Firefox\/|FxiOS/.test(ua) ? "Firefox"
    : /OPR\//.test(ua) ? "Opera"
    : /Chrome\/|CriOS/.test(ua) ? "Chrome"
    : /Safari\//.test(ua) ? "Safari"
    : "A browser";
  const iPad = /iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
  const os = iPad ? "iPad" : /iPhone/.test(ua) ? "iPhone" : /Android/.test(ua) ? "Android"
    : /Windows/.test(ua) ? "Windows" : /CrOS/.test(ua) ? "Chromebook" : /Mac OS X/.test(ua) ? "Mac" : /Linux/.test(ua) ? "Linux" : "";
  const device = iPad || (/Android/.test(ua) && !/Mobile/.test(ua)) ? "tablet" : /iPhone|Android.*Mobile/.test(ua) ? "phone" : "computer";
  return { name: os ? `${browser} on ${os}` : browser, device };
}

const stroke = (d) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
const ICONS = {
  phone: stroke('<rect x="6.5" y="2.5" width="11" height="19" rx="2.5"/><path d="M10.5 18.5h3"/>'),
  tablet: stroke('<rect x="4" y="2.5" width="16" height="19" rx="2.5"/><path d="M10.5 18.5h3"/>'),
  mac: stroke('<rect x="3" y="4" width="18" height="12" rx="1.8"/><path d="M1.5 19.5h21"/>'),
  doc: stroke('<path d="M14 2.5H7A2.5 2.5 0 0 0 4.5 5v14A2.5 2.5 0 0 0 7 21.5h10a2.5 2.5 0 0 0 2.5-2.5V8z"/><path d="M14 2.5V8h5.5M8.5 13h7M8.5 16.5h5"/>'),
  lock: stroke('<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>'),
  download: stroke('<path d="M12 3.5v12M7 11l5 5 5-5M4.5 20.5h15"/>'),
  upload: stroke('<path d="M12 16V4M7 8.5l5-5 5 5M4.5 20.5h15"/>'),
};

function icon(name) {
  const el = h("span", { class: "icon", "aria-hidden": "true" });
  el.innerHTML = ICONS[name];
  return el;
}

if ("serviceWorker" in navigator && location.protocol === "https:") {
  navigator.serviceWorker.register("sw.js").catch(() => {});
}

start();

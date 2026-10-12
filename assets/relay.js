// The page's side of the relay (PROTOCOL.md §2): who's in the room, and passing
// connection set-up messages to them.
//
// Events: "status" (detail: "connecting" | "open" | "unavailable"), "peers"
// (detail: [peer]), "join" / "leave" (detail: peer), "signal" (detail: {from, data}).

const PING_EVERY = 25_000;
const OPEN_TIMEOUT = 6_000;

export class RelayClient extends EventTarget {
  #ws = null;
  #ping = null;
  #retry = null;
  #failures = 0;
  #stopped = false;

  /** `url` is the relay's WebSocket address; `room` is "auto" or a room id. */
  constructor(url, room, me) {
    super();
    this.url = url;
    this.room = room;
    this.me = me;
    this.status = "connecting";
    this.peers = new Map();
  }

  start() {
    this.#connect();
    return this;
  }

  stop() {
    this.#stopped = true;
    clearTimeout(this.#retry);
    clearInterval(this.#ping);
    this.#ws?.close();
    this.#ws = null;
  }

  signal(to, data) {
    if (this.#ws?.readyState === WebSocket.OPEN) {
      this.#ws.send(JSON.stringify({ t: "signal", to, data }));
    }
  }

  #emit(type, detail) {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }

  #setStatus(status) {
    if (this.status === status) return;
    this.status = status;
    this.#emit("status", status);
  }

  #connect() {
    const url = new URL(this.url);
    url.searchParams.set("room", this.room);
    url.searchParams.set("role", "web");
    url.searchParams.set("name", this.me.name);
    url.searchParams.set("device", this.me.device);
    let ws;
    try {
      ws = new WebSocket(url);
    } catch {
      this.#retryLater();
      return;
    }
    this.#ws = ws;
    const timeout = setTimeout(() => ws.readyState === WebSocket.CONNECTING && ws.close(), OPEN_TIMEOUT);

    ws.onopen = () => {
      clearTimeout(timeout);
      this.#failures = 0;
      this.#setStatus("open");
      this.#ping = setInterval(() => ws.send('{"t":"ping"}'), PING_EVERY);
    };
    ws.onmessage = (event) => {
      let message;
      try {
        message = JSON.parse(event.data);
      } catch {
        return;
      }
      this.#receive(message);
    };
    ws.onclose = () => {
      clearTimeout(timeout);
      clearInterval(this.#ping);
      if (this.#ws !== ws) return;
      this.#ws = null;
      for (const peer of this.peers.values()) this.#emit("leave", peer);
      this.peers.clear();
      this.#retryLater();
    };
  }

  #receive(message) {
    switch (message.t) {
      case "welcome":
        this.id = message.id;
        this.peers = new Map((message.peers || []).map((p) => [p.id, p]));
        this.#emit("peers", [...this.peers.values()]);
        break;
      case "join":
        if (message.peer?.id) {
          this.peers.set(message.peer.id, message.peer);
          this.#emit("join", message.peer);
        }
        break;
      case "leave": {
        const peer = this.peers.get(message.id);
        this.peers.delete(message.id);
        if (peer) this.#emit("leave", peer);
        break;
      }
      case "signal":
        if (message.from && message.data) this.#emit("signal", { from: message.from, data: message.data });
        break;
    }
  }

  #retryLater() {
    if (this.#stopped) return;
    this.#failures += 1;
    // Two misses in a row and the relay counts as out of reach (the page says so
    // and leans on QR pairing), but it keeps trying in the background.
    this.#setStatus(this.#failures >= 2 ? "unavailable" : "connecting");
    const delay = Math.min(30_000, 1_000 * 2 ** Math.min(this.#failures, 5));
    this.#retry = setTimeout(() => this.#connect(), delay);
  }
}

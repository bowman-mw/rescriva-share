# Rescriva Share

The web side of **Share Nearby** in [Rescriva](https://rescriva.com). It moves files between the
Rescriva app (iPhone, iPad, Mac) and any browser, directly from device to device and encrypted.
It's served by GitHub Pages at **https://share.rescriva.com**.

- **Same network:** open the page, open Share Nearby in Rescriva, and the device's shared
  documents appear. Each one needs the PIN shown in the app to download. The PIN lets the page
  download; it doesn't prove the card is your device, so the page and the app both show a
  nine-digit check number for the connection. Compare them before typing a PIN: matching
  numbers mean the card and the app's row are the same connection.
- **The app's QR code:** scanning it with a phone opens this page already paired, with no PINs.
- **No relay or internet:** Rescriva scans the QR code on this page. If the computer won't
  accept the connection, the app shows a short code to type here.

Files never go through a server. The relay in `relay/` only passes the few lines that set up the
connection. See [PROTOCOL.md](PROTOCOL.md).

## Layout

| Path | What it is |
|---|---|
| `index.html`, `assets/` | The page. Plain ES modules, no build step. |
| `assets/config.js` | The relay URL and the app certificate's fingerprint. |
| `assets/vendor/qrcode.js` | [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4, MIT. |
| `sw.js` | Keeps a copy of the page so it opens offline (hotspot with no signal). |
| `tests/` | Checks the page's encodings and the check number against PROTOCOL.md's test vectors, and what an unpaired device's file may be saved as. |
| `relay/` | The Cloudflare Worker relay and a local stand-in. See `relay/README.md`. |
| `CNAME`, `.nojekyll` | GitHub Pages settings. |

## Running it locally

```bash
python3 -m http.server 8770 --bind 127.0.0.1
```

```bash
python3 relay/dev_relay.py
```

Then open `http://127.0.0.1:8770/?relay=ws://127.0.0.1:8787/ws`, or use `?relay=off` to try
pairing with no relay. The `?relay=` override only works on a page served from localhost. Open
`http://127.0.0.1:8770/tests/` to run the tests.

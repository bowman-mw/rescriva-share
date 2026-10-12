// QR codes as SVG, drawn from the vendored qrcode-generator (assets/vendor/qrcode.js,
// MIT, Kazuhiko Arase), which index.html loads as a classic script.

const QUIET = 4;

export function qrSVG(text, label) {
  const qr = window.qrcode(0, "M");
  qr.addData(text, "Byte");
  qr.make();
  const count = qr.getModuleCount();
  const size = count + QUIET * 2;
  let path = "";
  for (let row = 0; row < count; row++) {
    for (let col = 0; col < count; col++) {
      if (qr.isDark(row, col)) path += `M${col + QUIET} ${row + QUIET}h1v1h-1z`;
    }
  }
  return `<svg viewBox="0 0 ${size} ${size}" role="img" aria-label="${label}" shape-rendering="crispEdges">` +
    `<rect width="${size}" height="${size}" fill="#fff"/><path d="${path}" fill="#1d150d"/></svg>`;
}

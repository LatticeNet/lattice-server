// Renders the notification icons internal/server embeds and serves at
// /notify-icons/ (design-notify-abstraction section 13.2).
//
// Input: internal/server/notifyicons/icons.json, the (glyph, tone) pairs the
// catalogue can produce, written by the Go test
// TestNotifyIconManifestMatchesCatalogue with -update-notify-icons.
// Output: one PNG per pair in internal/server/notifyicons/, a full-bleed
// 180 px square in the tone's fill with the lucide glyph in white, so the
// iOS icon mask and both iOS themes read it. PNGs no pair names are removed.
//
// The glyphs come from lucide-static at the version the console's
// lucide-vue-next uses, so a push and its Sent log row show the same glyph.

import { readFileSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Resvg } from '@resvg/resvg-js';

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, '..', '..', 'internal', 'server', 'notifyicons');
const manifestPath = join(outDir, 'icons.json');
const require = createRequire(import.meta.url);
const lucideIcons = join(dirname(require.resolve('lucide-static/package.json')), 'icons');

// Edge of every icon in pixels; the Go test checks the same size.
const SIZE = 180;
// The glyph's box: 60% of the edge, centred, so it also fits a circular mask
// (its corners sit 76 px from the centre, inside the 90 px radius).
const GLYPH = 108;

// Tone fills: the light-mode values of the console's semantic tokens in
// lattice-dashboard/src/style/app.css, converted from OKLCH to sRGB with
// per-channel clipping, which is what a browser shows on an sRGB display.
// destructive, warning and info sit just outside sRGB and clip; success and
// the muted grey do not. The grey is --muted-foreground: --muted itself is
// too light to carry a white glyph.
const TONES = {
  critical: { token: '--destructive', oklch: [0.55, 0.231, 27.5], hex: '#d8000b' },
  warning: { token: '--warning', oklch: [0.72, 0.16, 73], hex: '#e09200' },
  notice: { token: '--info', oklch: [0.6, 0.14, 240], hex: '#0089ca' },
  recovered: { token: '--success', oklch: [0.62, 0.16, 150], hex: '#20a04e' },
  quiet: { token: '--muted-foreground', oklch: [0.524, 0.022, 281], hex: '#676977' },
};
const GLYPH_INK = '#ffffff';

// OKLCH to sRGB hex, Bjorn Ottosson's OKLab matrices.
function oklchToHex([L, C, h]) {
  const hr = (h * Math.PI) / 180;
  const a = C * Math.cos(hr);
  const b = C * Math.sin(hr);
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  const linear = [
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
  ];
  const encode = (x) => (x <= 0.0031308 ? 12.92 * x : 1.055 * x ** (1 / 2.4) - 0.055);
  return `#${linear
    .map((x) => Math.round(Math.min(1, Math.max(0, encode(x))) * 255).toString(16).padStart(2, '0'))
    .join('')}`;
}

for (const [tone, t] of Object.entries(TONES)) {
  const derived = oklchToHex(t.oklch);
  if (derived !== t.hex) {
    throw new Error(`tone ${tone}: ${t.token} oklch(${t.oklch.join(' ')}) converts to ${derived}, not the recorded ${t.hex}`);
  }
}

// glyphBody is a lucide icon's drawing: the children of its <svg>, with the
// license comment dropped and currentColor inked white.
function glyphBody(icon) {
  let svg;
  try {
    svg = readFileSync(join(lucideIcons, `${icon}.svg`), 'utf8');
  } catch {
    throw new Error(`lucide-static has no icon "${icon}"; check the catalogue entry or the pinned version`);
  }
  const open = svg.indexOf('>', svg.indexOf('<svg'));
  const close = svg.lastIndexOf('</svg>');
  if (open < 0 || close < 0) {
    throw new Error(`${icon}.svg is not an <svg> document`);
  }
  return svg
    .slice(open + 1, close)
    .replace(/<!--[\s\S]*?-->/g, '')
    .replaceAll('currentColor', GLYPH_INK)
    .trim();
}

function iconSVG(icon, tone) {
  const fill = TONES[tone]?.hex;
  if (!fill) {
    throw new Error(`unknown tone "${tone}"`);
  }
  const offset = (SIZE - GLYPH) / 2;
  const scale = GLYPH / 24;
  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${SIZE}" height="${SIZE}" viewBox="0 0 ${SIZE} ${SIZE}">`,
    `<rect width="${SIZE}" height="${SIZE}" fill="${fill}"/>`,
    `<g transform="translate(${offset} ${offset}) scale(${scale})" fill="none" stroke="${GLYPH_INK}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">`,
    glyphBody(icon),
    '</g>',
    '</svg>',
  ].join('\n');
}

const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const wanted = new Set();
for (const { file, icon, tone } of manifest) {
  if (file !== `${icon}-${tone}.png`) {
    throw new Error(`manifest entry ${file} does not name ${icon}-${tone}.png`);
  }
  const png = new Resvg(iconSVG(icon, tone), {
    fitTo: { mode: 'width', value: SIZE },
    font: { loadSystemFonts: false },
  })
    .render()
    .asPng();
  writeFileSync(join(outDir, file), png);
  wanted.add(file);
}

const removed = [];
for (const name of readdirSync(outDir)) {
  if (name.endsWith('.png') && !wanted.has(name)) {
    unlinkSync(join(outDir, name));
    removed.push(name);
  }
}

console.log(`wrote ${wanted.size} icons to ${outDir}`);
if (removed.length > 0) {
  console.log(`removed icons no catalogue entry produces: ${removed.join(', ')}`);
}

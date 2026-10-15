# Notification icons

`generate.mjs` renders the PNGs a Bark push shows as its icon
(design-notify-abstraction section 13.2). The server embeds them from
`internal/server/notifyicons/` and serves them at `/notify-icons/<icon>-<tone>.png`.

Each icon is a 180 px full-bleed square in its tone's fill with the lucide
glyph in white. The tone fills are the light-mode values of the console's
semantic tokens in `lattice-dashboard/src/style/app.css`, converted to sRGB;
the script records the hex values and fails if they no longer match the OKLCH
source. The glyphs come from `lucide-static` pinned to the version of the
console's `lucide-vue-next`, so a push and its Sent log row show the same
glyph. The rasteriser is `@resvg/resvg-js`, which ships prebuilt binaries for
macOS and Linux (x64 and arm64) and needs no system libraries. Its output is
byte-for-byte reproducible for the same pinned versions.

## Regenerate after a catalogue change

A change to `internal/server/notify_catalogue.go` that adds a glyph or changes
an entry's tone fails `TestNotifyIconManifestMatchesCatalogue` and
`TestNotifyIconsCoverCatalogue` until the icons are regenerated. From the
repository root:

```sh
go test ./internal/server -run '^TestNotifyIconManifestMatchesCatalogue$' -update-notify-icons
cd scripts/notify-icons
npm ci
npm run generate
```

The first command rewrites `internal/server/notifyicons/icons.json`, the list of
(glyph, tone) pairs the catalogue can produce. The script renders one PNG per
pair and removes PNGs no pair names. Commit `icons.json` and the PNGs together.

The server sends `Cache-Control: public, max-age=31536000, immutable`, as the
design asks, so a cache between the server and the phone may keep showing an
old picture for up to a year when a lucide upgrade redraws a glyph under the
same name. Pushes already delivered keep the icon they arrived with either
way, so a redraw is cosmetic.

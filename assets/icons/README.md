# Cleanton Icons — Source of Truth

This directory intentionally contains **no extracted Font Awesome SVG/PNG assets.**

## Why this directory is (deliberately) empty of glyph files

Cleanton's UIs reference Font Awesome Pro 7 icons. The FA Pro Plus license does
**not** permit redistributing the raw SVG icon package, so we do not vendor
extracted SVGs here (`doc/ICONS.md` §2, §6). Instead, both UIs render icons
**directly from the licensed OTF font files we are permitted to embed**, which
live in [`../fonts/`](../fonts/):

- `Font Awesome 7 Pro-Solid-900.otf`
- `Font Awesome 7 Brands-Regular-400.otf`

## How each UI resolves its icons

| UI | Mechanism | Asset format |
|---|---|---|
| `cleanton-app` (Slint GUI) | The shared `FaIcon` component renders FA glyph **codepoints** with `font-family: "Font Awesome 7 Pro"` / `"Font Awesome 7 Brands"`. The OTFs are embedded via `include_bytes!` in `src/main.rs` and registered through Fontique at startup. | OTF glyphs (no separate asset files) |
| `cleanton-ui` (ratatui TUI) | Honest, font-independent **Unicode** symbols (e.g. `⚡ ⚠ ⓘ ✓`) rendered as ordinary text cells, consistent with the existing TUI. No proprietary font is assumed for the terminal grid. | Unicode text (no asset files) |

Because the code references **font glyphs, not files in this directory**, there
are zero missing-asset gaps: there is nothing here to be missing.

## Guarantee: no unresolved glyphs

`crates/cleanton-app/tests/icons.rs` parses both embedded OTFs and asserts that
**every** FA codepoint referenced anywhere in `ui/*.slint` and `src/main.rs`
resolves to a real glyph. If a new icon is added that the bundled fonts cannot
render, that test fails. Run it with:

```
cargo test -p cleanton-app --test icons
```

## Adding a new icon

1. Pick the FA icon and its codepoint (prefer Solid for clarity at small sizes;
   set `brand: true` for brand logos).
2. Use it through `FaIcon` in the Slint UI (never emoji or placeholder symbols).
3. Add its codepoint to the appropriate list in `tests/icons.rs` so the
   no-missing-glyph guarantee continues to cover it.

If a future requirement genuinely needs standalone raster/vector icon files in
this directory, they must be either self-authored or sourced under a license that
permits redistribution — not extracted from the FA Pro package.

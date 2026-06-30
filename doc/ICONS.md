# Cleanton — Icon Strategy (FontAwesome Pro)

> How we integrate FontAwesome Pro Plus 7.2.0 icons into Cleanton's native GUI and terminal UI.

---

## 1. The Challenge

Cleanton has two UI surfaces with different rendering constraints:

- `cleanton-app` is a native Slint GUI. It renders FA Pro text glyphs through embedded
  Font Awesome Pro Solid and Brands font files in `assets/fonts/`.
- `cleanton-ui` is a terminal UI. Terminals render in a character grid, so the TUI needs
  Nerd Font / Unicode / ASCII degradation instead of assuming a proprietary font.

The shared strategy must:

1. Works in **any** modern terminal (iTerm2, Ghostty, WezTerm, Kitty, Terminal.app)
2. Look **beautiful** — not just ASCII art
3. Leverages our **FA Pro Plus 7.2.0** license
4. Degrades gracefully when the terminal doesn't support advanced rendering

---

## 2. Native GUI Rendering

The Slint app uses a central `FaIcon` component in `crates/cleanton-app/ui/widgets.slint`.
This component renders Font Awesome glyph codepoints with:

```slint
font-family: brand ? "Font Awesome 7 Brands" : "Font Awesome 7 Pro";
font-weight: 900;
```

Current GUI icon usage includes:

| UI Area | FA Icon | Codepoint | Usage |
|---|---|---:|---|
| App mark | `broom` | `\u{f51a}` | Cleanton brand mark |
| Dashboard | `chart-pie` | `\u{f200}` | Dashboard navigation |
| Scanner | `magnifying-glass` | `\u{f002}` | Scan actions/navigation |
| Results | `list-check` | `\u{f0ae}` | Plan review |
| Services | `server` | `\u{f233}` | Service management |
| Settings | `gear` | `\u{f013}` | Settings |
| Review | `file-lines` | `\u{f15c}` | Dry-run review |
| Cancel | `stop` | `\u{f04d}` | Cancel operation |
| Trash action | `trash-can` | `\u{f2ed}` | Move to Trash action |
| Delete action | `trash` | `\u{f1f8}` | Permanent delete action |
| Archive action | `box-archive` | `\u{f187}` | Archive action |
| Immutable | `lock` | `\u{f023}` | Protected service |
| Rust | `rust` | `\u{e07a}` | Brands category icon |
| Swift | `swift` | `\u{f8e1}` | Brands category icon |
| Node | `node-js` | `\u{f3d3}` | Brands category icon |
| Python | `python` | `\u{f3e2}` | Brands category icon |
| Docker | `docker` | `\u{f395}` | Brands category icon |
| ML / AI | `microchip-ai` | `\u{e1ec}` | Model/cache category |

Do not add emoji or arbitrary geometric symbols in the Slint app when a matching FA Pro icon
exists. Add new app icons by extending the glyph usage through `FaIcon`.

The repository intentionally does **not** vendor the full FA Pro package. The GUI embeds only
the licensed OTF files it needs. Public distribution requires an explicit Font Awesome license
review before release artifacts are published.

## 3. Terminal Multi-Tier Icon Rendering

Cleanton uses a tiered approach:

### Tier 1: Nerd Font Glyphs (Default — `nerd-font` feature)

[Nerd Fonts](https://www.nerdfonts.com/) patch popular programming fonts with ~9000 glyphs,
including a subset of FontAwesome icons. Most developer terminals already use a Nerd Font.

**How it works:**
- Map each cleanton icon name to its Nerd Font Unicode codepoint
- Render as a single character in the terminal grid
- FA icons included in Nerd Fonts: ~700 icons from FA Free

**Advantages:** Zero dependencies, works everywhere with a Nerd Font, single character width.

**Example mappings:**

| Icon Name | Nerd Font Glyph | Codepoint | Usage |
|---|---|---|---|
| `folder` | 󰉋 | `\u{F0257}` | Directory entries |
| `file` | 󰈔 | `\u{F0214}` | File entries |
| `trash` | 󰩹 | `\u{F0A79}` | Delete action |
| `rust` |  | `\u{E7A8}` | Rust projects |
| `node` |  | `\u{E718}` | Node.js projects |
| `python` |  | `\u{E73C}` | Python projects |
| `swift` |  | `\u{E755}` | Swift projects |
| `docker` |  | `\u{E7B0}` | Docker |
| `git` |  | `\u{E702}` | Git repos |
| `brain` | 󰧑 | `\u{F09D1}` | ML/AI |
| `shield` | 󰒃 | `\u{F0483}` | Safety indicator |
| `chart` | 󰄧 | `\u{F0127}` | Statistics |
| `check` |  | `\u{F00C}` | Success |
| `xmark` |  | `\u{F00D}` | Error/remove |
| `warning` |  | `\u{F071}` | Warning |
| `spinner` | 󰑙 | `\u{F0459}` | Loading |
| `download` |  | `\u{F019}` | Size/download |
| `clock` |  | `\u{F017}` | Age/time |
| `search` |  | `\u{F002}` | Scanning |
| `gear` |  | `\u{F013}` | Settings |
| `broom` | 󰃢 | `\u{F00E2}` | Clean action |
| `hard-drive` |  | `\u{F0A0}` | Disk usage |
| `database` |  | `\u{F1C0}` | Datasets |
| `box` |  | `\u{F187}` | Packages |
| `robot` | 󰚩 | `\u{F06A9}` | AI tools |

### Tier 2: Unicode Symbols (Fallback — `unicode` mode)

For terminals without Nerd Fonts:

| Icon Name | Unicode | Character |
|---|---|---|
| `folder` | `\u{1F4C1}` | 📁 |
| `file` | `\u{1F4C4}` | 📄 |
| `trash` | `\u{1F5D1}` | 🗑 |
| `check` | `\u{2714}` | ✔ |
| `xmark` | `\u{2718}` | ✘ |
| `warning` | `\u{26A0}` | ⚠ |
| `gear` | `\u{2699}` | ⚙ |
| `brain` | `\u{1F9E0}` | 🧠 |

### Tier 3: ASCII (Minimal — `ascii` mode)

For bare-bones terminals:

| Icon Name | ASCII |
|---|---|
| `folder` | `[D]` |
| `file` | `[F]` |
| `check` | `[✓]` |
| `xmark` | `[x]` |
| `warning` | `[!]` |

---

## 4. Hero Icons (SVG → Halfblock — `icons-svg` feature)

For the **dashboard screen**, we render a few large "hero" icons using the full FA Pro SVG files.
These are rendered using the `resvg` crate to rasterize the SVG, then converted to terminal
"half-block" characters (▀▄█░▒▓) for double-resolution rendering.

**How it works:**
1. At build time, embed selected FA Pro SVGs via `include_str!()`
2. At runtime, parse SVG with `usvg`, rasterize with `resvg` to a small bitmap (e.g., 16×16 px)
3. Convert bitmap to half-block terminal art (each terminal cell = 2 vertical pixels)
4. Cache the rendered result

**Selected hero icons from FA Pro Plus:**

| Icon | FA Pro Path | Usage |
|---|---|---|
| `hard-drive` | `svgs/solid/hard-drive.svg` | Dashboard: disk usage |
| `broom-wide` | `svgs/solid/broom-wide.svg` | Dashboard: clean action |
| `shield-check` | `svgs/solid/shield-check.svg` | Dashboard: safety |
| `chart-pie` | `svgs/solid/chart-pie.svg` | Dashboard: analysis |
| `microchip-ai` | `svgs/solid/microchip-ai.svg` | ML classification |
| `gauge-high` | `svgs/solid/gauge-high.svg` | Performance |
| `layer-group` | `svgs/solid/layer-group.svg` | Categories |
| `sparkles` | `svgs/solid/sparkles.svg` | Intelligent cleanup |

### FA Pro Styles Available

The FA Pro Plus 7.2.0 desktop package includes these styles:

| Style | Directory | Description |
|---|---|---|
| **Solid** | `svgs/solid/` | Filled icons — primary style |
| **Regular** | `svgs/regular/` | Outlined icons |
| **Light** | `svgs/light/` | Thin outlined icons |
| **Thin** | `svgs/thin/` | Ultra-thin icons |
| **Duotone** | `svgs/duotone/` | Two-tone layered icons |
| **Sharp Solid** | `svgs/sharp-solid/` | Geometric solid |
| **Sharp Regular** | `svgs/sharp-regular/` | Geometric outlined |
| **Sharp Light** | `svgs/sharp-light/` | Geometric thin |
| **Sharp Thin** | `svgs/sharp-thin/` | Geometric ultra-thin |
| **Sharp Duotone** | `svgs/sharp-duotone-solid/` | Geometric two-tone |
| **Brands** | `svgs/brands/` | Brand logos (Docker, Rust, etc.) |

**For cleanton**, we primarily use **Solid** for clarity at small sizes, with **Duotone** for hero icons
where the two-tone effect translates well to terminal coloring.

---

## 5. Terminal Implementation: Icon Widget

```rust
/// Icon rendering modes, in order of visual quality
pub enum IconMode {
    /// Use Nerd Font glyphs (single character)
    NerdFont,
    /// Use Unicode emoji/symbols
    Unicode,
    /// Use ASCII representations
    Ascii,
}

/// Render an icon as a ratatui Span
pub fn icon(name: &str, mode: IconMode) -> Span<'static> {
    match mode {
        IconMode::NerdFont => {
            let glyph = NERD_FONT_MAP.get(name).unwrap_or(&"\u{F128}"); // question mark
            Span::styled(*glyph, Style::default().fg(icon_color(name)))
        }
        IconMode::Unicode => {
            let symbol = UNICODE_MAP.get(name).unwrap_or(&"?");
            Span::raw(*symbol)
        }
        IconMode::Ascii => {
            let ascii = ASCII_MAP.get(name).unwrap_or(&"[?]");
            Span::raw(*ascii)
        }
    }
}

/// Get the themed color for a specific icon
fn icon_color(name: &str) -> Color {
    match name {
        "rust" => Color::Rgb(222, 165, 132),    // Rust orange
        "node" => Color::Rgb(104, 159, 56),     // Node green
        "python" => Color::Rgb(55, 118, 171),   // Python blue
        "swift" => Color::Rgb(240, 81, 56),     // Swift orange
        "docker" => Color::Rgb(36, 150, 237),   // Docker blue
        "check" => Color::Rgb(34, 197, 94),     // Green
        "xmark" => Color::Rgb(239, 68, 68),     // Red
        "warning" => Color::Rgb(250, 204, 21),  // Amber
        _ => Color::Rgb(220, 220, 235),         // Default text color
    }
}
```

---

## 6. Build-Time Asset Pipeline

```
FA Pro Plus package (svgs/)
        │
        ▼
  [build.rs script]
        │
        ├── Embeds selected SVGs as include_str!()
        ├── Generates Nerd Font mapping table
        └── Pre-rasterizes hero icons to cached bitmaps
        │
        ▼
  [Compiled into binary]
        │
        ├── Zero runtime file I/O for icons
        └── Works on any machine without FA Pro installed
```

> **Important**: Do not commit the full FA Pro package. Only curated icons required by the UI may be embedded, and the exact distribution rights must be checked against the active FontAwesome license before any public release.

---

## 7. FA Pro Icon Selection Guidelines

When adding new icons to cleanton, follow these rules:

1. **Slint app uses FA Pro glyphs** — route native GUI icons through `FaIcon`, not emoji or placeholder symbols.
2. **Check Nerd Font first for TUI** — if the icon exists in Nerd Fonts, use Tier 1 (no SVG needed).
3. **Brand icons** — set `brand-icon: true` in Slint for brand logos (Rust, Docker, etc.).
4. **Hero icons only** — only embed SVGs for dashboard-level hero icons (max ~10 total).
5. **Solid style** — prefer `svgs/solid/` for best clarity at small sizes.
6. **Test all terminal tiers** — every TUI icon must have mappings in Nerd Font, Unicode, and ASCII.

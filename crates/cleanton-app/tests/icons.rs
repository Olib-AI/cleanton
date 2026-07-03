//! Verifies that every Font Awesome glyph the GUI references actually resolves
//! in the bundled OTF fonts.
//!
//! Cleanton renders icons **directly from the embedded FA Pro Solid / Brands OTF
//! files** (`assets/fonts/`) rather than vendoring extracted FA Pro SVG assets,
//! because the FA Pro Plus license does not permit redistributing the raw SVG
//! package (see `doc/ICONS.md` §2 and `assets/icons/README.md`). The OTF is the
//! single source of truth, so this test guarantees there are no missing-asset
//! gaps: each codepoint referenced in `ui/*.slint` and `src/main.rs` must have a
//! glyph in the corresponding embedded font.

use ttf_parser::Face;

const FA_PRO_SOLID: &[u8] =
    include_bytes!("../../../assets/fonts/Font Awesome 7 Pro-Solid-900.otf");
const FA_BRANDS_REGULAR: &[u8] =
    include_bytes!("../../../assets/fonts/Font Awesome 7 Brands-Regular-400.otf");

/// Solid-style codepoints referenced by the GUI (sidebar, tiles, buttons,
/// capacity panel, action icons, dark/light toggle, service status dots, locks).
const SOLID_REFS: &[(u32, &str)] = &[
    (0xf51a, "broom (app mark)"),
    (0xf200, "chart-pie (dashboard)"),
    (0xf002, "magnifying-glass (scanner)"),
    (0xf0ae, "list-check (results)"),
    (0xf233, "server (services)"),
    (0xf013, "gear (settings)"),
    (0xf185, "sun (light toggle)"),
    (0xf186, "moon (dark toggle)"),
    (0xf2ed, "trash-can (trash action)"),
    (0xf07b, "folder (scanned)"),
    (0xf15b, "file (files)"),
    (0xf0a0, "hard-drive (disk capacity)"),
    (0xf071, "triangle-exclamation (warnings)"),
    (0xe1ec, "microchip-ai (ml category)"),
    (0xf15c, "file-lines (refresh plan)"),
    (0xf00c, "check (confirm)"),
    (0xf1f8, "trash (delete / empty)"),
    (0xf04b, "play (running/attempted)"),
    (0xf05e, "ban (skipped)"),
    (0xf021, "rotate (refresh services)"),
    (0xf023, "lock (protected)"),
    (0xf111, "circle (status dot)"),
    (0xf04d, "stop (cancel)"),
    (
        0xf187,
        "box-archive (archive action / installer suggestion)",
    ),
    (0xf05a, "circle-info (snapshot note)"),
    (0xf03d, "video (screen-recording suggestion)"),
    (0xf03e, "image (screenshot suggestion)"),
    (0xf053, "chevron-left (category carousel paging)"),
    (
        0xf054,
        "chevron-right (collapsed plan group / carousel paging)",
    ),
    (0xf062, "arrow-up (package update)"),
    (0xf068, "minus (indeterminate selection)"),
    (0xf078, "chevron-down (expanded plan group)"),
    (0xf0c5, "copy (duplicate-set suggestion)"),
    (0xf0c7, "floppy-disk (other category)"),
    (0xf0e2, "rotate-left (restart service)"),
    (0xf0eb, "lightbulb (suggestions panel)"),
    (0xf110, "spinner (loading)"),
    (0xf126, "code-branch (re-clonable repo suggestion)"),
    (0xf1b3, "cubes (packages)"),
    (0xf35d, "up-right-from-square (reveal in Finder)"),
    (0xf544, "robot (ai tools category)"),
];

/// Brand-style codepoints referenced by the GUI (ecosystem category icons).
const BRAND_REFS: &[(u32, &str)] = &[
    (0xe07a, "rust"),
    (0xf8e1, "swift"),
    (0xf3d3, "node-js"),
    (0xf3e2, "python"),
    (0xf395, "docker"),
    (0xf17b, "android (jvm/android category)"),
];

#[test]
fn every_referenced_glyph_resolves_in_the_bundled_otf() {
    let solid = Face::parse(FA_PRO_SOLID, 0).expect("parse FA Pro Solid OTF");
    let brands = Face::parse(FA_BRANDS_REGULAR, 0).expect("parse FA Brands OTF");

    for &(codepoint, name) in SOLID_REFS {
        let ch = char::from_u32(codepoint).expect("valid codepoint");
        assert!(
            solid.glyph_index(ch).is_some(),
            "missing SOLID glyph U+{codepoint:04X} ({name}) in bundled FA Pro Solid OTF"
        );
    }

    for &(codepoint, name) in BRAND_REFS {
        let ch = char::from_u32(codepoint).expect("valid codepoint");
        assert!(
            brands.glyph_index(ch).is_some(),
            "missing BRAND glyph U+{codepoint:04X} ({name}) in bundled FA Brands OTF"
        );
    }
}

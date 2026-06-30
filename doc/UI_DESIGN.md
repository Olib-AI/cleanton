# Cleanton — UI Design Specification

> Visual design language, layout specifications, and animation details.
> Cleanton ships two presentation layers:
> 1. **`cleanton-app`** — Native macOS GUI powered by **Slint** (primary). SwiftUI-inspired
>    design with hardware-accelerated rendering, glassmorphism, and smooth animations.
>    Markup lives in `crates/cleanton-app/ui/*.slint`.
> 2. **`cleanton-ui`** — Terminal TUI powered by **ratatui + crossterm** (fallback).
>    Used for headless servers, SSH sessions, and CI pipelines.

---

## 1. Design Philosophy

Cleanton's UI should feel like a **premium native macOS utility** — think CleanMyMac but
built for developers, with the visual polish of SwiftUI.

### Design Pillars

| Pillar | Description |
|---|---|
| **Clarity** | Every piece of information has a clear visual hierarchy. No clutter. |
| **Confidence** | Users always know what will happen before it happens. Safety is visible. |
| **Delight** | Smooth animations, satisfying progress, pleasing color palette. |
| **Speed** | UI is always responsive. Long operations show progress, not spinners. |

---

## 2. Color Palette

### Dark Theme (Default)

```
Background:
  ┌─────────────────────────────────────────────┐
  │  Base         #0F0F19  rgb(15, 15, 25)      │  Deep midnight
  │  Surface      #1A1A2E  rgb(26, 26, 46)      │  Elevated panels
  │  Overlay      #252540  rgb(37, 37, 64)      │  Modals, popovers
  └─────────────────────────────────────────────┘

Borders & Dividers:
  ┌─────────────────────────────────────────────┐
  │  Border       #373755  rgb(55, 55, 85)      │  Subtle borders
  │  Divider      #2A2A45  rgb(42, 42, 69)      │  Section dividers
  └─────────────────────────────────────────────┘

Text:
  ┌─────────────────────────────────────────────┐
  │  Primary      #DCDCEB  rgb(220, 220, 235)   │  Main text
  │  Secondary    #9898B8  rgb(152, 152, 184)   │  Labels, hints
  │  Muted        #646482  rgb(100, 100, 130)   │  Disabled, subtle
  └─────────────────────────────────────────────┘

Accent Colors:
  ┌─────────────────────────────────────────────┐
  │  Primary      #6366F1  rgb(99, 102, 241)    │  Indigo — selections, active
  │  Secondary    #8B5CF6  rgb(139, 92, 246)    │  Violet — highlights
  │  Gradient     #6366F1 → #A855F7             │  Animated gradient accents
  └─────────────────────────────────────────────┘

Semantic Colors:
  ┌─────────────────────────────────────────────┐
  │  Success      #22C55E  rgb(34, 197, 94)     │  Safe, completed
  │  Warning      #FACC15  rgb(250, 204, 21)    │  Cautious, attention
  │  Danger       #EF4444  rgb(239, 68, 68)     │  Aggressive, error
  │  Info         #3B82F6  rgb(59, 130, 246)    │  Informational
  └─────────────────────────────────────────────┘

Ecosystem Colors:
  ┌─────────────────────────────────────────────┐
  │  Rust         #DEA584  rgb(222, 165, 132)   │
  │  Swift        #F05138  rgb(240, 81, 56)     │
  │  Node         #689F38  rgb(104, 159, 56)    │
  │  Python       #3776AB  rgb(55, 118, 171)    │
  │  Docker       #2496ED  rgb(36, 150, 237)    │
  │  ML/AI        #FF6F61  rgb(255, 111, 97)    │
  └─────────────────────────────────────────────┘
```

### 2.1 Color-Depth Degradation

The RGB palette above assumes a **24-bit truecolor** terminal. Cleanton must detect color
capability (`COLORTERM=truecolor/24bit`, terminfo `colors`, `NO_COLOR`) and degrade
deterministically:

| Capability | Behavior |
|---|---|
| Truecolor (24-bit) | Full palette as specified. |
| 256-color | Map each color to its nearest xterm-256 index (precomputed table, not runtime guesswork). |
| 16-color | Map to the 16 ANSI slots; rely on semantic roles (success/warning/danger), not exact hues. |
| `NO_COLOR` set / dumb terminal | No color; safety levels conveyed by text/badges (`[SAFE]`, `[CAUTION]`, `[AGGRESSIVE]`) so meaning never depends on color alone (also an accessibility requirement). |

A **light theme** must ship as a sibling of `DARK_THEME` (config `theme = "light"`/`"auto"`,
`ARCHITECTURE.md` §6.2). `auto` follows the terminal's reported background (`COLORFGBG` or OSC 11
query) and falls back to dark.

---

## 3. Layout System

### 3.1 Global Layout

```
┌─ Terminal Window (min 100×30) ──────────────────────────────────────┐
│                                                                     │
│  ┌─ Header Bar ──────────────────────────────────────────────────┐  │
│  │  🧹 Cleanton       [Dashboard] [Scanner] [Results] [Services] [Settings]│  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─ Main Content Area ──────────────────────────────────────────┐  │
│  │                                                               │  │
│  │  (varies by screen — see screen specs below)                  │  │
│  │                                                               │  │
│  │                                                               │  │
│  │                                                               │  │
│  │                                                               │  │
│  │                                                               │  │
│  │                                                               │  │
│  │                                                               │  │
│  │                                                               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─ Status Bar ──────────────────────────────────────────────────┐  │
│  │  ↑↓ Navigate  ⏎ Select  Tab Switch  q Quit  ? Help          │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Dashboard Screen

```
┌─ Dashboard ─────────────────────────────────────────────────────────┐
│                                                                     │
│  ┌─ Hero Section ────────────────────────────────────────────────┐  │
│  │                                                               │  │
│  │  ░░░ CLEANTON ░░░         Disk Usage: 487 GB / 1 TB          │  │
│  │  (big-text banner)        ████████████████░░░░░  48.7%       │  │
│  │                                                               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─ Category Cards (3 columns) ─────────────────────────────────┐  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │  │
│  │  │  🦀 Rust     │  │  🍎 Swift   │  │  📦 Node     │       │  │
│  │  │  14.2 GB     │  │  8.7 GB     │  │  22.1 GB     │       │  │
│  │  │  ████░░ 3%   │  │  ██░░░ 2%   │  │  █████ 5%    │       │  │
│  │  │  12 projects │  │  4 projects │  │  31 projects │       │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘       │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │  │
│  │  │  🐍 Python   │  │  🐳 Docker  │  │  🧠 ML/AI    │       │  │
│  │  │  3.4 GB      │  │  31.5 GB    │  │  67.2 GB     │       │  │
│  │  │  █░░░░ 1%    │  │  ██████ 6%  │  │  █████████14%│       │  │
│  │  │  8 projects  │  │  —          │  │  5 models    │       │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘       │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─ Quick Actions ───────────────────────────────────────────────┐  │
│  │  [S] Start Full Scan    [Q] Quick Clean (safe only)           │  │
│  │  [R] Run Recipe...      [C] Configure...                      │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Results Screen

```
┌─ Results ───────────────────────────────────────────────────────────┐
│                                                                     │
│  ┌─ Sidebar (25%) ──┐  ┌─ Main Panel (50%) ──┐  ┌─ Detail (25%) ┐ │
│  │                   │  │                      │  │               │ │
│  │  Categories       │  │  File Tree           │  │  Selected     │ │
│  │  ─────────────    │  │  ──────────          │  │  ───────      │ │
│  │  ▸ 🦀 Rust  14G  │  │  ▾ ~/projects/       │  │               │ │
│  │    🍎 Swift  8G  │  │    ▾ my-app/         │  │  📁 target/   │ │
│  │    📦 Node  22G  │  │      ▸ 📂 target/    │  │  Size: 2.3 GB │ │
│  │    🐍 Python 3G  │  │        14.2 GB       │  │  Age: 12 days │ │
│  │    🐳 Docker 31G │  │    ▾ web-app/        │  │  Recipe: rust  │ │
│  │    🧠 ML    67G  │  │      ▸ 📂 node_mod/  │  │  Safety: ✅    │ │
│  │    🤖 AI     2G  │  │        891 MB        │  │               │ │
│  │    📱 Apps   5G  │  │      ▸ 📂 .next/     │  │  ──────────── │ │
│  │    ⚙ System  1G  │  │        234 MB        │  │               │ │
│  │                   │  │                      │  │  [Enter] Act  │ │
│  │  ─────────────    │  │                      │  │  [Space] Mark │ │
│  │  Total: 152.4 GB  │  │                      │  │  [i] Inspect  │ │
│  │                   │  │                      │  │               │ │
│  └───────────────────┘  └──────────────────────┘  └───────────────┘ │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.4 Execution Screen

```
┌─ Cleaning ──────────────────────────────────────────────────────────┐
│                                                                     │
│  ┌─ Progress ────────────────────────────────────────────────────┐  │
│  │                                                               │  │
│  │  Cleaning 14 / 23 items                                       │  │
│  │  ██████████████████████████████░░░░░░░░░░░░░░  60.8%          │  │
│  │                                                               │  │
│  │  Moved to Trash: 47.3 GB   Freed (deleted): 0.1 GB           │  │
│  │  ⚠ Trash space is reclaimed only after you empty the Trash.  │  │
│  │                                                               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─ Action Log ──────────────────────────────────────────────────┐  │
│  │                                                               │  │
│  │  ✅ Trashed target/ from my-rust-app (2.3 GB)                │  │
│  │  ✅ Trashed node_modules/ from web-app (891 MB)              │  │
│  │  ✅ Deleted __pycache__/ from ml-project (12 MB)             │  │
│  │  ⏳ Trashing DerivedData/ from ios-app (4.1 GB)...           │  │
│  │  ○  Pending: target/ from another-app (1.7 GB)              │  │
│  │  ○  Pending: .next/ from blog (234 MB)                      │  │
│  │                                                               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  [Ctrl+C] Cancel remaining     [E] Empty Trash now (frees space — confirm)│
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.5 Services Screen

```
┌─ Services ──────────────────────────────────────────────────────────┐
│                                                                     │
│  ┌─ Active Services (2/6 running) ──────────────────────────────┐  │
│  │                                                               │  │
│  │  Name               Type            Status       CPU   Memory    │  │
│  │  ──────────────────────────────────────────────────────────   │  │
│  │  ● redis            Brew Service    Running      0.2%  14.2 MB   │  │
│  │  ● postgresql@16    Brew Service    Running      1.1%  84.5 MB   │  │
│  │  ○ ollama           User Agent      Stopped      —     —         │  │
│  │  ○ local-vector-db  User Agent      Stopped      —     —         │  │
│  │  ● com.apple.Finder System Agent    Running [🔒] 0.0%  42.1 MB   │  │
│  │  ○ nginx            Brew Service    Stopped      —     —         │  │
│  │                                                               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─ Service Detail: postgresql@16 ───────────────────────────────┐  │
│  │  Label:        homebrew.mxcl.postgresql@16                     │  │
│  │  Plist Path:   ~/Library/LaunchAgents/homebrew.mxcl.postg...  │  │
│  │  Executable:   /opt/homebrew/opt/postgresql@16/bin/postgres   │  │
│  │  Arguments:    -D /opt/homebrew/var/postgresql@16             │  │
│  │  Run At Load:  Yes (Starts automatically on login)            │  │
│  │  Logs Path:    /opt/homebrew/var/log/postgresql@16.log        │  │
│  │                                                               │  │
│  │  [s] Stop Service   [r] Restart   [d] Disable   [x] Clean Logs │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  [Tab] Switch screen   [Enter] Toggle Status   [?] Help             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Animations

### 4.1 Animation Catalog

| Animation | Location | Type | Duration |
|---|---|---|---|
| **Scan pulse** | Scanner screen | Pulsing icon (opacity cycle) | Continuous |
| **Progress fill** | Progress bars | Smooth left-to-right fill | Real-time |
| **Counter roll** | Freed space display | Number digits roll up | 300ms |
| **Card highlight** | Dashboard cards | Border glow on selection | 200ms |
| **Tab slide** | Header tabs | Active indicator slides | 150ms |
| **Tree expand** | Results tree | Children fade in top-to-bottom | 100ms |
| **Success burst** | Execution complete | Green flash + size counter | 500ms |
| **Gradient cycle** | Dashboard hero | Background gradient shifts | 3s loop |
| **Loading dots** | Status messages | `···` cycling dots | 500ms loop |

### 4.2 Animation Implementation

The UI runs at ~30 FPS (33ms tick). Each animation is a state machine:

```rust
pub struct AnimationTick {
    pub frame: u64,
    pub delta_ms: u16,
}

/// Easing functions for smooth animations
pub fn ease_out_cubic(t: f32) -> f32 {
    1.0 - (1.0 - t).powi(3)
}

pub fn ease_in_out_sine(t: f32) -> f32 {
    -(((t * std::f32::consts::PI).cos() - 1.0) / 2.0)
}

/// Animated progress value
pub struct SmoothProgress {
    current: f32,       // What's currently displayed
    target: f32,        // What we're animating toward
    velocity: f32,      // Current animation velocity
}

impl SmoothProgress {
    pub fn tick(&mut self, delta_ms: u16) {
        let diff = self.target - self.current;
        self.velocity = diff * 0.15;  // Spring-like
        self.current += self.velocity;
    }
}
```

### 4.3 Animation Guidelines

1. **Never block on animation** — animations are cosmetic, skip frames if the terminal is slow
2. **Respect `animation_speed = "off"`** — when disabled, all values snap to target instantly
3. **Keep it subtle** — animations should feel professional, not distracting
4. **Test at 80×24** — minimum terminal size; animations must work at small sizes

---

## 5. Keyboard Shortcuts

### Global

| Key | Action |
|---|---|
| `Tab` / `Shift+Tab` | Switch between screens |
| `q` / `Ctrl+C` | Quit |
| `?` | Toggle help overlay |
| `/` | Focus search/filter |
| `Esc` | Close modal / cancel |

### Navigation

| Key | Action |
|---|---|
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `←` / `h` | Collapse / go to parent |
| `→` / `l` | Expand / enter |
| `Home` / `g` | Go to top |
| `End` / `G` | Go to bottom |
| `PgUp` / `PgDn` | Page up / page down |

### Actions

| Key | Action |
|---|---|
| `Enter` | Primary action (select, confirm) |
| `Space` | Toggle mark item for cleanup |
| `a` | Mark all in current category |
| `u` | Unmark all |
| `d` | Toggle dry-run mode |
| `x` | Execute cleanup for marked items |
| `i` | Inspect selected item (detail view) |
| `r` | Refresh / re-scan |
| `s` | Sort cycle (size → name → age) |

### Services Screen Actions

| Key | Action |
|---|---|
| `s` | Toggle Start / Stop selected service |
| `r` | Restart selected service |
| `d` | Toggle Enable / Disable selected service |
| `x` | Delete logs and cache files for selected service |

---

## 6. Responsive Behavior

| Terminal Width | Layout |
|---|---|
| ≥ 120 cols | Full 3-column layout (sidebar + main + detail) |
| 100-119 cols | 2-column layout (sidebar + main); detail as overlay |
| 80-99 cols | Single column; sidebar as collapsible drawer |
| < 80 cols | Minimal mode; show warning about small terminal |

| Terminal Height | Behavior |
|---|---|
| ≥ 40 rows | Full layout with dashboard cards |
| 30-39 rows | Compact cards (single-line per card) |
| 24-29 rows | Minimal; no dashboard cards, list only |
| < 24 rows | Show error: "Terminal too small" |

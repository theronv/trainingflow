# TrainFlow Branding Plan
**Status: Pending Approval — No code has been changed.**

---

## Executive Summary

The current branding system has the right bones — CSS custom properties, a `brand` DB table, an `applyBrand()` function — but several critical pieces are broken or incomplete:

1. **`PUT /api/brand` only saves 2 of 8 fields** — colors, logo URL, and tagline are accepted by the frontend but silently ignored by the worker. The DB columns exist but are never written.
2. **Logo uploads are ephemeral** — base64 file uploads live in memory only and are lost on refresh.
3. **Only 1 functional brand color** — the secondary color input (`c2`) is overwritten internally and has no real effect on any CSS token. There is no third color at all.
4. **Brand doesn't reach every surface** — the landing page tagline is static, the course viewer header has no logo, and the browser theme-color meta tag is hard-coded.
5. **The branding page preview is minimal** — it shows a topbar mock but doesn't preview the landing page, certificate, or course header.

This plan fixes all of the above and adds a proper 3-color system with full surface coverage.

---

## 1. Color System: 3 True Brand Colors

### The Problem with the Current System

`--brand` (primary) is the only color that actually does anything. `--brand-2` is aliased to `--brand-dark`, which is computed as `darken(primary, 15%)` — so secondary color input is effectively a no-op. There is no third color.

### Proposed 3-Color Palette

| Role | CSS Variable | DB Column | Description | Default |
|---|---|---|---|---|
| **Primary** | `--brand` | `primary_color` | Main brand color. Buttons, links, active states, progress bars, sidebar highlight. | `#2563eb` |
| **Secondary** | `--brand-secondary` | `secondary_color` | Complementary color. Gradient backgrounds, decorative accents, landing hero, certificate header. | `#7c3aed` |
| **Accent** | `--brand-accent` | `accent_color` | High-contrast highlight. Badge chips, hover states, certificate name highlight, "Start" CTAs. | `#0891b2` |

### Derived Tokens (computed, not stored)

Each of the 3 colors generates 3 derived tokens automatically in `applyBrand()`:

| Token | Derivation | Usage |
|---|---|---|
| `--brand-dark` | `darken(primary, 15%)` | Primary button hover |
| `--brand-glow` | `rgba(primary, 0.12)` | Active sidebar item background, source banner |
| `--brand-secondary-dark` | `darken(secondary, 15%)` | Gradient end stop, decorative hover |
| `--brand-secondary-glow` | `rgba(secondary, 0.10)` | Hero section background tint |
| `--brand-accent-dark` | `darken(accent, 12%)` | Accent hover state |
| `--brand-accent-glow` | `rgba(accent, 0.12)` | Accent chip background |

**Legacy aliases kept for backwards compatibility:**
- `--brand-1` → stays as alias of `--brand`
- `--brand-2` → becomes true alias of `--brand-secondary` (breaking the old overwrite)

### Color Usage Map

```
PRIMARY    → Primary buttons, links, progress bars, active sidebar item,
             mod-bullet active, "Start Competency Check" button,
             source-banner border, focus ring shadow, quiz feedback

SECONDARY  → Landing page hero gradient, topbar gradient (optional),
             certificate accent bar, section dividers,
             decorative pill/badge backgrounds

ACCENT     → "Read This First" banner background tint (alternative to brand-glow),
             course completion badge, "Finish Course" button variant,
             chip-blue badges, learner avatar background
```

---

## 2. Logo System

### The Problem

- **Base64 uploads lost on refresh** — `saveBrand()` explicitly skips writing `data:` URLs to the database (`admin.js` line 352: `!b.logo.startsWith('data:')`).
- **Logo is too small on the landing page** — it sits at ~50px in a small wrap above the org name text, rather than being the dominant element.
- **No logo in the course viewer header** — learners spend most of their time on `screen-course`, which has zero brand presence.

### Fix: Logo Persistence

Remove the `startsWith('data:')` guard in `saveBrand()` and always write `brandCache.logo` to the `logo_url` field. SQLite `TEXT` columns are unlimited in size — a base64 image (typically 20–80 KB as text) is trivially small for the DB. This is the zero-infrastructure fix.

For URL-based logos, the existing flow already works fine. Admins should be guided to paste a public URL (CDN, Cloudflare Images, Imgur, etc.) for production use to keep DB payloads small.

### Logo Sizing & Placement

| Surface | Current Size | Proposed Size | Notes |
|---|---|---|---|
| Landing page (with logo) | ~50px height, small wrap | **120px max-height** | Dominant, centered, above org name |
| Landing page (no logo) | — | Org name in styled type | Brand color used for the type treatment |
| Topbar (learner/admin/manager) | 28px height | **36px height** | Slightly larger, more breathing room |
| Course viewer header | **None** | **32px height** | New — small logo mark on far left of header |
| Certificate | ~60px, always hidden by default | **80px max-height** | Larger, shown prominently above org name |
| Branding preview | 28px | **Responsive to uploaded size** | Preview should accurately reflect the landing page treatment |

---

## 3. Screen-by-Screen Changes

### 3.1 Landing Page (`screen-landing`)

**Current state:** Plain centered card with small logo wrap, org name text, static tagline, a thin horizontal rule, and a 2-column role grid.

**Proposed redesign:**

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│        [LOGO — 120px max-height, centered]                  │
│        [ORG NAME in brand-colored type if no logo]          │
│                                                             │
│          Tagline (dynamic from brandCache)                  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │   gradient bar: primary → secondary (4px height)     │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐  │
│   │  🎓 Learner  │   │ 💼 Manager   │   │  ⚙️ Admin    │  │
│   └──────────────┘   └──────────────┘   └──────────────┘  │
│                                                             │
│                  [ Try Demo Mode ]                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Specific changes:**
- `#ldg-logo-wrap` max-height increased to 120px; remove the `hidden`-on-no-logo behavior — instead show org name with brand color treatment when no logo exists
- `#ldg-tagline` updated dynamically by `applyBrand()` from `brandCache.tagline` (currently static)
- `.landing-rule` replaced with a 4px gradient bar using `linear-gradient(to right, var(--brand), var(--brand-secondary))`
- Role tiles get a subtle brand-colored left border on hover: `border-left: 3px solid var(--brand)`
- `<meta name="theme-color">` updated via `document.querySelector('meta[name="theme-color"]').content = hex` in `applyBrand()` (fixes the mobile browser address bar)

### 3.2 Topbar (Learner / Admin / Manager)

**Current state:** Logo at ~28px, followed by org name text.

**Proposed:**
- Logo bumped to 36px max-height
- Add a subtle 2px bottom-border gradient on the topbar itself: `linear-gradient(to right, var(--brand), var(--brand-secondary))` — visible only when logo is set, to give the topbar a branded feel without a heavy background color change
- Org name styled with `color: var(--brand)` when no logo is present, making it feel like the brand wordmark rather than plain text

### 3.3 Course Viewer Header (`screen-course`)

**Current state:** `← Back` | course title + progress bar | Focus Mode | Module X of Y. No brand presence.

**Proposed:**
- Add a small logo mark (32px) to the **left of the Back button** — this keeps the brand visible without disrupting the header layout
- New element: `<img id="ch-logo" class="course-header-logo hidden">` — populated by `applyBrand()`
- When no logo is set, a 3px brand-colored left border on the header creates a subtle accent strip

### 3.4 Learner Dashboard (`screen-learner`)

**Current state:** Course cards are un-branded; progress bars in primary brand color already.

**Proposed:**
- Course card "completed" badge: use `--brand-accent` color instead of hardcoded green-ish chip
- Course card assignment chip: use `--brand-secondary`
- Section headers in the course list: use `--brand-secondary` for the underline divider (replacing current `--rule-2`)
- Avatar circle: already uses `--brand` ✓

### 3.5 Certificate Overlay (`#cert-overlay` / `#cert-sheet`)

**Current state:** Thin 6px accent bar at top, logo small and often missing, org name as plain text, no secondary/accent color used on cert.

**Proposed redesign:**

```
┌──────────────────────────────────────────────────────────┐
│  ████████████████ accent bar (6px) ██████████████████   │
│                                                          │
│     [ LOGO — up to 80px height, centered ]              │
│     [ ORG NAME — bold, brand primary color ]            │
│                                                          │
│              C E R T I F I C A T E                      │
│                  of Completion                           │
│              ─────────────────────                       │
│           This certifies that                            │
│                                                          │
│        ★  LEARNER NAME  ★                               │
│           (accent color, larger type)                    │
│                                                          │
│        has successfully completed                        │
│                                                          │
│           [Course Title]                                 │
│                                                          │
│  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄  │
│   Date        Score        ID                           │
│                                                          │
│   [Org Name] Training Dept.    Authorised Signatory     │
└──────────────────────────────────────────────────────────┘
```

**Specific changes:**
- `.cert-accent-bar` stays (6px gradient: primary → secondary instead of solid primary)
- Logo area: `#c-logo` max-height → 80px, margins adjusted for prominence
- `#c-org` (org name): add `color: var(--brand)` styling — the org name becomes the brand wordmark on the cert
- `#c-name` (learner name): add `color: var(--brand-accent)` — differentiates the key element
- The `cert-rule` divider: use a gradient line (`background: linear-gradient(to right, transparent, var(--brand), transparent)`)

### 3.6 Admin Branding Page (`ap-branding`)

**Current state:** 2-column grid of Organisation card + Colours card (with 2 pickers), simple preview mockup.

**Proposed redesign:**

```
┌─────────────────────────────────────────────────────────────┐
│  ORGANISATION                                               │
│  ┌──────────────────────────────┐                          │
│  │  Name   [__________________] │                          │
│  │  Tagline[__________________] │                          │
│  │  Logo   [url] [upload]       │                          │
│  │         [ Logo preview box ] │                          │
│  └──────────────────────────────┘                          │
│                                                             │
│  COLOURS                                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  [●] Primary   #____   [●] Secondary  #____         │   │
│  │  [●] Accent    #____                                 │   │
│  │                                                      │   │
│  │  [Suggested palette chips: click to apply]           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  LIVE PREVIEW                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  [Topbar mock]     [Landing hero mock]              │   │
│  │  [Button samples]  [Certificate strip mock]         │   │
│  │  [Progress bar]    [Course card mock]               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  [ Save Branding ]  [ Reset to Defaults ]                  │
└─────────────────────────────────────────────────────────────┘
```

**Specific changes:**
- Logo field: dedicated preview box below the URL/upload inputs showing the logo at actual landing-page size (120px) with a neutral background — so you see exactly what learners will see before saving
- Add **3rd color picker**: Accent color with swatch + hex input (identical pattern to existing Primary/Secondary)
- Add **suggested palette row**: 6 pre-built 3-color combinations (e.g. "Corporate Blue", "Forest", "Sunset", "Slate", "Brand Red", "Midnight"). Each chip is a 3-dot swatch; clicking it populates all three pickers simultaneously
- **Live preview expanded**: Currently shows only a topbar strip + button + progress bar. Expand to show:
  - Topbar strip (existing)
  - A mini landing hero (logo + tagline + gradient rule)
  - A certificate accent strip (gradient bar + org name in brand color)
  - A progress bar + a quiz answer button
- Tagline field: add `oninput="App.previewBrand()"` (currently missing, tagline changes don't update live preview)

---

## 4. Backend Changes

### 4.1 Fix `PUT /api/brand` (`worker/index.js`)

**Current (broken):**
```sql
UPDATE brand SET org_name = ?, pass_threshold = ? WHERE id = "default"
```

**Proposed:**
```sql
UPDATE brand SET org_name = ?, tagline = ?, primary_color = ?, secondary_color = ?, accent_color = ?, logo_url = ?, pass_threshold = ? WHERE id = "default"
```

This is the most critical backend fix — without it, none of the color or logo changes persist across sessions.

### 4.2 Add `accent_color` column (`worker/index.js` `setupSections()` or a new `setupBrand()`)

```sql
ALTER TABLE brand ADD COLUMN accent_color TEXT NOT NULL DEFAULT '#0891b2'
```

Added as a safe migration (try/catch) alongside the other ALTER TABLE calls.

### 4.3 Add `GET /api/brand` returns `accent_color`

The existing `SELECT *` query already returns all columns, so this works automatically once the column exists.

---

## 5. Frontend Changes

### 5.1 `normBrand()` — `core.js`

Add `accent` field:
```js
function normBrand(b) {
  return {
    name:    b.org_name || CONFIG.DEFAULT_BRAND_NAME,
    tagline: b.tagline  || CONFIG.DEFAULT_TAGLINE,
    logo:    b.logo_url || '',
    c1:      b.primary_color   || CONFIG.DEFAULT_C1,
    c2:      b.secondary_color || CONFIG.DEFAULT_C2,
    c3:      b.accent_color    || CONFIG.DEFAULT_C3,   // new
    pass:    b.pass_threshold  ?? CONFIG.DEFAULT_PASS,
  };
}
```

### 5.2 `applyBrand()` — `core.js`

Add secondary and accent token derivation, fix legacy alias, update two missing surfaces:

```js
function applyBrand() {
  // --- Primary ---
  const c1 = validHex(b.c1, CONFIG.DEFAULT_C1);
  root.setProperty('--brand',       c1);
  root.setProperty('--brand-dark',  darken(c1, 15));
  root.setProperty('--brand-glow',  hexToRgba(c1, 0.12));
  root.setProperty('--shadow-brand', `0 0 0 3px ${hexToRgba(c1, 0.2)}`);
  root.setProperty('--brand-1', c1);  // legacy

  // --- Secondary (NEW — truly independent) ---
  const c2 = validHex(b.c2, CONFIG.DEFAULT_C2);
  root.setProperty('--brand-secondary',      c2);
  root.setProperty('--brand-secondary-dark', darken(c2, 15));
  root.setProperty('--brand-secondary-glow', hexToRgba(c2, 0.10));
  root.setProperty('--brand-2', c2);  // fix legacy alias

  // --- Accent (NEW) ---
  const c3 = validHex(b.c3, CONFIG.DEFAULT_C3);
  root.setProperty('--brand-accent',      c3);
  root.setProperty('--brand-accent-dark', darken(c3, 12));
  root.setProperty('--brand-accent-glow', hexToRgba(c3, 0.12));

  // --- Org name (existing) ---
  ['ldg-brand', 'l-brand', 'a-brand', 'm-brand'].forEach(...)

  // --- Tagline (NEW — currently missing) ---
  const taglineEl = $$('ldg-tagline');
  if (taglineEl) taglineEl.textContent = b.tagline;

  // --- Logo (existing + new course header logo) ---
  ['l-logo', 'a-logo', 'm-logo', 'ldg-logo', 'ch-logo'].forEach(...)  // ch-logo is new

  // --- Mobile browser theme color (NEW) ---
  const themeMeta = document.querySelector('meta[name="theme-color"]');
  if (themeMeta) themeMeta.content = c1;
}
```

### 5.3 CSS (`style.css`)

Add new variable declarations in `:root`:
```css
--brand-secondary:      #7c3aed;
--brand-secondary-dark: #6d28d9;
--brand-secondary-glow: rgba(124, 58, 237, 0.10);
--brand-accent:         #0891b2;
--brand-accent-dark:    #0e7490;
--brand-accent-glow:    rgba(8, 145, 178, 0.12);
```

Update the landing rule:
```css
.landing-rule {
  background: linear-gradient(to right, var(--brand), var(--brand-secondary));
}
```

Update certificate accent bar:
```css
.cert-accent-bar {
  background: linear-gradient(to right, var(--brand), var(--brand-secondary));
}
```

Add course header logo element style:
```css
.course-header-logo {
  height: 32px; width: auto; max-width: 100px;
  object-fit: contain; flex-shrink: 0;
}
```

Update landing logo wrap:
```css
.ldg-logo-img { max-height: 120px; max-width: 280px; width: auto; }
```

Expand learner avatar, chip-blue, and user-avatar to reference `--brand-accent` where appropriate.

### 5.4 Admin branding page (`index.html`)

- Add `id="br-c3"` color picker and `id="br-c3-hex"` text input for Accent color (identical markup pattern to existing Primary/Secondary)
- Add `id="br-prev-logo-box"` — a dedicated logo preview container (neutral background, 140px tall, centered)
- Add `id="br-prev-landing"` — a mini landing hero strip in the live preview section
- Add `id="br-prev-cert"` — a small certificate header strip (gradient bar + org name)
- Add `id="br-prev-palette"` — a row of 6 preset palette buttons

### 5.5 `saveBrand()` and `renderBranding()` — `admin.js`

**`saveBrand()`:** Add `accent_color` and `tagline` to the request body. Remove the `data:` URL check — always write `brandCache.logo` to `logo_url`.

**`renderBranding()`:** Set `$$('br-c3').value` and `$$('br-c3-hex').value` from `brandCache.c3`. Add live preview updates for the new preview panels.

**`App.uploadLogo()`:** Update `brandCache.logo` with the base64 result AND immediately set `$$('br-logo-url').value` to empty (so the URL field clears to reflect file-upload mode). The base64 will now save to DB on `saveBrand()`.

### 5.6 `CONFIG` defaults — `core.js`

Add:
```js
DEFAULT_C3: '#0891b2',  // accent default
```

---

## 6. Implementation Order

All changes are additive/non-breaking. Suggested order:

| # | Change | File(s) | Risk |
|---|---|---|---|
| 1 | Fix `PUT /api/brand` SQL | `worker/index.js` | Low |
| 2 | Add `accent_color` DB migration | `worker/index.js` | Low |
| 3 | Add `DEFAULT_C3` + update `normBrand()` | `core.js` | Low |
| 4 | Expand `applyBrand()` (secondary, accent, tagline, ch-logo, theme-color) | `core.js` | Low |
| 5 | Add new CSS variables + landing-rule gradient + cert gradient + course header logo | `style.css` | Low |
| 6 | Add `ch-logo` to course header HTML + increase landing logo size | `index.html` | Low |
| 7 | Add accent color picker + logo preview box + expanded live preview to branding page | `index.html` | Low |
| 8 | Update `saveBrand()` + `renderBranding()` + `uploadLogo()` | `admin.js` | Low |
| 9 | Update cert HTML: logo sizing, cert-accent gradient, learner name accent color | `index.html` + `style.css` | Low |
| 10 | Add preset palette chips to branding page | `index.html` + `admin.js` | Low |

Steps 1–4 are backend/logic; Steps 5–9 are visual. Step 10 is polish.

---

## 7. What This Will NOT Change

To keep scope clear, the following are explicitly out of scope for this plan:

- **Custom fonts** — Inter remains the UI font. Adding font uploads/selection is a separate initiative.
- **Dark/light mode default** — the theme toggle stays user-controlled; brand colors apply in both modes.
- **Course card layout** — shape, size, and grid structure of course cards are unchanged.
- **Email/notification branding** — not applicable to this codebase.
- **Per-course branding** — all branding is org-level. Individual courses do not get their own color schemes.

---

## 8. Before / After Summary

| Element | Before | After |
|---|---|---|
| Colors available | 1 (primary only) | 3 (primary, secondary, accent) |
| Color persistence | ❌ Not saved to DB | ✅ All 3 saved |
| Logo persistence | ❌ Lost on refresh if file-uploaded | ✅ Always saved |
| Logo on landing | 50px, secondary | 120px, dominant |
| Logo in course viewer | ❌ None | ✅ 32px mark in header |
| Tagline | ❌ Static HTML | ✅ Dynamic from DB |
| Certificate accent | Solid primary bar | Primary → Secondary gradient |
| Certificate learner name | Plain text | Accent color |
| Mobile theme-color meta | Hard-coded `#fafaf9` | Dynamic — matches primary |
| Branding preview | Topbar + button + progress bar | Full multi-surface preview |
| Preset palettes | ❌ None | ✅ 6 one-click presets |

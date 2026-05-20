# TrainFlow — Project Guide

## What This Is

TrainFlow is a full-stack LMS for professional teams. AI-assisted course creation, role-based access (Admin / Manager / Learner), targeted assignments, progress tracking, and verifiable PDF certificates.

**Live app:** https://theronv.github.io/trainingflow/

---

## Current Stack (as of 2026-05-20)

| Layer | Technology |
|---|---|
| Frontend | Vanilla JS (ES6), HTML5, CSS3 — SPA served from GitHub Pages |
| Edge Worker | Hono 4.7.0 on **Cloudflare Workers** (not Vercel Edge) |
| Database | Turso (libSQL/SQLite) via `@libsql/client` v0.14.0 — raw SQL, no Drizzle |
| Auth | Custom JWT + PBKDF2-SHA256 (100k iterations) — no Clerk |
| AI | Anthropic Claude (`claude-sonnet-4-6`) + Google Gemini 1.5 Flash — direct browser calls, keys in localStorage |
| PDF | jsPDF + html2canvas — client-side |
| Build | None — static HTML + Wrangler v4.75.0 deploy |

---

## Project Structure

```
index.html            # SPA shell — all screens, modals, overlays
css/
└── style.css         # Design system — semantic tokens, dark/light themes
js/
├── core.js           # Global state (13+ globals), API helpers, applyBrand()
├── auth.js           # Login/register for Admin, Manager, Learner
├── admin.js          # Admin portal (1,618 lines — oversized, see Architecture)
├── manager.js        # Manager portal (446 lines)
├── learner.js        # Learner portal (513 lines)
├── builder.js        # Course builder — module/question editor
└── app.js            # AppProxy — wires onclick attrs to JS modules (473 lines)
worker/
├── index.js          # All Hono routes + DB logic (1,214 lines — oversized)
├── wrangler.toml     # Cloudflare Worker config
├── package.json      # Worker deps (Hono, @libsql/client)
└── seed-demo.mjs     # Demo data seeding script
schema.sql            # Turso schema (run once; course_progress also created inline by worker)
scripts/
└── hash-password.mjs # PBKDF2 hash utility
docs/
├── kb-scraper-integration.md  # Planned integration (stub)
└── archive/          # Historical review documents (AUDIT.md, QA-REPORT.md)
```

---

## Running Locally

```bash
# Worker (Terminal 1)
cd worker && npm run dev       # Runs at http://localhost:8787

# Frontend (Terminal 2)
npx serve .                    # Runs at http://localhost:3000
```

## Environment Variables

Set as Wrangler secrets (production) or in `worker/.dev.vars` (local dev):

```
TURSO_URL=libsql://your-db.turso.io        # Turso database URL
TURSO_TOKEN=your-token                      # Turso access token
JWT_SECRET=32-char-random-string            # Signs all JWTs (min 32 chars)
ADMIN_PASSWORD_HASH=pbkdf2v1:salt:hash      # node scripts/hash-password.mjs <password>
GEMINI_API_KEY=AIza...                      # Used as AI Importer fallback in worker
ALLOWED_ORIGIN=https://theronv.github.io    # CORS — falls back to production domain if unset
```

> Claude and Gemini API keys for the AI Importer are entered per-session in Admin → AI Importer and stored in `localStorage`. They are never sent to the Worker.

## Deploying

```bash
turso db shell <db-name> < schema.sql    # First run only
cd worker && npx wrangler deploy         # Worker
# Push to GitHub → Pages auto-deploys frontend
```

## Demo Data Seeding

```bash
cd worker

# Seed production (preserves existing courses)
export TURSO_URL=libsql://your-db.turso.io
export TURSO_TOKEN=$(turso db tokens create <db-name>)
node seed-demo.mjs --prod --reset

# Seed using your own courses (skip the 4 built-in demo courses)
node seed-demo.mjs --prod --reset --skip-courses

# Full wipe including courses (destructive)
node seed-demo.mjs --prod --reset-courses
```

Demo credentials (password: `demo1234`):
- **Admin:** password only
- **Managers:** `sarah.chen`, `marcus.johnson`
- **Learners:** `alex.rivera`, `jordan.kim`, `taylor.brooks`, `sam.patel`, `casey.morgan`, `blake.thompson`, `drew.martinez`, `quinn.foster`, `avery.wilson`, `riley.hayes`

---

## Database Schema

All tables defined in `schema.sql`. The `course_progress` table is also created lazily by the worker on first write.

| Table | Key Columns | Notes |
|---|---|---|
| `users` | `id TEXT PK`, `name TEXT UNIQUE`, `password_hash TEXT`, `role TEXT` ('manager'\|'learner'), `team_id INTEGER → teams` | Admin has no row here — hardcoded via `ADMIN_PASSWORD_HASH` |
| `teams` | `id INTEGER PK AUTOINCREMENT`, `name TEXT UNIQUE` | Organizational units |
| `invite_codes` | `id INTEGER PK`, `code TEXT UNIQUE`, `team_id → teams`, `used INTEGER`, `expires_at TEXT` | Single-use, scoped to a team |
| `courses` | `id TEXT PK`, `icon TEXT`, `title TEXT`, `description TEXT` | `updated_at` auto-updated via trigger |
| `modules` | `id TEXT PK`, `course_id → courses CASCADE`, `title TEXT`, `content TEXT`, `sort_order INTEGER` | Indexed by `(course_id, sort_order)` |
| `questions` | `id TEXT PK`, `module_id → modules CASCADE`, `question TEXT`, `option_a/b/c/d TEXT`, `correct_index INTEGER`, `explanation TEXT`, `sort_order INTEGER` | Answer key — strip from public responses (see Security) |
| `assignments` | `PK (course_id, learner_id)`, `due_at TEXT` | Composite PK prevents duplicates |
| `completions` | `id TEXT PK`, `course_id → courses`, `learner_id → users CASCADE`, `score INTEGER`, `passed INTEGER`, `cert_id TEXT UNIQUE` | Multiple completions per learner/course allowed (retakes) |
| `module_progress` | `PK (learner_id, module_id)`, `course_id`, `passed`, `score`, `completed_at` | Per-module progress for resume |
| `course_progress` | `PK (learner_id, course_id)`, `module_idx INTEGER`, `modules TEXT` (JSON) | Resume position; created lazily by worker |
| `question_responses` | `completion_id → completions CASCADE`, `question_id → questions CASCADE`, `is_correct INTEGER` | Used for server-side score verification |
| `brand` | `id TEXT PK DEFAULT 'default'`, `org_name`, `tagline`, `logo_url`, `primary_color`, `secondary_color`, `pass_threshold INTEGER` | Single row; `accent_color` added via ALTER in worker |
| `tags` | `id TEXT PK`, `name TEXT UNIQUE` | UI stub — schema exists, Admin UI is "coming soon" |
| `learner_tags` | `PK (learner_id, tag_id)` | Tag assignments to learners |
| `tag_assignments` | `PK (course_id, tag_id)`, `due_at TEXT` | Tag assignments to courses |
| `admin` | `id TEXT PK DEFAULT 'default'`, `password_hash TEXT` | Single row for admin credentials |

---

## API Reference

All routes in `worker/index.js`. Auth middleware: `requireAdmin`, `requireManager` (scoped to `user.scopedToTeam`), `requireLearner` (role-checked).

| Method | Route | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | — | Admin login → JWT |
| `POST` | `/api/auth/manager/login` | — | Manager login → JWT |
| `POST` | `/api/auth/manager/register` | — | Manager registration with invite code |
| `POST` | `/api/learners/login` | — | Learner login → JWT |
| `GET` | `/api/brand` | — | Get org branding |
| `PUT` | `/api/brand` | Admin | Update org branding |
| `GET` | `/api/courses` | Any | List all courses |
| `POST` | `/api/courses` | Admin | Create a course (batch insert via `db.batch()`) |
| `GET` | `/api/courses/:id` | Auth required | Get course with modules + questions (correct answers stripped for learners) |
| `PATCH` | `/api/courses/:id` | Admin | Update course metadata |
| `PUT` | `/api/courses/:id` | Admin | Full course replace (modules + questions) |
| `DELETE` | `/api/courses/:id` | Admin | Delete course (cascades to modules, questions) |
| `GET` | `/api/sections` | Any | List all sections |
| `POST` | `/api/sections` | Admin | Create a section |
| `PATCH` | `/api/sections/:id` | Admin | Rename a section |
| `DELETE` | `/api/sections/:id` | Admin | Delete a section |
| `GET` | `/api/learners` | Admin/Manager | List learners (team-scoped for managers) |
| `POST` | `/api/learners` | Admin/Manager | Create a learner (team_id locked to manager's team) |
| `POST` | `/api/learners/bulk` | Admin/Manager | Bulk create from CSV |
| `GET` | `/api/learners/me` | Learner | Get own profile |
| `PATCH` | `/api/learners/me` | Learner | Update own name/password |
| `GET` | `/api/learners/:id` | Admin/Manager | Get learner (managers: team-scoped) |
| `PATCH` | `/api/learners/:id` | Admin | Edit learner |
| `DELETE` | `/api/learners/:id` | Admin | Delete learner |
| `PUT` | `/api/learners/:id/password` | Admin/Manager | Reset learner password (min 8 chars enforced) |
| `PATCH` | `/api/managers/me` | Manager | Update own name/password |
| `GET` | `/api/admin/stats` | Admin/Manager | Platform/team statistics |
| `GET` | `/api/admin/teams` | Admin/Manager | List teams with member counts |
| `POST` | `/api/admin/teams` | Admin | Create a team |
| `PATCH` | `/api/admin/teams/:id` | Admin | Rename a team |
| `DELETE` | `/api/admin/teams/:id` | Admin | Delete a team |
| `PATCH` | `/api/admin/learners/:lid/team` | Admin | Move learner to another team |
| `PUT` | `/api/admin/password` | Admin | Change admin password (current password required) |
| `GET` | `/api/admin/invites` | Admin | List invite codes |
| `POST` | `/api/admin/invites` | Admin | Generate an invite code |
| `DELETE` | `/api/admin/invites/:id` | Admin | Revoke an invite code |
| `GET` | `/api/admin/completions` | Admin/Manager | Completion log (filterable, team-scoped) |
| `DELETE` | `/api/completions` | Admin | Clear all completion records |
| `GET` | `/api/admin/trouble-spots` | Admin/Manager | Courses with highest failure rates |
| `POST` | `/api/admin/backup/restore` | Admin | Import courses from JSON backup |
| `GET` | `/api/assignments` | Admin/Manager | List assignments |
| `GET` | `/api/assignments/me` | Learner | Own assignments with status |
| `POST` | `/api/assignments` | Admin/Manager | Assign a course (team-scoped for managers) |
| `DELETE` | `/api/assignments` | Admin/Manager | Remove an assignment (team-scoped for managers) |
| `GET` | `/api/completions/me` | Learner | Own completion records |
| `POST` | `/api/completions` | Learner | Submit a course completion (score computed server-side from question_responses) |
| `GET` | `/api/progress/me` | Learner | Own module progress |
| `POST` | `/api/progress` | Learner | Save module progress |
| `DELETE` | `/api/progress/:course_id` | Learner | Clear progress for a course |
| `GET` | `/api/admin/tags` | Admin/Manager | List tags |
| `POST` | `/api/admin/tags` | Admin | Create a tag |
| `DELETE` | `/api/admin/tags/:id` | Admin | Delete a tag |
| `GET` | `/api/scrape` | Admin | Proxy Jina Reader fetch for KB Scraper integration (planned) |

---

## Architecture Notes

**State model:** 13+ global mutable variables in `core.js`, modified by any module:
```
curLearner, curManager, curCourse, curModIdx, quizSt, cbState,
csvParsed, compOffset, _allLearners, teamsCache, coursesCache,
assignCache, isDemo, brandCache
```
`app.js` also hangs ephemeral state on `App` (`App._resetPwId`, `App._editLearnerId`, etc.) — shared mutable slots between modal-open and modal-submit handlers.

**Data flow:** API response → inline template string → `innerHTML`. Brittle under race conditions (no `AbortController` except in `saveAiCourse`). All render functions mix data fetching with DOM writes.

**API helpers:** Three near-identical functions (`api()`, `managerApi()`, `learnerApi()`) each attach the correct JWT and handle 401. No request cancellation.

**`admin.js` is 1,618 lines** — AI Importer (~600 lines), Branding, Teams, Learners, Dashboard all in one object. Must be split before RN migration.

**`worker/index.js` is 1,214 lines** — all 45+ routes in one file. Schema migration calls (`setupSections()`, `setupTags()`) run `ALTER TABLE` on every relevant request rather than at deploy time.

**AI keys risk:** Claude/Gemini API keys stored in `localStorage`, called directly from the browser. The server-side proxy endpoint (`/api/ai/generate`) exists but is unused. Any XSS exposes all keys.

**`sectionsCache`** is assigned in `admin.js:renderCourses()` without being declared in `core.js` — creates an implicit `window.sectionsCache` global. Fix: declare in `core.js`.

---

## Design System (css/style.css)

Semantic token system on `:root`. All tokens are mobile-shifted (updated 2026-05-20 for RN migration):

**Color layers:**
- Background: `--bg`, `--bg-2`
- Surface: `--surface`, `--surface-2`
- Border: `--border`, `--border-2`
- Text: `--ink-1` (primary) → `--ink-4` (disabled)
- Brand primary (runtime): `--brand`, `--brand-dark`, `--brand-glow`, `--shadow-brand`
- Brand secondary (runtime): `--brand-secondary`, `--brand-secondary-dark`, `--brand-secondary-glow`
- Brand accent (runtime): `--brand-accent`, `--brand-accent-dark`, `--brand-accent-glow`
- Status: `--success`, `--warning`, `--danger` + `--pass-lt`, `--fail-lt`, `--warn-lt`, `--pass-bg`, `--fail-bg`, `--pass-dim`, `--fail-dim`, `--pass-border`, `--fail-border`, `--fail-border-lt`, `--warn-border`

**Spacing:** 4pt grid `--space-1` (4px) → `--space-16` (64px)

**Type scale (mobile-shifted):** `--text-xs` 12px → `--text-3xl` 30px (minimum 12pt; lower half shifted up from 11–14px)

**Touch targets (updated):** `.btn` min-height ~44pt; `.btn-sm` ~36pt; `.nav-btn` 10px vertical padding.

Dark mode via `[data-theme="light"]` CSS overrides. Brand colors applied at runtime via `applyBrand()` in `core.js`.

**Runtime brand system:** `applyBrand()` sets 9 CSS custom properties on `:root` from `brandCache` (3 colors × 3 derived tokens each). `normBrand()` in `core.js` is the type boundary for all API brand responses.

---

## Security Status (as of 2026-05-20)

All 14 security findings from the Auditor Review are resolved. F15 accepted (safe hardcoded fallback).

Key resolutions:
- **F1/F2 (CRITICAL):** Score computed server-side from `question_responses`; course answer key requires auth and strips `correct_index`/`explanation` for learner tokens
- **F3–F8 (HIGH):** Team ownership enforced on all manager routes; `requireLearner` checks `role === 'learner'`; role elevation restricted to Admin; `team_id` locked to manager's own team
- **F9–F12 (MEDIUM):** Password min-length enforced; current password required to change admin password; DB error detail removed from 500 responses; tag endpoints team-scoped

---

## Known Limitations (open backlog)

| ID | Issue | Effort |
|---|---|---|
| B-04 | CSV import into Course Builder — stub | ~2 hrs |
| B-06 | Tags feature — schema/API exist, UI incomplete | ~3 hrs |
| D-10 | Learner list pagination (all users rendered at once) | ~1 hr |
| — | Real-time dashboard updates (no SSE/WebSocket) | large |
| — | Logo CDN (base64 inflates API responses) | medium |
| — | KB Scraper → AI Importer integration | planned |

---

## Migration Status — 2026-05-20

### Context

TrainFlow is a vanilla JS SPA, not a React Native / Expo app. The "VD Canonical Stack" (Expo / Vercel Edge / Clerk / RevenueCat / Sentry / EAS) is the migration target for a future native build. All four pre-migration review stages are complete (Architect, Security, Strategist, Designer). Architecture decisions for RN are locked (see below).

---

### Stack Inventory

| Layer | Target | Status | Detail |
|---|---|---|---|
| Native: Expo SDK 54 + Expo Router | NOT STARTED | No Expo project, no RN code, no eas.json |
| API: Hono 4.7 on Vercel Edge | DIFFERENT APPROACH | Hono 4.7 ✅ on Cloudflare Workers; migration to Vercel Edge is low-risk, not yet made |
| DB: Turso/libSQL + Drizzle ORM | PARTIAL | Turso/libSQL ✅; raw SQL throughout — Drizzle ✗ |
| Auth: Clerk | NOT STARTED | Custom JWT + PBKDF2; no Clerk project |
| Subscriptions: RevenueCat | NOT STARTED | No monetization; B2B per-seat model ($4–7/learner/month) confirmed as target |
| Monitoring: Sentry | NOT STARTED | No Sentry projects |
| Build: EAS | NOT STARTED | No eas.json; no dev/preview/production profiles |

**Stack completion: 0/7 complete. 2/7 partial (Hono, Turso).**

---

### Feature Completeness

**Fully implemented (~23 features):**
- Admin: Dashboard, Course CRUD, Course Sections, AI Importer, Course Builder, Users, Team Management, Completions log, Branding system, Settings/Backup
- Manager: Dashboard, Courses, Team view, CSV bulk import, Completions, Assignments with due dates
- Learner: Course catalogue, Course player, Quiz engine (per-question feedback), Certificates (branded PDF), Progress tracking
- Platform: Dark/light theme, RBAC (server-side enforced), JWT auth all three roles, Branding runtime, Session safety/expiry warning

**Partially implemented:**
- Tags — schema + API + DB done; Admin UI stubs show "coming soon"
- CSV import into Course Builder — UI exists, parse + merge pipeline not implemented
- Learner list pagination — renders all at once; degrades at 500+

**Not started (web scope):**
- Email notifications (critical retention gap)
- Multi-tenant SaaS architecture (1 deployment = 1 org)
- SSO / SCIM / HRIS integrations

---

### Locked RN Architecture Decisions

Decisions locked during Designer Review (2026-05-20). These are binding for the P1 build.

**Decision 1 — Token migration format:**
Both: a TypeScript `tokens.ts` constants file (feeds StyleSheet objects) AND `tailwind.config.js` values referencing the same constants (consumed via NativeWind). Runtime brand overrides are handled via React Context, not the token file. Existing CSS variable names (`--brand`, `--surface`, `--ink-1`) map directly to Tailwind keys.

**Decision 4 — Press-state strategy:**
`Pressable` with `style={({ pressed }) => [baseStyle, pressed && pressedStyle]}`. Explicit color/scale changes only — no `TouchableOpacity` opacity flashes.

**Decision 5 — Navigation architecture:**
- Admin: 5 bottom tabs — Dashboard, Courses, Users, Reports, Settings
- Manager: 4 bottom tabs — Dashboard, Courses, Team, Completions
- Learner: 4 bottom tabs — Courses, Progress, Certificates, Account
- Course viewer: modal stack pushed from course list in all three roles (back-swipe dismisses)
- All tab bars use React Navigation `BottomTabNavigator`

**Decision 6 — Runtime brand theming:**
`ThemeContext` + `useTheme()` hook. On app launch, fetch `/api/brand`, store in context. NativeWind handles static dark/light via `dark:` class variant. Dynamic brand colors applied via inline `style` props reading from `useTheme()`. Static structural tokens are Tailwind config values resolved at build time.

**Decision 7 — Shadow-brand / focus ring:**
Replace `box-shadow: 0 0 0 3px rgba(brand, 0.2)` (unsupported spread in RN) with `borderWidth: 2, borderColor: theme.brand` on focus. Toggle via `onFocus`/`onBlur`.

**Decision 8 — Backdrop-filter:**
`expo-blur` `BlurView` for modal overlays and certificate overlay. Bare workflow fallback: `rgba(0,0,0,0.80)` background.

---

### Blocking Issues

**BLOCKING — Cannot proceed to P1:**

| # | Issue | Detail |
|---|---|---|
| B1 | No Expo project | `npx create-expo-app` not yet run; no `app.json`, no root `package.json`, no RN dependencies |
| B2 | No Clerk project | Apple Sign-In + Google Sign-In required; not configured |
| B3 | No EAS project | `eas.json` missing; no build profiles |
| B4 | No Sentry projects | Two projects (`trainingflow-app`, `trainingflow-api`) required; neither created |

**SIGNIFICANT — Rework required before/during migration:**

| # | Issue | Detail |
|---|---|---|
| S1 | AI keys in localStorage | Route through existing `/api/ai/generate` worker endpoint instead |
| S2 | `admin.js` at 1,618 lines | Must split before RN module-per-screen architecture |
| S3 | No Drizzle ORM | 45+ routes use raw SQL; Drizzle migration needed before RN API layer |
| S4 | No RevenueCat project | B2B per-seat pricing needs to be architected |

---

### What to Run Next

**Next step: P1 — Expo Project Setup**

1. `npx create-expo-app trainingflow-native` with TypeScript template
2. `eas build:configure` — create `eas.json` with dev/preview/production profiles
3. Clerk project creation — enable Apple Sign-In + Google Sign-In
4. Sentry project creation — two projects (`trainingflow-app`, `trainingflow-api`)
5. RevenueCat project creation — define entitlement structure for B2B per-seat model
6. `tokens.ts` — scaffold from existing CSS variable names (locked in Decision 1)
7. `tailwind.config.js` — NativeWind config pointing to token values
8. `ThemeContext` + `useTheme()` — brand runtime theming (locked in Decision 6)

Do NOT run the Architect refactor pass (splitting `admin.js`, adding Drizzle) in P1 — risks destabilizing the working web app before the RN scaffold is proven. Sequence: scaffold first, migrate screens second, refactor API third.

---

## Documentation History — 2026-05-20

**Consolidation pass — 7 files audited, 4 actions taken:**

| File | Action | Reason |
|---|---|---|
| `CLAUDE.md` | Updated | Absorbed: full DB schema with column detail, full API route table (45+ routes), complete env var reference, demo seeding commands, locked RN architecture decisions (Decisions 1/4/5/6/7/8), security audit summary (F1–F15), current branding system detail. Removed stale "CLAUDE.md Health" self-referential section. |
| `AUDIT.md` | Archived → `docs/archive/AUDIT.md` | 1,001-line historical record of 4 review stages (Architect, Security, Strategist, Designer) with execution logs. Too large for active use; key decisions extracted to CLAUDE.md. Preserved for reference. |
| `QA-REPORT.md` | Archived → `docs/archive/QA-REPORT.md` | 29-bug QA audit log; 26 of 29 resolved. 3 remaining (B-04, B-06, D-10) already tracked in ACTIVE_BUGS.md. |
| `branding_plan.md` | Deleted | Pre-implementation plan for 3-color branding system. System is implemented and reflected in current code and CLAUDE.md design system section. No ongoing reference value. |
| `README.md` | Kept as-is | Accurate, richly detailed public-facing GitHub reference. |
| `ACTIVE_BUGS.md` | Kept as-is | Current active issue tracker. |
| `docs/kb-scraper-integration.md` | Kept as-is | Active future-work stub referenced in backlog. |

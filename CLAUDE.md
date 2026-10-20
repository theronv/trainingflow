# Pregame Academy — Project Guide

Team workflow (branches, PRs, checks, deploy rules): @CONTRIBUTING.md

## What This Is

Pregame Academy is a full-stack LMS for professional teams. AI-assisted course creation, role-based access (Admin / Manager / Learner), targeted assignments, progress tracking, and verifiable PDF certificates.

**Live app:** https://theronv.github.io/trainingflow/

---

## Current Stack (as of 2026-05-20)

| Layer | Technology |
|---|---|
| Frontend | Vanilla JS (ES6), HTML5, CSS3 — SPA served from GitHub Pages |
| Edge Worker | Hono 4.7.0 on **Cloudflare Workers** (not Vercel Edge) |
| Database | Turso (libSQL/SQLite) via `@libsql/client` v0.14.0 — raw SQL, no Drizzle |
| Auth | Custom JWT + PBKDF2-SHA256 (100k iterations); Clerk email sign-in exchanges for the same app JWT |
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
├── auth.js           # Login/register for Admin, Manager, Learner (74 lines)
├── admin.js          # Admin portal (1,017 lines — still oversized, see Architecture)
├── importer.js       # AI Importer (555 lines — split out of admin.js)
├── manager.js        # Manager portal (460 lines)
├── learner.js        # Learner portal (530 lines)
├── builder.js        # Course builder — module/question editor (148 lines)
├── demo.js           # Interactive demo sandbox — fixture team + playable course, in-memory fake API (see Demo below)
└── app.js            # AppProxy — wires onclick attrs to JS modules (477 lines)
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

## Testing

Worker has a Vitest suite that drives the real Hono `app` against an in-memory
libSQL DB (no mocks — `getDb()` honours a test-only `env.DB_CLIENT` hook):

```bash
cd worker && npm test            # one-shot
cd worker && npm run test:watch  # watch mode
```

Coverage: `worker/test/` — `auth` (login + rate limiting), `rbac` (role gates + manager team scoping), `scoring` (answer-key stripping, server-side grading and score computation), `scrape` (URL import validation). `importer` (the frontend `js/importer.js` loaded with browser globals stubbed: reply parsing, question validation, answer shuffling, prompt building, reply merging, save validation). `learner` (the source-link visibility helper), `sections-ui` (`js/sections.js`: section move/collapse logic) and `sections` (incl. the order endpoint). The rest of `js/` has no tests yet.

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

**Shipping:** work on a branch and open a PR into `main` (see `CONTRIBUTING.md`). A push to `main` publishes the frontend, and one touching `worker/**` deploys the worker to production. Never run DB migrations, `wrangler secret`, or destructive `turso` commands without asking.

## Demo Data Seeding (local dev only)

The public **Demo** is a client-side sandbox (see "Demo" below) and needs nothing in Turso. The seeded users were removed from production on 2026-10-16. `worker/seed-demo.mjs` remains for populating a **local/dev** database — do **not** run it with `--prod`: `--reset` also deletes `brand`, `admin`, and every real user and team.

```bash
cd worker && node seed-demo.mjs          # local dev DB; demo password is demo1234
```

---

## Database Schema

All tables defined in `schema.sql`. The `course_progress` table is also created lazily by the worker on first write.

| Table | Key Columns | Notes |
|---|---|---|
| `users` | `id TEXT PK`, `name TEXT UNIQUE`, `password_hash TEXT`, `role TEXT` ('manager'\|'learner'), `is_admin INTEGER`, `team_id INTEGER → teams`, `email`, `clerk_id` | Capabilities, not exclusive roles: everyone can learn, `role='manager'` adds team management, `is_admin=1` adds administration. The legacy shared-password admin (`ADMIN_PASSWORD_HASH`) has no row |
| `teams` | `id INTEGER PK AUTOINCREMENT`, `name TEXT UNIQUE` | Organizational units |
| `invite_codes` | `id INTEGER PK`, `code TEXT UNIQUE`, `team_id → teams`, `used INTEGER`, `expires_at TEXT` | Single-use, scoped to a team |
| `courses` | `id TEXT PK`, `icon TEXT`, `title TEXT`, `description TEXT` | `updated_at` auto-updated via trigger |
| `modules` | `id TEXT PK`, `course_id → courses CASCADE`, `title TEXT`, `content TEXT`, `sort_order INTEGER` | Indexed by `(course_id, sort_order)` |
| `questions` | `id TEXT PK`, `module_id → modules CASCADE`, `question TEXT`, `option_a/b/c/d TEXT`, `correct_index INTEGER`, `explanation TEXT`, `sort_order INTEGER` | Answer key — strip from public responses (see Security) |
| `assignments` | `PK (course_id, learner_id)`, `due_at TEXT` | Composite PK prevents duplicates |
| `completions` | `id TEXT PK`, `course_id → courses`, `learner_id → users CASCADE`, `score INTEGER`, `passed INTEGER`, `cert_id TEXT UNIQUE` | Multiple completions per learner/course allowed (retakes) |
| `module_progress` | `PK (learner_id, module_id)`, `course_id`, `passed`, `score`, `completed_at` | Per-module progress for resume |
| `course_progress` | `PK (learner_id, course_id)`, `module_idx INTEGER`, `modules TEXT` (JSON) | Resume position; created lazily by worker |
| `quiz_answers` | `PK (learner_id, question_id)`, `selected_index`, `is_correct`, `answered_at` | Latest server-graded answer per learner/question; source of truth for completion scores; consumed on completion |
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
| `GET` | `/api/courses` | Any authenticated | List all courses |
| `POST` | `/api/courses` | Admin | Create a course (batch insert via `db.batch()`) |
| `GET` | `/api/courses/:id` | Auth required | Get course with modules + questions (answer key stripped for non-admin tokens) |
| `PATCH` | `/api/courses/:id` | Admin | Update course metadata |
| `PUT` | `/api/courses/:id` | Admin | Full course replace (modules + questions) |
| `DELETE` | `/api/courses/:id` | Admin | Delete course (cascades to modules, questions) |
| `GET` | `/api/sections` | Any authenticated | List all sections |
| `POST` | `/api/sections` | Admin | Create a section |
| `PATCH` | `/api/sections/:id` | Admin | Rename a section |
| `PUT` | `/api/sections/order` | Admin | Save display order: `{ids}` must list every section exactly once (400 malformed, 409 if the set changed); `sort_order` = position |
| `DELETE` | `/api/sections/:id` | Admin | Delete a section |
| `GET` | `/api/learners` | Admin/Manager | List learners (team-scoped for managers) |
| `POST` | `/api/learners` | Admin/Manager | Create a learner (team_id locked to manager's team) |
| `POST` | `/api/learners/bulk` | Admin/Manager | Bulk create from CSV |
| `GET` | `/api/learners/me` | Any account | Get own profile |
| `PATCH` | `/api/learners/me` | Any account | Update own name/password |
| `GET` | `/api/learners/:id` | Admin/Manager | Get learner (managers: team-scoped) |
| `PATCH` | `/api/learners/:id` | Admin | Edit user (name, team, role, email, `is_admin`) |
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
| `POST` | `/api/admin/invites` | Admin | Create an invite (`role` manager\|learner, `team_id`, `expires_in_days` default 7 / max 90, `max_uses`); server generates the code |
| `GET/POST/DELETE` | `/api/invites[/:id]` | Admin/Manager | Team-scoped invite management (managers: learner invites for their own team only) |
| `GET` | `/api/auth/invite/:code` | — | Public preview: `{role, team_name}` for a valid code |
| `POST` | `/api/auth/register` | — | Redeem an invite (learner or manager): invitee chooses name + password, is signed in. Rate-limited |
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
| `POST` | `/api/quiz/answer` | Learner | Grade one answer server-side; returns `{correct, correct_index, explanation}` |
| `POST` | `/api/completions` | Learner | Finish a course — score/passed computed server-side from `quiz_answers`; returns `{cert_id, score, passed}` |
| `GET` | `/api/progress/me` | Learner | Own module progress |
| `POST` | `/api/progress` | Learner | Save module progress |
| `DELETE` | `/api/progress/:course_id` | Learner | Clear progress for a course |
| `GET` | `/api/admin/tags` | Admin/Manager | List tags |
| `POST` | `/api/admin/tags` | Admin | Create a tag |
| `DELETE` | `/api/admin/tags/:id` | Admin | Delete a tag |
| `GET` | `/api/scrape` | Admin | Proxy Jina Reader fetch for KB Scraper integration (planned) |

---

## Roles & sessions (multi-role accounts)

One account can learn, manage and administer.
- **Token:** `issueSession()` (worker) builds the JWT: `{ id, name, role (highest), roles: ['learner','manager','admin'], team_id }`. Legacy tokens with only `role` still work; `rolesOf()` normalises both.
- **Middleware:** `requireLearner` = any token with an `id` (so managers/admins can take courses; the id-less shared-password admin cannot). `requireManager` = manager (team-scoped) or admin (unscoped; admin wins if both). `requireAdmin` = `roles` contains admin.
- **Admin sources:** `users.is_admin` (set in Admin → Users → Edit, or `PATCH /api/learners/:id {is_admin}`; you can't remove your own) and the `ADMIN_EMAILS` secret, which on Clerk sign-in finds/creates the user's row and records `is_admin=1`. The `is_admin` column is added by `setupRoles()` on first request.
- **Assignments:** admins can assign to managers by picking them individually; team selections and team managers only ever reach learners.
- **Frontend:** `Auth._enter()` stores the one token in every slot the person is entitled to plus `tf_user`/`tf_view` (sessionStorage); `Auth.openView('admin'|'manager'|'learner')` switches portals (topbar "My learning" / "← Admin|Manager"). `curManager` is only set while in the manager view (the assign modal picks its API from it).

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

**`admin.js` is 1,017 lines** — AI Importer already extracted to `importer.js` (555 lines). Branding, Teams, Learners, Dashboard still in one object. Should be split further before RN migration.

**`worker/index.js` is 1,277 lines** — all 45+ routes in one file. Schema migration calls (`setupBrand()`, `setupSections()`, `setupTags()`) are now guarded by `ensureSetup()` + a module-level `_setupComplete` flag, so the `ALTER TABLE`/`CREATE TABLE IF NOT EXISTS` statements run **once per Worker isolate**, not per request. (Previously per-request — fixed.)

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

## Visual Refinement — 2026-06-18

Visual design pass on the **web app** (vanilla JS SPA — the RN/NativeWind target in the original brief does not exist yet; the pass was retargeted to the live codebase with each RN technique mapped to its web equivalent). Auth and data/render logic untouched — presentation only.

**Tokens / depth (`css/style.css`):**
- Added `--scrim` / `--scrim-strong` for modal & certificate backdrops; replaced the last hardcoded `rgba(0,0,0,…)` scrims, `.chip-blue` border, and `.source-banner-link:hover` with tokens.
- Added `--surface-raised` (aliases `--surface-2`) and an explicit elevation ladder: `bg < bg-2 < surface (cards) < surface-raised (modals)`. Modals now read above the card layer instead of matching it.
- Removed stray hardcoded hex in markup/JS (`index.html` cert preview `#666` → `--ink-3`; `importer.js` answer-option `#bbf7d0`/raw px → `--pass-border` + spacing tokens). Remaining hex are **data**, not style: brand-palette preset swatches and `core.js` `DEFAULT_C*` seeds.

**Components:**
- `.btn` now has `min-height: 44px` (`.btn-sm` 36 / `.btn-lg` 48 / `.btn-xl` 52; `.btn-icon` opted out) — tap targets meet 44pt, aligning the CSS with what the design-system notes already claimed.
- Rich empty-state component (`.empty` = icon + headline + supporting text + optional `.empty-action`) hardened and applied to the screenshot-critical lists: learner Courses/Certificates, manager Dashboard activity, admin Courses (with a "+ New Course" action). Table-row empties (`colspan`) left inline by design.

**Typography:**
- `font-variant-numeric: tabular-nums` on numeric displays (`.stat-value`, `.score-big`, `.qr-score`, all `table`) plus `.tabular` / `.mono` utilities for aligned figures.

**Motion (CSS, RN-technique → web):**
- Press feedback `:active { transform: scale(0.97) }` on `.btn` (and lighter scales on `.course-card`, `.role-tile`, `.quiz-opt`).
- List entrance retuned: `.stagger` now `listIn` (fade + 8px rise, **150ms**, 8-step stagger) — was a 400ms `fadeUp` that violated the 350ms cap.
- Modal/overlay entrance: `fadeIn` backdrop + `modalIn` (200ms, 12px rise + scale).
- **`@media (prefers-reduced-motion: reduce)`** added — collapses animations/transitions to ~0ms and disables press transforms; the loading spinner keeps a minimal rotation so loading state stays legible.

**Not changed (deliberate):** the base spacing scale is a 4pt grid (`--space-1` = 4px) driving an 8pt rhythm — standard, left as-is; off-grid button paddings (`10/16`) are conventional and were not churned. No JS data flow, hooks, or auth touched.

---

## Brand — Pregame Academy (2026-10-15)

Renamed from TrainFlow and re-skinned to match the Pregame site (pregame.vickerydigital.com):
- Tokens: brand black + electric blue `#1565ff`, indigo `#1b1a5c`, amber `#d99100`; light surfaces `#f3f5fa`/`#fff`, dark `#05060a`/`#0e1118`. Text-safe `--accent`/`--accent-strong`/`--why-bg` for links and active states.
- Look: black topbar, aurora page-head hero (`--hero`), uppercase tracked labels, 6px buttons, 16px cards, system font stack. Theme follows the OS until the user toggles it.
- Logo: `assets/academy-icon-{192,512}.png` (graduation cap over the three-bar Pregame motif; source `assets/academy-icon.svg`) is the default logo/favicon on every surface; an admin-uploaded logo overrides it.
- Legacy defaults (`TrainFlow`, old blues/purples, `Inter`) saved in the `brand` row are migrated to the new defaults at runtime by `normBrand()`; customised values are kept.
- Deliberately **not** renamed (internal identifiers): the Worker/DB names (`trainflow-worker`, `trainflow-theronv`), repo/Pages path (`/trainingflow/`), and `trainflow_*` localStorage/sessionStorage keys — changing them would break the deployed URL and sign users out.

## Content Importer — 2026-10-20

Admin → AI Importer (`js/importer.js`). Lessons are imported **verbatim** (Markdown files, or web pages via Jina); AI only writes the summary, objectives and questions.
- **Claude.ai route (default, no API key):** Configure → "Build Claude prompts" splits modules into prompts of ≤30k chars (`PROMPT_CHAR_BUDGET`), each lesson tagged with a stable id (`m1`, `m2`…; screenshots become `[Screenshot: alt]` markers). The admin pastes each prompt into Claude.ai and pastes the reply (or `questions.json`) back; `applyQuestionsReply()` matches entries by id, validates every question, and shuffles option order (except "all of the above" style options). A module's entry is applied only if fully valid; lesson text and titles are never overwritten by a reply.
- **API-key route:** collapsed under "Use an API key instead"; same validation and shuffling, one call per module.
- **Review is editable:** titles, summaries, objectives, lesson text, questions, correct answers; add/remove questions and modules; "Redo with Claude" per module. Saving is blocked (with a list of problems) until every module has valid questions (`validateCourse()`).
- **Drafts:** state is saved to `localStorage` (`trainflow_import_draft`) so a refresh or closed tab can resume from the Upload screen.
- Full-course JSON import (Claude writes everything) still exists on the Upload screen and shares the same question validation.

**Course sections (collapse + order):** `js/sections.js` is shared by the Admin, Manager and Learner course lists. Section headers have a fold button; collapsed ids live per browser in `localStorage` (`trainflow_collapsed_sections`) and collapsing a parent hides its sub-sections. Admin headers also have move up/down buttons (siblings only; a parent carries its sub-sections), saved through `PUT /api/sections/order`; since all three lists use `orderSections()`, the saved order shows everywhere. The Admin page has a Collapse all / Expand all button.

**Hidden source links:** `HIDDEN_SOURCE_DOMAINS` at the top of `js/learner.js` lists hosts whose `reference_url` never renders the learner "Before You Begin / Open Source Material" banner (currently `support.synergysports.com`, being retired). The URL stays stored; add hosts to the list as needed (subdomains match too).

## Demo — 2026-10-16

"Demo" on the landing page opens a picker: **as a manager** (sample Patient Services team of five, progress, overdue, completions, assign flow) or **as a learner** (full Customer Service Excellence course: lessons, quizzes, certificate PDF). It is entirely client-side:
- `makeApi()` in `core.js` short-circuits to `Demo.handle()` while `isDemo` is true — no Worker calls, nothing stored; state is rebuilt on every launch. The real manager/learner screens run unchanged.
- Fixtures live in `js/demo.js` (the course is a copy of the seed script's Customer Service Excellence). Demo learner is Jamie Lee; finishing the course adds a completion that the manager view then shows (switch roles via the bar at the bottom).
- Demo users do not exist in Turso; `seed-demo.mjs` is only for local dev.

## UI Polish — 2026-10-14

Presentation-only passes on the web app (no data flow/auth changes), all at the end of `css/style.css` under "ENTERPRISE POLISH" / "RESPONSIVE SHELL":
- New default palette: `#1B78F2` primary, `#241C59` secondary, `#D9631E` accent (fallbacks only — the saved `brand` row in Turso still wins).
- Landing: SVG role tiles. Shell: Inter sentence-case sidebar, 56px topbar, 1240px content cap. Course library (`.cc`) and learner course cards (`.lc`).
- Mono/uppercase "terminal" labels retired; chips are pills; pass = green (`chip-green`), not `chip-brand-accent`.
- ≤860px: sidebar becomes a horizontal tab strip; course player stacks.
- AI Importer: "Import from web pages" (browser→Jina first, `GET /api/scrape` Worker proxy fallback; optional `JINA_API_KEY`).

---

## Security Status (last verified against code 2026-10-14)

F1–F12 are fixed and covered by `worker/test/`. **F1/F2 were regressed and are now closed again** — with a different design than the original:

- **F1 (answer key):** `GET /api/courses/:id` strips `correct_index` and `explanation` for every non-admin token. Learners grade answers one at a time with `POST /api/quiz/answer`, which returns the verdict (and key) only for the question just answered.
- **F2 (score integrity):** `POST /api/completions` ignores any client `score`/`passed`. It computes the score from the learner's server-recorded rows in `quiz_answers` (latest answer per question), requires every course question to be answered, writes `completions` + `question_responses` in one batch, and consumes the answers so a certificate can't be re-minted without retaking the quiz.
- **Unauthenticated catalog closed:** `GET /api/courses` and `GET /api/sections` now require a token (demo mode uses a built-in sample catalog, `DEMO_COURSES` in `js/core.js`).
- **Known residual risk:** because retakes are allowed and the key is revealed per answered question, a determined learner can probe answers by repeated attempts. This is inherent to retake-friendly quizzes; add attempt limits/cooldowns if certificates need stronger assurance.

Verified present:
- **F3–F8 (HIGH):** Team ownership enforced on manager routes; `requireLearner` checks `role === 'learner'` (`worker/index.js:152`); `team_id` locked to manager's own team
- **F9–F12 (MEDIUM):** Password min-length enforced; current password required to change admin password; DB error detail removed from 500 responses (`app.onError` returns generic message); tag endpoints team-scoped
- **F15 accepted** (safe hardcoded CORS fallback)

---

## Known Limitations (open backlog)

| ID | Issue | Effort |
|---|---|---|
| B-04 | CSV import into Course Builder — stub | ~2 hrs |
| B-06 | Tags feature — schema/API exist, UI incomplete | ~3 hrs |
| ~~D-10~~ | ~~Learner list pagination~~ — DONE: server-side `PAGE_SIZE`/`OFFSET` on `/api/learners` (`worker/index.js:604`) | — |
| — | Real-time dashboard updates (no SSE/WebSocket) | large |
| — | Logo CDN (base64 inflates API responses) | medium |
| — | KB Scraper → AI Importer integration | planned |

---

## Migration Status — 2026-05-20

### Context

Pregame Academy is a vanilla JS SPA, not a React Native / Expo app. The "VD Canonical Stack" (Expo / Vercel Edge / Clerk / RevenueCat / Sentry / EAS) is the migration target for a future native build. All four pre-migration review stages are complete (Architect, Security, Strategist, Designer). Architecture decisions for RN are locked (see below).

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
| S1 | AI keys in localStorage | Server proxy `/api/ai/generate` exists (`requireAdmin`, reads `CLAUDE_API_KEY`/`GEMINI_API_KEY` env secrets); frontend still defaults to localStorage keys — finish routing the browser through the proxy |
| S2 | `admin.js` at 1,017 lines | AI Importer already split to `importer.js`; split remaining concerns before RN module-per-screen architecture |
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

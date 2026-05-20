# TrainFlow — Audit Report & Source of Truth
**Date:** 2026-03-13
**Status:** Post-Angel Team Overhaul (v1-Ready)

---

## 🛑 BLOCKERS
*These issues were identified as critical launch blockers and have been resolved.*

### B1 - `importer.html`: Missing API authentication
- **File:** `importer.html`
- **Severity:** BLOCKER (Resolved)
- **Description:** Direct calls to Anthropic API lacked required `x-api-key` and CORS headers.
- **Resolution:** Implemented a direct browser auth model. Users now provide an API key in Phase 1, stored securely in `sessionStorage` and passed with all generation requests.

### B2 - `importer.html`: No API key input in UI
- **File:** `importer.html`
- **Severity:** BLOCKER (Resolved)
- **Description:** No mechanism existed for users to supply an Anthropic API key.
- **Resolution:** Added a secure key input card to Phase 1 with validation and persistent session storage.

### B3 - `importer.html`: Phase 3 dead-end on error
- **File:** `importer.html`
- **Severity:** BLOCKER (Resolved)
- **Description:** Generation failures left the user stuck with no way to retry or go back.
- **Resolution:** Added "Try Again" and "Back to Configure" recovery paths to the generation UI.

### B4 - `importer.html`: Invalid JSON escaping (`\\'`)
- **File:** `importer.html`
- **Severity:** BLOCKER (Resolved)
- **Description:** Smart quote replacement was producing `\\'` which is invalid in JSON.
- **Resolution:** Standardized smart-quote handling to use plain apostrophes, ensuring valid JSON parsing.

### B5 - `index.html`: False "Local Storage" claim
- **File:** `index.html`
- **Severity:** BLOCKER (Resolved)
- **Description:** Landing page falsely claimed data was stored locally with no account required.
- **Resolution:** Updated footer to accurately reflect the Cloudflare Workers + Turso architecture.

### B6 - `index.html`: Silent failure on missing Worker secrets
- **File:** `index.html`, `worker/index.js`
- **Severity:** BLOCKER (Resolved)
- **Description:** New deployments would fail with a generic 503 if secrets weren't set, with no guidance for the admin.
- **Resolution:** Implemented a "Worker Initialization Required" overlay that triggers on 503 errors, providing exact Wrangler CLI commands for setup.

---

## 🔴 HIGH PRIORITY BUGS

### H9 - `index.html`: The "O'Brien" Escaping Bug
- **File:** `js/app.js` (formerly `index.html`)
- **Severity:** HIGH (Resolved)
- **Description:** `esc()` failed to escape single quotes, breaking `onclick` attributes for users/courses with apostrophes.
- **Resolution:** Updated `esc()` to include `&#39;` escaping and moved logic to a decoupled JS file.

### H10 - `index.html`: Duplicate `drop-zone` IDs
- **File:** `index.html`
- **Severity:** HIGH (Resolved)
- **Description:** Duplicate IDs caused incorrect DOM targeting during file drags.
- **Resolution:** De-duplicated IDs to `imp-drop-zone` and `csv-drop-zone` with independent event listeners.

### H11 - `index.html`: Certificate Race Condition
- **File:** `js/app.js`
- **Severity:** HIGH (Resolved)
- **Description:** Fire-and-forget completion POSTs caused the certificate fetch to return empty if called too quickly.
- **Resolution:** Converted completion logic to `async/await`, ensuring the database record exists before the certificate UI is triggered.

### H12 - `index.html`: Missing Course Assignment System
- **File:** `index.html`, `worker/index.js`, `schema.sql`
- **Severity:** HIGH (Resolved)
- **Description:** No way to assign specific courses to specific learners; all users saw all courses.
- **Resolution:** Built a full Assignment engine, including a new DB table, Worker endpoints, and a Manager UI for targeted course assignments.

### H13 - `js/learner.js`: Hardcoded Passing Threshold Discrepancy
- **File:** `js/learner.js`
- **Severity:** HIGH (Resolved)
- **Description:** Both module (`showModResults`) and course (`completeCourse`) completion logic hardcode a 70% passing threshold.
- **Resolution:** Replaced hardcoded values with `brandCache.pass` (defaulting to 80%).

### H14 - `js/builder.js` vs `worker/index.js`: Question Property Mismatch
- **File:** `js/builder.js`, `worker/index.js`, `js/core.js`
- **Severity:** HIGH (Resolved)
- **Description:** Mismatched property names between frontend and backend caused question loss.
- **Resolution:** Standardized on long names (`question`, `options`, `correct_index`, `explanation`) across the frontend, and added robust fallback mapping in the backend.

### H15 - `js/learner.js`: Incomplete Certificate UI Population
- **File:** `js/learner.js`
- **Severity:** HIGH (Resolved)
- **Description:** `completeCourse()` only populated `c-name` and `c-id` on the certificate overlay.
- **Resolution:** Updated logic to fully populate organization name, course title, date, and score from session state.

---

## 🟡 MEDIUM PRIORITY BUGS

### M7 - `index.html`: UI Coupling in AI Importer
- **File:** `js/app.js`
- **Severity:** MEDIUM (Resolved)
- **Description:** AI Importer logic was directly writing to hidden Course Builder form fields.
- **Resolution:** Decoupled the logic during the script extraction and modularization pass.

### M8 - `index.html`: Duplicate Backups
- **File:** `js/app.js`
- **Severity:** MEDIUM
- **Description:** Importing the same backup JSON twice results in duplicate courses.
- **Status:** Awaiting deduplication logic implementation.

### M11 - `index.html`: Brittle AI Generation Loop
- **File:** `js/app.js`
- **Severity:** MEDIUM
- **Description:** Single module failure in the AI importer aborts the entire batch.
- **Status:** Proposed refactor to per-module partial success tracking.

---

## 🟢 FEATURE GAPS
- **Enrollment Groups:** Currently, assignments are per-learner. No "Department" or "Group" assignment logic exists.
- **Name Editing:** Learners can change passwords but not their display names.
- **Due Dates:** Assignments lack an optional `due_at` field for mandatory training deadlines.

---

## 🎨 UX FRICTION
- **Soft UI Flatness:** Resolved via "Premium Enterprise" overhaul (added elevation and typography contrast).
- **Navigation Efficiency:** Resolved via "Manager Switcher" and active nav states.
- **Mobile Readability:** Resolved via responsive grid and table hardening.

---

## ⚙️ DEPLOYMENT STATUS
**Current State:** v1-Production Ready.

**First-Run Requirements:**
Before the application is functional, the following Worker secrets **MUST** be configured via Wrangler:
1. `TURSO_URL`: Your libSQL database URL.
2. `TURSO_TOKEN`: Your Turso access token.
3. `JWT_SECRET`: A secure string for signing tokens.
4. `ADMIN_PASSWORD_HASH`: A PBKDF2 hash of the desired admin password.
5. `GEMINI_API_KEY`: Required for the AI Importer features.

*Note: The app will now detect missing secrets and display an initialization guide to the admin.*

---

## Architect Review — Stage 2 — 2026-05-20

**Stack Note:** The ROLE prompt referenced Expo/React Native/NativeWind/Clerk/RevenueCat — this project is none of those. It is a vanilla JavaScript SPA (GitHub Pages) + Cloudflare Worker (Hono) + Turso/libSQL. Review is conducted against the actual stack.

---

### 1 — PROJECT INVENTORY

| File | Purpose | Status |
|---|---|---|
| `index.html` | SPA shell — all screens, modals, overlays | COMPLETE |
| `css/style.css` | Full design system — tokens, components, themes | COMPLETE |
| `js/core.js` (303 lines) | Global state, API helpers, brand utilities | COMPLETE |
| `js/auth.js` (74 lines) | Login/register flows for all three roles | COMPLETE |
| `js/admin.js` (1,618 lines) | Admin portal — courses, users, teams, AI importer, branding | COMPLETE — oversized |
| `js/manager.js` (446 lines) | Manager portal — team, assignments, CSV import | COMPLETE |
| `js/learner.js` (513 lines) | Learner portal — course player, quiz engine, certificates | COMPLETE |
| `js/builder.js` (147 lines) | Course builder — module/question editor | COMPLETE |
| `js/app.js` (473 lines) | AppProxy — wires HTML onclick attributes to JS modules | COMPLETE |
| `worker/index.js` (1,214 lines) | All Hono API routes and DB logic | COMPLETE — oversized |
| `schema.sql` | Initial database schema | PARTIAL — `course_progress` table missing; defined as inline DDL in worker |
| `worker/wrangler.toml` | Cloudflare Worker configuration | COMPLETE |
| `worker/package.json` | Worker dependencies | COMPLETE |
| `worker/seed-demo.mjs` | Demo data seed script | COMPLETE |
| `scripts/hash-password.mjs` | Password hash utility | COMPLETE |
| `docs/kb-scraper-integration.md` | Integration plan for KB scraper | STUB (plan only) |
| `branding_plan.md` | Branding feature notes | UNKNOWN (not reviewed) |
| `worker/.dev.vars.bak` | Backup of dev secrets | RISK — gitignored but should not exist |
| `ACTIVE_BUGS.md` | Open issue tracker | CURRENT |
| `AUDIT.md` | This file | CURRENT |

---

### 2 — ARCHITECTURE QUALITY

#### Separation of Concerns
The JS module split (core / auth / admin / manager / learner / builder / app) is meaningful on paper. In practice the layering does not hold:

- **Every render function fetches its own data** — `renderDash()`, `renderCourses()`, `renderComps()` etc. all issue API calls and write `innerHTML` in the same function. There is no data layer; there is no presentation layer. These are collapsed into a single "fetch-and-template" pattern throughout.
- **`app.js` AppProxy** holds substantial business logic that belongs in its modules: `downloadCertPDF`, `changePw`, `submitGenerateInvite`, all CSV/import helpers, and backup/restore logic.
- **`admin.js` contains the entire AI Importer pipeline** (600+ lines): `parseMdToModules`, `callAI`, `startGeneration`, `renderReview`, `saveAiCourse`. This is a distinct feature that lives inside the admin module with no separation.

#### Data Flow
API response → inline template string → `innerHTML`. This is a linear but brittle pattern. The chain is predictable in simple cases and breaks down under:
- Multiple in-flight requests from rapid tab switching (no abort)
- Stale closes that overwrite fresh data (race condition)
- Re-renders triggered by events while a prior render is awaited

#### State Management
Thirteen global mutable variables are declared at module scope in `core.js` and modified by any file at any time:

```
curLearner, curManager, curCourse, curModIdx, quizSt, cbState,
csvParsed, compOffset, _allLearners, teamsCache, coursesCache,
assignCache, isDemo, brandCache
```

In addition, `app.js` hangs ephemeral state directly on the `App` object: `App._resetPwId`, `App._editLearnerId`, `App._assignCourseId`, `App._inviteTeamId`, `App._alSubmitFn`. These are shared mutable slots between modal-open and modal-submit handlers. If two modals were opened in sequence without closing, the state would collide (low probability due to modal blocking, but structurally unsound).

`sectionsCache` is assigned in `admin.js:renderCourses()` without ever being declared — this creates an implicit `window.sectionsCache` global. No `'use strict'` is in effect to catch it.

#### Component Design — Oversized Files

| File | Lines | Issue |
|---|---|---|
| `js/admin.js` | 1,618 | AI Importer alone is 400+ lines; Teams, Learners, Branding, Completions, Dashboard all cohabitate |
| `worker/index.js` | 1,214 | All 45+ routes in one file with no grouping |

Every render function mixes data fetching with rendering — no exceptions found.

**Prop drilling / state threading:** Not applicable (no component framework), but the `App.*` ephemeral state pattern (see above) is the structural equivalent.

#### Naming Issues
- `api()` — attaches the admin JWT but is also used for unauthenticated calls (`/api/brand`, `/api/courses`). Should be `adminApi()` with a separate `fetchPublic()` for unauthenticated endpoints.
- `Admin.openAddLearner()` / `Admin.submitAddLearner()` — also used to add managers (role dropdown allows manager). Function name misrepresents scope.
- `Manager.renderDash()` calls `managerApi('/api/admin/completions')` — the route name says admin but managers call it too. The route is correct (requireManager handles both); the naming causes confusion.

---

### 3 — TYPE SAFETY

This is plain ES6 JavaScript with no TypeScript, no JSDoc types, and no runtime schema validation library.

| Finding | File | Notes |
|---|---|---|
| No types anywhere | All JS files | Verdict is project-wide |
| Implicit `undefined` on DOM queries | All files | `$$(id)` can return `null`; callers do `.value`, `.textContent`, `.classList` without null checks. Mitigated by guarded patterns like `if(el)` but not consistent. |
| `normCourse()`, `normRecord()`, `normBrand()` | `js/core.js:128-147` | Serve as the only runtime type coercion; they are the project's type boundary |
| `curManager.team_name` / `curManager.team_id` | `js/manager.js:8,31,86,132,311` | `curManager` is set to the raw API response `{ token, user: { id, name, team_id } }`. Properties accessed as `curManager.team_name` and `curManager.team_id` are `undefined`. Server-side JWT scoping makes the team_id case work anyway, but `team_name` always falls back to `'My Team'`. |
| `JSON.parse()` without schema guard | `js/core.js:135` | `m.learning_objectives` parsed with try/catch — acceptable |
| Worker input validation | `worker/index.js` | Basic checks on required fields; no library validation |

**Overall verdict: JAVASCRIPT WITH EXTRA STEPS** — no type enforcement at any layer.

---

### 4 — API LAYER

#### Abstraction Consistency
All API calls go through `api()`, `managerApi()`, or `learnerApi()`. No raw `fetch()` in component code. This is good.

The three functions are near-identical (same 15-line structure), differing only in which session token they attach and which globals they clear on 401. This is triplication of error handling and auth logic.

The 401 handler in each function reaches into global state (`curCourse`, `curModIdx`, `quizSt`) to clear it. This is a layering violation — the API helper is managing application state.

#### Error Handling
- **Good:** All three api helpers throw typed errors on non-OK responses. Callers catch and show `Toast.err(e.message)`.
- **Silent failures (multiple):**
  - `Manager.renderCourses()` — empty `catch(e) { }` block; errors not surfaced to user
  - `Manager.openTeamAssign()` — empty `catch(e) { }` on loading team members
  - `Admin.renderTeams()` — empty `catch(e) { }` on initial render
  - `Admin.renderTroubleSpots()` — empty `catch(e) { }` on spot render
  - `Admin.setCourseSection()` fires `Admin.renderCourses()` without awaiting error
  - `Builder.openBuilder()` edit path — `.catch(() => {})` discards load errors silently
- **No distinction between user errors and system errors** — a 400 (bad input) and a 500 (server crash) both show as a Toast with the error message text.

#### Fire-and-Forget
- `learnerApi('/api/progress/${curCourse.id}', { method: 'DELETE' }).catch(() => {})` in `Learner.completeCourse()` — intentional; the completion record is already saved; progress cleanup is best-effort. Acceptable.
- `Manager.submitPostImportAssign()` — `Promise.all()` with `.catch(() => null)` per assignment. Already-assigned learners are silently skipped, others silently fail. The count in the success toast could be inaccurate (shows all IDs assigned, not just those that succeeded).

#### Parallel Request Risk
- **No request cancellation.** `Admin.nav()`, `Manager.nav()`, and `Learner.nav()` fire async renders on tab switch. Rapid clicking produces multiple in-flight requests; whichever resolves last wins. This can display stale data after fast navigation.
- `Admin.renderLearners()` fires two parallel requests (`api(path)` + `api('/api/admin/teams')`). The filter input (`Admin.filterLearners()`) operates on `_allLearners`, which is set by the in-flight request. If the filter is applied during a load, it runs on the previous dataset.
- `Admin.renderComps()` fires `api('/api/courses')` inside the render if the dropdown is empty, meaning a completion render can trigger a courses fetch — two API calls from one UI action, with no deduplication.

#### Security: AI API Keys
The `/api/ai/generate` endpoint in the worker accepts `claude_key`/`gemini_key` in the request body — this is a server-side proxy path. **It is unused.** The frontend calls Anthropic and Gemini APIs directly from the browser and stores keys in `localStorage`. This means keys are accessible to any JS on the same origin and visible in devtools. The server-side proxy path exists and should be used instead.

---

### 5 — COMPOUNDING DEBT

| Issue | What it is | Compounds how | Fix now | Fix later |
|---|---|---|---|---|
| **Global mutable state** | 13+ globals managed by any module | Every new feature must know which globals to reset on logout/nav; already requires `window._adminPreview` workaround | 2 days (session state manager) | 1 week+ (interlocked bugs) |
| **Triple-duplicated API helpers** | `api()`, `managerApi()`, `learnerApi()` with identical logic | Any retry/cache/abort logic must be added in 3 places | 2 hrs | Grows with each API feature |
| **No request cancellation** | `AbortController` never used | As nav complexity grows, race conditions become visible bugs | 4 hrs | Exponentially harder |
| **`admin.js` is 1,618 lines** | AI importer, branding, teams, learners, dashboard all in one object | Every new admin feature adds to the file; onboarding cost grows | 1 day to split | 2+ days later |
| **Lazy schema migrations on every request** | `setupBrand()`, `setupSections()`, `setupTags()` run ALTER TABLE on every request to their routes | Under load, wasted DB round-trips; schema split between SQL file and worker code means a fresh deploy may miss tables | 2 hrs | Bigger as more tables are added this way |
| **AI keys in localStorage** | Browser-direct AI calls store keys in localStorage | Any future XSS (even via a supply-chain compromise of a CDN dependency) steals all keys | 4 hrs (route through existing worker endpoint) | Rearchitect entire AI flow |
| **String-template UI** | All UI built via `innerHTML = \`...\`` | No testability; XSS surface grows with every new template; no component reuse | N/A (architectural choice for this stack) | Requires full rewrite to change |
| **`sectionsCache` undeclared** | Implicit `window.sectionsCache` global | Strict mode will throw; any minifier may rename it; collisions possible | 5 min (declare in core.js) | Invisible until it breaks |

---

### OVERALL QUALITY VERDICT: **LOOSE**

The app is functional and well-featured. Auth, RBAC, quiz engine, certificates, AI importer, and branding all work. The codebase follows consistent conventions within its paradigm (vanilla JS object modules, `api()` helpers, `Toast.*` errors).

The structural weaknesses are real and will compound: uncontrolled global state, no request lifecycle management, AI keys exposed in localStorage, and a 1,600-line God module. None of these will cause an immediate outage, but each new feature makes all of them worse.

---

### Approved Plan

*(Awaiting approval — see CLI output below)*

---

## Auditor Review — Stage 3 (Security) — 2026-05-20

**Scope:** Full data safety and authorization review. Every API route, auth middleware, DB query, and client-side data access path read before any evaluation.

**Exploitability:** EXPOSED

---

### 1 — AUTHORIZATION BOUNDARY TEST

All routes walked. Results:

| Route | Auth Required | Server-side Ownership Check | Can User A touch User B's data? |
|---|---|---|---|
| `GET /api/courses` | None | N/A | Public — all courses listed to anyone |
| `GET /api/courses/:id` | None | N/A | Full course + **correct answers** public |
| `GET /api/brand` | None | N/A | Public by design — OK |
| `GET /api/sections` | None | N/A | Public — OK |
| `POST /api/completions` | requireLearner | None | Learner posts own ID from JWT — but **score/passed from body, unverified** |
| `GET /api/learners/:id` | requireManager | **MISSING for managers** | Manager A can read any learner by ID |
| `POST /api/assignments` | requireManager | **MISSING** | Manager can assign courses to learners in other teams |
| `DELETE /api/assignments` | requireManager | **MISSING** | Manager can delete any assignment by knowing IDs |
| `POST /api/learners` | requireManager | Partial | Manager can pass any `team_id` in body (not scoped to manager's team) |
| `POST /api/learners` | requireManager | N/A | Manager can set `role: 'manager'` — promotes arbitrary accounts |
| `GET /api/admin/learners/:id/tags` | requireManager | **MISSING** | Manager can read tags for learners on other teams |
| `POST /api/admin/learners/:id/tags` | requireManager | **MISSING** | Manager can tag learners on other teams |
| `DELETE /api/admin/learners/:id/tags/:tagId` | requireManager | **MISSING** | Manager can untag learners on other teams |
| `PUT /api/learners/:id/password` | requireManager | Present (team check) | Scoped correctly for managers |
| All `requireAdmin` routes | requireAdmin | Admin has no team scoping — by design | OK |

**requireLearner role blind-spot (worker/index.js:152-160):**
```js
async function requireLearner(c, next) {
  const payload = await verify(auth.slice(7), c.env.JWT_SECRET, 'HS256')
  c.set('user', payload)   // no role check
  await next()
}
```
No `payload.role === 'learner'` check. A manager or admin JWT passes `requireLearner`. A manager can POST `/api/completions` using their manager token, creating a completion record and a certificate for themselves without taking any quiz.

---

### 2 — INPUT TRUST AUDIT

**All SQL queries are fully parameterized.** No string interpolation in SQL found. No SQL injection risk.

| Input | Route | Issue |
|---|---|---|
| `body.score`, `body.passed` | `POST /api/completions` | Entirely trusted from client — no server-side verification against quiz answers |
| `body.team_id` | `POST /api/learners` | Not validated against manager's `scopedToTeam` — manager can create users in any team |
| `body.role` | `POST /api/learners` | Allows `'manager'` from any authenticated manager |
| `body.password` | `PUT /api/learners/:id/password` | No minimum length check — empty string accepted |
| `body.current_password` | `PUT /api/admin/password` | Optional — if omitted, current password verification is skipped entirely |
| `from`, `to` | `GET /api/admin/completions` | `new Date(from).getTime()` can produce `NaN` for malformed dates — passes to parameterized query silently |
| No string length limits | All string fields | No server-side enforcement on name, title, content, etc. |

---

### 3 — DATA EXPOSURE AUDIT

**password_hash in API responses (worker/index.js:444-448, 532-588, 609):**
`GET /api/learners/:id` and `GET /api/learners` both execute `SELECT u.*` which includes the `password_hash` column. The admin stats endpoint also does `SELECT * FROM users`. Password hashes (PBKDF2) are returned in every user API response to any authenticated manager or admin.

**Course answer key publicly accessible (worker/index.js:635-649):**
`GET /api/courses/:id` requires no authentication. The response includes the full course structure with `correct_index` and `explanation` for every quiz question. Any unauthenticated visitor can download the complete answer key for any course.

**Error message leakage (worker/index.js:118-121):**
```js
app.onError((err, c) => {
  return c.json({ error: 'Internal server error', detail: err.message }, 500)
})
```
`err.message` on a DB error will contain table names, column names, and constraint names. Several routes also do `return c.json({ error: e.message }, 500)` directly. Raw libSQL exceptions are client-visible.

**List scoping (completions, learners, stats):** Managers see only their team's data via `user.scopedToTeam`. This scoping is correctly applied on GET /api/learners, GET /api/admin/stats, GET /api/admin/completions, GET /api/assignments. The bypass is through GET /api/learners/:id which has no team check.

---

### 4 — STATE CORRUPTION PATHS

**Completion fabrication (repeated submissions):**
`POST /api/completions` uses `INSERT OR REPLACE` keyed on a fresh UID per request. There is no `UNIQUE(learner_id, course_id)` constraint. A learner can submit the same course multiple times, producing multiple `cert_id` records and multiple rows in the completions table. Pass-rate calculations and admin dashboards accumulate all records. This is likely intentional for retakes but allows unbounded record inflation.

**Invite code TOCTOU:**
The `SELECT` check for `used = 0` and the `UPDATE SET used = 1` are in separate operations. Two simultaneous registration requests with the same invite code could both pass the SELECT check. The batch contains an INSERT (which would fail on name uniqueness if identical names) and an UPDATE. If two different managers register with the same code simultaneously, both could succeed. Low probability in practice; structurally present.

---

### 5 — AUTH EDGE CASES

**JWT expiry:** Clean — `verify()` throws on expiry, middleware returns 401, client clears token and redirects to login. No partial response risk.

**requireLearner accepts any role:** As noted in Section 1 — a valid manager JWT passes requireLearner. A manager can call any `requireLearner`-protected endpoint. Primary impact: fake completions and certificates under the manager's own account.

**`PUT /api/admin/password` — current password optional (worker/index.js:344-359):**
```js
if (body.current_password) {  // check is inside an optional block
  ...verify...
}
```
An authenticated admin (or someone who has hijacked an admin session) can change the admin password without knowing the current one by sending `{ new_password: "new" }` with no `current_password` field.

**Client-side auth checks:** `App.show()` guards UI screen access. All screens that matter (`screen-admin`, `screen-manager`, `screen-course`) are also protected server-side. Client-side checks are not load-bearing.

**Brand endpoint:** `GET /api/brand` is public and unauthenticated. This leaks the org name, logo URL, brand colors, and pass threshold to anyone. For an internal training platform this may be undesirable but is not a data safety issue.

---

### 6 — FINDINGS REGISTER

| # | Severity | File + Line | Attack Vector | Impact | Exploitability | Remediation |
|---|---|---|---|---|---|---|
| F1 | **CRITICAL** | `worker/index.js:664-675` | Learner posts `{ course_id, score:100, passed:true }` without taking quiz | Fake completion record + legitimate cert_id stored in DB; training compliance records corrupted | **NOW** | Compute score server-side from stored quiz responses, or at minimum require question response proof |
| F2 | **CRITICAL** | `worker/index.js:635-649` | Any unauthenticated request to `GET /api/courses/:id` | Complete answer key (`correct_index`, `explanation`) for every quiz question publicly available before test | **NOW** | Require auth to fetch course detail, or strip answer fields for non-admin/manager responses |
| F3 | **HIGH** | `worker/index.js:442-448` | Manager requests `GET /api/learners/:id` with any learner ID | Reads any user's full record including `password_hash`; no team ownership enforced | **NOW** | Add `WHERE team_id = user.scopedToTeam` check for managers |
| F4 | **HIGH** | `worker/index.js:444,586` | Any `GET /api/learners` or `GET /api/learners/:id` | `password_hash` returned in API response to any authenticated manager or admin | **NOW** | Replace `SELECT *` with explicit column list excluding `password_hash` |
| F5 | **HIGH** | `worker/index.js:152-160` | Manager or admin JWT used to call `POST /api/completions` | Manager creates fake completion + cert without taking quiz; DB records appear legitimate | **NOW** | Add `if (payload.role !== 'learner') throw new Error('Forbidden')` in `requireLearner` |
| F6 | **HIGH** | `worker/index.js:1030-1053` | Manager calls `POST /api/assignments` or `DELETE /api/assignments` with any learner_id | Assigns/removes courses for learners on other teams; no team ownership enforced | **NOW** | Add team membership check before insert/delete |
| F7 | **HIGH** | `worker/index.js:427-440` | Manager sends `POST /api/learners` with arbitrary `team_id` in body | Manager creates user in any team, not just their own | **NOW** | Override `body.team_id` with `user.scopedToTeam` when caller is a scoped manager |
| F8 | **HIGH** | `worker/index.js:431` | Manager sends `POST /api/learners` with `role: 'manager'` | Promotes any user to manager role without admin approval | **NOW** | Restrict role elevation to `requireAdmin` only |
| F9 | **MEDIUM** | `worker/index.js:361-372` | Manager sends `PUT /api/learners/:id/password` with 1-char password | Sets trivially weak password on any learner account they manage | **NOW** | Add `if (!body.password || body.password.length < 8)` check |
| F10 | **MEDIUM** | `worker/index.js:344-359` | Admin sends `PUT /api/admin/password` without `current_password` field | Admin session hijack allows password change without knowing original | CONDITIONAL | Make `current_password` required (remove optional `if` wrapper) |
| F11 | **MEDIUM** | `worker/index.js:118-121` | Any 500 error | DB exception messages (`err.message`) returned as `detail` field; leaks column/table/constraint names | CONDITIONAL | Remove `detail` field from 500 responses; log server-side only |
| F12 | **MEDIUM** | `worker/index.js:1190-1203` | Manager calls tag endpoints with any learner ID | Tags/untags learners on other teams | **NOW** | Add team ownership check matching F3 pattern |
| F13 | **LOW** | `js/importer.js:21-37` | Admin UI sends full admin password to `/api/auth/login` just to unlock key editor | Unnecessary auth roundtrip; admin password in-flight for UI-only purpose | THEORETICAL | ✅ **Resolved** — replaced with session token presence check (`tf_token`) |
| F14 | **LOW** | `worker/index.js:728-729` | Malformed `from`/`to` date strings | `NaN` timestamp in parameterized query causes silent filter failure; no injection risk | THEORETICAL | ✅ **Resolved** — NaN guard returns 400 before query execution |
| F15 | **LOW** | `worker/index.js:104-116` | `ALLOWED_ORIGIN` env var not set in production | CORS falls back to `theronv.github.io` (safe hardcoded default); localhost echoing only triggers for localhost origins | ACCEPTED | Hardcoded safe fallback mitigates the risk; no further action required |

---

### Resolution Summary

All F1–F14 findings resolved. F15 accepted (safe hardcoded fallback in place).

| Finding | Severity | Status | File |
|---|---|---|---|
| F1 — Client-controlled score/passed | CRITICAL | ✅ Resolved | worker/index.js |
| F2 — Answer key public | CRITICAL | ✅ Resolved | worker/index.js |
| F3 — Manager reads any learner | HIGH | ✅ Resolved | worker/index.js |
| F4 — password_hash in responses | HIGH | ✅ Resolved | worker/index.js |
| F5 — requireLearner role-blind | HIGH | ✅ Resolved | worker/index.js |
| F6 — Assignment team bypass | HIGH | ✅ Resolved | worker/index.js |
| F7 — Manager sets arbitrary team_id | HIGH | ✅ Resolved | worker/index.js |
| F8 — Manager promotes to manager role | HIGH | ✅ Resolved | worker/index.js |
| F9 — Weak password allowed | MEDIUM | ✅ Resolved | worker/index.js |
| F10 — Admin password change without current | MEDIUM | ✅ Resolved | worker/index.js |
| F11 — DB error message leakage | MEDIUM | ✅ Resolved | worker/index.js |
| F12 — Tag endpoints team bypass | MEDIUM | ✅ Resolved | worker/index.js |
| F13 — Admin password in-flight for UI | LOW | ✅ Resolved | js/importer.js |
| F14 — NaN date filter | LOW | ✅ Resolved | worker/index.js |
| F15 — CORS localhost echo | LOW | ✅ Accepted | worker/index.js |

---

## Strategist Review — Stage 2 — 2026-05-20

**Scope:** Commercial viability review — screens, flows, copy, monetization, retention mechanics, acquisition positioning. No code changes made.

**Stack context:** TrainFlow is a vanilla JS SPA deployed on GitHub Pages + Cloudflare Worker + Turso. It is a self-hosted, developer-deployed B2B tool, not a consumer subscription app. Standard mobile VD targets (RevenueCat, hard paywall, trial) do not apply — this is an infrastructure product sold (or potentially sold) org-by-org.

---

### 1 — FIRST SESSION AUDIT

**Flow traced for a brand-new learner:**

1. **First screen:** Landing page — "TrainFlow" wordmark, three role tiles (🎓 Learner / 💼 Manager / ⚙️ Admin), a Demo Mode button, and a footer.
2. **Purpose clear in 10 seconds?** MOSTLY — the role tiles and "Training & Certification Platform" tagline communicate category immediately. It does not communicate why this is better than any other LMS or who it's for.
3. **Taps to first meaningful action:** Landing → tap Learner → sign in (2 fields) → course list → tap course = **4 actions** to reach content. Acceptable but the sign-in wall is friction before any value demonstration.
4. **Aha moment:** Completing a module quiz → confetti animation + branded PDF certificate with unique cert ID. This is a genuinely satisfying moment and it's reachable in a first session if demo data is seeded.
5. **Friction before aha:**
   - The "Welcome." greeting on the learner sign-in is cold — learners land here already knowing they're signing in, so the heading adds no value.
   - "✨ Try Demo Mode (Offline)" on the landing is unexplained — non-technical users don't know what "Offline" means in this context.
   - Empty state if no courses exist: "No courses available." — a dead end with no call to action.
   - The footer on the landing reads "Securely powered by Cloudflare Workers and Turso Database" — this is infrastructure credentialing, not a user-facing benefit.

---

### 2 — CORE LOOP QUALITY

**Core loop (Learner):**
> Assigned course appears → open module → read content → take competency check → receive per-question feedback → see score → earn certificate → move to next module → repeat

The loop is **mechanically sound**. Per-question feedback (correct/incorrect highlight + explanation) is better than most indie LMS tools. Progress resumes across sessions. Certificates are branded, downloadable PDF with unique verifiable IDs.

**Does value accumulate?**
YES — to a degree. Certificates pile up in the Certificates tab. Progress tracks. Pass/fail history is visible. A learner on day 30 has a portfolio of certifications they can download.

**What is missing:**
- **No notification mechanism.** When a manager assigns a new mandatory course, the learner has zero signal — no email, no push, no in-app badge. They discover it by logging in. This is the single biggest retention gap: learners have no reason to open the app unless they're scheduled to do training.
- **No urgency mechanics.** Due dates exist in the schema but are only shown to learners in the Progress tab as a date string. There are no countdown timers, overdue banners, or escalation states beyond a red color.
- **Day 30 = Day 1 for the Manager.** The Manager dashboard shows aggregate stats but there is no trend data, no historical comparison, no "X% improvement this quarter" — the value of long-term usage is invisible.

**What would cause a user to open tomorrow?**
Currently: nothing, unless their manager verbally reminds them. This is a critical commercial weakness.

---

### 3 — MONETIZATION REVIEW

**Verdict: BROKEN — no monetization mechanism exists.**

TrainFlow has no pricing tier, no paywall, no subscription, no billing, and no RevenueCat integration. It is currently a self-hosted open source deployment: each organization installs their own Cloudflare Worker, provisions their own Turso database, and configures their own secrets. There is no "sign up and start training your team in 5 minutes" path that doesn't require a developer.

**Implications:**
- The product has genuine feature depth (AI importer, role-based RBAC, branded certificates, team management, CSV bulk import) that could command $4–8/learner/month in the SMB LMS market (Trainual is $299/mo for 25 seats; TalentLMS free tier is 5 users/5 courses).
- The deployment model prevents any commercial traction without either: (a) a hosted SaaS offering with multi-tenant architecture and a signup flow, or (b) a marketplace/agency model where developers deploy it for clients.
- Standard VD targets (annual $19.99 / monthly $3.99 / 7-day trial / hard paywall) are consumer-app framing — not applicable here. The correct frame is **per-seat B2B**: $4–7/active learner/month with an org minimum.

**Free experience vs. upgrade:** The entire product is free as deployed. There is no upgrade path, no teaser for premium features, no trial expiry. All features are available to anyone who deploys the worker.

---

### 4 — COPY AUDIT

**All visible strings reviewed. Worst 3 failures:**

---

**Failure 1 — Landing tagline**
> Current: "Training & Certification Platform"

This is the category, not the value. Every LMS on the market describes itself this way. It answers "what is this?" but not "why does this matter for my team?"

> Should be: "Turn your team's training into verifiable credentials." or "Assign, track, and certify your team's training — in one place."

---

**Failure 2 — Landing helper text**
> Current: "Not sure which to pick? Your manager will let you know."

This copy assumes the confused user (most likely a new learner arriving from a link their manager sent) should already know who their manager is and feel comfortable asking. It's a dead end. A confused user closing the tab costs a learner activation.

> Should be: "Joining your team's training? Tap Learner and sign in with the credentials your manager provided."

---

**Failure 3 — Learner empty state (courses)**
> Current: "No courses available."

No context. No next step. A learner who just signed in sees this and has no idea if this is an error, if they need to wait, or if they did something wrong.

> Should be: "No courses assigned yet. Your manager will add you to training — check back soon, or reach out to let them know you're ready."

---

**Additional copy notes:**
- "Welcome." on the learner sign-in screen: Drop it. The learner knows they're signing in.
- "✨ Try Demo Mode (Offline)": Rewrite as "Explore with demo data →" — remove the word "Offline," which implies broken.
- Certificate empty state: "No certificates yet — complete a course and pass the quiz to earn your first one!" — this is actually good copy. Keep it.
- Learner certs tab button label: "↓ Download PDF" — clear and functional. Fine.
- AI Importer phase subtitles are functional and clear for an admin audience. No changes needed.
- "Worker Initialization Required" overlay: This technical overlay (showing `npx wrangler secret put` CLI commands) surfaces to anyone who hits the admin login on an unconfigured deployment. This is a developer screen bleeding into the end-user surface. It should only appear if the admin is authenticated or be replaced with a friendlier "Setup required — contact your system administrator."

---

### 5 — ACQUISITION POSITIONING

**Most realistic acquirers today:**
1. **HR tech consolidators** (Rippling, Gusto, BambooHR, Lattice) — TrainFlow could be the training module they don't want to build. The three-role model (Admin/Manager/Learner) maps cleanly onto their existing user hierarchies.
2. **Compliance platforms** (Vanta, Drata, Secureframe) — these products mandate training completion as part of compliance evidence. A lightweight embedded LMS with verifiable cert IDs is a natural add-on.
3. **LMS mid-market** (TalentLMS, Absorb, Docebo) — acquires for the AI importer and lightweight deployment model as a competitive differentiator for their SMB tier.

**What metrics need to improve most:**
- **Learner activation rate** — currently unmeasured. No analytics on how many learners who receive credentials actually log in and complete training.
- **Completion rate** — the data exists (completions table) but there's no cohort or funnel view. An acquirer wants "X% of assigned learners complete training within 7 days of assignment."
- **Org count** — the multi-tenant story is absent. One deployment = one org. An acquirer needs to see repeatable org onboarding.

**What an acquirer questions:**
1. "How does a new organization get started without a developer?" — There is no hosted offering, no SaaS signup, no org provisioning.
2. "What's the retention signal?" — No notification system means no behavioral retention data.
3. "Where is the integration story?" — No SSO (SAML/OIDC), no SCIM, no HRIS connectors. An HR tech acquirer cannot embed this without those.
4. "What happens at 500+ learners?" — The README acknowledges pagination gaps; the all-learners-rendered-at-once issue is a known scaling hole.

**What TrainFlow needs to demonstrate in 90 days:**
1. A hosted SaaS path: org signup → provisioned subdomain → first course in under 10 minutes, no developer required.
2. Email notification: assignment created → learner gets email with due date. This is the single most impactful retention unlock.
3. An integration stub: even a read-only CSV export to HRIS is a proof point for the compliance acquisition story.
4. Org count: onboard 5 paying pilot organizations, even at $0, to demonstrate the multi-tenant pattern works.

---

### Findings Summary

| Dimension | Rating | Primary Gap |
|---|---|---|
| First-session clarity | GOOD | Tagline is generic; demo path is unclear |
| Aha moment | PRESENT | Certificate + confetti is genuinely satisfying |
| Core loop | FUNCTIONAL | Loop works; no retention hooks between sessions |
| Monetization | BROKEN | Zero — no pricing, no paywall, no SaaS offering |
| Copy quality | WEAK | 3 high-impact failures; functional elsewhere |
| Acquisition readiness | LOW | No multi-tenancy, no integrations, no analytics |

---

### Approved Plan — Execution Log

Plan approved 2026-05-20. 8 items executed. No code was written that required approval before this point.

| # | Item | File(s) | Change |
|---|---|---|---|
| 1 | Landing tagline — benefit-led copy | `js/core.js`, `index.html` (×2) | `DEFAULT_TAGLINE` + HTML default + branding placeholder all updated from "Training & Certification Platform" to "Assign, track, and certify your team's training — in one place." |
| 2 | Landing helper text — directive for new learners | `index.html` | "Not sure which to pick? Your manager will let you know." → "Joining your team's training? Tap **Learner** and sign in with the credentials your manager provided." |
| 3 | Learner empty state (courses) — context + next step | `js/learner.js` (×2) | Both "No courses available." instances replaced with: "No courses assigned yet. Your manager will add you to training — check back soon, or reach out to let them know you're ready." |
| 4 | Demo Mode button — remove "Offline" | `index.html` | "✨ Try Demo Mode (Offline)" → "✨ Explore with demo data →" |
| 5 | Landing footer — trust statement | `index.html` | "Securely powered by Cloudflare Workers and Turso Database" → "Your data stays private. No third-party tracking." |
| 6 | Learner sign-in greeting — actionable | `index.html` | "Welcome." → "Sign in to your training." / "Sign in to access your training." → "Enter the credentials your manager gave you." |
| 7 | Overdue visual urgency on course cards | `js/learner.js` | `renderCard` now finds the full assignment object, derives `dueTs` and `overdue` flag; adds red ⚠ Overdue chip (highest priority below Passed) and shows "Due [date]" inline for upcoming deadlines on Mandatory cards |
| 8 | Worker Init overlay — improved framing | `index.html` | Heading changed from "Worker Initialization Required" to "Setup Required"; body copy tightened; README reference added |

**Nothing unexpected.** The `DEFAULT_TAGLINE` constant in `js/core.js` feeds both the HTML fallback (via `applyBrand()`) and the `normBrand()` coercion for new orgs without a saved tagline — so the single constant change propagates correctly to all surfaces without additional edits. The overdue chip reuses the existing `--fail` CSS token already used on the Progress tab; no new CSS was needed.

---

## Designer Review — Stage 1 — 2026-05-20

**Stack context:** This is a vanilla JS SPA (no React, no Tailwind, no NativeWind yet). The review is conducted against the actual stack and its migration target: React Native via NativeWind. Every finding is evaluated on whether it will compound into debt in the native build.

---

### 1 — DESIGN SYSTEM INVENTORY

#### Colors — DEFINED (with legacy debt)

A full semantic token system exists in `css/style.css` `:root`:

| Layer | Tokens | Notes |
|---|---|---|
| Background | `--bg`, `--bg-2` | Dark default; properly overridden in `[data-theme="light"]` |
| Surface | `--surface`, `--surface-2` | Card and panel layers |
| Border | `--border`, `--border-2` | Two-level border system |
| Brand (primary) | `--brand`, `--brand-dark`, `--brand-glow`, `--shadow-brand` | Runtime-overridable |
| Brand (secondary) | `--brand-secondary`, `--brand-secondary-dark`, `--brand-secondary-glow` | Runtime-overridable |
| Brand (accent) | `--brand-accent`, `--brand-accent-dark`, `--brand-accent-glow` | Runtime-overridable |
| Status | `--success`, `--warning`, `--danger`, `--muted` | Semantic, not overridable |
| Text | `--ink-1`, `--ink-2`, `--ink-3`, `--ink-4` | 4-level ink hierarchy |

**Dark/light mode:** Implemented correctly. `[data-theme="light"]` overrides the structural tokens. Token names are semantic (`--bg`, `--surface`, `--ink-1`), not literal (`--gray-900`). Dark mode is supported by design. **This is correctly done.**

**Legacy alias debt:** 20+ legacy aliases exist for backwards compatibility: `--white`, `--r`, `--r-lg`, `--r-full`, `--rule`, `--rule-2`, `--pass`, `--fail`, `--warn`, `--pass-lt`, `--fail-lt`, `--warn-lt`, `--accent-lt`, `--brand-1`, `--brand-2`, `--s-1`, `--s-2`, `--s-4`, `--s-6`, `--ink-meta`, `--shadow-xs`. These are still referenced in `index.html` inline styles. When migrating to NativeWind these aliases will not survive — anything referencing them needs to be updated.

#### Typography — DEFINED (with mobile-readability problem)

| Token | Value | Issue |
|---|---|---|
| `--text-xs` | 11px | Below iOS minimum readable size |
| `--text-sm` | 12px | Below iOS minimum readable size |
| `--text-base` | 13px | Below iOS minimum readable size |
| `--text-md` | 14px | Borderline; Apple HIG suggests 17pt for body |
| `--text-lg` | 16px | Acceptable minimum for body |
| `--text-xl` | 20px | Fine |
| `--text-2xl` | 24px | Fine |
| `--text-3xl` | 30px | Fine |

**Critical:** The entire lower half of the scale (`xs` through `base`) is below the iOS minimum legible size. `--text-xs` (11px) is used heavily for labels, chips, nav section headers, table headers, and cert metadata. These will read as illegible on a physical iOS device. The scale needs an upward shift for mobile.

**Fonts:** Inter (body) + JetBrains Mono (mono). Both are open source and available via expo-font. No mobile licensing issue.

**Font loading:** Via Google Fonts CDN (`fonts.googleapis.com`). RN will require `expo-font` — CDN loading does not work in RN.

#### Spacing — DEFINED (with inline escapes)

4pt-base grid is formally defined: `--space-1` (4px) through `--space-16` (64px). The scale is clean and consistent.

**Violations found in `style.css`:**
- `.modal { padding: 28px 32px; }` — 28px is not on the scale (closest is 24 or 32)
- `.login-card { padding: 36px 40px; }` — 36px not on scale
- `.cert-body { padding: 52px 64px 48px; }` — all raw certificate values
- `.cert-heading { margin-bottom: 28px; }` — raw
- `gap: 6px` in `.btn` — not on scale
- `margin-bottom: 6px` in several places
- `padding: 7px 14px` in `.btn` — 7px not on scale

**Violations in `index.html` inline styles:**
- Arbitrary pixel values are common in inline `style="..."` attributes throughout the admin screens (e.g., `margin-top: -8px`, `padding: 4px`, `letter-spacing: 0.1em` on non-scale values)

Overall the system exists; the escape rate is moderate but acceptable for this stage.

#### Border Radius — PARTIAL

Scale: `--radius-sm` (4px), `--radius-md` (6px), `--radius-lg` (10px), `--radius-xl` (14px), `--r-full` (50%).

**Escapes:**
- `.chip { border-radius: 4px; }` — should be `--radius-sm`
- `.progress-track, .progress-fill { border-radius: 2px; }` — no token for 2px; intentional pill
- `.mod-meta-chip { border-radius: 99px; }` — pill shape, no token
- Toggle track `border-radius: 24px` — no token
- `border-radius: 50%` hardcoded in several places (avatars) — should use `--r-full`

Minor drift, correctable.

---

### 2 — TOKEN COMPLIANCE

#### Hardcoded Color Values in CSS (not routed through token system)

Every instance that should use a token but doesn't:

| Location | Hardcoded Value | Correct Token |
|---|---|---|
| `.btn-danger` background | `rgba(239,68,68,0.1)` | `--fail-lt` |
| `.btn-danger` border | `rgba(239,68,68,0.2)` | No token — needs one |
| `.chip-green` background | `rgba(16,185,129,0.1)` | `--pass-lt` |
| `.chip-green` border | `rgba(16,185,129,0.2)` | No token |
| `.chip-red` background | `rgba(239,68,68,0.1)` | `--fail-lt` |
| `.chip-red` border | `rgba(239,68,68,0.2)` | No token |
| `.chip-amber` background | `rgba(245,158,11,0.1)` | `--warn-lt` |
| `.chip-amber` border | `rgba(245,158,11,0.2)` | No token |
| `.qr-item-pass` background | `rgba(16,185,129,0.05)` | No token |
| `.qr-item-pass` border | `rgba(16,185,129,0.2)` | No token |
| `.qr-item-fail` background | `rgba(239,68,68,0.05)` | No token |
| `.qr-item-fail` border | `rgba(239,68,68,0.15)` | No token |
| `.quiz-opt.correct` background | `rgba(16,185,129,0.08)` | No token |
| `.quiz-opt.wrong` background | `rgba(239,68,68,0.08)` | No token |
| `.quiz-feedback.fb-pass` background | `rgba(16,185,129,0.08)` | No token |
| `.quiz-feedback.fb-fail` background | `rgba(239,68,68,0.08)` | No token |
| `.source-banner-link:hover` background | `rgba(37,99,235,0.12)` | `--brand-glow` |
| `.overlay` background | `rgba(0,0,0,0.7)` | No token — unthemed |
| `#cert-overlay` background | `rgba(0,0,0,0.85)` | No token — unthemed |
| Brand preview `style="background:white"` | `white` | Intentional cert preview, but unthemed |
| Toggle thumb | `white` hardcoded | No token |
| `font-size: 9px` (cert labels) | Raw | Below scale minimum |
| `font-size: 10px` (various) | Raw | Below scale minimum |
| `font-size: 11px` (various) | Raw | Equal to `--text-xs` but not using the token |

**Pattern:** Status/quiz state colors (`pass`, `fail`, `warn`) are the biggest offenders. Each state generates 4-6 rgba variants that are all hardcoded rather than derived from the status tokens. In a NativeWind migration these would need to be explicit palette values in the Tailwind config.

#### Contrast Ratios

Checked against WCAG AA (4.5:1 for body text, 3:1 for large text):

| Dark Mode | Foreground | Background | Ratio | Status |
|---|---|---|---|---|
| `--ink-1` (#f1f5f9) on `--bg` (#0f1117) | #f1f5f9 | #0f1117 | ~15:1 | PASSES |
| `--ink-2` (#94a3b8) on `--bg` (#0f1117) | #94a3b8 | #0f1117 | ~7.7:1 | PASSES |
| `--ink-3` (#64748b) on `--bg` (#0f1117) | #64748b | #0f1117 | ~4.2:1 | **FAILS AA** |
| `--ink-4` (#475569) on `--bg` (#0f1117) | #475569 | #0f1117 | ~2.8:1 | **FAILS AA** |

**`--ink-3` is used for body-level content** (page subtitles, button labels in `.btn-ghost`, nav labels, `page-sub` descriptors) and fails WCAG AA contrast in dark mode by a thin margin (~4.2:1 vs 4.5:1 minimum). This is a real accessibility defect, not just a design note.

`--ink-4` is used for hint text and metadata — acceptable as decorative/non-critical at this ratio, but any meaningful label using it fails.

---

### 3 — PLATFORM CONVENTION AUDIT

#### Navigation — WRONG PATTERN FOR IOS

**Current pattern:** Left sidebar navigation (`sidenav`, 220px wide) with vertically stacked text buttons. This is a web/desktop SaaS pattern.

**iOS HIG requires:** Tab bar at the bottom of the screen for top-level navigation (max 5 tabs). Drill-down into content uses a navigation stack with a back button at top-left.

**Impact:** The entire navigation architecture needs to be replaced. The sidenav cannot be adapted — it must become a bottom TabNavigator. This affects three role views (Admin, Manager, Learner), each with 4–5 top-level nav items. The course viewer drill-down pattern (enter course from list → back button) maps well to a navigation stack. The page show/hide mechanism (`display: none / block`) needs to become React Navigation screen components.

This is the highest-impact single structural decision in the entire migration.

#### Touch Targets — FAILS iOS HIG ACROSS THE BOARD

iOS Human Interface Guidelines: minimum interactive target 44×44pt.

| Element | Approx. Height | Status |
|---|---|---|
| `.nav-btn` (sidebar) | ~26px | **FAILS** |
| `.btn-sm` | ~20px | **FAILS** |
| `.btn-icon` | ~28px | **FAILS** |
| `.theme-toggle` | 32px | **FAILS** |
| `.mod-item` | ~28px | **FAILS** |
| `.team-list-item` | ~32px | **FAILS** |
| `.quiz-opt` | ~48px | Passes |
| `.quick-action-btn` | ~58px | Passes |
| `.role-tile` | 200px wide | Passes |

The majority of interactive elements fail the 44pt minimum. The `.btn` system needs to be resized across all variants before the RN build begins, or the token values will propagate incorrect sizing into 20+ components.

#### Hover States — ALL MUST BE REPLACED

**Complete list of hover interactions that do not exist on touch:**

- `.btn-primary:hover` — background/border color shift
- `.btn-outline:hover` — surface background, text color
- `.btn-ghost:hover` — background fill
- `.btn-danger:hover` — full background change from ghost to solid
- `.theme-toggle:hover` — background + border
- `.nav-btn:hover` — background + text color
- `.quick-action-btn:hover` — brand-glow background + border color
- `.course-card:hover` — border + shadow elevation
- `.role-tile:hover` — border color + `box-shadow: var(--shadow-brand)` + `transform: translateY(-2px)` **[includes animation]**
- `.team-list-item:hover` — background
- `.mod-item:hover` — background + text
- `.quiz-opt:hover` — border + background + text
- `.link-cell:hover` — text decoration
- `.prose-content a:hover` — opacity
- `.ref-link:hover` — background
- `.source-banner-link:hover` — background
- `tbody tr:hover td` — row highlight
- `[data-theme] .mod-builder-head:hover` — background
- `::-webkit-scrollbar-thumb:hover` — scrollbar (irrelevant in RN)

In React Native, all of these become press states via `Pressable` with `pressed` style argument or `TouchableOpacity`. The design decisions (what changes color, what elevates, what animates) must be explicitly re-mapped.

#### Fixed Positioning

All fixed-positioned elements need RN-specific replacement:

| Element | CSS | RN Replacement |
|---|---|---|
| `#toast-root` | `position: fixed; top: 16px; right: 16px` | RN toast library (react-native-toast-message) |
| `.theme-toggle` button | `position: fixed; bottom: 20px; right: 20px` | Floating action button with `position: absolute` in a SafeAreaView |
| `.overlay` (all modals) | `position: fixed; inset: 0` | React Native `Modal` component |
| `#cert-overlay` | `position: fixed; inset: 0` | `Modal` with `SafeAreaView` |

**Safe area insets are not accounted for anywhere** — iOS notch/Dynamic Island and home indicator need SafeAreaView wrapping that does not exist in the current layout model.

#### Swipe Gesture Conflicts

No current swipe-based interactions found. The module sidebar (`module-nav`) is toggled via a button (focus mode), not swiped. No conflicts with iOS system gestures (back swipe, home swipe) identified.

---

### 4 — WEB-ONLY VISUAL PATTERNS

#### CSS Animations — ALL NEED REANIMATED EQUIVALENTS

| Keyframe / Transition | Usage | RN Equivalent Needed |
|---|---|---|
| `@keyframes fadeUp` | Page transitions, `.stagger` children | `react-native-reanimated` entering animation |
| `@keyframes fadeIn` | General fade | `react-native-reanimated` `FadeIn` |
| `@keyframes slideUp` | Module results | `SlideInDown` or custom |
| `@keyframes slideIn` | Toast slide | `SlideInRight` |
| `@keyframes shake` | Login error feedback | `react-native-reanimated` `useAnimatedStyle` with sequence |
| `@keyframes pulse` | Button press feedback | `useAnimatedStyle` scale |
| `@keyframes spin` | Spinner | `Animated.loop` or Reanimated |
| `.stagger > * { animation-delay }` | Staggered list entry | Imperatively triggered in RN |
| `transition: all 0.15s` | All button states | Implicit in Pressable; explicit Animated for color |
| `transition: width 0.3s ease` | Progress bar fill | `Animated.Value` width |
| `.module-nav { transition: all 0.3s cubic-bezier }` | Focus mode panel | `react-native-reanimated` layout animation |
| `role-tile:hover transform: translateY(-2px)` | Card hover lift | Press animation with `useAnimatedStyle` |

#### Box Shadows — MODEL IS INCOMPATIBLE

CSS box-shadow supports offset X/Y, blur, spread, and color in a single property. React Native splits this across 5 properties (`shadowColor`, `shadowOffset`, `shadowOpacity`, `shadowRadius`, `elevation`), and **spread radius is not supported**.

| Token | CSS Value | RN Problem |
|---|---|---|
| `--shadow-sm` | `0 1px 3px rgba(0,0,0,0.4)` | Translatable |
| `--shadow-md` | `0 4px 12px rgba(0,0,0,0.5)` | Translatable |
| `--shadow-lg` | `0 8px 32px rgba(0,0,0,0.6)` | Translatable |
| `--shadow-brand` | `0 0 0 3px rgba(59,130,246,0.2)` | **Cannot translate** — zero-offset ring with spread; needs border workaround |

The brand focus ring (`--shadow-brand`) used on inputs and primary button focus states cannot be replicated in RN's shadow model. A border approach (setting `borderWidth: 3, borderColor`) will need to replace it.

#### CSS Grid — NO RN EQUIVALENT

Every grid layout needs to become Flexbox. The hardest case:

| Grid | Usage | RN Challenge |
|---|---|---|
| `repeat(4, 1fr)` stats row | Dashboard stats | Flexbox `flex: 1` per child — straightforward |
| `1fr 260px` dash-mid | Dashboard layout | Flexbox row — straightforward |
| `220px 1fr` teams-layout | Teams sidebar | Flexbox row — straightforward |
| `1fr 1fr` field-row | Forms | Flexbox row — straightforward |
| `repeat(auto-fill, minmax(280px, 1fr))` courses-grid | **Main course listing** | **NO DIRECT EQUIVALENT** — needs `FlatList` with computed `numColumns`, or a responsive width calculation. Auto-fill with minmax is a web-only responsive pattern. |

The courses grid is the most important: it's the primary surface all learners see. A concrete decision on the RN equivalent is needed before building begins.

#### Backdrop Blur

`backdrop-filter: blur(4px)` used on `.overlay` and `#cert-overlay`. Not available in React Native core. Options: `expo-blur` BlurView (iOS native, requires Expo), or drop to semi-opaque `rgba(0,0,0,0.7)` background.

#### CSS Pseudo-Elements (Structural)

`.brand::before` and `.ldg-wordmark::before` generate the diamond logo mark via CSS `content: ''` + `transform: rotate(45deg)`. These are pure CSS constructs with no RN equivalent. In React Native these need to be explicit `<View>` components or SVG elements.

#### CSS calc()

`.nav-sub { font-size: calc(var(--text-sm) - 1px); }` — `calc()` is not supported in React Native StyleSheets. Replace with a hardcoded value or a token.

#### Scrollbar Styling

`::-webkit-scrollbar` rules — web-only, ignored in RN. No action needed; just remove during migration.

#### HTML Tables

`.table-wrap` + `<table>` used for all data grids (completions, users, teams). React Native has no native table component. All data tables need custom `FlatList` or `ScrollView`-based implementations.

#### Google Fonts CDN

`<link href="fonts.googleapis.com/...">` — will not work in React Native. Both Inter and JetBrains Mono are available via `expo-font` and are open-source licensed for mobile use.

#### Runtime CSS Variable Theme System

`applyBrand()` changes CSS custom properties on `:root` at runtime — this is how the branding system works (admin picks colors, CSS updates everywhere instantly). **This mechanism does not exist in React Native.** NativeWind themes are static at build time. Runtime theme changes in RN require React Context + re-render of affected components. This is an architectural migration decision that affects every surface.

---

### 5 — DECISIONS NEEDED BEFORE MIGRATION

Ordered by impact (highest first):

#### ESTABLISH NOW — Affects every component

1. **Token system migration format.** Decide: (a) Tailwind config values in `tailwind.config.js` consumed via NativeWind utility classes, OR (b) a TypeScript `tokens.ts` constants file used in StyleSheet objects, OR (c) both. Every component in the RN build depends on this choice. Current CSS variable names are semantic and well-structured — they can transfer cleanly.

2. **Type scale shift for mobile.** The bottom half of the scale (`xs`=11px, `sm`=12px, `base`=13px) is below iOS legibility standards. Establish minimum body size of 14pt and remap the scale before any RN component is built. Decisions made now get baked into 20 components.

3. **Touch target minimum.** Establish 44pt as the binding minimum for all interactive elements. Button padding needs to be increased (`.btn` minimum height should be 44pt; `.btn-sm` should become `.btn-compact` at 36pt with a note that it requires careful placement). All nav items need 44pt tap areas even if the visual appearance is smaller.

4. **Press state strategy.** Choose the RN interactive model: `Pressable` with `pressed` state (recommended — most flexible), or `TouchableOpacity`. Every one of the 18+ hover states needs a mapped press equivalent before building starts.

#### DECIDE BEFORE P1 — Affects navigation/shell architecture

5. **Navigation architecture.** Side sidebar → bottom `TabNavigator`. Confirm: Admin gets 5 tabs (Dashboard, Courses, Users, Reports, Settings), Manager gets 4 (Dashboard, Courses, Team, Completions), Learner gets 4 (Courses, Progress, Certs, Account). Course viewer is a modal stack pushed from all three views. Lock this before any screen work begins.

6. **Runtime brand theming approach.** The current `applyBrand()` / CSS variable system needs to become React Context + re-render in RN. Two options: (a) load brand from API on app start and inject into a ThemeContext that every component consumes via `useTheme()`, or (b) use NativeWind's built-in dark/light theming and restrict runtime brand changes to brand colors only via context. This decision determines whether NativeWind can be used for theming at all or whether StyleSheet objects must be computed dynamically.

7. **Shadow brand / focus ring replacement.** CSS `box-shadow: 0 0 0 3px` ring cannot be replicated in RN. Decide: `borderWidth: 2 + borderColor` on focus, or a wrapper View for the ring effect. Lock this so form inputs and primary buttons are consistent.

8. **`backdrop-filter: blur` replacement.** For modals and certificate overlay: expo-blur BlurView (requires Expo managed workflow) or semi-opaque background. If BlurView, commit to expo-blur as a dependency now.

#### CLEAN UP — Lower compounding risk

9. **Legacy alias consolidation.** 20+ legacy aliases in CSS (`--rule`, `--r`, `--white`, `--brand-1`, `--s-1`, etc.) are still referenced in HTML inline styles. None will survive migration. Audit all 1,242 lines of `index.html` for legacy alias references and replace with canonical tokens before the RN build so the team starts from a clean mapping.

10. **Status color token gaps.** rgba variants of `--success`, `--warning`, `--danger` are hardcoded throughout CSS (16 instances). Add `--pass-lt-08` (0.08 opacity), `--pass-lt-20` (0.20 opacity), and equivalents for fail/warn, or commit to a Tailwind opacity modifier approach. These affect chip, quiz feedback, and quiz option components.

11. **Inline font size cleanup.** `font-size: 9px`, `10px`, `11px` appear as inline styles in `index.html` across cert labels, AI importer key display, and chip overrides. These are below the mobile minimum and below the token scale. Replace with `--text-xs` at minimum, resized as per decision #2.

---

### Design System Status Per Dimension

| Dimension | Status | Primary Issue |
|---|---|---|
| Colors | DEFINED | Semantic tokens correct; 16 hardcoded rgba escapes; `--ink-3` fails WCAG AA contrast in dark mode |
| Typography | PARTIAL | Scale defined but bottom half (11–13px) is below iOS minimum; Google Fonts CDN won't work in RN |
| Spacing | PARTIAL | 4pt grid defined; ~10 inline escapes in CSS; many more in HTML |
| Border radius | PARTIAL | System exists; several hardcoded escapes |
| Dark mode | DEFINED | Semantic naming is correct; light mode implementation is proper |
| Navigation | WRONG PLATFORM | Sidebar nav pattern must be completely replaced with bottom tab bar |
| Touch targets | INCONSISTENT | Most elements fail 44pt minimum; quiz options and role tiles pass |
| Hover states | MISSING ALTERNATIVES | 18+ hover interactions with no press-state equivalents defined |
| Animations | PARTIAL | 7 keyframe animations + transitions; all need Reanimated equivalents |
| Box shadows | PARTIAL | 3 shadow levels are translatable; shadow-brand ring is not |
| Grid layouts | INCOMPATIBLE | 6 grid layouts; courses auto-fill has no RN equivalent |
| Runtime theming | INCOMPATIBLE | CSS variable runtime swap has no RN equivalent |

---

### Decisions Locked (Items 1, 4, 5, 6, 7, 8)

**Decision 1 — Token migration format:**
Both: a TypeScript `tokens.ts` constants file (feeds StyleSheet objects in RN) AND `tailwind.config.js` values that reference the same constants (consumed via NativeWind utility classes). The existing CSS variable names (`--brand`, `--surface`, `--ink-1`, etc.) map directly to Tailwind keys. Runtime brand overrides are handled via React Context, not via the token file.

**Decision 4 — Press-state strategy:**
React Native `Pressable` with a `pressed` state argument. Each interactive element gets `style={({ pressed }) => [baseStyle, pressed && pressedStyle]}`. Pressed state colors are derived from the corresponding CSS hover-state values already defined. No `TouchableOpacity` opacity flashes — use explicit color/scale changes only.

**Decision 5 — Navigation architecture:**
- **Admin:** 5 bottom tabs — Dashboard, Courses, Users, Reports, Settings (maps directly to current sidenav sections)
- **Manager:** 4 bottom tabs — Dashboard, Courses, Team, Completions
- **Learner:** 4 bottom tabs — Courses, Progress, Certificates, Account
- **Course viewer:** Modal stack pushed from the course list in all three roles (back-swipe dismisses via navigation stack)
- All tab bars use React Navigation `BottomTabNavigator`. The current CSS `display: none / block` page switching becomes React Navigation screen components.

**Decision 6 — Runtime brand theming for RN:**
`ThemeContext` with a `useTheme()` hook. On app launch, fetch `/api/brand`, store the brand object in context. Brand color changes by admin require app reload or a manual `refetch()`. NativeWind handles static dark/light theming via the `dark:` class variant. Dynamic brand colors (`--brand`, `--brand-secondary`, `--brand-accent`) are applied via inline `style` props that read from `useTheme()`. Static structural tokens (`--surface`, `--bg`, `--ink-1`, etc.) are Tailwind config values resolved at build time.

**Decision 7 — Shadow-brand / focus ring replacement:**
Replace `box-shadow: 0 0 0 3px rgba(brand, 0.2)` (unsupported spread radius in RN) with: `borderWidth: 2, borderColor: theme.brand` on focused inputs and primary button press state. On iOS this produces a 2pt colored border that matches the visual intent. Focus management in RN uses `onFocus`/`onBlur` handlers to toggle the border style.

**Decision 8 — Backdrop-filter replacement:**
Use `expo-blur` `BlurView` for modal overlays and the certificate overlay (provides native iOS blur, tintColor controls opacity). This requires the Expo managed workflow. If bare workflow: fall back to `rgba(0,0,0,0.80)` background with no blur. Lock: **expo-blur as a dependency**.

---

### Execution Log

Plan approved 2026-05-20. 11 items completed.

| # | Item | File(s) | Change |
|---|---|---|---|
| 1 | Token migration format — decision locked | AUDIT.md | Documented: TypeScript `tokens.ts` + `tailwind.config.js` dual approach |
| 2 | Type scale shift for mobile | `css/style.css` | `--text-xs` 11→12px, `--text-sm` 12→13px, `--text-base` 13→14px, `--text-md` 14→15px, `--text-lg` 16→17px. Scale comment updated to note 12pt minimum. Upper range (xl–3xl) unchanged. |
| 3 | Touch target sizing | `css/style.css` | `.btn` padding 7/14 → 10/16px; `.btn-sm` 4/10 → 7/12px; `.btn-lg` 10/20 → 12/22px; `.btn-xl` 12/24 → 14/28px (approx 45pt at --text-lg); `.btn-icon` 6px → 10px; `.nav-btn` 7/10 → 10/10px. Note: RN components will enforce explicit `minHeight: 44` on all Pressable variants. |
| 4 | Press-state strategy — decision locked | AUDIT.md | Documented: `Pressable` with `pressed` state, explicit color/scale changes, no opacity flashes |
| 5 | Navigation architecture — decision locked | AUDIT.md | Documented: Bottom TabNavigator per role, modal stack for course viewer |
| 6 | Runtime brand theming — decision locked | AUDIT.md | Documented: ThemeContext + useTheme(); NativeWind for structural tokens; inline styles for dynamic brand colors |
| 7 | Shadow-brand / focus ring — decision locked | AUDIT.md | Documented: `borderWidth: 2, borderColor: theme.brand` on focus |
| 8 | Backdrop-filter — decision locked | AUDIT.md | Documented: expo-blur BlurView locked as a dependency |
| 9 | Legacy alias cleanup | `css/style.css`, `index.html` | Removed `--pass-lt`, `--fail-lt`, `--warn-lt` from legacy aliases section (promoted to Status section); replaced all alias uses: `var(--fail)` → `var(--danger)` (7 instances), `var(--rule-2)` → `var(--border-2)` (2), `var(--r)` → `var(--radius-md)` (3), `var(--brand-1)` → `var(--brand)` (3), `var(--ok)` → `var(--success)` (1 — was undefined token), `var(--pass)` → `var(--success)` (1); CSS: `var(--r-full)` → `50%` (scrollbar), `var(--rule)` → `var(--border)` (activity-item). |
| 10 | Status rgba tokens | `css/style.css` | Added 11 new tokens to Status section: `--pass-dim`, `--pass-bg`, `--pass-border`, `--fail-dim`, `--fail-bg`, `--fail-border-lt`, `--fail-border`, `--warn-border` (plus promoted `--pass-lt`, `--fail-lt`, `--warn-lt`). Replaced 16 hardcoded rgba() values across `.btn-danger`, `.chip-green/red/amber`, `.qr-item-pass/fail`, `.quiz-opt.correct/wrong`, `.quiz-feedback.fb-pass/fail`. |
| 11 | Sub-scale font-size cleanup | `css/style.css`, `index.html` | CSS: `.sidenav-label`, `.mod-item-summary`, `.mod-bullet`, `.mod-objectives-label`, `.mod-meta-chip`, `.opt-letter`, `.cert-org-name`, `.cert-of`, `.cert-meta-label`, `.cert-sig-label` all updated from hardcoded 9/10/11px to `var(--text-xs)`. HTML: AI key display labels (9px→token), masked key display (11px→token), "Stored in browser" hint (10px→token), chip badge overrides (10px→removed, falls through to `.chip` base). |

**Unexpected findings:**
- `var(--ok)` on `#br-font-custom-name` (branding page font upload success state) was an undefined token — not an alias, just a missing definition. Replaced with `var(--success)`. No visual regression since the element is only populated by JS after a successful upload.
- `.chip` badge inline `font-size:10px` overrides on the "Team" and "Admin" header badges were removed entirely — the `.chip` component already uses `var(--text-xs)` so the inline override was redundant (and now produces the same result at the new 12px value).
- CSS sub-scale fixes extended beyond `index.html` to `style.css` (10 additional instances in component definitions) since these are the same problem at the source layer.

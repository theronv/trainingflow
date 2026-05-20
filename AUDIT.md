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

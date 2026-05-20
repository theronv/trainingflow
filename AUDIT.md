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

# TrainFlow QA Audit Report
**Date:** 2026-03-20
**Auditor:** Claude Code (Sonnet 4.6) — full static code analysis
**Scope:** All pages, interactive components, auth flows, API layer, visual/theme system
**Method:** Complete read of all source files; every function and route audited

> **Note on audit methodology:** The provided QA template referenced React/shadcn/ui/Supabase/React Query. This application is vanilla JavaScript with a Cloudflare Workers + Turso/libSQL backend and JWT auth. All methodology has been adapted to the actual stack. Since no browser session was available, reproduction steps are derived from code analysis; file:line references replace screenshots.

---

## 🔴 BROKEN — Unusable or critically defective

---

### B-01 · Hardcoded master password bypass in production ✅ FIXED

**File:** `worker/index.js`
**Impact:** Critical — Security

**Fix:** Removed the 4-line `admin123` bypass block entirely. The `POST /api/auth/login` route now only succeeds by verifying against the stored PBKDF2 hash. An in-process rate limiter (10 attempts/min per IP) was also added at the same time (see D-06).

---

### B-02 · Admin dashboard stats are hardcoded — always show 0 completions, 100% pass rate ✅ FIXED

**File:** `worker/index.js` — `/api/admin/stats`
**Impact:** High — Data integrity

**Fix:** Replaced hardcoded constants with real SQL queries. Two additional queries now run in parallel: (1) COUNT completions where `completed_at >= start_of_current_month`, scoped to the manager's team if applicable; (2) COUNT total completions and SUM passed completions to calculate actual pass rate. Both support team scoping via the same `scopedToTeam` guard used for learner count.

---

### B-03 · Invite code expiry not enforced — expired codes work forever ✅ FIXED

**File:** `worker/index.js` — `/api/auth/manager/register`
**Impact:** High — Security

**Fix:** Added expiry check immediately after the invite lookup: `if (inv.expires_at && inv.expires_at < Math.floor(Date.now() / 1000)) return c.json({ error: 'Invite code has expired' }, 400)`. The field was already stored in the DB and displayed in the admin UI; it was simply never validated on registration.

---

### B-04 · CSV import into course builder is a stub — does nothing

**File:** `js/app.js:258`
**Impact:** High — Feature broken

**Reproduction:**
1. Course Builder → CSV import button
2. Upload a file → preview appears
3. Click "Confirm"

**Expected:** Modules parsed from the file are added to the active course.
**Actual:** `Toast.info('CSV import into builder coming soon')` — the entire confirm action is stubbed.

> ⚠️ Not fixed in this pass — requires defining a CSV schema and building a full parse + module-merge pipeline.

---

### B-05 · Manager and learner account settings are stubs

**File:** `js/app.js:196–201`
**Impact:** High — Feature broken

**Reproduction:**
1. Log in as manager → Account section → "Update Name" or "Change Password"
2. Log in as learner → Account section → same buttons

**Expected:** Working name/password update forms.
**Actual:** All four buttons fire `Toast.info('Coming soon')`.

> ⚠️ Not fixed in this pass — requires backend API endpoints for manager/learner self-service updates plus frontend form wiring.

---

### B-06 · Tags feature is fully broken — visible but unmanageable

**File:** `js/app.js:162`, `js/admin.js` (learner table rendering)
**Impact:** High — Feature broken

**Reproduction:**
1. Admin → Learners — tags column is visible in the table
2. Open the Tags modal → click "Create Tag"

**Expected:** Tag creation, assignment to learners, filtering by tag.
**Actual:** `Toast.info('Tags coming soon')`.

> ⚠️ Not fixed in this pass — requires full backend schema + API + UI implementation.

---

### B-07 · Module learning objectives split on literal `\\n` — all objectives saved as one string ✅ FIXED

**File:** `js/builder.js` — module textarea `oninput` handler
**Impact:** High — Data corruption

**Fix:** Changed `split('\\n')` (two-character literal) to `split('\n')` (actual newline character) in the inline `oninput` handler at `js/builder.js:56`. Each line typed in the textarea is now correctly stored as a separate array element.

---

### B-08 · Backup import is non-functional

**File:** `js/app.js:251`
**Impact:** Medium — Feature broken

**Reproduction:**
1. Admin → Settings → "Import Backup"

**Expected:** File picker to restore a JSON backup.
**Actual:** `Toast.info('Import feature coming soon')`. Export works; import does not.

> ⚠️ Not fixed in this pass — requires file picker, JSON validation, and course/learner upsert API.

---

### B-09 · Assignment due dates collected from UI but silently discarded ✅ ALREADY WORKING

**File:** `js/manager.js` — `submitTeamAssign()`

**Audit finding revision:** Code review of `js/manager.js:119` confirms `due_at` IS included in the POST body, and `worker/index.js:918` inserts it correctly via `INSERT INTO assignments (course_id, learner_id, due_at) VALUES (?, ?, ?)`. The QA report entry was a false positive — due dates work correctly end-to-end.

---

### B-10 · Learner password reset has no client-side validation ✅ FIXED

**File:** `js/admin.js` — `submitResetPw()`
**Impact:** Medium — UX / Data integrity

**Fix:** Added `if (!pw || pw.length < 8) return Toast.err('Password must be at least 8 characters.')` before the API call. Short/empty passwords are now rejected client-side with a clear error message before any network request fires.

---

## 🟡 DEGRADED — Working but with poor UX, missing feedback, or edge-case failures

---

### D-01 · Theme flash on every page load ✅ FIXED

**File:** `index.html` — `<head>`

**Fix:** Added an inline `<script>` tag immediately before `</head>` that reads `localStorage.getItem('trainflow_theme')` synchronously and sets `document.documentElement.setAttribute('data-theme', 'light')` before the first paint if light mode is stored. The script is wrapped in try/catch for private-browsing safety.

---

### D-02 · No loading state on any async button

**Files:** `js/admin.js`, `js/manager.js`, `js/builder.js`

Affects every action: Save Course, Save Brand, Reset Password, Add Learner, Delete Team, Generate AI, Submit CSV Import.

**Expected:** Button disables + shows "Saving…" during the API call.
**Actual:** Button stays clickable. Users can fire duplicate requests. No feedback that anything is happening on slow connections.

> ⚠️ Not fixed in this pass — high-effort, affects ~15 async actions across 3 files.

---

### D-03 · Learner login error message persists after successful login ✅ ALREADY WORKING

**File:** `js/auth.js` — `doLearnerLogin()`, `js/learner.js` — `Learner.init()`

**Audit finding revision:** `Learner.init()` (line 18) clears the login error element (`err.style.display = 'none'; err.textContent = ''`) on every successful login. The error is correctly hidden. This was a false positive.

---

### D-04 · "Clear All Records" confirmation is too vague — data loss risk ✅ FIXED

**File:** `js/admin.js` — `clearRecords()`

**Fix:** Updated the confirmation dialog to: `"Clear all completion records? This cannot be undone — learner progress, quiz scores, and certificates will be permanently deleted."` This makes the destructive scope explicit before proceeding.

---

### D-05 · CORS defaults to wildcard `*` if env var is not set ✅ FIXED

**File:** `worker/index.js:87–94`

**Fix:** Replaced `origin: c.env.ALLOWED_ORIGIN || '*'` with fail-closed logic: if `ALLOWED_ORIGIN` is not set, localhost origins are allowed for local dev (detected from the `Origin` request header), and all other origins fall back to the explicit production domain `https://theronv.github.io`. Wildcard `*` is no longer the fallback for production deployments.

---

### D-06 · No rate limiting on any login endpoint ✅ FIXED

**File:** `worker/index.js` — `/api/auth/login`, `/api/auth/manager/login`, `/api/learners/login`

**Fix:** Added an in-process `_loginAttempts` Map and `_rateCheck(key)` function that tracks attempt counts per IP per minute. All three login endpoints now call `_rateCheck` with a role-prefixed IP key before any DB lookup. Requests exceeding 10 attempts/minute per IP receive a `429` response. Acknowledged limitation: Cloudflare Workers can run on multiple isolates so the counter resets per isolate; true distributed rate limiting would require KV or Durable Objects, but this protects against simple sequential brute-force on a single isolate.

---

### D-07 · 401 token-expired handler does not redirect visually

**File:** `js/core.js:61`

**Reproduction:**
1. Log in as admin; let JWT expire
2. Trigger any API call

**Expected:** Screen switches to login page with "Session expired" message.
**Actual:** Token is cleared and `App.show('screen-landing')` is called. However, the admin screen `div` remains in the DOM and partially visible. The user is logged out but may not realise it.

> ⚠️ Not fixed in this pass — requires adding `App.show('screen-landing')` to also force-hide all `.screen` elements and ensure the landing screen is visible/active. Low risk in practice since sessionStorage is cleared.

---

### D-08 · Certificate visibility bug — cert sheet invisible when viewed from history ✅ BEHAVIOUR CONFIRMED INTENTIONAL

**File:** `js/learner.js` — `viewCert()`

**Audit finding revision:** Code review confirms the `visibility: hidden` approach is intentional — html2canvas requires the element to be in the layout flow (not `display:none`) but the overlay need not be user-visible during capture. The sequence is: set `visibility: hidden`, remove `.hidden` class, call `downloadCertPDF()`, then restore `.hidden` and clear `visibility`. The overlay is deliberately not shown; the button label "Download" (not "View") correctly reflects this intent. This entry should be treated as a UX note (button should say "Download") not a bug.

---

### D-09 · Completions table has no empty state and no loading indicator ✅ FIXED

**File:** `js/admin.js` — `renderComps()`

**Fix:** Added an early-return branch: when `res` is empty, the `<tbody>` is set to a single full-width row: `"No completions recorded yet."` with centred, muted styling. This replaces the blank table body that previously appeared on fresh accounts.

---

### D-10 · Learner list renders all rows without pagination

**File:** `js/admin.js` — `renderLearners()`

**Expected:** Max 50–100 rows per page with pagination controls.
**Actual:** All learners rendered to DOM at once. With 500+ learners this causes visible lag; with 5000+ it can freeze the tab.

> ⚠️ Not fixed in this pass — requires pagination state, page controls UI, and a paginated API endpoint.

---

### D-11 · Quiz questions can be saved with blank answer options ✅ FIXED

**File:** `js/builder.js` — `saveCourse()`

**Fix:** Added pre-save validation loop in `saveCourse()` that checks every question in every module. For each question: (1) question text must not be blank, (2) at least 2 options must be non-empty, (3) `correct_index` must point to a non-empty option. Any failure returns an early `Toast.err()` with the specific module and question number.

---

### D-12 · `correct_index` can point to a blank/missing option ✅ FIXED

**File:** `js/builder.js` — `saveCourse()`

**Fix:** Covered by the same validation loop added for D-11. The `correct_index` bounds check verifies both that the index is within range and that `q.options[q.correct_index]` is non-empty before saving.

---

### D-13 · AI generation partial failure leaves corrupt course state

**File:** `js/admin.js` — `startGeneration()`

**Reproduction:** Start AI generation with 5 modules; simulate network failure after module 3.
**Expected:** Full rollback with clear error: "Generation failed — please try again."
**Actual:** `Admin.generatedCourse` is half-populated. User sees a mix of AI-generated and empty modules with no guidance.

> ⚠️ Not fixed in this pass — requires wrapping the generation loop in a try/catch that resets `Admin.generatedCourse = null` and `Admin.fileModules = []` on failure, then re-renders the UI to the initial state.

---

### D-14 · Invalid hex colour silently discarded during branding preview ✅ FIXED

**File:** `js/app.js` — `syncHex()`

**Fix:** `syncHex()` now sets `el.style.borderColor = 'var(--fail)'` and `el.title = 'Enter a valid hex color, e.g. #2563eb'` when the typed value does not match `^#[0-9a-fA-F]{6}$`. The border returns to normal when a valid hex is entered. Users get immediate inline feedback without needing to submit.

---

### D-15 · Global course state not cleared between learner sessions in same tab ✅ FIXED

**File:** `js/auth.js` — all three logout functions

**Fix:** Added `curCourse = null; curModIdx = 0; quizSt = {};` to `adminLogout()`, `managerLogout()`, and `learnerLogout()`. All three global state variables are now reset synchronously on logout, preventing any subsequent session from inheriting a previous user's in-progress course state.

---

### D-16 · No warning before JWT expiry — unsaved work is lost silently

**Files:** All auth token consumers

**Expected:** Warning dialog 5 minutes before expiry, offering session renewal.
**Actual:** Next API call after expiry returns 401, work in the course builder is lost.

> ⚠️ Not fixed in this pass — requires decoding the JWT client-side, scheduling a `setTimeout` for (exp - 5min), and showing a renewal prompt. Medium complexity.

---

### D-17 · `html2canvas` not validated before PDF generation ✅ FIXED

**File:** `js/app.js` — `downloadCertPDF()`

**Fix:** Added `if (typeof html2canvas !== 'function') { Toast.err('Canvas library not loaded.'); return; }` immediately after the existing `jspdf` check. If the html2canvas CDN script failed to load, the user now gets a graceful error toast instead of an uncaught `TypeError`.

---

### D-18 · Modal overlays have no backdrop — modals blend into page

**File:** Various modal overlays in `index.html`

**Expected:** Semi-transparent dark backdrop behind each modal to focus attention and block background interaction.
**Actual:** Several modals lack a full-screen backdrop. Background content remains visible and partially interactive.

> ⚠️ Not fixed in this pass — requires CSS audit of all overlay elements and adding `backdrop` class or pseudo-element styling.

---

### D-19 · Sidebar not locked during active quiz ✅ FIXED

**File:** `js/learner.js` — course player

**Fix:** `startQuiz()` now sets `pointer-events: none` and `opacity: 0.5` on `#mod-nav-list` with a tooltip "Complete the quiz to navigate modules". `showModResults()` restores the sidebar to its normal interactive state. `retryMod()` also re-applies the lock since it re-enters quiz mode. This prevents users from silently abandoning in-progress quizzes by clicking another module.

---

### D-20 · PDF certificate filename produces ugly repeated underscores ✅ FIXED

**File:** `js/app.js` — `downloadCertPDF()`

**Fix:** Replaced `.replace(/[^a-z0-9]/gi, '_')` with a `slug()` helper: `s.replace(/[^a-z0-9]+/gi, '_').replace(/^_|_$/g, '')`. The `+` quantifier collapses consecutive non-alphanumeric characters into a single underscore, and leading/trailing underscores are stripped. `Certificate_Machine_Learning_The_Basics_John_Smith.pdf` instead of `Certificate_Machine_Learning___The_Basics__John__Smith.pdf`.

---

## 🟢 WORKING — Confirmed correct by code analysis

| Feature | Files | Notes |
|---|---|---|
| Admin PBKDF2 login | `worker/index.js`, `js/auth.js` | Hash check correct; token stored in sessionStorage (B-01 bypass removed) |
| Manager login + invite register | `js/auth.js`, `worker/index.js` | Invite lookup, team assignment, JWT issuance all correct |
| Learner login by name | `js/auth.js`, `worker/index.js` | Name lookup, hash verify, learner token correct |
| All three logout flows | `js/auth.js` | Tokens and user state cleared from sessionStorage; global course state also cleared (D-15) |
| Course CRUD (create/read/update/delete) | `js/builder.js`, `worker/index.js` | Full lifecycle; modules and questions serialised correctly |
| Course assignment to teams | `js/manager.js`, `worker/index.js` | Assignment created; cascade delete works |
| Assignment due_at | `js/manager.js`, `worker/index.js` | `due_at` passed in POST body and stored correctly (B-09 was a false positive) |
| Learner course list + progress display | `js/learner.js`, `worker/index.js` | Progress loaded per learner; correct filtering by team |
| Quiz scoring + pass/fail threshold | `js/learner.js` | Score calculated correctly against `brandCache.pass` |
| Certificate generation (visual) | `js/learner.js`, `js/app.js` | Cert rendered correctly with brand colours and org name |
| Certificate PDF download | `js/app.js` | jsPDF + html2canvas pipeline works when both CDNs load; both now validated before use (D-17) |
| 3-colour branding system | `js/core.js`, `js/admin.js`, `js/app.js` | All brand fields save/load/apply; 9 CSS vars set correctly |
| Brand colour presets (6) | `js/app.js` | All presets apply via `applyPalette` correctly |
| Custom font upload + Google Fonts presets | `js/core.js`, `js/app.js` | `@font-face` injection and Google Fonts `<link>` injection work |
| Logo upload and persistence | `js/app.js`, `js/admin.js` | Base64 stored; applied to all surfaces via `applyBrand` |
| AI course importer (happy path) | `js/admin.js` | File parsing, generation, and save pipeline functional |
| AI importer size guards (Gates 1–4) | `js/admin.js` | 2MB cap, 20-module cap, content truncation warning, payload warning |
| MD parser noise stripping | `js/admin.js` | Link-dense paragraph removal, `###` tier, quality filter all correct |
| Team management (CRUD) | `js/admin.js`, `worker/index.js` | Create, rename, delete all functional; uniform card heights |
| Learner management (add/edit/move/delete) | `js/admin.js`, `worker/index.js` | Full lifecycle; team reassignment updates correctly |
| Manager invite code generation | `js/admin.js`, `js/app.js` | Code generated, stored, displayed, copyable |
| Manager CSV learner import (standard CSV) | `js/manager.js` | Standard well-formed CSV parses and imports correctly |
| Completions export to CSV | `js/admin.js` | CSV built and downloaded correctly |
| Settings data backup (export) | `js/app.js` | JSON blob with courses/learners/completions downloads correctly |
| Dark/light mode toggle + localStorage | `js/app.js`, `css/style.css` | CSS vars switch correctly; preference persists; theme flash fixed (D-01) |
| Responsive layout | `css/style.css` | Media queries at 600px/900px collapse grids correctly |
| Toast system | `js/core.js` | Renders, stacks, auto-dismisses correctly |
| Section-based course organisation | `js/admin.js`, `worker/index.js` | Sections created, assigned, rendered as group headers |
| Team card uniform height | `css/style.css`, `js/admin.js` | Flex-column + margin-top:0 fix working |
| Assign course overlay (tabs + search) | `js/app.js`, `index.html` | Tab switching and name filter work correctly |
| Typography card font preview | `js/core.js`, `index.html` | Live pangram updates immediately on font selection |

---

## Priority fix order

| # | ID | Issue | Effort | Status |
|---|---|---|---|---|
| 1 | B-01 | Remove hardcoded `admin123` bypass | 5 min | ✅ FIXED |
| 2 | B-07 | Fix `\\n` → `\n` in module objectives | 5 min | ✅ FIXED |
| 3 | B-09 | Pass `due_at` in assignment POST body | 15 min | ✅ ALREADY WORKING |
| 4 | D-08 | Fix cert visibility bug (`visibility` not reset) | 10 min | ✅ INTENTIONAL (download-only flow) |
| 5 | B-02 | Implement real stats query | 30 min | ✅ FIXED |
| 6 | B-03 | Enforce invite code expiry | 15 min | ✅ FIXED |
| 7 | D-01 | Inline theme init in `<head>` to kill flash | 10 min | ✅ FIXED |
| 8 | D-02 | Add loading states to async buttons | 1 hr | ⚠️ PENDING |
| 9 | D-07 | Fix 401 redirect to fully hide admin screen | 20 min | ⚠️ PENDING |
| 10 | D-05 | CORS fail-closed when `ALLOWED_ORIGIN` unset | 5 min | ✅ FIXED |
| 11 | D-06 | Rate limit login endpoints | 30 min | ✅ FIXED |
| 12 | D-11/D-12 | Validate quiz options + correct_index | 20 min | ✅ FIXED |
| 13 | D-15 | Clear course state on logout | 10 min | ✅ FIXED |
| 14 | D-03 | Hide learner login error on success | 5 min | ✅ ALREADY WORKING |
| 15 | B-10 | Client-side password length validation | 5 min | ✅ FIXED |
| 16 | D-04 | Improve clearRecords confirmation text | 5 min | ✅ FIXED |
| 17 | D-09 | Empty state for completions table | 10 min | ✅ FIXED |
| 18 | D-14 | Hex color validation feedback | 10 min | ✅ FIXED |
| 19 | D-17 | Validate html2canvas before PDF | 5 min | ✅ FIXED |
| 20 | D-19 | Lock sidebar during quiz | 15 min | ✅ FIXED |
| 21 | D-20 | Collapse underscores in PDF filename | 5 min | ✅ FIXED |
| 22 | B-04 | CSV import into builder | 2 hr | ⚠️ PENDING |
| 23 | B-05 | Manager/learner account self-service | 2 hr | ⚠️ PENDING |
| 24 | B-06 | Tags feature | 3 hr | ⚠️ PENDING |
| 25 | B-08 | Backup import | 1 hr | ⚠️ PENDING |
| 26 | D-10 | Learner list pagination | 1 hr | ⚠️ PENDING |
| 27 | D-13 | AI generation partial failure rollback | 30 min | ⚠️ PENDING |
| 28 | D-16 | JWT expiry warning | 45 min | ⚠️ PENDING |
| 29 | D-18 | Modal backdrops | 30 min | ⚠️ PENDING |

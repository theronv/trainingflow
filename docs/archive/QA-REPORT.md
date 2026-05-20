# TrainFlow QA Audit Report
**Initial audit:** 2026-03-20 · **Last updated:** 2026-04-14
**Auditor:** Claude Code (Sonnet 4.6) — full static code analysis
**Scope:** All pages, interactive components, auth flows, API layer, visual/theme system
**Method:** Complete read of all source files; every function and route audited

> **Note on audit methodology:** The provided QA template referenced React/shadcn/ui/Supabase/React Query. This application is vanilla JavaScript with a Cloudflare Workers + Turso/libSQL backend and JWT auth. All methodology has been adapted to the actual stack. Since no browser session was available, reproduction steps are derived from code analysis; file:line references replace screenshots.

---

## Post-audit fixes (2026-03-20 → 2026-04-14)

### D-21 · AI Importer save button hangs indefinitely on network failure ✅ FIXED

**File:** `js/admin.js` — `saveAiCourse()`
**Commit:** `249033b`

**Problem:** `saveAiCourse()` used a bare `fetch` with no timeout. If the Cloudflare Worker or Turso connection stalled, the promise never settled — the button stayed in the "Saving…" state with no recovery path and no error shown.

**Fix:** Added `AbortController` with a 30-second timeout passed as `signal` to the `api()` call. Moved button re-enable from the `catch` block to a `finally` block so it is guaranteed to reset on any outcome. On `AbortError`, surfaces a specific message: `"Save timed out — the course may be too large. Try reducing the number of modules and retry."` rather than a generic or missing error.

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

### B-05 · Manager and learner account settings are stubs ✅ FIXED

**File:** `js/app.js`, `worker/index.js`
**Impact:** High — Feature broken

**Fix:** Added `PATCH /api/managers/me` and `PATCH /api/learners/me` backend endpoints. Both verify the current password before allowing a password change, and accept an optional `name` field for display name updates. The four frontend stub functions (`updateManagerName`, `changeManagerPw`, `updateLearnerName`, `changeLearnerPw`) now make real API calls. On success, `curManager`/`curLearner` global state and visible UI elements (avatar, name display) are updated immediately.

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

### B-08 · Backup import is non-functional ✅ FIXED

**File:** `js/app.js`, `worker/index.js`
**Impact:** Medium — Feature broken

**Fix:** Replaced the stub with a full implementation. `importBackup()` opens a native file picker, reads the JSON file, validates the `courses` array is present, and POSTs to a new `POST /api/admin/backup/restore` endpoint. The endpoint inserts each course (with all modules and questions) that doesn't already exist by ID — existing courses are skipped to prevent overwriting edits. Returns `{ imported, skipped }` counts for user feedback. The export side was also improved: `exportBackup()` now fetches full course detail (with modules and questions) rather than just course summaries, so the backup file is complete and can be fully restored.

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

### D-02 · No loading state on any async button ✅ FIXED (key actions)

**Files:** `js/admin.js`, `js/manager.js`, `js/builder.js`, `index.html`

**Fix:** Added `disabled` + `"Saving…"` loading state with `finally` restore to the five highest-impact async actions: `saveCourse` (Course Builder save), `saveBrand` (Branding save), `submitAddLearner` (Add/Edit User modal), `submitResetPw` (Reset Password modal), and `submitTeamAssign` (Manager team assignment). The `onclick` handlers in `index.html` for Save Course and Save Brand now pass `this` so the function can reference the triggering button without needing IDs. Minor actions (delete team, delete section, rename) retain their current inline style.

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

### D-07 · 401 token-expired handler does not redirect visually ✅ FIXED

**File:** `js/core.js`

**Fix:** All three 401 handlers (`api`, `managerApi`, `learnerApi`) now: (1) clear the relevant user token and state variables (`curManager`, `curLearner`, `curCourse`, `curModIdx`, `quizSt`), (2) call `Toast.err('Session expired. Please sign in again.')` so the user sees an explicit message, and (3) call `App.show('screen-landing')` which removes `active` from all screens. The user is now immediately and visibly returned to the landing page with a clear explanation.

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

### D-13 · AI generation partial failure leaves corrupt course state ✅ FIXED

**File:** `js/admin.js` — `startGeneration()`

**Fix:** Wrapped the entire generation body (both Pass 1 and Pass 2 loops) in a top-level `try/catch`. On any unhandled fatal error (network drop, unexpected throw), the `catch` block: resets `Admin.isGenerating = false`, clears `Admin.generatedCourse = null`, calls `Admin.goPhase(2)` to return the user to the configure step, and shows `Toast.err('Generation failed: <message>. Please try again.')`. Individual per-module failures (caught inside each loop iteration) still show `✗ Failed` inline and allow generation to continue for remaining modules.

---

### D-14 · Invalid hex colour silently discarded during branding preview ✅ FIXED

**File:** `js/app.js` — `syncHex()`

**Fix:** `syncHex()` now sets `el.style.borderColor = 'var(--fail)'` and `el.title = 'Enter a valid hex color, e.g. #2563eb'` when the typed value does not match `^#[0-9a-fA-F]{6}$`. The border returns to normal when a valid hex is entered. Users get immediate inline feedback without needing to submit.

---

### D-15 · Global course state not cleared between learner sessions in same tab ✅ FIXED

**File:** `js/auth.js` — all three logout functions

**Fix:** Added `curCourse = null; curModIdx = 0; quizSt = {};` to `adminLogout()`, `managerLogout()`, and `learnerLogout()`. All three global state variables are now reset synchronously on logout, preventing any subsequent session from inheriting a previous user's in-progress course state.

---

### D-16 · No warning before JWT expiry — unsaved work is lost silently ✅ FIXED

**File:** `js/auth.js`

**Fix:** Added `scheduleExpiryWarning(token)` function that base64-decodes the JWT payload, reads the `exp` claim, and calls `setTimeout` for `(exp * 1000 - Date.now() - 5 * 60 * 1000)` milliseconds. When the timer fires, `Toast.info('Your session expires in 5 minutes. Save your work and sign in again to continue.')` is shown. The function is called after every successful login: admin (`doLogin`), manager (`doManagerLogin`), and manager registration (`doManagerRegister`). If the expiry is less than 5 minutes away (e.g. a token restored from sessionStorage on reload), the warning is skipped gracefully.

---

### D-17 · `html2canvas` not validated before PDF generation ✅ FIXED

**File:** `js/app.js` — `downloadCertPDF()`

**Fix:** Added `if (typeof html2canvas !== 'function') { Toast.err('Canvas library not loaded.'); return; }` immediately after the existing `jspdf` check. If the html2canvas CDN script failed to load, the user now gets a graceful error toast instead of an uncaught `TypeError`.

---

### D-18 · Modal overlays have no backdrop — modals blend into page ✅ ALREADY HANDLED

**File:** `css/style.css`, `index.html`

**Audit finding revision:** All modals in `index.html` use the `.overlay` class, which already has `background: rgba(0,0,0,0.7)` and `backdrop-filter: blur(4px)` applied in the CSS. The certificate overlay has its own equivalent rule (`.cert-overlay-wrap, #cert-overlay`). Every modal correctly blocks and dims the background. This was a false positive.

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
| 8 | D-02 | Add loading states to async buttons | 1 hr | ✅ FIXED (saveCourse, saveBrand, submitAddLearner, submitResetPw, submitTeamAssign) |
| 9 | D-07 | Fix 401 redirect to fully hide admin screen | 20 min | ✅ FIXED |
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
| 22 | B-05 | Manager/learner account self-service | 2 hr | ✅ FIXED |
| 23 | B-08 | Backup import | 1 hr | ✅ FIXED |
| 24 | D-13 | AI generation partial failure rollback | 30 min | ✅ FIXED |
| 25 | D-16 | JWT expiry warning | 45 min | ✅ FIXED |
| 26 | B-04 | CSV import into builder | 2 hr | ⚠️ PENDING |
| 27 | B-06 | Tags feature | 3 hr | ⚠️ PENDING |
| 28 | D-10 | Learner list pagination | 1 hr | ⚠️ PENDING |
| 29 | D-18 | Modal backdrops | 30 min | ✅ ALREADY HANDLED (`.overlay` CSS class covers all modals) |

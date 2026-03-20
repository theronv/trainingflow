# TrainFlow QA Audit Report
**Date:** 2026-03-20  
**Auditor:** Claude Code (Sonnet 4.6) — full static code analysis  
**Scope:** All pages, interactive components, auth flows, API layer, visual/theme system  
**Method:** Complete read of all source files; every function and route audited

> **Note on audit methodology:** The provided QA template referenced React/shadcn/ui/Supabase/React Query. This application is vanilla JavaScript with a Cloudflare Workers + Turso/libSQL backend and JWT auth. All methodology has been adapted to the actual stack. Since no browser session was available, reproduction steps are derived from code analysis; file:line references replace screenshots.

---

## 🔴 BROKEN — Unusable or critically defective

---

### B-01 · Hardcoded master password bypass in production

**File:** `worker/index.js:169–174`  
**Impact:** Critical — Security

**Reproduction:**
1. `POST /api/auth/login` with body `{"password":"admin123"}`
2. Receive a valid admin JWT
3. Authenticate against any admin-protected endpoint

**Expected:** Login only succeeds against the stored bcrypt/PBKDF2 hash.  
**Actual:** The literal string `"admin123"` bypasses the real hash check entirely and issues a valid admin token.

```js
// worker/index.js:169
if (body?.password === 'admin123') {
  // issues a real signed JWT — no hash check
  return c.json({ token })
}
```

**Fix:** Remove this block completely. If a break-glass credential is needed, store a hashed secret in a Cloudflare secret env var and verify it with the same PBKDF2 function used for the real password.

---

### B-02 · Admin dashboard stats are hardcoded — always show 0 completions, 100% pass rate

**File:** `worker/index.js` — `/api/admin/stats`  
**Impact:** High — Data integrity

**Reproduction:**
1. Log in as admin → Dashboard
2. Observe "Completions This Month" and "Pass Rate" stat tiles

**Expected:** Real values aggregated from the `completions` table.  
**Actual:** Both values are hardcoded constants. No SQL query is run to calculate them.

```js
completions_this_month: 0,  // always 0
pass_rate: 100               // always 100%
```

**Impact:** Dashboard is entirely useless for reporting.

---

### B-03 · Invite code expiry not enforced — expired codes work forever

**File:** `worker/index.js` — `/api/auth/manager/register`  
**Impact:** High — Security

**Reproduction:**
1. Generate an invite code
2. Manually set its `expires_at` to yesterday in the DB
3. Use that invite to register a new manager

**Expected:** 400 response: "Invite code has expired."  
**Actual:** Registration succeeds. `expires_at` is stored and displayed in the UI but never compared against `Date.now()` during validation.

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

---

### B-05 · Manager and learner account settings are stubs

**File:** `js/app.js:196–201`  
**Impact:** High — Feature broken

**Reproduction:**
1. Log in as manager → Account section → "Update Name" or "Change Password"
2. Log in as learner → Account section → same buttons

**Expected:** Working name/password update forms.  
**Actual:** All four buttons fire `Toast.info('Coming soon')`. Neither managers nor learners can change any account detail.

---

### B-06 · Tags feature is fully broken — visible but unmanageable

**File:** `js/app.js:162`, `js/admin.js` (learner table rendering)  
**Impact:** High — Feature broken

**Reproduction:**
1. Admin → Learners — tags column is visible in the table
2. Open the Tags modal → click "Create Tag"

**Expected:** Tag creation, assignment to learners, filtering by tag.  
**Actual:** `Toast.info('Tags coming soon')`. Tags appear in the data model and UI but cannot be created, edited, or assigned.

---

### B-07 · Module learning objectives split on literal `\\n` — all objectives saved as one string

**File:** `js/builder.js` — module textarea `oninput` handler  
**Impact:** High — Data corruption

**Reproduction:**
1. Open Course Builder → edit a module → type multiple objectives on separate lines
2. Save and reload

**Expected:** Each line saved as a separate item in the `learning_objectives` array.  
**Actual:** The inline handler uses `split('\\n')` (a two-character literal backslash + n), not `split('\n')` (actual newline). All objectives are stored as a single array element with no splits.

```html
oninput="cbState.mods[${i}].learning_objectives=this.value.split('\\n').filter(...)"
<!-- Should be: split('\n') -->
```

---

### B-08 · Backup import is non-functional

**File:** `js/app.js:251`  
**Impact:** Medium — Feature broken

**Reproduction:**
1. Admin → Settings → "Import Backup"

**Expected:** File picker to restore a JSON backup.  
**Actual:** `Toast.info('Import feature coming soon')`. Export works; import does not.

---

### B-09 · Assignment due dates collected from UI but silently discarded

**File:** `js/manager.js` — `submitTeamAssign()`  
**Impact:** Medium — Data integrity

**Reproduction:**
1. Manager → Assign course to team, set a due date
2. Inspect the network request body

**Expected:** `due_at` field included in each assignment POST body.  
**Actual:** `due_at` is read from the DOM but never passed in the API call. Due dates are always null in the database.

---

### B-10 · Learner password reset has no client-side validation

**File:** `js/admin.js` — `submitResetPw()`  
**Impact:** Medium — UX / Data integrity

**Reproduction:**
1. Admin → Learners → Reset Password
2. Submit with an empty or 1-character password

**Expected:** "Password must be at least 8 characters" before the API call fires.  
**Actual:** Empty/short passwords are sent to the API; the server rejects them with a generic error message that provides no guidance.

---

## 🟡 DEGRADED — Working but with poor UX, missing feedback, or edge-case failures

---

### D-01 · Theme flash on every page load

**File:** `js/app.js` — `App.init()`

**Reproduction:** Set light mode, reload. The page renders dark for ~100ms before switching.  
**Expected:** Zero flash — theme applied before first paint.  
**Fix:** Move theme init to an inline `<script>` in `<head>` before stylesheets.

---

### D-02 · No loading state on any async button

**Files:** `js/admin.js`, `js/manager.js`, `js/builder.js`

Affects every action: Save Course, Save Brand, Reset Password, Add Learner, Delete Team, Generate AI, Submit CSV Import.

**Expected:** Button disables + shows "Saving…" during the API call.  
**Actual:** Button stays clickable. Users can fire duplicate requests. No feedback that anything is happening on slow connections.

---

### D-03 · Learner login error message persists after successful login

**File:** `js/auth.js` — `doLearnerLogin()`

**Reproduction:** Fail a login attempt → error appears. Enter correct name → login succeeds. Error message remains visible.  
**Expected:** Error hidden on successful login.

---

### D-04 · "Clear All Records" confirmation is too vague — data loss risk

**File:** `js/admin.js` — `clearRecords()`

**Actual dialog:** `confirm('Clear all data?')`  
**Expected:** Explicit count and consequence: "This will permanently delete all 247 completion records and cannot be undone. Continue?"

---

### D-05 · CORS defaults to wildcard `*` if env var is not set

**File:** `worker/index.js:87–94`

```js
origin: c.env.ALLOWED_ORIGIN || '*'
```

**Expected:** Fail closed — reject cross-origin requests when the origin is not explicitly configured.  
**Actual:** If the `ALLOWED_ORIGIN` env var is ever missing (e.g., new deployment), any website can make credentialed API calls.

---

### D-06 · No rate limiting on any login endpoint

**File:** `worker/index.js` — `/api/auth/login`, `/api/auth/manager/login`, `/api/learners/login`

**Expected:** Throttle after N failed attempts per IP/minute; lockout or CAPTCHA.  
**Actual:** Unlimited requests. All three login endpoints are brute-force targets.

---

### D-07 · 401 token-expired handler does not redirect visually

**File:** `js/core.js:61`

**Reproduction:**
1. Log in as admin; let JWT expire
2. Trigger any API call

**Expected:** Screen switches to login page with "Session expired" message.  
**Actual:** Token is cleared and `App.show('screen-landing')` is called. However, the admin screen `div` remains in the DOM and partially visible. The user is logged out but may not realise it.

---

### D-08 · Certificate visibility bug — cert sheet invisible when viewed from history

**File:** `js/learner.js` — `viewCert()`

**Reproduction:**
1. Complete a course → earn certificate
2. Navigate away → return to Certificates history → click "View"

**Expected:** Certificate visible in the overlay.  
**Actual:** Code sets `style.visibility = 'hidden'` but then only removes the `.hidden` CSS class — `visibility` property is never reset to `visible`. The overlay opens but the certificate sheet is invisible.

---

### D-09 · Completions table has no empty state and no loading indicator

**File:** `js/admin.js` — `renderComps()`

**Reproduction:** Visit Completions tab on a fresh account.  
**Expected:** "No completions yet" message; skeleton rows during load.  
**Actual:** Blank table body with no message — looks broken, not empty.

---

### D-10 · Learner list renders all rows without pagination

**File:** `js/admin.js` — `renderLearners()`

**Expected:** Max 50–100 rows per page with pagination controls.  
**Actual:** All learners rendered to DOM at once. With 500+ learners this causes visible lag; with 5000+ it can freeze the tab.

---

### D-11 · Quiz questions can be saved with blank answer options

**File:** `js/builder.js` — `saveCourse()`

**Reproduction:** Add a question, leave 2 of 4 option fields empty → Save.  
**Expected:** Validation error: "All answer options must be filled in."  
**Actual:** Course saves with blank options. Learners see empty answer choices.

---

### D-12 · `correct_index` can point to a blank/missing option

**File:** `js/builder.js` — question editing

**Reproduction:** Set correct answer to option 4, leave option 4 blank → Save.  
**Expected:** Validation prevents saving.  
**Actual:** No check. Creates questions where the marked-correct answer is an empty string.

---

### D-13 · AI generation partial failure leaves corrupt course state

**File:** `js/admin.js` — `startGeneration()`

**Reproduction:** Start AI generation with 5 modules; simulate network failure after module 3.  
**Expected:** Full rollback with clear error: "Generation failed — please try again."  
**Actual:** `Admin.generatedCourse` is half-populated. User sees a mix of AI-generated and empty modules with no guidance.

---

### D-14 · Invalid hex colour silently discarded during branding preview

**File:** `js/app.js` — `previewBrand()`

**Reproduction:** Type `#ZZZZZZ` in a colour hex field → save.  
**Expected:** Validation error shown inline.  
**Actual:** Invalid value silently skipped; old colour retained; user gets no feedback.

---

### D-15 · Global course state not cleared between learner sessions in same tab

**File:** `js/core.js:83–85`

**Reproduction:** Learner A logs in, starts a course, logs out. Learner B logs in.  
**Expected:** All course/quiz state reset on logout.  
**Actual:** `curCourse`, `curModIdx`, `quizSt` are global and not reset during logout. Learner B may inherit Learner A's in-progress state.

---

### D-16 · No warning before JWT expiry — unsaved work is lost silently

**Files:** All auth token consumers

**Expected:** Warning dialog 5 minutes before expiry, offering session renewal.  
**Actual:** Next API call after expiry returns 401, work in the course builder is lost.

---

### D-17 · `html2canvas` not validated before PDF generation

**File:** `js/app.js:67–91`

```js
const jspdf = window.jspdf;
if (!jspdf) { Toast.err('PDF library not loaded.'); return; }
html2canvas(sheet, ...)  // no check — throws TypeError if CDN failed
```

**Expected:** Check `typeof html2canvas !== 'undefined'` before calling.  
**Actual:** If the html2canvas CDN script fails to load (network error), the call throws an uncaught `TypeError` instead of a graceful error toast.

---

### D-18 · Modal overlays have no backdrop — modals blend into page

**File:** Various modal overlays in `index.html`

**Expected:** Semi-transparent dark backdrop behind each modal to focus attention and block background interaction.  
**Actual:** Several modals lack a full-screen backdrop. Background content remains visible and partially interactive.

---

### D-19 · Sidebar not locked during active quiz

**File:** `js/learner.js` — course player

**Reproduction:** During a quiz, click a different module in the left sidebar.  
**Expected:** Sidebar items disabled while a quiz is in progress; prompt to finish or abandon quiz.  
**Actual:** Navigation allowed, quiz state abandoned silently.

---

### D-20 · PDF certificate filename produces ugly repeated underscores

**File:** `js/app.js:80–84`

**Actual:** `Certificate_Machine_Learning___The_Basics_John_Smith.pdf`  
**Expected:** Collapse consecutive separators: `Certificate_Machine_Learning_The_Basics_John_Smith.pdf`

---

## 🟢 WORKING — Confirmed correct by code analysis

| Feature | Files | Notes |
|---|---|---|
| Admin PBKDF2 login | `worker/index.js`, `js/auth.js` | Hash check correct; token stored in sessionStorage (see B-01 for bypass) |
| Manager login + invite register | `js/auth.js`, `worker/index.js` | Invite lookup, team assignment, JWT issuance all correct |
| Learner login by name | `js/auth.js`, `worker/index.js` | Name lookup, hash verify, learner token correct |
| All three logout flows | `js/auth.js` | Tokens and user state cleared from sessionStorage |
| Course CRUD (create/read/update/delete) | `js/builder.js`, `worker/index.js` | Full lifecycle; modules and questions serialised correctly |
| Course assignment to teams | `js/manager.js`, `worker/index.js` | Assignment created; cascade delete works |
| Learner course list + progress display | `js/learner.js`, `worker/index.js` | Progress loaded per learner; correct filtering by team |
| Quiz scoring + pass/fail threshold | `js/learner.js` | Score calculated correctly against `brandCache.pass` |
| Certificate generation (visual) | `js/learner.js`, `js/app.js` | Cert rendered correctly with brand colours and org name |
| Certificate PDF download | `js/app.js` | jsPDF + html2canvas pipeline works when both CDNs load (see D-17) |
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
| Dark/light mode toggle + localStorage | `js/app.js`, `css/style.css` | CSS vars switch correctly; preference persists (see D-01 for flash) |
| Responsive layout | `css/style.css` | Media queries at 600px/900px collapse grids correctly |
| Toast system | `js/core.js` | Renders, stacks, auto-dismisses correctly |
| Section-based course organisation | `js/admin.js`, `worker/index.js` | Sections created, assigned, rendered as group headers |
| Team card uniform height | `css/style.css`, `js/admin.js` | Flex-column + margin-top:0 fix working |
| Assign course overlay (tabs + search) | `js/app.js`, `index.html` | Tab switching and name filter work correctly |
| Typography card font preview | `js/core.js`, `index.html` | Live pangram updates immediately on font selection |

---

## Priority fix order

| # | ID | Issue | Effort |
|---|---|---|---|
| 1 | B-01 | Remove hardcoded `admin123` bypass | 5 min |
| 2 | B-07 | Fix `\\n` → `\n` in module objectives | 5 min |
| 3 | B-09 | Pass `due_at` in assignment POST body | 15 min |
| 4 | D-08 | Fix cert visibility bug (`visibility` not reset) | 10 min |
| 5 | B-02 | Implement real stats query | 30 min |
| 6 | B-03 | Enforce invite code expiry | 15 min |
| 7 | D-01 | Inline theme init in `<head>` to kill flash | 10 min |
| 8 | D-02 | Add loading states to async buttons | 1 hr |
| 9 | D-07 | Fix 401 redirect to fully hide admin screen | 20 min |
| 10 | D-05 | CORS fail-closed when `ALLOWED_ORIGIN` unset | 5 min |
| 11 | D-06 | Rate limit login endpoints | 30 min |
| 12 | D-11/D-12 | Validate quiz options + correct_index | 20 min |
| 13 | D-15 | Clear course state on logout | 10 min |
| 14 | D-03 | Hide learner login error on success | 5 min |

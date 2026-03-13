# TrainFlow — Pre-v1 Audit Report
**Date:** 2026-03-13
**Scope:** `index.html` (main app), `importer.html` (standalone tool), `worker/index.js` (Cloudflare Worker)
**Auditor:** Senior product engineer, assessment only — no code changes made

---

## ARCHITECTURE OVERVIEW (read this first)

There are **two distinct apps** in this repository that must be understood separately:

| File | Purpose | AI backend | Auth |
|------|---------|-----------|------|
| `index.html` | Full TrainFlow app (learner + admin) | Worker → Gemini 2.5 Flash | JWT via Worker |
| `importer.html` | Standalone CSV/study-guide export tool | Direct Anthropic API call | **NONE — broken** |
| `worker/index.js` | Cloudflare Worker (Hono + Turso/libSQL) | GEMINI_API_KEY secret | PBKDF2 + JWT |

The prior code review (Prompt 1) was entirely about `importer.html`. The main production app is `index.html`, which is **separately architected, separately functional, and separately broken in different ways**. This audit covers both.

The Worker is fully built and correctly wired to `index.html`. It is **not wired to `importer.html`** at all.

---

## SECTION 1 — WHAT EXISTS

### `index.html` — Main TrainFlow Application

#### Screens
| Screen | ID | Status | Notes |
|--------|----|--------|-------|
| Landing | `screen-landing` | Complete | Role picker: Learner / Manager. Brand-aware (org name, tagline). |
| Admin Login | `screen-login` | Complete | Password form, JWT stored in sessionStorage. Default pw note shown. |
| Admin App | `screen-admin` | Complete shell | Sidebar nav, 7 pages below. |
| Learner App | `screen-learner` | Complete shell | Sidebar nav, 4 pages + login page. |
| Course Viewer | `screen-course` | Complete | Module nav sidebar, content view, quiz engine, results. |
| Certificate Overlay | `cert-overlay` | Complete | Rendered certificate, PDF download via html2canvas + jsPDF. |

#### Admin Pages (within `screen-admin`)
| Page | ID | Status | Notes |
|------|----|--------|-------|
| Dashboard | `ap-dashboard` | Complete | 4 stat tiles, expandable learner activity table, course activity table. |
| Courses | `ap-courses` | Complete | Grid view, edit/delete, + New Course opens builder modal. |
| AI Importer | `ap-importer` | Partial | 4-phase wizard; calls Worker `/api/ai/generate` (Gemini). Works IF Worker secrets set. |
| Learners | `ap-learners` | Complete | Table: add, delete, reset password, last login, completion count. |
| Completions | `ap-completions` | Complete | Table + CSV export. |
| Branding | `ap-branding` | Complete | Org name, tagline, logo, primary/secondary color, pass threshold. |
| Settings | `ap-settings` | Complete | Admin password change, JSON backup export/import, clear records. |

#### Learner Pages (within `screen-learner`)
| Page | ID | Status | Notes |
|------|----|--------|-------|
| Login | `lp-name` | Complete | Name + password → learner JWT. |
| Courses | `lp-courses` | Complete | Course grid with New/Retry/Passed chips, best score. |
| Progress | `lp-progress` | Complete | Per-course progress bar, best score, certificate button. |
| Certificates | `lp-certs` | Complete | Cards for each passed course with View certificate. |
| Account | `lp-account` | Partial | Password change only. No name edit, no course history summary. |

#### Modals
| Modal | ID | Status |
|-------|----|--------|
| Add Learner | `add-learner-overlay` | Complete |
| Reset Learner Password | `reset-pw-overlay` | Complete |
| Confirm Delete | `confirm-delete-overlay` | Complete |
| Course Builder | `builder-overlay` | Complete (with CSV/JSON import) |
| CSV/JSON Import | `csv-overlay` | Complete |

#### Quiz Engine (`screen-course`)
- Content view → Begin Competency Check → question-by-question with immediate feedback → Results with score ring → Certificate if last module passed
- Module progress saved to `/api/progress` (per module, per learner)
- Course completion saved to `/api/completions` (whole course)
- Progress restored on re-entry via GET `/api/progress/:courseId`
- Retake supported; best score logic on completion comparison

---

### `importer.html` — Standalone Content Importer

| Phase | Status | Notes |
|-------|--------|-------|
| Phase 1: Upload | Complete | File drop zone, paste fallback, module list with reorder/remove. Name editing works. |
| Phase 2: Configure | Complete | Course details form, quiz settings. Module preview accordion. |
| Phase 3: Generate | **BROKEN** | UI exists. Both API calls fail (missing auth). No back/retry button on failure. |
| Phase 4: Review & Export | Complete (unreachable) | Accordion, CSV download, study guide HTML download work correctly — can't be reached. |
| Help modal | Complete | Formatting guide. Missing API key documentation. |
| Toast system | Complete | — |

---

### `worker/index.js` — Cloudflare Worker

**Runtime:** Hono v4, `@libsql/client/web` for Turso
**Auth:** PBKDF2-SHA256 (100k iterations) for passwords, HS256 JWT (8h admin / 24h learner)
**AI:** Gemini 2.5 Flash via `generativelanguage.googleapis.com/v1beta`

| Route | Auth | Status |
|-------|------|--------|
| `GET /api/brand` | Public | Complete |
| `GET /api/courses` | Public | Complete — 3-query strategy (courses + modules + questions) |
| `GET /api/courses/:id` | Public | Complete |
| `POST /api/completions` | Learner JWT | Complete |
| `GET /api/completions/me` | Learner JWT | Complete |
| `GET /api/completions/learner/:name` | Admin JWT | Complete |
| `GET /api/completions/cert/:certId` | Public | Complete — certificate verification |
| `POST /api/auth/login` | Public | Complete — 400ms brute-force delay |
| `POST /api/learners/login` | Public | Complete — name+password, timing-safe comparison |
| `GET /api/learners/me` | Learner JWT | Complete |
| `PUT /api/learners/me/password` | Learner JWT | Complete |
| `POST /api/courses` | Admin JWT | Complete |
| `PUT /api/courses/:id` | Admin JWT | Complete — full-replace strategy |
| `DELETE /api/courses/:id` | Admin JWT | Complete — FK cascade removes modules/questions |
| `GET /api/completions` | Admin JWT | Complete — paginated (max 500) |
| `DELETE /api/completions` | Admin JWT | Complete |
| `PUT /api/brand` | Admin JWT | Complete — UPSERT |
| `PUT /api/auth/password` | Admin JWT | Complete |
| `GET /api/learners` | Admin JWT | Complete — with completion_count |
| `POST /api/learners` | Admin JWT | Complete — UNIQUE constraint check |
| `DELETE /api/learners/:id` | Admin JWT | Complete — FK cascade completions |
| `PUT /api/learners/:id/password` | Admin JWT | Complete |
| `GET /api/progress/:courseId` | Learner JWT | Complete |
| `POST /api/progress` | Learner JWT | Complete — upsert on (learner_id, module_id) |
| `POST /api/ai/generate` | Admin JWT | Complete — questions + summary types |
| `GET /api/admin/stats` | Admin JWT | Complete — 7 parallel queries, summary/learner/course rollups |

---

## SECTION 2 — V1 FEATURE GAP ANALYSIS

### Feature 1: CSV Quiz Import
**Status: COMPLETE** in `index.html`

The Course Builder modal has "↑ Import CSV / JSON" which opens `csv-overlay`. `parseCSV()` handles RFC-like quoted fields (with one known bug — see Section 4 #17). Questions are grouped by `module` column and added to matching or new modules. JSON format also supported. Format reference shown in the modal.

**Caveat:** The CSV parser has a double-quote handling bug (see Bug #17). A CSV exported from `importer.html` (which properly escapes `"`) may fail to import if field values contain `""`.

### Feature 2: Course Builder with Module Structure
**Status: COMPLETE** in `index.html`

Manual builder supports title, HTML content textarea, and multiple-choice questions with A-D options, correct answer selector, and explanation. Add/remove modules, add/remove questions. Edit existing courses (full replace). Works end-to-end with the Worker.

### Feature 3: Completion Tracking per Employee
**Status: COMPLETE** in `index.html`

- Module-level: `finishQuiz()` POSTs to `/api/progress` (upsert)
- Course-level: `checkDone()` POSTs to `/api/completions`
- Admin view: Completions page, Dashboard learner activity table (expandable to module detail)
- Learner view: Progress page, Certificates page
- Progress persists across sessions (token-restored on page load)

### Feature 4: Certificate Generation on Course Completion
**Status: COMPLETE** in `index.html`

`showCert()` renders a styled certificate overlay with org name, learner name, course title, date, score, and cert ID. `downloadCertPDF()` uses html2canvas + jsPDF for landscape PDF export. Cert ID is stored in DB (`cert_id` column) and is verifiable via public `/api/completions/cert/:certId` endpoint.

**One edge case (see Bug #15):** If `courseComplete()` fires before the `checkDone()` completion POST has propagated (fire-and-forget race), the records fetch may return 0 passing records, silently calling `exitCourse()` instead of showing the certificate.

### Feature 5: Employee Roster + Course Assignment
**Status: PARTIAL**

- **Roster:** COMPLETE — Admin can add learners (name + password), delete learners, reset passwords. Learner list shows last login and completion count.
- **Course Assignment:** **MISSING** — All learners see all published courses. There is no mechanism to assign specific courses to specific employees, set mandatory training, add due dates, or restrict course visibility. This is a meaningful gap for a mid-market team tool where different departments need different training.

### Feature 6: Study Guide / Course Export
**Status: PARTIAL**

- `importer.html` generates a styled standalone HTML study guide + a TrainFlow-compatible quiz CSV. This feature exists but is **currently non-functional** (broken API auth).
- The main `index.html` admin can export a full JSON backup (courses + completions + brand) and a completions CSV, but there is no per-course study guide or learner-facing content export.
- The internal AI Importer in `index.html` saves directly to the database without producing a downloadable study guide.

### Cloudflare Worker: Is It Wired?
**For `index.html`:** YES. `WORKER_URL` at line 1235-1237 auto-selects `http://localhost:8787` for local or `https://trainflow-worker.theronv.workers.dev` for production. All API calls go through this URL. CORS configured in `wrangler.toml` (`ALLOWED_ORIGIN = "https://theronv.github.io"`).

**For `importer.html`:** NO. `CLAUDE_API` at line 433 is hardcoded to `https://api.anthropic.com/v1/messages`. No worker proxy. No auth.

### Post-Launch Features Accidentally Built
| Feature | Location | Status |
|---------|---------|--------|
| AI content generation | `index.html` (AI Importer page) + `importer.html` | Built — in-app version works; standalone broken |
| Manager dashboard with team progress | `index.html` `renderDash()` | Fully built — stats tiles, learner drill-down, course stats |
| Custom branding per organization | `index.html` branding page + Worker `PUT /api/brand` | Fully built |
| Slack/email reminders | — | Correctly absent |

---

## SECTION 3 — BLOCKER INVENTORY

### B1 — `importer.html`: Missing API authentication headers
**File:** `importer.html`
**Lines:** 932–940 (`generateQuestions` fetch), 1291–1298 (`generateSummary` fetch)
**Confirmed:** YES

Both fetch calls include only `'Content-Type': 'application/json'`. Missing:
- `x-api-key: <key>` — required for Anthropic API authentication
- `anthropic-version: 2023-06-01` — required header
- `anthropic-dangerous-direct-browser-access: true` — required for browser-direct CORS

Without all three, the API returns 401 (auth) or the browser blocks the request (CORS). The tool cannot generate a single question or summary.

### B2 — `importer.html`: No API key input in the UI
**File:** `importer.html`
**Lines:** 1–1343 (confirmed by full read — no input for API key anywhere)
**Confirmed:** YES

There is no `<input>` of any kind for an API key. No `localStorage` lookup. No `sessionStorage` lookup. Even if B1 (headers) were fixed to add `x-api-key`, there is no mechanism to supply the key value. The key would have to be hardcoded — which is both insecure and breaks multi-user use.

### B3 — `importer.html`: Phase 3 has no exit path on error
**File:** `importer.html`
**Lines:** 278–302 (Phase 3 HTML), 776–786 (error handling in `startGeneration`)
**Confirmed:** YES

When Pass 1 fails (`failed = true; isGenerating = false; return` at L786), the `gen-error` div becomes visible. The error message is shown. There is no Back button, no Retry button, and no other navigation element in Phase 3. The step indicator is not clickable. The user must reload the page, losing all uploaded state.

### B4 — `importer.html`: Smart quote replacement produces invalid JSON
**File:** `importer.html`
**Line:** 963
**Confirmed:** YES

```js
.replace(/[\u2018\u2019\u02BC]/g, "\\'")  // produces \' in the string
```
`\'` is not a valid JSON escape sequence. JSON only recognizes `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, `\uXXXX`. If Claude returns any curly apostrophe in question text (despite the prompt instruction), `JSON.parse()` will throw a `SyntaxError` and the module fails. `generateSummary()` at line 1317 correctly uses `"'"` (plain apostrophe) — `generateQuestions()` does not.

### B5 — `index.html`: Landing page text is factually wrong (NEW)
**File:** `index.html`
**Line:** 677
**Confirmed:** YES (new finding, not in prior review)

```html
<p class="landing-foot">All data stored locally in your browser &mdash; no account required</p>
```
This is false. The app requires a deployed Cloudflare Worker, Turso database credentials, and an admin password. A first-time user who opens the app and believes this text will be confused by every error. This is carry-over text from a previous localStorage-based prototype and must be replaced before v1.

### B6 — `index.html`: No setup guide or first-run experience (NEW)
**File:** `index.html`, `worker/wrangler.toml`
**Lines:** `index.html` L692-698, `wrangler.toml` L13-22
**Confirmed:** YES (new finding)

The Worker requires `TURSO_TOKEN`, `JWT_SECRET`, and `ADMIN_PASSWORD_HASH` to be set via `wrangler secret put` before any login works. Until `ADMIN_PASSWORD_HASH` is set, the Worker returns 503: "Admin account not initialised." The instructions are in `wrangler.toml` comments (good) but invisible to users of the app. There is no in-app setup screen, no helpful error message on first login, and no README explaining deployment. The app silently fails on first run without guidance.

---

## SECTION 4 — BUG INVENTORY

### HIGH PRIORITY — `importer.html` (all confirmed from prior review)

**H1** — "summary" chip renders green when summary generation failed
**Line:** 1031
Condition is `m.summary` (truthy object check), not `m.summary?.intro || m.summary?.bullets?.length`. The fallback sets `summary = { intro: '', bullets: [] }`, which is truthy, so the green chip renders even when no summary content exists. The content box at L1036 correctly hides itself, creating a chip that promises content that isn't there.

**H2** — `correct_index` out-of-bounds silently defaults to 'A' in CSV
**Line:** 1243
`letters[q.correct_index] || 'A'` — if Claude returns `correct_index: 4` or any value ≥ 4 (or < 0), `letters[n]` is `undefined`, fallback to 'A'. CSV marks option A as correct regardless of what Claude intended. No bounds check at normalization (L1010).

**H3** — Options array < 4 entries produces empty CSV columns
**Lines:** 1239–1242
`csvEscape(q.options[2] || '')` — if `q.options.length < 3`, the value is `undefined`, `csvEscape` converts to empty string, CSV has blank option columns. TrainFlow importer may reject or mishandle these.

**H4** — `isGenerating` not in try/finally
**Lines:** 729, 786, 830
If an unguarded DOM query (e.g., `document.getElementById('gen-progress-label')` at L769 returning null due to a future HTML change) throws between L729 and the first try/catch, `isGenerating` stays `true` permanently. The "Generate quiz questions" button remains disabled for the session.

**H5** — No "Start Over" path from Phase 4
**Lines:** 304–381 (Phase 4 HTML)
"← Edit" (L316) goes to Phase 2, not Phase 1. To add new files, the user must click "← Edit" → "← Back" (Phase 2's back button goes to Phase 1). This two-step path exists but is not obvious. No explicit "Start Over" button clears state and returns to Phase 1.

**H6** — No "Expand All" in Phase 4 accordion
**Line:** 380 (`review-modules` container)
No expand/collapse-all control. Each of 10 modules requires a manual click to review.

**H7** — Silent content truncation at 3000 / 4000 chars
**Lines:** 906, 1265
Content is sliced silently. A 10,000-word module produces questions about only the first ~600 words of content. No indicator in Phase 2 preview or anywhere.

**H8** — Empty module content proceeds to generation silently
**Line:** 582 (`if (!parsedModules.length)`)
Checks total module count, not per-module content. A file with only whitespace produces `content: ''`. Generation then asks Claude to write questions about nothing.

---

### HIGH PRIORITY — `index.html` (new findings)

**H9** — `esc()` does not escape single quotes — learner names with apostrophes break onclick attributes
**Lines:** 1336–1338 (`esc()` definition), 1967–1968 (rendered onclick attrs)

```js
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
```
`esc()` correctly escapes `"` to `&quot;` but does NOT escape `'` to `&#39;`. In the learner table at L1967-1968:
```js
onclick="App.openResetPw('${l.id}','${esc(l.name)}')"
```
A learner named `O'Brien` produces:
```html
onclick="App.openResetPw('abc123','O'Brien')"
```
This is a syntax error — the onclick attribute breaks on the apostrophe. The "Reset Password" and "Delete" buttons for that learner stop working.

**H10** — Duplicate `id="drop-zone"` — same ID on two different DOM elements
**Lines:** `index.html` L858 (importer upload zone) and L1157 (CSV import modal)
`document.getElementById('drop-zone')` returns only the first match. `App.handleDrop()` removes `drag-active` from `$$('drop-zone')` — this always targets the importer's zone, not the CSV modal's zone. During CSV imports, the drag-over state on the modal's drop zone cannot be cleared via `$$('drop-zone')`. Low-severity visual bug, but duplicate IDs are invalid HTML.

**H11** — Course completion race condition: certificate may not be shown
**Lines:** 2427–2431 (`checkDone` — fire and forget), 2433–2442 (`courseComplete`)
`checkDone()` sends the completion POST as a fire-and-forget (`.catch(e => console.error(...))` with no await). When the user clicks "Get Certificate →" immediately after the last module, `courseComplete()` fetches `GET /api/completions/me`. If the POST hasn't committed yet, the fetch returns no passing record for this course, and `courseComplete()` silently calls `exitCourse()`. The learner sees no certificate, no error, just a return to the courses list.

**H12** — No course assignment (V1 feature gap)
All learners see all published courses. No admin UI to restrict which employees are assigned to which course, no due dates, no mandatory training flags. For a mid-market team tool (50–500 staff, different departments), this is a fundamental missing feature.

---

### MEDIUM PRIORITY — `importer.html` (all confirmed from prior review)

**M1** — Model name magic string duplicated
**Lines:** 937, 1295
`'claude-sonnet-4-20250514'` appears twice, not a constant. Model version updates require two separate edits.

**M2** — `.hidden` + inline `display:flex` fragile CSS pattern
**Lines:** 192 (`#upload-actions`), 386 (`#help-modal`)
Both elements have `class="hidden"` AND `style="...display:flex"` inline. Works only because `.hidden { display: none !important }` uses `!important`. Future CSS refactoring that removes `!important` silently breaks the show/hide behavior.

**M3** — `--accent` and `--brand-1` are identical dead duplicates
**Lines:** 13 (`--accent: #2563eb`), 17 (`--brand-1: #2563eb`)
`--accent` is only referenced in `--accent-lt` and `--accent-md` definitions. `--brand-1` is used throughout the actual component CSS. `--accent` as a standalone color is dead.

**M4** — No HTML escaping in exported study guide
**Lines:** 1071 (`m.summary.intro`), 1072 (`b` bullets), 1080 (`m.title`), 1087 (`m.title`), 1095 (`c.title`), 1174 (`c.title`), 1175 (`c.description`)
All user-provided and Claude-generated strings are interpolated raw into the exported HTML. A course title like `<script>alert(1)</script>` executes in the downloaded file. Self-XSS only (the user attacks their own downloaded file), but poor practice and a bad signal for a "shippable tool."

**M5** — `mdToHtml` does not handle nested lists, blockquotes, or horizontal rules
**Lines:** 671–679
`allBullet` check requires `^[-*•] ` (no leading spaces), so `  - sub-item` falls through to `<p>`. Blockquote `>` lines become paragraph text. `---` alone renders as `<p>---</p>`.

**M6** — Help modal mentions nothing about API keys or authentication
**Lines:** 395–428
Formatting guide only. No mention of Claude API key setup, the required `x-api-key` header, or how credentials are supplied.

---

### MEDIUM PRIORITY — `index.html` (new findings)

**M7** — `saveAiCourse()` hacks the builder's hidden modal
**Lines:** 1789–1809
`saveAiCourse()` writes to `$$('cb-title')`, `$$('cb-icon')`, `$$('cb-desc')` (the course builder modal form fields) and sets `cbState.mods`, then calls `App.saveCourse()`. `saveCourse()` ends by calling `App.closeBuilder()` — which calls `$$('builder-overlay').classList.add('hidden')` on a modal that was never opened. This is harmless but represents tight coupling between two UI flows that should be separate.

**M8** — `importBackup()` creates duplicate courses silently
**Lines:** 2604–2611
On restore, each course in the backup is inserted via `POST /api/courses` with no deduplication check. Importing the same backup twice doubles all courses. No user warning.

**M9** — Landing page footer text is factually wrong
**Line:** 677
`"All data stored locally in your browser — no account required"` — this was true in a prior localStorage version. Now all data is in Turso via Worker. Must be replaced.

**M10** — `delCourse()` uses `confirm()` instead of the custom modal
**Line:** 2066
`if(!confirm('Delete this course?')) return;` — native browser dialog, inconsistent with the rest of the app which uses `confirm-delete-overlay`. Minor UX inconsistency.

**M11** — `startGeneration()` in `index.html` has no per-module partial failure handling
**Lines:** 1731–1770
Questions and summary are generated together in one loop per module. If any module's generation throws (API error, network error), the entire try/catch fires: user gets a toast and is returned to Phase 2. All already-generated modules are discarded. In contrast, `importer.html` has a two-pass system where summary failures are non-fatal. The main app is more brittle.

---

## SECTION 5 — UX FRICTION POINTS

### `importer.html` — Friction Walk

**First-time user, valid markdown file, broken API:**
1. User drops a `.md` file → file module list appears. Names editable.
2. "Configure course →" → Phase 2. Course details and quiz settings visible. Module preview works.
3. "Generate quiz questions →" → Phase 3. Progress bar at 0%. First module shows "Generating…"
4. API call returns 401. `gen-error` div appears: "Generation failed" + error message.
5. **DEAD END.** No Back button. No Retry button. Step indicator is not clickable. User must reload the page. All uploaded files, names, and configuration are gone. Start over from scratch.

**User completes generation, Phase 4, wants to add a module:**
1. In Phase 4, clicks "← Edit" → goes to Phase 2 (Configure), not Phase 1.
2. In Phase 2, clicks "← Back" → goes to Phase 1.
3. Phase 1 still shows the original file list (state not cleared). User can add a file.
4. Clicks "Configure course →" again → re-flattens all modules including the new one.
5. Goes back to Phase 2, re-generates everything from scratch.
This path works but requires discovering the two-step "← Edit → ← Back" sequence. Not intuitive.

**User tries to review all generated questions in Phase 4:**
All 10 modules are collapsed. User must click each accordion individually — 10 separate clicks. No "Expand All."

### `index.html` — Friction Walk

**First-time admin, Worker not deployed:**
1. Landing screen loads. "Manager" tile clicked.
2. Password form. Enters `admin123`. `doLogin()` fires `api('/api/auth/login', ...)`.
3. `fetch()` throws CORS or network error. `Toast.err("Failed to fetch")` appears.
4. No guidance. User doesn't know whether the password is wrong, the app is broken, or setup is needed.

**First-time admin, Worker deployed but secrets not set:**
1. Password form. `api('/api/auth/login')` returns 503.
2. Toast: "Admin account not initialised — set ADMIN_PASSWORD_HASH in Worker secrets."
3. A dev understands this. A non-dev admin is completely lost.

**Learner named `O'Brien` — admin tries to reset password:**
1. Admin opens Learners page. `O'Brien` appears in the table.
2. Rendered onclick: `App.openResetPw('abc','O'Brien')` — syntax error.
3. "Reset Password" button does nothing (JS error swallowed). No toast. User can't reset the password for that learner without a workaround.

**Learner finishes last module — certificate not shown:**
1. Learner passes last module. "Get Certificate →" button appears immediately.
2. Learner clicks. `courseComplete()` fires. `checkDone()` has already fire-and-forget POSTed completion.
3. Race: if the POST hasn't returned yet, `GET /api/completions/me` returns no passing record.
4. `courseComplete()` sees `recs.length === 0`. Calls `App.exitCourse()`. No toast. No certificate.
5. Learner is back at the courses list. "Best: X%" chip updates eventually (on next load) but the certificate moment is lost.

**Admin imports a backup file twice:**
1. Admin → Settings → Import Backup → selects same JSON file.
2. Toast: "Backup restored." All courses now exist twice in the DB.
3. No warning, no deduplication, no undo.

---

## SECTION 6 — CODE QUALITY FLAGS

### Functions over 100 lines

| Function | File | Lines | Issue |
|----------|------|-------|-------|
| `startGeneration()` | `importer.html` | L717–832 = 115 lines | Two-pass generation loop + UI updates + error handling all inline. Should be three functions. |
| `generateQuestions()` | `importer.html` | L892–1013 = 121 lines | Fetch + 3-level nested try/catch JSON fallback chain. Inner fallbacks are especially hard to reason about. |
| `exportStudyGuide()` | `importer.html` | L1063–1200 = 137 lines | Entire HTML template inlined. Extract template to a function. |
| `renderACourses()` + `renderLCourses()` | `index.html` | ~30 lines each but dense template literals | Not over 100 but the inline HTML strings are hard to maintain. |

### Hardcoded values that should be constants (`importer.html`)

| Value | Lines | Should be |
|-------|-------|-----------|
| `'claude-sonnet-4-20250514'` | 937, 1295 | `const MODEL = 'claude-sonnet-4-20250514'` |
| `3000` (question content limit) | 906 | `const CONTENT_LIMIT_Q = 3000` |
| `4000` (summary content limit) | 1265 | `const CONTENT_LIMIT_S = 4000` |
| `3000` (max_tokens for questions) | 938 | Should be same constant or separate |
| `800` (max_tokens for summaries) | 1296 | `const MAX_TOKENS_SUMMARY = 800` |

### Hardcoded values (`index.html`)

| Value | Line | Should be |
|-------|------|-----------|
| `'https://trainflow-worker.theronv.workers.dev'` | 1237 | Acceptable for now; should be documented |
| `500` as completions limit | 1931, 2563 | Named constant or URL param |

### Dead CSS variables (`importer.html`)

- `--accent: #2563eb` (L13) — Same value as `--brand-1` (L17). Only referenced indirectly via `--accent-lt` and `--accent-md`. Never used directly in component CSS. Dead.

### Fragile CSS patterns (`importer.html`)

- `#upload-actions` (L192): `class="hidden"` + `style="display:flex"` simultaneously. Works only because `.hidden { display: none !important }`. Remove the inline style; use a dedicated "show" class.
- `#help-modal` (L386): Same pattern.

### `innerHTML` assignments without escaping

**`importer.html`** — intentional (renders as HTML) but unescaped:
- L640–642: `parse-status` innerHTML — no user data, safe.
- L698: `m.content` — result of `mdToHtml()`, intended as HTML. XSS risk if markdown contains `<script>` tags.
- L1071: `m.summary.intro` — Claude-generated, not escaped.
- L1072: `b` (bullet) — Claude-generated, not escaped.
- L1080, L1087: `m.title` — user-entered title, NOT escaped in study guide export.
- L1095, L1174, L1175: `c.title`, `c.description` — user-entered, NOT escaped in study guide export.

**`index.html`** — intentional:
- L2296–2303: `mod.content` rendered directly in `loadMod()`. Content is stored HTML from DB. Admin-authored, acceptable attack surface for internal tool.
- L1710: `m.content` in module preview — from `mdToHtml()`, same XSS caveat.
- L1795: `esc(m.summary.intro)` and `esc(b)` — CORRECTLY escaped here (good pattern to note).

---

## SECTION 7 — DEPLOYMENT MODEL DECISION

### Current State

**`index.html`** → `WORKER_URL` → Worker → Turso
The Worker is the single trust boundary. Secrets (TURSO_TOKEN, JWT_SECRET, ADMIN_PASSWORD_HASH, GEMINI_API_KEY) never touch the browser. CORS locked to `ALLOWED_ORIGIN = "https://theronv.github.io"` in production.

**`importer.html`** → `CLAUDE_API = 'https://api.anthropic.com/v1/messages'` → Anthropic directly
No Worker involvement. Missing all auth headers. Will never work as written.

### What Must Be Decided Before v1

**Decision 1: How does `importer.html` get API credentials?**

Two architectures:

*Option A — Route through the Worker (recommended)*
The Worker already has `/api/ai/generate` using Gemini. Either:
- Add a parallel endpoint `/api/ai/claude` that uses a `CLAUDE_API_KEY` secret
- OR change `importer.html` to call the existing Worker endpoint (requires admin JWT)

Pros: No key in browser. Consistent with main app architecture.
Cons: `importer.html` is currently a standalone tool (no login). Routing through Worker requires admin auth, which requires the Worker to be deployed.

*Option B — API key input field in `importer.html`*
Add a key input in Phase 1. Store in `sessionStorage`. Pass as `x-api-key` header.

Pros: Truly standalone — works without Worker deployment.
Cons: API key visible in browser dev tools and network inspector. Less professional for a v1 product.

**Decision 2: Is `importer.html` a product feature or a dev tool?**

The main app (`index.html`) already has a working AI Importer page (4-phase wizard, saves to DB via Gemini). The standalone `importer.html` serves a different use case: **generating files for teams that don't have the full TrainFlow deployment** (CSV for import + study guide HTML for distribution).

If `importer.html` is a **product feature**: fix auth, add API key UI or Worker proxy, link from main app.
If `importer.html` is a **dev tool**: acceptable to have rough edges, but broken auth still makes it useless.

**Decision 3: ALLOWED_ORIGIN**

`wrangler.toml` sets `ALLOWED_ORIGIN = "https://theronv.github.io"`. If the app is deployed to any other domain, all browser API calls fail with CORS errors. This must be updated before deploying to a customer-facing domain.

**Decision 4: `importer.html` uses Claude; main app uses Gemini — intentional?**

The Worker's `/api/ai/generate` calls Gemini 2.5 Flash. The `importer.html` references `claude-sonnet-4-20250514`. These are different models with different cost/quality profiles. The commit history suggests a migration from Gemini to Claude that was half-finished. Pick one model (or make it configurable) and standardize.

---

## SECTION 8 — PRIORITY ORDER

| # | Priority | Item | File |
|---|----------|------|------|
| 1 | **BLOCKER** | `importer.html` API calls have no auth headers — tool is completely non-functional | `importer.html` L932-940, L1291-1298 |
| 2 | **BLOCKER** | `importer.html` has no API key input — no way to supply credentials | `importer.html` (no such field exists) |
| 3 | **BLOCKER** | `importer.html` Phase 3 has no back/retry on error — user is permanently stuck | `importer.html` Phase 3 HTML L278-302 |
| 4 | **BLOCKER** | `importer.html` smart quote replacement writes invalid JSON (`\\'`) | `importer.html` L963 |
| 5 | **BLOCKER** | `index.html` landing page falsely claims "no account required / local storage" | `index.html` L677 |
| 6 | **HIGH** | `index.html` learner names with apostrophes break onclick attrs (`esc()` missing `'` → `&#39;`) | `index.html` L1336-1338, L1967-1968 |
| 7 | **HIGH** | `index.html` duplicate `id="drop-zone"` — two elements, wrong targeting | `index.html` L858, L1157 |
| 8 | **HIGH** | `index.html` course completion race condition — certificate may silently not appear | `index.html` L2427-2442 |
| 9 | **HIGH** | `index.html` missing course assignment feature — all learners see all courses | `index.html` (feature absent) |
| 10 | **HIGH** | `importer.html` "summary" chip renders green when summary failed (truthy empty object) | `importer.html` L1031 |
| 11 | **HIGH** | `importer.html` `correct_index` out-of-bounds silently defaults to 'A' in CSV | `importer.html` L1243 |
| 12 | **HIGH** | `importer.html` `isGenerating` not in try/finally — button permanently disabled on uncaught exception | `importer.html` L717-832 |
| 13 | **HIGH** | `importer.html` no "Start Over" from Phase 4 | `importer.html` Phase 4 HTML |
| 14 | **MEDIUM** | `index.html` `importBackup()` creates duplicate courses silently | `index.html` L2604-2611 |
| 15 | **MEDIUM** | `importer.html` no "Expand All" in Phase 4 accordion | `importer.html` L380 |
| 16 | **MEDIUM** | `importer.html` silent content truncation at 3000/4000 chars with no user warning | `importer.html` L906, L1265 |
| 17 | **MEDIUM** | `importer.html` empty module content proceeds to generation silently | `importer.html` L582 |
| 18 | **MEDIUM** | `index.html` `delCourse()` uses native `confirm()` — inconsistent UX | `index.html` L2066 |
| 19 | **MEDIUM** | `importer.html` model name duplicated magic string (not a constant) | `importer.html` L937, L1295 |
| 20 | **LOW** | `importer.html` no HTML escaping in exported study guide (self-XSS) | `importer.html` L1071-1175 |
| 21 | **LOW** | `importer.html` `mdToHtml` no nested lists, blockquotes, horizontal rules | `importer.html` L671-679 |
| 22 | **LOW** | `importer.html` dead `--accent` CSS variable | `importer.html` L13 |
| 23 | **LOW** | `importer.html` fragile `.hidden` + inline `display:flex` CSS | `importer.html` L192, L386 |
| 24 | **LOW** | `importer.html` help modal says nothing about API keys | `importer.html` L395-428 |

---

## SECTION 9 — VERDICT

The system is meaningfully more complete than the standalone `importer.html` audit suggested. The main `index.html` app is a well-structured, fully-wired product: a real Cloudflare Worker handles auth and data persistence, a Turso database stores everything, Gemini AI generation works through the Worker's `/api/ai/generate` endpoint, certificate generation and PDF export work, the quiz engine is solid, and the admin dashboard has genuine team-visibility features. Most V1 features exist and function. The two concrete gaps are: **(1)** course assignment per learner (all employees see all courses — a meaningful product miss), and **(2)** the false landing page text that will confuse every first-time user.

The standalone `importer.html` is a completely separate concern. It is entirely non-functional due to missing API authentication, and fixing it requires an architectural decision (Worker proxy vs. client-side key input) that hasn't been made. Crucially, the main app already contains an equivalent AI Importer page that works — so `importer.html`'s brokenness doesn't block the core product.

**The single most important fix** is to decide the fate of `importer.html`: either route its API calls through the Worker (which means choosing Claude vs. Gemini and adding a Worker endpoint), or add an API key input field for standalone use. Until that decision is made, `importer.html` cannot be fixed. The main app needs roughly one focused day of work — course assignment UI, the apostrophe escaping bug, the false landing text, the duplicate drop-zone ID, and the certificate race condition — to be v1-ready for an internal pilot.

---

## P2 — Blockers Fixed
**Date:** 2026-03-13
**Scope:** `importer.html` only

**Deployment decision made:** Direct browser auth model (Option B from Section 7). API key entered by user in Phase 1, stored in `sessionStorage('trainflow_api_key')`, passed as `x-api-key` header on every Anthropic fetch call.

### B1 — API key UI ✓ resolved
Added a password `<input>` card at the top of Phase 1 (before the drop zone). Label: "Anthropic API Key". Placeholder: `sk-ant-...`. Validates on input: must start with `sk-ant-` and be >20 chars. Shows green "✓ Key saved" indicator when valid. Stored in `sessionStorage`. Restored from sessionStorage on `DOMContentLoaded` (refresh-safe within session). Help modal updated with a dedicated "API key setup" section explaining where to get a key and confirming it is never sent anywhere except Anthropic's API.

### B2 — Auth headers on all fetch calls ✓ resolved
Both fetch calls (`generateQuestions` L978–993, `generateSummary` L1365–1380) now include all four required headers:
- `x-api-key`: pulled from `sessionStorage.getItem('trainflow_api_key')`
- `anthropic-version: 2023-06-01`
- `anthropic-dangerous-direct-browser-access: true`
- `Content-Type: application/json`

`startGeneration()` validates the key before setting `isGenerating = true` — if missing or malformed, aborts with a toast and navigates back to Phase 1.

### B3 — Phase 3 exit path on error ✓ resolved
The `gen-error` div now contains two recovery buttons inside `flex` row below the error message:
- **← Back to Configure** — resets `isGenerating = false` and calls `goPhase(2)`
- **Try Again** — resets `isGenerating = false` and calls `startGeneration()`

`isGenerating` is now reset by the `finally` block in `startGeneration()` (see B6), so both buttons correctly re-enable generation.

### B4 — Smart quote JSON escape bug ✓ resolved
Fixed `generateQuestions` L1013: `.replace(/[\u2018\u2019\u02BC]/g, "\\'")` → `.replace(/[\u2018\u2019\u02BC]/g, "'")`. Both `generateQuestions` and `generateSummary` now use identical smart-quote handling (plain apostrophe replacement). The invalid `\'` JSON escape sequence is gone.

### B5 — Model name constant ✓ resolved
Added three constants after `CLAUDE_API`:
```js
const MODEL = 'claude-sonnet-4-20250514';
const CHAR_LIMIT_QUESTIONS = 3000;
const CHAR_LIMIT_SUMMARY = 4000;
```
All hardcoded instances replaced:
- `slice(0, 3000)` in `generateQuestions` → `slice(0, CHAR_LIMIT_QUESTIONS)`
- `model: 'claude-sonnet-4-20250514'` in both fetches → `model: MODEL`
- `max_tokens: 3000` in `generateQuestions` fetch → `max_tokens: CHAR_LIMIT_QUESTIONS`
- `slice(0, 4000)` in `generateSummary` → `slice(0, CHAR_LIMIT_SUMMARY)`

### B6 — isGenerating safety ✓ resolved
`startGeneration()` body (from `isGenerating = true` through `goPhase(4)`) is now wrapped in `try { ... } finally { isGenerating = false; }`. The explicit `isGenerating = false` lines inside the function body have been removed (handled by `finally`). The `if (failed) { isGenerating = false; return; }` pattern simplified to `if (failed) { return; }` — `finally` resets the flag on any exit path including uncaught exceptions.

### New issues discovered during this pass
None. All six blockers resolved cleanly. No regressions observed.

---

## P3 — Data Integrity Fixes
**Date:** 2026-03-13
**Scope:** `importer.html` only — HIGH priority bugs from Section 4

### H8 — Empty module content proceeds silently ✓ resolved
Added `#empty-mod-warning` banner to Phase 2 HTML (below module-preview). In `startGeneration(skipEmpty = false)`, before any API call: filter parsedModules for `wordCount(m.content) === 0`, list offending module names in the banner, and return early. Banner has two buttons: "← Fix modules" (dismisses) and "Generate anyway" (`startGeneration(true)`). User always has the choice; nothing is silently blocked.

### H7 — Silent content truncation ✓ resolved
Added `rawTextLength()` helper that strips HTML tags before measuring chars. Three-layer warning:
1. **Phase 2 module preview chip**: amber "⚠ long" chip on each mod-card header where `rawTextLength > CHAR_LIMIT_QUESTIONS` (3,000 chars), with tooltip explaining truncation.
2. **Phase 2 global banner** (`#truncation-banner`): populated in `populateConfigurePhase()` — lists count of modules that will be truncated with advice to split.
3. **Phase 3 progress row**: amber "⚠ long content" chip injected into each truncated module's row at generation time via `truncFlags` array.

### H1 — Summary chip renders green when summary failed ✓ resolved
`renderReview()` chip condition changed from `m.summary` (truthy on empty object) to:
- Green "summary" chip: only when `m.summary?.intro || m.summary?.bullets?.length > 0`
- Grey "summary failed" chip: when `m.summary?.failed === true`
- No chip: when `m.summary` is null

### H2 — `correct_index` out of bounds silently defaults to 'A' ✓ resolved
In `generateQuestions()` normalization: `rawIdx` is computed, `clampedIdx = Math.max(0, Math.min(3, rawIdx))`. If they differ, `console.warn(...)` logs the out-of-bounds value and question text. `_oob: true` flag is stored on the question object. In `exportCSV()`: `q._oob ? 'REVIEW' : letters[q.correct_index]` — out-of-bounds questions get `REVIEW` in the correct-answer column instead of silently defaulting to 'A'.

### H3 — Options array shorter than 4 produces empty CSV columns ✓ resolved
In `exportCSV()`: each option column now uses `q.options[n] !== undefined ? csvEscape(q.options[n]) : '—'`. An em-dash makes missing options visually distinct from legitimately empty strings in the importer.

### H4 — `isGenerating` not in try/finally ✓ resolved (P2)
Already fixed in P2 via `try { ... } finally { isGenerating = false; }`.

### H5 — No "Start Over" from Phase 4 ⚠ not addressed
Deferred. The two-step "← Edit → ← Back" path exists and works. Fixing requires adding a "Start Over" button that clears all state.

### H6 — No "Expand All" in Phase 4 accordion ⚠ not addressed
Deferred. MEDIUM priority; cosmetic UX polish.

### Bug 6 (P3) — Summary failures show orange dot and failed chip ✓ resolved
Summary `catch` block now:
- Stores `{ intro: '', bullets: [], failed: true }` on `generatedModules[i].summary`
- Sets `dotEl.style.background = 'var(--warn)'` (orange, not green)
- Sets status text to `⚠ Summary failed`
- Green dot is reserved for successful completion only

### Bug 7 (P3) — 401 errors surface with specific message and Phase 1 path ✓ resolved
Both `generateQuestions` and `generateSummary` fetch calls now throw `Error` with `.status = response.status` attached. 401-specific message: `"API key rejected (401). Check your key in Phase 1 and try again."` On 401:
- `genErrorIs401 = true` is set
- `sessionStorage` key is cleared; green "✓ Key saved" indicator is hidden
- `gen-error-back` button text changes to "← Fix API Key (Phase 1)"
- `genErrorBack()` function navigates to Phase 1 (not Phase 2) when `genErrorIs401` is true
- 401 during summary pass is treated as fatal (exits generation entirely)
- `genErrorIs401` is reset to `false` at the start of each new `startGeneration()` call

### New issues discovered during this pass
None. The `_oob` flag on question objects will be serialized into `generatedCourse` JSON if the user ever adds a JSON export. Harmless for now but worth cleaning up if a full JSON export is added.

---

## P4 — UX Fixes (2026-03-13)

All 7 UX items from Prompt 4 addressed. Items H4 and H5 from the P3 deferred list are now resolved.

### UX Fix 1 — ↺ Start Over button ✓ resolved
- `<button id="btn-start-over">` added to topbar `.topbar-right`; starts hidden
- `startOver()` shows a `confirm()` dialog then resets `fileModules`, `parsedModules`, `generatedCourse`, `isGenerating`, and all form fields (course title/icon/desc, paste area) before calling `goPhase(1)`
- API key in sessionStorage is intentionally preserved — user should not have to re-enter it after starting over
- `goPhase()` already toggled visibility: hidden in Phase 1, visible in Phases 2–4

### UX Fix 2 — Expand all / Collapse all ✓ resolved
- `let reviewExpanded = false` added to top-level state
- `toggleExpandAll()` flips `reviewExpanded`, bulk-toggles `.open` on all `[id^="review-body-"]` elements, and updates button label
- `renderReview()` injects `<button id="btn-expand-all">` in the Review modules header row
- `goPhase(4)` resets `reviewExpanded = false` and resets button text to `'Expand all'` on each Phase 4 entry

### UX Fix 3 — ← Back to Files in Phase 4 ✓ resolved
- Success bar now has two ghost buttons: `← Back to Files` (calls `goPhase(1)`) and `← Edit Settings` (calls `goPhase(2)`)
- Replaces single "← Edit" button; both sit in a flex row at `margin-left:auto`

### UX Fix 4 — Help modal privacy note ✓ resolved
- Added sentence: "It will be cleared when you close your browser tab." to the `sessionStorage` privacy note in the help modal

### UX Fix 5 — Step indicator ✓ checkmarks ✓ resolved (prior session)
- `goPhase()` sets `.done` class and `✓` on completed steps, `.active` on current step

### UX Fix 6 — Phase 3 elapsed timer ✓ resolved
- `<span id="gen-elapsed">` added inline with `#gen-pass-sub` in the Phase 3 card
- `setInterval` timer starts immediately after `goPhase(3)`, updates every second: `Xs elapsed` or `Xm Ys elapsed`
- `clearInterval` called in the `finally` block; timer text cleared on completion

### UX Fix 7 — Phase 1 empty state hint panel ✓ resolved
- Three-column hint grid (`id="upload-hint"`) added above the drop zone in Phase 1 HTML
- Shows three steps: "1. Upload files", "2. Configure & generate", "3. Export"
- Hidden by `renderFileModuleList()` as soon as the first file is added (via `hintEl.classList.add('hidden')`)
- Shown again by `startOver()` → `renderFileModuleList()` when state is cleared

### Deferred items
None remaining from P4. The H4/H5 items from P3 are now both resolved (Start Over = UX Fix 1, Expand All = UX Fix 2).

---

## P5 — Visual Polish & Code Quality (2026-03-13)

### Quality Fix 1 — Dead `--accent` CSS variable ✓ resolved
- Removed `--accent: #2563eb` from `:root` (was identical to `--brand-1`)
- `--accent-lt` and `--accent-md` retained (lighter tints used in chips and status bars)
- Replaced 2 direct `var(--accent)` uses: `.chip-blue { color }` and `.spinner { border-top-color }` → both now use `var(--brand-1)`
- **M3 from Section 5 / Issue #22 from tracker: ✓ resolved**

### Quality Fix 2 — `.hidden` + inline `display:flex` fragile CSS pattern ✓ resolved
- Added dedicated show classes: `.upload-actions-visible { display:flex }`, `.modal-visible { display:flex }`, `.api-key-status-visible { display:flex }`
- Removed inline `display:flex` from `#upload-actions`, `#help-modal`, `#api-key-status`
- JS now calls `classList.add/remove('upload-actions-visible')` alongside the hidden toggle
- Added `showApiKeyStatus()` and `hideApiKeyStatus()` helpers used everywhere the status is shown/hidden
- **Decision:** `.hidden { display:none !important }` — the `!important` is **retained** intentionally. Several elements use both `.status-bar` (which has `display:flex` via a class rule) and `.hidden` simultaneously; removing `!important` would let the class rule win and make those elements unhideable without restructuring all toggle sites. The fragile pattern is eliminated for the three specific elements.
- **M2 from Section 5 / Issue tracker: ✓ resolved (pattern fixed; !important retention documented)**

### Quality Fix 3 — HTML escaping in study guide export ✓ resolved
- `exportStudyGuide()` now applies `esc()` to: `c.title` (title tag + cover), `c.description`, `m.title` (h2 + TOC), `m.summary.intro`, each `bullet` string
- `m.content` is **intentionally left unescaped** — it is the output of `mdToHtml()`, a controlled HTML serializer, not raw user string input
- `esc()` was already defined globally (the same function used throughout the importer); no new helper added
- **M4 from Section 5 / Issue tracker: ✓ resolved**

### Quality Fix 4 — `mdToHtml` improvements ✓ resolved
Three new Markdown patterns added:
- **Blockquotes:** `> text` → `<blockquote style="border-left:3px solid var(--brand-1)...">` using a `.replace(/^> ?(.+)$/gm, ...)` pass before block splitting
- **Horizontal rules:** lines that are exactly `---` or more dashes → `<hr style="border:none;border-top:1px solid var(--rule)...">` via `.replace(/^-{3,}\s*$/gm, ...)`
- **Nested lists:** bullet lines with 2–4 leading spaces or a tab are wrapped in `<ul class="nested">` inside the parent list; handled during the block-level bullet pass
- Both `<hr>` and `<blockquote>` are added to the "pass-through" guard in the block splitter so they aren't re-wrapped in `<p>` tags
- **M5 from Section 5 / Issue tracker: ✓ resolved**

### Polish 1 — Phase 3 error state visual ✓ resolved
- `.status-bar.error` CSS updated to add `border-left: 4px solid var(--fail)` — gives the error card a strong red left accent that distinguishes it from the info bar
- The ⚠ icon was already present in HTML; error message text already surfaces `err.message` directly (specific, not generic)
- Back and Try Again buttons already use `.btn` classes consistently

### Polish 2 — API key input styling ✓ resolved
- Lock icon 🔒 added to the label: `🔒 Anthropic API Key`
- `#api-key-status` now uses `.api-key-status-visible` class (fade-in via CSS `transition: opacity 0.25s`)
- Invalid input (non-empty, doesn't start with `sk-ant-`) triggers: CSS shake animation + red helper text `"Key must start with sk-ant-"` shown in `#api-key-invalid-msg`
- Shake implemented as a CSS `@keyframes shake` animation added to input via `.shake` class; reflow trick used to allow re-triggering
- API key card given `border-bottom: 2px solid var(--rule-2)` to visually separate it from the file upload section below

### Polish 3 — Progress dots 5 states ✓ resolved
Five CSS classes added for dot states:
| Class | Color | Animation | Meaning |
|-------|-------|-----------|---------|
| `gen-dot-pending` | `var(--ink-4)` grey | `dotPulse` breathing | Waiting to start |
| `gen-dot-active` | `var(--brand-1)` blue | `spin` rotating ring | Currently generating |
| `gen-dot-done` | `var(--pass)` green | none | Both passes complete |
| `gen-dot-partial` | `var(--warn)` amber | none | Questions OK, summary failed |
| `gen-dot-fail` | `var(--fail)` red | none | Questions failed (fatal) |

- `setDotState(el, state)` helper added — removes all state classes, clears any inline background, adds the new class
- All `dotEl.style.background = ...` calls replaced with `setDotState(dotEl, state)` calls
- A static legend appended after the module rows: `● pending  ● generating  ● complete  ⚠ partial  ✕ failed` (using static colors, not animated, for legibility)
- Initial row HTML uses `class="gen-dot gen-dot-pending"` so dots pulse immediately on Phase 3 load

### Polish 4 — Phase 4 accordion chips ✓ resolved
- `renderReview()` now computes `wasTruncated = rawTextLength(m.content) > CHAR_LIMIT_QUESTIONS` per module
- Truncated modules show `⚠ truncated` chip (amber) in the collapsed header with tooltip text
- Summary chip logic cleaned up: always shows either `summary` (green) or `no summary` (gray) — no ambiguous empty state
- All chips visible in the collapsed mod-head; no expansion needed to read module status

### Remaining items from Section 6
| Issue | Status |
|-------|--------|
| M1 — Model name magic string | ✓ Resolved in P2 (`const MODEL = ...`) |
| M2 — `.hidden` + inline display | ✓ Resolved P5 |
| M3 — Dead `--accent` variable | ✓ Resolved P5 |
| M4 — No escaping in study guide export | ✓ Resolved P5 |
| M5 — mdToHtml gaps | ✓ Resolved P5 |
| M6 — Help modal missing API key info | ✓ Resolved in P2 (API key section added to modal) |
| M7–M11 — `index.html` issues | ⚠ Out of scope for importer.html pass |

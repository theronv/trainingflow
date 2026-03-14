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

# TrainFlow

> A modern, lightweight Learning Management System (LMS) for professional teams — AI-assisted course creation, role-based access, targeted assignments, progress tracking, and verifiable certifications.

## Live App
[https://theronv.github.io/trainingflow/](https://theronv.github.io/trainingflow/)

---

## What It Does

TrainFlow is a full-stack LMS designed for professional environments where rapid deployment and verifiable compliance matter. It covers the entire training lifecycle — from AI-assisted content ingestion to learner certification — with three distinct role-based portals.

**Admins** manage the entire platform: create and organise courses into sections, import content via AI, manage all users and teams, configure branding, and export compliance data.

**Managers** oversee their assigned team: track completion rates, assign courses with optional due dates, import learners in bulk via CSV, and reset passwords.

**Learners** work through assigned courses module by module, receive real-time quiz feedback, and generate downloadable PDF certificates on passing.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Vanilla JavaScript (ES6+), HTML5, CSS3 |
| Edge Worker | [Hono](https://hono.dev/) v4.7.0 on Cloudflare Workers |
| Database | Turso (libSQL / SQLite-compatible) via `@libsql/client` v0.14.0 |
| Deployment | Wrangler v4.75.0, GitHub Pages (frontend) |
| AI — Primary | Anthropic Claude API (`claude-sonnet-4-6`) — direct browser calls |
| AI — Fallback | Google Gemini 1.5 Flash — direct browser calls |
| PDF Generation | `jsPDF` + `html2canvas` (client-side) |
| Auth | JWT + PBKDF2-SHA256 password hashing (100k iterations) |

---

## Architecture

```mermaid
graph TD
    UI[index.html / css/style.css] --> JS[JS Modules / js/]
    JS --> Worker[Cloudflare Worker — Hono API]
    Worker --> Auth[JWT / PBKDF2]
    Worker --> DB[(Turso / libSQL)]
    JS --> Claude[Anthropic Claude API — AI Importer]
    JS --> Gemini[Google Gemini API — AI Importer fallback]
    JS --> PDF[jsPDF / html2canvas — client PDF]
```

The frontend is a Single Page Application served from GitHub Pages. All API calls route through a Hono worker on Cloudflare Workers. AI content generation is called **directly from the browser** (Claude → Gemini fallback) with API keys stored in `localStorage`. The database is Turso (globally distributed libSQL). All DB writes to Turso are sent as a single `db.batch()` request to avoid per-statement HTTP round-trips and Worker timeout limits.

---

## Project Structure

```
index.html          # Single-page app shell — all screens, modals, overlays
css/
└── style.css       # Full design system — tokens, components, dark/light themes
js/
├── core.js         # Global state, API helpers, applyBrand(), config constants
├── auth.js         # Login/register flows for all three roles
├── admin.js        # Admin portal — courses, users, teams, branding, importer
├── manager.js      # Manager portal — team, assignments, CSV import
├── learner.js      # Learner portal — course player, quiz engine, certificates
├── builder.js      # Course builder — module/question editor
└── app.js          # AppProxy — wires HTML onclick attributes to JS; theme toggle
worker/
├── index.js        # All Hono API routes and DB logic
├── seed-demo.mjs   # Demo data seed script (teams, learners, completions)
└── wrangler.toml   # Cloudflare Worker configuration
docs/
└── kb-scraper-integration.md  # Plan for KB scraper → AI Importer integration
schema.sql          # Initial database schema (run once against Turso)
```

---

## Features

### Admin Portal
- **Dashboard** — global stats: total learners, completions this month, pass rate, overdue count; recent activity table; trouble-spot reporting (courses with highest failure rates)
- **Course Management** — create, edit, delete courses; assign courses to sections; emoji icons per course
- **Course Sections** — group courses into named sections for organised browsing across all portals
- **AI Content Importer** — upload Markdown files, configure generation settings (question count, difficulty, focus), generate module summaries + multiple-choice quizzes via Claude/Gemini with full review step before saving; 30s timeout guard prevents silent hang on save
- **Course Builder** — manual course creation with rich module/question editor; learning objectives per module; pre-save validation
- **Users** — unified view of all managers and learners; add, edit, delete, move between teams; bulk actions; search/filter; password reset
- **Team Management** — create teams, add managers, generate invite codes for manager self-registration; sidebar list with member counts
- **Completions** — paginated completion log with course, score, pass/fail, date; CSV export
- **Branding** — live-preview org name, logo (URL or file upload), primary/secondary/accent colour pickers, pass threshold; changes propagate instantly across all portals; section headers and status chips reflect accent colour
- **Settings** — admin password change, data backup export/import

### Manager Portal
- **Dashboard** — team-scoped stats: assignment count, completion count, pass rate, overdue assignments; recent activity table
- **Courses** — browse all courses grouped by section; assign to entire team or individual learners with optional due date
- **Team** — view members with completion counts and overdue flags; reset member passwords
- **CSV Bulk Import** — upload a CSV to create multiple learners at once; downloadable template; validation preview before import
- **Completions** — team-scoped completion records

### Learner Portal
- **Course Catalogue** — courses grouped by section; "In Progress" chip on started courses
- **Course Player** — module-by-module content with progress restored between sessions
- **Quiz Engine** — per-question feedback (correct/incorrect highlight), correct answer revealed, explanation shown; score summary with pass/fail result; retry support; sidebar locked during active quiz
- **Certificates** — branded PDF certificates generated client-side on pass; unique verifiable cert ID (format: `TF-XXXXXXXX`)
- **Progress** — assignment list with due dates and completion status

### Platform-Wide
- **Light / Dark theme toggle** — persistent via localStorage, applies instantly across all screens; no flash on load
- **Role-Based Access Control** — separate JWT tokens per role; server-side enforcement on all routes; 10-attempt/min rate limiting on all login endpoints
- **Brandable UI** — all CSS brand tokens (`--brand`, `--brand-dark`, `--brand-glow`, `--shadow-brand`) update live from the Admin panel and persist across reloads
- **Session safety** — JWT expiry warning shown 5 minutes before expiry; global course state cleared on logout; 401 responses redirect to landing immediately

---

## Getting Started

### Prerequisites
- Node.js v18+
- Wrangler CLI: `npm install -g wrangler`
- A [Turso](https://turso.tech/) account and database

### Installation

```bash
git clone https://github.com/theronv/trainingflow.git
cd trainingflow/worker
npm install
```

### Environment Variables

Set the following as Wrangler secrets (production) or in `worker/.dev.vars` (local dev):

```bash
TURSO_URL="libsql://your-db-name.turso.io"
TURSO_TOKEN="your-turso-token"
JWT_SECRET="a-long-random-secret-32-chars-min"
ADMIN_PASSWORD_HASH="pbkdf2v1:salt:hash"   # generate: node scripts/hash-password.mjs <password>
GEMINI_API_KEY="AIza..."                    # optional — used as AI Importer fallback in worker
```

> Claude and Gemini API keys for the AI Importer are entered per-session in Admin → AI Importer and stored in `localStorage` — they are never sent to the Worker.

### Running Locally

```bash
# Terminal 1 — start the worker
cd worker && npm run dev

# Terminal 2 — serve the frontend (any static server)
npx serve .
```

Open `http://localhost:3000`. The worker runs at `http://localhost:8787`.

### Deployment

1. **Database** — `turso db shell <db-name> < schema.sql`
2. **Worker** — `cd worker && npx wrangler deploy`
3. **Frontend** — push to GitHub; GitHub Pages serves `index.html` from the repo root

### Demo Data Seeding

To populate the database with realistic demo data (teams, managers, learners, completions backdated over 5 weeks):

```bash
cd worker

# Seed production (preserves existing courses)
export TURSO_URL=libsql://your-db.turso.io
export TURSO_TOKEN=$(turso db tokens create <db-name>)
node seed-demo.mjs --prod --reset

# Seed using your own existing courses (skip the 4 built-in demo courses)
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

| Table | Purpose |
|---|---|
| `users` | All learners and managers (role, team, hashed password) |
| `teams` | Organisational units |
| `courses` | Course metadata (title, icon, description) |
| `modules` | Course content sections (ordered, rich text, summary, learning objectives) |
| `questions` | Multiple-choice quiz questions per module |
| `assignments` | Links learners to courses, optional due date |
| `completions` | Pass/fail records with score, cert ID, timestamp |
| `module_progress` | Per-learner, per-module progress (for resume) |
| `question_responses` | Per-question answer tracking per completion |
| `brand` | Org branding settings (name, logo, colors, pass threshold) |
| `invite_codes` | Manager invite codes (team-scoped, single-use, optional expiry) |
| `tags` | Tag definitions (system stubbed — not yet in UI) |
| `learner_tags` | Tag assignment to learners |
| `tag_assignments` | Tag assignment to courses |
| `admin` | Admin credentials (PBKDF2 hash) |

---

## API Reference

| Method | Route | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | — | Admin login → JWT |
| `POST` | `/api/auth/manager/login` | — | Manager login → JWT |
| `POST` | `/api/auth/manager/register` | — | Manager registration with invite code |
| `POST` | `/api/learners/login` | — | Learner login → JWT |
| `GET` | `/api/brand` | — | Get org branding |
| `PUT` | `/api/brand` | Admin | Update org branding |
| `GET` | `/api/courses` | Any | List all courses |
| `POST` | `/api/courses` | Admin | Create a course (batch insert via Turso `db.batch()`) |
| `GET` | `/api/courses/:id` | Any | Get course with modules + questions |
| `PATCH` | `/api/courses/:id` | Admin | Update course metadata |
| `PUT` | `/api/courses/:id` | Admin | Full course replace (modules + questions) |
| `DELETE` | `/api/courses/:id` | Admin | Delete course (cascades to modules, questions) |
| `GET` | `/api/sections` | Any | List all sections |
| `POST` | `/api/sections` | Admin | Create a section |
| `PATCH` | `/api/sections/:id` | Admin | Rename a section |
| `DELETE` | `/api/sections/:id` | Admin | Delete a section |
| `GET` | `/api/learners` | Admin/Manager | List learners (filterable by team) |
| `POST` | `/api/learners` | Admin/Manager | Create a learner |
| `POST` | `/api/learners/bulk` | Admin/Manager | Bulk create from CSV |
| `PATCH` | `/api/learners/:id` | Admin | Edit learner |
| `DELETE` | `/api/learners/:id` | Admin | Delete learner |
| `GET` | `/api/learners/me` | Learner | Get own profile |
| `PUT` | `/api/learners/:id/password` | Admin/Manager | Reset learner password |
| `PATCH` | `/api/learners/me` | Learner | Update own name/password |
| `PATCH` | `/api/managers/me` | Manager | Update own name/password |
| `GET` | `/api/admin/stats` | Admin/Manager | Platform/team statistics |
| `GET` | `/api/admin/teams` | Admin/Manager | List teams with member counts |
| `POST` | `/api/admin/teams` | Admin | Create a team |
| `PATCH` | `/api/admin/teams/:id` | Admin | Rename a team |
| `DELETE` | `/api/admin/teams/:id` | Admin | Delete a team |
| `PATCH` | `/api/admin/learners/:lid/team` | Admin | Move learner to another team |
| `PUT` | `/api/admin/password` | Admin | Change admin password |
| `GET` | `/api/admin/invites` | Admin | List invite codes |
| `POST` | `/api/admin/invites` | Admin | Generate an invite code |
| `DELETE` | `/api/admin/invites/:id` | Admin | Revoke an invite code |
| `GET` | `/api/admin/completions` | Admin/Manager | Completion log (filterable) |
| `DELETE` | `/api/completions` | Admin | Clear all completion records |
| `GET` | `/api/admin/trouble-spots` | Admin/Manager | Courses with highest failure rates |
| `POST` | `/api/admin/backup/restore` | Admin | Import courses from JSON backup |
| `GET` | `/api/assignments` | Admin/Manager | List assignments |
| `GET` | `/api/assignments/me` | Learner | Own assignments with status |
| `POST` | `/api/assignments` | Admin/Manager | Assign a course to a learner |
| `DELETE` | `/api/assignments` | Admin/Manager | Remove an assignment |
| `GET` | `/api/completions/me` | Learner | Own completion records |
| `POST` | `/api/completions` | Learner | Submit a course completion |
| `GET` | `/api/progress/me` | Learner | Own module progress |
| `POST` | `/api/progress` | Learner | Save module progress |
| `DELETE` | `/api/progress/:course_id` | Learner | Clear progress for a course |
| `GET` | `/api/admin/tags` | Admin/Manager | List tags |
| `POST` | `/api/admin/tags` | Admin | Create a tag |
| `DELETE` | `/api/admin/tags/:id` | Admin | Delete a tag |

---

## Design System

**Theme:** Light mode default with dark mode toggle. Inspired by Linear, Vercel, and Rippling.

**Fonts:**
- UI & Body: Inter (300, 400, 500, 600) via Google Fonts
- Monospace / Data: JetBrains Mono (400, 500) via Google Fonts

**Theme switching:**
A persistent `☀/☾` toggle button is fixed bottom-right on all screens. The selected theme is stored in `localStorage('trainflow_theme')` and restored before first render (inline script in `<head>`). Light mode is implemented via `[data-theme="light"]` CSS overrides on `:root`.

**Design Tokens (`css/style.css :root`):**

| Token | Purpose |
|---|---|
| `--bg`, `--bg-2` | Page and secondary backgrounds |
| `--surface`, `--surface-2` | Card and panel surfaces |
| `--border`, `--border-2` | Dividers and input borders |
| `--ink-1` → `--ink-4` | Text hierarchy (primary → disabled) |
| `--pass`, `--fail`, `--warn` | Status colours |
| `--brand` | Primary accent (buttons, active states) |
| `--brand-secondary` | Secondary accent (section headers) |
| `--brand-accent` | Tertiary accent (status chips) |
| `--brand-dark` | Computed hover variant |
| `--brand-glow` | Ambient fill at 15% opacity |
| `--shadow-brand` | Focus ring at 20% opacity |

---

## Known Limitations

- **AI Importer** — optimised for Markdown input; PDF/Word ingestion not yet supported
- **KB Scraper integration** — planned (see `docs/kb-scraper-integration.md`); currently requires manual `.md` file upload
- **Tags** — schema and API exist; full tag-based filtering UI is not yet implemented
- **Learner list pagination** — all learners rendered at once; may lag with 500+ learners
- **CSV import into Course Builder** — stub; not yet implemented
- **Real-time updates** — dashboards use manual refresh; no WebSocket/SSE push
- **Logo storage** — uploaded logos stored as base64 data URIs; for production use the URL input with a CDN-hosted image

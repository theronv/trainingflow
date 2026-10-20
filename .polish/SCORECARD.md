# Scorecard

## 2026-10-20 — Baseline
Scale: 0 absent · 1 exists but unreliable · 2 solid · 3 best-in-class. Benchmark: SaaS admin dashboards (Linear/Stripe).

| Dimension | Score | Evidence |
|---|---|---|
| Architecture & conformance | 1 | 13+ mutable globals in `js/core.js`; `worker/index.js` 1,867 lines / one file; `admin.js` 1,126; data→`innerHTML` templates (`innerHTML` ×118 across js/). Off-stack (no TS/Next) but documented and working. |
| Code quality | 1 | No linter, formatter or types anywhere. `esc()` exists (`core.js:220`) but safety depends on every template remembering it. 11 `console.*` calls in js/ + worker. |
| Testing | 2 | 154 passing Vitest tests against real Hono app + in-memory libSQL: auth, RBAC, scoring, assignments, sections, roles, access requests. Gap: `admin.js`, `manager.js`, `learner.js`, `core.js`, `auth.js` untested; no E2E. |
| CI/CD | 0–1 | Only workflow deploys the worker on push to main; it never runs tests (`.github/workflows/deploy-worker.yml`). No PR checks, no Dependabot. Pages deploy is unguarded. |
| Observability | 0 | No Sentry/logging/alerts (grep: none). Worker errors return generic 500 with no capture. |
| Security | 2 | F1–F12 fixed with tests; server-side grading; team-scoped RBAC; rate limiting (`index.js:709`). Gaps: no CSP/security headers (grep: none), in-memory rate limit resets per isolate, tokens in sessionStorage, retake answer-probing (documented). |
| Reliability | 1 | `app.onError` generic handler; lazy per-isolate migrations in request path; no health check, no retries, no error boundary equivalent in SPA; fetch race conditions noted in CLAUDE.md. |
| Data & privacy | 1 | No privacy policy/terms in `index.html`; no self-service account deletion found (admin can delete learners); no data export; bulk "clear all completions" endpoint. |
| Performance | 1 | No build/minify; 2,345-line CSS and 1,450-line HTML shipped whole; jsPDF/html2canvas loading unverified; screenshots in course content compressed (recent commit). Not measured. |
| Visual design | 2 | Token system, dark/light, elevation ladder, skeletons, empty states, consistent shell; recent polish passes. Raw hex only in `core.js` (7), `auth.js`/`app.js` (1 each). No automated token lint or contrast test. |
| UX & copy | 2 | Role-based portals, resume, bulk assign, sections, import review flow. Admin/Manager mobile unaudited; some stubs ("coming soon" tags, CSV builder import). |
| Accessibility | 1 | Dialog roles, Escape, contrast fixes done in Polish IV; only 21 `aria-` attrs in 1,450-line shell, no a11y lint, no keyboard/focus audit, clickable-div risk via `onclick` attrs. |
| Store/launch readiness (web 6.1) | 1 | Custom domain, favicon/meta present; no privacy/terms, no error pages, no uptime/analytics, no SEO/OG check. |
| Docs | 2 | Thorough CLAUDE.md/README/CONTRIBUTING; some stale (e.g. says AI proxy unused, line counts drift). |
| Cost | 2 | Free tiers (Pages, Workers, Turso). AI cost is client-keyed or proxy; no budgets/limits on `/api/ai/generate` verified. |

**Overall: ~1.3 / 3.** Strong functional core and server security; weak safety net (CI, observability, lint), privacy, and measured a11y/perf.

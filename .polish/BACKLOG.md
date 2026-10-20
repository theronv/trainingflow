# Backlog

Ordered by impact ÷ effort. Status Open until you approve. "Resolves in" = playbook prompt.

## Critical
None found. (No data-loss, auth bypass or crash-on-launch evidence.) Closest: CI-01, which lets untested worker code reach production.

| ID | Phase | Area | Finding | Evidence | Severity | Effort | Fix | Status |
|---|---|---|---|---|---|---|---|---|
| CI-01 | 2.4 | CI/CD | Worker auto-deploys to production on push to main with no tests/lint run | `.github/workflows/deploy-worker.yml` (no test step); CONTRIBUTING.md says so | High | S | PR workflow running `npm test`; make deploy `needs` test job | Open |
| TST-01 | 2.2 | Hooks | No lint/format/type tooling or Stop hook; baseline is green (154 pass) so a blocking hook is safe | no eslint/prettier config; `.claude/settings.local.json` only has allow rules | High | M | ESLint (+ a11y plugin) + Prettier, token-literal lint, hooks | Open |
| SEC-01 | 3.1 | Security | No CSP / security headers on Worker responses or Pages shell | grep: no `secureHeaders`/CSP anywhere | High | M | Hono `secureHeaders` on API; CSP `<meta>` for Pages (needs inline-handler refactor or `unsafe-inline` decision) | Open |
| OBS-01 | 2.5 | Observability | No error capture; production failures invisible | no Sentry in repo | High | M | Sentry (Worker + browser), env-gated, PII-scrubbed. Needs your OK (new dependency) | Open |
| PRV-01 | 3.3 | Privacy | No privacy policy/terms; no self-service account deletion/export | none in `index.html`; no `DELETE /api/learners/me` | High | M | Policy page, delete-my-account endpoint + test | Open |
| SEC-02 | 3.1 | Security | `innerHTML` templates (118 sites) rely on manual `esc()`; one miss = stored XSS, and AI keys sit in localStorage | `js/admin.js` 50, `importer.js` 19, `manager.js` 22 | High | L | Audit every interpolation for `esc()`; add test that scans templates; finish AI-proxy-only and drop localStorage keys (S1) | Open |
| A11-01 | 4.11 | A11y | Sparse ARIA, no a11y lint, `onclick`-attribute wiring risks non-keyboard controls | 21 `aria-` in `index.html`; `js/app.js` AppProxy | Medium | M | Keyboard/focus audit, labels, a11y lint | Open |
| REL-01 | 3.2 | Reliability | Lazy migrations run in request path; in-memory rate limiter resets per isolate; no health endpoint | `ensureSetup`, `index.js:709` | Medium | M | Health route; move migrations to a run-once script; durable limiter if abuse matters | Open |
| VIS-01 | 2.6 | Tokens | No automated token-literal lint or contrast test; stray hex in JS | hex in `core.js` (7; mostly brand seeds), `auth.js:1`, `app.js:1` | Medium | S | Lint script + AA contrast unit test over token pairs | Open |
| ARC-01 | 7/5 | Architecture | Oversized modules and global state; admin.js 1,126 lines, worker 1,867 lines | `wc -l` | Medium | L | Split by resource/screen after tests cover them (defer until TST/CI done) | Open |

## Added after owner priorities (consistency + enterprise scale)

| ID | Phase | Area | Finding | Evidence | Severity | Effort | Fix | Status |
|---|---|---|---|---|---|---|---|---|
| UX-01 | 4.1/4.2 | Consistency | No component inventory or audit of how buttons, tables, modals, forms, chips and empty states differ across Admin/Manager/Learner; UI is built from per-screen template strings | `innerHTML` templates in admin/manager/learner.js | High | M | Audit against Skilljar-style patterns; define shared render helpers for table, modal, form row, page header; migrate screens | Open |
| VIS-02 | 2.6 | Consistency | Three style generations stacked in one 2,345-line CSS (base, "ENTERPRISE POLISH", "RESPONSIVE SHELL"), later overrides earlier | `css/style.css` section comments | Medium | M | Consolidate duplicate selectors, remove dead rules, keep tokens as single source | Open |
| SCL-01 | 3/5 | Scale | Single-tenant: no `org_id`, `brand`/`admin` singletons. Blocks selling to multiple enterprises | `docs/multi-tenancy-plan.md`; `schema.sql` | High | L | Decide tenancy model (plan recommends shared DB + org_id); needs your approval and a migration plan | Open |
| SCL-02 | 5.1 | Scale | Only `/api/learners` is paginated; other lists (completions, assignments, courses, trouble-spots) are fetched whole and rendered client-side | `index.js:991` is the only PAGE_SIZE; `D-10` note | High | M | Server pagination + search/filter for completions, assignments, courses; virtualize large tables | Open |
| SCL-03 | 5.1 | Scale | No SSO/SCIM/HRIS and no email notifications, standard enterprise LMS asks | CLAUDE.md "Not started" | Medium | L | Roadmap item; scope after SCL-01 | Open |

## Suggested order (given your priorities)
1. CI-01 + TST-01 (safe to change things)  2. VIS-01/VIS-02 + UX-01 (consistency foundation, then 4.x fix passes)  3. SCL-02, then SCL-01 decision  4. SEC-01, OBS-01, PRV-01, SEC-02  5. A11-01, REL-01, ARC-01.

## Housekeeping
- Done: `.DS_Store` untracked; CLAUDE.md AI-proxy notes corrected. The 6 deleted content JSONs are left uncommitted pending your call.

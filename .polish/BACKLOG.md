# Backlog

Ordered by impact ÷ effort. Status Open until you approve. "Resolves in" = playbook prompt.

## Critical
None found. (No data-loss, auth bypass or crash-on-launch evidence.) Closest: CI-01, which lets untested worker code reach production.

| ID | Phase | Area | Finding | Evidence | Severity | Effort | Fix | Status |
|---|---|---|---|---|---|---|---|---|
| CI-01 | 2.4 | CI/CD | Worker auto-deploys to production on push to main with no tests/lint run | `.github/workflows/deploy-worker.yml` (no test step); CONTRIBUTING.md says so | High | S | PR workflow running `npm test`; make deploy `needs` test job | Fixed (branch polish/phase-2; confirm green run after merge) |
| TST-01 | 2.2 | Hooks | No lint/format/type tooling or Stop hook; baseline is green (154 pass) so a blocking hook is safe | no eslint/prettier config; `.claude/settings.local.json` only has allow rules | High | M | ESLint (+ a11y plugin) + Prettier, token-literal lint, hooks | Fixed (polish/phase-2): lint, HTML a11y rules, Stop hook, CI lint job; Prettier configured, not enforced |
| SEC-01 | 3.1 | Security | No CSP / security headers on Worker responses or Pages shell | grep: no `secureHeaders`/CSP anywhere | High | M | Hono `secureHeaders` on API; CSP `<meta>` for Pages (needs inline-handler refactor or `unsafe-inline` decision) | Open |
| OBS-01 | 2.5 | Observability | No error capture; production failures invisible | no Sentry in repo | High | M | Sentry (Worker + browser), env-gated, PII-scrubbed. Needs your OK (new dependency) | Open |
| PRV-01 | 3.3 | Privacy | No privacy policy/terms; no self-service account deletion/export | none in `index.html`; no `DELETE /api/learners/me` | High | M | Policy page, delete-my-account endpoint + test | Open |
| SEC-02 | 3.1 | Security | `innerHTML` templates (118 sites) rely on manual `esc()`; one miss = stored XSS, and AI keys sit in localStorage | `js/admin.js` 50, `importer.js` 19, `manager.js` 22 | High | L | Audit every interpolation for `esc()`; add test that scans templates; finish AI-proxy-only and drop localStorage keys (S1) | Open |
| A11-01 | 4.11 | A11y | Sparse ARIA, no a11y lint, `onclick`-attribute wiring risks non-keyboard controls | 21 `aria-` in `index.html`; `js/app.js` AppProxy | Medium | M | Keyboard/focus audit, labels, a11y lint | Open |
| REL-01 | 3.2 | Reliability | Lazy migrations run in request path; in-memory rate limiter resets per isolate; no health endpoint | `ensureSetup`, `index.js:709` | Medium | M | Health route; move migrations to a run-once script; durable limiter if abuse matters | Open |
| VIS-01 | 2.6 | Tokens | No automated token-literal lint or contrast test; stray hex in JS | hex in `core.js` (7; mostly brand seeds), `auth.js:1`, `app.js:1` | Medium | S | Lint script + AA contrast unit test over token pairs | Fixed (ratchet at 138 literals; contrast test passes in both themes). Remaining literals tracked under VIS-02 |
| ARC-01 | 7/5 | Architecture | Oversized modules and global state; admin.js 1,126 lines, worker 1,867 lines | `wc -l` | Medium | L | Split by resource/screen after tests cover them (defer until TST/CI done) | Open |

## Added after owner priorities (consistency + enterprise scale)

| ID | Phase | Area | Finding | Evidence | Severity | Effort | Fix | Status |
|---|---|---|---|---|---|---|---|---|
| UX-01 | 4.1/4.2 | Consistency | No component inventory or audit of how buttons, tables, modals, forms, chips and empty states differ across Admin/Manager/Learner; UI is built from per-screen template strings | `innerHTML` templates in admin/manager/learner.js | High | M | Audit against Skilljar-style patterns; define shared render helpers for table, modal, form row, page header; migrate screens | Open |
| VIS-02 | 2.6 | Consistency | Three style generations stacked in one 2,345-line CSS (base, "ENTERPRISE POLISH", "RESPONSIVE SHELL"), later overrides earlier | `css/style.css` section comments | Medium | M | Consolidate duplicate selectors, remove dead rules, keep tokens as single source | Plan written in `VIS-02-plan.md` (305 dead declarations, 101 dead rules, 122 duplicated selectors); awaiting approval |
| SCL-01 | 3/5 | Scale | Single-tenant: no `org_id`, `brand`/`admin` singletons. Blocks selling to multiple enterprises | `docs/multi-tenancy-plan.md`; `schema.sql` | High | L | Decide tenancy model (plan recommends shared DB + org_id); needs your approval and a migration plan | Open |
| SCL-02 | 5.1 | Scale | Only `/api/learners` is paginated; other lists (completions, assignments, courses, trouble-spots) are fetched whole and rendered client-side | `index.js:991` is the only PAGE_SIZE; `D-10` note | High | M | Server pagination + search/filter for completions, assignments, courses; virtualize large tables | Open |
| SCL-03 | 5.1 | Scale | No SSO/SCIM/HRIS and no email notifications, standard enterprise LMS asks | CLAUDE.md "Not started" | Medium | L | Roadmap item; scope after SCL-01 | Open |

| A11-02 | 4.11 | A11y | Contrast test covers ink/accent text only; status text (`--success/--warning/--danger`), chips and button text are unchecked and the test ignores tokens redefined inside `@media` | `worker/test/contrast.test.mjs` | Medium | S | Extend pairs once status/chip tokens are consolidated (VIS-02) | Open |
| TST-02 | 2.2 | Lint | `no-unused-vars` is off for `js/` (cross-file globals) and Prettier is not enforced; implicit globals like `sectionsCache` are not detected | `eslint.config.mjs` | Low | M | Declare globals explicitly during ARC-01 split, then enable the rule | Open |

## UX-01 findings (audit 2026-10-20, details in `COMPONENTS.md`)

| ID | Phase | Area | Finding | Evidence | Severity | Effort | Fix | Status |
|---|---|---|---|---|---|---|---|---|
| UX-02 | 4.2 | Consistency | 12 destructive actions use native `confirm()` while a styled confirm modal exists; look and wording differ, unusable on some mobile browsers, not themable | `admin.js:305,360,397,483,1018,1060,1117`, `manager.js:152`, `builder.js:34`, `importer.js:314,969,1049` | High | M | One `Confirm.ask({title, body, confirmLabel, danger})` helper built on the modal; migrate all call sites; test | Fixed (polish/phase-4; `js/confirm.js`, 0 native `confirm()` left, old user-delete overlay removed; awaiting 🔍 review) |
| UX-03 | 4.1 | Consistency | Destructive buttons styled four ways, same verb uses outline vs ghost | `admin.js:171,231,339`, `builder.js:48`, `importer.js:916` | Medium | S | Single `btn-danger-ghost` for row actions, `btn-danger` for confirm; remove inline colours | Fixed (polish/phase-4; also undefined `btn-secondary` → `btn-outline`) |
| UX-04 | 4.1 | Consistency | Two empty-state systems; most empties give no next step | `empty-state-sm` x7 vs `.empty`; `style.css:612,791` | Medium | M | `emptyState({icon,title,hint,action})` helper; use for lists and tables; drop `-sm` and inline `grid-column` | Open |
| UX-05 | 4.1 | Consistency | Chip names are colours not meanings; green forced uppercase; amber hardcoded hex | `style.css:297-302,1862-1865` | Medium | S | `chip-success/danger/warning/info/neutral` + `statusChip()` helper; fold into VIS-02 and A11-02 | Open |
| UX-06 | 4.2 | Scale | Tables other than Users lack search/pagination; completions table duplicated in two portals | `index.html:319,906`; SCL-02 | High | M | One `dataTable()` renderer (columns, sort, filter, page), shared by Admin/Manager; pairs with SCL-02 | Open |
| UX-07 | 4.11 | A11y | Clickable `div`s without role/keyboard; modals missing dialog semantics (6 attrs for 14 overlays) | `admin.js:102,141,1005`, `learner.js:282`, `index.html` overlays | Medium | S | Use `button`/`role=button tabindex=0` + Enter/Space; add `role=dialog aria-modal aria-labelledby` to every overlay. Merge with A11-01 | Open |
| UX-08 | 4.1 | Consistency | Inline `style=` bypasses the system: 229 in index.html, 146 in js | grep counts | Medium | L | Replace with utility/component classes in batches, by screen, after VIS-02 | Open |
| UX-09 | 4.4 | States | Spinners/"Loading…" text where skeletons exist | `admin.js:175,177,406`, `manager.js:417` | Low | S | Use `skelList` helpers | Open |
| UX-10 | 4.2 | Safety | No undo for deletes; bulk "clear all completions" has a single OK dialog | `admin.js:1117` | Medium | M | Typed confirmation for irreversible bulk deletes; undo toast where soft delete is feasible (needs schema, ask first) | Open |

Proposed order: UX-02 and UX-03 first (shared helper + button rule), then UX-04/05 with VIS-02 (CSS consolidation), then UX-06 with SCL-02, then UX-07/08/09.

## Suggested order (given your priorities)
1. CI-01 + TST-01 (safe to change things)  2. VIS-01/VIS-02 + UX-01 (consistency foundation, then 4.x fix passes)  3. SCL-02, then SCL-01 decision  4. SEC-01, OBS-01, PRV-01, SEC-02  5. A11-01, REL-01, ARC-01.

## Housekeeping
- Done: `.DS_Store` untracked; CLAUDE.md AI-proxy notes corrected. The 6 deleted content JSONs are left uncommitted pending your call.

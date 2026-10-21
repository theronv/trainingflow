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
| VIS-02 | 2.6 | Consistency | Three style generations stacked in one 2,345-line CSS (base, "ENTERPRISE POLISH", "RESPONSIVE SHELL"), later overrides earlier | `css/style.css` section comments | Medium | M | Consolidate duplicate selectors, remove dead rules, keep tokens as single source | Plan written in `VIS-02-plan.md` (305 dead declarations, 101 dead rules, 122 duplicated selectors); Batches 1-2 done (polish/vis-02): 2,357 → 1,916 lines, 302 dead declarations + 101 dead rules + 12 tokens + 2 keyframes removed, cascade verified; batch 3 done: 47 declarations merged into their last definition (cascade + tie-order verified), 351 left because an equal-specificity rule in between touches a related property; batch 4: legacy layer names (II/III/IV/v3) and stale comments replaced, **full section reorder not done** (see VIS-02-plan.md); batch 5 (breakpoints/literals, UX-04/05) open |
| SCL-01 | 3/5 | Scale | Single-tenant: no `org_id`, `brand`/`admin` singletons. Blocks selling to multiple enterprises | `docs/multi-tenancy-plan.md`; `schema.sql` | High | L | Decide tenancy model (plan recommends shared DB + org_id); needs your approval and a migration plan | Open |
| SCL-02 | 5.1 | Scale | Only `/api/learners` is paginated; other lists (completions, assignments, courses, trouble-spots) are fetched whole and rendered client-side | `index.js:991` is the only PAGE_SIZE; `D-10` note | High | M | Server pagination + search/filter for completions, assignments, courses; virtualize large tables | Open |
| SCL-03 | 5.1 | Scale | No SSO/SCIM/HRIS and no email notifications, standard enterprise LMS asks | CLAUDE.md "Not started" | Medium | L | Roadmap item; scope after SCL-01 | Open |

| A11-02 | 4.11 | A11y | Contrast test covers ink/accent text only; status text (`--success/--warning/--danger`), chips and button text are unchecked and the test ignores tokens redefined inside `@media` | `worker/test/contrast.test.mjs` | Medium | S | Extend pairs once status/chip tokens are consolidated (VIS-02) | Partly fixed: chip/status text tokens covered by `contrast.test.mjs`; button text and tokens redefined inside `@media` still unchecked |
| TST-02 | 2.2 | Lint | `no-unused-vars` is off for `js/` (cross-file globals) and Prettier is not enforced; implicit globals like `sectionsCache` are not detected | `eslint.config.mjs` | Low | M | Declare globals explicitly during ARC-01 split, then enable the rule | Open |

## UX-01 findings (audit 2026-10-20, details in `COMPONENTS.md`)

| ID | Phase | Area | Finding | Evidence | Severity | Effort | Fix | Status |
|---|---|---|---|---|---|---|---|---|
| UX-02 | 4.2 | Consistency | 12 destructive actions use native `confirm()` while a styled confirm modal exists; look and wording differ, unusable on some mobile browsers, not themable | `admin.js:305,360,397,483,1018,1060,1117`, `manager.js:152`, `builder.js:34`, `importer.js:314,969,1049` | High | M | One `Confirm.ask({title, body, confirmLabel, danger})` helper built on the modal; migrate all call sites; test | Fixed (polish/phase-4; `js/confirm.js`, 0 native `confirm()` left, old user-delete overlay removed; awaiting 🔍 review) |
| UX-03 | 4.1 | Consistency | Destructive buttons styled four ways, same verb uses outline vs ghost | `admin.js:171,231,339`, `builder.js:48`, `importer.js:916` | Medium | S | Single `btn-danger-ghost` for row actions, `btn-danger` for confirm; remove inline colours | Fixed (polish/phase-4; also undefined `btn-secondary` → `btn-outline`) |
| UX-04 | 4.1 | Consistency | Two empty-state systems; most empties give no next step | `empty-state-sm` x7 vs `.empty`; `style.css:612,791` | Medium | M | `emptyState({icon,title,hint,action})` helper; use for lists and tables; drop `-sm` and inline `grid-column` | Fixed (polish/vis-02-ux): `empty-state-sm` removed; the 7 list empties use `.empty.empty-compact`; helper + next-step actions still open |
| UX-05 | 4.1 | Consistency | Chip names are colours not meanings; green forced uppercase; amber hardcoded hex | `style.css:297-302,1862-1865` | Medium | S | `chip-success/danger/warning/info/neutral` + `statusChip()` helper; fold into VIS-02 and A11-02 | Fixed (polish/vis-02-ux): chips are `chip-success/danger/warning/info/neutral`; amber and status text come from tokens (`--warning-*`, `--success-text`, `--danger-text`); light-mode success/danger chip text darkened to pass AA; `statusChip()` helper still open |
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

## Phase 3.1 Security audit (2026-10-20)

Scope: OWASP Top 10 pass over `worker/index.js` (70 routes), the SPA shell, git history and dependencies. Recorded, not fixed: waiting for approval (see order at the end).

| ID | Phase | Area | Finding | Evidence | Severity | Effort | Fix | Status |
|---|---|---|---|---|---|---|---|---|
| SEC-03 | 3.1 | Secrets | `worker/.dev.vars` was committed to the **public** repo and is still in history: a `GEMINI_API_KEY` in real Google key format (39 chars), a `JWT_SECRET` placeholder starting "super" (39 chars), a dev `ADMIN_PASSWORD_HASH`, and a mock `TURSO_TOKEN` (10 chars). Untracked in b6b03dd but never purged | `git log --all -- worker/.dev.vars` → 808778e, d120300, 8321ad3; `gh repo view` → PUBLIC | **Critical if the key is live or production reuses these values** | S | **Owner actions:** revoke/rotate that Gemini key in Google AI Studio; confirm production `JWT_SECRET` and admin password differ from the committed dev values (rotate if unsure: rotating `JWT_SECRET` signs everyone out). Claude cannot read production secrets, so this cannot be checked from here. **Do not rewrite history**: rotation makes the leaked values worthless. | Open (owner) |
| SEC-04 | 3.1 | Dependencies | `hono` is 4.12.7 (we pin `^4.7.0`; fixed in 4.13.13): 2 high advisories in `npm audit --omit=dev`. Relevant to what we use: `hono/jwt` verify accepts invalid NumericDate claims (GHSA-hm8q-7f3q-5f36) and the CORS middleware has a ReDoS (GHSA-8j4g-w8fx-2239); also `bodyLimit` bypass (needed for SEC-06). `ws` (via `@libsql/client`) has a memory-exhaustion DoS. Root package: 0 vulnerabilities | `cd worker && npm audit --omit=dev`; `worker/package.json:13-14` | High | S | `npm update hono` (to 4.13.13) and `npm audit fix` for `ws`, run the suite, deploy. Needs your OK (dependency change) | Open |
| SEC-05 | 3.1 | Authorization | Roles and `team_id` are read from the JWT only (`bearer()`, `requireAdmin/Manager/Learner`, `index.js:164-196`). A deleted, demoted or team-moved user keeps their old access until the token expires (learner 24 h, admin/manager 8 h); a password change or reset does not end existing sessions | `index.js:158-196`; no DB check in middleware | Medium | M | Re-check the user row (exists, role, `is_admin`, `team_id`) on admin/manager routes, or add a `sessions_valid_after` column and reject older tokens. Touches auth: needs your decision | Open |
| SEC-06 | 3.1 | Abuse/cost | No request body size limit anywhere; `/api/ai/generate` accepts any `prompt` length and a client-chosen `max_tokens`. Admin-only, so the risk is a compromised admin or runaway import | `index.js:1533-1555`; grep `bodyLimit` → none | Low–Medium | S | Cap prompt (~200k chars) and `max_tokens` (≤ 8000); add body limit after SEC-04 | Open |
| SEC-07 | 3.1 | Auth hardening | Login rate limiting is per-IP and per-isolate (`_rateCheck`), so it resets on cold start and is bypassed by rotating IPs; no per-account lockout or backoff. `GET /api/verify/:id` shares the limit. Old certificates (`TF-`/`PG-` 8 hex, 32 bits) are enumerable in principle | `index.js:257-263` | Medium | M | Durable limiter (Cloudflare Rate Limiting rule or KV/DO) on login and verify; per-account failed-attempt counter. Folds into REL-01 | Open |
| SEC-08 | 3.1 | Privacy/ops | Resend is now a sub-processor: recipient email, learner name, course, score and cert id are sent to it on first passes | `worker/email.js` | Info | S | Record in the privacy policy (PRV-01) and the data map (3.3) | Open |

**Updates to existing items**
- **SEC-01 (headers):** still no CSP or security headers (grep: none in `worker/index.js` or `index.html`). GitHub Pages cannot set response headers and `<meta>` CSP cannot set `frame-ancestors`, so clickjacking protection and HSTS are impossible on Pages alone. The custom domain's DNS is on Cloudflare (per Resend): if the app record is proxied, Cloudflare Transform Rules can add CSP/HSTS/X-Frame-Options with no code. API side: Hono `secureHeaders()` is a one-line add. Inline `onclick` handlers mean a strict script CSP needs the handler refactor or `unsafe-inline` for now.
- **SEC-02 (XSS):** a crude scan of 64 candidate interpolations found **no confirmed unescaped sink**; spot checks (`admin.js:534`, `auth.js:137/255`, `admin.js:702/1006`) go to `Toast`/`textContent`/`Confirm`, which escape or avoid HTML. Not proven safe: replace the heuristic with a real test that fails on any `${…}` inside an `innerHTML` template that isn't `esc()`/known-safe. New code (verify page, ceremony, wall, emails) escapes everything.
- **REL-01:** also covers SEC-07.

**Checked and fine**
- Authorization map: every one of the 70 routes carries a middleware except the 11 intended-public ones (brand GET, three logins, invite preview, access-request POST, Clerk login, two registers, verify). Manager-scoped mutations (password reset, invite delete, tag routes) check team ownership and return 404 for other teams (`index.js:532-545`, `433-443`, `1983-2025`); admin-only routes use `requireAdmin`.
- JWT: HS256 pinned on sign and verify, `exp` set (8 h / 24 h); passwords PBKDF2-SHA256 100k with per-user salt.
- CORS: explicit allow-list echoed back, never a wildcard (the wildcard advisory does not apply).
- SQL: parameterised throughout (spot-checked all new routes).
- 500s return a generic message; errors never echo DB detail except `PUT /api/brand` (returns `detail: e.message`, `index.js:~506`): fold into SEC-06's batch.

**Proposed order (approve to proceed)**
1. SEC-03 now (owner actions, 10 minutes, nothing to code). It is the only Critical.
2. SEC-04 (dependency bump + tests), then SEC-01 API headers + the Cloudflare rule if the record is proxied, then SEC-06.
3. SEC-05 (needs your decision on the approach), SEC-07, then the real SEC-02 scanner test.
4. Then 3.2 Reliability and 3.3 Privacy (PRV-01, SEC-08); re-score at the end of Phase 3.

# Profile — Pregame Academy (2026-10-20)

- **What it does:** Multi-role LMS for professional teams. AI-assisted course import/creation, assignments, progress, quizzes graded server-side, verifiable PDF certificates. One account can learn, manage and administer.
- **Platform:** Web (vanilla-JS SPA). Native RN/Expo build is a future target, not started. Mobile-web matters (iOS home-screen use).
- **Audience:** Staff at organisations/teams (first customer content: Synergy Sports courses). B2B per-seat model ($4–7/learner/month) is the stated target.
- **Maturity:** Live in production (https://theronv.github.io/trainingflow/, custom domain pregame-academy.vickerydigital.com). Single-tenant (1 deployment = 1 org); `docs/multi-tenancy-plan.md` exists.
- **Design benchmark category (§1.3):** LMS platform — **Skilljar** and comparable enterprise LMSs (owner-confirmed 2026-10-20). Admin surfaces also borrow from SaaS dashboards (Linear/Stripe).
- **Owner priorities:** (1) UI/UX consistency, (2) scalability for enterprise use.

## Stack
| Layer | Actual |
|---|---|
| Frontend | Vanilla JS ES6, HTML, CSS, no build step, no TypeScript; GitHub Pages |
| API | Hono 4.7 on Cloudflare Workers (`worker/index.js`, 1,867 lines) |
| DB | Turso/libSQL, raw SQL, `schema.sql` + lazy inline migrations |
| Auth | Custom JWT + PBKDF2; Clerk email/Google sign-in exchanged for app JWT |
| AI | Claude/Gemini; keys in browser localStorage and/or Worker proxy `/api/ai/generate` |
| PDF | jsPDF + html2canvas, client-side |
| CI | One workflow: deploy worker on push to main touching `worker/**` (no tests, no lint) |
| Monitoring | None |

## Env var names (values never recorded)
TURSO_URL, TURSO_TOKEN, JWT_SECRET, ADMIN_PASSWORD_HASH, GEMINI_API_KEY, CLAUDE_API_KEY, ALLOWED_ORIGIN, ADMIN_EMAILS, JINA_API_KEY, Clerk keys (see worker/index.js).

## How to run / check
- Worker: `cd worker && npm run dev` (8787). Frontend: `npx serve .` (3000).
- Tests: `cd worker && npm test` → **14 files, 154 tests, all pass** (1.8s).
- Lint / type check / build: **none exist** (no ESLint, Prettier, tsconfig, build).
- Deploy: push to `main` (Pages); worker deploys via workflow; CLAUDE.local.md authorises Claude to auto-deploy its own changes.

## Deviations from §1 (see DECISIONS.md)
Vanilla JS instead of Next/TS; Cloudflare instead of Vercel; custom JWT + Clerk; Drizzle absent; no Zustand; tests only cover the Worker + a few `js/` modules.

## Working-tree note
`content/synergy-baseball/*.json` (6 files) deleted but uncommitted: left as-is (deleting content needs owner sign-off; recoverable from git).

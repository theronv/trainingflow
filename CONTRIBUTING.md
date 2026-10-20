# Contributing to Pregame Academy

Thanks for helping out. Read `CLAUDE.md` first: it covers the stack, the API, the database schema and the design system.

## Workflow

1. Branch from an up-to-date `main`. Never commit to `main` directly.
   - Names: `feature/<short-topic>`, `fix/<short-topic>`, `docs/<short-topic>`.
2. Keep each branch to one logical change, with commits in the imperative mood ("Add X", not "Added X").
3. Run the checks below, then open a pull request into `main`.
4. Merged branches are deleted automatically. Don't keep long-lived branches; rebase or merge `main` into yours if it falls behind.

## Run locally

```bash
cd worker && npm install && npm run dev   # API at http://localhost:8787
npx serve .                               # frontend at http://localhost:3000
```

Worker secrets for local dev go in `worker/.dev.vars` (see `CLAUDE.md`). Never commit secrets or `.dev.vars`.

## Before you open a PR

- `npm run lint` passes (ESLint for `js/` and `worker/`, HTML accessibility rules for `index.html`, and the token-literal check that stops new raw colours). Run `npm install` once at the repo root first.
- `cd worker && npm test` passes. New or changed worker logic needs tests in `worker/test/`. A bug fix starts with a failing test.
- For UI changes, check the screen at 390px (mobile) and desktop widths, in light and dark mode, and attach screenshots to the PR.
- Use the existing design tokens in `css/style.css`. Don't add one-off colors, spacing or fonts.
- No `console.log`, TODOs or commented-out code left behind.
- Update `README.md` or `CLAUDE.md` if setup or behavior changed.

## Deploys: read this

- **Frontend:** every push to `main` publishes to GitHub Pages.
- **Worker:** a push to `main` that touches `worker/**` deploys to **production** Cloudflare (`.github/workflows/deploy-worker.yml`). That workflow now runs the worker tests first and only deploys if they pass; a separate CI workflow (`ci.yml`) runs them on every pull request.
- Don't run `wrangler deploy`, `wrangler secret`, database migrations or destructive `turso` commands without the owner's sign-off.

## Ask first

Get agreement before you: add or remove a dependency, change `schema.sql` or run a migration, touch auth, permissions or other security-sensitive code, or do a large refactor.

# VIS-02 plan: consolidate `css/style.css` (audit, 2026-10-20)

Measured with a small cascade-aware parser (no dependencies, no browser). Numbers are for `css/style.css` at 2,357 lines, 924 rules, 3,203 declarations, 25 `!important`, 12 distinct media queries.

## What is wrong
The file is five style generations appended in order: base (1-1404), ENTERPRISE POLISH I/II (1405-1663), RESPONSIVE SHELL, POLISH III, PREGAME ACADEMY SKIN, POLISH IV, MOBILE I/II (to 2357). Each later layer restyles the same selectors instead of editing them.

| Measure | Count |
|---|---|
| Selectors (same media context) defined more than once | 122 (covering 272 rules) |
| Declarations overridden by a later rule for the same selector (dead) | **305** (55 are overridden with the identical value) |
| Worst offenders | `#screen-landing` 7x, `[data-theme=light]` 3x, `body`, `.btn`, `.topbar`, `.brand`, `.sidenav`, `.nav-btn`, `.main`, `.page-head` 3x each |
| Classes in CSS that appear nowhere in `index.html`/`js/` (excluding dynamic prefixes like `t-${type}`, and documented utilities) | 49 |
| Rules that only target those classes (fully dead) | **101 rules / 184 lines**, 34 of them the retired "Landing (enterprise layout)" and "Landing v3" blocks (lines 2100-2180) |
| Unused tokens | 13: `--muted --text-3xl --white --r-lg --r-full --accent-lt --s-1 --s-2 --s-4 --s-6 --ink-meta --shadow-xs --why-text` (note `--text-3xl` is documented in CLAUDE.md; keep it) |
| Unused keyframes | `toastIn`, `slideUp` |
| Breakpoints | 12 distinct (`520 560 600 720 860 900 960`, written `720px` two ways) |
| Raw colour literals | 79 in `style.css` (ratchet baseline 138 repo-wide) |

## Proposed batches (each one commit; lint + tests + equivalence check after each)
1. **Dead declarations (safe by construction).** Remove the 305 declarations that a later rule of the same selector and media context already overrides. Skips anything with `!important` and same-rule fallback pairs (e.g. `100vh` then `100dvh`). Delete rules that become empty.
2. **Dead rules and selectors.** Remove the 101 rules for classes nothing renders, trim dead members from 9 mixed selector lists, drop 2 unused keyframes and the unused tokens. Keep documented utilities (`sr-only`, `tabular`, `mono`).
3. **Merge duplicate rules in place.** For the 122 duplicated selectors, fold the surviving declarations into the position of the last definition only when no rule between them has an equal-or-higher-specificity match for the same properties (checked by the script); otherwise leave and list it for manual review.
4. **Section order and headings.** Reorder to tokens → base → components → layout → pages → responsive → motion/print, with one heading each, no "II/III/IV/v3" names. Only after 1-3, and only for rules the script proves order-independent.
5. **Breakpoints and literals.** Normalise to a small set (`480 / 720 / 860 / 1024`), only where the existing values are within a few px and the change is a no-op at the sizes in CONTRIBUTING (390, desktop); move remaining literals to tokens, lowering `token-baseline.json`. This one changes pixels at the margins, so it is last and optional.

Folds in **UX-05** (chip tokens: `chip-success/danger/warning/info/neutral`, remove the hardcoded amber and forced uppercase) and **UX-04** (one empty-state, `.empty` + helper, drop `.empty-state-sm`) because they touch the same rules. Those two change visible output, so they get their own commits and a 🔍 list.

## Verification without a browser
- New `scripts/css-audit.mjs` (no dependencies) resolves the cascade per (media context, selector, property) before and after each batch. Batches 1-4 must leave every resolved value identical, except for rules proven dead. The script fails the run otherwise.
- A test in `worker/test/` runs it against `css/style.css` so the dead/duplicate counts can only go down.
- Existing checks: `npm run lint` (token ratchet), contrast test, 205+ tests.
- Limits: the script cannot see specificity ties between *different* selectors, so batch 3-4 only move rules it can prove independent; everything else is left alone and listed.

## 🔍 What you review afterwards
Landing (signed out), one screen per portal (Admin Courses, Manager Dashboard, Learner Courses), the course player and a modal, at 390px and desktop, light and dark. Batches 1-4 should look identical; only batches 5 and UX-04/05 can change pixels.

## Risks and assumptions
- Class names assembled in JS beyond the `prefix-${...}` pattern would be missed as "live"; that only makes the script keep more, never delete more.
- A class used only by Clerk or a third-party script would look unused. None are known; `.cl-*` selectors are excluded from removal.
- No dependencies are added.

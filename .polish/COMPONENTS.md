# Component & pattern inventory (UX-01 audit, 2026-10-20)

Code-only audit; no browser launched. Benchmark: Skilljar-style LMS (learner), SaaS admin (Admin/Manager).
Counts are grep results over `index.html` and `js/*.js` at branch `polish/phase-4`.

| Component | Canonical form | Variants found | Verdict |
|---|---|---|---|
| Button | `.btn` + `-primary/-outline/-ghost/-danger` + size | 21 class combos. Destructive styled 4 ways: `btn-danger`, `btn-danger-ghost`, `btn-outline`+inline `color:var(--fail)` (`admin.js:171`), `btn-ghost`+inline `color:var(--fail)` (`admin.js:339`, `builder.js:48`). `btn-secondary` used once, may be undefined | Inconsistent |
| Row action | Edit / Revoke / Delete in a table "Actions" cell | Text buttons everywhere; mixed `btn-outline` vs `btn-ghost` for the same verb (Edit = outline in courses, ghost elsewhere). `Reset PW` abbreviation (`manager.js:176`) | Inconsistent |
| Chip / status | `.chip-success/danger/warning/info/neutral` | Colour-named, not meaning-named. `chip-green` is forced uppercase (`style.css:1865`) while the others are not. `.chip-amber` redefined with hardcoded `#d99100` (`style.css:1863`) | Inconsistent |
| Table | `.table-wrap > table` | 5 JS + 4 HTML tables; sortable headers added globally (`core.js:38`), but no search/pagination except Users; completions table duplicated in Manager (`index.html:319`) and Admin (`:906`) with identical columns | Duplicated, no scale handling |
| Modal | `.overlay > .modal > head/body/foot` | 13 modals, structure consistent. `modal-sm` and `modal-wide` sizes. Only `aria-modal`/`role=dialog` on some (6 attrs vs 14 overlays) | Mostly consistent, a11y gaps |
| Confirm | `#confirm-delete-overlay` modal | Used by user delete only. **12 other destructive actions use native `confirm()`** (`admin.js` x7, `manager.js:152`, `builder.js:34`, `importer.js` x3) | Inconsistent |
| Empty state | `.empty` (icon, title, hint, action) | `.empty.empty-compact` for the 7 table/list empties; only 2 of ~15 empties have a next-step action; `.empty` has inline `grid-column` hack in 3 places | Two systems |
| Loading | `.skeleton` helpers in `core.js` | Admin team detail and tags use a bare `.spinner` (`admin.js:175,177,406`); manager select shows "Loading…" text | Mixed |
| Feedback | `Toast.ok/err/info` | Consistent. No undo on delete | OK |
| Page header | `.page-head` / `.page-head-row` | 15 uses, consistent. Primary action placement varies (header row vs inside card) | Mostly OK |
| Form row | `.field > label + input` | Consistent in modals; builder/importer use inline-styled variants (`builder.js` 33 `style=`, `importer.js` 31) | Mostly OK |
| Nav | `.nav-btn` sidebar → tab strip at ≤860px | Admin groups (Content/People/Reporting/Configure); Manager has 4 + "Settings"; Learner is flat 4. Consistent mechanism | OK |
| Clickable card/row | `role=button tabindex=0` | Only `learner.js:129` does it. `div onclick` without role/keyboard: `admin.js:102,141,1005`, `learner.js:282` | A11y bug |
| Inline styles | Tokens via classes | **229 in `index.html`, 146 in js** | Bypasses system |
| CSS | One system | `style.css` 2,345 lines, 4 stacked layers (base, ENTERPRISE POLISH I/II/III, RESPONSIVE SHELL) with later overrides of earlier rules; `.chip-blue`, `.empty`, `.table-wrap`, `.btn` etc. defined 2-3x | Needs VIS-02 |

## Skilljar-style gaps (learner/admin patterns we lack)
- Learner: no course catalogue filters/search; no per-course progress summary on the dashboard beyond card status; no "continue where you left off" row separate from the grid (resume is a card state).
- Admin: no bulk actions on completions/assignments; no filter chips or saved views; no CSV export of completions (verify); lists are not paginated (SCL-02).
- Destructive actions have no undo and no typed confirmation for irreversible bulk deletes (`clearRecords`).

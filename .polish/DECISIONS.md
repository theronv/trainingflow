# Decisions

| Date | Decision | Reason |
|---|---|---|
| 2026-10-20 | Platform recorded as Web; mobile-web is first-class | Vanilla SPA; native app not started |
| 2026-10-20 | Design benchmark = Skilljar / enterprise LMS platforms (+ SaaS admin for admin screens) | Owner decision |
| 2026-10-20 | Priorities: UI/UX consistency, then enterprise scalability | Owner decision; backlog re-ranked |
| 2026-10-20 | Untracked the two `.DS_Store` files (already in .gitignore) | Housekeeping, files kept on disk |
| 2026-10-20 | Left the 6 uncommitted `content/synergy-baseball/*.json` deletions alone | Deleting content needs sign-off; still in git history |
| 2026-10-20 | Corrected stale AI-proxy notes in CLAUDE.md | Importer already uses `/api/ai/generate` |
| 2026-10-20 | Phase 0/1 are audit-only; no app code changed | Per playbook |

Deviations to rule on after Prompt 1.2 (conform vs keep) are listed in BACKLOG.md as CNF-xx once approved.
| 2026-10-20 | ESLint with `allowEmptyCatch` and `console.warn/error` allowed | Empty catches are idempotent migrations/storage guards; warn/error are deliberate error reporting. `console.log` stays banned |
| 2026-10-20 | Token lint is a ratchet (baseline 138 literals), not zero | Existing literals are mostly brand data and legacy CSS; ratchet stops growth now, VIS-02 burns it down |
| 2026-10-20 | Prettier installed but not enforced or auto-run | Formatting the existing files would rewrite most lines; do one approved format-only commit later |
| 2026-10-20 | No `ask` permission rules in `.claude/settings.json` | Ask rules outrank the owner's local allow for push/deploy and would break the authorised auto-deploy; package installs already prompt |

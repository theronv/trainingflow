# TrainFlow — Active Issues

**Last updated:** 2026-04-14

All bugs from the initial audit (AUDIT.md) and QA pass (QA-REPORT.md) have been resolved. This file tracks only current open issues and recently closed ones.

---

## ✅ Recently Closed

### AI Importer — Save button hangs indefinitely on network failure
**Closed:** 2026-04-14 · `249033b`

`saveAiCourse()` had no timeout on the `fetch` call. If the Worker or Turso connection hung, the "Saving…" state persisted forever with no recovery path.

**Fix:** Added `AbortController` with 30s timeout. Moved button reset from `catch` to `finally` so it always recovers. On timeout, shows a clear actionable message rather than a generic error.

---

## ⚠️ Open — Known Limitations

### CSV import into Course Builder (B-04)
The "Confirm" button in the Course Builder CSV import modal shows a "coming soon" toast. Requires defining a CSV schema and building a parse + module-merge pipeline. **Effort: ~2hrs.**

### Tags feature (B-06)
Schema, DB tables, and API routes exist. The admin UI tag creation and learner tag assignment stubs show "coming soon" toasts. Full tag-based filtering not implemented. **Effort: ~3hrs.**

### Learner list pagination (D-10)
All learners are rendered to the DOM at once. Acceptable up to ~200 learners; will lag noticeably at 500+ and may freeze at 5000+. **Effort: ~1hr.**

---

## 📋 Backlog / Planned

- **KB Scraper → AI Importer integration** — see `docs/kb-scraper-integration.md`
- **Real-time dashboard updates** — currently manual refresh only; no SSE/WebSocket
- **Logo CDN support** — currently base64 data URI; large logos inflate API response size

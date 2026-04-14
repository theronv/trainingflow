# KB Scraper → AI Importer Integration Plan

**Status:** Drafted — not yet implemented  
**Date:** 2026-04-13  
**Effort estimate:** 1–2 hours

---

## Background

`kb_scraper.py` is a local browser-based tool that takes a list of URLs, fetches each via the Jina Reader API (`r.jina.ai/{url}`), and saves clean Markdown files to `~/Desktop/training_docs/`. It's currently a standalone Python utility.

The TrainingFlow AI Importer (Upload → Configure → Generate → Review) already accepts `.md` files and parses them via `Admin.parseMdToModules()` in `js/admin.js:1190`. Jina Reader's output format — `Title:`, `URL Source:`, `##` section headings — maps directly to what the parser expects.

**The scraper and importer already speak the same language. No format conversion needed.**

---

## Tier 1 — Works Today (Zero Code)

Run the scraper → drag `.md` files from `~/Desktop/training_docs/` into the Upload drop zone.

No changes required. Use this in the interim.

---

## Tier 2 — "Scrape from URLs" Tab in Upload Step (Recommended)

Add a second input tab to the Upload phase so admins paste URLs directly in the app — no Python, no Desktop folder.

```
[ Drop / Browse Files ]  |  [ Scrape from URLs ]
```

### Implementation

**1. Worker proxy route** (`worker/index.js`)

Proxies Jina fetches server-side to avoid browser CORS restrictions.

```js
app.get('/api/scrape', requireAdmin, async (c) => {
  const url = c.req.query('url')
  if (!url) return c.json({ error: 'url param required' }, 400)
  const res = await fetch(`https://r.jina.ai/${encodeURIComponent(url)}`, {
    headers: { 'User-Agent': 'TrainingFlow-Educational' }
  })
  if (!res.ok) return c.json({ error: `Jina fetch failed: ${res.status}` }, 502)
  const markdown = await res.text()
  return c.json({ markdown, url })
})
```

**2. Upload phase UI** (`index.html` + `js/admin.js`)

- Add a tab toggle between "Files" and "URLs" in the `phase-upload` section
- URLs tab: `<textarea>` — one URL per line, lines starting with `#` ignored
- On submit: iterate URLs → `GET /api/scrape?url=...` → call `Admin.addFileModule(md, derivedTitle)` for each
- Show per-URL progress (fetching / done / failed) inline
- Delay between requests: 1–2s to be polite (mirrors scraper behavior)
- After all URLs processed, advance to Configure phase automatically

The Generate step and everything downstream runs exactly as today — no other changes needed.

---

## Tier 3 — Full In-App Scraper (Future)

Replace the Python tool entirely. Build a Scrape Queue UI inside TrainingFlow with start/stop/progress identical to the Python tool, but embedded in the Importer flow. Lower priority — Tier 2 covers the practical need.

---

## Key Files

| File | Change |
|---|---|
| `worker/index.js` | Add `GET /api/scrape` route (~10 lines) |
| `index.html` | Add URL tab to `#phase-upload` section |
| `js/admin.js` | Add `scrapeUrls()` method, tab toggle logic |

---

## Notes

- Jina Reader is a free public API — no auth token needed for basic use
- Rate limit: add ~1–2s delay between URL fetches to avoid 429s
- The existing `parseMdToModules()` already handles Jina's metadata format (`Title:`, `URL Source:`) — confirmed by reading `js/admin.js:1194–1210`
- CORS is the only reason a worker proxy is needed; if Jina adds CORS headers in future, the proxy can be removed and fetches can go direct from the browser

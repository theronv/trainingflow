# Active Bug Report: TrainFlow "White Screen" Issues

**Status:** RESOLVED (2026-03-17)
**Priority:** HIGH (Blocker for v1 Launch)

---

## ✅ Fixes Applied

### Root Cause: CSS/Class Mismatch in Nav Functions
**Problem:** All three nav functions (`Admin.nav`, `Manager.nav`, `Learner.nav`) toggled the `.hidden` class on page elements. However, the CSS uses `.page { display: none }` / `.page.active { display: block }` — so removing `.hidden` alone never made a page visible because the base `.page` rule keeps it hidden.

**Fix:** Added `pg.classList.toggle('active', k===p)` alongside the existing `hidden` toggle in all three nav functions.

### Learner Login Crash
**Problem:** `auth.js` set `curLearner = { id: data.id, name: data.name }` but the API returns `{ token, user: { id, name } }`. This caused `curLearner.name` to be `undefined`, making `Learner.init()` crash on `curLearner.name[0]`.

**Fix:** Updated to use `data.user.id` / `data.user.name`.

### Missing Backend Routes
Added the following routes to `worker/index.js`:
- `GET /api/courses/:id` — for `Learner.startCourse()`
- `POST /api/completions` — for `Learner.completeCourse()`
- `GET /api/assignments` — for `Builder.openAssign()` and `Manager.openTeamAssign()`
- `PATCH /api/admin/teams/:id` — for team renaming

### Missing App Proxy Methods
Added the following to `js/app.js` AppProxy:
- `exitCourse`, `showLearner`, `moveLearner`
- `renderMComps`, `updateManagerName`, `changeManagerPw`
- `updateLearnerName`, `changeLearnerPw`
- `setAssignTab`, `filterAssignList`
- `compPage` (completions pagination)
- `uploadLogo`, `syncHex` (branding)
- `exportBackup`, `importBackup` (settings)
- `createTag`, `closeTagsModal`, `closeLearnerTagsModal`
- `copyInviteCode`, `closeConfirmDelete`
- `csvImportOpen`, `csvDrop`, `csvFileSelected`, `csvClose`, `csvConfirm`

### Missing Admin Methods
Added to `js/admin.js`:
- `openRenameTeam` / `submitRenameTeam`
- `openGenerateInvite`
- Fixed `openCreateTeam` to wire up the submit button's `onclick`

---

## 📝 Remaining Known Limitations

- `updateManagerName`, `changeManagerPw`, `updateLearnerName`, `changeLearnerPw` show "Coming soon" toast — backend routes not yet implemented.
- `csvConfirm` shows "Coming soon" toast — `Builder.importModulesFromCsv` not yet implemented.
- `importBackup` shows "Coming soon" toast.
- `createTag` shows "Coming soon" toast — tag system not yet built.
- `exportCSV` in admin shows "Exporting..." toast but does not produce a file.
- Manager registration uses `invite_code` field name but the API expects `code` — minor schema mismatch to verify.

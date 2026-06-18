# Multi-Tenancy Plan — TrainFlow

**Status:** Proposal · **Author:** Architecture review · **Date:** 2026-06-18

## Why

Today **1 deployment = 1 org**. There is no `org_id` on any table, no tenant
isolation, and a single `brand` / `admin` singleton row. To sell the confirmed
B2B per-seat model ($4–7/learner/month) to more than one customer, the data
model and every query need a tenant scope. This is the single largest item
gating "set up to scale," and it touches the whole schema + API. It should be
decided **before** the React Native migration so the native client is built
against a tenant-aware API, not retrofitted later.

## Tenancy model decision

Three options, in increasing isolation/cost:

| Model | Isolation | Ops cost | Fit |
|---|---|---|---|
| **A. Shared DB, `org_id` column (row-level)** | Logical | Low — one Turso DB | **Recommended for v1** |
| B. DB-per-tenant (Turso multi-DB) | Strong | Medium — provisioning per org | Good upsell tier for enterprise |
| C. Deployment-per-tenant (today) | Strong | High — does not scale past a handful | Status quo; abandon |

**Recommendation: Model A (shared DB + `org_id`)** for the standard tier, with
Model B reserved as a later "dedicated instance" enterprise upgrade. Model A is
the smallest change that unlocks self-serve onboarding, and Turso's libSQL
handles the row counts comfortably. The migration below assumes Model A.

## Schema changes

Add an `orgs` table and a non-null `org_id` foreign key to every tenant-scoped
table. The two current singletons (`brand`, `admin`) become **per-org** rows.

```sql
CREATE TABLE IF NOT EXISTS orgs (
  id          TEXT PRIMARY KEY,            -- uid()
  name        TEXT NOT NULL,
  slug        TEXT NOT NULL UNIQUE,        -- subdomain / login routing key
  plan        TEXT NOT NULL DEFAULT 'standard',
  seat_limit  INTEGER NOT NULL DEFAULT 0,  -- 0 = unlimited; enforced on learner create
  status      TEXT NOT NULL DEFAULT 'active', -- active | suspended | trial
  created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);
```

Tables that gain `org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE`:

| Table | Notes |
|---|---|
| `teams` | scope `name UNIQUE` → `UNIQUE(org_id, name)` |
| `users` | **`name UNIQUE` → `UNIQUE(org_id, name)`** — usernames must collide across orgs |
| `invite_codes` | `code` stays globally unique (it routes registration to an org) |
| `courses` | content is per-org (no shared catalogue in v1) |
| `modules`, `questions` | inherit via `course_id`, but add `org_id` too for direct-query filtering |
| `completions`, `module_progress`, `course_progress` | per-org |
| `assignments`, `question_responses` | per-org |
| `tags`, `learner_tags`, `tag_assignments` | `tags.name UNIQUE` → `UNIQUE(org_id, name)` |
| `brand` | drop the `id='default'` singleton; PK becomes `org_id` (one brand row per org) |
| `admin` | drop singleton; PK becomes `org_id`. Admin is now per-org, not global. |

**Uniqueness is the sharp edge.** Every current global `UNIQUE` (`users.name`,
`teams.name`, `tags.name`, `brand.id='default'`, `admin.id='default'`) must
become `UNIQUE(org_id, ...)` or it will block the second tenant. `cert_id` and
`invite_codes.code` stay globally unique by design.

## Auth / JWT changes

- **Embed `org_id` in every JWT** (admin, manager, learner) at sign time. This
  is the tenant claim that scopes all subsequent queries — never read `org_id`
  from the request body.
- Login routing: resolve the org from the login surface (subdomain slug, an
  org-scoped login URL, or an org picker after username). Admin login becomes
  per-org (look up `admin` row by `org_id`), removing the global
  `ADMIN_PASSWORD_HASH` as the primary path (keep it only as a break-glass
  bootstrap for org 0).
- The three middlewares (`requireAdmin`, `requireManager`, `requireLearner`)
  set `c.set('user', {...payload})` — add `org_id` to that user object so every
  handler has it.

## Query changes (the bulk of the work)

Every one of the 45+ routes that touches a tenant-scoped table must add
`WHERE org_id = ?` (and every `INSERT` must set `org_id`). Two ways to do this:

1. **Manual** — add `org_id = ?` to each query. ~45 routes; error-prone; one
   missed `WHERE` is a cross-tenant data leak.
2. **Enforced at a boundary (recommended)** — introduce a thin `db` wrapper that
   takes `org_id` from `c.get('user')` and a query builder that *requires* a
   tenant scope. This pairs naturally with the **planned Drizzle migration
   (S3)**: define a `withOrg(orgId)` repository layer so the scope cannot be
   forgotten. Doing tenancy and Drizzle together is more efficient than doing
   them sequentially.

**Recommendation:** do S3 (Drizzle) and multi-tenancy as one coordinated pass,
with a repository layer that bakes in `org_id`. Add a test (see
`worker/test/`) that asserts no cross-tenant read is possible for each role.

## Migration steps (Model A)

1. **Schema:** create `orgs`; add `org_id` columns (nullable first), backfill
   all existing rows to a single `org_id = 'org_default'`, then set `NOT NULL`.
2. **Uniqueness:** rebuild the composite `UNIQUE` constraints listed above.
   (SQLite/libSQL: create new table → copy → swap, or add new unique indexes
   and drop old ones.)
3. **Singletons:** migrate `brand` and `admin` rows to carry `org_id`.
4. **Auth:** add `org_id` to JWT signing + middleware user object; implement org
   resolution at login.
5. **Routes:** add tenant scope to every query (via the repository layer).
6. **Seat enforcement:** check `seat_limit` against active learner count on
   `POST /api/learners` and bulk import.
7. **Provisioning:** add an org-creation flow (super-admin or self-serve signup)
   that seeds `orgs` + first `admin` + default `brand`.
8. **Tests:** cross-tenant isolation tests per role must pass before deploy.

## Out of scope for v1 (later)

- DB-per-tenant enterprise tier (Model B).
- Shared/global course catalogue across orgs.
- SSO / SCIM / HRIS per-org (tracked separately in the web backlog).
- RevenueCat per-seat billing wiring (S4) — depends on `orgs.seat_limit`.

## Effort

Large. Rough sequencing: schema + uniqueness (~1 day), auth/org-resolution
(~1 day), repository layer + route scoping done alongside Drizzle (~3–5 days),
provisioning + seat limits (~1 day), isolation tests (~1 day). Best executed as
a single coordinated branch with the test harness gating merge.

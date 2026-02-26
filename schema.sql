-- ══════════════════════════════════════════════════════════
--  TrainFlow — Turso / libSQL schema
--  Compatible with libSQL (SQLite 3.44+)
--  json_group_array / json_object available for course queries
-- ══════════════════════════════════════════════════════════

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys  = ON;


-- ─── COURSES ─────────────────────────────────────────────
-- Top-level training unit visible to learners.

CREATE TABLE IF NOT EXISTS courses (
  id          TEXT    PRIMARY KEY,               -- uid() string e.g. "lc3k9a"
  icon        TEXT    NOT NULL DEFAULT '📋',
  title       TEXT    NOT NULL,
  description TEXT    NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TRIGGER IF NOT EXISTS trg_courses_updated_at
AFTER UPDATE ON courses
FOR EACH ROW WHEN OLD.updated_at = NEW.updated_at
BEGIN
  UPDATE courses SET updated_at = unixepoch() WHERE id = NEW.id;
END;


-- ─── MODULES ─────────────────────────────────────────────
-- Ordered sections within a course. Each module has prose content
-- followed by a competency quiz.
-- `sort_order` is set explicitly by the frontend and is independent
-- of insert order, so the UI can reorder modules without re-inserting.

CREATE TABLE IF NOT EXISTS modules (
  id         TEXT    PRIMARY KEY,
  course_id  TEXT    NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  title      TEXT    NOT NULL,
  content    TEXT    NOT NULL DEFAULT '',   -- HTML prose (sanitised before storage)
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_modules_course ON modules(course_id, sort_order);

CREATE TRIGGER IF NOT EXISTS trg_modules_updated_at
AFTER UPDATE ON modules
FOR EACH ROW WHEN OLD.updated_at = NEW.updated_at
BEGIN
  UPDATE modules SET updated_at = unixepoch() WHERE id = NEW.id;
END;


-- ─── QUESTIONS ───────────────────────────────────────────
-- Multiple-choice questions belonging to a module.
-- Always four options (A–D). correct_index: 0=A 1=B 2=C 3=D.
-- `sort_order` is set explicitly by the frontend.

CREATE TABLE IF NOT EXISTS questions (
  id            TEXT    PRIMARY KEY,
  module_id     TEXT    NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
  question      TEXT    NOT NULL,
  option_a      TEXT    NOT NULL DEFAULT '',
  option_b      TEXT    NOT NULL DEFAULT '',
  option_c      TEXT    NOT NULL DEFAULT '',
  option_d      TEXT    NOT NULL DEFAULT '',
  correct_index INTEGER NOT NULL DEFAULT 0,   -- 0=A  1=B  2=C  3=D
  explanation   TEXT    NOT NULL DEFAULT '',
  sort_order    INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_questions_module ON questions(module_id, sort_order);

CREATE TRIGGER IF NOT EXISTS trg_questions_updated_at
AFTER UPDATE ON questions
FOR EACH ROW WHEN OLD.updated_at = NEW.updated_at
BEGIN
  UPDATE questions SET updated_at = unixepoch() WHERE id = NEW.id;
END;


-- ─── COMPLETIONS ─────────────────────────────────────────
-- One row per quiz attempt. Multiple rows per learner+course are
-- allowed (retry support). cert_id is globally unique for verification.
-- Completions are logically immutable but updated_at is included for
-- schema consistency; the trigger handles any administrative corrections.

CREATE TABLE IF NOT EXISTS completions (
  id           TEXT    PRIMARY KEY,              -- uid() string
  course_id    TEXT    NOT NULL REFERENCES courses(id),
  learner_name TEXT    NOT NULL,
  score        INTEGER NOT NULL,                 -- 0–100 (whole number)
  passed       INTEGER NOT NULL DEFAULT 0,       -- 0 | 1  (SQLite boolean)
  completed_at INTEGER NOT NULL DEFAULT (unixepoch()),  -- Unix seconds
  updated_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  cert_id      TEXT    NOT NULL UNIQUE           -- "TF-" + 8 uppercase hex chars
);

CREATE INDEX IF NOT EXISTS idx_completions_learner ON completions(learner_name);
CREATE INDEX IF NOT EXISTS idx_completions_course  ON completions(course_id);
CREATE INDEX IF NOT EXISTS idx_completions_date    ON completions(completed_at DESC);

CREATE TRIGGER IF NOT EXISTS trg_completions_updated_at
AFTER UPDATE ON completions
FOR EACH ROW WHEN OLD.updated_at = NEW.updated_at
BEGIN
  UPDATE completions SET updated_at = unixepoch() WHERE id = NEW.id;
END;


-- ─── BRAND ───────────────────────────────────────────────
-- Single-row config table (id always = 'default').
-- Seeded on first deploy; updated via admin branding page.

CREATE TABLE IF NOT EXISTS brand (
  id              TEXT    PRIMARY KEY DEFAULT 'default',
  org_name        TEXT    NOT NULL DEFAULT 'TrainFlow',
  tagline         TEXT    NOT NULL DEFAULT 'Training & Certification Platform',
  logo_url        TEXT    NOT NULL DEFAULT '',
  primary_color   TEXT    NOT NULL DEFAULT '#2563eb',
  secondary_color TEXT    NOT NULL DEFAULT '#1d4ed8',
  pass_threshold  INTEGER NOT NULL DEFAULT 80,    -- percentage required to pass
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Seed the default row so GET /api/brand always returns something.
INSERT OR IGNORE INTO brand (id) VALUES ('default');

CREATE TRIGGER IF NOT EXISTS trg_brand_updated_at
AFTER UPDATE ON brand
FOR EACH ROW WHEN OLD.updated_at = NEW.updated_at
BEGIN
  UPDATE brand SET updated_at = unixepoch() WHERE id = NEW.id;
END;


-- ─── ADMIN ───────────────────────────────────────────────
-- Single-row admin credentials (id always = 'default').
--
-- Password storage strategy:
--   • On first deploy the worker reads ADMIN_PASSWORD_HASH from the
--     Cloudflare Worker environment secret (a pre-computed bcrypt hash).
--   • Subsequent password changes via the admin settings panel write
--     a new bcrypt hash to this table, which takes precedence.
--   • bcrypt embeds the salt in the hash string ($2b$10$<salt><hash>),
--     so no separate salt column is required.
--
-- Login lookup order:
--   1. SELECT password_hash FROM admin WHERE id = 'default'
--   2. If no row, fall back to env.ADMIN_PASSWORD_HASH

CREATE TABLE IF NOT EXISTS admin (
  id            TEXT    PRIMARY KEY DEFAULT 'default',
  password_hash TEXT    NOT NULL,   -- bcrypt hash, e.g. $2b$10$...
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TRIGGER IF NOT EXISTS trg_admin_updated_at
AFTER UPDATE ON admin
FOR EACH ROW WHEN OLD.updated_at = NEW.updated_at
BEGIN
  UPDATE admin SET updated_at = unixepoch() WHERE id = NEW.id;
END;

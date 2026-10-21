-- ══════════════════════════════════════════════════════════
--  Pregame Academy — Turso / libSQL schema
--  Compatible with libSQL (SQLite 3.44+)
-- ══════════════════════════════════════════════════════════

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys  = ON;


-- ─── TEAMS ───────────────────────────────────────────────
-- Organizational units.

CREATE TABLE IF NOT EXISTS teams (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  name         TEXT NOT NULL UNIQUE,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);


-- ─── USERS ────────────────────────────────────────────────
-- All database-backed accounts. Every account can take courses (learner); `role = 'manager'` adds
-- team management and `is_admin = 1` adds full administration, so one person can hold all three.
-- The legacy shared-password admin has no row here.

CREATE TABLE IF NOT EXISTS users (
  id            TEXT    PRIMARY KEY,              -- uid() string
  name          TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  role          TEXT    NOT NULL DEFAULT 'learner', -- 'manager' | 'learner'
  is_admin      INTEGER NOT NULL DEFAULT 0,         -- 1 = administrator (also keeps their learner/manager role)
  team_id       INTEGER REFERENCES teams(id),
  last_login_at INTEGER,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  email         TEXT,                     -- optional; used for Clerk email sign-in
  clerk_id      TEXT,                     -- Clerk user id, set on first email sign-in
  email_notifications INTEGER NOT NULL DEFAULT 1 -- 0 = no certificate emails
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_clerk_id ON users(clerk_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(lower(email));


-- ─── INVITE CODES ────────────────────────────────────────
-- Invites for manager and learner self-registration.

CREATE TABLE IF NOT EXISTS invite_codes (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  code         TEXT NOT NULL UNIQUE,
  role         TEXT NOT NULL DEFAULT 'manager',   -- 'manager' | 'learner'
  team_id      INTEGER REFERENCES teams(id),
  max_uses     INTEGER NOT NULL DEFAULT 1,        -- managers: 1; learner team links: up to 500
  use_count    INTEGER NOT NULL DEFAULT 0,
  used         INTEGER NOT NULL DEFAULT 0,        -- 1 once use_count reaches max_uses
  used_by      TEXT REFERENCES users(id),
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at   TEXT
);


-- ─── COURSES ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS courses (
  id          TEXT    PRIMARY KEY,
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

CREATE TABLE IF NOT EXISTS modules (
  id         TEXT    PRIMARY KEY,
  course_id  TEXT    NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  title      TEXT    NOT NULL,
  content    TEXT    NOT NULL DEFAULT '',
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

CREATE TABLE IF NOT EXISTS questions (
  id            TEXT    PRIMARY KEY,
  module_id     TEXT    NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
  question      TEXT    NOT NULL,
  option_a      TEXT    NOT NULL DEFAULT '',
  option_b      TEXT    NOT NULL DEFAULT '',
  option_c      TEXT    NOT NULL DEFAULT '',
  option_d      TEXT    NOT NULL DEFAULT '',
  correct_index INTEGER NOT NULL DEFAULT 0,
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

CREATE TABLE IF NOT EXISTS completions (
  id           TEXT    PRIMARY KEY,
  course_id    TEXT    NOT NULL REFERENCES courses(id),
  learner_id   TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  learner_name TEXT    NOT NULL,
  score        INTEGER NOT NULL,
  passed       INTEGER NOT NULL DEFAULT 0,
  completed_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  cert_id      TEXT    NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_completions_learner ON completions(learner_id);
CREATE INDEX IF NOT EXISTS idx_completions_course  ON completions(course_id);
CREATE INDEX IF NOT EXISTS idx_completions_date    ON completions(completed_at DESC);

CREATE TRIGGER IF NOT EXISTS trg_completions_updated_at
AFTER UPDATE ON completions
FOR EACH ROW WHEN OLD.updated_at = NEW.updated_at
BEGIN
  UPDATE completions SET updated_at = unixepoch() WHERE id = NEW.id;
END;


-- ─── MODULE PROGRESS ─────────────────────────────────────

CREATE TABLE IF NOT EXISTS module_progress (
  id           TEXT    PRIMARY KEY,
  learner_id   TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  module_id    TEXT    NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
  course_id    TEXT    NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  passed       INTEGER NOT NULL DEFAULT 0,
  score        INTEGER NOT NULL DEFAULT 0,
  completed_at INTEGER,
  created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE(learner_id, module_id)
);


-- ─── ASSIGNMENTS ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS assignments (
  course_id   TEXT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  learner_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  assigned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
  due_at      TEXT,
  PRIMARY KEY (course_id, learner_id)
);


-- ─── TAGS ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tags (
  id         TEXT    PRIMARY KEY,
  name       TEXT    NOT NULL UNIQUE,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS learner_tags (
  learner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tag_id     TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (learner_id, tag_id)
);

CREATE TABLE IF NOT EXISTS tag_assignments (
  course_id  TEXT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  tag_id     TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  due_at     TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (course_id, tag_id)
);


-- ─── QUESTION RESPONSES ──────────────────────────────────

CREATE TABLE IF NOT EXISTS question_responses (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  completion_id TEXT    NOT NULL REFERENCES completions(id) ON DELETE CASCADE,
  question_id   TEXT    NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
  is_correct    INTEGER NOT NULL,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_responses_question ON question_responses(question_id);


-- ─── BRAND ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS brand (
  id              TEXT    PRIMARY KEY DEFAULT 'default',
  org_name        TEXT    NOT NULL DEFAULT 'Pregame Academy',
  tagline         TEXT    NOT NULL DEFAULT 'Training & Certification Platform',
  logo_url        TEXT    NOT NULL DEFAULT '',
  primary_color   TEXT    NOT NULL DEFAULT '#1565ff',
  secondary_color TEXT    NOT NULL DEFAULT '#1b1a5c',
  pass_threshold  INTEGER NOT NULL DEFAULT 80,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT OR IGNORE INTO brand (id) VALUES ('default');


-- ─── COURSE PROGRESS ─────────────────────────────────────
-- Tracks per-learner resume position within a course.
-- NOTE: also created lazily by the worker on first progress write.

CREATE TABLE IF NOT EXISTS course_progress (
  learner_id TEXT    NOT NULL,
  course_id  TEXT    NOT NULL,
  module_idx INTEGER NOT NULL DEFAULT 0,
  modules    TEXT    NOT NULL DEFAULT '[]',
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (learner_id, course_id)
);


-- ─── ADMIN ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS admin (
  id            TEXT    PRIMARY KEY DEFAULT 'default',
  password_hash TEXT    NOT NULL,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
);


-- ─── QUIZ ANSWERS (server-graded; source of truth for completion scores) ──

CREATE TABLE IF NOT EXISTS quiz_answers (
  learner_id     TEXT    NOT NULL,
  question_id    TEXT    NOT NULL,
  selected_index INTEGER NOT NULL,
  is_correct     INTEGER NOT NULL,
  answered_at    INTEGER NOT NULL,
  PRIMARY KEY (learner_id, question_id)
);

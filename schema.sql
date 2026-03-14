-- ══════════════════════════════════════════════════════════
--  TrainFlow — Turso / libSQL schema
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
-- All database-backed accounts (Managers and Learners).
-- Hardcoded Admin does not have a row here.

CREATE TABLE IF NOT EXISTS users (
  id            TEXT    PRIMARY KEY,              -- uid() string
  name          TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  role          TEXT    NOT NULL DEFAULT 'learner', -- 'manager' | 'learner'
  team_id       INTEGER REFERENCES teams(id),
  last_login_at INTEGER,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);


-- ─── INVITE CODES ────────────────────────────────────────
-- Used for manager self-registration.

CREATE TABLE IF NOT EXISTS invite_codes (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  code         TEXT NOT NULL UNIQUE,
  role         TEXT NOT NULL DEFAULT 'manager',
  team_id      INTEGER REFERENCES teams(id),
  used         INTEGER NOT NULL DEFAULT 0,
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
  org_name        TEXT    NOT NULL DEFAULT 'TrainFlow',
  tagline         TEXT    NOT NULL DEFAULT 'Training & Certification Platform',
  logo_url        TEXT    NOT NULL DEFAULT '',
  primary_color   TEXT    NOT NULL DEFAULT '#2563eb',
  secondary_color TEXT    NOT NULL DEFAULT '#1d4ed8',
  pass_threshold  INTEGER NOT NULL DEFAULT 80,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT OR IGNORE INTO brand (id) VALUES ('default');


-- ─── ADMIN ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS admin (
  id            TEXT    PRIMARY KEY DEFAULT 'default',
  password_hash TEXT    NOT NULL,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

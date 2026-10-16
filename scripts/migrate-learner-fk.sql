-- Repoint stale foreign keys (learners -> users) on tables created by the old schema.
-- All four tables were empty in production when this was written (checked 2026-10-15).
-- Back up first:  turso db shell trainflow .dump > backup.sql
-- Run:            turso db shell trainflow < scripts/migrate-learner-fk.sql
-- NOTE: completions is handled separately below; it has a TEXT PK referenced by question_responses.

DROP TABLE IF EXISTS assignments;
CREATE TABLE assignments (
  course_id   TEXT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  learner_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
  due_at      TEXT,
  assigned_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
  PRIMARY KEY (course_id, learner_id)
);

DROP TABLE IF EXISTS learner_tags;
CREATE TABLE learner_tags (
  learner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tag_id     TEXT NOT NULL REFERENCES tags(id)  ON DELETE CASCADE,
  PRIMARY KEY (learner_id, tag_id)
);

DROP TABLE IF EXISTS module_progress;
CREATE TABLE module_progress (
  id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  learner_id   TEXT NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
  module_id    TEXT NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
  course_id    TEXT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  passed       INTEGER NOT NULL DEFAULT 0,
  score        INTEGER NOT NULL DEFAULT 0,
  completed_at INTEGER,
  created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE(learner_id, module_id)
);
CREATE INDEX idx_module_progress_learner ON module_progress(learner_id, course_id);

-- completions: only learner_id carries the stale FK. SQLite can't alter a FK in place,
-- so rebuild it (and its indexes). question_responses references completions(id).
DROP TABLE IF EXISTS question_responses;
DROP TABLE IF EXISTS completions;
CREATE TABLE completions (
  id           TEXT    PRIMARY KEY,
  course_id    TEXT    NOT NULL REFERENCES courses(id),
  learner_name TEXT    NOT NULL,
  score        INTEGER NOT NULL,
  passed       INTEGER NOT NULL DEFAULT 0,
  completed_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  cert_id      TEXT    NOT NULL UNIQUE,
  learner_id   TEXT    REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_completions_learner ON completions(learner_name);
CREATE INDEX idx_completions_course  ON completions(course_id);
CREATE INDEX idx_completions_date    ON completions(completed_at DESC);

CREATE TABLE question_responses (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  completion_id TEXT    NOT NULL REFERENCES completions(id) ON DELETE CASCADE,
  question_id   TEXT    NOT NULL REFERENCES questions(id)   ON DELETE CASCADE,
  is_correct    INTEGER NOT NULL DEFAULT 0
);

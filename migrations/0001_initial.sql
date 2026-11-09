CREATE TABLE IF NOT EXISTS mocks (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  subjects_json TEXT NOT NULL DEFAULT '[]',
  duration_minutes INTEGER NOT NULL CHECK (duration_minutes > 0),
  question_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'draft'
    CHECK (status IN ('draft', 'published', 'archived')),
  available_from TEXT,
  available_until TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS students (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS access_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash TEXT NOT NULL UNIQUE,
  is_active INTEGER NOT NULL DEFAULT 1
    CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  redeemed_at TEXT,
  redeemed_by_student_id TEXT REFERENCES students(id),
  redeemed_for_mock_id TEXT REFERENCES mocks(id)
);

CREATE TABLE IF NOT EXISTS questions (
  id TEXT PRIMARY KEY,
  mock_id TEXT NOT NULL REFERENCES mocks(id) ON DELETE CASCADE,
  question_text TEXT NOT NULL,
  options_json TEXT NOT NULL,
  correct_option TEXT NOT NULL,
  explanation TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS attempts (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL REFERENCES students(id),
  mock_id TEXT NOT NULL REFERENCES mocks(id),
  started_at TEXT NOT NULL,
  submitted_at TEXT,
  status TEXT NOT NULL DEFAULT 'in_progress'
    CHECK (status IN ('in_progress', 'submitted', 'expired')),
  score REAL,
  total_questions INTEGER
);

CREATE TABLE IF NOT EXISTS answers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attempt_id TEXT NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
  question_id TEXT NOT NULL REFERENCES questions(id),
  selected_option TEXT,
  answered_at TEXT NOT NULL,
  UNIQUE (attempt_id, question_id)
);

CREATE INDEX IF NOT EXISTS idx_mocks_status
ON mocks(status);

CREATE INDEX IF NOT EXISTS idx_access_codes_active_used
ON access_codes(is_active, redeemed_at);

CREATE INDEX IF NOT EXISTS idx_attempts_student
ON attempts(student_id);

CREATE INDEX IF NOT EXISTS idx_attempts_mock
ON attempts(mock_id);

CREATE INDEX IF NOT EXISTS idx_questions_mock_order
ON questions(mock_id, sort_order);

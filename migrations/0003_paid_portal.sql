
-- A² Tutorials Paid Student Portal
-- Separate tables: existing public CBT tables remain untouched.

CREATE TABLE IF NOT EXISTS paid_student_ids (
  id TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  is_active INTEGER NOT NULL DEFAULT 1
    CHECK (is_active IN (0, 1)),
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  redeemed_at TEXT,
  redeemed_by_email TEXT
);

CREATE TABLE IF NOT EXISTS paid_students (
  id TEXT PRIMARY KEY,
  student_id_id TEXT NOT NULL UNIQUE
    REFERENCES paid_student_ids(id),
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  profile_picture_url TEXT,
  subjects_json TEXT NOT NULL DEFAULT '[]',
  dream_score INTEGER,
  aspiring_course TEXT,
  aspiring_university TEXT,
  profile_completed INTEGER NOT NULL DEFAULT 0
    CHECK (profile_completed IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS paid_student_sessions (
  session_hash TEXT PRIMARY KEY,
  student_id TEXT NOT NULL
    REFERENCES paid_students(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS paid_announcements (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  is_published INTEGER NOT NULL DEFAULT 1
    CHECK (is_published IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS paid_mocks (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  scheduled_date TEXT NOT NULL,
  duration_minutes INTEGER NOT NULL CHECK (duration_minutes > 0),
  status TEXT NOT NULL DEFAULT 'draft'
    CHECK (status IN ('draft', 'published', 'unpublished')),
  review_mode TEXT NOT NULL DEFAULT 'after_results'
    CHECK (review_mode IN ('immediate', 'after_results')),
  results_released INTEGER NOT NULL DEFAULT 0
    CHECK (results_released IN (0, 1)),
  published_at TEXT,
  unpublished_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS paid_mock_subjects (
  id TEXT PRIMARY KEY,
  mock_id TEXT NOT NULL
    REFERENCES paid_mocks(id) ON DELETE CASCADE,
  subject_name TEXT NOT NULL,
  question_count INTEGER NOT NULL DEFAULT 0,
  sort_order INTEGER NOT NULL DEFAULT 0,
  UNIQUE (mock_id, subject_name)
);

CREATE TABLE IF NOT EXISTS paid_mock_questions (
  id TEXT PRIMARY KEY,
  mock_id TEXT NOT NULL
    REFERENCES paid_mocks(id) ON DELETE CASCADE,
  subject_id TEXT NOT NULL
    REFERENCES paid_mock_subjects(id) ON DELETE CASCADE,
  question_text TEXT NOT NULL,
  options_json TEXT NOT NULL,
  correct_option TEXT NOT NULL,
  explanation TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS paid_mock_attempts (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL
    REFERENCES paid_students(id),
  mock_id TEXT NOT NULL
    REFERENCES paid_mocks(id),
  started_at TEXT NOT NULL,
  deadline_at TEXT NOT NULL,
  submitted_at TEXT,
  status TEXT NOT NULL DEFAULT 'in_progress'
    CHECK (status IN ('in_progress', 'submitted', 'expired')),
  score REAL,
  total_questions INTEGER,
  UNIQUE (student_id, mock_id)
);

CREATE TABLE IF NOT EXISTS paid_mock_answers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attempt_id TEXT NOT NULL
    REFERENCES paid_mock_attempts(id) ON DELETE CASCADE,
  question_id TEXT NOT NULL
    REFERENCES paid_mock_questions(id),
  selected_option TEXT,
  answered_at TEXT NOT NULL,
  UNIQUE (attempt_id, question_id)
);

CREATE TABLE IF NOT EXISTS paid_videos (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  video_url TEXT NOT NULL,
  platform TEXT NOT NULL
    CHECK (platform IN ('YouTube', 'TikTok')),
  is_published INTEGER NOT NULL DEFAULT 1
    CHECK (is_published IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_paid_ids_active_expiry
ON paid_student_ids(is_active, expires_at);

CREATE INDEX IF NOT EXISTS idx_paid_sessions_student
ON paid_student_sessions(student_id, expires_at);

CREATE INDEX IF NOT EXISTS idx_paid_mocks_schedule
ON paid_mocks(scheduled_date, status);

CREATE INDEX IF NOT EXISTS idx_paid_mock_questions_subject
ON paid_mock_questions(subject_id, sort_order);

CREATE INDEX IF NOT EXISTS idx_paid_attempts_student
ON paid_mock_attempts(student_id, started_at);

CREATE INDEX IF NOT EXISTS idx_paid_announcements_published
ON paid_announcements(is_published, created_at);

CREATE INDEX IF NOT EXISTS idx_paid_videos_published
ON paid_videos(is_published, created_at);

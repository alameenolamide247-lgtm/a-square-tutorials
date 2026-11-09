CREATE TABLE IF NOT EXISTS videos (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  video_url TEXT NOT NULL,
  platform TEXT NOT NULL
    CHECK (platform IN ('YouTube', 'TikTok')),
  is_published INTEGER NOT NULL DEFAULT 1
    CHECK (is_published IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_videos_published
ON videos(is_published, created_at);

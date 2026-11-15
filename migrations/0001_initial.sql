PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS enquiries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL CHECK (type IN ('loan', 'account')),
  full_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT,
  details_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'reviewing', 'contacted', 'closed')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_enquiries_status_created ON enquiries(status, created_at DESC);

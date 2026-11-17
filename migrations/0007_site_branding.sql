PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS site_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value TEXT NOT NULL DEFAULT '',
  updated_by INTEGER REFERENCES customers(id),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

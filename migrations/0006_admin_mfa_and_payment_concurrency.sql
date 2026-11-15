PRAGMA foreign_keys = ON;
ALTER TABLE customers ADD COLUMN admin_totp_secret TEXT;
ALTER TABLE customers ADD COLUMN admin_totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN mfa_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE loan_applications ADD COLUMN payment_version INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS admin_mfa_recovery_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_admin_mfa_recovery_customer ON admin_mfa_recovery_codes(customer_id,used_at);
CREATE TABLE IF NOT EXISTS payment_assertions (
  ok INTEGER NOT NULL CHECK(ok=1)
);

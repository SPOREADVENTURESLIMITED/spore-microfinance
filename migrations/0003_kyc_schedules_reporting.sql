PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS kyc_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL UNIQUE REFERENCES customers(id) ON DELETE CASCADE,
  date_of_birth TEXT NOT NULL,
  residential_address TEXT NOT NULL,
  district TEXT NOT NULL,
  occupation TEXT NOT NULL,
  document_type TEXT NOT NULL CHECK(document_type IN ('national_id','passport','driving_permit','voter_card')),
  document_last4 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'submitted' CHECK(status IN ('submitted','reviewing','verified','rejected')),
  reviewer_id INTEGER REFERENCES customers(id),
  review_note TEXT NOT NULL DEFAULT '',
  submitted_at TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_kyc_status ON kyc_profiles(status, submitted_at DESC);

CREATE TABLE IF NOT EXISTS loan_terms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  application_id INTEGER NOT NULL UNIQUE REFERENCES loan_applications(id),
  principal_ugx INTEGER NOT NULL CHECK(principal_ugx > 0),
  monthly_rate_bps INTEGER NOT NULL CHECK(monthly_rate_bps BETWEEN 0 AND 10000),
  total_interest_ugx INTEGER NOT NULL DEFAULT 0,
  total_payable_ugx INTEGER NOT NULL,
  disbursement_date TEXT NOT NULL,
  first_due_date TEXT NOT NULL,
  created_by INTEGER REFERENCES customers(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS repayment_schedule (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  application_id INTEGER NOT NULL REFERENCES loan_applications(id),
  installment_no INTEGER NOT NULL,
  due_date TEXT NOT NULL,
  principal_due_ugx INTEGER NOT NULL,
  interest_due_ugx INTEGER NOT NULL,
  amount_due_ugx INTEGER NOT NULL,
  principal_paid_ugx INTEGER NOT NULL DEFAULT 0,
  interest_paid_ugx INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','partial','paid')),
  paid_at TEXT,
  UNIQUE(application_id, installment_no)
);
CREATE INDEX IF NOT EXISTS idx_schedule_due ON repayment_schedule(due_date,status);
CREATE TABLE IF NOT EXISTS repayment_allocations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repayment_id INTEGER NOT NULL REFERENCES repayments(id) ON DELETE CASCADE,
  schedule_id INTEGER NOT NULL REFERENCES repayment_schedule(id),
  principal_ugx INTEGER NOT NULL DEFAULT 0,
  interest_ugx INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alloc_repayment ON repayment_allocations(repayment_id);

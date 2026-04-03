-- PostgreSQL schema for gemhunter-auth (run once against DATABASE_URL database)

CREATE TABLE IF NOT EXISTS licenses (
  license_key   TEXT PRIMARY KEY,
  expiry_date   DATE NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active',
  hwid          TEXT,
  customer_name TEXT
);

CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses (status);

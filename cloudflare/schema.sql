-- KudexTech License API D1 schema
-- Safe to run repeatedly. Existing vps_licenses rows are preserved.

CREATE TABLE IF NOT EXISTS vps_licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_address TEXT NOT NULL UNIQUE,
  license_type TEXT NOT NULL CHECK (license_type IN ('trial', '30_days', 'lifetime')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vps_licenses_status
  ON vps_licenses(status);

CREATE INDEX IF NOT EXISTS idx_vps_licenses_expiry
  ON vps_licenses(expires_at);

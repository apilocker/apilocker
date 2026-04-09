-- Migration: add country column to audit_logs (v1.0.0 launch tracking)
--
-- Captures the 2-letter country code from Cloudflare's CF-IPCountry
-- header on every audit log insert. Used by the admin analytics
-- dashboard to show geographic distribution of users.
--
-- Backwards compatible: all existing rows get NULL. New rows are
-- populated automatically by the audit log insert path going forward.

ALTER TABLE audit_logs ADD COLUMN country TEXT;
CREATE INDEX IF NOT EXISTS idx_audit_logs_country ON audit_logs(country);

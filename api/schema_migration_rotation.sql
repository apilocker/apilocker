-- Migration: track rotation timestamps on credentials.
--
-- Adds a nullable `rotated_at` column to keys_metadata. Populated by the
-- new POST /v1/keys/:keyId/rotate endpoint (v0.4.0) every time a credential
-- is rotated. Used by the v0.5.0 `apilocker doctor` command to surface
-- stale credentials ("your Stripe key hasn't been rotated in 180 days").
--
-- Backwards compatible: NULL means "never rotated since storage" (which
-- is indistinguishable from "rotated at created_at" for reporting).

ALTER TABLE keys_metadata ADD COLUMN rotated_at TEXT;

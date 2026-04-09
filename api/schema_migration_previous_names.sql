-- Migration: lossless rename via previous_names fallback (v1.0.0 pre-publish fix)
--
-- Adds a `previous_names` column to keys_metadata that stores a JSON
-- array of historical names for each credential. The reveal endpoint
-- uses this as a fallback when a caller asks for a name that doesn't
-- match any current credential — if the requested name appears in
-- some row's previous_names array, that row is returned with a
-- `deprecated_alias` flag. This makes renames 100% non-breaking:
-- existing .apilockerrc files and app code that reference old names
-- keep working indefinitely.
--
-- Name-recycling semantics: if a user later stores a NEW credential
-- under a name that's currently in some other row's previous_names,
-- the store handler purges the name from that row's history (the new
-- credential "reclaims" the name). This is enforced by the application,
-- not the DB, so the column stays simple.
--
-- Backwards compatible: existing rows are populated with '[]' and the
-- fallback logic treats missing / null / malformed values as empty.

ALTER TABLE keys_metadata ADD COLUMN previous_names TEXT DEFAULT '[]';

-- Backfill any existing NULL values (shouldn't be any given the DEFAULT,
-- but belt-and-suspenders)
UPDATE keys_metadata SET previous_names = '[]' WHERE previous_names IS NULL;

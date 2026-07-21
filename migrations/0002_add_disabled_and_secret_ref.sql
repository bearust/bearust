-- The columns are included in 0001 so upgrades from databases created by the
-- pre-migration bootstrap are safe on every SQLx backend.  This migration is
-- retained as the ordered additive compatibility marker for those upgrades.
SELECT 1;

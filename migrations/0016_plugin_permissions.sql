-- Plugin permissions are seeded by repository::migrate after the schema
-- migrations. This marker keeps the additive migration ordering explicit and
-- remains portable across SQLite, PostgreSQL, and MySQL.
SELECT 1;

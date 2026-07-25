-- Legacy upgrades are completed by repository::migrate's backend-aware column
-- checks. Keeping this migration side-effect free makes it safe on SQLite,
-- MySQL, and PostgreSQL while fresh databases receive the column at startup.
SELECT 1;

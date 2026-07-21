-- Legacy upgrades are completed by repository::migrate's backend-aware column
-- checks. Keeping this migration side-effect free makes it safe on fresh DBs.
SELECT 1;

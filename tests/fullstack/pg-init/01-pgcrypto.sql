-- Full-stack E2E Postgres init (runs once on an empty data dir), mirroring the
-- parent dev stack. The `sessionlayer` owner role + database come from the
-- container env; the CP's Flyway migrations own all application schema. pgcrypto
-- provides digest()/crypt() a few migrations use (gen_random_uuid is core in PG17).
CREATE EXTENSION IF NOT EXISTS pgcrypto;

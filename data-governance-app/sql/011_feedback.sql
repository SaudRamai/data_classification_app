create schema if not exists scan_catalog;

create table if not exists scan_catalog.feedback (
  feedback_id number autoincrement,
  object_type text,
  table_catalog text,
  table_schema text,
  table_name text,
  column_name text,
  action text,
  payload variant,
  user_id text,
  username text,
  created_at timestamp_ntz default current_timestamp(),
  primary key (feedback_id)
);

-- Example grants (adjust to your roles)
-- grant usage on schema scan_catalog to role DATA_STEWARD;
-- grant select, insert on table scan_catalog.feedback to role DATA_STEWARD;

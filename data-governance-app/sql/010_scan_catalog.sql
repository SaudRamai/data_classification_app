-- Configure database and warehouse context
set DB = coalesce($DATABASE, current_database());
set WH = coalesce($WAREHOUSE, current_warehouse());

use database identifier($DB);

create schema if not exists scan_catalog;

create table if not exists scan_catalog.tables (
  table_catalog text,
  table_schema text,
  table_name text,
  table_type text,
  is_transient boolean,
  is_external boolean,
  is_view boolean,
  row_count number,
  created timestamp_ntz,
  last_altered timestamp_ntz,
  last_commit_time timestamp_ntz,
  refreshed_at timestamp_ntz default current_timestamp(),
  primary key (table_catalog, table_schema, table_name)
);

create table if not exists scan_catalog.columns (
  table_catalog text,
  table_schema text,
  table_name text,
  column_name text,
  data_type text,
  is_nullable text,
  ordinal_position number,
  refreshed_at timestamp_ntz default current_timestamp(),
  primary key (table_catalog, table_schema, table_name, column_name)
);

create table if not exists scan_catalog.table_samples (
  table_catalog text,
  table_schema text,
  table_name text,
  column_name text,
  samples variant,
  sampled_at timestamp_ntz default current_timestamp(),
  primary key (table_catalog, table_schema, table_name, column_name)
);

-- Stored procedure to refresh from ACCOUNT_USAGE (fast, includes external/transient, and views)
create or replace procedure scan_catalog.sp_refresh_account_usage()
returns string
language javascript
as
$$
var sqls = [];
sqls.push(`merge into scan_catalog.tables tgt using (
  select 
    t.table_catalog,
    t.table_schema,
    t.table_name,
    t.table_type,
    iff(lower(t.is_transient)='true', true, false) as is_transient,
    iff(t.table_type='EXTERNAL TABLE', true, false) as is_external,
    false as is_view,
    t.row_count,
    t.created,
    t.last_altered,
    t.last_commit_time
  from snowflake.account_usage.tables t
) src
on (tgt.table_catalog=src.table_catalog and tgt.table_schema=src.table_schema and tgt.table_name=src.table_name)
when matched then update set 
  table_type=src.table_type,
  is_transient=src.is_transient,
  is_external=src.is_external,
  is_view=src.is_view,
  row_count=src.row_count,
  created=src.created,
  last_altered=src.last_altered,
  last_commit_time=src.last_commit_time,
  refreshed_at=current_timestamp()
when not matched then insert (
  table_catalog, table_schema, table_name, table_type, is_transient, is_external, is_view, row_count, created, last_altered, last_commit_time
) values (
  src.table_catalog, src.table_schema, src.table_name, src.table_type, src.is_transient, src.is_external, src.is_view, src.row_count, src.created, src.last_altered, src.last_commit_time
);`);

sqls.push(`merge into scan_catalog.tables tgt using (
  select 
    v.table_catalog,
    v.table_schema,
    v.table_name,
    'VIEW' as table_type,
    false as is_transient,
    false as is_external,
    true as is_view,
    null as row_count,
    v.created,
    v.last_altered,
    null as last_commit_time
  from snowflake.account_usage.views v
) src
on (tgt.table_catalog=src.table_catalog and tgt.table_schema=src.table_schema and tgt.table_name=src.table_name)
when matched then update set 
  table_type=src.table_type,
  is_transient=src.is_transient,
  is_external=src.is_external,
  is_view=src.is_view,
  row_count=src.row_count,
  created=src.created,
  last_altered=src.last_altered,
  refreshed_at=current_timestamp()
when not matched then insert (
  table_catalog, table_schema, table_name, table_type, is_transient, is_external, is_view, row_count, created, last_altered, last_commit_time
) values (
  src.table_catalog, src.table_schema, src.table_name, src.table_type, src.is_transient, src.is_external, src.is_view, src.row_count, src.created, src.last_altered, src.last_commit_time
);`);

sqls.push(`merge into scan_catalog.columns tgt using (
  select 
    c.table_catalog,
    c.table_schema,
    c.table_name,
    c.column_name,
    c.data_type,
    c.is_nullable,
    c.ordinal_position
  from snowflake.account_usage.columns c
  where c.table_catalog is not null and c.table_schema is not null and c.table_name is not null
) src
on (
  tgt.table_catalog=src.table_catalog and tgt.table_schema=src.table_schema and tgt.table_name=src.table_name and tgt.column_name=src.column_name
)
when matched then update set 
  data_type=src.data_type,
  is_nullable=src.is_nullable,
  ordinal_position=src.ordinal_position,
  refreshed_at=current_timestamp()
when not matched then insert (
  table_catalog, table_schema, table_name, column_name, data_type, is_nullable, ordinal_position
) values (
  src.table_catalog, src.table_schema, src.table_name, src.column_name, src.data_type, src.is_nullable, src.ordinal_position
);`);

for (var i=0; i<sqls.length; i++) {
  snowflake.execute({sqlText: sqls[i]});
}
return 'OK';
$$;

-- Daily task to refresh (adjust warehouse, schedule, and role as needed)
-- Ensure current role has EXECUTE TASK and OWNERSHIP on objects
create or replace task scan_catalog.task_daily_refresh
warehouse = identifier($WH)
schedule = 'USING CRON 0 2 * * * UTC'
comment = 'Daily refresh of scan catalog from ACCOUNT_USAGE'
as
call scan_catalog.sp_refresh_account_usage();

-- To enable the task
-- alter task scan_catalog.task_daily_refresh resume;

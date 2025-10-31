-- Snowflake Tasks to enforce SLA checks and enqueue notifications (no static values)
-- Requires: DATA_CLASSIFICATION_GOVERNANCE schema, CHECKS, CHECK_RESULTS, VIOLATIONS, APP_SETTINGS, CLASSIFICATION_QUEUE, NOTIFICATIONS_OUTBOX
-- Run as a privileged role with USAGE on target warehouse and OWNERSHIP on DATA_CLASSIFICATION_GOVERNANCE objects.

-- Configure
set dbname = current_database();
set sch    = 'DATA_CLASSIFICATION_GOVERNANCE';
set wh     = '{{YOUR_WAREHOUSE}}'; -- replace before running

-- Ensure settings and outbox tables exist
create schema if not exists identifier($dbname)||'.'||identifier($sch);
create table if not exists identifier($dbname)||'.'||identifier($sch)||'.APP_SETTINGS' (
  KEY string primary key,
  VALUE string
);
create table if not exists identifier($dbname)||'.'||identifier($sch)||'.NOTIFICATIONS_OUTBOX' (
  ID string,
  CREATED_AT timestamp_ntz default current_timestamp,
  CHANNEL string,
  TARGET string,
  SUBJECT string,
  BODY string,
  SENT_AT timestamp_ntz,
  SENT_RESULT string
);

-- Helper view to resolve SLA values with defaults (no static hardcoding in tasks below)
create or replace view identifier($dbname)||'.'||identifier($sch)||'.SLA_CONFIG' as
select 
  coalesce(try_to_number((select value from identifier($dbname)||'.'||identifier($sch)||'.APP_SETTINGS' where key='SLA_PROVISIONAL_IA_DAYS')), 7) as SLA_PROVISIONAL_IA_DAYS,
  coalesce(try_to_number((select value from identifier($dbname)||'.'||identifier($sch)||'.APP_SETTINGS' where key='SLA_UNCLASSIFIED_BD_THRESHOLD')), 5) as SLA_UNCLASSIFIED_BD_THRESHOLD
;

-- Task: Provisional I/A overdue check → writes to CHECK_RESULTS and VIOLATIONS; enqueues notification when overdue>0
create or replace task identifier($dbname)||'.'||identifier($sch)||'.TASK_IA_PROVISIONAL_REVIEW'
  warehouse = identifier($wh)
  schedule = 'USING CRON 0 2 * * * America/Los_Angeles'  -- daily at 02:00 PT
as
begin
  let sla_days number := (select SLA_PROVISIONAL_IA_DAYS from identifier($dbname)||'.'||identifier($sch)||'.SLA_CONFIG');
  -- Count overdue provisional
  create or replace temporary table tmp_overdue as
  select distinct asset_full_name as full
  from identifier($dbname)||'.'||identifier($sch)||'.CLASSIFICATION_QUEUE'
  where reason = 'PROVISIONAL_IA'
    and coalesce(created_at, current_timestamp()) < dateadd(day, -sla_days, current_timestamp());

  -- Upsert check result row
  insert into identifier($dbname)||'.'||identifier($sch)||'.CHECK_RESULTS'
  (ID, CHECK_CODE, RESULT, DETAILS, CREATED_AT)
  select uuid_string(), 'IA_PROVISIONAL_REVIEW', case when count(*)>0 then 'FAIL' else 'PASS' end,
         object_construct('overdue', count(*), 'sla_days', :sla_days), current_timestamp()
  from tmp_overdue;

  -- Insert violations per asset
  insert into identifier($dbname)||'.'||identifier($sch)||'.VIOLATIONS'
  (ID, FRAMEWORK, CHECK_CODE, ASSET_FULL_NAME, SEVERITY, DETAILS, CREATED_AT)
  select uuid_string(), 'SOC2', 'IA_PROVISIONAL_REVIEW', full, 'Medium',
         object_construct('reason','Provisional I/A overdue','sla_days', :sla_days), current_timestamp()
  from tmp_overdue;

  -- Enqueue notification if any
  insert into identifier($dbname)||'.'||identifier($sch)||'.NOTIFICATIONS_OUTBOX'
  (ID, CHANNEL, TARGET, SUBJECT, BODY)
  select uuid_string(), 'SLACK', null,
         'Provisional I/A overdue',
         'There are '||count(*)||' assets overdue for I/A finalization (SLA='||:sla_days||' days).'
  from tmp_overdue
  having count(*) > 0;
end;

-- Task: Unclassified > N business days (approximate as calendar days; replace with business calendar if available)
create or replace task identifier($dbname)||'.'||identifier($sch)||'.TASK_SLA_5_DAY_OVERDUE'
  warehouse = identifier($wh)
  schedule = 'USING CRON 30 2 * * * America/Los_Angeles'
as
begin
  let bd number := (select SLA_UNCLASSIFIED_BD_THRESHOLD from identifier($dbname)||'.'||identifier($sch)||'.SLA_CONFIG');
  -- Approximate discovery: tables/views without DATA_CLASSIFICATION tag
  create or replace temporary table tmp_uncls as
  with objs as (
    select table_schema||'.'||table_name as fqn
    from identifier($dbname)||'.INFORMATION_SCHEMA.TABLES'
    where table_schema not in ('INFORMATION_SCHEMA')
    union all
    select table_schema||'.'||table_name as fqn
    from identifier($dbname)||'.INFORMATION_SCHEMA.VIEWS'
    where table_schema not in ('INFORMATION_SCHEMA')
  )
  select fqn
  from objs o
  where not exists (
    select 1 from "SNOWFLAKE"."ACCOUNT_USAGE"."TAG_REFERENCES" tr
    where upper(tr.tag_name)='DATA_CLASSIFICATION' and tr.object_database = $dbname and tr.object_schema||'.'||tr.object_name = o.fqn
  );

  insert into identifier($dbname)||'.'||identifier($sch)||'.CHECK_RESULTS'
  (ID, CHECK_CODE, RESULT, DETAILS, CREATED_AT)
  select uuid_string(), 'SLA_5_DAY_OVERDUE', case when count(*)>0 then 'FAIL' else 'PASS' end,
         object_construct('unclassified', count(*), 'threshold_days', :bd), current_timestamp()
  from tmp_uncls;

  insert into identifier($dbname)||'.'||identifier($sch)||'.VIOLATIONS'
  (ID, FRAMEWORK, CHECK_CODE, ASSET_FULL_NAME, SEVERITY, DETAILS, CREATED_AT)
  select uuid_string(), 'SOC2', 'SLA_5_DAY_OVERDUE', fqn, 'Medium',
         object_construct('reason','Unclassified beyond threshold','threshold_days', :bd), current_timestamp()
  from tmp_uncls;

  insert into identifier($dbname)||'.'||identifier($sch)||'.NOTIFICATIONS_OUTBOX'
  (ID, CHANNEL, TARGET, SUBJECT, BODY)
  select uuid_string(), 'SLACK', null,
         'Unclassified assets beyond SLA',
         'There are '||count(*)||' unclassified objects beyond the SLA threshold ('||:bd||' days).'
  from tmp_uncls
  having count(*) > 0;
end;

-- Enable tasks (edit warehouse name above first)
alter task if exists identifier($dbname)||'.'||identifier($sch)||'.TASK_IA_PROVISIONAL_REVIEW' resume;
alter task if exists identifier($dbname)||'.'||identifier($sch)||'.TASK_SLA_5_DAY_OVERDUE' resume;

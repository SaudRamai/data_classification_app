-- 007_classification_objects.sql
-- Governance objects for Classification Center
-- Creates missing tables and views referenced by the app UI

-- Configuration
set dbname = coalesce($DATABASE, current_database());
set sch    = 'DATA_GOVERNANCE';

use database identifier($dbname);
create schema if not exists identifier($sch);

-- =============================
-- Tables
-- =============================
-- Tasks assigned to users for classification work
create table if not exists identifier($dbname)||'.'||identifier($sch)||'.CLASSIFICATION_TASKS' (
  ID string,
  ASSET_FULL_NAME string,         -- DB.SCHEMA.OBJECT
  TITLE string,
  DESCRIPTION string,
  PRIORITY string,                -- Low/Medium/High/Urgent
  STATUS string,                  -- Assigned/In Progress/Pending Review/Completed/Closed
  ASSIGNED_TO string,             -- user or group
  CREATED_BY string,
  DUE_DATE date,
  CREATED_AT timestamp_ntz default current_timestamp(),
  UPDATED_AT timestamp_ntz,
  DETAILS variant
);

-- Decisions recorded per asset (used by live feed and audit)
create table if not exists identifier($dbname)||'.'||identifier($sch)||'.CLASSIFICATION_DECISIONS' (
  ID string,
  ASSET_FULL_NAME string,
  CLASSIFICATION_LABEL string,    -- Public/Internal/Restricted/Confidential
  C number,
  I number,
  A number,
  DECISION_MAKER string,
  SOURCE string,                  -- NEW_CLASSIFICATION / REVIEW / BULK / AI
  STATUS string,                  -- SUBMITTED/APPROVED/REJECTED/APPLIED
  RATIONALE string,
  DETAILS variant,
  CREATED_AT timestamp_ntz default current_timestamp(),
  UPDATED_AT timestamp_ntz
);

-- Ensure alert logs table exists in DATA_GOVERNANCE (some envs created it elsewhere)
create table if not exists identifier($dbname)||'.'||identifier($sch)||'.ALERT_LOGS' (
  ALERT_ID string,
  ALERT_TYPE string,
  ALERT_PRIORITY string,
  ALERT_STATUS string,
  ASSET_FULL_NAME string,
  ALERT_TITLE string,
  ALERT_MESSAGE string,
  ALERT_DETAILS variant,
  ASSIGNED_TO string,
  DUE_DATE date,
  CREATED_BY string,
  CREATED_TIMESTAMP timestamp_ntz default current_timestamp(),
  ACKNOWLEDGED_TIMESTAMP timestamp_ntz,
  RESOLVED_TIMESTAMP timestamp_ntz,
  RESOLUTION_NOTES string
);

-- =============================
-- Views - Classification Management
-- =============================
-- My Classification Tasks
create or replace view identifier($dbname)||'.'||identifier($sch)||'.VW_MY_CLASSIFICATION_TASKS' as
select 
  ID, ASSET_FULL_NAME, TITLE, DESCRIPTION, PRIORITY, STATUS, ASSIGNED_TO,
  CREATED_BY, DUE_DATE, CREATED_AT, UPDATED_AT, DETAILS
from identifier($dbname)||'.'||identifier($sch)||'.CLASSIFICATION_TASKS'
where upper(coalesce(ASSIGNED_TO,'')) = upper(current_user());

-- Pending Reviews from reclassification requests
create or replace view identifier($dbname)||'.'||identifier($sch)||'.VW_CLASSIFICATION_REVIEWS' as
select 
  ID,
  ASSET_FULL_NAME,
  REQUESTED_BY as CREATED_BY,
  CURRENT_LABEL,
  REQUESTED_LABEL,
  STATUS,
  CREATED_AT,
  UPDATED_AT,
  DETAILS
from identifier($dbname)||'.'||identifier($sch)||'.RECLASSIFICATION_REQUESTS'
where upper(coalesce(STATUS,'')) in ('SUBMITTED');

-- =============================
-- Views - Alerts
-- =============================
create or replace view identifier($dbname)||'.'||identifier($sch)||'.VW_ACTIVE_ALERTS' as
select *
from identifier($dbname)||'.'||identifier($sch)||'.ALERT_LOGS'
where upper(coalesce(ALERT_STATUS,'')) in ('OPEN','ACTIVE');

-- =============================
-- Views - Audit trail & history
-- =============================
-- Normalized audit view expected by app live feed: RESOURCE_ID, ACTION, DETAILS, CREATED_AT
create or replace view identifier($dbname)||'.'||identifier($sch)||'.VW_CLASSIFICATION_AUDIT' as
with decisions as (
  select 
    ASSET_FULL_NAME as RESOURCE_ID,
    'DECISION' as ACTION,
    object_construct(
      'label', CLASSIFICATION_LABEL,
      'c', C, 'i', I, 'a', A,
      'maker', DECISION_MAKER,
      'status', STATUS,
      'rationale', RATIONALE,
      'source', SOURCE,
      'details', DETAILS
    ) as DETAILS,
    CREATED_AT
  from identifier($dbname)||'.'||identifier($sch)||'.CLASSIFICATION_DECISIONS'
),
history as (
  select 
    ASSET_FULL_NAME as RESOURCE_ID,
    'HISTORY' as ACTION,
    coalesce(DETAILS, object_construct(
      'label', LABEL,
      'c', C, 'i', I, 'a', A,
      'by', DECISION_BY,
      'source', SOURCE
    )) as DETAILS,
    DECISION_AT as CREATED_AT
  from CLASSIFICATION_HISTORY.CLASSIFICATION_HISTORY
)
select * from decisions
union all
select * from history;

-- Backward/compatibility alias for app queries expecting DATA_GOVERNANCE.CLASSIFICATION_AUDIT
create or replace view identifier($dbname)||'.'||identifier($sch)||'.CLASSIFICATION_AUDIT' as
select * from identifier($dbname)||'.'||identifier($sch)||'.VW_CLASSIFICATION_AUDIT';

-- =============================
-- Views - Combined task view (optional)
-- =============================
create or replace view identifier($dbname)||'.'||identifier($sch)||'.VW_MY_TASKS' as
with my_tasks as (
  select 
    ID,
    'CLASSIFICATION' as TASK_TYPE,
    ASSET_FULL_NAME,
    TITLE,
    STATUS,
    PRIORITY,
    DUE_DATE,
    CREATED_AT,
    DETAILS
  from identifier($dbname)||'.'||identifier($sch)||'.CLASSIFICATION_TASKS'
  where upper(coalesce(ASSIGNED_TO,'')) = upper(current_user())
),
my_alerts as (
  select 
    ALERT_ID as ID,
    'ALERT' as TASK_TYPE,
    ASSET_FULL_NAME,
    ALERT_TITLE as TITLE,
    ALERT_STATUS as STATUS,
    ALERT_PRIORITY as PRIORITY,
    DUE_DATE,
    CREATED_TIMESTAMP as CREATED_AT,
    ALERT_DETAILS as DETAILS
  from identifier($dbname)||'.'||identifier($sch)||'.ALERT_LOGS'
  where upper(coalesce(ASSIGNED_TO,'')) = upper(current_user())
)
select * from my_tasks
union all
select * from my_alerts;

-- =============================
-- View - KPI summary dashboard
-- =============================
create or replace view identifier($dbname)||'.'||identifier($sch)||'.VW_TASK_DASHBOARD' as
with inv as (
  select 
    count(*) as total_assets,
    sum(case when coalesce(CLASSIFIED,false) then 1 else 0 end) as classified_assets
  from identifier($dbname)||'.'||identifier($sch)||'.ASSET_INVENTORY'
),
pii as (
  select 
    sum(case when coalesce(PII_DETECTED,false) then 1 else 0 end) as pii_assets
  from identifier($dbname)||'.'||identifier($sch)||'.ASSETS'
),
alerts as (
  select 
    sum(case when upper(coalesce(ALERT_STATUS,'')) in ('OPEN','ACTIVE') then 1 else 0 end) as active_alerts
  from identifier($dbname)||'.'||identifier($sch)||'.ALERT_LOGS'
),
tasks as (
  select 
    sum(case when coalesce(DUE_DATE, current_date) < current_date and upper(coalesce(STATUS,'')) not in ('COMPLETED','CLOSED') then 1 else 0 end) as overdue_tasks,
    sum(case when upper(coalesce(STATUS,'')) in ('ASSIGNED','IN PROGRESS','PENDING REVIEW') then 1 else 0 end) as open_tasks
  from identifier($dbname)||'.'||identifier($sch)||'.CLASSIFICATION_TASKS'
)
select 
  inv.total_assets,
  inv.classified_assets,
  round(100.0 * nullif(inv.classified_assets,0) / nullif(inv.total_assets,0), 2) as classified_pct,
  pii.pii_assets,
  alerts.active_alerts,
  tasks.open_tasks,
  tasks.overdue_tasks
from inv, pii, alerts, tasks;

-- =============================
-- Compatibility passthroughs
-- =============================
-- Provide ASSETS in DATA_GOVERNANCE by referencing the canonical table in DATA_CLASSIFICATION_GOVERNANCE
create or replace view identifier($dbname)||'.'||identifier($sch)||'.ASSETS' as
select * from identifier($dbname)||'.DATA_CLASSIFICATION_GOVERNANCE.ASSETS';

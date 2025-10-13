import os
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import re

# Ensure project root on path
_here = os.path.abspath(__file__)
_src_dir = os.path.dirname(os.path.dirname(_here))
_project_root = os.path.dirname(_src_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from src.ui.theme import apply_global_theme
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

# ------------- Page Setup -------------
st.set_page_config(page_title="Data Intelligence", page_icon="🧠", layout="wide")
apply_global_theme()
st.title("Data Intelligence")
st.caption("Unified Quality and Lineage powered by Snowflake metadata and account usage views")

# ------------- Helpers -------------
DEFAULT_TTL = int(os.getenv("INTEL_CACHE_TTL", "300"))

@st.cache_data(ttl=DEFAULT_TTL)
def _run(sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    return snowflake_connector.execute_query(sql, params)

def _nonq(sql: str) -> None:
    try:
        snowflake_connector.execute_non_query(sql)
    except Exception:
        pass

# Discover columns for an ACCOUNT_USAGE view to build robust selects
@st.cache_data(ttl=DEFAULT_TTL)
def _account_usage_columns(view_name: str) -> List[str]:
    try:
        rows = _run(
            """
            select COLUMN_NAME
            from SNOWFLAKE.INFORMATION_SCHEMA.COLUMNS
            where TABLE_SCHEMA = 'ACCOUNT_USAGE' and TABLE_NAME = %(t)s
            """,
            {"t": view_name.upper()}
        ) or []
        return [r.get("COLUMN_NAME") for r in rows if r.get("COLUMN_NAME")]
    except Exception:
        return []

@st.cache_data(ttl=DEFAULT_TTL)
def _warehouses() -> List[str]:
    """Return available warehouse names (best-effort)."""
    try:
        rows = _run("SHOW WAREHOUSES") or []
        # Snowflake returns NAME or name depending on driver
        return [r.get("name") or r.get("NAME") for r in rows if (r.get("name") or r.get("NAME"))]
    except Exception:
        return []

def _use_warehouse(wh: Optional[str]) -> None:
    """Resume and USE the selected warehouse, best-effort."""
    if not wh:
        return
    try:
        try:
            snowflake_connector.execute_non_query("ALTER WAREHOUSE IDENTIFIER(%(wh)s) RESUME", {"wh": wh})
        except Exception:
            pass
        try:
            snowflake_connector.execute_non_query("USE WAREHOUSE IDENTIFIER(%(wh)s)", {"wh": wh})
        except Exception:
            pass
        st.session_state['sf_warehouse'] = wh
    except Exception:
        pass

@st.cache_data(ttl=DEFAULT_TTL)
def _databases() -> List[str]:
    try:
        rows = _run("SHOW DATABASES") or []
        names = [r.get("name") or r.get("NAME") for r in rows if (r.get("name") or r.get("NAME"))]
        return sorted({n for n in names if n})
    except Exception:
        return []

@st.cache_data(ttl=DEFAULT_TTL)
def _schemas(db: str) -> List[str]:
    try:
        rows = _run(f"SELECT SCHEMA_NAME FROM {db}.INFORMATION_SCHEMA.SCHEMATA ORDER BY 1") or []
        return [r.get("SCHEMA_NAME") for r in rows if r.get("SCHEMA_NAME")]
    except Exception:
        return []

@st.cache_data(ttl=DEFAULT_TTL)
def _objects(db: str, schema: Optional[str]) -> List[str]:
    try:
        where = f"WHERE TABLE_SCHEMA = '{schema}'" if schema and schema != "All" else ""
        rows = _run(
            f"""
            with t as (
              select TABLE_CATALOG as DB, TABLE_SCHEMA as SCH, TABLE_NAME as NAME, TABLE_TYPE as T
              from {db}.INFORMATION_SCHEMA.TABLES {where}
              union all
              select TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, 'VIEW' as T
              from {db}.INFORMATION_SCHEMA.VIEWS {where}
            )
            select DB||'.'||SCH||'.'||NAME as FULL
            from t
            order by 1
            """
        ) or []
        return [r.get("FULL") for r in rows if r.get("FULL")]
    except Exception:
        return []

@st.cache_data(ttl=DEFAULT_TTL)
def _columns(db: str, schema: str, object_name: str) -> List[str]:
    try:
        rows = _run(
            f"""
            select COLUMN_NAME
            from {db}.INFORMATION_SCHEMA.COLUMNS
            where TABLE_SCHEMA = %(sch)s and TABLE_NAME = %(tbl)s
            order by ORDINAL_POSITION
            """,
            {"sch": schema, "tbl": object_name}
        ) or []
        return [r["COLUMN_NAME"] for r in rows if r.get("COLUMN_NAME")]
    except Exception:
        return []

@st.cache_data(ttl=DEFAULT_TTL)
def _estimate_size(fqn: str) -> Optional[int]:
    try:
        # SYSTEM$ESTIMATE_TABLE_SIZE returns VARIANT; select value:bytes_total if available
        rows = _run(f"select SYSTEM$ESTIMATE_TABLE_SIZE('{fqn}') as EST") or []
        if not rows:
            return None
        est = rows[0].get("EST")
        if isinstance(est, dict):
            # snowflake-connector may parse VARIANT to dict
            return int(est.get("bytes") or est.get("bytes_total") or 0) or None
        # Fallback: try to parse JSON string
        try:
            import json
            d = json.loads(est)
            return int(d.get("bytes") or d.get("bytes_total") or 0) or None
        except Exception:
            return None
    except Exception:
        return None

# Storage metrics (active / time-travel bytes)
@st.cache_data(ttl=DEFAULT_TTL)
def _storage_metrics(db: str, schema: str, table: str) -> Optional[Dict[str, Any]]:
    try:
        rows = _run(
            f"""
            select coalesce(ACTIVE_BYTES,0) as ACTIVE_BYTES,
                   coalesce(TIME_TRAVEL_BYTES,0) as TIME_TRAVEL_BYTES
            from {db}.INFORMATION_SCHEMA.TABLE_STORAGE_METRICS
            where TABLE_SCHEMA=%(s)s and TABLE_NAME=%(t)s
            limit 1
            """,
            {"s": schema, "t": table}
        ) or []
        return rows[0] if rows else {"ACTIVE_BYTES": 0, "TIME_TRAVEL_BYTES": 0}
    except Exception:
        return None

# ---------- Standard (Account Usage-free) DQ helpers ----------
def _ensure_std_dq_objects(active_db: Optional[str]) -> None:
    """Create DATA_GOVERNANCE schema and standard DQ tables if not exist."""
    if not active_db:
        return
    try:
        snowflake_connector.execute_non_query(f"create schema if not exists {active_db}.DATA_GOVERNANCE")
    except Exception:
        pass
    try:
        snowflake_connector.execute_non_query(
            f"""
            create table if not exists {active_db}.DATA_GOVERNANCE.DATA_QUALITY_METRICS (
                METRIC_ID STRING default uuid_string(),
                DATABASE_NAME STRING,
                SCHEMA_NAME STRING,
                TABLE_NAME STRING,
                METRIC_NAME STRING,
                METRIC_VALUE NUMBER(38,6),
                THRESHOLD_VALUE NUMBER(38,6),
                STATUS STRING,
                MEASURED_AT TIMESTAMP_TZ default current_timestamp()
            )
            """
        )
    except Exception:
        pass
    try:
        snowflake_connector.execute_non_query(
            f"""
            create table if not exists {active_db}.DATA_GOVERNANCE.DATA_QUALITY_RULES (
                RULE_ID STRING default uuid_string(),
                DATABASE_NAME STRING,
                SCHEMA_NAME STRING,
                TABLE_NAME STRING,
                COLUMN_NAME STRING,
                RULE_TYPE STRING,
                RULE_DEFINITION STRING,
                SEVERITY STRING,
                IS_ACTIVE BOOLEAN
            )
            """
        )
    except Exception:
        pass

def _run_std_dq_health_checks(active_db: Optional[str]) -> Tuple[int, int]:
    """Insert table health and freshness metrics into standard DQ tables. Returns (rowcount_inserts, freshness_inserts)."""
    if not active_db:
        return 0, 0
    _ensure_std_dq_objects(active_db)
    inserted1 = inserted2 = 0
    try:
        inserted1 = snowflake_connector.execute_non_query(
            f"""
            insert into {active_db}.DATA_GOVERNANCE.DATA_QUALITY_METRICS (METRIC_ID, DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, METRIC_NAME, METRIC_VALUE, THRESHOLD_VALUE, STATUS, MEASURED_AT)
            select 
                uuid_string(),
                TABLE_CATALOG,
                TABLE_SCHEMA,
                TABLE_NAME,
                'ROW_COUNT',
                coalesce(ROW_COUNT, 0),
                0,
                case when coalesce(ROW_COUNT,0) = 0 then 'FAIL' else 'PASS' end,
                current_timestamp()
            from {active_db}.INFORMATION_SCHEMA.TABLES
            where TABLE_TYPE = 'BASE TABLE'
              and TABLE_SCHEMA not like 'INFORMATION_SCHEMA%'
            """
        )
    except Exception:
        inserted1 = 0
    try:
        inserted2 = snowflake_connector.execute_non_query(
            f"""
            insert into {active_db}.DATA_GOVERNANCE.DATA_QUALITY_METRICS (METRIC_ID, DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, METRIC_NAME, METRIC_VALUE, THRESHOLD_VALUE, STATUS, MEASURED_AT)
            select 
                uuid_string(),
                TABLE_CATALOG,
                TABLE_SCHEMA,
                TABLE_NAME,
                'DATA_FRESHNESS_DAYS',
                datediff('day', LAST_ALTERED, current_timestamp()),
                7,
                case when datediff('day', LAST_ALTERED, current_timestamp()) > 7 then 'FAIL' else 'PASS' end,
                current_timestamp()
            from {active_db}.INFORMATION_SCHEMA.TABLES
            where TABLE_TYPE = 'BASE TABLE'
            """
        )
    except Exception:
        inserted2 = 0
    return inserted1, inserted2

"""Standard-only Data Quality helpers"""

# ---------- Ensure DQ objects ----------
def _ensure_dq_objects(active_db: Optional[str]) -> None:
    if not active_db:
        return
    try:
        snowflake_connector.execute_non_query(f"create schema if not exists {active_db}.DATA_GOVERNANCE")
    except Exception:
        pass
    try:
        snowflake_connector.execute_non_query(
            f"""
            create table if not exists {active_db}.DATA_GOVERNANCE.DQ_METRICS (
              SNAPSHOT_AT timestamp_tz default current_timestamp(),
              DATABASE_NAME string,
              SCHEMA_NAME string,
              TABLE_NAME string,
              COLUMN_NAME string,
              METRIC string,
              VALUE number(38,6)
            )
            """
        )
    except Exception:
        pass
    try:
        snowflake_connector.execute_non_query(
            f"""
            create table if not exists {active_db}.DATA_GOVERNANCE.DQ_ISSUES (
              ISSUE_ID string default uuid_string(),
              DATABASE_NAME string,
              SCHEMA_NAME string,
              TABLE_NAME string,
              COLUMN_NAME string,
              METRIC string,
              VALUE number(38,6),
              THRESHOLD number(38,6),
              STATUS string default 'Open',
              RESOLVED_FLAG boolean default false,
              DETECTED_AT timestamp_tz default current_timestamp(),
              RESOLVED_AT timestamp_tz,
              RESOLVED_BY string,
              NOTES string
            )
            """
        )
    except Exception:
        pass

# ---------- Snapshot computation ----------
def _run_snapshot(active_db: Optional[str], schemas: List[str], table_limit: int = 25, column_limit: int = 10) -> int:
    if not active_db:
        return 0
    _ensure_dq_objects(active_db)
    inserted = 0
    where_s = " and (" + " or ".join([f"TABLE_SCHEMA = '{s}'" for s in schemas if s and s != 'All']) + ")" if schemas else ""
    trows = _run(
        f"""
        select TABLE_CATALOG as DB, TABLE_SCHEMA as SCH, TABLE_NAME as T
        from {active_db}.INFORMATION_SCHEMA.TABLES
        where TABLE_SCHEMA not in ('INFORMATION_SCHEMA'){where_s}
        order by coalesce(ROW_COUNT,0) desc
        limit {table_limit}
        """
    ) or []
    for tr in trows:
        db = tr.get('DB'); sch = tr.get('SCH'); tbl = tr.get('T')
        fqn = f"{db}.{sch}.{tbl}"
        try:
            snowflake_connector.execute_non_query(
                f"insert into {active_db}.DATA_GOVERNANCE.DQ_METRICS (DATABASE_NAME,SCHEMA_NAME,TABLE_NAME,COLUMN_NAME,METRIC,VALUE)\n                 select %(d)s, %(s)s, %(t)s, null, 'ROW_COUNT', coalesce((select ROW_COUNT from {db}.INFORMATION_SCHEMA.TABLES where TABLE_SCHEMA=%(s)s and TABLE_NAME=%(t)s),0)",
                {"d": db, "s": sch, "t": tbl}
            )
            inserted += 1
        except Exception:
            pass
        cols = _run(
            f"select COLUMN_NAME from {db}.INFORMATION_SCHEMA.COLUMNS where TABLE_SCHEMA=%(s)s and TABLE_NAME=%(t)s order by ORDINAL_POSITION limit {column_limit}",
            {"s": sch, "t": tbl}
        ) or []
        for c in cols:
            col = c.get('COLUMN_NAME')
            try:
                res = _run(f"select count(*) as TOTAL, count(\"{col}\") as NON_NULL, approx_count_distinct(\"{col}\") as AD from {fqn}") or []
                if res:
                    total = int(res[0].get('TOTAL') or 0)
                    nonnull = int(res[0].get('NON_NULL') or 0)
                    ad = int(res[0].get('AD') or 0)
                    comp = round((nonnull/total)*100,2) if total else 100.0
                    uniq = round((ad/total)*100,2) if total else 100.0
                    snowflake_connector.execute_non_query(
                        f"insert into {active_db}.DATA_GOVERNANCE.DQ_METRICS (DATABASE_NAME,SCHEMA_NAME,TABLE_NAME,COLUMN_NAME,METRIC,VALUE) values (%(d)s,%(s)s,%(t)s,%(c)s,'COMPLETENESS_PCT',%(v1)s)",
                        {"d": db, "s": sch, "t": tbl, "c": col, "v1": comp}
                    )
                    snowflake_connector.execute_non_query(
                        f"insert into {active_db}.DATA_GOVERNANCE.DQ_METRICS (DATABASE_NAME,SCHEMA_NAME,TABLE_NAME,COLUMN_NAME,METRIC,VALUE) values (%(d)s,%(s)s,%(t)s,%(c)s,'UNIQUENESS_PCT',%(v2)s)",
                        {"d": db, "s": sch, "t": tbl, "c": col, "v2": uniq}
                    )
                    inserted += 2
            except Exception:
                pass
            try:
                r2 = _run(f"select try_min(\"{col}\") as MINV, try_max(\"{col}\") as MAXV, try_avg(iff(try_to_double(\"{col}\") is null, null, try_to_double(\"{col}\"))) as AVGV from {fqn}") or []
                if r2:
                    minv = r2[0].get('MINV'); maxv = r2[0].get('MAXV'); avgv = r2[0].get('AVGV')
                    for metric, val in [("MIN", minv), ("MAX", maxv), ("AVG", avgv)]:
                        if val is not None:
                            try:
                                snowflake_connector.execute_non_query(
                                    f"insert into {active_db}.DATA_GOVERNANCE.DQ_METRICS (DATABASE_NAME,SCHEMA_NAME,TABLE_NAME,COLUMN_NAME,METRIC,VALUE) values (%(d)s,%(s)s,%(t)s,%(c)s,%(m)s,%(v)s)",
                                    {"d": db, "s": sch, "t": tbl, "c": col, "m": metric, "v": float(val)}
                                )
                                inserted += 1
                            except Exception:
                                pass
            except Exception:
                pass
    return inserted

@st.cache_data(ttl=DEFAULT_TTL)
def _table_rowcount(db: str, schema: str, name: str) -> Optional[int]:
    try:
        rows = _run(f"select ROW_COUNT from {db}.INFORMATION_SCHEMA.TABLES where TABLE_SCHEMA=%(s)s and TABLE_NAME=%(t)s",
                    {"s": schema, "t": name}) or []
        if rows:
            rc = rows[0].get("ROW_COUNT")
            return int(rc) if rc is not None else None
    except Exception:
        return None
    return None

# ------------- Sidebar Filters -------------
with st.sidebar:
    st.header("Filters")
    # Warehouse selection (optional)
    wh_opts = _warehouses()
    cur_wh = st.session_state.get('sf_warehouse')
    try:
        # If not in options, preprend for visibility
        if cur_wh and cur_wh not in (wh_opts or []):
            wh_display = [cur_wh] + (wh_opts or [])
        else:
            wh_display = wh_opts or []
    except Exception:
        wh_display = wh_opts or []
    if wh_display:
        sel_wh = st.selectbox("Warehouse", options=wh_display, index=(wh_display.index(cur_wh) if (cur_wh and cur_wh in wh_display) else 0), key="int_wh")
        if sel_wh:
            _use_warehouse(sel_wh)
    else:
        st.caption("No warehouses available")
        sel_wh = None
    db_opts = _databases()
    db_display = ["All"] + db_opts if db_opts else (["All", settings.SNOWFLAKE_DATABASE] if settings.SNOWFLAKE_DATABASE else ["All"])
    sel_db = st.selectbox("Database", options=db_display,
                          index=(db_display.index(settings.SNOWFLAKE_DATABASE) if (settings.SNOWFLAKE_DATABASE and settings.SNOWFLAKE_DATABASE in db_display) else 0),
                          key="int_db")
    active_db = None if sel_db == "All" else sel_db
    sch_opts = ["All"] + (_schemas(active_db) if active_db else [])
    sel_schema = st.selectbox("Schema", options=sch_opts, index=0, key="int_schema")
    obj_opts = _objects(active_db, sel_schema) if active_db else []
    sel_object = st.selectbox("Object (table/view)", options=["None"] + obj_opts, index=0, key="int_object")
    time_rng = st.selectbox("Time window", ["Last 7 days", "Last 30 days", "Last 90 days", "All"], index=0)
    if st.button("Clear Cache"):
        st.cache_data.clear()
        st.rerun()

# Helper to split FQN

def _split_fqn(fqn: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    try:
        db, sch, obj = fqn.split(".")
        return db, sch, obj
    except Exception:
        return None, None, None

# ------------- Tabs -------------
q_tab, l_tab = st.tabs(["📈 Data Quality", "🕸️ Data Lineage"])

# =====================================
# Data Quality
# =====================================
with q_tab:
    dq_dash, dq_profile, dq_issues, dq_resolve, dq_rt = st.tabs([
        "Quality Metrics Dashboard",
        "Data Profiling Tools",
        "Quality Issues Log",
        "Resolution Tracking",
        "Real-time (Info Schema)",
    ])

    # ---- Quality Metrics Dashboard ----
    with dq_dash:
        st.subheader("Quality Metrics Dashboard")
        # Build targets based on selected filters
        if sel_object and sel_object != "None":
            targets = [sel_object]
            st.caption(f"Using selected object: {sel_object}")
        else:
            if not active_db:
                st.info("Select a database (and optional schema/object) from the sidebar to view metrics.")
                targets = []
            else:
                # Pull objects filtered by selected schema
                try:
                    filt_opts = _objects(active_db, sel_schema)
                except Exception:
                    filt_opts = []
                default_count = min(10, len(filt_opts))
                sel_list = st.multiselect(
                    "Objects (filtered by sidebar)",
                    options=filt_opts,
                    default=filt_opts[:default_count] if filt_opts else [],
                    help="Pick one or more tables/views from the selected database/schema"
                )
                targets = sel_list
                st.caption(
                    f"Filters → Database: {active_db or '—'}, Schema: {sel_schema} | Selected objects: {len(targets)}"
                )

        k1, k2, k3, k4, k5 = st.columns(5)
        total_rows = 0
        total_distinct_id = 0
        total_non_null_id = 0
        fresh_days: List[int] = []
        failed_checks = 0
        total_active_bytes = 0
        total_tt_bytes = 0

        for fqn in targets:
            db, sch, name = _split_fqn(fqn)
            if not db:
                continue
            # Identify an id-like column from information_schema
            cols = [c.upper() for c in _columns(db, sch, name)]
            id_like = next((c for c in cols if c in ("ID", f"{name.upper()}_ID", "PK_ID", "ROW_ID")), None)
            # Compute completeness/uniqueness
            try:
                sel_parts = ["COUNT(*) AS TOTAL"]
                if id_like:
                    sel_parts += [f"COUNT({id_like}) AS NON_NULL_ID", f"COUNT(DISTINCT {id_like}) AS DISTINCT_ID"]
                q = f"select {', '.join(sel_parts)} from {fqn}"
                res = _run(q) or []
                total_rows += int(res[0].get("TOTAL") or res[0].get("TOTAL_ROWS") or 0) if res else 0
                if id_like:
                    total_non_null_id += int(res[0].get("NON_NULL_ID") or 0)
                    total_distinct_id += int(res[0].get("DISTINCT_ID") or 0)
            except Exception:
                pass
            # Freshness via LAST_ALTERED
            try:
                r = _run(
                    f"""
                    select LAST_ALTERED
                    from {db}.INFORMATION_SCHEMA.TABLES
                    where TABLE_SCHEMA=%(s)s and TABLE_NAME=%(t)s
                    union all
                    select LAST_ALTERED
                    from {db}.INFORMATION_SCHEMA.VIEWS
                    where TABLE_SCHEMA=%(s)s and TABLE_NAME=%(t)s
                    limit 1
                    """,
                    {"s": sch, "t": name}
                ) or []
                if r and r[0].get("LAST_ALTERED"):
                    ts = pd.to_datetime(r[0]["LAST_ALTERED"], errors="coerce")
                    if pd.notnull(ts):
                        fresh_days.append(max((pd.Timestamp.utcnow() - ts).days, 0))
            except Exception:
                pass
            # Storage metrics
            try:
                sm = _storage_metrics(db, sch, name)
                if sm:
                    total_active_bytes += int(sm.get("ACTIVE_BYTES", 0) or 0)
                    total_tt_bytes += int(sm.get("TIME_TRAVEL_BYTES", 0) or 0)
            except Exception:
                pass

        comp_pct = round((total_non_null_id/total_rows)*100, 2) if total_rows and total_non_null_id else 0.0
        uniq_pct = round((total_distinct_id/total_rows)*100, 2) if total_rows and total_distinct_id else 0.0
        fresh_avg = round(sum(fresh_days)/len(fresh_days), 1) if fresh_days else None

        k1.metric("Row Count", f"{total_rows:,}")
        k2.metric("Completeness (ID)%", f"{comp_pct}%")
        k3.metric("Uniqueness (ID)%", f"{uniq_pct}%")
        k4.metric("Avg Freshness (days)", f"{fresh_avg}" if fresh_avg is not None else "—")
        k5.metric("Active Storage (MB)", f"{(total_active_bytes/1024/1024):,.2f}")

        # Snapshots & Trends removed
        st.markdown("---")

        # Ingestion Monitoring (ACCOUNT_USAGE) — enabled alongside INFORMATION_SCHEMA
        st.markdown("---")
        st.subheader("Ingestion Monitoring (Account Usage)")
        cI1, cI2 = st.columns(2)
        with cI1:
            try:
                start_dt = datetime.utcnow() - (timedelta(days=7) if time_rng == "Last 7 days" else timedelta(days=30) if time_rng == "Last 30 days" else timedelta(days=90) if time_rng == "Last 90 days" else timedelta(days=365))
                end_dt = datetime.utcnow()
                qh = _run(
                    """
                    select query_id, user_name, query_text, error_code, error_message, start_time, end_time
                    from SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                    where start_time between %(s)s and %(e)s
                      and error_code is not null
                    order by start_time desc
                    limit 200
                    """,
                    {"s": start_dt, "e": end_dt}
                ) or []
                st.caption("Failed queries in window")
                st.dataframe(pd.DataFrame(qh), use_container_width=True)
            except Exception as e:
                st.info(f"QUERY_HISTORY unavailable: {e}")
        with cI2:
            start_dt = datetime.utcnow() - (timedelta(days=7) if time_rng == "Last 7 days" else timedelta(days=30) if time_rng == "Last 30 days" else timedelta(days=90) if time_rng == "Last 90 days" else timedelta(days=365))
            end_dt = datetime.utcnow()
            pu_cols = set(_account_usage_columns("PIPE_USAGE_HISTORY"))
            lh_cols = set(_account_usage_columns("LOAD_HISTORY"))
            pu = []
            pu_err = None
            try:
                if pu_cols:
                    sel_cols = [c for c in ["PIPE_NAME","START_TIME","END_TIME","FILES_PROCESSED","BYTES_PROCESSED","CREDITS_USED","ERROR_COUNT","LAST_ERROR_MESSAGE"] if c in pu_cols]
                    if sel_cols:
                        time_col = "START_TIME" if "START_TIME" in pu_cols else ("END_TIME" if "END_TIME" in pu_cols else None)
                        where_time = f"where {time_col} between %(s)s and %(e)s" if time_col else ""
                        order_time = f"order by {time_col} desc" if time_col else ""
                        pu = _run(
                            f"""
                            select {', '.join(sel_cols)}
                            from SNOWFLAKE.ACCOUNT_USAGE.PIPE_USAGE_HISTORY
                            {where_time}
                            {order_time}
                            limit 200
                            """,
                            {"s": start_dt, "e": end_dt} if time_col else None
                        ) or []
            except Exception as e:
                pu_err = str(e)
            if pu:
                st.caption("Pipe usage (ACCOUNT_USAGE.PIPE_USAGE_HISTORY)")
                st.dataframe(pd.DataFrame(pu), use_container_width=True)
            else:
                try:
                    lh = []
                    if lh_cols:
                        sel_cols = [c for c in ["PIPE_NAME","FILE_NAME","LAST_LOAD_TIME","STATUS","ROWS_PARSED","ROWS_LOADED","ERROR_COUNT","FIRST_ERROR_MESSAGE"] if c in lh_cols]
                        if sel_cols:
                            time_col = "LAST_LOAD_TIME" if "LAST_LOAD_TIME" in lh_cols else None
                            where_time = f"where {time_col} between %(s)s and %(e)s" if time_col else ""
                            order_time = f"order by {time_col} desc" if time_col else ""
                            lh = _run(
                                f"""
                                select {', '.join(sel_cols)}
                                from SNOWFLAKE.ACCOUNT_USAGE.LOAD_HISTORY
                                {where_time}
                                {order_time}
                                limit 200
                                """,
                                {"s": start_dt, "e": end_dt} if time_col else None
                            ) or []
                    if lh:
                        st.caption("Load history (ACCOUNT_USAGE.LOAD_HISTORY)")
                        st.dataframe(pd.DataFrame(lh), use_container_width=True)
                        if pu_err:
                            st.caption(f"PIPE_USAGE_HISTORY note: {pu_err}")
                    else:
                        if pu_err:
                            st.caption(f"PIPE/LOAD note: {pu_err}")
                        st.info("No pipe/load activity in window or insufficient privileges.")
                except Exception as e2:
                    st.info(f"LOAD_HISTORY unavailable: {e2}")

    # ---- Data Profiling Tools ----
    with dq_profile:
        st.subheader("Data Profiling Tools")
        if sel_object and sel_object != "None":
            db, sch, name = _split_fqn(sel_object)
            cols = _columns(db, sch, name)
            st.caption(f"Object: {sel_object}")
            # Information Schema and Account Usage views
            cA, cB = st.columns(2)
            with cA:
                try:
                    rows = _run(
                        f"""
                        select COLUMN_NAME, DATA_TYPE, IS_NULLABLE
                        from {db}.INFORMATION_SCHEMA.COLUMNS
                        where TABLE_SCHEMA=%(s)s and TABLE_NAME=%(t)s
                        order by ORDINAL_POSITION
                        """,
                        {"s": sch, "t": name}
                    ) or []
                    st.markdown("**INFORMATION_SCHEMA.COLUMNS**")
                    df_cols = pd.DataFrame(rows)
                    st.dataframe(df_cols, use_container_width=True)
                except Exception as e:
                    st.info(f"Columns unavailable: {e}")
            with cB:
                try:
                    rows = _run(
                        f"select * from SNOWFLAKE.ACCOUNT_USAGE.COLUMNS where TABLE_CATALOG=%(d)s and TABLE_SCHEMA=%(s)s and TABLE_NAME=%(t)s limit 500",
                        {"d": db, "s": sch, "t": name}
                    ) or []
                    st.markdown("**ACCOUNT_USAGE.COLUMNS**")
                    st.dataframe(pd.DataFrame(rows), use_container_width=True)
                except Exception as e:
                    st.info(f"Account usage columns unavailable: {e}")
            # Table metadata + size
            try:
                tmeta = _run(
                    f"select * from {db}.INFORMATION_SCHEMA.TABLES where TABLE_SCHEMA=%(s)s and TABLE_NAME=%(t)s",
                    {"s": sch, "t": name}
                ) or []
            except Exception:
                tmeta = []
            size_b = _estimate_size(sel_object)
            rc = _table_rowcount(db, sch, name)
            k1, k2, k3 = st.columns(3)
            k1.metric("Row Count", f"{rc:,}" if rc is not None else "—")
            k2.metric("Estimated Size (MB)", f"{(size_b/1024/1024):,.2f}" if size_b else "—")
            k3.metric("Table Type", (tmeta[0].get("TABLE_TYPE") if tmeta else "—"))

            # Column statistics and distributions
            st.markdown("---")
            st.subheader("Column Statistics")
            # Use deep-link focus column if provided via session state
            focus_col = st.session_state.pop('int_profile_focus_col', None) if 'int_profile_focus_col' in st.session_state else None
            default_cols = [focus_col] if (focus_col and cols and focus_col in cols) else (cols[:5] if cols else [])
            chosen_cols = st.multiselect("Columns to profile", options=cols, default=default_cols) if cols else []
            # Type map for consistency checks
            try:
                type_rows = _run(
                    f"""
                    select upper(COLUMN_NAME) as CN, upper(DATA_TYPE) as DT
                    from {db}.INFORMATION_SCHEMA.COLUMNS
                    where TABLE_SCHEMA=%(s)s and TABLE_NAME=%(t)s
                    """,
                    {"s": sch, "t": name}
                ) or []
                type_map = {r.get("CN"): (r.get("DT") or "").upper() for r in type_rows}
            except Exception:
                type_map = {}

            def _pct_color(v: Optional[float]) -> str:
                if v is None:
                    return "#cccccc"
                if v >= 95:
                    return "#2ecc71"  # green
                if v >= 80:
                    return "#f1c40f"  # yellow
                return "#e74c3c"       # red

            stats_rows = []
            for c in chosen_cols:
                try:
                    r = _run(f"select count(*) as TOTAL, count(\"{c}\") as NON_NULL, count(distinct \"{c}\") as DISTINCT from {sel_object}") or []
                    total = int(r[0].get("TOTAL") or 0) if r else 0
                    nonnull = int(r[0].get("NON_NULL") or 0) if r else 0
                    distinct = int(r[0].get("DISTINCT") or 0) if r else 0
                    minv = maxv = avgv = None
                    try:
                        r2 = _run(f"select try_min(\"{c}\") as MINV, try_max(\"{c}\") as MAXV, try_avg(iff(try_to_double(\"{c}\") is null, null, try_to_double(\"{c}\"))) as AVGV from {sel_object}") or []
                        minv = r2[0].get("MINV") if r2 else None
                        maxv = r2[0].get("MAXV") if r2 else None
                        avgv = r2[0].get("AVGV") if r2 else None
                    except Exception:
                        pass
                    # Derived metrics
                    completeness_pct = round((nonnull/total)*100, 2) if total else None
                    uniqueness_pct = round((distinct/nonnull)*100, 2) if nonnull else None
                    cardinality_ratio = round((distinct/nonnull)*100, 2) if nonnull else None

                    # Pattern validity (heuristics by column name)
                    cname = c.upper()
                    pattern_valid_pct: Optional[float] = None
                    if any(k in cname for k in ["EMAIL"]):
                        re_pat = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
                        rr = _run(f"select sum(iff(\"{c}\" is not null and \"{c}\" rlike %(p)s,1,0)) as OK, sum(iff(\"{c}\" is not null,1,0)) as N from {sel_object}", {"p": re_pat}) or []
                        n = int(rr[0].get("N") or 0) if rr else 0
                        ok = int(rr[0].get("OK") or 0) if rr else 0
                        pattern_valid_pct = round((ok/n)*100, 2) if n else None
                    elif any(k in cname for k in ["PHONE","MOBILE"]):
                        re_pat = r'^[+]?\d[\d\s().-]{7,}$'
                        rr = _run(f"select sum(iff(\"{c}\" is not null and \"{c}\" rlike %(p)s,1,0)) as OK, sum(iff(\"{c}\" is not null,1,0)) as N from {sel_object}", {"p": re_pat}) or []
                        n = int(rr[0].get("N") or 0) if rr else 0
                        ok = int(rr[0].get("OK") or 0) if rr else 0
                        pattern_valid_pct = round((ok/n)*100, 2) if n else None
                    elif any(k in cname for k in ["URL","LINK"]):
                        re_pat = r'^(https?://).+'
                        rr = _run(f"select sum(iff(\"{c}\" is not null and \"{c}\" rlike %(p)s,1,0)) as OK, sum(iff(\"{c}\" is not null,1,0)) as N from {sel_object}", {"p": re_pat}) or []
                        n = int(rr[0].get("N") or 0) if rr else 0
                        ok = int(rr[0].get("OK") or 0) if rr else 0
                        pattern_valid_pct = round((ok/n)*100, 2) if n else None
                    elif any(k in cname for k in ["DATE","DOB"]):
                        rr = _run(f"select sum(iff(\"{c}\" is not null and try_to_timestamp(\"{c}\") is not null,1,0)) as OK, sum(iff(\"{c}\" is not null,1,0)) as N from {sel_object}") or []
                        n = int(rr[0].get("N") or 0) if rr else 0
                        ok = int(rr[0].get("OK") or 0) if rr else 0
                        pattern_valid_pct = round((ok/n)*100, 2) if n else None

                    # Type consistency based on declared type
                    declared = type_map.get(c.upper(), "")
                    type_consist_pct: Optional[float] = None
                    if declared.startswith("NUMBER") or declared in ("INT","INTEGER","DECIMAL","FLOAT","DOUBLE"):
                        rr = _run(f"select sum(iff(\"{c}\" is not null and try_to_double(\"{c}\") is not null,1,0)) as OK, sum(iff(\"{c}\" is not null,1,0)) as N from {sel_object}") or []
                        n = int(rr[0].get("N") or 0) if rr else 0
                        ok = int(rr[0].get("OK") or 0) if rr else 0
                        type_consist_pct = round((ok/n)*100, 2) if n else None
                    elif declared.startswith("DATE") or declared.startswith("TIMESTAMP"):
                        # If column is already date/timestamp, consider consistent; else try parsing
                        rr = _run(f"select sum(iff(\"{c}\" is not null and try_to_timestamp(\"{c}\") is not null,1,0)) as OK, sum(iff(\"{c}\" is not null,1,0)) as N from {sel_object}") or []
                        n = int(rr[0].get("N") or 0) if rr else 0
                        ok = int(rr[0].get("OK") or 0) if rr else 0
                        type_consist_pct = round((ok/n)*100, 2) if n else None
                    else:
                        # Treat varchar/text as consistent by default
                        type_consist_pct = 100.0 if nonnull else None

                    # Range checks (heuristics)
                    range_ok_pct: Optional[float] = None
                    if any(k in cname for k in ["AGE"]):
                        rr = _run(f"select sum(iff(try_to_double(\"{c}\") between 0 and 120,1,0)) as OK, sum(iff(\"{c}\" is not null,1,0)) as N from {sel_object}") or []
                        n = int(rr[0].get("N") or 0) if rr else 0
                        ok = int(rr[0].get("OK") or 0) if rr else 0
                        range_ok_pct = round((ok/n)*100, 2) if n else None
                    elif any(k in cname for k in ["SALARY","AMOUNT","PRICE","COST"]):
                        rr = _run(f"select sum(iff(try_to_double(\"{c}\") > 0 and try_to_double(\"{c}\") < 1e9,1,0)) as OK, sum(iff(\"{c}\" is not null,1,0)) as N from {sel_object}") or []
                        n = int(rr[0].get("N") or 0) if rr else 0
                        ok = int(rr[0].get("OK") or 0) if rr else 0
                        range_ok_pct = round((ok/n)*100, 2) if n else None

                    # Column health score (weighted by heuristics)
                    health_score: Optional[float] = None
                    if any(k in cname for k in ["_ID","ID"]):
                        weights = [(uniqueness_pct, 0.4), (completeness_pct, 0.4), (pattern_valid_pct, 0.2)]
                    elif "EMAIL" in cname:
                        weights = [(pattern_valid_pct, 0.5), (completeness_pct, 0.3), (uniqueness_pct, 0.2)]
                    elif declared.startswith("VARCHAR") and uniqueness_pct is not None and uniqueness_pct <= 30:
                        # Category-like
                        inv_uniq = (100 - uniqueness_pct) if uniqueness_pct is not None else None
                        weights = [(completeness_pct, 0.6), (inv_uniq, 0.4)]
                    else:
                        weights = [(completeness_pct, 0.5), (type_consist_pct, 0.3), (pattern_valid_pct, 0.2)]
                    try:
                        num = sum((v or 0)*w for v, w in weights if v is not None)
                        den = sum(w for v, w in weights if v is not None)
                        health_score = round(num/den, 2) if den else None
                    except Exception:
                        health_score = None

                    stats_rows.append({
                        "COLUMN": c,
                        "TOTAL": total,
                        "NON_NULL": nonnull,
                        "NULLS": max(total - nonnull, 0),
                        "DISTINCT": distinct,
                        "COMPLETENESS_%": completeness_pct,
                        "UNIQUENESS_%": uniqueness_pct,
                        "PATTERN_VALID_%": pattern_valid_pct,
                        "TYPE_CONSIST_%": type_consist_pct,
                        "CARDINALITY_%": cardinality_ratio,
                        "RANGE_OK_%": range_ok_pct,
                        "HEALTH_SCORE": health_score,
                        "MIN": minv,
                        "MAX": maxv,
                        "AVG": avgv,
                    })
                except Exception:
                    continue
            if stats_rows:
                df_stats = pd.DataFrame(stats_rows)
                st.dataframe(df_stats, use_container_width=True)

            # Simple distributions for first selected column
            if chosen_cols:
                col0 = chosen_cols[0]
                try:
                    vals = _run(
                        f"select \"{col0}\" as V, count(*) as C from {sel_object} group by 1 order by C desc nulls last limit 20"
                    ) or []
                    if vals:
                        dfv = pd.DataFrame(vals)
                        st.plotly_chart(px.bar(dfv, x="V", y="C", title=f"Distribution: {col0}"), use_container_width=True)
                except Exception:
                    pass
        else:
            st.info("Select an object to profile from the sidebar.")

    # ---- Standard DQ removed per INFORMATION_SCHEMA-only design ----
    st.caption("Standard DQ (custom tables) removed — using live INFORMATION_SCHEMA only.")

    # ---- Real-time (Info Schema) ----
    with dq_rt:
        st.subheader("Real-time Issues (Information Schema)")
        st.caption("Live detection without custom tables. Uses INFORMATION_SCHEMA views directly.")
        colA, colB = st.columns(2)
        with colA:
            stale_days = st.number_input("Stale if last_altered older than (days)", min_value=1, max_value=3650, value=7, step=1, key="rt_stale_days")
        with colB:
            sch_filter = sel_schema if sel_schema != "All" else None
            st.write("")
        if not active_db:
            st.info("Select a database to run real-time checks.")
        else:
            # Stale tables
            try:
                rows = _run(
                    f"""
                    select TABLE_CATALOG as DATABASE_NAME, TABLE_SCHEMA as SCHEMA_NAME, TABLE_NAME,
                           LAST_ALTERED,
                           datediff('day', LAST_ALTERED, current_timestamp()) as STALE_DAYS
                    from {active_db}.INFORMATION_SCHEMA.TABLES
                    where TABLE_TYPE='BASE TABLE'
                      {("and TABLE_SCHEMA=%(s)s" if sch_filter else "")}
                      and LAST_ALTERED < dateadd('day', -%(d)s, current_timestamp())
                    order by STALE_DAYS desc
                    limit 1000
                    """,
                    ({"s": sch_filter, "d": int(stale_days)} if sch_filter else {"d": int(stale_days)})
                ) or []
            except Exception as e:
                rows = []
                st.info(f"Stale scan unavailable: {e}")
            st.markdown("**Stale Tables**")
            st.dataframe(pd.DataFrame(rows), use_container_width=True)

            # Empty tables
            try:
                empty = _run(
                    f"""
                    select TABLE_CATALOG as DATABASE_NAME, TABLE_SCHEMA as SCHEMA_NAME, TABLE_NAME,
                           coalesce(ROW_COUNT,0) as ROW_COUNT
                    from {active_db}.INFORMATION_SCHEMA.TABLES
                    where TABLE_TYPE='BASE TABLE'
                      {("and TABLE_SCHEMA=%(s)s" if sch_filter else "")}
                      and coalesce(ROW_COUNT,0) = 0
                    order by TABLE_SCHEMA, TABLE_NAME
                    limit 1000
                    """,
                    ({"s": sch_filter} if sch_filter else None)
                ) or []
            except Exception as e:
                empty = []
                st.info(f"Empty table scan unavailable: {e}")
            st.markdown("**Empty Tables**")
            st.dataframe(pd.DataFrame(empty), use_container_width=True)

            # Schema quality (nullability summary)
            try:
                schq = _run(
                    f"""
                    with cols as (
                      select TABLE_CATALOG as DATABASE_NAME, TABLE_SCHEMA as SCHEMA_NAME, TABLE_NAME,
                             sum(case when IS_NULLABLE='YES' then 1 else 0 end) as NULLABLE_COLS,
                             count(*) as TOTAL_COLS
                      from {active_db}.INFORMATION_SCHEMA.COLUMNS
                      {("where TABLE_SCHEMA=%(s)s" if sch_filter else "")}
                      group by 1,2,3
                    )
                    select *, round(NULLABLE_COLS * 100.0 / nullif(TOTAL_COLS,0), 2) as NULLABLE_PCT
                    from cols
                    order by NULLABLE_PCT desc
                    limit 1000
                    """,
                    ({"s": sch_filter} if sch_filter else None)
                ) or []
            except Exception as e:
                schq = []
                st.info(f"Schema quality summary unavailable: {e}")
            st.markdown("**Schema Quality (Nullability Summary)**")
            st.dataframe(pd.DataFrame(schq), use_container_width=True)

            st.markdown("**Prompt 2: Automated DQ Monitoring System**")
            st.code("""
Build an automated data quality monitoring system for Snowflake standard account that:

1. Creates scheduled tasks to run DQ checks daily
2. Uses Snowflake's TASK feature to automate monitoring
3. Implements these specific checks:
   - Table growth anomalies (>50% change in row count)
   - Data freshness (tables not updated in 7 days)
   - Schema drift detection (new columns, changed data types)
   - Referential integrity checks
   - Custom business rules from a config table

4. Sends alerts via Snowflake notifications or email
5. Maintains 90 days of DQ history for trending

Provide complete SQL implementation including:
- DQ configuration tables
- Stored procedures for each check type
- Task scheduling setup
- Alerting mechanism
""", language="text")

            st.markdown("**Prompt 3: Streamlit DQ Dashboard**")
            st.code("""
Create a Streamlit data quality dashboard that connects to Snowflake standard account and displays:

1. Executive Summary:
   - Overall DQ Score (%) 
   - Critical vs Warning Issues
   - Trending (improvement/decline)

2. Detailed DQ Issues:
   - Tables with most failures
   - Freshness violations
   - Completeness issues
   - Schema changes

3. Interactive Features:
   - Filter by database/schema
   - Date range selection  
   - Drill-down to table level
   - Export reports

4. Automated Features:
   - Refresh every 5 minutes
   - Color-coded severity indicators
   - Historical trends charts

Generate the complete Streamlit Python code that uses only INFORMATION_SCHEMA and custom DQ tables. Include proper error handling and connection management.
""", language="text")

            st.markdown("**Prompt 4: Column-Level Data Quality**")
            st.code("""
Implement column-level data quality checks for Snowflake standard account focusing on:

1. Data Type Validation:
   - Email format validation
   - Phone number patterns
   - Date format consistency
   - Numeric range checks

2. Completeness Checks:
   - Null percentage per column
   - Empty string detection
   - Default value overuse

3. Uniqueness & Distribution:
   - Duplicate detection
   - Cardinality analysis
   - Value distribution skew

4. Cross-Table Validation:
   - Foreign key relationships
   - Reference data compliance
   - Business rule validation across tables

Create SQL stored procedures for each check type that:
- Can be configured per table/column
- Store results in a central DQ repository
- Support threshold-based alerting
- Handle large tables efficiently with sampling
""", language="text")

            st.markdown("**Prompt 5: Data Quality Alerting & SLA**")
            st.code("""
Design a data quality SLA monitoring system for Snowflake standard account with:

1. SLA Definitions:
   - Freshness SLA (max 24h old)
   - Completeness SLA (<5% nulls)
   - Accuracy SLA (business rule compliance)
   - Availability SLA (table accessibility)

2. Alerting Rules:
   - Critical: Breaches SLA for 2 consecutive days
   - Warning: Single day SLA breach
   - Info: Approaching thresholds

3. Notification System:
   - Daily summary reports
   - Immediate critical alerts
   - Escalation paths

4. SLA Reporting:
   - Monthly SLA compliance reports
   - Root cause analysis tracking
   - Improvement initiatives tracking

Provide complete implementation including:
- SLA configuration tables
- Alerting logic as stored procedures
- Notification templates
- Escalation workflow
""", language="text")

        # Tags and masking integration (best-effort)
        if sel_object and sel_object != "None":
            st.markdown("---")
            st.subheader("Tags & Masking (Column-level)")
            db, sch, name = _split_fqn(sel_object)
            c1, c2 = st.columns(2)
            with c1:
                # Prefer INFORMATION_SCHEMA.TAG_REFERENCES; fallback to ACCOUNT_USAGE.TAG_REFERENCES
                try:
                    tr = _run(
                        f"""
                        select OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME, TAG_NAME, TAG_VALUE
                        from {db}.INFORMATION_SCHEMA.TAG_REFERENCES
                        where OBJECT_SCHEMA=%(s)s and OBJECT_NAME=%(t)s and COLUMN_NAME is not null
                        limit 1000
                        """,
                        {"s": sch, "t": name}
                    ) or []
                except Exception:
                    try:
                        tr = _run(
                            """
                            select OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME, TAG_NAME, TAG_VALUE
                            from SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                            where OBJECT_DATABASE=%(d)s and OBJECT_SCHEMA=%(s)s and OBJECT_NAME=%(t)s and COLUMN_NAME is not null
                            limit 1000
                            """,
                            {"d": db, "s": sch, "t": name}
                        ) or []
                    except Exception:
                        tr = []
                st.caption("Column Tags")
                st.dataframe(pd.DataFrame(tr), use_container_width=True)
            with c2:
                try:
                    rows = _run(
                        f"""
                        select COLUMN_NAME, DATA_TYPE, MASKING_POLICY
                        from {db}.INFORMATION_SCHEMA.COLUMNS
                        where TABLE_SCHEMA=%(s)s and TABLE_NAME=%(t)s
                        order by ORDINAL_POSITION
                        """,
                        {"s": sch, "t": name}
                    ) or []
                    st.caption("Masking Policies")
                    st.dataframe(pd.DataFrame(rows), use_container_width=True)
                except Exception as e:
                    st.info(f"Masking policy info unavailable: {e}")

    # ---- Quality Issues Log ----
    with dq_issues:
        st.subheader("Quality Issues Log")
        st.caption("Live detection from INFORMATION_SCHEMA only (no persistence)")
        colt1, colt2 = st.columns(2)
        with colt1:
            stale_days = st.number_input("Stale if last_altered older than (days)", min_value=1, max_value=3650, value=7, step=1, key="qi_stale")
        with colt2:
            sch_filter = sel_schema if sel_schema != "All" else None
        if not active_db:
            st.info("Select a database to scan.")
        else:
            # Stale tables
            try:
                rows_stale = _run(
                    f"""
                    select TABLE_CATALOG as DATABASE_NAME, TABLE_SCHEMA as SCHEMA_NAME, TABLE_NAME,
                           LAST_ALTERED,
                           datediff('day', LAST_ALTERED, current_timestamp()) as STALE_DAYS
                    from {active_db}.INFORMATION_SCHEMA.TABLES
                    where TABLE_TYPE='BASE TABLE'
                      {("and TABLE_SCHEMA=%(s)s" if sch_filter else "")}
                      and LAST_ALTERED < dateadd('day', -%(d)s, current_timestamp())
                    order by STALE_DAYS desc
                    limit 1000
                    """,
                    ({"s": sch_filter, "d": int(stale_days)} if sch_filter else {"d": int(stale_days)})
                ) or []
            except Exception:
                rows_stale = []
                st.info("Stale scan unavailable.")
            st.markdown("**Stale Tables**")
            st.dataframe(pd.DataFrame(rows_stale), use_container_width=True)

            # Empty tables
            try:
                rows_empty = _run(
                    f"""
                    select TABLE_CATALOG as DATABASE_NAME, TABLE_SCHEMA as SCHEMA_NAME, TABLE_NAME,
                           coalesce(ROW_COUNT,0) as ROW_COUNT
                    from {active_db}.INFORMATION_SCHEMA.TABLES
                    where TABLE_TYPE='BASE TABLE'
                      {("and TABLE_SCHEMA=%(s)s" if sch_filter else "")}
                      and coalesce(ROW_COUNT,0) = 0
                    order by TABLE_SCHEMA, TABLE_NAME
                    limit 1000
                    """,
                    ({"s": sch_filter} if sch_filter else None)
                ) or []
            except Exception:
                rows_empty = []
                st.info("Empty table scan unavailable.")
            st.markdown("**Empty Tables**")
            st.dataframe(pd.DataFrame(rows_empty), use_container_width=True)

            # Schema quality summary (nullability)
            try:
                rows_schema = _run(
                    f"""
                    select TABLE_CATALOG as DATABASE_NAME, TABLE_SCHEMA as SCHEMA_NAME, TABLE_NAME,
                           sum(iff(upper(IS_NULLABLE)='NO',1,0)) as NON_NULLABLE_COLS,
                           count(*) as TOTAL_COLS
                    from {active_db}.INFORMATION_SCHEMA.COLUMNS
                    {("where TABLE_SCHEMA=%(s)s" if sch_filter else "")}
                    group by 1,2,3
                    order by TOTAL_COLS desc
                    limit 1000
                    """,
                    ({"s": sch_filter} if sch_filter else None)
                ) or []
            except Exception:
                rows_schema = []
                st.info("Schema quality scan unavailable.")
            st.markdown("**Schema Quality (Nullability Summary)**")
            st.dataframe(pd.DataFrame(rows_schema), use_container_width=True)

        def _detect_and_persist(dbname: Optional[str], thr_null_pct: float, thr_duplicates_pct: float) -> int:
            if not dbname:
                return 0
            _ensure_dq_objects(dbname)
            rows = _run(
                f"""
                with last as (
                  select DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, COLUMN_NAME, METRIC, VALUE,
                         row_number() over(partition by DATABASE_NAME,SCHEMA_NAME,TABLE_NAME,COLUMN_NAME,METRIC order by SNAPSHOT_AT desc) as rn
                  from {dbname}.DATA_GOVERNANCE.DQ_METRICS
                ),
                p as (
                  select * from last where rn = 1 and COLUMN_NAME is not null and METRIC in ('COMPLETENESS_PCT','UNIQUENESS_PCT')
                )
                select * from p
                """
            ) or []
            created = 0
            for r in rows:
                db = r.get('DATABASE_NAME'); sch = r.get('SCHEMA_NAME'); tbl = r.get('TABLE_NAME'); col = r.get('COLUMN_NAME')
                metric = r.get('METRIC'); val = float(r.get('VALUE') or 0)
                if metric == 'COMPLETENESS_PCT':
                    nullpct = 100.0 - val
                    if nullpct > thr_null_pct:
                        try:
                            snowflake_connector.execute_non_query(
                                f"""
                                insert into {dbname}.DATA_GOVERNANCE.DQ_ISSUES (DATABASE_NAME,SCHEMA_NAME,TABLE_NAME,COLUMN_NAME,METRIC,VALUE,THRESHOLD,STATUS,RESOLVED_FLAG,DETECTED_AT)
                                select %(d)s,%(s)s,%(t)s,%(c)s,'NULL_PCT',%(v)s,%(th)s,'Open',false,current_timestamp()
                                where not exists (
                                  select 1 from {dbname}.DATA_GOVERNANCE.DQ_ISSUES i
                                  where i.DATABASE_NAME=%(d)s and i.SCHEMA_NAME=%(s)s and i.TABLE_NAME=%(t)s and i.COLUMN_NAME=%(c)s
                                    and i.METRIC='NULL_PCT' and coalesce(i.RESOLVED_FLAG,false)=false and i.STATUS in ('Open','In Progress')
                                )
                                """,
                                {"d": db, "s": sch, "t": tbl, "c": col, "v": nullpct, "th": thr_null_pct}
                            )
                            created += 1
                        except Exception:
                            pass
                elif metric == 'UNIQUENESS_PCT':
                    dup_pct = max(0.0, 100.0 - val)
                    if dup_pct > thr_duplicates_pct:
                        try:
                            snowflake_connector.execute_non_query(
                                f"""
                                insert into {dbname}.DATA_GOVERNANCE.DQ_ISSUES (DATABASE_NAME,SCHEMA_NAME,TABLE_NAME,COLUMN_NAME,METRIC,VALUE,THRESHOLD,STATUS,RESOLVED_FLAG,DETECTED_AT)
                                select %(d)s,%(s)s,%(t)s,%(c)s,'DUPLICATE_PCT',%(v)s,%(th)s,'Open',false,current_timestamp()
                                where not exists (
                                  select 1 from {dbname}.DATA_GOVERNANCE.DQ_ISSUES i
                                  where i.DATABASE_NAME=%(d)s and i.SCHEMA_NAME=%(s)s and i.TABLE_NAME=%(t)s and i.COLUMN_NAME=%(c)s
                                    and i.METRIC='DUPLICATE_PCT' and coalesce(i.RESOLVED_FLAG,false)=false and i.STATUS in ('Open','In Progress')
                                )
                                """,
                                {"d": db, "s": sch, "t": tbl, "c": col, "v": dup_pct, "th": thr_duplicates_pct}
                            )
                            created += 1
                        except Exception:
                            pass
            return created

        # Live scan only; no persistence or detect button. Use the tables above.

    # ---- Resolution Tracking ----
    with dq_resolve:
        st.subheader("Resolution Tracking")
        st.caption("Session-only notes; verify via re-scan against INFORMATION_SCHEMA")
        if "dq_resolutions" not in st.session_state:
            st.session_state["dq_resolutions"] = []
        colr1, colr2 = st.columns(2)
        with colr1:
            res_note = st.text_input("Resolution note")
        with colr2:
            if st.button("Add Note") and res_note:
                st.session_state["dq_resolutions"].append({"at": datetime.utcnow().isoformat(), "note": res_note})
        if st.session_state["dq_resolutions"]:
            st.markdown("**Notes (session)**")
            st.dataframe(pd.DataFrame(st.session_state["dq_resolutions"]), use_container_width=True, hide_index=True)
        st.markdown("---")
        st.subheader("Verify Resolutions")
        st.caption("Re-run the Quality Issues scans to confirm issues are resolved")
        if st.button("Re-Scan Now"):
            st.cache_data.clear(); st.rerun()

# =====================================
# Data Lineage
# =====================================
with l_tab:
    lin_viz, lin_impact, lin_map, lin_change, lin_column = st.tabs([
        "Lineage Visualization",
        "Impact Analysis",
        "Dependency Mapping",
        "Change Propagation",
        "Column-level Info",
    ])

    # Base: dependencies from INFORMATION_SCHEMA
    def _deps(db: str, schema: Optional[str], name: Optional[str]) -> pd.DataFrame:
        try:
            where = []
            params: Dict[str, Any] = {}
            if schema and schema != "All":
                where.append("REFERENCING_OBJECT_SCHEMA = %(s)s")
                params["s"] = schema
            if name:
                where.append("REFERENCING_OBJECT_NAME = %(t)s")
                params["t"] = name
            w = (" where " + " and ".join(where)) if where else ""
            rows = _run(
                f"""
                select REFERENCING_OBJECT_DATABASE, REFERENCING_OBJECT_SCHEMA, REFERENCING_OBJECT_NAME,
                       REFERENCED_OBJECT_DATABASE, REFERENCED_OBJECT_SCHEMA, REFERENCED_OBJECT_NAME,
                       REFERENCED_OBJECT_DOMAIN as REFERENCED_TYPE
                from {db}.INFORMATION_SCHEMA.OBJECT_DEPENDENCIES
                {w}
                limit 2000
                """,
                params
            ) or []
            return pd.DataFrame(rows)
        except Exception:
            return pd.DataFrame()

    # ---- Lineage Visualization ----
    with lin_viz:
        st.subheader("Lineage Visualization")
        if sel_object and sel_object != "None":
            db, sch, name = _split_fqn(sel_object)
            df = _deps(db, sch, name)
            if df.empty:
                st.info("No dependencies found or insufficient privileges.")
            else:
                # Build simple network layout
                edges = []
                for _, r in df.iterrows():
                    src = f"{r['REFERENCED_OBJECT_DATABASE']}.{r['REFERENCED_OBJECT_SCHEMA']}.{r['REFERENCED_OBJECT_NAME']}"
                    dst = f"{r['REFERENCING_OBJECT_DATABASE']}.{r['REFERENCING_OBJECT_SCHEMA']}.{r['REFERENCING_OBJECT_NAME']}"
                    edges.append((src, dst))
                nodes = sorted({n for e in edges for n in e})
                idx = {n: i for i, n in enumerate(nodes)}
                # circular layout
                import math
                N = len(nodes)
                xs = [math.cos(2*math.pi*i/max(N,1)) for i in range(N)]
                ys = [math.sin(2*math.pi*i/max(N,1)) for i in range(N)]
                node_x = []
                node_y = []
                for i in range(N):
                    node_x.append(xs[i])
                    node_y.append(ys[i])
                edge_x = []
                edge_y = []
                for a, b in edges:
                    ia, ib = idx[a], idx[b]
                    edge_x += [node_x[ia], node_x[ib], None]
                    edge_y += [node_y[ia], node_y[ib], None]
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode='lines', line=dict(width=1, color='#888')))
                fig.add_trace(go.Scatter(x=node_x, y=node_y, mode='markers+text', text=nodes, textposition='top center',
                                         marker=dict(size=10, color='#1f77b4')))
                fig.update_layout(showlegend=False, margin=dict(l=10,r=10,t=10,b=10), height=500)
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Select an object from the sidebar to visualize lineage.")

    # ---- Impact Analysis ----
    with lin_impact:
        st.subheader("Impact Analysis")
        if sel_object and sel_object != "None":
            db, sch, name = _split_fqn(sel_object)
            df = _deps(db, sch, name)
            if df.empty:
                st.info("No downstream dependencies found.")
            else:
                down = df[[
                    "REFERENCING_OBJECT_DATABASE","REFERENCING_OBJECT_SCHEMA","REFERENCING_OBJECT_NAME"
                ]].drop_duplicates()
                down["FULL_NAME"] = down["REFERENCING_OBJECT_DATABASE"] + "." + down["REFERENCING_OBJECT_SCHEMA"] + "." + down["REFERENCING_OBJECT_NAME"]
                st.dataframe(down[["FULL_NAME"]], use_container_width=True)
        else:
            st.info("Select an object to analyze impact.")

    # ---- Dependency Mapping ----
    with lin_map:
        st.subheader("Dependency Mapping")
        try:
            db = active_db
            df = _deps(db, None if sel_schema == "All" else sel_schema, None)
            if df.empty:
                st.info("No dependencies available.")
            else:
                # Filter by object type
                typ = st.multiselect("Referenced Type", sorted(df.get("REFERENCED_TYPE", pd.Series(dtype=str)).dropna().unique().tolist()))
                view = df.copy()
                if typ:
                    view = view[view["REFERENCED_TYPE"].isin(typ)]
                st.dataframe(view, use_container_width=True)
        except Exception as e:
            st.info(f"Dependency mapping unavailable: {e}")

    # ---- Change Propagation ----
    with lin_change:
        st.subheader("Change Propagation")
        start_dt = datetime.utcnow() - (timedelta(days=7) if time_rng == "Last 7 days" else timedelta(days=30) if time_rng == "Last 30 days" else timedelta(days=90) if time_rng == "Last 90 days" else timedelta(days=365))
        end_dt = datetime.utcnow()
        if sel_object and sel_object != "None":
            db, sch, name = _split_fqn(sel_object)
            try:
                # Escape regex for schema.table pattern
                pat = ".*" + re.escape(f"{scht}.{name}").upper() + ".*"
                qh = _run(
                    """
                    select QUERY_ID, USER_NAME, START_TIME, QUERY_TEXT
                    from SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                    where START_TIME between %(s)s and %(e)s
                      and (upper(QUERY_TEXT) like any_values(array_construct('%INSERT%','%UPDATE%','%MERGE%','%DELETE%','%CREATE TABLE AS%')))
                      and regexp_like(upper(QUERY_TEXT), %(pat)s)
                    order by START_TIME desc limit 1000
                    """,
                    {"s": start_dt, "e": end_dt, "pat": pat}
                ) or []
            except Exception as e:
                qh = []
                st.info(f"QUERY_HISTORY unavailable: {e}")
            try:
                th = _run(
                    """
                    select NAME, SCHEDULED_TIME, STATE, QUERY_TEXT
                    from SNOWFLAKE.ACCOUNT_USAGE.TASK_HISTORY
                    where SCHEDULED_TIME between %(s)s and %(e)s
                    order by SCHEDULED_TIME desc limit 1000
                    """,
                    {"s": start_dt, "e": end_dt}
                ) or []
            except Exception as e:
                th = []
                st.info(f"TASK_HISTORY unavailable: {e}")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Recent DML/CTAS touching object**")
                st.dataframe(pd.DataFrame(qh), use_container_width=True)
            with c2:
                st.markdown("**Recent Task Executions**")
                st.dataframe(pd.DataFrame(th), use_container_width=True)
        else:
            st.info("Select an object to trace changes.")

    # ---- Column-level Info ----
    with lin_column:
        st.subheader("Column-level Info")
        if sel_object and sel_object != "None":
            db, sch, name = _split_fqn(sel_object)
            c1, c2 = st.columns(2)
            with c1:
                try:
                    tr = _run(
                        """
                        select OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME, TAG_NAME, TAG_VALUE
                        from SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                        where OBJECT_DATABASE=%(d)s and OBJECT_SCHEMA=%(s)s and OBJECT_NAME=%(t)s and COLUMN_NAME is not null
                        limit 1000
                        """,
                        {"d": db, "s": sch, "t": name}
                    ) or []
                    st.markdown("**Column Tags**")
                    st.dataframe(pd.DataFrame(tr), use_container_width=True)
                except Exception as e:
                    st.info(f"TAG_REFERENCES unavailable: {e}")
            with c2:
                try:
                    rows = _run(
                        f"""
                        select COLUMN_NAME, DATA_TYPE, MASKING_POLICY
                        from {db}.INFORMATION_SCHEMA.COLUMNS
                        where TABLE_SCHEMA=%(s)s and TABLE_NAME=%(t)s
                        order by ORDINAL_POSITION
                        """,
                        {"s": sch, "t": name}
                    ) or []
                    st.markdown("**Masking Policies**")
                    st.dataframe(pd.DataFrame(rows), use_container_width=True)
                except Exception as e:
                    st.info(f"Masking policy info unavailable: {e}")
            st.markdown("---")
            st.subheader("Column Lineage (best-effort)")
            try:
                # Attempt programmatic lineage function
                rows = _run(
                    """
                    select * from table(SNOWFLAKE.CORE.GET_LINEAGE(object_name=>%(f)s, include_columns=>true))
                    limit 2000
                    """,
                    {"f": sel_object}
                ) or []
                if rows:
                    st.dataframe(pd.DataFrame(rows), use_container_width=True)
                else:
                    st.info("No column-level lineage returned.")
            except Exception as e:
                st.info(f"GET_LINEAGE unavailable: {e}")
        else:
            st.info("Select an object to view column-level details.")

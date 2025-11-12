from pathlib import Path as _Path
import sys
import os

# Add the project root (parent of 'src') to the Python path so 'src.*' imports work
_here = os.path.abspath(__file__)
_src_dir = os.path.dirname(os.path.dirname(_here))  # .../src
_project_root = os.path.dirname(_src_dir)           # project root containing 'src'
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import streamlit as st
import pandas as pd
import re
import json
from datetime import date, datetime, timedelta
from typing import Optional, List, Dict, Tuple, Set, Union, Any, AnyStr
from src.ui.theme import apply_global_theme
from src.components.filters import render_data_filters
from src.connectors.snowflake_connector import snowflake_connector
from src.services.authorization_service import authz
try:
    from src.services.tagging_service import tagging_service, TAG_DEFINITIONS
except Exception:
    tagging_service = None  # type: ignore
    TAG_DEFINITIONS = {  # minimal fallback to keep page loading
        "DATA_CLASSIFICATION": ["Public", "Internal", "Restricted", "Confidential"],
    }

# Get allowed classifications from tagging service
ALLOWED_CLASSIFICATIONS = TAG_DEFINITIONS.get("DATA_CLASSIFICATION") or ["Public", "Internal", "Restricted", "Confidential"]
from src.services.reclassification_service import reclassification_service
from src.services.ai_sensitive_detection_service import ai_sensitive_detection_service
from src.services.governance_db_resolver import resolve_governance_db
from src.services.audit_service import audit_service
try:
    from src.services.ai_assistant_service import ai_assistant_service
except Exception:
    ai_assistant_service = None
from src.services.ai_sensitive_tables_service import ai_sensitive_tables_service
from src.services.ai_classification_pipeline_service import ai_classification_pipeline_service

def _detect_sensitive_tables(database: str, schema: Optional[str] = None, sample_size: int = 1000) -> List[Dict[str, Any]]:
    """Detect sensitive tables in the specified database using metadata, patterns, and AI.
    
    Args:
        database: Database name to analyze
        schema: Optional schema to filter by
        sample_size: Number of rows to sample per table for pattern matching
        
    Returns:
        List of dicts with table metadata and sensitivity information
    """
    try:
        # Resolve/validate database (avoid NONE/NULL)
        db = database or st.session_state.get("sf_database")
        try:
            if not db:
                db = _active_db_from_filter()  # type: ignore[name-defined]
        except Exception:
            pass
        if not db or str(db).strip().upper() in {"NONE", "(NONE)", "NULL", "UNKNOWN"}:
            st.info("Select a database from Global Filters to run classification.")
            return []
        database = str(db).strip()

        # Run hybrid scan and persist results using governance configs
        try:
            ai_sensitive_detection_service.sample_size = int(max(1, sample_size))
        except Exception:
            pass
        try:
            ai_sensitive_detection_service.run_scan_and_persist(database, schema_name=schema)
        except Exception:
            # Continue even if persistence fails; we can still return in-memory results
            pass

        # Build table-level view from service (governance-driven weights/thresholds)
        tbl_results = ai_sensitive_detection_service.detect_sensitive_tables(database, schema_name=schema)
        results: List[Dict[str, Any]] = []
        for t in (tbl_results or []):
            try:
                dbn = t.get('database') or database
                scn = t.get('schema')
                tbn = t.get('table')
                fqn = f"{dbn}.{scn}.{tbn}"
                cols_src = t.get('sensitive_columns') or []
                # Map column details to prior structure; scale scores to 0-1
                col_rows = []
                high_cnt = 0
                med_cnt = 0
                for c in cols_src:
                    s100 = float(c.get('sensitivity_score') or 0.0)
                    s = max(0.0, min(1.0, s100 / 100.0))
                    lvl = c.get('sensitivity_level') or ('HIGH' if s >= 0.8 else 'MEDIUM' if s >= 0.6 else 'LOW')
                    if lvl == 'HIGH':
                        high_cnt += 1
                    elif lvl == 'MEDIUM':
                        med_cnt += 1
                    col_rows.append({
                        'column': c.get('column_name'),
                        'data_type': c.get('data_type'),
                        'sensitivity_score': round(s, 2),
                        'sensitivity_level': lvl,
                        'detection_methods': list(c.get('detection_methods') or []),
                    })
                # Table score is 0-100 in service
                tscore100 = float(t.get('sensitivity_score') or 0.0)
                tscore = max(0.0, min(1.0, tscore100 / 100.0))
                results.append({
                    'database': dbn,
                    'schema': scn,
                    'table': tbn,
                    'full_name': fqn,
                    'sensitivity_level': t.get('sensitivity_level') or ('HIGH' if tscore >= 0.8 else 'MEDIUM' if tscore >= 0.6 else 'LOW'),
                    'confidence_score': round(tscore, 2),
                    'high_sensitivity_cols': high_cnt,
                    'medium_sensitivity_cols': med_cnt,
                    'total_columns': len(col_rows),
                    'columns': col_rows,
                })
            except Exception:
                continue
        return results

    except Exception as e:
        st.error(f"Error detecting sensitive tables: {str(e)}")
        if st.session_state.get('show_debug', False):
            st.exception(e)
        return []

 
from src.services.audit_service import audit_service
from src.services.ai_classification_service import ai_classification_service
import src.services.classification_history_service as classification_history_service
import src.services.tag_drift_service as tag_drift_service
from src.services.classification_decision_service import classification_decision_service
from src.services.notifier_service import notifier_service
from src.services.governance_db_resolver import resolve_governance_db
from src.services.policy_enforcement_service import policy_enforcement_service
from src.services.my_tasks_service import (
    fetch_assigned_tasks as my_fetch_tasks,
    update_or_submit_classification as my_update_submit,
)
from src.ui.classification_history_tab import render_classification_history_tab
from src.services.seed_governance_service import refresh_governance
try:
    from src.services.classification_review_service import list_reviews as cr_list_reviews
except Exception:
    cr_list_reviews = None
try:
    from src.services.discovery_service import discovery_service
except Exception:
    discovery_service = None
from src.services import review_actions_service as review_actions
try:
    from src.ui.reclassification_requests import render_reclassification_requests
except Exception:
    render_reclassification_requests = None
try:
    from src.services.metrics_service import metrics_service
except Exception:
    metrics_service = None
try:
    from src.services.compliance_service import compliance_service
except Exception:
    compliance_service = None

try:
    from src.config.settings import settings
except Exception:
    settings = None

# No local services/helpers; all functionality is encapsulated in the centralized
# Classification Center to ensure a single policy-aligned implementation.

 

# Page configuration
st.set_page_config(
    page_title="Data Classification",
    page_icon="🏷️",
    layout="wide",
)

# Apply centralized theme (fonts, CSS variables, Plotly template)
apply_global_theme()

# Top-level title and signed-in banner (placed above content per requirements)
st.title("Data Classification")
try:
    _ident_top = authz.get_current_identity()
    st.caption(f"Signed in as: {_ident_top.user or 'Unknown'} | Role: {_ident_top.current_role or 'Unknown'}")
    if not authz.can_access_classification(_ident_top):
        st.error("You do not have permission to access the Classification Center.")
        st.stop()
except Exception as _top_auth_err:
    st.warning(f"Authorization check failed: {_top_auth_err}")
    st.stop()


# Ensure AI service is properly initialized
try:
    ai_classification_service.set_mode(True)
    _db_init = st.session_state.get("sf_database") or resolve_governance_db()
    if _db_init:
        _sc_fqn_init = f"{_db_init}.DATA_CLASSIFICATION_GOVERNANCE"
        try:
            # Initialize with empty config first to prevent errors
            ai_classification_service._sensitivity_config = {
                "patterns": {},
                "keywords": {},
                "categories": {},
                "bundles": {},
                "compliance_mapping": {},
                "model_metadata": {},
                "name_tokens": {}
            }
            # Try to load the real config
            try:
                ai_classification_service.load_sensitivity_config(force_refresh=True, schema_fqn=_sc_fqn_init)
            except Exception as e:
                st.warning(f"Warning: Could not load sensitivity config: {str(e)}. Using default configuration.")
        except Exception as e:
            st.warning(f"Warning: Could not initialize sensitivity config: {str(e)}. Some features may be limited.")
except Exception as e:
    st.warning(f"Warning: Could not fully initialize AI service: {str(e)}. Some features may be limited.")
    # Ensure we have at least an empty config
    if not hasattr(ai_classification_service, '_sensitivity_config'):
        ai_classification_service._sensitivity_config = {
            "patterns": {},
            "keywords": {},
            "categories": {},
            "bundles": {},
            "compliance_mapping": {},
            "model_metadata": {},
            "name_tokens": {}
        }

# Add verification of AI service readiness
def verify_ai_service_ready():
    """Check if AI service is properly configured"""
    try:
        if not ai_classification_service:
            return False
        # Use the pre-loaded config instead of calling load_sensitivity_config again
        cfg = getattr(ai_classification_service, '_sensitivity_config', {})
        # If we have patterns or keywords, consider it ready
        return bool(cfg.get('patterns') or cfg.get('keywords'))
    except Exception:
        return False

# Show resolved governance database and allow re-detection (DB + Schema)
try:
    col_db1, col_db2, col_db3 = st.columns([3,1,1])
    with col_db1:
        _db_resolved = resolve_governance_db()
        # Auto-detect governance schema (force DATA_CLASSIFICATION_GOVERNANCE)
        def _auto_detect_governance_schema(active_db: str) -> str:
            return "DATA_CLASSIFICATION_GOVERNANCE"

        # Initialize or refresh schema in session
        try:
            _active_db = st.session_state.get("sf_database") or _db_resolved
            if _active_db:
                if not st.session_state.get("governance_schema"):
                    st.session_state["governance_schema"] = _auto_detect_governance_schema(_active_db)
        except Exception:
            pass

    # (Removed) Sidebar scanning options

    
        # Hidden: previously displayed resolved governance schema
    with col_db2:
        if st.button("Re-detect DB", key="btn_redetect_db"):
            try:
                _db_new = resolve_governance_db(force_refresh=True)
                if _db_new:
                    st.session_state["sf_database"] = _db_new
                    st.success(f"Detected: {_db_new}")
                # Removed st.rerun() to prevent no-op warning
            except Exception as _e:
                st.warning(f"Re-detect failed: {_e}")
    with col_db3:
        if st.button("Re-detect Schema", key="btn_redetect_schema"):
            try:
                _active_db = st.session_state.get("sf_database") or _db_resolved
                if _active_db:
                    st.session_state["governance_schema"] = _auto_detect_governance_schema(_active_db)
                    st.success(f"Schema: {st.session_state['governance_schema']}")
                # Removed st.rerun() to prevent no-op warning
            except Exception as _e:
                st.warning(f"Schema detect failed: {_e}")
except Exception:
    pass

# Global Filters (sidebar) and driver for tabs
with st.sidebar.expander("🌐 Global Filters", expanded=True):
    # Warehouse selector (optional, shown by default)
    try:
        wh_rows = snowflake_connector.execute_query("SHOW WAREHOUSES") or []
        wh_opts = [r.get("name") or r.get("NAME") for r in wh_rows if (r.get("name") or r.get("NAME"))]
    except Exception:
        wh_opts = []
    cur_wh = st.session_state.get('sf_warehouse')
    # Keep current selection visible even if not in list
    wh_display = ([cur_wh] + [w for w in wh_opts if w != cur_wh]) if cur_wh else wh_opts
    sel_wh = st.selectbox(
        "Warehouse",
        options=(wh_display or [""]),
        index=(wh_display.index(cur_wh) if (cur_wh and cur_wh in wh_display) else 0) if wh_display else 0,
        key="global_wh",
        help="Select a Snowflake warehouse to run queries",
    )
    if sel_wh:
        try:
            snowflake_connector.execute_non_query(f"USE WAREHOUSE {sel_wh}")
            st.session_state['sf_warehouse'] = sel_wh
        except Exception:
            pass

    # Database, Schema, Table/View, Column
    global_sel = render_data_filters(key_prefix="global")
    try:
        if "virtual_mode" not in st.session_state:
            st.session_state["virtual_mode"] = False
    except Exception:
        pass
    # Persist the selected database to session to drive services that rely on it
    if global_sel.get("database"):
        _db_sel = str(global_sel.get("database") or "").strip()
        if _db_sel and _db_sel.upper() not in {"ALL", "NONE", "(NONE)", "NULL", "UNKNOWN"}:
            st.session_state["sf_database"] = _db_sel
            try:
                snowflake_connector.execute_non_query(f"USE DATABASE {_db_sel}")
            except Exception as _e_use_db:
                try:
                    st.warning(f"Failed to set database context: {_e_use_db}")
                except Exception:
                    pass
            try:
                ai_classification_service.set_mode(True)
                _sc_fqn_sel = f"{_db_sel}.DATA_CLASSIFICATION_GOVERNANCE"
                ai_classification_service.load_sensitivity_config(force_refresh=True, schema_fqn=_sc_fqn_sel)
            except Exception:
                pass
    # Persist selected schema to session if provided
    try:
        _sc_sel = str(global_sel.get("schema") or "").strip()
        if _sc_sel and _sc_sel.upper() not in {"ALL", "NONE", "(NONE)", "NULL", "UNKNOWN"}:
            st.session_state["sf_schema"] = _sc_sel
    except Exception:
        pass
    # Persist all filters for downstream queries
    try:
        st.session_state["global_filters"] = {
            "database": global_sel.get("database"),
            "schema": global_sel.get("schema"),
            "table": global_sel.get("table"),
        }
    except Exception:
        pass

    # (Removed) Object (table/view) selector per request

# Ensure session DB context matches Global Filters selection (best-effort)
try:
    _set_db_from_filters_if_available()
except NameError:
    # Function defined later in the module during initial import; ignore on first pass
    pass

# Apply Snowflake context (DB/Schema) to settings and verify permissions
try:
    _apply_snowflake_context()
    _verify_information_schema_permissions()
    try:
        _sel_table = (st.session_state.get("global_filters") or {}).get("table")
        if _sel_table and _sel_table.count(".") == 2:
            _compute_and_store_table_stats(_sel_table)
    except Exception:
        pass
except Exception:
    pass

# (Removed) Sidebar advanced governance objects

def _active_db_from_filter() -> Optional[str]:
    """Resolve active DB for this page, prioritizing the sidebar selection.
    Order: sidebar/session → resolver → None.
    """
    try:
        db = st.session_state.get("sf_database")
        if db:
            v = str(db).strip()
            if v and v.upper() not in {"NONE", "(NONE)", "NULL", "UNKNOWN"}:
                return v
    except Exception:
        pass
    try:
        return resolve_governance_db()
    except Exception:
        return None

def _set_db_from_filters_if_available() -> None:
    """Ensure Snowflake session context uses the DB selected in Global Filters.
    Sets st.session_state['sf_database'] and issues USE DATABASE when valid.
    """
    try:
        db = _active_db_from_filter()
        if db and str(db).strip() and str(db).strip().upper() not in {"NONE", "(NONE)", "NULL", "UNKNOWN"}:
            st.session_state["sf_database"] = db
            try:
                snowflake_connector.execute_non_query(f"USE DATABASE {db}")
            except Exception as _e_use_db2:
                try:
                    st.warning(f"Failed to set database context: {_e_use_db2}")
                except Exception:
                    pass
    except Exception:
        pass

def _apply_snowflake_context() -> None:
    try:
        try:
            ai_classification_service.set_mode(True)
        except Exception:
            pass

        db = st.session_state.get("sf_database")
        sc = st.session_state.get("sf_schema") or (st.session_state.get("global_filters") or {}).get("schema")
        if settings is not None:
            try:
                if db:
                    setattr(settings, "SCAN_CATALOG_DB", str(db))
                    # Use the database for SNOWFLAKE_DATABASE (not the schema)
                    setattr(settings, "SNOWFLAKE_DATABASE", str(db))
            except Exception:
                pass
        # Utilities: one-click refresh/seed of governance config for selected DB
        c1, c2 = st.columns([1,3])
        with c1:
            if st.button("Refresh governance (seed/update)", type="secondary", help="Creates tables if missing, upserts default seeds, and refreshes AI config"):
                db_f = st.session_state.get("sf_database") or resolve_governance_db()
                if not db_f:
                    st.warning("Select a Database first in Global Filters")
                else:
                    try:
                        res = refresh_governance(database=db_f)
                        # Force-refresh config for active DB/schema
                        try:
                            _sc_fqn = f"{db_f}.DATA_CLASSIFICATION_GOVERNANCE"
                            ai_classification_service.load_sensitivity_config(force_refresh=True, schema_fqn=_sc_fqn)
                        except Exception:
                            pass
                        # Feedback
                        failures = res.get("failures") or []
                        counts = res.get("counts") or {}
                        st.success(
                            f"Governance refresh complete for {db_f}: statements ok={res.get('success_statements',0)}, failures={res.get('failure_count',0)}"
                        )
                        if counts:
                            try:
                                df_counts = pd.DataFrame([{"TABLE": k, "ROW_COUNT": v} for k, v in counts.items()])
                                st.dataframe(df_counts, hide_index=True, width='stretch')
                            except Exception:
                                st.write(counts)
                        if failures:
                            st.warning("Some statements failed. See details below.")
                            for f in failures[:10]:
                                st.caption(str(f))
                    except Exception as _seed_ex:
                        st.error(f"Refresh failed: {_seed_ex}")
        with c2:
            st.caption("")
        try:
            if db and sc:
                snowflake_connector.execute_non_query(f"USE SCHEMA {db}.{sc}")
            elif sc:
                snowflake_connector.execute_non_query(f"USE SCHEMA {sc}")
        except Exception as _e_use_schema:
            try:
                st.warning(f"Failed to set schema context: {_e_use_schema}")
            except Exception:
                pass
        
    except Exception:
        pass

def _verify_information_schema_permissions() -> None:
    try:
        db = st.session_state.get("sf_database") or _active_db_from_filter()
        sc = st.session_state.get("sf_schema")
        if not db:
            return
        issues = []
        try:
            snowflake_connector.execute_query(f"SELECT 1 FROM {db}.INFORMATION_SCHEMA.TABLES LIMIT 1")
        except Exception as e:
            issues.append("TABLES")
        try:
            if sc:
                snowflake_connector.execute_query(
                    f"SELECT 1 FROM {db}.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%(s)s LIMIT 1",
                    {"s": sc},
                )
            else:
                snowflake_connector.execute_query(f"SELECT 1 FROM {db}.INFORMATION_SCHEMA.COLUMNS LIMIT 1")
        except Exception:
            issues.append("COLUMNS")
        try:
            snowflake_connector.execute_query(f"SELECT 1 FROM {db}.INFORMATION_SCHEMA.CONSTRAINTS LIMIT 1")
        except Exception:
            issues.append("CONSTRAINTS")
        if issues:
            st.warning(
                "Insufficient privileges for INFORMATION_SCHEMA: " + ", ".join(issues) + ". Please grant SELECT on these views to the active role."
            )
        else:
            st.caption("INFORMATION_SCHEMA access verified for current role.")
    except Exception:
        pass

def _compute_and_store_table_stats(table_fqn: str) -> None:
    try:
        if not table_fqn or table_fqn.count(".") != 2:
            return
        db, sc, tb = table_fqn.split(".")
        if not db:
            db = st.session_state.get("sf_database") or ""
        snowflake_connector.execute_non_query(
            f"CREATE SCHEMA IF NOT EXISTS {db}.DATA_CLASSIFICATION_GOVERNANCE"
        )
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {db}.DATA_CLASSIFICATION_GOVERNANCE.COLUMN_STATS (
              TABLE_CATALOG STRING,
              TABLE_SCHEMA STRING,
              TABLE_NAME STRING,
              COLUMN_NAME STRING,
              ROW_COUNT NUMBER,
              NULL_COUNT NUMBER,
              UNIQUE_COUNT NUMBER,
              COMPUTED_AT TIMESTAMP_NTZ,
              COMPUTED_BY STRING,
              SESSION_ID STRING
            )
            """
        )
        try:
            snowflake_connector.execute_non_query(
                f"ALTER TABLE {db}.DATA_CLASSIFICATION_GOVERNANCE.COLUMN_STATS ADD COLUMN IF NOT EXISTS COMPUTED_BY STRING"
            )
        except Exception:
            pass
        try:
            snowflake_connector.execute_non_query(
                f"ALTER TABLE {db}.DATA_CLASSIFICATION_GOVERNANCE.COLUMN_STATS ADD COLUMN IF NOT EXISTS SESSION_ID STRING"
            )
        except Exception:
            pass
        rows = snowflake_connector.execute_query(
            f"SELECT COLUMN_NAME FROM {db}.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%(s)s AND TABLE_NAME=%(t)s ORDER BY ORDINAL_POSITION",
            {"s": sc, "t": tb},
        ) or []
        total = 0
        try:
            rci = snowflake_connector.execute_query(
                f"SELECT COALESCE(ROW_COUNT,0) AS RC FROM {db}.INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=%(s)s AND TABLE_NAME=%(t)s LIMIT 1",
                {"s": sc, "t": tb},
            ) or []
            total = int(rci[0].get("RC") or 0) if rci else 0
        except Exception:
            total = 0
        if total <= 0:
            try:
                rc = snowflake_connector.execute_query(f"SELECT COUNT(*) AS C FROM {db}.{sc}.{tb}") or []
                total = int(list(rc[0].values())[0]) if rc else 0
            except Exception:
                total = 0
        try:
            refresh = bool(st.session_state.get("refresh_column_stats"))
        except Exception:
            refresh = False
        try:
            if not refresh:
                ex = snowflake_connector.execute_query(
                    f"SELECT MAX(COMPUTED_AT) AS TS FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.COLUMN_STATS WHERE TABLE_CATALOG=%(dc)s AND TABLE_SCHEMA=%(sc)s AND TABLE_NAME=%(tb)s",
                    {"dc": db, "sc": sc, "tb": tb},
                ) or []
                ts = ex[0].get("TS") if ex else None
                if ts:
                    # Skip recomputation if within 24h
                    staleness_ok = True
                    try:
                        import pandas as _pdx
                        age = (pd.to_datetime("now") - pd.to_datetime(ts)).total_seconds()
                        staleness_ok = age > 24*3600
                    except Exception:
                        staleness_ok = False
                    if not staleness_ok:
                        return
        except Exception:
            pass
        user_id = None
        session_id = None
        try:
            ident = authz.get_current_identity()
            user_id = ident.user
        except Exception:
            user_id = None
        try:
            session_id = st.session_state.get("session_id") or st.session_state.get("_session_id")
        except Exception:
            session_id = None
        for r in rows:
            col = r.get("COLUMN_NAME")
            if not col:
                continue
            try:
                qn = f'"{db}"."{sc}"."{tb}"'
                qcol = '"' + str(col).replace('"','""') + '"'
                if total and total > 5000000:
                    res = snowflake_connector.execute_query(
                        f"SELECT COUNT(*) AS N, COUNT({qcol}) AS NN, APPROX_COUNT_DISTINCT({qcol}) AS UDIST FROM {qn}"
                    ) or []
                else:
                    res = snowflake_connector.execute_query(
                        f"SELECT COUNT(*) AS N, COUNT({qcol}) AS NN, COUNT(DISTINCT {qcol}) AS UDIST FROM {qn}"
                    ) or []
                n = int(res[0].get("N") or 0) if res else total
                nn = int(res[0].get("NN") or 0) if res else 0
                ud = int(res[0].get("UDIST") or 0) if res else 0
                nulls = max(0, n - nn)
                snowflake_connector.execute_non_query(
                    f"""
                    MERGE INTO {db}.DATA_CLASSIFICATION_GOVERNANCE.COLUMN_STATS t
                    USING (SELECT %(dc)s AS DC, %(sc)s AS SC, %(tb)s AS TB, %(col)s AS CN) s
                    ON t.TABLE_CATALOG=s.DC AND t.TABLE_SCHEMA=s.SC AND t.TABLE_NAME=s.TB AND t.COLUMN_NAME=s.CN
                    WHEN MATCHED THEN UPDATE SET ROW_COUNT=%(rc)s, NULL_COUNT=%(nc)s, UNIQUE_COUNT=%(uc)s, COMPUTED_AT=CURRENT_TIMESTAMP, COMPUTED_BY=%(by)s, SESSION_ID=%(sid)s
                    WHEN NOT MATCHED THEN INSERT (TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, ROW_COUNT, NULL_COUNT, UNIQUE_COUNT, COMPUTED_AT, COMPUTED_BY, SESSION_ID)
                    VALUES (%(dc)s, %(sc)s, %(tb)s, %(col)s, %(rc)s, %(nc)s, %(uc)s, CURRENT_TIMESTAMP, %(by)s, %(sid)s)
                    """,
                    {"dc": db, "sc": sc, "tb": tb, "col": col, "rc": n, "nc": nulls, "uc": ud, "by": user_id, "sid": session_id},
                )
            except Exception:
                continue
    except Exception:
        pass

def _ensure_governance_objects(db: str) -> None:
    try:
        snowflake_connector.execute_non_query(
            f"CREATE SCHEMA IF NOT EXISTS {db}.DATA_CLASSIFICATION_GOVERNANCE"
        )
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS (
                ASSET_ID VARCHAR(100) NOT NULL,
                ASSET_NAME VARCHAR(500) NOT NULL,
                ASSET_TYPE VARCHAR(50) NOT NULL,
                DATABASE_NAME VARCHAR(255),
                SCHEMA_NAME VARCHAR(255),
                OBJECT_NAME VARCHAR(255),
                FULLY_QUALIFIED_NAME VARCHAR(1000),
                BUSINESS_UNIT VARCHAR(100),
                DATA_OWNER VARCHAR(100) NOT NULL,
                DATA_OWNER_EMAIL VARCHAR(255),
                DATA_CUSTODIAN VARCHAR(100),
                DATA_CUSTODIAN_EMAIL VARCHAR(255),
                BUSINESS_PURPOSE VARCHAR(2000),
                DATA_DESCRIPTION VARCHAR(4000),
                CLASSIFICATION_LABEL VARCHAR(20),
                CLASSIFICATION_LABEL_COLOR VARCHAR(20),
                CONFIDENTIALITY_LEVEL VARCHAR(2),
                INTEGRITY_LEVEL VARCHAR(2),
                AVAILABILITY_LEVEL VARCHAR(2),
                OVERALL_RISK_CLASSIFICATION VARCHAR(20),
                CONTAINS_PII BOOLEAN DEFAULT FALSE,
                CONTAINS_FINANCIAL_DATA BOOLEAN DEFAULT FALSE,
                SOX_RELEVANT BOOLEAN DEFAULT FALSE,
                SOC_RELEVANT BOOLEAN DEFAULT FALSE,
                REGULATORY_DATA BOOLEAN DEFAULT FALSE,
                CLASSIFICATION_RATIONALE VARCHAR(4000),
                CONFIDENTIALITY_IMPACT_ASSESSMENT VARCHAR(2000),
                INTEGRITY_IMPACT_ASSESSMENT VARCHAR(2000),
                AVAILABILITY_IMPACT_ASSESSMENT VARCHAR(2000),
                CLASSIFICATION_DATE TIMESTAMP_NTZ(9),
                CLASSIFIED_BY VARCHAR(100),
                CLASSIFICATION_METHOD VARCHAR(50),
                CLASSIFICATION_REVIEWED_BY VARCHAR(100),
                CLASSIFICATION_REVIEW_DATE TIMESTAMP_NTZ(9),
                CLASSIFICATION_APPROVED_BY VARCHAR(100),
                CLASSIFICATION_APPROVAL_DATE TIMESTAMP_NTZ(9),
                LAST_RECLASSIFICATION_DATE TIMESTAMP_NTZ(9),
                RECLASSIFICATION_TRIGGER VARCHAR(500),
                RECLASSIFICATION_COUNT NUMBER(10,0) DEFAULT 0,
                PREVIOUS_CLASSIFICATION_LABEL VARCHAR(20),
                LAST_REVIEW_DATE TIMESTAMP_NTZ(9),
                NEXT_REVIEW_DATE TIMESTAMP_NTZ(9),
                REVIEW_FREQUENCY_DAYS NUMBER(10,0) DEFAULT 365,
                REVIEW_STATUS VARCHAR(20),
                PEER_REVIEW_COMPLETED BOOLEAN DEFAULT FALSE,
                PEER_REVIEWER VARCHAR(100),
                MANAGEMENT_REVIEW_COMPLETED BOOLEAN DEFAULT FALSE,
                MANAGEMENT_REVIEWER VARCHAR(100),
                TECHNICAL_REVIEW_COMPLETED BOOLEAN DEFAULT FALSE,
                TECHNICAL_REVIEWER VARCHAR(100),
                CONSISTENCY_CHECK_DATE TIMESTAMP_NTZ(9),
                CONSISTENCY_CHECK_STATUS VARCHAR(20),
                DATA_CREATION_DATE TIMESTAMP_NTZ(9),
                DATA_SOURCE_SYSTEM VARCHAR(255),
                DATA_RETENTION_PERIOD_DAYS NUMBER(10,0),
                DATA_DISPOSAL_DATE TIMESTAMP_NTZ(9),
                SENSITIVE_DATA_USAGE_COUNT NUMBER(10,0) DEFAULT 0,
                LAST_ACCESSED_DATE TIMESTAMP_NTZ(9),
                ACCESS_FREQUENCY VARCHAR(20),
                NUMBER_OF_CONSUMERS NUMBER(10,0),
                HAS_EXCEPTION BOOLEAN DEFAULT FALSE,
                EXCEPTION_TYPE VARCHAR(100),
                EXCEPTION_JUSTIFICATION VARCHAR(2000),
                EXCEPTION_APPROVED_BY VARCHAR(100),
                EXCEPTION_APPROVAL_DATE TIMESTAMP_NTZ(9),
                EXCEPTION_EXPIRY_DATE TIMESTAMP_NTZ(9),
                EXCEPTION_MITIGATION_MEASURES VARCHAR(2000),
                COMPLIANCE_STATUS VARCHAR(20),
                NON_COMPLIANCE_REASON VARCHAR(1000),
                CORRECTIVE_ACTION_REQUIRED BOOLEAN DEFAULT FALSE,
                CORRECTIVE_ACTION_DESCRIPTION VARCHAR(2000),
                CORRECTIVE_ACTION_DUE_DATE TIMESTAMP_NTZ(9),
                CREATED_TIMESTAMP TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
                CREATED_BY VARCHAR(100),
                LAST_MODIFIED_TIMESTAMP TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
                LAST_MODIFIED_BY VARCHAR(100),
                RECORD_VERSION NUMBER(10,0) DEFAULT 1,
                ADDITIONAL_NOTES VARCHAR(4000),
                STAKEHOLDER_COMMENTS VARCHAR(4000),
                PRIMARY KEY (ASSET_ID)
            )
            """
        )
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_TASKS (
              TASK_ID STRING,
              DATASET_NAME STRING,
              ASSET_FULL_NAME STRING,
              ASSIGNED_TO STRING,
              STATUS STRING,
              CONFIDENTIALITY_LEVEL STRING,
              INTEGRITY_LEVEL STRING,
              AVAILABILITY_LEVEL STRING,
              DUE_DATE DATE,
              CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
              UPDATED_AT TIMESTAMP_NTZ,
              DETAILS VARIANT
            )
            """
        )
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_DECISIONS (
              ID STRING,
              ASSET_FULL_NAME STRING,
              USER_ID STRING,
              ACTION STRING,
              CLASSIFICATION_LEVEL STRING,
              CIA_CONF NUMBER,
              CIA_INT NUMBER,
              CIA_AVAIL NUMBER,
              RATIONALE STRING,
              CREATED_AT TIMESTAMP_NTZ,
              DETAILS VARIANT
            )
            """
        )
    except Exception:
        pass

try:
    _db_ctx = _active_db_from_filter()
    if _db_ctx:
        _apply_snowflake_context()
        _ensure_governance_objects(_db_ctx)
        try:
            ai_sensitive_detection_service.ensure_governance_tables()
        except Exception:
            pass
except Exception:
    pass

def _gv_schema() -> str:
    """Governance schema from session with default."""
    try:
        return str(st.session_state.get("governance_schema") or "DATA_CLASSIFICATION_GOVERNANCE")
    except Exception:
        return "DATA_CLASSIFICATION_GOVERNANCE"

def _where_from_filters_for_fqn(column_name: str, sel: dict) -> Tuple[List[str], dict]:
    """Build WHERE fragments/params to filter a fully-qualified name column (DATABASE.SCHEMA.OBJECT)
    using the current Global Filters. Returns (where_fragments, params).
    """
    frags: List[str] = []
    params: dict = {}
    try:
        sdb = str(sel.get("database") or "").upper()
        ssch = str(sel.get("schema") or "").upper()
        stab = str(sel.get("table") or "").upper()
        if sdb:
            frags.append(f"UPPER({column_name}) LIKE UPPER(%(w_db)s)"); params["w_db"] = f"{sdb}.%"
        if ssch:
            # Match middle segment .SCHEMA.
            frags.append(f"POSITION('.' || UPPER(%(w_s)s) || '.' IN UPPER({column_name})) > 0"); params["w_s"] = ssch
        if stab:
            # Match trailing segment .TABLE or full equality
            frags.append(f"(UPPER({column_name}) LIKE UPPER(%(w_t1)s) OR RIGHT(UPPER({column_name}), LENGTH(%(w_t2)s)) = UPPER(%(w_t2)s))")
            params["w_t1"] = f"%.{stab}"
            params["w_t2"] = f".{stab}"
    except Exception:
        pass
    return frags, params

def _inventory_assets(db: str, gv_schema: str, sel: dict) -> List[Dict]:
    try:
        where, params = _where_from_filters_for_fqn("FULLY_QUALIFIED_NAME", sel or {})
        sql = f"""
            SELECT 
              FULLY_QUALIFIED_NAME AS FULL_NAME,
              BUSINESS_UNIT AS OBJECT_DOMAIN,
              COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP) AS FIRST_DISCOVERED,
              (CLASSIFICATION_LABEL IS NOT NULL) AS CLASSIFIED
            FROM {db}.{gv_schema}.ASSETS
            {('WHERE ' + ' AND '.join(where)) if where else ''}
            ORDER BY COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP) DESC
            LIMIT 500
        """
        rows = snowflake_connector.execute_query(sql, params) or []
    except Exception:
        rows = []
    return rows

def _matches_global(row, sel: dict) -> bool:
    """Best-effort row filter against selected Database/Schema/Table.
    Expects row to have columns: 'database'/'DATABASE', 'schema'/'SCHEMA', 'asset_name'/'ASSET'/'FULL_NAME'
    """
    try:
        db = (row.get("database") or row.get("DATABASE") or "").upper()
        sch = (row.get("schema") or row.get("SCHEMA") or "").upper()
        name = (row.get("asset_name") or row.get("ASSET") or row.get("FULL_NAME") or "").upper()
        sdb = str(sel.get("database") or "").upper()
        ssch = str(sel.get("schema") or "").upper()
        stab = str(sel.get("table") or "").upper()

        # Database match
        if sdb and db and sdb != db:
            return False
        # Schema match: use schema column if present; else fall back to parsing FULL_NAME
        if ssch:
            if sch:
                if sch != ssch:
                    return False
            elif name and f".{ssch}." not in name:
                return False
        # Table match against trailing segment of FULL_NAME
        if stab and name and not (name.endswith(f".{stab}") or name == stab):
            return False
        return True
    except Exception:
        return True

def _business_days_between(start_d: Union[date, datetime], end_d: Union[date, datetime]) -> int:
    """Return business days (Mon-Fri) between two dates (positive if end is in future)."""
    try:
        s = pd.Timestamp(start_d).normalize()
        e = pd.Timestamp(end_d).normalize()
        if pd.isna(s) or pd.isna(e):
            return 0
        # Inclusive of end? We compute future days remaining from today to due (exclusive of today)
        if e <= s:
            return int(-pd.bdate_range(e, s, freq="B").size)
        return int(pd.bdate_range(s + pd.Timedelta(days=1), e, freq="B").size)
    except Exception:
        return 0

def _add_business_days(start_d: Union[date, datetime], n: int) -> date:
    """Add n business days to start date and return date."""
    try:
        s = pd.Timestamp(start_d).normalize()
        if n <= 0:
            return s.date()
        rng = pd.bdate_range(start=s + pd.Timedelta(days=1), periods=n, freq="B")
        return rng[-1].date() if len(rng) else s.date()
    except Exception:
        return pd.Timestamp(start_d).date()

def render_live_feed():
    """Realtime Snowflake live feed with refresh controls.
    Sources:
      - Asset Inventory (recently discovered/unclassified)
      - Recent Decisions (governance decisions)
      - Audit Trail (classification audit)
    """
    import time as _time

    st.caption("Realtime Snowflake feed. Uses the active database from the sidebar filters.")
    _apply_snowflake_context()
    db = _active_db_from_filter()
    if not db:
        st.info("Select a database from the Global Filters to enable live data.")
        return

    c1, c2, c3, c4 = st.columns([1.6, 1, 1, 1])
    with c1:
        source = st.selectbox(
            "Source",
            options=["Asset Inventory", "Recent Decisions", "Audit Trail"],
            index=0,
            key="live_source",
        )
    with c2:
        limit = st.number_input("Rows", min_value=10, max_value=2000, value=200, step=10, key="live_limit")
    with c3:
        interval = st.number_input("Interval (s)", min_value=5, max_value=300, value=30, step=5, key="live_interval")
    with c4:
        auto = st.toggle("Auto-refresh", value=False, key="live_auto")

    # Manual refresh
    colr1, colr2 = st.columns([1, 3])
    with colr1:
        force_refresh = st.button("Refresh now", key="live_refresh")
    with colr2:
        st.caption("Auto-refresh will re-run the app every N seconds while enabled.")

    @st.cache_data(ttl=5)
    def _fetch_live(_db: str, _source: str, _limit: int):
        try:
            gv = st.session_state.get("governance_schema") or "DATA_CLASSIFICATION_GOVERNANCE"
            gf = st.session_state.get("global_filters") or {}
            if _source == "Asset Inventory":
                where, params = _where_from_filters_for_fqn("FULLY_QUALIFIED_NAME", gf)
                sql = f"""
                    SELECT 
                      FULLY_QUALIFIED_NAME AS FULL_NAME,
                      BUSINESS_UNIT AS OBJECT_DOMAIN,
                      COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP) AS FIRST_DISCOVERED,
                      (CLASSIFICATION_LABEL IS NOT NULL) AS CLASSIFIED
                    FROM {_db}.{gv}.ASSETS
                    {('WHERE ' + ' AND '.join(where)) if where else ''}
                    ORDER BY COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP) DESC
                    LIMIT {_limit}
                """
                rows = snowflake_connector.execute_query(sql, params) or []
                return pd.DataFrame(rows)
            if _source == "Recent Decisions":
                dec_tbl = st.session_state.get("governance_decisions_table") or "CLASSIFICATION_DECISIONS"
                where, params = _where_from_filters_for_fqn("ASSET_FULL_NAME", gf)
                sql = f"""
                    SELECT ASSET_FULL_NAME, CLASSIFICATION_LABEL, C, I, A, DECISION_MAKER, STATUS, CREATED_AT
                    FROM {_db}.{gv}.{dec_tbl}
                    {('WHERE ' + ' AND '.join(where)) if where else ''}
                    ORDER BY COALESCE(CREATED_AT, CURRENT_TIMESTAMP()) DESC
                    LIMIT {_limit}
                """
                rows = snowflake_connector.execute_query(sql, params) or []
                return pd.DataFrame(rows)
            if _source == "Audit Trail":
                where, params = _where_from_filters_for_fqn("RESOURCE_ID", gf)
                sql = f"""
                    SELECT RESOURCE_ID, ACTION, DETAILS, CREATED_AT
                    FROM {_db}.{gv}.CLASSIFICATION_AUDIT
                    {('WHERE ' + ' AND '.join(where)) if where else ''}
                    ORDER BY COALESCE(CREATED_AT, CURRENT_TIMESTAMP()) DESC
                    LIMIT {_limit}
                """
                rows = snowflake_connector.execute_query(sql, params) or []
                return pd.DataFrame(rows)
        except Exception as e:
            st.warning(f"Live fetch failed: {e}")
        return pd.DataFrame()

    # Bust cache if manual refresh
    if force_refresh:
        try:
            st.cache_data.clear()
        except Exception:
            pass

    df_live = _fetch_live(db, source, int(limit))
    if df_live.empty:
        st.info("No rows returned for the selected source/filters.")
    else:
        st.dataframe(df_live, width='stretch')

    # Simple auto-refresh loop (blocking) only when enabled
    if auto:
        placeholder = st.empty()
        for i in range(int(interval), 0, -1):
            try:
                placeholder.caption(f"Refreshing in {i}s…")
                _time.sleep(1)
            except Exception:
                break
        placeholder.empty()
        st.rerun()

# (Removed) Sidebar scanning options (pre-tabs)

# Primary tabs per requirements
tab_new, tab_tasks, tab_qa = st.tabs([
    "New Classification",
    "Classification Management",
    "Quality Assurance (QA)",
])

with tab_new:
    pass

with tab_qa:
    st.subheader("Quality Assurance (QA)")
    qa_consistency, qa_peer, qa_metrics = st.tabs([
        "Consistency Checks",
        "Peer Review Dashboard",
        "Metrics Dashboard",
    ])

    # --- Consistency Checks ---
    with qa_consistency:
        st.markdown("#### Consistency Checks")
        st.caption("Detect similar datasets classified differently (by common object name across schemas/DBs) and governance vs tag drift.")
        db = _active_db_from_filter()
        group_by_suffix = st.checkbox("Group by object name only (ignore DB/Schema)", value=True, key="qa_consistency_group")
        sample_limit = st.slider("Max assets to analyze", 100, 5000, 1000, 100)
        run = st.button("Run Consistency Scan", type="primary", key="qa_consistency_run")

        if run:
            inconsistent_df = pd.DataFrame()
            drift_df = pd.DataFrame()
            try:
                # Prefer canonical ASSETS table if present
                if db:
                    gv = st.session_state.get("governance_schema") or "DATA_CLASSIFICATION_GOVERNANCE"
                    sql = f"""
                        select DATABASE_NAME, SCHEMA_NAME, ASSET_NAME,
                               coalesce(CLASSIFICATION_TAG, CURRENT_CLASSIFICATION, '') as CLASSIFICATION,
                               coalesce(CIA_C, 0) as C, coalesce(CIA_I, 0) as I, coalesce(CIA_A, 0) as A
                        from {db}.{gv}.ASSETS
                        qualify row_number() over (order by DATABASE_NAME, SCHEMA_NAME, ASSET_NAME) <= %(lim)s
                    """
                    rows = snowflake_connector.execute_query(sql, {"lim": int(sample_limit)}) or []
                else:
                    rows = []
            except Exception:
                rows = []

            if rows:
                df = pd.DataFrame(rows)
                for col in ["DATABASE_NAME","SCHEMA_NAME","ASSET_NAME","CLASSIFICATION"]:
                    if col not in df.columns:
                        df[col] = None
                key_col = "ASSET_NAME" if group_by_suffix else None
                if key_col:
                    grp = (df.assign(KEY=df[key_col].str.upper())
                             .groupby("KEY")
                             .agg(distinct_classes=("CLASSIFICATION", lambda s: len(set([str(x).upper() for x in s if str(x).strip()]))),
                                  samples=("CLASSIFICATION", "count"))
                             .reset_index())
                else:
                    df = df.assign(KEY=(df["DATABASE_NAME"].str.upper()+"."+df["SCHEMA_NAME"].str.upper()+"."+df["ASSET_NAME"].str.upper()))
                    grp = (df.groupby("KEY")
                             .agg(distinct_classes=("CLASSIFICATION", lambda s: len(set([str(x).upper() for x in s if str(x).strip()]))),
                                  samples=("CLASSIFICATION", "count"))
                             .reset_index())
                inconsistent = grp[grp["distinct_classes"] > 1]
                if not inconsistent.empty:
                    st.warning(f"Found {len(inconsistent)} inconsistent name group(s)")
                    st.dataframe(inconsistent.sort_values(["distinct_classes","samples"], ascending=False), width='stretch')
                    # Expand one group for detail preview
                    pick = st.selectbox("Inspect group", options=inconsistent["KEY"].tolist(), key="qa_consistency_pick")
                    if pick:
                        detail = df[df["KEY"] == pick].copy()
                        st.dataframe(detail[["DATABASE_NAME","SCHEMA_NAME","ASSET_NAME","CLASSIFICATION","C","I","A"]], width='stretch')
                else:
                    st.success("No cross-dataset classification inconsistencies detected in the sample.")
            else:
                st.info("ASSETS table not available or no rows returned. Falling back to tag drift sample.")

            # Tag drift check (governance vs applied tags)
            try:
                from src.services.tag_drift_service import analyze_tag_drift as _drift
            except Exception:
                _drift = None
            if _drift is not None:
                try:
                    drift = _drift(database=db, limit=sample_limit)
                    drift_items = pd.DataFrame(drift.get("items", []))
                    if not drift_items.empty:
                        st.markdown("---")
                        st.markdown("##### Governance vs Tag Drift")
                        st.dataframe(drift_items, width='stretch')
                        st.caption(f"Drift %: {drift.get('summary',{}).get('drift_pct', 0)} across {drift.get('summary',{}).get('total_assets_sampled', 0)} assets")
                    else:
                        st.info("No drift items detected in the sample.")
                except Exception as e:
                    st.warning(f"Tag drift analysis failed: {e}")

    # --- Peer Review Dashboard ---
    with qa_peer:
        st.markdown("#### Peer Review Dashboard")
        lb = st.slider("Lookback days", 7, 90, 30, 1, key="qa_peer_lb")
        me = None
        try:
            ident = authz.get_current_identity()
            me = getattr(ident, "user", None)
        except Exception:
            me = None

        pending = []
        total = 0
        error = None
        if cr_list_reviews is not None:
            try:
                all_res = cr_list_reviews(current_user=str(me or ""), review_filter="All", lookback_days=int(lb), page_size=200)
                pen_res = cr_list_reviews(current_user=str(me or ""), review_filter="Pending approvals", approval_status="All pending", lookback_days=int(lb), page_size=200)
                total = int(all_res.get("total", 0))
                pending = pen_res.get("reviews", [])
            except Exception as e:
                error = str(e)
        else:
            error = "Review service unavailable"

        pending_count = len(pending)
        completion_pct = round(100.0 * (1 - (pending_count / total)) , 2) if total else 100.0

        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Pending approvals", pending_count)
        with c2:
            st.metric("Review completion %", completion_pct)
        with c3:
            st.metric("Items in lookback", total)

        # Pending table with age buckets
        if pending_count:
            pdf = pd.DataFrame(pending)
            if "change_timestamp" in pdf.columns:
                try:
                    pdf["age_days"] = (pd.Timestamp.utcnow() - pd.to_datetime(pdf["change_timestamp"])) / pd.Timedelta(days=1)
                    pdf["age_days"] = pdf["age_days"].round(1)
                except Exception:
                    pdf["age_days"] = None
            st.dataframe(pdf[[c for c in ["database","schema","asset_name","classification","c_level","created_by","change_timestamp","age_days"] if c in pdf.columns]], width='stretch')

            # Aging chart
            try:
                bins = pd.cut(pdf["age_days"].fillna(0), bins=[-1,2,7,14,30,9999], labels=["<=2d","3-7d","8-14d","15-30d",">30d"])
                aging = bins.value_counts().sort_index()
                st.bar_chart(aging)
            except Exception:
                pass
        if error:
            st.caption(f"Note: {error}")

    # --- Metrics Dashboard ---
    with qa_metrics:
        st.markdown("#### Metrics Dashboard")
        db = _active_db_from_filter()
        cov = {"total_assets": 0, "tagged_assets": 0, "coverage_pct": 0.0}
        hist = []
        drift_pct = None
        pass_rate = None

        # Coverage via metrics_service
        if metrics_service is not None:
            try:
                cov = metrics_service.classification_coverage(database=db)
            except Exception:
                pass

        # Accuracy proxy via tag drift (accuracy = 100 - drift%)
        try:
            from src.services.tag_drift_service import analyze_tag_drift as _drift
            dsum = _drift(database=db, limit=1000).get("summary", {})
            drift_pct = float(dsum.get("drift_pct", 0))
        except Exception:
            drift_pct = None

        # Audit pass rate from recent check results
        if compliance_service is not None:
            try:
                checks = compliance_service.list_check_results(limit=1000) or []
                if checks:
                    total_checks = len(checks)
                    passed = sum(1 for c in checks if bool(c.get("PASSED")))
                    pass_rate = round(100.0 * passed / total_checks, 2)
            except Exception:
                pass

        # KPI tiles
        m1, m2, m3 = st.columns(3)
        with m1:
            st.metric("Classification coverage %", value=cov.get("coverage_pct", 0.0), delta=f"{cov.get('tagged_assets',0)}/{cov.get('total_assets',0)} tagged")
        with m2:
            acc = None if drift_pct is None else round(100.0 - float(drift_pct), 2)
            st.metric("Accuracy rate (proxy)", value=(acc if acc is not None else "N/A"), delta=(f"Drift {drift_pct}%" if drift_pct is not None else None))
        with m3:
            st.metric("Audit pass rate", value=(pass_rate if pass_rate is not None else "N/A"))

        # Timeliness KPI: Past Due (≥5 business days)
        past_due_count = None
        try:
            if db:
                gv = st.session_state.get("governance_schema") or "DATA_CLASSIFICATION_GOVERNANCE"
                # Detect an available date column to use (some environments may lack LAST_CLASSIFIED_DATE)
                try:
                    col_rows = snowflake_connector.execute_query(
                        f"""
                        select upper(COLUMN_NAME) as CN
                        from {db}.INFORMATION_SCHEMA.COLUMNS
                        where TABLE_SCHEMA=%(s)s and TABLE_NAME='ASSETS'
                        """,
                        {"s": gv}
                    ) or []
                    cols = {r.get("CN") for r in col_rows}
                except Exception:
                    cols = set()
                # Preferred columns in order
                preferred = [
                    "LAST_CLASSIFIED_DATE",
                    "LAST_REVIEW_DATE",
                    "LAST_MODIFIED_DATE",
                    "UPDATED_TIMESTAMP",
                    "CREATED_DATE",
                ]
                date_col = next((c for c in preferred if c in cols), None)
                if date_col is None:
                    # No suitable column; skip KPI gracefully
                    past_due_count = None
                else:
                    sql_pd = f"""
                        select
                          count(*) as total,
                          sum(CASE
                                WHEN {date_col} IS NULL THEN 1
                                WHEN {date_col} < DATEADD(day, -5, CURRENT_DATE()) THEN 1
                                ELSE 0
                              END) as past_due
                        from {db}.{gv}.ASSETS
                    """
                    try:
                        rows_pd = snowflake_connector.execute_query(sql_pd) or []
                    except Exception:
                        rows_pd = []
                    if rows_pd:
                        past_due_count = int(rows_pd[0].get("PAST_DUE") or rows_pd[0].get("past_due") or 0)
        except Exception:
            past_due_count = None

        if past_due_count is not None:
            c_pd1, c_pd2 = st.columns([1, 3])
            with c_pd1:
                st.metric("Past Due (≥5d)", value=past_due_count)

        # Special Category Counts: PII, Financial, Regulatory
        pii_cnt = fin_cnt = reg_cnt = None
        try:
            if db:
                gv = st.session_state.get("governance_schema") or "DATA_CLASSIFICATION_GOVERNANCE"
                sql_cat = f"""
                    select
                      sum(CASE WHEN COALESCE(CONTAINS_PII, false) THEN 1 ELSE 0 END) as pii,
                      sum(CASE WHEN COALESCE(CONTAINS_FINANCIAL_DATA, false) THEN 1 ELSE 0 END) as financial,
                      sum(CASE WHEN COALESCE(REGULATORY_DATA, false) THEN 1 ELSE 0 END) as regulatory
                    from {db}.{gv}.ASSETS
                """
                rows_cat = snowflake_connector.execute_query(sql_cat) or []
                if rows_cat:
                    pii_cnt = int(rows_cat[0].get("PII") or rows_cat[0].get("pii") or 0)
                    fin_cnt = int(rows_cat[0].get("FINANCIAL") or rows_cat[0].get("financial") or 0)
                    reg_cnt = int(rows_cat[0].get("REGULATORY") or rows_cat[0].get("regulatory") or 0)
        except Exception:
            pii_cnt = fin_cnt = reg_cnt = None

        if any(v is not None for v in [pii_cnt, fin_cnt, reg_cnt]):
            st.markdown("##### Special Category Counts")
            sc1, sc2, sc3 = st.columns(3)
            with sc1:
                st.metric("PII Assets", value=(pii_cnt if pii_cnt is not None else "N/A"))
            with sc2:
                st.metric("SOX Assets", value=(fin_cnt if fin_cnt is not None else "N/A"))
            with sc3:
                st.metric("Regulatory Assets", value=(reg_cnt if reg_cnt is not None else "N/A"))

        # Policy Guidance (Quick Reference)
        with st.expander("Policy Guidance (Quick Reference)", expanded=False):
            st.markdown("""
            - Decision Tree: Public? If yes → Public (C0). Else contains personal/proprietary/confidential? If yes → Severe harm? If yes → Confidential (C3) else Restricted (C2). Then assess I and A.
            - Checklist (Before): Understand purpose; identify stakeholders; consider regulations; assess C/I/A impact; review similar data; document rationale.
            - Checklist (After): Apply tags; document decision; communicate; schedule review; ensure handling procedures are followed.
            """)
            st.caption("See full policy: docs/DATA_CLASSIFICATION_POLICY.md")

        # Trends and breakdowns
        if metrics_service is not None:
            try:
                hist = metrics_service.historical_classifications(database=db, days=30) or []
                if hist:
                    hdf = pd.DataFrame(hist)
                    hdf = hdf.rename(columns={"DAY": "Day", "DECISIONS": "Decisions"})
                    st.markdown("##### Decisions over last 30 days")
                    st.bar_chart(hdf.set_index("Day")[["Decisions"]])
            except Exception:
                pass

        # Framework counts (optional)
        if metrics_service is not None:
            try:
                fc = metrics_service.framework_counts(database=db)
                if fc:
                    fdf = pd.DataFrame([fc]).T.reset_index()
                    fdf.columns = ["Framework", "Count"]
                    st.markdown("##### Compliance framework counts")
                    st.bar_chart(fdf.set_index("Framework")[["Count"]])
            except Exception:
                pass

with tab_new:
    st.subheader("New Classification")
    sub_guided, sub_bulk, sub_ai = st.tabs(["Guided Workflow", "Bulk Upload", "AI Assistant"])
    
    # Bulk Upload
    with sub_bulk:
        st.markdown("#### Bulk Classification Tool")
        st.markdown("""
**Review Your Data**  
• Ensure you have the necessary permissions to classify this data  
• Verify no sensitive credentials are included

**Required Columns**  
• `DATA_ASSET_PATH` (format: `DATABASE.SCHEMA.TABLE`)  
• `BUSINESS_CONTEXT` (describe the data's purpose)  
• `DATA_OWNER_EMAIL` (must be @avendra.com)

**Optional Columns**  
• `C`/`I`/`A`: 0-3 (leave blank for auto-suggestion)  
• `BUSINESS_RATIONALE` (required for overrides)

**File Requirements**  
• Max size: 10MB  
• Format: CSV (UTF-8)  
• No special characters in headers  
• No empty rows between data

**What Happens Next**  
1. Instant validation  
2. Automatic processing  
3. Email notification with results

_Download the template below to begin_
""", unsafe_allow_html=True)
        
        # Download template section
        try:
            _tmpl_csv = (
                "DATA_ASSET_PATH,BUSINESS_CONTEXT,DATA_OWNER_EMAIL,C,I,A,BUSINESS_RATIONALE,FORCE_OVERRIDE,MANUAL_CATEGORY,MANUAL_C,MANUAL_I,MANUAL_A\n"
                "DATA_DB.PUBLIC.CUSTOMERS,Customer analytics for retention campaigns,owner@avendra.com,,,,Contains PII; restrict access per policy,false,PII,,,\n"
            )
            st.download_button(
                label="Download CSV Template",
                data=_tmpl_csv,
                file_name="bulk_semantic_classification_template.csv",
                mime="text/csv",
                key="bulk_semantic_tmpl_dl_btn",
            )
            st.caption("Required: DATA_ASSET_PATH, BUSINESS_CONTEXT, DATA_OWNER_EMAIL. Optional: C,I,A,BUSINESS_RATIONALE and manual overrides (FORCE_OVERRIDE, MANUAL_CATEGORY or MANUAL_C/I/A)")
        except Exception:
            pass

        up = st.file_uploader("Upload CSV/XLSX for semantic bulk processing", type=["csv","xlsx"], key="nc_bulk_upl")
        if up is not None:
            import pandas as _pd
            import re as _re
            try:
                bdf = _pd.read_csv(up) if up.name.lower().endswith('.csv') else _pd.read_excel(up)
            except Exception as e:
                st.error(f"Bulk parse failed: {e}")
                bdf = _pd.DataFrame()

            if not bdf.empty:
                # Normalize headers
                cols_up = {c.strip().upper(): c for c in bdf.columns}
                # Backward compatibility support
                cols_up.setdefault("DATA_ASSET_PATH", cols_up.get("FULL_NAME") or cols_up.get("ASSET") or cols_up.get("TABLE"))
                # Validators
                def _is_fqn(val: str) -> bool:
                    try:
                        s = str(val or "").strip()
                        parts = [p.strip('"') for p in s.split('.')]
                        return len(parts) == 3 and all(p for p in parts)
                    except Exception:
                        return False
                def _is_email(val: str) -> bool:
                    try:
                        s = str(val or "").strip()
                        return bool(_re.match(r"^[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+)\.[A-Za-z]{2,}$", s)) and s.lower().endswith("@avendra.com")
                    except Exception:
                        return False
                def _object_exists(full: str) -> bool:
                    try:
                        parts = [p.strip('"') for p in str(full).split('.')]
                        if len(parts) != 3:
                            return False
                        db, sc, tb = parts
                        def _q(x: str) -> str:
                            return '"' + str(x).replace('"','""') + '"'
                        rows = snowflake_connector.execute_query(
                            f"SELECT 1 FROM {_q(db)}.INFORMATION_SCHEMA.TABLES WHERE UPPER(TABLE_SCHEMA) = UPPER(%(s)s) AND UPPER(TABLE_NAME) = UPPER(%(t)s)\n"
                            f"UNION ALL\n"
                            f"SELECT 1 FROM {_q(db)}.INFORMATION_SCHEMA.VIEWS WHERE UPPER(TABLE_SCHEMA) = UPPER(%(s)s) AND UPPER(TABLE_NAME) = UPPER(%(t)s)\n"
                            f"LIMIT 1",
                            {"s": sc, "t": tb},
                        ) or []
                        return len(rows) > 0
                    except Exception:
                        return False
                # Semantic detection from business context and patterns
                def _semantic_from_context(text: str) -> Dict[str, float]:
                    scores: Dict[str, float] = {}
                    if not text:
                        return scores
                    try:
                        # AI semantic category scores
                        ai_out = ai_classification_service.classify_texts(texts=[str(text)])
                        cats = (ai_out or {}).get("categories") or {}
                        for k, v in cats.items():
                            try:
                                scores[str(k).upper()] = max(scores.get(str(k).upper(), 0.0), float(v))
                            except Exception:
                                continue
                    except Exception:
                        pass
                    # Keyword/pattern reinforcement using governance-configured rows
                    try:
                        kw_rows = getattr(ai_sensitive_detection_service, 'keyword_rows', [])
                        pat_rows = getattr(ai_sensitive_detection_service, 'pattern_rows', [])
                        t_up = str(text).upper()
                        for r in (kw_rows or []):
                            if not r.get("IS_ACTIVE", True):
                                continue
                            cat = str(r.get("SENSITIVITY_TYPE") or r.get("CATEGORY_NAME") or "").upper()
                            kw = str(r.get("KEYWORD") or "").upper().strip()
                            if kw and kw in t_up:
                                w = float(r.get("SCORE") or 0.5)
                                scores[cat] = max(scores.get(cat, 0.0), min(1.0, w))
                        for p in (pat_rows or []):
                            if not p.get("IS_ACTIVE", True):
                                continue
                            cat = str(p.get("SENSITIVITY_TYPE") or p.get("CATEGORY_ID") or "").upper()
                            pref = p.get("PATTERN_REGEX") or p.get("PATTERN_STRING")
                            try:
                                if pref and _re.search(str(pref), str(text)):
                                    w = float(p.get("SCORE") or p.get("WEIGHT") or 0.6)
                                    scores[cat] = max(scores.get(cat, 0.0), min(1.0, w))
                            except Exception:
                                continue
                        # Synonym boosts for common phrases (PII/Financial/Regulatory)
                        try:
                            syn_boosts = {
                                "PII": [
                                    "SOCIAL SECURITY", "SSN", "NATIONAL INSURANCE", "NINO", "CUSTOMER CONTACT",
                                    "EMAIL", "E-MAIL", "PHONE", "CONTACT NUMBER", "ADDRESS", "DATE OF BIRTH", "DOB"
                                ],
                                "FINANCIAL": [
                                    "GL", "LEDGER", "INVOICE", "ACCOUNT NUMBER", "BANK", "IBAN", "SWIFT",
                                    "TRANSACTION", "PAYMENT", "BALANCE", "CREDIT", "DEBIT"
                                ],
                                "REGULATORY": ["GDPR", "CCPA", "HIPAA", "PCI DSS", "REGULATORY", "COMPLIANCE"],
                                "PCI": ["CREDIT CARD", "CARDHOLDER", "PAN", "CVV", "EXPIRY"],
                                "SOX": ["SOX", "FINANCIAL REPORT", "AUDIT", "IFRS", "GAAP"],
                            }
                            for cat, phrases in syn_boosts.items():
                                for phrase in phrases:
                                    if phrase in t_up:
                                        base = 0.85 if phrase in ("SOCIAL SECURITY", "SSN", "ACCOUNT NUMBER", "CREDIT CARD", "PAN") else 0.7
                                        scores[cat] = max(scores.get(cat, 0.0), base)
                        except Exception:
                            pass
                    except Exception:
                        pass
                    return scores
                def _map_category_to_cia(cat_up: str) -> Tuple[int,int,int]:
                    m = {
                        "PERSONAL": (2,3,2),
                        "PII": (2,3,2),
                        "PHI": (3,3,2),
                        "HIPAA": (3,3,2),
                        "FINANCIAL": (2,2,2),
                        "SOX": (3,2,2),
                        "PCI": (3,2,2),
                        "REGULATORY": (3,2,2),
                        "GDPR": (3,2,2),
                        "CCPA": (3,2,2),
                        "INTERNAL": (1,1,1),
                    }
                    return m.get(cat_up, (1,1,1))
                def _route(conf: float, c_val: int, sensitive: bool) -> str:
                    try:
                        if conf >= 0.85 and (not sensitive or c_val <= 2):
                            return "AUTO_APPROVE"
                        if conf >= 0.7 and c_val <= 2:
                            return "EXPEDITED_REVIEW"
                        if conf >= 0.5:
                            return "STANDARD_REVIEW"
                        return "ENHANCED_REVIEW"
                    except Exception:
                        return "STANDARD_REVIEW"

                # Build enriched preview with validation, detection, mapping
                bad_rows = []
                rows_view = []
                for _, r in bdf.iterrows():
                    full = str(r.get(cols_up.get("DATA_ASSET_PATH")))
                    context_txt = str(r.get(cols_up.get("BUSINESS_CONTEXT")) or "").strip()
                    owner_email = str(r.get(cols_up.get("DATA_OWNER_EMAIL")) or "").strip()
                    # Raw CIA (optional)
                    try:
                        c_raw = r.get(cols_up.get("C"))
                        c_raw = int(c_raw) if str(c_raw).strip() != "" and c_raw is not None else None
                    except Exception:
                        c_raw = None
                    try:
                        i_raw = r.get(cols_up.get("I"))
                        i_raw = int(i_raw) if str(i_raw).strip() != "" and i_raw is not None else None
                    except Exception:
                        i_raw = None
                    try:
                        a_raw = r.get(cols_up.get("A"))
                        a_raw = int(a_raw) if str(a_raw).strip() != "" and a_raw is not None else None
                    except Exception:
                        a_raw = None
                    rationale = str(r.get(cols_up.get("BUSINESS_RATIONALE")) or "").strip()
                    # Manual override support
                    force_override = False
                    manual_cat = None
                    manual_c = manual_i = manual_a = None
                    try:
                        force_val = r.get(cols_up.get("FORCE_OVERRIDE"))
                        force_override = str(force_val).strip().lower() in {"1","true","yes","y"}
                    except Exception:
                        force_override = False
                    try:
                        manual_cat = str(r.get(cols_up.get("MANUAL_CATEGORY") or cols_up.get("OVERRIDE_CATEGORY")) or "").strip().upper() or None
                    except Exception:
                        manual_cat = None
                    try:
                        mv = r.get(cols_up.get("MANUAL_C") or cols_up.get("OVERRIDE_C"))
                        manual_c = int(mv) if mv not in (None, "") else None
                    except Exception:
                        manual_c = None
                    try:
                        mv = r.get(cols_up.get("MANUAL_I") or cols_up.get("OVERRIDE_I"))
                        manual_i = int(mv) if mv not in (None, "") else None
                    except Exception:
                        manual_i = None
                    try:
                        mv = r.get(cols_up.get("MANUAL_A") or cols_up.get("OVERRIDE_A"))
                        manual_a = int(mv) if mv not in (None, "") else None
                    except Exception:
                        manual_a = None

                    errs = []
                    if not _is_fqn(full):
                        errs.append("Invalid DATA_ASSET_PATH (expected DB.SCHEMA.TABLE)")
                    if not _is_email(owner_email):
                        errs.append("DATA_OWNER_EMAIL must be @avendra.com")
                    if _is_fqn(full) and not _object_exists(full):
                        errs.append("Snowflake object not found")
                    for name, val in (("C", c_raw), ("I", i_raw), ("A", a_raw)):
                        if val is not None and (val < 0 or val > 3):
                            errs.append(f"{name} must be in 0..3")
                    if len(context_txt) < 5:
                        errs.append("BUSINESS_CONTEXT too short")

                    # Semantic detection
                    scores = _semantic_from_context(context_txt)
                    # Merge with table-level detection (optional boost)
                    try:
                        parts = [p.strip('"') for p in full.split('.')]
                        if len(parts) == 3:
                            db, sc, tb = parts
                            dets = ai_sensitive_detection_service.detect_sensitive_columns(db, sc, tb)
                            cat_set = set()
                            for d in (dets or []):
                                for t in (getattr(d, 'detected_categories', []) or []):
                                    cat_set.add(str(t).upper())
                            for cat in cat_set:
                                scores[cat] = max(scores.get(cat, 0.0), 0.7)  # reinforcement
                    except Exception:
                        pass
                    # Aggregate best category
                    top_cat = None
                    top_score = 0.0
                    for k, v in (scores or {}).items():
                        if v >= top_score:
                            top_cat, top_score = k, float(v)
                    # Map to CIA defaults
                    if top_cat:
                        c_def, i_def, a_def = _map_category_to_cia(str(top_cat).upper())
                    else:
                        c_def, i_def, a_def = (1,1,1)
                    c_s = c_raw if c_raw is not None else c_def
                    i_s = i_raw if i_raw is not None else i_def
                    a_s = a_raw if a_raw is not None else a_def
                    # Enforce policy minimums based on any detected categories (not just top category)
                    try:
                        detected_keys = {str(k).upper() for k in (scores or {}).keys()}
                        # include table-level category reinforcements
                        try:
                            for k2 in list(cat_set or []):
                                detected_keys.add(str(k2).upper())
                        except Exception:
                            pass
                        min_c_req = 0
                        if {"GDPR","CCPA","REGULATORY","HIPAA","PCI","PCI DSS"} & detected_keys:
                            min_c_req = max(min_c_req, 3)
                        if {"PII","PERSONAL"} & detected_keys:
                            min_c_req = max(min_c_req, 2)
                        if {"FINANCIAL","SOX"} & detected_keys:
                            min_c_req = max(min_c_req, 2)
                        if min_c_req > 0:
                            c_s = max(int(c_s), int(min_c_req))
                    except Exception:
                        pass
                    # Apply manual overrides (bypasses detection but not policy)
                    if force_override:
                        if manual_cat:
                            oc, oi, oa = _map_category_to_cia(manual_cat)
                            c_s = c_s if manual_c is None else manual_c
                            i_s = i_s if manual_i is None else manual_i
                            a_s = a_s if manual_a is None else manual_a
                            # If no CIA provided with category, use defaults
                            if manual_c is None and manual_i is None and manual_a is None:
                                c_s, i_s, a_s = oc, oi, oa
                        else:
                            c_s = c_s if manual_c is None else manual_c
                            i_s = i_s if manual_i is None else manual_i
                            a_s = a_s if manual_a is None else manual_a
                    # Enforce policy minimums pre-check
                    label_s = ["Public","Internal","Restricted","Confidential"][max(c_s, i_s, a_s)]
                    ok_dm, reasons_dm = dm_validate(label_s, int(c_s), int(i_s), int(a_s))
                    issue = None if ok_dm else "; ".join([str(x) for x in (reasons_dm or [])])
                    # Workflow route
                    route = _route(float(top_score or 0.0), int(c_s), sensitive=(max(c_s, i_s, a_s) >= 2))
                    # Require rationale for higher sensitivity
                    if label_s in ("Restricted","Confidential") and not rationale:
                        errs.append("BUSINESS_RATIONALE required for Restricted/Confidential")

                    rows_view.append({
                        "FULL_NAME": full,
                        "OWNER_EMAIL": owner_email,
                        "BUSINESS_CONTEXT": context_txt,
                        "AUTO_CATEGORY": top_cat or "INTERNAL",
                        "CONFIDENCE": round(float(top_score or 0.0), 3),
                        "SUGGESTED_C": int(c_s),
                        "SUGGESTED_I": int(i_s),
                        "SUGGESTED_A": int(a_s),
                        "SUGGESTED_LABEL": label_s,
                        "ROUTE": route,
                        "ERRORS": "; ".join(errs) if errs else "",
                        "POLICY_OK": bool(ok_dm and not errs),
                        "ISSUE": issue,
                        "RATIONALE": rationale,
                        "FORCE_OVERRIDE": bool(force_override),
                        "MANUAL_CATEGORY": manual_cat or "",
                    })
                    if errs:
                        bad_rows.append(full)

                vdf = _pd.DataFrame(rows_view)
                st.dataframe(vdf, width='stretch')
                st.caption("Rows with errors cannot be submitted. Routes: AUTO_APPROVE, EXPEDITED (1 day), STANDARD (2 days), ENHANCED (committee)")

                can_submit = not vdf.empty and all(not str(e or "").strip() for e in vdf["ERRORS"].tolist())
                has_valid_some = not vdf.empty and any(not str(e or "").strip() for e in vdf["ERRORS"].tolist())
                if not can_submit:
                    st.warning("Fix validation errors before submitting or submit only valid rows.")
                    try:
                        import pandas as _pd2
                        err_rows = vdf[vdf["ERRORS"].astype(str).str.strip() != ""]
                        if not err_rows.empty:
                            _csv = err_rows.to_csv(index=False)
                            st.download_button("Download Error Report CSV", data=_csv, file_name="bulk_errors.csv", mime="text/csv", key="bulk_err_dl")
                    except Exception:
                        pass

                # Create columns for the buttons
                col1, col2 = st.columns([1, 1])
                
                with col1:
                    if st.button("Submit Valid Rows Only", type="secondary", disabled=not has_valid_some, key="bulk_submit_valid_only"):
                        v_valid = vdf[vdf["ERRORS"].astype(str).str.strip() == ""]
                        if v_valid.empty:
                            st.info("No valid rows to submit.")
                        else:
                            # This will be replaced by the actual logic below
                            st.rerun()
                
                with col2:
                    if st.button("Submit Batch", type="primary", disabled=not can_submit, key="bulk_submit_btn"):
                        # Initialize counters
                        applied = 0
                        queued = 0
                        failed = 0
                        for _, rr in vdf.iterrows():
                            full = str(rr.get("FULL_NAME"))
                            try:
                                c_s = int(rr.get("SUGGESTED_C"))
                                i_s = int(rr.get("SUGGESTED_I"))
                                a_s = int(rr.get("SUGGESTED_A"))
                                lbl = str(rr.get("SUGGESTED_LABEL") or "Internal")
                                route = str(rr.get("ROUTE") or "STANDARD_REVIEW")
                                owner_email = str(rr.get("OWNER_EMAIL") or "system")
                                rationale = str(rr.get("RATIONALE") or "")
                                
                                # Tags (uppercase for TaggingService)
                                tags = {
                                    "DATA_CLASSIFICATION": lbl,
                                    "CONFIDENTIALITY_LEVEL": str(c_s),
                                    "INTEGRITY_LEVEL": str(i_s),
                                    "AVAILABILITY_LEVEL": str(a_s),
                                }
                                
                                if route == "AUTO_APPROVE":
                                    try:
                                        if not authz.can_apply_tags_for_object(full, object_type="TABLE"):
                                            raise Exception("Insufficient privileges to apply tags")
                                        tagging_service.apply_tags_to_object(full, "TABLE", tags)
                                        try:
                                            classification_decision_service.record(
                                                asset_full_name=full,
                                                decision_by=owner_email,
                                                source="BULK_SEMANTIC",
                                                status="Applied",
                                                label=lbl,
                                                c=int(c_s), i=int(i_s), a=int(a_s),
                                                rationale=rationale,
                                                details={"route": route, "auto_category": rr.get("AUTO_CATEGORY"), "confidence": rr.get("CONFIDENCE")},
                                            )
                                        except Exception:
                                            pass
                                        try:
                                            _sf_audit_log_classification(full, "BULK_AUTO_APPROVED", {"label": lbl, "c": c_s, "i": i_s, "a": a_s, "confidence": rr.get("CONFIDENCE")})
                                        except Exception:
                                            pass
                                        applied += 1
                                    except Exception as e:
                                        st.error(f"Failed to process auto-approval for {full}: {str(e)}")
                                        failed += 1
                                else:
                                    # Queue for review via decision service
                                    try:
                                        classification_decision_service.record(
                                            asset_full_name=full,
                                            decision_by=owner_email,
                                            source="BULK_SEMANTIC",
                                            status="Submitted",
                                            label=lbl,
                                            c=int(c_s), i=int(i_s), a=int(a_s),
                                            rationale=rationale or f"Routed to {route}",
                                            details={"route": route, "auto_category": rr.get("AUTO_CATEGORY"), "confidence": rr.get("CONFIDENCE")},
                                        )
                                        try:
                                            _sf_audit_log_classification(full, "BULK_QUEUED_REVIEW", {"label": lbl, "c": c_s, "i": i_s, "a": a_s, "route": route, "confidence": rr.get("CONFIDENCE")})
                                        except Exception:
                                            pass
                                        queued += 1
                                    except Exception as e:
                                        st.error(f"Failed to queue {full} for review: {str(e)}")
                                        failed += 1
                            except Exception as e:
                                failed += 1
                                st.error(f"Failed to process row for {full}: {str(e)}")
                                continue
                # Submit valid rows only (skips rows with errors)
                if 'bulk_submit_valid_only' in st.session_state and st.session_state.get('bulk_submit_valid_only'):
                    st.session_state.bulk_submit_valid_only = False  # Reset the state
                    v_valid = vdf[vdf["ERRORS"].astype(str).str.strip() == ""]
                    if v_valid.empty:
                        st.info("No valid rows to submit.")
                    else:
                        applied = 0; queued = 0; failed = 0
                        for _, rr in v_valid.iterrows():
                            try:
                                full = str(rr.get("FULL_NAME"))
                                c_s = int(rr.get("SUGGESTED_C")); i_s = int(rr.get("SUGGESTED_I")); a_s = int(rr.get("SUGGESTED_A"))
                                lbl = str(rr.get("SUGGESTED_LABEL") or "Internal")
                                route = str(rr.get("ROUTE") or "STANDARD_REVIEW")
                                owner_email = str(rr.get("OWNER_EMAIL") or "system")
                                rationale = str(rr.get("RATIONALE") or "")
                                tags = {
                                    "DATA_CLASSIFICATION": lbl,
                                    "CONFIDENTIALITY_LEVEL": str(c_s),
                                    "INTEGRITY_LEVEL": str(i_s),
                                    "AVAILABILITY_LEVEL": str(a_s),
                                }
                                if route == "AUTO_APPROVE":
                                    try:
                                        if not authz.can_apply_tags_for_object(full, object_type="TABLE"):
                                            raise Exception("Insufficient privileges to apply tags")
                                    except Exception:
                                        pass
                                    tagging_service.apply_tags_to_object(full, "TABLE", tags)
                                    try:
                                        classification_decision_service.record(
                                            asset_full_name=full,
                                            decision_by=owner_email,
                                            source="BULK_SEMANTIC",
                                            status="Applied",
                                            label=lbl,
                                            c=int(c_s), i=int(i_s), a=int(a_s),
                                            rationale=rationale,
                                            details={"route": route, "auto_category": rr.get("AUTO_CATEGORY"), "confidence": rr.get("CONFIDENCE")},
                                        )
                                    except Exception:
                                        pass
                                    try:
                                        _sf_audit_log_classification(full, "BULK_AUTO_APPROVED", {"label": lbl, "c": c_s, "i": i_s, "a": a_s, "confidence": rr.get("CONFIDENCE")})
                                    except Exception:
                                        pass
                                    applied += 1
                                else:
                                    try:
                                        classification_decision_service.record(
                                            asset_full_name=full,
                                            decision_by=owner_email,
                                            source="BULK_SEMANTIC",
                                            status="Submitted",
                                            label=lbl,
                                            c=int(c_s), i=int(i_s), a=int(a_s),
                                            rationale=rationale or f"Routed to {route}",
                                            details={"route": route, "auto_category": rr.get("AUTO_CATEGORY"), "confidence": rr.get("CONFIDENCE")},
                                        )
                                    except Exception:
                                        pass
                                    try:
                                        _sf_audit_log_classification(full, "BULK_QUEUED_REVIEW", {"label": lbl, "c": c_s, "i": i_s, "a": a_s, "route": route, "confidence": rr.get("CONFIDENCE")})
                                    except Exception:
                                        pass
                                    queued += 1
                            except Exception as e:
                                failed += 1
                                st.error(f"Failed row for {rr.get('FULL_NAME')}: {e}")
                        if failed == 0:
                            st.success(f"Submitted valid rows — Applied: {applied}, Queued: {queued}")
                        else:
                            st.warning(f"Submitted valid rows with some errors — Applied: {applied}, Queued: {queued}, Failed: {failed}")

    # AI Assistant tab
    with sub_ai:
        # Render AI Assistant sub-tabs via modular services
        ai_overview_tab, ai_pipeline_tab = st.tabs([
            "Sensitive Tables Overview",
            "Automatic AI Classification Pipeline",
        ])

        with ai_overview_tab:
            try:
                ai_sensitive_tables_service.render_sensitive_tables_overview()
            except Exception as e:
                st.error(f"Failed to render Sensitive Tables Overview: {e}")

        with ai_pipeline_tab:
            try:
                ai_classification_pipeline_service.render_classification_pipeline()
            except Exception as e:
                st.error(f"Failed to render AI Classification Pipeline: {e}")

    _LEGACY_AI_ASSISTANT_DISABLED = '''
                      'PUBLIC': {'BASELINE_LABEL': 'Public', 'BASELINE_C': 0, 'BASELINE_I': 0, 'BASELINE_A': 0, 'COMPLIANCE': 'Public Disclosure'},
                        }
                        specials = []
                        def _label_from_cia(_c: int, _i: int, _a: int) -> str:
                            try:
                                c2, i2, a2 = int(_c or 0), int(_i or 0), int(_a or 0)
                            except Exception:
                                c2, i2, a2 = 0, 0, 0
                            if c2 >= 3 and i2 >= 3 and a2 >= 2:
                                return 'Confidential'
                            if c2 >= 2 and i2 >= 2 and (1 <= a2 <= 2):
                                return 'Restricted'
                            if c2 == 1 and i2 == 1 and a2 == 1:
                                return 'Internal'
                            if c2 == 0 and i2 == 0 and a2 == 0:
                                return 'Public'
                            # Fallback by highest level present
                            if max(c2, i2, a2) >= 3:
                                return 'Confidential'
                            if max(c2, i2, a2) == 2:
                                return 'Restricted'
                            if max(c2, i2, a2) == 1:
                                return 'Internal'
                            return 'Public'
                        def _risk_from_cia(_c: int, _i: int, _a: int) -> str:
                            try:
                                c2, i2, a2 = int(_c or 0), int(_i or 0), int(_a or 0)
                            except Exception:
                                c2, i2, a2 = 0, 0, 0
                            if max(c2, i2, a2) >= 3:
                                return 'High'
                            if (2 in (c2, i2, a2)):
                                return 'Medium'
                            return 'Low'
                        def _risk_action(level: str) -> str:
                            l = str(level or '').lower()
                            if l == 'high':
                                return 'Strict governance and encryption'
                            if l == 'medium':
                                return 'Moderate monitoring and control'
                            return 'Standard retention and access'
                        for t in tables:
                            cat = _norm_cat(str(t.get('category') or ''))
                            if cat in special_set:
                                _cm = comp_map.get(cat) or {}
                                _bl = str(_cm.get('BASELINE_LABEL') or '')
                                _bc = _cm.get('BASELINE_C')
                                _bi = _cm.get('BASELINE_I')
                                _ba = _cm.get('BASELINE_A')
                                _cr = str(_cm.get('COMPLIANCE') or '')
                                # Use detected CIA if present, else category baseline
                                eff_c = t.get('c') if t.get('c') is not None else _bc
                                eff_i = t.get('i') if t.get('i') is not None else _bi
                                eff_a = t.get('a') if t.get('a') is not None else _ba
                                rule_label = _label_from_cia(eff_c, eff_i, eff_a)
                                risk_level = _risk_from_cia(eff_c, eff_i, eff_a)
                                # Map route to review status
                                def _review_status(route: str) -> str:
                                    r = str(route or '').upper()
                                    if r == 'AUTO_APPROVE':
                                        return 'Applied'
                                    if r in ('EXPEDITED_REVIEW','STANDARD_REVIEW','ENHANCED_REVIEW'):
                                        return 'Queued'
                                    return 'Pending'
                                specials.append({
                                    'FULLY_QUALIFIED_NAME': t.get('fqn'),
                                    'CATEGORY': cat,
                                    'CONFIDENCE': round(float(t.get('confidence') or 0.0), 4),
                                    'C': eff_c,
                                    'I': eff_i,
                                    'A': eff_a,
                                    'ROUTE': t.get('route'),
                                    'REVIEW_STATUS': _review_status(t.get('route')),
                                    'ROW_COUNT': t.get('row_count'),
                                    'SCHEMA': t.get('schema'),
                                    'TABLE': t.get('table'),
                                    'BASELINE_LABEL': _bl,
                                    'BASELINE_C': _bc,
                                    'BASELINE_I': _bi,
                                    'BASELINE_A': _ba,
                                    'COMPLIANCE': _cr,
                                    'RULE_LABEL': rule_label,
                                    'RISK_LEVEL': risk_level,
                                    'RISK_ACTION': _risk_action(risk_level),
                                })
                        # Apply global filters to specials
                        if sel_schema:
                            specials = [r for r in specials if str(r.get('SCHEMA') or '').upper() == str(sel_schema).upper()]
                        if sel_table_filter:
                            _tf = str(sel_table_filter).upper()
                            specials = [r for r in specials if _tf in str(r.get('TABLE') or '').upper()]
                        st.markdown("#### Special Categories Detected (Preview)")
                        st.caption("CIA → Label rules: 🟥 Confidential (C3,I3,A2–A3) | 🟧 Restricted (C2,I2,A1–A2) | 🟨 Internal (C1,I1,A1) | 🟩 Public (C0,I0,A0)")
                        st.caption("Risk rules: High (any CIA=3) → Strict governance; Medium (any CIA=2) → Moderate controls; Low (all ≤1) → Standard")
                        if specials and _pd is not None:
                            df_spec = _pd.DataFrame(specials)
                            st.dataframe(df_spec[[
                                'FULLY_QUALIFIED_NAME','CATEGORY','CONFIDENCE','C','I','A','RULE_LABEL','RISK_LEVEL','RISK_ACTION','COMPLIANCE','REVIEW_STATUS','ROW_COUNT'
                            ]], width='stretch', hide_index=True)
                            # Optional: generate tag SQL for selected tables
                            try:
                                _choices_sql = df_spec['FULLY_QUALIFIED_NAME'].dropna().astype(str).tolist()
                            except Exception:
                                _choices_sql = []
                            if _choices_sql:
                                sel_sql = st.multiselect("Select tables to generate tag SQL:", options=_choices_sql, key="ai_spec_sql_sel")
                                if st.button("Generate Tag SQL", key="btn_gen_tag_sql") and sel_sql:
                                    from src.services.tagging_service import tagging_service as _tag_svc
                                    _sqls = []
                                    for fqn in sel_sql:
                                        try:
                                            row = df_spec[df_spec['FULLY_QUALIFIED_NAME'] == fqn].iloc[0]
                                            c_val = int(row.get('C') if row.get('C') is not None else 1)
                                            i_val = int(row.get('I') if row.get('I') is not None else 1)
                                            a_val = int(row.get('A') if row.get('A') is not None else 1)
                                            lbl = str(row.get('RULE_LABEL') or 'Internal')
                                            _sqls.append(_tag_svc.generate_tag_sql_for_object(fqn, 'TABLE', {
                                                'DATA_CLASSIFICATION': lbl,
                                                'CONFIDENTIALITY_LEVEL': str(c_val),
                                                'INTEGRITY_LEVEL': str(i_val),
                                                'AVAILABILITY_LEVEL': str(a_val),
                                            }))
                                        except Exception:
                                            continue
                                    if _sqls:
                                        st.code("\n\n".join(_sqls), language='sql')
                            # Apply tags to selected tables using RULE_LABEL/CIA (fallback to Internal C1/I1/A1)
                            try:
                                _choices = df_spec['FULLY_QUALIFIED_NAME'].dropna().astype(str).tolist()
                            except Exception:
                                _choices = []
                            if _choices:
                                sel_apply = st.multiselect("Select tables to apply tags:", options=_choices, key="ai_spec_apply_sel")
                                if st.button("Apply Tags to Selected Tables", key="btn_apply_tags_selected") and sel_apply:
                                    from src.services.tagging_service import tagging_service as _tag_svc
                                    from src.services.classification_decision_service import classification_decision_service as _cds
                                    from src.services.audit_service import audit_service as _aud
                                    applied_ok = 0
                                    failed_appl = 0
                                    for fqn in sel_apply:
                                        try:
                                            row = df_spec[df_spec['FULLY_QUALIFIED_NAME'] == fqn].iloc[0]
                                            # Fallback CIA and label
                                            c_val = int(row.get('C') if row.get('C') is not None else 1)
                                            i_val = int(row.get('I') if row.get('I') is not None else 1)
                                            a_val = int(row.get('A') if row.get('A') is not None else 1)
                                            lbl = str(row.get('RULE_LABEL') or 'Internal')
                                            # Enforce baseline CIA minimums from category mapping
                                            try:
                                                cat_key = str(row.get('CATEGORY') or '').upper()
                                                base = comp_map.get(cat_key) or {}
                                                bc, bi, ba = int(base.get('BASELINE_C') or 0), int(base.get('BASELINE_I') or 0), int(base.get('BASELINE_A') or 0)
                                                c_val = max(c_val, bc); i_val = max(i_val, bi); a_val = max(a_val, ba)
                                                lbl = _label_from_cia(c_val, i_val, a_val)
                                            except Exception:
                                                pass
                                            # High-risk gating: queue for review if Confidential
                                            is_high_risk = (lbl == 'Confidential') or (c_val >= 3 and i_val >= 3 and a_val >= 2)
                                            if is_high_risk:
                                                try:
                                                    _cds.record(
                                                        asset_full_name=fqn,
                                                        decision_by='AI_ASSISTANT',
                                                        source='AI_ASSISTANT',
                                                        status='Submitted',
                                                        label=lbl,
                                                        c=int(c_val), i=int(i_val), a=int(a_val),
                                                        rationale='High-risk requires manual approval',
                                                        details={'route': 'ENHANCED_REVIEW', 'reason': 'HIGH_RISK_ENFORCEMENT'}
                                                    )
                                                    _aud.log('AI_ASSISTANT','AI_TAG_QUEUED','ASSET',fqn,{'label':lbl,'c':c_val,'i':i_val,'a':a_val,'reason':'HIGH_RISK'})
                                                    applied_ok += 1
                                                    continue
                                                except Exception:
                                                    pass
                                            # Apply tags via service (ensures tag existence and validation)
                                            _tag_svc.apply_tags_to_object(
                                                fqn,
                                                'TABLE',
                                                {
                                                    'DATA_CLASSIFICATION': lbl,
                                                    'CONFIDENTIALITY_LEVEL': str(c_val),
                                                    'INTEGRITY_LEVEL': str(i_val),
                                                    'AVAILABILITY_LEVEL': str(a_val),
                                                }
                                            )
                                            try:
                                                _aud.log('AI_ASSISTANT','AI_TAG_APPLIED','ASSET',fqn,{'label':lbl,'c':c_val,'i':i_val,'a':a_val})
                                            except Exception:
                                                pass
                                            applied_ok += 1
                                        except Exception as _te:
                                            failed_appl += 1
                                            st.warning(f"Failed to tag {fqn}: {_te}")
                                    if applied_ok:
                                        st.success(f"Applied tags to {applied_ok} table(s). {('Failures: ' + str(failed_appl)) if failed_appl else ''}")
                            # Drill-down: select a table to view column-level detections
                            try:
                                from src.services.ai_classification_service import ai_classification_service as _svc
                            except Exception:
                                _svc = None
                            if _svc is not None:
                                _options = [r['FULLY_QUALIFIED_NAME'] for r in specials if r.get('FULLY_QUALIFIED_NAME')]
                                if _options:
                                    sel_tbl = st.selectbox("Drill down to column-level for:", options=["— Select —"] + _options, index=0, key="ai_spec_drill_sel")
                                    if sel_tbl and sel_tbl != "— Select —":
                                        try:
                                            # Load column data types for the table once
                                            try:
                                                parts = (sel_tbl or '').split('.')
                                                _dbp, _scp, _tbp = parts[0], parts[1], parts[2]
                                                _coltype_rows = snowflake_connector.execute_query(
                                                    f"select column_name, data_type from {_dbp}.information_schema.columns where table_schema=%(s)s and table_name=%(t)s",
                                                    {"s": _scp, "t": _tbp}
                                                ) or []
                                                _dtype_map = {str(r.get('COLUMN_NAME') or '').upper(): str(r.get('DATA_TYPE') or '') for r in _coltype_rows}
                                            except Exception:
                                                _dtype_map = {}
                                            dets = _svc.detect_sensitive_columns(sel_tbl) or []
                                            # Normalize to a compact table: column, categories, confidence (max)
                                            rows_dd = []
                                            for d in dets:
                                                cname = d.get('column') or d.get('column_name') or d.get('name')
                                                cats = d.get('categories') or []
                                                try:
                                                    conf = float(d.get('confidence')) if d.get('confidence') is not None else None
                                                except Exception:
                                                    conf = None
                                                cia = d.get('suggested_cia') or {}
                                                cia_txt = f"C{int(cia.get('C',0))}/I{int(cia.get('I',0))}/A{int(cia.get('A',0))}"
                                                # Heuristic detection source
                                                src = 'SEMANTIC' if (d.get('semantic_top_cat') or d.get('semantic_scores')) else ('PATTERN' if d.get('pattern_ids') else 'RULE')
                                                # Compliance tags from category
                                                _cmpl = ''
                                                try:
                                                    dom_cat = None
                                                    if cats:
                                                        dom_cat = str(cats[0]).upper()
                                                    _cm2 = comp_map.get(dom_cat) or {}
                                                    _cmpl = str(_cm2.get('COMPLIANCE') or '')
                                                except Exception:
                                                    _cmpl = ''
                                                # Derived label
                                                def _label_from_cia2(c,i,a):
                                                    if c >= 3 and i >= 3 and a >= 2: return 'Confidential'
                                                    if c >= 2 and i >= 2 and (1 <= a <= 2): return 'Restricted'
                                                    if c == 1 and i == 1 and a == 1: return 'Internal'
                                                    if c == 0 and i == 0 and a == 0: return 'Public'
                                                    if max(c,i,a) >= 3: return 'Confidential'
                                                    if max(c,i,a) == 2: return 'Restricted'
                                                    if max(c,i,a) == 1: return 'Internal'
                                                    return 'Public'
                                                c_val,i_val,a_val = int(cia.get('C',0)), int(cia.get('I',0)), int(cia.get('A',0))
                                                _lbl = _label_from_cia2(c_val,i_val,a_val)
                                                # Generate tag SQL for column
                                                try:
                                                    from src.services.tagging_service import tagging_service as _tag_svc
                                                    tag_sql_col = _tag_svc.generate_tag_sql_for_column(sel_tbl, str(cname), {
                                                        'DATA_CLASSIFICATION': _lbl,
                                                        'CONFIDENTIALITY_LEVEL': str(c_val),
                                                        'INTEGRITY_LEVEL': str(i_val),
                                                        'AVAILABILITY_LEVEL': str(a_val),
                                                    })
                                                except Exception:
                                                    tag_sql_col = None
                                                rows_dd.append({
                                                    'COLUMN_NAME': cname,
                                                    'DATA_TYPE': _dtype_map.get(str(cname or '').upper()),
                                                    'CATEGORIES': ", ".join([str(c) for c in cats]) if cats else "",
                                                    'CONFIDENCE': conf,
                                                    'CIA': cia_txt,
                                                    'LABEL': _lbl,
                                                    'COMPLIANCE': _cmpl,
                                                    'SOURCE': src,
                                                    'TAG_SQL': tag_sql_col,
                                                })
                                            if rows_dd:
                                                df_dd = _pd.DataFrame(rows_dd)
                                                st.dataframe(df_dd[['COLUMN_NAME','DATA_TYPE','CATEGORIES','LABEL','CIA','COMPLIANCE','SOURCE','CONFIDENCE','TAG_SQL']], width='stretch', hide_index=True)
                                                # Column-level tagging: select column and apply label (derived from CIA or fallback to Internal)
                                                try:
                                                    col_options = df_dd['COLUMN_NAME'].dropna().astype(str).tolist()
                                                except Exception:
                                                    col_options = []
                                                if col_options:
                                                    sel_col = st.selectbox("Select a column to tag:", options=["— Select —"] + col_options, index=0, key="ai_col_tag_sel")
                                                    if sel_col and sel_col != "— Select —":
                                                        # Derive CIA from CIA text if available
                                                        def _parse_cia(txt: str):
                                                            try:
                                                                parts = str(txt or '').upper().replace('C','').replace('I','').replace('A','').split('/')
                                                                if len(parts) == 3:
                                                                    return int(parts[0] or 0), int(parts[1] or 0), int(parts[2] or 0)
                                                            except Exception:
                                                                pass
                                                            return 1,1,1
                                                        def _label_from_cia2(c,i,a):
                                                            if c >= 3 and i >= 3 and a >= 2: return 'Confidential'
                                                            if c >= 2 and i >= 2 and (1 <= a <= 2): return 'Restricted'
                                                            if c == 1 and i == 1 and a == 1: return 'Internal'
                                                            if c == 0 and i == 0 and a == 0: return 'Public'
                                                            if max(c,i,a) >= 3: return 'Confidential'
                                                            if max(c,i,a) == 2: return 'Restricted'
                                                            if max(c,i,a) == 1: return 'Internal'
                                                            return 'Public'
                                                        rowc = df_dd[df_dd['COLUMN_NAME'] == sel_col].iloc[0]
                                                        c_txt = str(rowc.get('CIA') or '')
                                                        c_val,i_val,a_val = _parse_cia(c_txt)
                                                        lbl_col = _label_from_cia2(c_val,i_val,a_val)
                                                        st.caption(f"Proposed column label: {lbl_col} (C{c_val}/I{i_val}/A{a_val}) — fallback to Internal if invalid")
                                                        if st.button("Apply Column Tag", key="btn_apply_col_tag"):
                                                            try:
                                                                from src.services.tagging_service import tagging_service as _tag_svc
                                                                from src.services.classification_decision_service import classification_decision_service as _cds
                                                                from src.services.audit_service import audit_service as _aud
                                                                # High-risk gating for columns
                                                                if lbl_col == 'Confidential' or (c_val >= 3 and i_val >= 3 and a_val >= 2):
                                                                    try:
                                                                        _cds.record(
                                                                            asset_full_name=sel_tbl,
                                                                            decision_by='AI_ASSISTANT',
                                                                            source='AI_ASSISTANT',
                                                                            status='Submitted',
                                                                            label=lbl_col,
                                                                            c=int(c_val), i=int(i_val), a=int(a_val),
                                                                            rationale=f'Column {sel_col}: High-risk requires manual approval',
                                                                            details={'route':'ENHANCED_REVIEW','column':sel_col}
                                                                        )
                                                                        _aud.log('AI_ASSISTANT','AI_COL_TAG_QUEUED','ASSET',sel_tbl,{'column':sel_col,'label':lbl_col,'c':c_val,'i':i_val,'a':a_val})
                                                                        st.info(f"Queued for review (high-risk): {sel_tbl}.{sel_col}")
                                                                        raise SystemExit
                                                                    except SystemExit:
                                                                        pass
                                                                _tag_svc.apply_tags_to_column(sel_tbl, sel_col, {
                                                                    'DATA_CLASSIFICATION': lbl_col,
                                                                    'CONFIDENTIALITY_LEVEL': str(c_val),
                                                                    'INTEGRITY_LEVEL': str(i_val),
                                                                    'AVAILABILITY_LEVEL': str(a_val),
                                                                })
                                                                try:
                                                                    _aud.log('AI_ASSISTANT','AI_COL_TAG_APPLIED','ASSET',sel_tbl,{'column':sel_col,'label':lbl_col,'c':c_val,'i':i_val,'a':a_val})
                                                                except Exception:
                                                                    pass
                                                                st.success(f"Applied column tag to {sel_tbl}.{sel_col}")
                                                            except Exception as _ce:
                                                                st.warning(f"Failed to tag column {sel_tbl}.{sel_col}: {_ce}")
                                            else:
                                                st.caption("No sensitive columns detected for the selected table.")
                                        except Exception as _e:
                                            st.warning(f"Failed to load column-level detections: {_e}")
                        else:
                            # If semantic specials are empty, run CTE-based fallback detection and show reason
                            st.caption("No tables with special categories detected by semantic search. Running fallback detection...")
                            # Summarize semantic failure reasons from this run, if any
                            try:
                                _reasons = {}
                                for t in (tables or []):
                                    fr = str(t.get('fail_reason') or '').strip()
                                    if fr:
                                        _reasons[fr] = _reasons.get(fr, 0) + 1
                                if _reasons:
                                    _top = sorted(_reasons.items(), key=lambda kv: kv[1], reverse=True)[:5]
                                    _txt = "; ".join([f"{k} ({v})" for k, v in _top])
                                    st.info(f"Semantic detection reasons: {_txt}")
                            except Exception:
                                pass
                            try:
                                _active_db = db
                                _schema_filter = " AND UPPER(c.TABLE_SCHEMA) = UPPER(%(sc)s)" if sel_schema else ""
                                cte_sql = f"""
                                WITH
                                ACTIVE_CATEGORIES AS (
                                    SELECT CATEGORY_ID, CATEGORY_NAME, DETECTION_THRESHOLD
                                    FROM {gv_str}.SENSITIVITY_CATEGORIES
                                    WHERE IS_ACTIVE = TRUE
                                ),
                                COLUMN_SCORES AS (
                                    SELECT c.TABLE_CATALOG AS DATABASE_NAME, c.TABLE_SCHEMA, c.TABLE_NAME, c.COLUMN_NAME,
                                           COALESCE(k.CATEGORY_ID, p.CATEGORY_ID) AS CATEGORY_ID,
                                           COALESCE(cat.CATEGORY_NAME, 'UNCATEGORIZED') AS CATEGORY_NAME,
                                           COALESCE(k.SENSITIVITY_WEIGHT, p.SENSITIVITY_WEIGHT, 1.0) AS MATCH_WEIGHT,
                                           COALESCE(cat.DETECTION_THRESHOLD, 0.7) AS DETECTION_THRESHOLD
                                    FROM {_active_db}.INFORMATION_SCHEMA.COLUMNS c
                                    LEFT JOIN {gv_str}.SENSITIVE_KEYWORDS k
                                      ON k.IS_ACTIVE = TRUE AND (
                                         (k.MATCH_TYPE = 'EXACT' AND LOWER(c.COLUMN_NAME) = LOWER(k.KEYWORD_STRING)) OR
                                         (k.MATCH_TYPE IN ('CONTAINS','PARTIAL') AND LOWER(c.COLUMN_NAME) LIKE '%' || LOWER(k.KEYWORD_STRING) || '%')
                                      )
                                    LEFT JOIN {gv_str}.SENSITIVE_PATTERNS p
                                      ON p.IS_ACTIVE = TRUE AND REGEXP_LIKE(LOWER(c.COLUMN_NAME), p.PATTERN_STRING, 'i')
                                    LEFT JOIN ACTIVE_CATEGORIES cat ON COALESCE(k.CATEGORY_ID, p.CATEGORY_ID) = cat.CATEGORY_ID
                                    WHERE COALESCE(k.CATEGORY_ID, p.CATEGORY_ID) IS NOT NULL AND cat.CATEGORY_ID IS NOT NULL{_schema_filter}
                                ),
                                COLUMN_TOP AS (
                                    SELECT *, ROW_NUMBER() OVER (PARTITION BY DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME ORDER BY MATCH_WEIGHT DESC) AS RN
                                    FROM COLUMN_SCORES
                                ),
                                TABLE_TOP AS (
                                    SELECT DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME, CATEGORY_NAME,
                                           ROUND(AVG(MATCH_WEIGHT),3) AS AVG_SCORE,
                                           MAX(DETECTION_THRESHOLD) AS DETECTION_THRESHOLD,
                                           ROW_NUMBER() OVER (PARTITION BY DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME ORDER BY AVG(MATCH_WEIGHT) DESC) AS CAT_RANK
                                    FROM COLUMN_TOP WHERE RN = 1
                                    GROUP BY DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME, CATEGORY_NAME
                                )
                                """
                                where_parts = []
                                params_fb = {}
                                if sel_schema:
                                    where_parts.append("TABLE_SCHEMA = %(sc)s"); params_fb["sc"] = sel_schema
                                if sel_table_filter:
                                    where_parts.append("TABLE_NAME ILIKE %(tb)s"); params_fb["tb"] = f"%{sel_table_filter}%"
                                where_fb = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
                                agg_sql = f"""
                                {cte_sql}
                                SELECT
                                    CONCAT(DATABASE_NAME,'.',TABLE_SCHEMA,'.',TABLE_NAME) AS FULLY_QUALIFIED_NAME,
                                    CATEGORY_NAME AS CATEGORY,
                                    AVG_SCORE AS CONFIDENCE,
                                    CASE WHEN AVG_SCORE >= 0.7 THEN 'HIGH' WHEN AVG_SCORE >= 0.5 THEN 'MEDIUM' ELSE 'LOW' END AS VALIDATION_STATUS
                                FROM TABLE_TOP
                                WHERE CAT_RANK = 1
                                {(' AND ' + where_fb[6:]) if where_fb else ''}
                                ORDER BY AVG_SCORE DESC, DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME
                                LIMIT 500
                                """
                                fb_rows = snowflake_connector.execute_query(agg_sql, params_fb) or []
                                if fb_rows:
                                    fb_specials = []
                                    for r in fb_rows:
                                        try:
                                            fqn = r.get('FULLY_QUALIFIED_NAME')
                                            parts = (fqn or '').split('.')
                                            fb_specials.append({
                                                'FULLY_QUALIFIED_NAME': fqn,
                                                'CATEGORY': r.get('CATEGORY'),
                                                'CONFIDENCE': float(r.get('CONFIDENCE') or 0.0),
                                                'C': None, 'I': None, 'A': None,
                                                'ROUTE': None,
                                                'ROW_COUNT': None,
                                                'SCHEMA': parts[1] if len(parts) == 3 else None,
                                                'TABLE': parts[2] if len(parts) == 3 else None,
                                            })
                                        except Exception:
                                            continue
                                    if fb_specials:
                                        st.info("Fallback results shown (pattern/keyword CTE). Semantic search returned no special-category tables.")
                                        df_fb = _pd.DataFrame(fb_specials)
                                        st.dataframe(df_fb[['FULLY_QUALIFIED_NAME','CATEGORY','CONFIDENCE']], width='stretch', hide_index=True)
                                    else:
                                        st.caption("No special-category tables found by fallback detection.")
                                else:
                                    st.caption("No special-category tables found by fallback detection.")
                            except Exception as _fe:
                                st.warning(f"Fallback detection failed: {_fe}")
                    except Exception:
                        pass

                    # Step 7: Snowflake Tagging & Metadata Updates
                    try:
                        applied = 0
                        for table in valid_tables:
                            try:
                                if table['route'] == 'AUTO_APPROVE':
                                    # Apply tags
                                    tags = {
                                        'DATA_CLASSIFICATION': table['category'],
                                        'CONFIDENTIALITY_LEVEL': str(table['c']),
                                        'INTEGRITY_LEVEL': str(table['i']),
                                        'AVAILABILITY_LEVEL': str(table['a']),
                                    }
                                    tagging_service.apply_tags_to_object(table['fqn'], 'TABLE', tags)
                                    # Update ASSETS table
                                    snowflake_connector.execute_non_query(
                                        f"""
                                        MERGE INTO {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS t
                                        USING (SELECT %(id)s AS ID) s
                                        ON t.ASSET_ID = s.ID
                                        WHEN MATCHED THEN UPDATE SET
                                            CLASSIFICATION_LABEL = %(label)s,
                                            CONFIDENTIALITY_LEVEL = %(c)s,
                                            INTEGRITY_LEVEL = %(i)s,
                                            AVAILABILITY_LEVEL = %(a)s,
                                            CLASSIFIED_BY = %(by)s,
                                            CLASSIFICATION_DATE = CURRENT_TIMESTAMP(),
                                            CLASSIFICATION_METHOD = 'AI_AUTO',
                                            LAST_MODIFIED_TIMESTAMP = CURRENT_TIMESTAMP()
                                        WHEN NOT MATCHED THEN INSERT (
                                            ASSET_ID, ASSET_NAME, ASSET_TYPE, DATABASE_NAME, SCHEMA_NAME, OBJECT_NAME, FULLY_QUALIFIED_NAME,
                                            DATA_OWNER, CLASSIFICATION_LABEL, CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, AVAILABILITY_LEVEL,
                                            CLASSIFIED_BY, CLASSIFICATION_DATE, CLASSIFICATION_METHOD, CREATED_TIMESTAMP, LAST_MODIFIED_TIMESTAMP
                                        ) VALUES (
                                            %(id)s, %(name)s, 'TABLE', %(db)s, %(sc)s, %(tb)s, %(fqn)s,
                                            %(by)s, %(label)s, %(c)s, %(i)s, %(a)s,
                                            %(by)s, CURRENT_TIMESTAMP(), 'AI_AUTO', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()
                                        )
                                        """,
                                        {
                                            'id': table['fqn'],
                                            'name': table['table'],
                                            'db': db,
                                            'sc': table['schema'],
                                            'tb': table['table'],
                                            'fqn': table['fqn'],
                                            'label': table['category'],
                                            'c': table['c'],
                                            'i': table['i'],
                                            'a': table['a'],
                                            'by': 'AI_ASSISTANT'
                                        }
                                    )
                                    applied += 1
                                else:
                                    # Queue for review
                                    snowflake_connector.execute_non_query(
                                        f"""
                                        INSERT INTO {db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_TASKS (
                                            TASK_ID, DATASET_NAME, ASSET_FULL_NAME, ASSIGNED_TO, STATUS, 
                                            CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, AVAILABILITY_LEVEL,
                                            DUE_DATE, CREATED_AT, UPDATED_AT, DETAILS
                                        )
                                        SELECT 
                                            %(tid)s, %(dsn)s, %(fqn)s, %(owner)s, 'PENDING',
                                            %(c)s, %(i)s, %(a)s,
                                            DATEADD(day, 5, CURRENT_DATE()), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), TO_VARIANT(PARSE_JSON(%(det)s))
                                        """,
                                        {
                                            'tid': f"AI_{table['fqn']}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                                            'dsn': table['fqn'].split('.')[-1] if '.' in table['fqn'] else table['fqn'],
                                            'fqn': table['fqn'],
                                            'owner': st.session_state.get('user_email', 'SYSTEM'),
                                            'c': str(table['c']),
                                            'i': str(table['i']),
                                            'a': str(table['a']),
                                            'det': json.dumps({
                                                'category': table['category'],
                                                'c': table['c'],
                                                'i': table['i'],
                                                'a': table['a'],
                                                'confidence': table['confidence'],
                                                'route': table['route']
                                            })
                                        }
                                    )
                            except Exception as e:
                                st.warning(f"Failed to apply tags for {table['fqn']}: {e}")

                        # Step 8: Audit Logging & Monitoring
                        for table in valid_tables:
                            try:
                                audit_service.log(
                                    'AI_ASSISTANT',
                                    'AI_CLASSIFICATION_APPLIED' if table['route'] == 'AUTO_APPROVE' else 'AI_CLASSIFICATION_QUEUED',
                                    'ASSET',
                                    table['fqn'],
                                    {
                                        'category': table['category'],
                                        'c': table['c'],
                                        'i': table['i'],
                                        'a': table['a'],
                                        'confidence': table['confidence'],
                                        'route': table['route']
                                    }
                                )
                            except Exception as e:
                                st.warning(f"Failed to log audit for {table['fqn']}: {e}")

                        # Step 9: Security, Error Handling & Scalability
                        # Already handled with try-except

                        # Completed pipeline summary suppressed in UI

                    except Exception as e:
                        st.error(f"Pipeline failed: {e}")
                        st.exception(e)

                except Exception as e:
                    st.error(f"Pipeline failed: {e}")
                    st.exception(e)

    # Keep the existing code below
        try:
            st.caption("AI Assistant: Filter by database/schema to view sensitive tables, then drill down into editable sensitive columns.")
        except Exception:
            pass

        # Service handle
        try:
            from src.services.ai_classification_service import ai_classification_service as _svc
        except Exception:
            _svc = None

        # Use existing global filters from the sidebar (no new filters here)
        # Active DB from helper; schema from session/global filters if available
        try:
            sel_db = _active_db_from_filter()
        except Exception:
            sel_db = None
        try:
            gf = st.session_state.get("global_filters", {}) if hasattr(st, "session_state") else {}
            sel_schema = (
                st.session_state.get("schema_filter")
                or (gf.get("schema") if isinstance(gf, dict) else None)
            )
        except Exception:
            sel_schema = None
        try:
            sel_table = (gf.get("table") if isinstance(gf, dict) else None)
        except Exception:
            sel_table = None
        st.caption("Scope is controlled by the sidebar global filter (Database/Schema).")

        # Level 1 — Sensitive Tables Overview
        st.markdown("####  Sensitive Tables Overview")
        import pandas as _pd
        level1_rows: list[dict] = []
        try:
            _active_db = sel_db or _active_db_from_filter()
            _gv = st.session_state.get("governance_schema") or "DATA_CLASSIFICATION_GOVERNANCE"
            fqn_candidates = [
                f"{_active_db}.{_gv}.AI_ASSISTANT_SENSITIVE_ASSETS" if _active_db else None,
                "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.AI_ASSISTANT_SENSITIVE_ASSETS",
            ]
            fqn_candidates = [x for x in fqn_candidates if x]
            rows = []
            # Primary: run dynamic CTE over the active DB's INFORMATION_SCHEMA
            if _active_db:
                try:
                    _schema_filter = " AND UPPER(c.TABLE_SCHEMA) = UPPER(%(sc)s)" if sel_schema else ""
                    cte_sql = f"""
                    WITH
                    -- 1️⃣ Get all active categories dynamically
                    ACTIVE_CATEGORIES AS (
                        SELECT 
                            CATEGORY_ID,
                            CATEGORY_NAME,
                            DETECTION_THRESHOLD
                        FROM {gv_str}.SENSITIVITY_CATEGORIES
                        WHERE IS_ACTIVE = TRUE
                    ),

                    -- 2️⃣ Detect sensitive columns (keywords + patterns)
                    COLUMN_SCORES AS (
                        SELECT
                            c.TABLE_CATALOG AS DATABASE_NAME,
                            c.TABLE_SCHEMA,
                            c.TABLE_NAME,
                            c.COLUMN_NAME,
                            COALESCE(k.CATEGORY_ID, p.CATEGORY_ID) AS CATEGORY_ID,
                            COALESCE(cat.CATEGORY_NAME, 'UNCATEGORIZED') AS CATEGORY_NAME,
                            COALESCE(k.SENSITIVITY_WEIGHT, p.SENSITIVITY_WEIGHT, 1.0) AS MATCH_WEIGHT,
                            COALESCE(cat.DETECTION_THRESHOLD, 0.7) AS DETECTION_THRESHOLD,
                            CASE 
                                WHEN k.KEYWORD_STRING IS NOT NULL THEN 'KEYWORD_MATCH'
                                WHEN p.PATTERN_NAME IS NOT NULL THEN 'PATTERN_MATCH'
                                ELSE 'UNKNOWN'
                            END AS DETECTION_TYPE
                        FROM {_active_db}.INFORMATION_SCHEMA.COLUMNS c
                        LEFT JOIN {gv_str}.SENSITIVE_KEYWORDS k
                            ON k.IS_ACTIVE = TRUE
                           AND (
                                (k.MATCH_TYPE = 'EXACT' AND LOWER(c.COLUMN_NAME) = LOWER(k.KEYWORD_STRING))
                                OR
                                (k.MATCH_TYPE = 'CONTAINS' AND LOWER(c.COLUMN_NAME) LIKE CONCAT('%', LOWER(k.KEYWORD_STRING), '%'))
                                OR
                                (k.MATCH_TYPE = 'PARTIAL' AND LOWER(c.COLUMN_NAME) LIKE CONCAT('%', LOWER(k.KEYWORD_STRING), '%'))
                            )
                        LEFT JOIN {gv_str}.SENSITIVE_PATTERNS p
                            ON p.IS_ACTIVE = TRUE
                           AND REGEXP_LIKE(LOWER(c.COLUMN_NAME), p.PATTERN_STRING, 'i')
                        LEFT JOIN ACTIVE_CATEGORIES cat
                            ON COALESCE(k.CATEGORY_ID, p.CATEGORY_ID) = cat.CATEGORY_ID
                        WHERE COALESCE(k.CATEGORY_ID, p.CATEGORY_ID) IS NOT NULL
                          AND cat.CATEGORY_ID IS NOT NULL{_schema_filter}
                    ),

                    -- 3️⃣ Rank detections per column and pick the highest confidence match
                    COLUMN_TOP_CATEGORY AS (
                        SELECT
                            DATABASE_NAME,
                            TABLE_SCHEMA,
                            TABLE_NAME,
                            COLUMN_NAME,
                            CATEGORY_ID,
                            CATEGORY_NAME,
                            LEAST(MATCH_WEIGHT, 1.0) AS MATCH_WEIGHT,
                            DETECTION_THRESHOLD,
                            DETECTION_TYPE,
                            ROW_NUMBER() OVER (
                                PARTITION BY DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME
                                ORDER BY MATCH_WEIGHT DESC
                            ) AS RANK_ORDER
                        FROM COLUMN_SCORES
                    ),

                    -- 4️⃣ Pick only the top match per column
                    COLUMN_TOP_ONLY AS (
                        SELECT *
                        FROM COLUMN_TOP_CATEGORY
                        WHERE RANK_ORDER = 1
                    ),

                    -- 5️⃣ Aggregate per table (average of column scores)
                    TABLE_AGG AS (
                        SELECT
                            DATABASE_NAME,
                            TABLE_SCHEMA,
                            TABLE_NAME,
                            CATEGORY_NAME AS MOST_RELEVANT_CATEGORY,
                            ROUND(AVG(MATCH_WEIGHT), 3) AS AVG_CONFIDENCE_SCORE,
                            MAX(DETECTION_THRESHOLD) AS DETECTION_THRESHOLD
                        FROM COLUMN_TOP_ONLY
                        GROUP BY DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME, CATEGORY_NAME
                    ),

                    -- 6️⃣ Pick top-scoring category per table
                    TABLE_TOP_CATEGORY AS (
                        SELECT
                            DATABASE_NAME,
                            TABLE_SCHEMA,
                            TABLE_NAME,
                            MOST_RELEVANT_CATEGORY,
                            AVG_CONFIDENCE_SCORE,
                            DETECTION_THRESHOLD,
                            ROW_NUMBER() OVER (
                                PARTITION BY DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME
                                ORDER BY AVG_CONFIDENCE_SCORE DESC
                            ) AS CAT_RANK
                        FROM TABLE_AGG
                    )
                    """
                    where_parts = []
                    params = {}
                    if sel_schema:
                        where_parts.append("TABLE_SCHEMA = %(sc)s"); params["sc"] = sel_schema
                    if sel_table:
                        where_parts.append("TABLE_NAME = %(tb)s"); params["tb"] = sel_table
                    where_sql = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
                    agg_sql = f"""
                    {cte_sql}
                    SELECT
                        CONCAT(DATABASE_NAME, '.', TABLE_SCHEMA, '.', TABLE_NAME) AS "Table Name",
                        MOST_RELEVANT_CATEGORY AS "Sensitive Data Type",
                        CONCAT(TO_VARCHAR(ROUND(LEAST(AVG_CONFIDENCE_SCORE, 1.0) * 100, 2)), '%') AS "Confidence Score",
                        CASE 
                            WHEN AVG_CONFIDENCE_SCORE >= DETECTION_THRESHOLD THEN 'POLICY_REQUIRED'
                            WHEN AVG_CONFIDENCE_SCORE >= (DETECTION_THRESHOLD * 0.6) THEN 'NEEDS_REVIEW'
                            ELSE 'OK'
                        END AS "Recommended Policy",
                        CASE 
                            WHEN AVG_CONFIDENCE_SCORE >= DETECTION_THRESHOLD THEN 'HIGH'
                            WHEN AVG_CONFIDENCE_SCORE >= (DETECTION_THRESHOLD * 0.6) THEN 'MEDIUM'
                            ELSE 'LOW'
                        END AS "Sensitivity Level",
                        CURRENT_TIMESTAMP() AS DETECTED_AT
                    FROM TABLE_TOP_CATEGORY
                    WHERE CAT_RANK = 1
                    {" AND " + where_sql[6:] if where_sql else ""}
                    AND MOST_RELEVANT_CATEGORY IS NOT NULL AND AVG_CONFIDENCE_SCORE > 0
                    ORDER BY AVG_CONFIDENCE_SCORE DESC, DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME
                    """
                    rows = snowflake_connector.execute_query(agg_sql, params) or []
                except Exception:
                    rows = []
            # Fallback: use persisted AI assistant table if CTE had no rows
            if not rows:
                for _fqn in fqn_candidates:
                    where = []
                    params = {}
                    if sel_db:
                        where.append("DATABASE_NAME = %(db)s"); params["db"] = sel_db
                    if sel_schema:
                        where.append("SCHEMA_NAME = %(sc)s"); params["sc"] = sel_schema
                    if sel_table:
                        where.append("TABLE_NAME = %(tb)s"); params["tb"] = sel_table
                    sql = f"""
                        SELECT 
                          DATABASE_NAME, 
                          SCHEMA_NAME, 
                          TABLE_NAME, 
                          COALESCE(DETECTED_CATEGORY, DETECTED_TYPE) AS DETECTED_TYPE,
                          MAX_CONF,
                          LAST_SCAN_TS
                        FROM (
                          SELECT 
                            DATABASE_NAME,
                            SCHEMA_NAME,
                            TABLE_NAME,
                            DETECTED_CATEGORY,
                            DETECTED_TYPE,
                            LAST_SCAN_TS,
                            COMBINED_CONFIDENCE AS CONF,
                            MAX(COMBINED_CONFIDENCE) OVER (PARTITION BY DATABASE_NAME, SCHEMA_NAME, TABLE_NAME) AS MAX_CONF,
                            ROW_NUMBER() OVER (
                              PARTITION BY DATABASE_NAME, SCHEMA_NAME, TABLE_NAME 
                              ORDER BY LAST_SCAN_TS DESC, COMBINED_CONFIDENCE DESC
                            ) AS RN
                          FROM {_fqn}
                          {('WHERE ' + ' AND '.join(where)) if where else ''}
                        ) t
                        WHERE RN = 1 AND COALESCE(DETECTED_CATEGORY, DETECTED_TYPE) IS NOT NULL
                        ORDER BY MAX_CONF DESC, DATABASE_NAME, SCHEMA_NAME, TABLE_NAME
                        LIMIT 1000
                    """
                    try:
                        rows = snowflake_connector.execute_query(sql, params) or []
                        if rows:
                            break
                    except Exception:
                        continue
            for r in rows:
                if "Table Name" in r:
                    fqn = str(r.get("Table Name") or "").strip()
                    if not fqn or not r.get("Sensitive Data Type"):
                        continue
                    level1_rows.append({
                        "Table Name": fqn,
                        "Sensitive Data Type": r.get("Sensitive Data Type"),
                        "Confidence Score": r.get("Confidence Score"),
                        "Recommended Policy": r.get("Recommended Policy"),
                        "Sensitivity Level": r.get("Sensitivity Level"),
                        "_FQN": fqn,
                    })
                else:
                    db = r.get("DATABASE_NAME"); sc = r.get("SCHEMA_NAME"); tbl = r.get("TABLE_NAME")
                    fqn = f"{db}.{sc}.{tbl}"
                    cat = str(r.get("DETECTED_TYPE") or "")
                    if not cat:
                        continue
                    try:
                        maxc = float(r.get('MAX_CONF') or 0.0)
                    except Exception:
                        maxc = 0.0
                    _thr = 0.7
                    if maxc >= _thr:
                        pol = 'POLICY_REQUIRED'
                        level = 'HIGH'
                    elif maxc >= (_thr * 0.6):
                        pol = 'NEEDS_REVIEW'
                        level = 'MEDIUM'
                    else:
                        pol = 'OK'
                        level = 'LOW'
                    level1_rows.append({
                        "Table Name": fqn,
                        "Sensitive Data Type": cat,
                        "Confidence Score": f"{round(maxc*100, 2)}%",
                        "Recommended Policy": pol,
                        "Sensitivity Level": level,
                        "_FQN": fqn,
                    })
        except Exception:
            level1_rows = []

        df_level1 = _pd.DataFrame(level1_rows)
        if df_level1.empty:
            st.info("No sensitive tables found for the selected scope.")
            if st.button("Scan now", key="ai_scan_now"):
                _db_to_scan = sel_db or _active_db_from_filter()
                if _db_to_scan:
                    with st.spinner("Scanning sensitive data for selected scope..."):
                        try:
                            summary = ai_sensitive_detection_service.run_scan_and_persist(
                                _db_to_scan,
                                schema_name=(sel_schema or None),
                                table_name=(sel_table or None)
                            )
                            st.success(f"Scan complete. Columns detected: {summary.get('columns_detected', 0)}")
                        except Exception as e:
                            st.error(f"Scan failed: {e}")
                        # Removed st.rerun() to prevent no-op warning
                else:
                    st.warning("Please select a Database in the global filter to run a scan.")
            selected_full_name = ""
        else:
            st.dataframe(df_level1[[
                "Table Name",
                "Sensitive Data Type",
                "Recommended Policy"
            ]], width='stretch', hide_index=True)
            # Simple selection for drill-down without session syncing
            _options = [""] + df_level1["_FQN"].tolist()
            selected_label = st.selectbox(
                "Select a table to drill down",
                options=_options,
            )
            selected_full_name = selected_label

        # Level 2 — Drill-Down: Sensitive Columns View (editable)
        if selected_full_name:
            st.markdown("#### Sensitive Columns Drill-down")
            cols_detect = []
            try:
                db, sc, tbl = selected_full_name.split('.')
                db, sc, tbl = db.strip(), sc.strip(), tbl.strip()
                _active_db = sel_db or _active_db_from_filter() or db
                _gv = st.session_state.get("governance_schema") or "DATA_CLASSIFICATION_GOVERNANCE"
                fqn_candidates = [
                    f"{_active_db}.{_gv}.AI_ASSISTANT_SENSITIVE_ASSETS" if _active_db else None,
                    "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.AI_ASSISTANT_SENSITIVE_ASSETS",
                ]
                fqn_candidates = [x for x in fqn_candidates if x]
                try:
                    # Validate resolved identifiers early to avoid NONE/NULL errors
                    _invalid = {"", "NONE", "(NONE)", "NULL", "UNKNOWN"}
                    if (not db) or (db.upper() in _invalid) or (not sc) or (sc.upper() in _invalid) or (not tbl) or (tbl.upper() in _invalid):
                        st.info("Select a valid Database, Schema, and Table to run the AI Assistant drill-down.")
                        cols_detect = []
                        raise RuntimeError("Invalid context (db/schema/table)")
                    cte_sql = f"""
                        WITH
                        -- 1️⃣ Active sensitivity categories (with default CIA levels)
                        CATEGORIES AS (
                          SELECT 
                              CATEGORY_ID,
                              CATEGORY_NAME,
                              COALESCE(DETECTION_THRESHOLD, 0.7) AS DETECTION_THRESHOLD,
                              CONFIDENTIALITY_LEVEL AS C_LEVEL,
                              INTEGRITY_LEVEL AS I_LEVEL,
                              AVAILABILITY_LEVEL AS A_LEVEL
                          FROM {gv_str}.SENSITIVITY_CATEGORIES
                          WHERE IS_ACTIVE = TRUE
                        ),

                        -- 2️⃣ Active detection weights
                        WEIGHTS AS (
                          SELECT
                              COALESCE(MAX(CASE WHEN UPPER(SENSITIVITY_TYPE) = 'RULE_BASED' THEN WEIGHT END), 1.0) AS RULE_BASED_WEIGHT,
                              COALESCE(MAX(CASE WHEN UPPER(SENSITIVITY_TYPE) = 'PATTERN_BASED' THEN WEIGHT END), 1.0) AS PATTERN_BASED_WEIGHT
                          FROM {gv_str}.SENSITIVITY_WEIGHTS
                          WHERE IS_ACTIVE = TRUE
                        ),

                        -- 3️⃣ Rule-based keyword matches
                        RULE_BASED AS (
                          SELECT
                              c.TABLE_CATALOG AS DATABASE_NAME,
                              c.TABLE_SCHEMA,
                              c.TABLE_NAME,
                              c.COLUMN_NAME,
                              k.CATEGORY_ID,
                              cat.CATEGORY_NAME,
                              'RULE_BASED' AS DETECTION_TYPE,
                              k.KEYWORD_STRING AS MATCHED_KEYWORD,
                              NULL AS MATCHED_PATTERN,
                              COALESCE(k.SENSITIVITY_WEIGHT, 1.0) AS MATCH_WEIGHT,
                              cat.DETECTION_THRESHOLD,
                              cat.C_LEVEL,
                              cat.I_LEVEL,
                              cat.A_LEVEL
                          FROM {db}.INFORMATION_SCHEMA.COLUMNS c
                          JOIN {gv_str}.SENSITIVE_KEYWORDS k
                            ON k.IS_ACTIVE = TRUE
                           AND (
                                (k.MATCH_TYPE = 'EXACT' AND LOWER(c.COLUMN_NAME) = LOWER(k.KEYWORD_STRING))
                                OR
                                (k.MATCH_TYPE IN ('CONTAINS', 'PARTIAL') AND LOWER(c.COLUMN_NAME) LIKE '%' || LOWER(k.KEYWORD_STRING) || '%')
                               )
                          JOIN CATEGORIES cat
                            ON k.CATEGORY_ID = cat.CATEGORY_ID
                        ),

                        -- 4️⃣ Pattern-based detections
                        PATTERN_BASED AS (
                          SELECT
                              c.TABLE_CATALOG AS DATABASE_NAME,
                              c.TABLE_SCHEMA,
                              c.TABLE_NAME,
                              c.COLUMN_NAME,
                              p.CATEGORY_ID,
                              cat.CATEGORY_NAME,
                              'PATTERN_BASED' AS DETECTION_TYPE,
                              NULL AS MATCHED_KEYWORD,
                              p.PATTERN_NAME AS MATCHED_PATTERN,
                              COALESCE(p.SENSITIVITY_WEIGHT, 1.0) AS MATCH_WEIGHT,
                              cat.DETECTION_THRESHOLD,
                              cat.C_LEVEL,
                              cat.I_LEVEL,
                              cat.A_LEVEL
                          FROM {db}.INFORMATION_SCHEMA.COLUMNS c
                          JOIN {gv_str}.SENSITIVE_PATTERNS p
                            ON p.IS_ACTIVE = TRUE
                           AND REGEXP_LIKE(LOWER(c.COLUMN_NAME), p.PATTERN_STRING, 'i')
                          JOIN CATEGORIES cat
                            ON p.CATEGORY_ID = cat.CATEGORY_ID
                        ),

                        -- 5️⃣ Combine detections
                        COMBINED AS (
                          SELECT * FROM RULE_BASED
                          UNION ALL
                          SELECT * FROM PATTERN_BASED
                        ),

                        -- 6️⃣ Rank detections per column
                        RANKED_DETECTIONS AS (
                          SELECT
                              DATABASE_NAME,
                              TABLE_SCHEMA,
                              TABLE_NAME,
                              COLUMN_NAME,
                              CATEGORY_ID,
                              CATEGORY_NAME,
                              DETECTION_TYPE,
                              MATCHED_KEYWORD,
                              MATCHED_PATTERN,
                              MATCH_WEIGHT,
                              DETECTION_THRESHOLD,
                              C_LEVEL,
                              I_LEVEL,
                              A_LEVEL,
                              ROW_NUMBER() OVER (
                                  PARTITION BY DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME
                                  ORDER BY MATCH_WEIGHT DESC
                              ) AS RANK_ORDER
                          FROM COMBINED
                        ),

                        -- 7️⃣ Take top detection per column
                        TOP_DETECTIONS AS (
                          SELECT *
                          FROM RANKED_DETECTIONS
                          WHERE RANK_ORDER = 1
                        ),

                        -- 8️⃣ Aggregate detections
                        AGGREGATED AS (
                          SELECT
                              DATABASE_NAME,
                              TABLE_SCHEMA,
                              TABLE_NAME,
                              COLUMN_NAME,
                              CATEGORY_NAME,
                              ARRAY_AGG(DISTINCT MATCHED_KEYWORD) WITHIN GROUP (ORDER BY MATCHED_KEYWORD) AS MATCHED_KEYWORDS,
                              ARRAY_AGG(DISTINCT MATCHED_PATTERN) WITHIN GROUP (ORDER BY MATCHED_PATTERN) AS MATCHED_PATTERNS,
                              MAX(MATCH_WEIGHT) AS RAW_SCORE,
                              MAX(DETECTION_THRESHOLD) AS DETECTION_THRESHOLD,
                              MAX(C_LEVEL) AS C_LEVEL,
                              MAX(I_LEVEL) AS I_LEVEL,
                              MAX(A_LEVEL) AS A_LEVEL,
                              MAX(DETECTION_TYPE) AS DETECTION_TYPE
                          FROM TOP_DETECTIONS
                          WHERE MATCHED_KEYWORD IS NOT NULL OR MATCHED_PATTERN IS NOT NULL
                          GROUP BY DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, CATEGORY_NAME
                        ),

                        -- 9️⃣ Compute weighted confidence score
                        SCORED AS (
                          SELECT
                              a.*,
                              LEAST(
                                CASE 
                                  WHEN a.DETECTION_TYPE = 'RULE_BASED' THEN a.RAW_SCORE * (SELECT RULE_BASED_WEIGHT FROM WEIGHTS)
                                  WHEN a.DETECTION_TYPE = 'PATTERN_BASED' THEN a.RAW_SCORE * (SELECT PATTERN_BASED_WEIGHT FROM WEIGHTS)
                                  ELSE a.RAW_SCORE
                                END * 100,
                                100
                              ) AS CONFIDENCE_SCORE
                          FROM AGGREGATED a
                        )
                    """
                    # No semantic placeholders needed for this query
                    sql2 = f"""
                        {cte_sql.replace('{DB}', db)}
                        SELECT
                            COLUMN_NAME                                      AS "Column Name",
                            CATEGORY_NAME                                    AS "Sensitivity Type",
                            ROUND(CONFIDENCE_SCORE, 2)                       AS "Confidence",
                            ROUND(C_LEVEL, 2)                                AS "C",
                            ROUND(A_LEVEL, 2)                                AS "A",
                            ROUND(I_LEVEL, 2)                                AS "I",
                            CASE C_LEVEL
                                WHEN 0 THEN 'Public'
                                WHEN 1 THEN 'Internal'
                                WHEN 2 THEN 'Restricted'
                                WHEN 3 THEN 'Confidential'
                                ELSE 'Unknown'
                            END                                               AS "Confidentiality Level",
                            CASE I_LEVEL
                                WHEN 0 THEN 'Low'
                                WHEN 1 THEN 'Standard'
                                WHEN 2 THEN 'High'
                                WHEN 3 THEN 'Critical'
                                ELSE 'Unknown'
                            END                                               AS "Integrity Level",
                            CASE A_LEVEL
                                WHEN 0 THEN 'Low'
                                WHEN 1 THEN 'Standard'
                                WHEN 2 THEN 'High'
                                WHEN 3 THEN 'Critical'
                                ELSE 'Unknown'
                            END                                               AS "Availability Level",
                            CASE 
                                WHEN CONFIDENCE_SCORE >= (DETECTION_THRESHOLD * 100) THEN 'POLICY_REQUIRED'
                                WHEN CONFIDENCE_SCORE >= (DETECTION_THRESHOLD * 100 * 0.6) THEN 'NEEDS_REVIEW'
                                ELSE 'OK'
                            END                                               AS "Recommended Policies",
                            ''                                                AS "Bundle",
                            CASE 
                                WHEN CONFIDENCE_SCORE >= (DETECTION_THRESHOLD * 100 * 0.6) 
                                     AND CONFIDENCE_SCORE < (DETECTION_THRESHOLD * 100) THEN TRUE
                                ELSE FALSE
                            END                                               AS "Need Review",
                            CASE 
                                WHEN CONFIDENCE_SCORE >= (DETECTION_THRESHOLD * 100) THEN 'Column contains high-sensitivity data (PII/Financial/RegEx Match)'
                                WHEN CONFIDENCE_SCORE >= (DETECTION_THRESHOLD * 100 * 0.6) THEN 'Column partially matches sensitive patterns — manual review recommended'
                                ELSE 'Column appears safe under current detection thresholds'
                            END                                               AS "Reason / Justification",
                            CASE 
                                WHEN CONFIDENCE_SCORE >= (DETECTION_THRESHOLD * 100) THEN 'HIGH'
                                WHEN CONFIDENCE_SCORE >= (DETECTION_THRESHOLD * 100 * 0.6) THEN 'MEDIUM'
                                ELSE 'LOW'
                            END                                               AS "Sensitivity Level",
                            DATABASE_NAME,
                            TABLE_SCHEMA,
                            TABLE_NAME,
                            CURRENT_TIMESTAMP()                               AS DETECTED_AT
                        FROM SCORED
                        WHERE UPPER(DATABASE_NAME) = UPPER(%(db)s)
                          AND UPPER(TABLE_SCHEMA) = UPPER(%(sc)s)
                          AND UPPER(TABLE_NAME) = UPPER(%(tb)s)
                        ORDER BY CONFIDENCE_SCORE DESC, DATABASE_NAME, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME
                        """
                    # Debug: Log query and parameters (commented out for production)
                    # st.warning(f"Executing query with parameters: db={db}, schema={sc}, table={tbl}")
                    
                    # No LIKE CONCAT fixup needed; query already uses concatenation operator for Snowflake
                    
                    # Now handle the parameter binding
                    safe_sql = sql2
                    
                    # For debugging purposes, you can uncomment the next line to see the query
                    # st.code(f"SQL Query with parameters:\n{safe_sql}", language='sql')
                    
                    # Verify database context
                    try:
                        with snowflake_connector.get_connection() as conn:
                            with conn.cursor() as cursor:
                                # Set context
                                cursor.execute(f"USE DATABASE {db}")
                                cursor.execute(f"USE SCHEMA {sc}")
                                
                                # Execute with debug info
                                start_time = datetime.now()
                                
                                # Prepare the query with parameters
                                debug_query = safe_sql.replace("%(db)s", f"'{db.upper()}'") \
                                                    .replace("%(sc)s", f"'{sc.upper()}'") \
                                                    .replace("%(tb)s", f"'{tbl.upper()}'")
                                
                                # Uncomment the next line to see the query in the UI for debugging
                                # st.code(f"Executing query:\n{debug_query}", language='sql')
                                
                                # Execute the query with direct string formatting for now
                                # This is just for debugging - we'll make it more secure after we get it working
                                cursor.execute(debug_query)
                                # Get column names and fetch results
                                columns = [desc[0] for desc in cursor.description]
                                cols_detect = [dict(zip(columns, row)) for row in cursor.fetchall()]
                    except Exception as perm_e:
                        st.error(f"Failed to execute drill-down query: {str(perm_e)}")
                except Exception as e:
                    st.error(f"Drill-down query failed: {str(e)}")
                    cols_detect = []
            except Exception as outer_e:
                st.error(f"Unexpected error in drill-down: {str(outer_e)}")
                import traceback
                st.code(f"Outer error traceback:\n{traceback.format_exc()}", language='python')
                cols_detect = []
            # No special empty-state or fallback logic

            # Show detected table-level sensitive type (top category by total confidence across columns)
            try:
                # Compute from current results to avoid re-querying without context
                if cols_detect:
                    agg = {}
                    for r in cols_detect:
                        cat = r.get("Sensitivity Type") or r.get("DETECTED_TYPE")
                        try:
                            conf = float(r.get("Confidence") if r.get("Confidence") is not None else 0.0)
                        except Exception:
                            conf = 0.0
                        if cat:
                            agg[cat] = agg.get(cat, 0.0) + conf
                    if agg:
                        detected_type = max(agg.items(), key=lambda x: x[1])[0]
                        st.caption(f"Table sensitive type: `{detected_type}`")
            except Exception:
                pass

            # Build editable grid
            editor_rows = []
            for c in (cols_detect or []):
                _sens = c.get("Sensitivity Type") or c.get("DETECTED_TYPE") or ""
                try:
                    _conf = float(c.get("Confidence") if c.get("Confidence") is not None else (c.get("COMBINED_CONFIDENCE") if c.get("COMBINED_CONFIDENCE") is not None else (c.get("CONFIDENCE_SCORE") if c.get("CONFIDENCE_SCORE") is not None else 0.0)))
                except Exception:
                    _conf = 0.0
                _need = c.get("Need Review")
                if _need is None:
                    try:
                        _need = bool(_conf < 0.7)
                    except Exception:
                        _need = False
                # Map C/A/I values to 0..3 scale if they appear as fractional weights
                try:
                    _c_val = float(c.get("C") if c.get("C") is not None else 0.0)
                except Exception:
                    _c_val = 0.0
                try:
                    _a_val = float(c.get("A") if c.get("A") is not None else 0.0)
                except Exception:
                    _a_val = 0.0
                try:
                    _i_val = float(c.get("I") if c.get("I") is not None else 0.0)
                except Exception:
                    _i_val = 0.0
                _c_level = int(round(_c_val * 3)) if _c_val <= 1.0 else int(round(max(0.0, min(_c_val, 3.0))))
                _a_level = int(round(_a_val * 3)) if _a_val <= 1.0 else int(round(max(0.0, min(_a_val, 3.0))))
                _i_level = int(round(_i_val * 3)) if _i_val <= 1.0 else int(round(max(0.0, min(_i_val, 3.0))))
                editor_rows.append({
                    "Column Name": c.get("Column Name") or c.get("COLUMN_NAME") or c.get("column"),
                    "Sensitivity Type": _sens,
                    "C": ["0 - Public","1 - Internal","2 - Restricted","3 - Confidential"][_c_level],
                    "A": ["0 - Low","1 - Standard","2 - High","3 - Critical"][_a_level],
                    "I": ["0 - Low","1 - Standard","2 - High","3 - Critical"][_i_level],
                    "Recommended Policies": c.get("Recommended Policies") or "",
                    "Bundle": c.get("Bundle") or "",
                    "Need Review": bool(_need),
                    "Reason / Justification": c.get("Reason / Justification") or "",
                })
            df_edit = _pd.DataFrame(editor_rows)
            _orig_key = f"orig_edit_{selected_full_name}"
            if not df_edit.empty:
                # Ensure CIA columns are strings to match Selectbox options
                try:
                    for _col in ("C","A","I"):
                        if _col in df_edit.columns:
                            df_edit[_col] = df_edit[_col].astype(str)
                    _c_opts = ["0 - Public","1 - Internal","2 - Restricted","3 - Confidential"]
                    _ai_opts = ["0 - Low","1 - Standard","2 - High","3 - Critical"]
                    if "C" in df_edit.columns:
                        df_edit["C"] = _pd.Categorical(df_edit["C"], categories=_c_opts, ordered=True)
                    if "A" in df_edit.columns:
                        df_edit["A"] = _pd.Categorical(df_edit["A"], categories=_ai_opts, ordered=True)
                    if "I" in df_edit.columns:
                        df_edit["I"] = _pd.Categorical(df_edit["I"], categories=_ai_opts, ordered=True)
                except Exception:
                    pass
                st.session_state[_orig_key] = df_edit.copy()
            editor_conf_ai = {
                "C": st.column_config.SelectboxColumn(options=["0 - Public","1 - Internal","2 - Restricted","3 - Confidential"], help="Confidentiality: 0=Public, 1=Internal, 2=Restricted, 3=Confidential"),
                "I": st.column_config.SelectboxColumn(options=["0 - Low","1 - Standard","2 - High","3 - Critical"], help="Integrity: 0=Low, 1=Standard, 2=High, 3=Critical"),
                "A": st.column_config.SelectboxColumn(options=["0 - Low","1 - Standard","2 - High","3 - Critical"], help="Availability: 0=Low, 1=Standard, 2=High, 3=Critical"),
            }
            edited = st.data_editor(
                df_edit,
                width='stretch',
                num_rows="fixed",
                hide_index=True,
                column_config=editor_conf_ai,
                key=f"cia_editor_{selected_full_name}",
            ) if not df_edit.empty else None

            st.markdown("### Tagging Assistant")
            if tagging_service is None:
                st.warning("Tagging service unavailable")
            else:
                _default_fqn = selected_full_name or ""
                _c1, _c2, _c3 = st.columns(3)
                with _c1:
                    _op = st.selectbox("Action", [
                        "Generate tags from CIA",
                        "Generate SQL",
                        "Explain tag",
                        "Diagnose issue",
                        "Apply tags",
                    ], key=f"ai_tag_action_{selected_full_name}")
                with _c2:
                    _target_fqn = st.text_input("Object (DB.SCHEMA.OBJECT)", value=_default_fqn, key=f"ai_tag_target_{selected_full_name}")
                with _c3:
                    _object_type = st.selectbox("Object type", ["TABLE", "VIEW", "SCHEMA", "DATABASE"], key=f"ai_tag_objtype_{selected_full_name}")
                _l, _r = st.columns(2)
                with _l:
                    _class_idx = ALLOWED_CLASSIFICATIONS.index("Internal") if "Internal" in (ALLOWED_CLASSIFICATIONS or []) else 0
                    _classification = st.selectbox("Classification", ALLOWED_CLASSIFICATIONS, index=_class_idx, key=f"ai_tag_class_{selected_full_name}")
                    _c_val = st.number_input("C", min_value=0, max_value=3, step=1, value=1, key=f"ai_tag_c_{selected_full_name}")
                    _i_val = st.number_input("I", min_value=0, max_value=3, step=1, value=1, key=f"ai_tag_i_{selected_full_name}")
                    _a_val = st.number_input("A", min_value=0, max_value=3, step=1, value=1, key=f"ai_tag_a_{selected_full_name}")
                    if _op == "Generate tags from CIA" and st.button("Suggest tags", key=f"ai_tag_suggest_{selected_full_name}"):
                        try:
                            _tags = tagging_service.suggest_tags_from_criteria(_classification, int(_c_val), int(_i_val), int(_a_val))
                            st.json(_tags)
                            if _target_fqn:
                                try:
                                    _sql_obj = tagging_service.generate_tag_sql_for_object(_target_fqn, _object_type, _tags)
                                    st.code(_sql_obj, language="sql")
                                except Exception as _e_sql:
                                    st.warning(str(_e_sql))
                        except Exception as _e:
                            st.error(str(_e))
                with _r:
                    _tags_text = st.text_area("Tags (TAG=VALUE per line)", value="DATA_CLASSIFICATION=Internal\nCONFIDENTIALITY_LEVEL=1", height=120, key=f"ai_tag_text_{selected_full_name}")
                    def _parse_lines(_txt: str):
                        _out = {}
                        for _line in (_txt or "").splitlines():
                            if "=" in _line:
                                _k, _v = _line.split("=", 1)
                                _out[str(_k).strip().upper()] = str(_v).strip()
                        return _out
                    if _op == "Generate SQL" and st.button("Generate SQL", key=f"ai_tag_gensql_{selected_full_name}"):
                        _tags2 = _parse_lines(_tags_text)
                        try:
                            if _target_fqn and _tags2:
                                _sql = tagging_service.generate_tag_sql_for_object(_target_fqn, _object_type, _tags2)
                                st.code(_sql, language="sql")
                        except Exception as _e:
                            st.error(str(_e))
                    if _op == "Explain tag":
                        _tname = st.text_input("Tag name", value="DATA_CLASSIFICATION", key=f"ai_tag_name_{selected_full_name}")
                        _tval = st.text_input("Value (optional)", value="", key=f"ai_tag_val_{selected_full_name}")
                        if st.button("Explain", key=f"ai_tag_explain_{selected_full_name}"):
                            try:
                                _info = tagging_service.explain_tag(_tname, _tval if _tval else None)
                                st.json(_info)
                            except Exception as _e:
                                st.error(str(_e))
                    if _op == "Diagnose issue":
                        _errmsg = st.text_area("Error message", value="", key=f"ai_tag_err_{selected_full_name}")
                        if st.button("Diagnose", key=f"ai_tag_diag_{selected_full_name}"):
                            try:
                                _diag_tags = _parse_lines(_tags_text)
                                _sug = tagging_service.diagnose(_target_fqn or None, _object_type if _target_fqn else None, _diag_tags or None, _errmsg)
                                st.json({"suggestions": _sug})
                            except Exception as _e:
                                st.error(str(_e))
                    if _op == "Apply tags" and st.button("Apply", key=f"ai_tag_apply_{selected_full_name}"):
                        try:
                            _tags_apply = _parse_lines(_tags_text)
                            if _target_fqn and _tags_apply:
                                tagging_service.apply_tags_to_object(_target_fqn, _object_type, _tags_apply)
                                st.success("Applied.")
                            else:
                                st.warning("Provide object and at least one TAG=VALUE")
                        except Exception as _e:
                            st.error(str(_e))

            if edited is not None and st.button("Save Changes", key=f"save_edits_{selected_full_name}"):
                try:
                    orig = st.session_state.get(_orig_key, _pd.DataFrame())
                    user = None
                    try:
                        ident = authz.get_current_identity()
                        user = getattr(ident, "user", None)
                    except Exception:
                        user = None
                    actor = str(user or st.session_state.get("user") or "user")
                    ts = __import__('datetime').datetime.utcnow().isoformat() + 'Z'
                    for idx in range(len(edited)):
                        row_new = edited.iloc[idx].to_dict()
                        row_old = orig.iloc[idx].to_dict() if idx < len(orig) else {k: None for k in row_new}
                        col_name = row_new.get("Column Name")
                        path = {"table": selected_full_name, "column": col_name}
                        for field in [
                            "Sensitivity Type","C","A","I","Recommended Policies","Bundle","Need Review","Reason / Justification","Keywords"
                        ]:
                            if str(row_new.get(field)) != str(row_old.get(field)):
                                change_payload = {
                                    "username": actor,
                                    "timestamp": ts,
                                    "action_type": "edit",
                                    "field": field,
                                    "old_value": row_old.get(field),
                                    "new_value": row_new.get(field),
                                    "object_path": path,
                                    "comment": row_new.get("Reason / Justification"),
                                }
                                try:
                                    if _svc and hasattr(_svc, 'audit_change'):
                                        _svc.audit_change(selected_full_name, str(col_name or ""), "EDIT", change_payload)
                                except Exception:
                                    pass
                        # Persist override aggregate for column
                        try:
                            _c_int = 0
                            _a_int = 0
                            _i_int = 0
                            try:
                                _c_val = row_new.get("C")
                                _c_int = int(str(_c_val).split('-')[0].strip())
                            except Exception:
                                try:
                                    _c_int = int(_c_val)
                                except Exception:
                                    _c_int = 0
                            try:
                                _a_val = row_new.get("A")
                                _a_int = int(str(_a_val).split('-')[0].strip())
                            except Exception:
                                try:
                                    _a_int = int(_a_val)
                                except Exception:
                                    _a_int = 0
                            try:
                                _i_val = row_new.get("I")
                                _i_int = int(str(_i_val).split('-')[0].strip())
                            except Exception:
                                try:
                                    _i_int = int(_i_val)
                                except Exception:
                                    _i_int = 0
                            ov = {
                                "sensitivity_type": row_new.get("Sensitivity Type"),
                                "C": _c_int,
                                "A": _a_int,
                                "I": _i_int,
                                "policies": [s.strip() for s in str(row_new.get("Recommended Policies") or "").split(',') if s.strip()],
                                "bundle": row_new.get("Bundle"),
                                "need_review": bool(row_new.get("Need Review")),
                                "reason": row_new.get("Reason / Justification"),
                                "keywords": [s.strip() for s in str(row_new.get("Keywords") or "").split(',') if s.strip()],
                            }
                            if _svc and hasattr(_svc, 'persist_column_overrides'):
                                _svc.persist_column_overrides(selected_full_name, str(col_name or ""), ov)
                        except Exception:
                            pass
                    st.success("Changes saved and audited.")
                except Exception as e:
                    st.error(f"Failed to save changes: {e}")
        # Minimal debug expander
        show_debug = st.checkbox("Show Debug Info", value=False)
        if show_debug:
            with st.expander("🔍 Debug Information", expanded=False):
                try:
                    cfg = getattr(ai_classification_service, '_sensitivity_config', {})
                    st.json({
                        "config_keys": list(cfg.keys()) if isinstance(cfg, dict) else [],
                        "use_snowflake": bool(getattr(ai_classification_service, 'use_snowflake', False)),
                    })
                except Exception as e:
                    st.error(f"Error getting debug info: {str(e)}")

   

    '''

    # Guided Workflow
    with sub_guided:
        st.markdown("#### Guided Classification Workflow")
        # Snowflake ops via services
        def _sf_apply_tags(asset_full_name: str, tags: dict):
            """Apply tags to a Snowflake object using tagging service or direct ALTER statements."""
            try:
                tagging_service.apply_tags_to_object(asset_full_name, tags)  # real service call
            except Exception:
                pass

        def _sf_record_decision(asset_full_name: str, label: str, c: int, i: int, a: int, rationale: str, details: dict):
            """Record decision for audit via service or governance table."""
            try:
                classification_decision_service.record(
                    asset_full_name=asset_full_name,
                    decision_maker=str(st.session_state.get("user") or "user"),
                    source="NEW_CLASSIFICATION",
                    status="SUBMITTED",
                    classification_label=label,
                    c=int(c), i=int(i), a=int(a),
                    rationale=rationale,
                    details=details,
                )
            except Exception:
                pass

        # Inventory-backed selection, ordered by FIRST_DISCOVERED (recent first)
        _db_active = _active_db_from_filter()
        _gv = st.session_state.get("governance_schema") or "DATA_CLASSIFICATION_GOVERNANCE"
        _gf = st.session_state.get("global_filters") or {}
        inv_rows = _inventory_assets(_db_active, _gv, _gf)
        inv_options_real = [ (r.get("FULLY_QUALIFIED_NAME") or r.get("FULL_NAME")) for r in (inv_rows or []) if (r.get("FULLY_QUALIFIED_NAME") or r.get("FULL_NAME")) ]
        placeholder = "— Select an asset —"
        inv_options = ([placeholder] + inv_options_real) if inv_options_real else ["No assets available"]
        sel_asset_nc = st.selectbox("Asset (from Inventory)", options=inv_options, index=0, key="nc_asset")
        # Track last selection to gate prefill
        last_asset_key = "nc_asset_last"
        prev_asset = st.session_state.get(last_asset_key)
        inv_map = {r.get("FULL_NAME"): r for r in (inv_rows or [])}
        valid_asset_selected = bool(sel_asset_nc and sel_asset_nc not in ("No assets available", placeholder))

        # Prefill context fields on selection from inventory
        if valid_asset_selected and sel_asset_nc != prev_asset:
            try:
                meta = inv_map.get(sel_asset_nc) or {}
                st.session_state.setdefault("nc_type", meta.get("ASSET_TYPE") or meta.get("OBJECT_TYPE") or "")
                st.session_state.setdefault("nc_dept", meta.get("DATA_DOMAIN") or meta.get("OBJECT_DOMAIN") or "")
                st.session_state.setdefault("nc_owner", meta.get("OWNER") or meta.get("CUSTODIAN") or "")
            except Exception:
                pass
            # Update last asset tracker
            st.session_state[last_asset_key] = sel_asset_nc

        # Show metadata context
        if valid_asset_selected:
            with st.expander("Asset Metadata", expanded=False):
                m = inv_map.get(sel_asset_nc) or {}
                st.markdown(f"- Type: `{(m.get('ASSET_TYPE') or m.get('OBJECT_TYPE') or '—')}`")
                st.markdown(f"- Domain: `{(m.get('DATA_DOMAIN') or m.get('OBJECT_DOMAIN') or '—')}`")
                st.markdown(f"- Source: `{(m.get('SOURCE_SYSTEM') or '—')}`")
                st.markdown(f"- Owner: `{(m.get('OWNER') or m.get('CUSTODIAN') or '—')}`")

        # Gate: render form only after valid selection
        if valid_asset_selected:
            # clear_on_submit ensures Streamlit drops widget state after submission so the form is 'freed'
            with st.form(key="nc_guided_form", clear_on_submit=True):
                # Step 1
                st.markdown("##### Step 1: Business Context Assessment")
                # Scoped keys per selected asset to avoid stale reuse
                try:
                    import re
                    _aid = re.sub(r"[^A-Za-z0-9_]", "_", str(sel_asset_nc))
                except Exception:
                    _aid = str(sel_asset_nc).replace('.', '_').replace('-', '_').replace(' ', '_')
                nc_type = st.text_input("Asset Type", key=f"nc_type_{_aid}", help="E.g., Table, View, File, Report")
                nc_dept = st.text_input("Department", key=f"nc_dept_{_aid}", help="Owning business unit/department")
                nc_owner = st.text_input("Owner", key=f"nc_owner_{_aid}", help="Primary data owner or steward")
                nc_purpose = st.text_area("Business Purpose", key=f"nc_purpose_{_aid}", help="What business outcome this asset supports")
                # Mirror into base keys for downstream usage
                st.session_state["nc_type"] = nc_type
                st.session_state["nc_dept"] = nc_dept
                st.session_state["nc_owner"] = nc_owner
                st.session_state["nc_purpose"] = nc_purpose

                # PHASE 1: Tracking & deadlines
                c1d, c2d, c3d = st.columns([1,1,1])
                with c1d:
                    nc_created = st.date_input("Creation Date", value=st.session_state.get("nc_creation_date") or date.today(), key=f"nc_creation_date_{_aid}")
                    st.session_state["nc_creation_date"] = nc_created
                with c2d:
                    default_due = st.session_state.get("nc_due_date") or _add_business_days(date.today(), 5)
                    nc_due = st.date_input("Due Date", value=default_due, key=f"nc_due_date_{_aid}")
                    st.session_state["nc_due_date"] = nc_due
                    st.caption("Due within 5 business days per Policy 6.1.1")
                with c3d:
                    try:
                        bdays_remaining = _business_days_between(date.today(), nc_due)
                    except Exception:
                        bdays_remaining = 0
                    # Deadline status coloring
                    if bdays_remaining <= 0:
                        st.error(f"Deadline Status: Overdue — {bdays_remaining} business days remaining")
                        nc_deadline_status = "Overdue"
                    elif bdays_remaining <= 5:
                        st.warning(f"Deadline Status: Due Soon — {bdays_remaining} business days remaining")
                        nc_deadline_status = "Due Soon"
                    else:
                        st.success(f"Deadline Status: On Track — {bdays_remaining} business days remaining")
                        nc_deadline_status = "On Track"

                # Heuristic signals from inventory
                import pandas as _pd
                pii_flag = False; fin_flag = False
                try:
                    db = _active_db_from_filter()
                    gv = st.session_state.get("governance_schema") or "DATA_CLASSIFICATION_GOVERNANCE"
                    rowi = snowflake_connector.execute_query(
                        f"""
                        select CONTAINS_PII as PII_DETECTED, 
                               (CONTAINS_FINANCIAL_DATA OR SOX_RELEVANT) as FINANCIAL_DATA_DETECTED
                        from {db}.{gv}.ASSETS
                        where FULLY_QUALIFIED_NAME = %(f)s
                        limit 1
                        """,
                        {"f": sel_asset_nc},
                    ) or [] if db else []
                    if rowi:
                        pii_flag = bool(rowi[0].get("PII_DETECTED", False))
                        fin_flag = bool(rowi[0].get("FINANCIAL_DATA_DETECTED", False))
                except Exception:
                    pass
                # AI special category detection (with confidence)
                ai_categories = []
                ai_confidence = {}
                try:
                    dets = ai_classification_service.detect_sensitive_columns(sel_asset_nc) or []
                    cats = []
                    conf_map = {}
                    for d in dets:
                        d_cats = (d.get('categories') or [])
                        for cat in d_cats:
                            cats.append(str(cat))
                        # Optional confidence per detection
                        try:
                            conf_val = float(d.get('confidence')) if d.get('confidence') is not None else None
                        except Exception:
                            conf_val = None
                        if conf_val is not None:
                            for cat in d_cats:
                                conf_map[cat] = max(conf_map.get(cat, 0.0), conf_val)
                    # Normalize category names (rename Financial -> SOX for display parity)
                    ai_categories = sorted(set([("SOX" if str(c).upper()=="FINANCIAL" else str(c)) for c in cats]))
                    ai_confidence = { ("SOX" if str(k).upper()=="FINANCIAL" else str(k)) : float(v) for k,v in conf_map.items() }
                except Exception:
                    ai_categories = []
                    ai_confidence = {}
                # Show detection summary to user
                if ai_categories:
                    try:
                        st.info("Detected special categories: " + ", ".join([f"`{c}`" for c in ai_categories]))
                        _det_df = _pd.DataFrame([{"Category": k, "Confidence": round(v, 2)} for k, v in (ai_confidence.items() or [])])
                        if not _det_df.empty:
                            st.dataframe(_det_df, hide_index=True, use_container_width=True)
                    except Exception:
                        pass
                # Persist detected categories for downstream tagging review
                try:
                    st.session_state["nc_ai_categories"] = list(ai_categories)
                except Exception:
                    pass
                # Step 2: C, Step 3: I, Step 4: A — Guided Questions with automatic scoring
                st.markdown("##### Step 2: Confidentiality (C0–C3)")
                st.caption("C0: Public | C1: Internal | C2: Restricted (PII/Financial) | C3: Confidential/Highly Sensitive")
                # Confidentiality questions
                c_q_unauth = st.selectbox(
                    "What happens if this data is seen by unauthorized people?",
                    ["No impact", "Minor", "Significant", "Severe"],
                    index=1,
                    key=f"nc_c_unauth_{_aid}",
                    help="Assess business, legal, and reputational impact of unauthorized disclosure"
                )
                c_q_pii = st.radio(
                    "Does this contain personal customer information?",
                    ["No", "Yes"],
                    index=(1 if (pii_flag or ("PII" in [str(x).upper() for x in ai_categories])) else 0),
                    key=f"nc_c_pii_{_aid}"
                )
                c_q_competitor = st.selectbox(
                    "Would competitors benefit from accessing this data?",
                    ["No", "Some", "High"],
                    index=0,
                    key=f"nc_c_comp_{_aid}"
                )
                c_q_legal = st.selectbox(
                    "Are there legal requirements to protect this data?",
                    ["No", "Contractual", "Regulatory"],
                    index=0,
                    key=f"nc_c_legal_{_aid}"
                )
                _map_c1 = {"No impact": 0, "Minor": 1, "Significant": 2, "Severe": 3}
                _map_comp = {"No": 0, "Some": 1, "High": 2}
                _map_legal = {"No": 0, "Contractual": 2, "Regulatory": 3}
                c_score = 0
                try:
                    c_score = max(c_score, _map_c1.get(str(c_q_unauth), 0))
                    c_score = max(c_score, _map_comp.get(str(c_q_competitor), 0))
                    c_score = max(c_score, _map_legal.get(str(c_q_legal), 0))
                    if str(c_q_pii).lower() == "yes":
                        c_score = max(c_score, 2)
                except Exception:
                    pass
                # Integrity questions
                st.markdown("##### Step 3: Integrity (I0–I3)")
                st.caption("I0: Low | I1: Moderate | I2: High | I3: Critical — impact if data is inaccurate or corrupted")
                i_q_wrong = st.selectbox(
                    "What happens if this data is wrong or gets changed?",
                    ["No impact", "Minor", "Significant", "Severe"],
                    index=1,
                    key=f"nc_i_wrong_{_aid}"
                )
                i_q_accuracy = st.selectbox(
                    "How critical is 100% accuracy for business decisions?",
                    ["Not critical", "Important", "Critical"],
                    index=1,
                    key=f"nc_i_acc_{_aid}"
                )
                i_q_finlegal = st.selectbox(
                    "Would incorrect data cause financial or legal problems?",
                    ["No", "Possibly", "Likely"],
                    index=1,
                    key=f"nc_i_fin_{_aid}"
                )
                _map_i1 = {"No impact": 0, "Minor": 1, "Significant": 2, "Severe": 3}
                _map_i2 = {"Not critical": 0, "Important": 2, "Critical": 3}
                _map_i3 = {"No": 0, "Possibly": 2, "Likely": 3}
                i_score = 0
                try:
                    i_score = max(i_score, _map_i1.get(str(i_q_wrong), 0))
                    i_score = max(i_score, _map_i2.get(str(i_q_accuracy), 0))
                    i_score = max(i_score, _map_i3.get(str(i_q_finlegal), 0))
                except Exception:
                    pass
                # Availability questions
                st.markdown("##### Step 4: Availability (A0–A3)")
                st.caption("A0: Days+ | A1: Hours | A2: <1 hour | A3: Near real-time — operational need to access data promptly")
                a_q_noaccess = st.selectbox(
                    "What happens if we can't access this data during work hours?",
                    ["Minimal", "Disruptive", "Severe"],
                    index=1,
                    key=f"nc_a_nowork_{_aid}"
                )
                a_q_restore = st.selectbox(
                    "How quickly do we need this data restored if unavailable?",
                    ["Days", "Hours", "<1 hour", "Real-time"],
                    index=1,
                    key=f"nc_a_restore_{_aid}"
                )
                a_q_ops = st.selectbox(
                    "Would business operations stop without this data?",
                    ["No", "Partial", "Yes"],
                    index=1,
                    key=f"nc_a_ops_{_aid}"
                )
                _map_a1 = {"Minimal": 0, "Disruptive": 1, "Severe": 2}
                _map_a2 = {"Days": 0, "Hours": 1, "<1 hour": 2, "Real-time": 3}
                _map_a3 = {"No": 0, "Partial": 2, "Yes": 3}
                a_score = 0
                try:
                    a_score = max(a_score, _map_a1.get(str(a_q_noaccess), 0))
                    a_score = max(a_score, _map_a2.get(str(a_q_restore), 0))
                    a_score = max(a_score, _map_a3.get(str(a_q_ops), 0))
                except Exception:
                    pass
                # Persist and expose as C/I/A selections
                c_q = max(0, min(3, int(c_score)))
                i_q = max(0, min(3, int(i_score)))
                a_q = max(0, min(3, int(a_score)))
                try:
                    _comp_fw = []
                    try:
                        _ctx = None
                        try:
                            _ctx = ai_classification_service.build_enriched_context(sel_asset_nc, sample_rows=10)
                        except Exception:
                            _ctx = None
                        _ctab = ai_classification_service.classify_table(sel_asset_nc, context=_ctx)
                        _comp_fw = list(_ctab.get("compliance_frameworks") or [])
                    except Exception:
                        _comp_fw = []
                    _ai_cats_up = [str(x).upper() for x in (ai_categories or [])]
                    _fw_up = [str(x).upper() for x in (_comp_fw or [])]
                    if ("PII" in _ai_cats_up):
                        c_q = max(c_q, 2)
                    if ("PHI" in _ai_cats_up) or ("HIPAA" in _fw_up):
                        c_q = 3
                    if ("SOX" in _ai_cats_up) or ("FINANCIAL" in _ai_cats_up) or ("SOX" in _fw_up) or ("PCI" in _fw_up):
                        c_q = 3
                    if ("REGULATORY" in _ai_cats_up) or ("GDPR" in _fw_up) or ("CCPA" in _fw_up):
                        c_q = 3
                    c_q = max(0, min(3, int(c_q)))
                except Exception:
                    pass
                st.session_state["nc_c"] = c_q
                st.session_state["nc_i"] = i_q
                st.session_state["nc_a"] = a_q
                st.session_state["nc_c_answers"] = {
                    "unauthorized_view": str(c_q_unauth),
                    "pii_present": str(c_q_pii),
                    "competitor_benefit": str(c_q_competitor),
                    "legal_requirements": str(c_q_legal),
                }
                st.session_state["nc_i_answers"] = {
                    "wrong_or_changed_impact": str(i_q_wrong),
                    "accuracy_criticality": str(i_q_accuracy),
                    "financial_or_legal_risk": str(i_q_finlegal),
                }
                st.session_state["nc_a_answers"] = {
                    "work_hours_unavailable": str(a_q_noaccess),
                    "restore_speed": str(a_q_restore),
                    "ops_dependency": str(a_q_ops),
                }

                # Step 5: Overall Risk label
                highest = max(int(c_q), int(i_q), int(a_q))
                label = ["Public","Internal","Restricted","Confidential"][highest]
                risk_bucket = "Low" if highest <= 1 else ("Medium" if highest == 2 else "High")
                ok_dm, reasons = dm_validate(label, int(c_q), int(i_q), int(a_q))
                st.info(f"Overall Classification: {label} | Risk: {risk_bucket}")
                st.success(f"Based on your answers: This should be classified as {label}")
                if not ok_dm and reasons:
                    for r in reasons:
                        st.error(r)

                # PHASE 2: Policy guard for sensitive data (Section 5.5)
                # Consider heuristics and AI-detected categories and enforce minimum classification
                sensitive = bool(pii_flag or fin_flag or (ai_categories and len(ai_categories) > 0))
                cats_upper = {str(x).upper() for x in (ai_categories or [])}
                min_c_required = 0
                reasons_min = []
                if pii_flag or ("PII" in cats_upper) or any(k in cats_upper for k in {"EMAIL","PHONE","ADDRESS","PERSONAL"}):
                    min_c_required = max(min_c_required, 2)
                    reasons_min.append("contains personal data")
                if fin_flag or ("FINANCIAL" in cats_upper) or ("SOX" in cats_upper):
                    min_c_required = max(min_c_required, 2)
                    reasons_min.append("contains financial/SOX-relevant data")
                if any(k in cats_upper for k in {"SSN","NATIONAL_ID","CARD","PAN","PHI","SECRETS","CREDENTIALS","GOVERNMENT_ID"}):
                    min_c_required = max(min_c_required, 3)
                    reasons_min.append("highly sensitive identifiers present")
                st.session_state["nc_min_c_required"] = int(min_c_required)
                policy_compliant = True
                if int(c_q) < int(min_c_required):
                    min_label = ["Public","Internal","Restricted","Confidential"][int(min_c_required)]
                    msg_reason = ("; ".join(reasons_min)) or "sensitive content detected"
                    st.error(f"Minimum classification enforced: {min_label} (C>={min_c_required}) due to {msg_reason}.")
                    policy_compliant = False
                st.session_state["nc_policy_compliant"] = policy_compliant

                # PHASE 3: Replace override with Policy Exception workflow
                if not policy_compliant:
                    st.markdown("**Policy Exception Required**")
                    exc_col1, exc_col2 = st.columns([2,1])
                    with exc_col1:
                        exc_reason = st.text_area("Exception Justification (required)", key="nc_exception_reason", help="Provide rationale and approvals context for policy exception request")
                    with exc_col2:
                        exc_submit = st.form_submit_button("Request Policy Exception", key="nc_request_exception")
                        if exc_submit:
                            st.session_state["nc_exception_requested"] = True
                            st.session_state["nc_exception_reason_saved"] = exc_reason
                            st.info("Policy exception requested and saved to draft context. Submission is blocked until approved externally.")
                    # Hard stop submission path
                    if not exc_reason:
                        st.caption("Add justification and save draft for exception processing.")

                # PHASE 3: Structured CIA Assessment (Section 6.2.1)
                st.markdown("##### Step 6: Structured CIA Assessment (per Policy Section 6.2.1)")
                with st.expander("Confidentiality Assessment", expanded=True):
                    # TODO: Replace labels below with exact wording from Policy Section 6.2.1
                    c_q1 = st.text_area("[6.2.1-C1] Describe data categories and sensitivity drivers (exact policy text)", key=f"nc_c_q1_{_aid}")
                    c_q2 = st.text_area("[6.2.1-C2] Describe access roles, external sharing, contractual constraints (exact policy text)", key=f"nc_c_q2_{_aid}")
                    c_q3 = st.text_area("[6.2.1-C3] Describe impact of unauthorized disclosure (exact policy text)", key=f"nc_c_q3_{_aid}")
                    st.session_state["nc_c_q1"] = c_q1
                    st.session_state["nc_c_q2"] = c_q2
                    st.session_state["nc_c_q3"] = c_q3
                with st.expander("Integrity Assessment", expanded=False):
                    i_q1 = st.text_area("[6.2.1-I1] Required data quality/validation controls (exact policy text)", key=f"nc_i_q1_{_aid}")
                    i_q2 = st.text_area("[6.2.1-I2] Business impact of inaccurate or stale data (exact policy text)", key=f"nc_i_q2_{_aid}")
                    st.session_state["nc_i_q1"] = i_q1
                    st.session_state["nc_i_q2"] = i_q2
                with st.expander("Availability Assessment", expanded=False):
                    a_q1 = st.text_area("[6.2.1-A1] RTO/RPO or maximum tolerable downtime (exact policy text)", key=f"nc_a_q1_{_aid}")
                    a_q2 = st.text_area("[6.2.1-A2] Operational dependencies and access criticality (exact policy text)", key=f"nc_a_q2_{_aid}")
                    st.session_state["nc_a_q1"] = a_q1
                    st.session_state["nc_a_q2"] = a_q2

                # Auto-generate rationale from answers (prefill if empty)
                try:
                    _reasons_txt = ", ".join(reasons_min) if (reasons_min) else ("policy-aligned risk assessment")
                except Exception:
                    _reasons_txt = "policy-aligned risk assessment"
                auto_rationale = (
                    f"Classified as {label} because {_reasons_txt}. "
                    f"Integrity set to I{i_q} based on impact and accuracy needs. "
                    f"Availability set to A{a_q} considering restore time and operational dependency."
                )
                if not st.session_state.get(f"nc_rationale_{_aid}"):
                    st.session_state[f"nc_rationale_{_aid}"] = auto_rationale

                # Documentation & Approval (kept for backward compatibility)
                st.markdown("##### Step 7: Documentation & Approval")
                rationale = st.text_area("Additional Notes", key=f"nc_rationale_{_aid}", help="Any additional context (optional)")
                refs = st.text_area("References", key=f"nc_refs_{_aid}", help="Links to policies, Jira tickets, runbooks, etc.")
                attachments = st.file_uploader("Attachments", accept_multiple_files=True, key=f"nc_files_{_aid}")
                st.session_state["nc_rationale"] = rationale
                st.session_state["nc_refs"] = refs
                st.session_state["nc_files"] = attachments
                col1, col2 = st.columns(2)
                with col1:
                    save = st.form_submit_button("Save Draft")
                with col2:
                    approve = st.form_submit_button("Submit for Approval", type="primary")

            # Handle form actions
            if 'save' in locals() and save:
                st.session_state.setdefault("nc_drafts", {})[sel_asset_nc] = {
                    "c": int(st.session_state.get("nc_c", 1)),
                    "i": int(st.session_state.get("nc_i", 1)),
                    "a": int(st.session_state.get("nc_a", 1)),
                    "rationale": st.session_state.get("nc_rationale", ""),
                    "purpose": st.session_state.get("nc_purpose", ""),
                    "type": st.session_state.get("nc_type", ""),
                    "department": st.session_state.get("nc_dept", ""),
                    "owner": st.session_state.get("nc_owner", ""),
                    "references": st.session_state.get("nc_refs", ""),
                    "attachments": [f.name for f in (st.session_state.get("nc_files") or [])],
                    # PHASE 1 & 3 persistence
                    "creation_date": str(st.session_state.get("nc_creation_date", "")),
                    "due_date": str(st.session_state.get("nc_due_date", "")),
                    "deadline_status": locals().get("nc_deadline_status", ""),
                    "risk": locals().get("risk_bucket", ""),
                    "assessment": {
                        "confidentiality": {
                            "categories": st.session_state.get("nc_c_q1", ""),
                            "access_sharing": st.session_state.get("nc_c_q2", ""),
                            "disclosure_impact": st.session_state.get("nc_c_q3", ""),
                        },
                        "integrity": {
                            "controls": st.session_state.get("nc_i_q1", ""),
                            "impact": st.session_state.get("nc_i_q2", ""),
                        },
                        "availability": {
                            "rto_rpo": st.session_state.get("nc_a_q1", ""),
                            "dependencies": st.session_state.get("nc_a_q2", ""),
                        },
                    },
                    "policy_compliance": bool(st.session_state.get("nc_policy_compliant", True)),
                    "policy_exception_requested": bool(st.session_state.get("nc_exception_requested", False)),
                    "policy_exception_reason": st.session_state.get("nc_exception_reason_saved", ""),
                    "ai_detection": {
                        "categories": ai_categories,
                        "confidence": ai_confidence,
                    },
                }
                st.success("Draft saved in session.")
            if 'approve' in locals() and approve:
                try:
                    # Block submit until Decision Matrix validation passes
                    ok_dm2, reasons2 = dm_validate(label, int(st.session_state.get('nc_c', 1)), int(st.session_state.get('nc_i', 1)), int(st.session_state.get('nc_a', 1)))
                    if not ok_dm2:
                        for r in (reasons2 or []):
                            st.error(r)
                        st.stop()
                    # Block submit if policy exception required and not handled
                    if not bool(st.session_state.get("nc_policy_compliant", True)):
                        st.error("Policy exception required: sensitive asset not compliant (C must be >=2).")
                        st.stop()
                    # Deadline enforcement: escalate and block repeated violations
                    try:
                        if st.session_state.get("nc_deadline_status") == "Overdue":
                            st.warning("This item is overdue. Escalation has been triggered.")
                            st.session_state["nc_overdue_count"] = int(st.session_state.get("nc_overdue_count", 0)) + 1
                            _sf_audit_log_classification(sel_asset_nc, "ESCALATE_OVERDUE", {
                                "creation_date": str(st.session_state.get("nc_creation_date", "")),
                                "due_date": str(st.session_state.get("nc_due_date", ""))
                            })
                            if int(st.session_state.get("nc_overdue_count", 0)) > 1:
                                st.error("Submission blocked due to repeated overdue violations. Manager approval required.")
                                _sf_audit_log_classification(sel_asset_nc, "BLOCKED_REPEATED_VIOLATION", {})
                                st.stop()
                    except Exception:
                        pass
                    # Validate required structured assessment (Section 6.2.1)
                    missing = []
                    if not st.session_state.get("nc_c_q1"): missing.append("Confidentiality: categories")
                    if not st.session_state.get("nc_c_q2"): missing.append("Confidentiality: access/sharing")
                    if not st.session_state.get("nc_c_q3"): missing.append("Confidentiality: disclosure impact")
                    if not st.session_state.get("nc_i_q1"): missing.append("Integrity: controls")
                    if not st.session_state.get("nc_i_q2"): missing.append("Integrity: impact")
                    if not st.session_state.get("nc_a_q1"): missing.append("Availability: RTO/RPO")
                    if not st.session_state.get("nc_a_q2"): missing.append("Availability: dependencies")
                    if missing:
                        st.error("Policy Section 6.2.1: Please complete required assessment fields: " + ", ".join(missing))
                        st.stop()
                    # Enforce Section 5.5 (hard stop)
                    if not bool(st.session_state.get("nc_policy_compliant", True)):
                        st.error("Policy Section 5.5: Submission blocked. Sensitive data must be classified at least 'Restricted' (C>=2).")
                        st.stop()
                    db = _active_db_from_filter()
                    # Lowercase tag keys as requested
                    final_label = label
                    # Risk-based routing and tag application
                    try:
                        owner = (st.session_state.get("nc_owner") or "").strip()
                        classification_date = date.today().isoformat()
                        review_date = (date.today() + timedelta(days=365)).isoformat()
                        tags = {
                            "data_classification": final_label,
                            "confidentiality_level": f"C{int(st.session_state.get('nc_c', 0))}",
                            "integrity_level": f"I{int(st.session_state.get('nc_i', 0))}",
                            "availability_level": f"A{int(st.session_state.get('nc_a', 0))}",
                            "business_owner": owner,
                            "classification_date": classification_date,
                            "review_date": review_date,
                        }
                        # Persist detailed answers to audit trail
                        _sf_audit_log_classification(sel_asset_nc, "SUBMIT_FOR_APPROVAL", {
                            "label": final_label,
                            "risk": locals().get("risk_bucket", ""),
                            "cia": {
                                "c": int(st.session_state.get('nc_c', 0)),
                                "i": int(st.session_state.get('nc_i', 0)),
                                "a": int(st.session_state.get('nc_a', 0)),
                            },
                            "answers": {
                                "confidentiality": st.session_state.get("nc_c_answers", {}),
                                "integrity": st.session_state.get("nc_i_answers", {}),
                                "availability": st.session_state.get("nc_a_answers", {}),
                            },
                            "ai_detection": st.session_state.get("nc_drafts", {}).get(sel_asset_nc, {}).get("ai_detection", {"categories": ai_categories}),
                        })
                        # Route by risk
                        if locals().get("risk_bucket") == "Low":
                            _sf_apply_tags(sel_asset_nc, tags)
                            _sf_audit_log_classification(sel_asset_nc, "APPROVED_AUTO", {"tags": tags})
                            st.success("Low-risk asset auto-approved. Tags applied.")
                        elif locals().get("risk_bucket") == "Medium":
                            _sf_audit_log_classification(sel_asset_nc, "PENDING_PEER_REVIEW", {"tags": tags})
                            st.info("Medium-risk asset routed for Peer Review. Tags will be applied after approval.")
                            st.stop()
                        else:
                            _sf_audit_log_classification(sel_asset_nc, "PENDING_MANAGER_APPROVAL", {"tags": tags})
                            st.warning("High-risk asset requires Manager approval. Tags will be applied after approval.")
                            st.stop()
                    except Exception:
                        pass
                    try:
                        keys_to_clear = [
                            "nc_type","nc_dept","nc_owner","nc_purpose",
                            "nc_creation_date","nc_due_date",
                            "nc_c","nc_i","nc_a",
                            "nc_c_q1","nc_c_q2","nc_c_q3",
                            "nc_i_q1","nc_i_q2",
                            "nc_a_q1","nc_a_q2",
                            "nc_rationale","nc_refs","nc_files",
                            "nc_policy_compliant","nc_exception_requested","nc_exception_reason_saved",
                        ]
                        for _k in keys_to_clear:
                            st.session_state.pop(_k, None)
                        # Also clear scoped keys for this asset id
                        try:
                            for _k in list(st.session_state.keys()):
                                if _k.startswith("nc_") and _k.endswith(f"_{_aid}"):
                                    st.session_state.pop(_k, None)
                        except Exception:
                            pass
                        # Also clear any draft and selection to fully free the workflow
                        try:
                            if 'nc_drafts' in st.session_state and sel_asset_nc in (st.session_state.get('nc_drafts') or {}):
                                st.session_state['nc_drafts'].pop(sel_asset_nc, None)
                        except Exception:
                            pass
                        # Reset selected asset so the selectbox returns to default
                        st.session_state.pop("nc_asset", None)
                        st.session_state.pop(last_asset_key, None)
                    except Exception:
                        pass
                except Exception:
                    pass

        # Final Tagging Review under Guided Workflow
        if valid_asset_selected and st.session_state.get("nc_c") is not None:
            try:
                import json as _json
            except Exception:
                _json = None
            # Recompute asset-scoped key id
            try:
                import re as _re
                _aid2 = _re.sub(r"[^A-Za-z0-9_]", "_", str(sel_asset_nc))
            except Exception:
                _aid2 = str(sel_asset_nc).replace('.', '_').replace('-', '_').replace(' ', '_')
            st.markdown("#### Final Tagging Review")
            st.caption("Review the generated Snowflake tags from your selections and apply now or schedule for later.")
            # Pull CIA from session
            _c_val = int(st.session_state.get("nc_c", 1))
            _i_val = int(st.session_state.get("nc_i", 1))
            _a_val = int(st.session_state.get("nc_a", 1))
            # Default label from highest CIA
            _default_label = ["Public","Internal","Restricted","Confidential"][max(_c_val, _i_val, _a_val)]
            _cls_choice = st.selectbox(
                "Classification Label",
                options=ALLOWED_CLASSIFICATIONS,
                index=(ALLOWED_CLASSIFICATIONS.index(_default_label) if _default_label in ALLOWED_CLASSIFICATIONS else 1),
                key=f"nc_final_cls_{_aid2}"
            )
            # Build tags preview
            try:
                _tags_preview = tagging_service.suggest_tags_from_criteria(_cls_choice, _c_val, _i_val, _a_val) if tagging_service else {}
            except Exception:
                _tags_preview = {
                    "DATA_CLASSIFICATION": _cls_choice,
                    "CONFIDENTIALITY_LEVEL": str(_c_val),
                    "INTEGRITY_LEVEL": str(_i_val),
                    "AVAILABILITY_LEVEL": str(_a_val),
                }
            try:
                _ai_specials = st.session_state.get("nc_ai_categories") or []
                if _ai_specials:
                    _tags_preview["SPECIAL_CATEGORY"] = ",".join([str(s) for s in _ai_specials])
            except Exception:
                pass
            st.write("Proposed tags:")
            st.json(_tags_preview)
            _rat2 = st.text_input("Rationale (required for audit)", key=f"nc_final_rat_{_aid2}")
            _confirm2 = st.checkbox("I confirm applying these tags to Snowflake", key=f"nc_final_confirm_{_aid2}")
            st.markdown("##### Schedule for later (optional)")
            sc1, sc2 = st.columns([1,1])
            with sc1:
                _sched_date2 = st.date_input("Apply date", key=f"nc_final_date_{_aid2}")
            with sc2:
                _sched_time2 = st.time_input("Apply time", key=f"nc_final_time_{_aid2}")
            b1, b2 = st.columns([1,1])
            with b1:
                if st.button("Apply Now", key=f"nc_final_apply_{_aid2}"):
                    if not _rat2.strip():
                        st.error("Rationale is required for audit logging.")
                    elif not _confirm2:
                        st.error("Please confirm before applying tags.")
                    else:
                        try:
                            if not authz.can_apply_tags_for_object(sel_asset_nc, object_type="TABLE"):
                                st.error("Insufficient privileges to apply tags (ALTER/OWNERSHIP required).")
                            else:
                                tagging_service.apply_tags_to_object(sel_asset_nc, "TABLE", _tags_preview)
                                st.success("Tags applied.")
                                # Audit
                                try:
                                    ident = authz.get_current_identity()
                                    user_id = getattr(ident, "user", None)
                                except Exception:
                                    user_id = None
                                actor = str(user_id or st.session_state.get("user") or "user")
                                try:
                                    classification_decision_service.record(
                                        asset_full_name=sel_asset_nc,
                                        decision_by=actor,
                                        source="GUIDED_TAG_APPLY",
                                        status="Applied",
                                        label=str(_cls_choice),
                                        c=int(_c_val), i=int(_i_val), a=int(_a_val),
                                        rationale=str(_rat2).strip(),
                                        details={"scope": "TABLE", "tags": _tags_preview},
                                    )
                                except Exception:
                                    pass
                        except Exception as e:
                            st.error(f"Failed to apply tags: {e}")
            with b2:
                if st.button("Schedule for later", key=f"nc_final_sched_{_aid2}"):
                    try:
                        _dt2 = None
                        try:
                            import datetime as _dtm
                            if _sched_date2 and _sched_time2:
                                _dt2 = _dtm.datetime.combine(_sched_date2, _sched_time2)
                        except Exception:
                            _dt2 = None
                        if _dt2 is None:
                            st.error("Please pick a valid date and time to schedule.")
                        else:
                            try:
                                db2 = sel_asset_nc.split('.')[0]
                            except Exception:
                                db2 = None
                            gov_schema2 = st.session_state.get("governance_schema") or "DATA_CLASSIFICATION_GOVERNANCE"
                            try:
                                _tags_json2 = _json.dumps(_tags_preview) if _json else str(_tags_preview)
                            except Exception:
                                _tags_json2 = str(_tags_preview)
                            if db2:
                                try:
                                    snowflake_connector.execute_non_query(
                                        f"""
                                        create schema if not exists {db2}.{gov_schema2};
                                        create table if not exists {db2}.{gov_schema2}.TAG_APPLY_QUEUE (
                                          ID string,
                                          ASSET_FULL_NAME string,
                                          SCOPE string,
                                          COLUMN_NAME string,
                                          TAGS_JSON string,
                                          APPLY_AT timestamp_ntz,
                                          STATUS string,
                                          CREATED_BY string,
                                          CREATED_AT timestamp_ntz
                                        );
                                        insert into {db2}.{gov_schema2}.TAG_APPLY_QUEUE
                                          (ID, ASSET_FULL_NAME, SCOPE, COLUMN_NAME, TAGS_JSON, APPLY_AT, STATUS, CREATED_BY, CREATED_AT)
                                        select UUID_STRING(), %(full)s, 'TABLE', NULL, %(tags)s, %(at)s, 'PENDING', %(by)s, CURRENT_TIMESTAMP;
                                        """,
                                        {"full": sel_asset_nc, "tags": _tags_json2, "at": _dt2.isoformat(), "by": str(st.session_state.get("user") or "user")}
                                    )
                                    st.success("Tag application scheduled.")
                                except Exception as e:
                                    st.error(f"Failed to schedule tag apply: {e}")
                            else:
                                st.error("Could not determine database from asset name for scheduling.")
                    except Exception:
                        pass
                    # Removed st.rerun() to prevent no-op warning


            @st.cache_data(ttl=30)
            def _inv_tables_for_db(db: str, gv_schema: str, sel_db: str) -> List[str]:
                try:
                    rows = snowflake_connector.execute_query(
                        f"""
                        SELECT FULLY_QUALIFIED_NAME AS FULL_NAME
                        FROM {db}.{gv_schema}.ASSETS
                        WHERE DATABASE_NAME = %(sdb)s
                        ORDER BY FULLY_QUALIFIED_NAME
                        """,
                        {"sdb": sel_db},
                    ) or []
                    return [r.get("FULL_NAME") for r in rows]
                except Exception:
                    return []

        def _sf_apply_tags(asset_full_name, tags):
            """Apply Snowflake tags via tagging_service or ALTER statements."""
            try:
                tagging_service.apply_tags_to_object(asset_full_name, tags)
            except Exception:
                pass

        def _sf_audit_log_classification(asset_full_name, action, details):
            """Insert into CLASSIFICATION_AUDIT or use audit_service."""
            try:
                db = _active_db_from_filter() or resolve_governance_db()
                if db:
                    import json as _json
                    snowflake_connector.execute_non_query(
                        f"INSERT INTO {db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_AUDIT (RESOURCE_ID, ACTION, DETAILS) SELECT %(r)s, %(a)s, PARSE_JSON(%(j)s)",
                        {"r": asset_full_name, "a": action, "j": _json.dumps(details or {}, default=str)},
                    )
                    return
            except Exception:
                pass
            try:
                audit_service.log("CLASSIFICATION", action, {"resource": asset_full_name, **(details or {})})
            except Exception:
                pass

        # Removed legacy SOC/SOX heuristic flags in favor of dynamic compliance mapping from AI outputs

        def _suggest_cia_from_flags(signals: Dict, flags: Dict) -> Tuple[int,int,int,int,str]:
            # Reuse previous heuristic and elevat per flags
            cols = list(signals.keys())
            n = len(cols) or 1
            sensitive = [c for c, s in signals.items() if s.get("pii") or s.get("financial") or s.get("regulatory")]
            ratio = len(sensitive) / n
            c = 2 if ratio > 0 else 1
            if any(signals[cname].get("regulatory") for cname in cols):
                c = max(c, 3)
            if bool(flags.get("SOX")):
                c = max(c, 3)
                i = 2
            else:
                i = 1 if ratio <= 0.2 else 2
            a = 1 if ratio <= 0.2 else 2
            label = ["Public","Internal","Restricted","Confidential"][min(max(c,0),3)]
            confidence = int(60 + 40*min(ratio,1.0))
            return c, i, a, confidence, label

        def _keyify(name: str) -> str:
            """Sanitize a name for use in Streamlit widget keys (letters, digits, underscore)."""
            try:
                import re
                return re.sub(r"[^A-Za-z0-9_]", "_", str(name or ""))
            except Exception:
                return str(name or "").replace('.', '_').replace('-', '_').replace(' ', '_')

        @st.cache_data(ttl=30)
        def _inv_sensitive_tables(db: str, gv_schema: str, target_db: str, schema_f: Optional[str], table_f: Optional[str]) -> List[Dict]:
            """Dynamic sensitive table discovery combining:
            1) Inventory flags from ASSETS (canonical governance table)
            2) Heuristics from INFORMATION_SCHEMA (name/token matches)
            3) Lightweight sampling-based detection via AI service
            4) Optional AI table-level probability from classify_sensitive
            """
            if not target_db:
                return []

            # Configurable sensitivity threshold (0..100)
            try:
                sens_threshold = int(st.session_state.get("ai_sens_threshold", 60))
            except Exception:
                sens_threshold = 60

            # Helper to compute a combined score for a table
            def _score_table(fqn: str, flags: Dict[str, bool], name_hits: int, col_name_hits: int,
                             sample_conf: Optional[float], ai_prob: Optional[float]) -> int:
                score = 0.0
                try:
                    # Inventory flags are a strong signal
                    if any(flags.values()):
                        score += 60.0
                        # Extra weight if regulatory flags present
                        if flags.get("SOX") or flags.get("SOC"):
                            score += 10.0
                    # Heuristic name matches (table + columns)
                    score += min(30.0, float(name_hits) * 10.0)  # table name tokens
                    score += min(30.0, float(col_name_hits) * 5.0)  # column name tokens
                    # Sampling-based confidence (0..1) -> up to 40 points
                    if isinstance(sample_conf, (int, float)) and sample_conf is not None:
                        score += max(0.0, min(40.0, float(sample_conf) * 40.0))
                    # AI probability (0..1) -> up to 30 points
                    if isinstance(ai_prob, (int, float)) and ai_prob is not None:
                        score += max(0.0, min(30.0, float(ai_prob) * 30.0))
                except Exception:
                    pass
                return int(max(0.0, min(100.0, score)))

            # Sensitive tokens for names/columns from dynamic configuration only
            sensitive_tokens: list[str] = []
            try:
                _cfg = st.session_state.get("sensitivity_config") if hasattr(st, "session_state") else None
                if isinstance(_cfg, dict):
                    _kw = _cfg.get("keywords_flat") or _cfg.get("keywords") or []
                    # Support both list-of-dicts and dict-of-category->list
                    if isinstance(_kw, dict):
                        _iter = []
                        for _cat, _items in (_kw or {}).items():
                            for _it in (_items or []):
                                _iter.append(_it)
                    else:
                        _iter = list(_kw)
                    for it in _iter:
                        try:
                            tok = str((getattr(it, "get", lambda *_: None)("token")
                                       or getattr(it, "get", lambda *_: None)("keyword")
                                       or "")).strip().lower()
                            if tok:
                                sensitive_tokens.append(tok)
                        except Exception:
                            continue
            except Exception:
                pass
                sensitive_tokens = []
            tokens_up = {t.upper() for t in (sensitive_tokens or [])}

            # 1) Inventory flags
            base_where = ["DATABASE_NAME = %(db)s"]
            params = {"db": target_db}
            if schema_f:
                base_where.append("SCHEMA_NAME = %(sc)s"); params["sc"] = schema_f
            if table_f:
                base_where.append("TABLE_NAME = %(tb)s"); params["tb"] = table_f
            where_sql = ' AND '.join(base_where)
            fqn_candidates = [
                f"{db}.{gv_schema}.ASSETS" if db and gv_schema else None,
                "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS",
            ]
            fqn_candidates = [x for x in fqn_candidates if x]

            inv_rows: List[Dict[str, object]] = []
            try:
                for _fqn in fqn_candidates:
                    try:
                        q = f"""
                            SELECT FULLY_QUALIFIED_NAME AS FULL_NAME,
                                   COALESCE(CONTAINS_PII, FALSE)              AS PII,
                                   COALESCE(CONTAINS_FINANCIAL_DATA, FALSE)   AS FIN,
                                   FALSE                                       AS IP,
                                   COALESCE(SOC_RELEVANT, FALSE)               AS SOC,
                                   COALESCE(SOX_RELEVANT, FALSE)               AS SOX
                            FROM {_fqn}
                            WHERE {where_sql}
                        """
                        _rows = snowflake_connector.execute_query(q, params) or []
                        if _rows:
                            inv_rows = _rows
                            break
                    except Exception:
                        continue
            except Exception:
                inv_rows = []

            # 2) Heuristic discovery from INFORMATION_SCHEMA: table and column name tokens
            heur_tables: Dict[str, Dict[str, object]] = {}
            try:
                # Table-level name match
                q_tbl = f"""
                    select table_catalog, table_schema, table_name
                    from {target_db}.information_schema.tables
                    where 1=1
                    {" and upper(table_schema)=%(sc)s" if schema_f else ""}
                    {" and upper(table_name)=%(tb)s" if table_f else ""}
                """
                rows_tbl = snowflake_connector.execute_query(q_tbl, {k:v for k,v in {"sc": schema_f, "tb": table_f}.items() if v}) or []
                for r in rows_tbl:
                    fqn = f"{r.get('TABLE_CATALOG')}.{r.get('TABLE_SCHEMA')}.{r.get('TABLE_NAME')}"
                    up = fqn.upper()
                    hits = sum(1 for tok in tokens_up if tok in up)
                    if hits > 0:
                        heur_tables[fqn] = {"FULL_NAME": fqn, "name_hits": hits, "col_hits": 0}
            except Exception:
                pass
            try:
                # Column-level name match
                q_col = f"""
                    select table_catalog, table_schema, table_name, column_name
                    from {target_db}.information_schema.columns
                    where 1=1
                    {" and upper(table_schema)=%(sc)s" if schema_f else ""}
                    {" and upper(table_name)=%(tb)s" if table_f else ""}
                """
                rows_col = snowflake_connector.execute_query(q_col, {k:v for k,v in {"sc": schema_f, "tb": table_f}.items() if v}) or []
                for r in rows_col:
                    fqn = f"{r.get('TABLE_CATALOG')}.{r.get('TABLE_SCHEMA')}.{r.get('TABLE_NAME')}"
                    col = str(r.get('COLUMN_NAME') or "").upper()
                    if any(tok in col for tok in tokens_up):
                        if fqn not in heur_tables:
                            heur_tables[fqn] = {"FULL_NAME": fqn, "name_hits": 0, "col_hits": 1}
                        else:
                            heur_tables[fqn]["col_hits"] = heur_tables[fqn].get("col_hits", 0) + 1
            except Exception:
                pass

            # 3) Lightweight sampling-based detection for non-inventory candidates
            # Run only for a bounded set to limit cost
            sample_conf_map: Dict[str, float] = {}
            try:
                from src.services.ai_classification_service import ai_classification_service as _svc
            except Exception:
                _svc = None  # type: ignore
            try:
                sample_size = int(st.session_state.get("ai_table_sample_size", 200)) if hasattr(st, "session_state") else 200
            except Exception:
                sample_size = 200
            try:
                to_sample = [fqn for fqn in heur_tables.keys() if fqn and not any((r.get("FULL_NAME") or "").upper() == fqn.upper() for r in (inv_rows or []))]
                # Cap number of sampled tables to avoid heavy scans
                to_sample = to_sample[:50]
                for fqn in to_sample:
                    conf = 0.0
                    try:
                        if _svc is not None:
                            cols = _svc.detect_sensitive_columns(fqn, sample_size=sample_size) or []
                            # Use aggregated average confidence across detected columns (0..1)
                            if cols:
                                avg = sum([float((c.get('confidence') or 0))/100.0 for c in cols]) / float(len(cols))
                                conf = float(max(0.0, min(1.0, avg)))
                    except Exception:
                        conf = 0.0
                    sample_conf_map[fqn] = conf
            except Exception:
                pass

            # 4) Optional AI probability using unified classify_table features
            ai_prob_map: Dict[str, float] = {}
            try:
                if _svc is not None:
                    # Evaluate a small set: inventory + top heuristics
                    eval_set = set([str(r.get("FULL_NAME")) for r in (inv_rows or []) if r.get("FULL_NAME")]) | set(list(heur_tables.keys())[:50])
                    for fqn in list(eval_set)[:100]:
                        try:
                            _ctx = None
                            try:
                                _ctx = _svc.build_enriched_context(str(fqn), sample_rows=10)
                            except Exception:
                                _ctx = None
                            cls = _svc.classify_table(str(fqn), context=_ctx) or {}
                            feats = (cls.get("features") or {})
                            ts = float(feats.get("table_sensitivity_score") or 0.0)
                            ai_prob_map[str(fqn)] = float(max(0.0, min(1.0, ts)))
                        except Exception:
                            continue
            except Exception:
                pass

            # Merge and score
            out_map: Dict[str, Dict[str, object]] = {}
            # Seed with inventory rows
            for r in (inv_rows or []):
                try:
                    fqn = str(r.get("FULL_NAME"))
                    flags = {k: bool(r.get(k)) for k in ("PII","FIN","IP","SOC","SOX")}
                    name_hits = 0
                    col_hits = heur_tables.get(fqn, {}).get("col_hits", 0)
                    sc = _score_table(
                        fqn,
                        flags,
                        name_hits,
                        col_hits,
                        sample_conf_map.get(fqn),
                        ai_prob_map.get(fqn),
                    )
                    out_map[fqn] = {"FULL_NAME": fqn, "SCORE": sc, **flags}
                except Exception:
                    continue
            # Add heuristic-only tables
            for fqn, meta in heur_tables.items():
                if fqn in out_map:
                    # Already present; keep max score
                    try:
                        prev = out_map[fqn].get("SCORE", 0)
                        flags = {k: bool(out_map[fqn].get(k, False)) for k in ("PII","FIN","IP","SOC","SOX")}
                        sc = _score_table(
                            fqn,
                            flags,
                            int(meta.get("name_hits", 0)),
                            int(meta.get("col_hits", 0)),
                            sample_conf_map.get(fqn),
                            ai_prob_map.get(fqn),
                        )
                        out_map[fqn]["SCORE"] = max(prev, sc)
                    except Exception:
                        pass
                else:
                    try:
                        sc = _score_table(
                            fqn,
                            {"PII": False, "FIN": False, "IP": False, "SOC": False, "SOX": False},
                            int(meta.get("name_hits", 0)),
                            int(meta.get("col_hits", 0)),
                            sample_conf_map.get(fqn),
                            ai_prob_map.get(fqn),
                        )
                        out_map[fqn] = {"FULL_NAME": fqn, "SCORE": sc}
                    except Exception:
                        continue

            # Filter and rank by threshold
            rows = [v for v in out_map.values() if int(v.get("SCORE", 0)) >= int(sens_threshold)]
            try:
                rows.sort(key=lambda x: int(x.get("SCORE", 0)), reverse=True)
            except Exception:
                pass

            # If nothing found, fallback to simple inventory FULL_NAME listing to preserve legacy behavior
            if not rows:
                for _fqn in fqn_candidates:
                    try:
                        q = f"SELECT FULL_NAME FROM {_fqn} WHERE {where_sql} ORDER BY FULL_NAME LIMIT 1000"
                        _rows = snowflake_connector.execute_query(q, params) or []
                        if _rows:
                            return _rows
                    except Exception:
                        continue
            return rows

        

# Get global filters (used by other sections)
_gv = st.session_state.get("governance_schema") or "DATA_CLASSIFICATION_GOVERNANCE"
gf = st.session_state.get("global_filters") or {}

if False:
    st.markdown("### Sensitive Table Detection")
    st.caption("Detect and classify sensitive tables based on column names and data patterns.")
    
    # Get current database and schema
    current_db = _active_db_from_filter()
    current_schema = st.session_state.get("global_filters", {}).get("schema")
    
    # Database and schema selection
    col1, col2 = st.columns(2)
    with col1:
        db_list = [""] + snowflake_connector.execute_query("SHOW DATABASES")
        selected_db = st.selectbox(
            "Select Database", 
            options=db_list, 
            index=db_list.index(current_db) if current_db in db_list else 0,
            key="ai_sensitive_db",
            on_change=_trigger_sensitive_scan
        )
    
    schema_list = [""]
    if selected_db:
        try:
            schema_list.extend([s[0] for s in snowflake_connector.execute_query(
                f"SHOW SCHEMAS IN DATABASE {selected_db}")])
        except Exception as e:
            st.warning(f"Could not load schemas: {str(e)}")
    
    with col2:
        selected_schema = st.selectbox(
            "Filter by Schema", 
            options=schema_list, 
            index=schema_list.index(current_schema) if current_schema in schema_list else 0,
            key="ai_sensitive_schema",
            on_change=_trigger_sensitive_scan
        )
    
    # Trigger scan on filter change or button press
    if st.session_state.get("trigger_sensitive_scan", False) and selected_db:
        st.session_state["trigger_sensitive_scan"] = False
        with st.spinner("Scanning for sensitive tables..."):
            try:
                results = _detect_sensitive_tables(
                    database=selected_db,
                    schema=selected_schema if selected_schema else None,
                    sample_size=1000
                )
                st.session_state["sensitive_tables"] = results
            except Exception as e:
                st.error(f"Error during sensitive table detection: {str(e)}")
    
    # Manual scan button
    if st.button("🔍 Scan for Sensitive Tables"):
        st.session_state["trigger_sensitive_scan"] = True
        st.experimental_rerun()
    
    # Display results if available
    if "sensitive_tables" in st.session_state and st.session_state["sensitive_tables"]:
        results = st.session_state["sensitive_tables"]
        
        # Filter by sensitivity level
        sensitivity_filter = st.multiselect(
            "Filter by Sensitivity",
            options=["HIGH", "MEDIUM"],
            default=["HIGH"],
            key="sensitivity_filter"
        )
        
        # Apply filters
        filtered_results = [
            t for t in results 
            if t['sensitivity_level'] in sensitivity_filter
        ]
        
        if not filtered_results:
            st.info("No tables match the selected filters.")
        else:
            # Display summary table
            summary_data = []
            for table in filtered_results:
                summary_data.append({
                    "Schema": table['schema'],
                    "Table": table['table'],
                    "Sensitivity": table['sensitivity_level'],
                    "Confidence": f"{table['confidence_score']:.0%}",
                    "Sensitive Columns": table['high_sensitivity_cols'] + table['medium_sensitivity_cols']
                })
            
            st.dataframe(
                pd.DataFrame(summary_data),
                use_container_width=True,
                hide_index=True
            )
            
            # Show details for each table
            for table in filtered_results:
                with st.expander(f"{table['schema']}.{table['table']} - {table['sensitivity_level']}"):
                    st.markdown("#### Column Analysis")
                    col_details = []
                    for col in table['columns']:
                        if col['sensitivity_level'] != 'LOW':
                            col_details.append({
                                "Column": col['column'],
                                "Type": col['data_type'],
                                "Sensitivity": col['sensitivity_level'],
                                "Score": f"{col['sensitivity_score']:.0%}"
                            })
                    
                    if col_details:
                        st.dataframe(
                            pd.DataFrame(col_details),
                            use_container_width=True,
                            hide_index=True
                        )
                    else:
                        st.info("No sensitive columns detected in this table.")
                    
                    # Add action buttons
                    if st.button("View Sample Data", key=f"view_sample_{table['schema']}_{table['table']}"):
                        try:
                            sample_query = f"SELECT * FROM {table['database']}.{table['schema']}.{table['table']} LIMIT 10"
                            sample_data = snowflake_connector.execute_query(sample_query)
                            st.dataframe(pd.DataFrame(sample_data or []))
                        except Exception as e:
                            st.error(f"Error fetching sample data: {str(e)}")
        
            # Removed 'AI Analysis' tab and its content
        # Helper: compute table-level suggestions and compliance
        def _compute_table_ai(fqn: str) -> dict:
            try:
                _ssz = 200
                try:
                    _ssz = int(st.session_state.get("ai_table_sample_size", 200))
                except Exception:
                    _ssz = 200
                # Ensure latest patterns/keywords are loaded prior to detection
                try:
                    _sel_db = (st.session_state.get("db_filter") or st.session_state.get("global_db_filter") or db_f)
                    _sc_fqn = (f"{_sel_db}.DATA_CLASSIFICATION_GOVERNANCE" if _sel_db else None)
                    ai_classification_service.load_sensitivity_config(force_refresh=False, schema_fqn=_sc_fqn)
                except Exception:
                    pass
                dets = ai_classification_service.detect_sensitive_columns(fqn, sample_size=_ssz) if ai_classification_service else []
                st.session_state["ai_sensitive_cols"][fqn] = dets
                # Unified: prefer classify_and_persist output
                cls = ai_classification_service.classify_and_persist(fqn, sample_size=_ssz) if ai_classification_service else {}
                t = {"table_name": fqn, "table_sensitivity_score": (cls.get("features") or {}).get("table_sensitivity_score")}
                cls_feats = (cls or {}).get('features') or {}
                ai_conf_avg = cls_feats.get('ai_confidence_avg')
                sens_cols = cls_feats.get('sensitive_columns_count')
                # Map AI outputs to legacy grid fields
                try:
                    t['classification_label'] = cls.get('classification')
                    t['confidence_score'] = int(round(float((cls_feats.get('table_sensitivity_score') or 0.0)) * 100))
                    t['predominant_type'] = cls_feats.get('dominant_table_category')
                except Exception:
                    pass
                # Apply table-level overrides if present
                try:
                    tbl_ovr = (st.session_state.get("ai_overrides", {}) or {}).get("tables", {}).get(fqn)
                except Exception:
                    tbl_ovr = None
                if isinstance(tbl_ovr, dict):
                    # Override classification and CIA
                    t['classification_label'] = tbl_ovr.get('classification_label') or t.get('classification_label')
                    t['C'] = int(tbl_ovr.get('C')) if tbl_ovr.get('C') is not None else t.get('C')
                    t['I'] = int(tbl_ovr.get('I')) if tbl_ovr.get('I') is not None else t.get('I')
                    t['A'] = int(tbl_ovr.get('A')) if tbl_ovr.get('A') is not None else t.get('A')
                    if tbl_ovr.get('policy_suggestion'):
                        t['policy_suggestion'] = tbl_ovr.get('policy_suggestion')
                # Persist light summary for other parts of the page
                st.session_state["ai_suggestions"][fqn] = {
                    "C": int(t.get("C", 0)),
                    "I": int(t.get("I", 0)),
                    "A": int(t.get("A", 0)),
                    "label": t.get("classification_label"),
                    "confidence": int(t.get("confidence_score") or 0),
                }
                return {
                    "FULL_NAME": str(t.get("fullname") or fqn),
                    "SENSITIVITY": str(t.get("predominant_type") or ""),
                    "ROW_COUNT": t.get("row_count"),
                    "C": int(t.get("C", 0)), "I": int(t.get("I", 0)), "A": int(t.get("A", 0)),
                    "LABEL": t.get("classification_label"),
                    "POLICY_OK": bool(t.get("policy_ok", True)),
                    "POLICY_ISSUES": "",
                    "AI_CONFIDENCE": int(t.get("confidence_score") or 0),
                    # Display fields from classify_table()
                    "SENSITIVITY_LEVEL": str((cls or {}).get('classification') or ''),
                    "AI_CONFIDENCE_AVG": (int(round(float(ai_conf_avg)*100)) if isinstance(ai_conf_avg, (int,float)) else None),
                    "SENSITIVE_COLUMNS": (int(sens_cols) if isinstance(sens_cols, (int,float)) else None),
                    "POLICY_SUGGESTION": t.get("policy_suggestion"),
                    "REASONING": t.get("reasoning"),
                    "REQUIRES_REVIEW": bool(t.get("requires_review", False)),
                }
            except Exception as e:
                return {"FULL_NAME": fqn, "SENSITIVITY": "", "ROW_COUNT": None, "C": 1, "I": 1, "A": 1, "LABEL": "Internal", "POLICY_OK": False, "POLICY_ISSUES": str(e)}
        # Compute summaries (force recompute to avoid stale cached outputs)
        if sensitive_options:
            st.session_state.setdefault("ai_table_summary", {})
            for fqn in sensitive_options:
                st.session_state["ai_table_summary"][fqn] = _compute_table_ai(fqn)
        # Render sensitive tables summary
        import pandas as _pd
        sum_rows = list((st.session_state.get("ai_table_summary") or {}).values())
        sum_df = _pd.DataFrame(sum_rows)
        # Augment with aggregated table-level detection (label, confidence) via classify_table()
        try:
            from src.services.ai_classification_service import ai_classification_service as _svc
            st.session_state.setdefault("ai_table_agg", {})
            names = [str(r.get("FULL_NAME")) for r in sum_rows if r.get("FULL_NAME")]
            new_agg = {}
            for fqn in names:
                if fqn in st.session_state["ai_table_agg"]:
                    continue
                try:
                    _ctx = None
                    try:
                        _ctx = _svc.build_enriched_context(fqn, sample_rows=10)
                    except Exception:
                        _ctx = None
                    cls = _svc.classify_table(fqn, context=_ctx)
                    feats = (cls.get("features") or {})
                    new_agg[fqn] = {
                        "overall_classification_label": cls.get("classification"),
                        "confidence_score": float(feats.get("table_sensitivity_score") or 0.0),
                        "requires_review": False,
                    }
                except Exception:
                    continue
            if new_agg:
                st.session_state["ai_table_agg"].update(new_agg)
            if not sum_df.empty:
                def _map_agg(fqn: str, key: str):
                    try:
                        return (st.session_state.get("ai_table_agg", {}) or {}).get(fqn, {}).get(key)
                    except Exception:
                        return None
                sum_df = sum_df.copy()
                sum_df["Agg Label"] = sum_df["FULL_NAME"].map(lambda n: _map_agg(n, "T_LABEL"))
                sum_df["Agg Confidence"] = sum_df["FULL_NAME"].map(lambda n: _map_agg(n, "T_CONF"))
                sum_df["Agg C"] = sum_df["FULL_NAME"].map(lambda n: _map_agg(n, "T_C"))
                sum_df["Agg I"] = sum_df["FULL_NAME"].map(lambda n: _map_agg(n, "T_I"))
                sum_df["Agg A"] = sum_df["FULL_NAME"].map(lambda n: _map_agg(n, "T_A"))
                sum_df["Agg Requires Review"] = sum_df["FULL_NAME"].map(lambda n: _map_agg(n, "T_REQ_REVIEW"))
                sum_df["Agg Policy"] = sum_df["FULL_NAME"].map(lambda n: _map_agg(n, "T_POLICY"))
                sum_df["Agg Name Semantic"] = sum_df["FULL_NAME"].map(lambda n: _map_agg(n, "T_SEM"))
                sum_df["Agg Sensitive Ratio"] = sum_df["FULL_NAME"].map(lambda n: _map_agg(n, "T_SENS_RATIO"))
        except Exception:
            pass
        # Removed legacy table keyword heuristics and policy suggestions; rely on live AI detection output exclusively

        # Statistical Profiling + Metadata Heuristics for table-level confidence
        try:
            USE_LEGACY_AI_CONFIDENCE = False
            st.session_state.setdefault("ai_table_profile", {})
            def _profile_table(fqn: str) -> dict:
                if fqn in st.session_state["ai_table_profile"]:
                    return st.session_state["ai_table_profile"][fqn]
                out = {"email":0, "phone":0, "ssn":0, "card":0, "hash":0, "rows":0, "null_ratio":0.0, "distinct_ratio":0.0}
                try:
                    # pick up to 5 candidate columns (VARCHAR/STRING) for quick profiling
                    parts = fqn.split('.')
                    if len(parts) == 3:
                        db, sch, tbl = parts
                        cols = snowflake_connector.execute_query(
                            f"select column_name, data_type from {db}.information_schema.columns where table_schema='{sch}' and table_name='{tbl}' order by ordinal_position limit 10"
                        ) or []
                    else:
                        cols = []
                    cand = [c.get('COLUMN_NAME') for c in cols if str(c.get('DATA_TYPE','')).upper().startswith(('VARCHAR','STRING','TEXT'))][:5]
                    # sample up to 1000 rows to compute pattern prevalence per column using dynamic patterns
                    from src.services.ai_classification_service import ai_classification_service as _svc
                    from src.services.sensitive_detection import regex_screen as _rx_screen
                    import pandas as _pdx
                    _cfg = _svc.load_sensitivity_config() if _svc else {}
                    total_rows = 0
                    nulls_total = 0
                    distinct_total = 0
                    for c in cand:
                        try:
                            rs = snowflake_connector.execute_query(
                                f"select {c} as V from {fqn} where {c} is not null limit 1000"
                            ) or []
                            vals = [list(r.values())[0] for r in rs if r]
                            total_rows += len(vals)
                            # crude null/unique from this sample scope
                            nulls_total += 0  # filtered non-nulls above
                            distinct_total += len(set([str(v) for v in vals]))
                            # dynamic regex screen per column sample
                            ser = _pdx.Series([str(v) for v in vals]) if vals else _pdx.Series([], dtype=str)
                            rx_probs = _rx_screen(ser, max_rows=1000, cfg=_cfg)
                            # Map common keys for summary view if present
                            out['email'] += int(round((rx_probs.get('email') or 0.0) * len(vals)))
                            out['phone'] += int(round((rx_probs.get('phone') or 0.0) * len(vals)))
                            out['ssn'] += int(round((rx_probs.get('ssn') or 0.0) * len(vals)))
                            out['card'] += int(round((rx_probs.get('credit_card') or 0.0) * len(vals)))
                        except Exception:
                            continue
                    out['rows'] = total_rows
                    # approximate ratios based on sample across columns
                    if total_rows > 0 and cand:
                        out['distinct_ratio'] = min(1.0, distinct_total / float(total_rows * len(cand)))
                        out['null_ratio'] = 0.0
                except Exception:
                    pass
                st.session_state["ai_table_profile"][fqn] = out
                return out

            def _profile_score(p: dict) -> int:
                score = 0
                score += 10 if p.get('email',0) > 0 else 0
                score += 10 if p.get('phone',0) > 0 else 0
                score += 15 if (p.get('ssn',0) > 0 or p.get('card',0) > 0) else 0
                score += 10 if p.get('hash',0) > 0 else 0
                if p.get('distinct_ratio',0.0) > 0.7:
                    score += 5
                return min(40, score)

            def _meta_boost(fqn: str) -> int:
                up = fqn.upper()
                boost = 0
                if any(k in up for k in ['AUDIT','SOX','LEDGER','PAYROLL','HR','CUSTOMER','VENDOR']):
                    boost += 10
                return boost

            if not sum_df.empty and USE_LEGACY_AI_CONFIDENCE:
                updated = []
                for idx, row in sum_df.iterrows():
                    fqn = str(row.get('FULL_NAME'))
                    prof = _profile_table(fqn)
                    prof_score = _profile_score(prof)
                    boost = _meta_boost(fqn)
                    base = int(row.get('AI_CONFIDENCE') or 50)
                    combined = max(0, min(100, base + prof_score + boost))
                    row['AI_CONFIDENCE'] = combined
                    row['POLICY_SUGGESTION'] = row.get('POLICY_SUGGESTION') or (
                        'Row Access Policy + Dynamic Masking (strong)' if prof.get('card',0) or prof.get('ssn',0) else (
                        'Dynamic Masking: partial; steward override' if prof.get('email',0) or prof.get('phone',0) else 'Tags only')
                    )
                    updated.append(row)
                sum_df = _pd.DataFrame(updated)
        except Exception:
            pass
        try:
            if not sum_df.empty and "AI_CONFIDENCE" in sum_df.columns:
                min_conf = st.slider("Minimum sensitivity confidence", min_value=0, max_value=100, value=0, step=1, key="ai_min_conf")
                if int(min_conf) > 0:
                    _before = len(sum_df)
                    sum_df = sum_df[sum_df["AI_CONFIDENCE"] >= int(min_conf)].copy()
                    _hidden = _before - len(sum_df)
                    if _hidden > 0:
                        st.caption(f"Filtered {_hidden} table(s) below {int(min_conf)/100.0:.1f} sensitivity confidence")
        except Exception:
            pass
        if not sum_df.empty:
            # Prefer service-driven fields; hide legacy Agg columns by default
            preferred = [
                "FULL_NAME","SENSITIVITY","AI_CONFIDENCE","ROW_COUNT",
                "C","I","A","LABEL","POLICY_SUGGESTION","REQUIRES_REVIEW","REASONING",
            ]
            display_cols = [c for c in preferred if c in sum_df.columns]
            def _style_row(row):
                try:
                    c_val = int(row.get('C') or 0)
                    if c_val >= 3:
                        bg = '#7f1d1d'  # high risk
                    elif c_val == 2:
                        bg = '#a16207'  # medium risk (amber)
                    else:
                        bg = '#065f46'  # low risk
                    fg = '#000000'
                    style = f'background-color: {bg}; color: {fg};'
                    return [style for _ in row]
                except Exception:
                    return ['' for _ in row]

            st.markdown("##### Sensitive Tables — AI Suggestions")
            # Compute and display Actual Row Count for each sensitive table (auto)
            st.session_state.setdefault("ai_actual_counts", {})
            try:
                names = sum_df["FULL_NAME"].tolist()
                def _valid_db_from_fqn(_f: str) -> bool:
                    try:
                        dbtok = str((_f or '').split('.')[0]).strip().upper()
                        return dbtok and dbtok not in {"NONE","(NONE)","NULL","UNKNOWN"}
                    except Exception:
                        return False
                names = [n for n in names if _valid_db_from_fqn(n)]
                new_counts = {}
                for fqn in names:
                    if fqn in st.session_state["ai_actual_counts"]:
                        continue
                    try:
                        rs = snowflake_connector.execute_query(f"select count(*) as CNT from {fqn}") or []
                        cnt = int((rs[0] or {}).get("CNT", 0)) if rs else 0
                        new_counts[fqn] = cnt
                    except Exception:
                        new_counts[fqn] = None
                if new_counts:
                    st.session_state["ai_actual_counts"].update(new_counts)
                sum_df = sum_df.copy()
                sum_df["Actual Row Count"] = sum_df["FULL_NAME"].map(lambda n: st.session_state["ai_actual_counts"].get(n))
                # Ensure only Actual Row Count is shown (no metadata ROW_COUNT)
                if "ROW_COUNT" in display_cols:
                    display_cols = [c for c in display_cols if c != "ROW_COUNT"]
                if "Actual Row Count" not in display_cols:
                    display_cols.insert(2, "Actual Row Count")
            except Exception:
                pass
            st.dataframe(
                sum_df[display_cols]
                    .style
                    .apply(_style_row, axis=1)
                    .set_properties(**{"color": "#000000"})
                    .set_table_styles([
                        {"selector": "th", "props": "color: #000000;"},
                        {"selector": "td", "props": "color: #000000;"},
                    ])
                    .hide(axis="index"),
                width='stretch',
            )
            try:
                names = sum_df["FULL_NAME"].dropna().astype(str).tolist()
                if names:
                    sel = st.selectbox("Select a sensitive table for drilldown", options=names, key="ai_drill_table")
                    if sel:
                        cls = ai_classification_service.classify_and_persist(sel, sample_size=300) if ai_classification_service else {}
                        if cls.get('features', {}).get('method') == 'SEMANTIC_FALLBACK':
                            st.info("Semantic classification was used as fallback due to low CTE confidence.")
                        cols = ((cls.get("features") or {}).get("column_detections") or [])
                        if cols:
                            import pandas as _pdx
                            cdf = _pdx.DataFrame([
                                {
                                    "Column Name": r.get("column_name"),
                                    "Detected Category": r.get("sensitive_type"),
                                    "Confidence": float(int(r.get("confidence_score", 0)))/100.0,
                                    "CIA": f"{int((r.get('CIA (C/I/A)') or {}).get('C',0))},{int((r.get('CIA (C/I/A)') or {}).get('I',0))},{int((r.get('CIA (C/I/A)') or {}).get('A',0))}",
                                    "Recommended Policies": r.get("policy_suggestion"),
                                    "Review Flag": "Yes" if int(r.get("confidence_score",0)) < 75 else "No",
                                }
                                for r in cols
                            ])
                            try:
                                # Apply any existing approved column-level overrides from session state
                                _over = (st.session_state.get("ai_column_overrides", {}) or {}).get(sel)
                                if _over:
                                    _omap = {str(o.get("column")): o for o in _over}
                                    def _apply_override_row(row):
                                        oc = _omap.get(str(row["Column Name"]))
                                        if not oc:
                                            return row
                                        row["Detected Category"] = oc.get("dominant_category") or row.get("Detected Category")
                                        row["Confidence"] = float(int(oc.get("confidence", 0)))/100.0
                                        row["CIA"] = f"{int((oc.get('suggested_cia') or {}).get('C',0))},{int((oc.get('suggested_cia') or {}).get('I',0))},{int((oc.get('suggested_cia') or {}).get('A',0))}"
                                        return row
                                    cdf = cdf.apply(_apply_override_row, axis=1)
                            except Exception:
                                pass
                            try:
                                ups = [str(u).upper() for u in cdf["Column Name"].tolist()]
                                present = set(ups)
                                def _has_any(tokens):
                                    for u in present:
                                        for t in tokens:
                                            if t in u:
                                                return True
                                    return False
                                def _first_any(tokens):
                                    for u in present:
                                        for t in tokens:
                                            if t in u:
                                                return u
                                    return None
                                bundles = {}
                                if _has_any(["FIRST_NAME","GIVEN_NAME","FNAME"]) and _has_any(["LAST_NAME","SURNAME","LNAME"]) and _has_any(["DOB","DATE_OF_BIRTH","BIRTH","BIRTHDATE"]):
                                    a = _first_any(["FIRST_NAME","GIVEN_NAME","FNAME"]); b = _first_any(["LAST_NAME","SURNAME","LNAME"]); c = _first_any(["DOB","DATE_OF_BIRTH","BIRTH","BIRTHDATE"])
                                    for x in [a,b,c]:
                                        if x:
                                            bundles.setdefault(x, []).append("Identity")
                                if (_has_any(["CARD","CARD_NO","PAN"]) and (_has_any(["EXP","EXPIRY","EXPIRE","MMYY","MM_YY"]) or _has_any(["CVV","CVC"]))):
                                    a = _first_any(["CARD","CARD_NO","PAN"]); b = _first_any(["EXP","EXPIRY","EXPIRE","MMYY","MM_YY"]); c = _first_any(["CVV","CVC"]) or b
                                    for x in [a,b,c]:
                                        if x:
                                            bundles.setdefault(x, []).append("Payment")
                                if _has_any(["ACCOUNT","ACCT"]) and _has_any(["ROUTING","SWIFT","IFSC","SORT_CODE"]):
                                    a = _first_any(["ACCOUNT","ACCT"]); b = _first_any(["ROUTING","SWIFT","IFSC","SORT_CODE"])
                                    for x in [a,b]:
                                        if x:
                                            bundles.setdefault(x, []).append("Payment")
                                if _has_any(["ADDRESS","ADDR","STREET"]) and (_has_any(["CITY"]) or _has_any(["STATE","PROVINCE"]) or _has_any(["ZIP","POSTAL"])):
                                    a = _first_any(["ADDRESS","ADDR","STREET"]); b = _first_any(["CITY"]) or _first_any(["STATE","PROVINCE"]) or _first_any(["ZIP","POSTAL"]) 
                                    for x in [a,b]:
                                        if x:
                                            bundles.setdefault(x, []).append("Address")
                                def _bundle_for(name):
                                    u = str(name).upper()
                                    return ", ".join(sorted(set(bundles.get(u, [])))) if u in bundles else ""
                                cdf["Bundle"] = cdf["Column Name"].map(_bundle_for)
                            except Exception:
                                pass
                            try:
                                # Split CIA into C/I/A numeric fields for editing
                                def _parse_cia(s: str):
                                    try:
                                        parts = [int(p.strip()) for p in str(s or "0,0,0").split(",")[:3]]
                                        while len(parts) < 3:
                                            parts.append(0)
                                        return parts[0], parts[1], parts[2]
                                    except Exception:
                                        return 0, 0, 0
                                cdf[["C","I","A"]] = cdf["CIA"].apply(lambda x: _parse_cia(x)).apply(_pdx.Series)
                                editable_cols = [
                                    "Column Name","Detected Category","Confidence","C","I","A","Recommended Policies","Review Flag","Bundle"
                                ]
                                # Ensure confidence stays within 0..1 in the editor
                                cdf["Confidence"] = cdf["Confidence"].clip(lower=0.0, upper=1.0)
                                st.markdown("###### Review and edit column classifications")
                                edited = st.data_editor(
                                    cdf[editable_cols],
                                    width='stretch',
                                    key=f"ai_edit_drill_{sel}",
                                )
                                if st.button(f"Approve and Apply for {sel}", type="primary", key=f"ai_approve_{sel}"):
                                    try:
                                        # Build column_rows payload expected by persist_scan_results
                                        col_rows = []
                                        for _, rr in edited.iterrows():
                                            dom = str(rr.get("Detected Category") or "")
                                            conf_pct = int(round(float(rr.get("Confidence") or 0.0) * 100))
                                            c_val = int(rr.get("C") or 0)
                                            i_val = int(rr.get("I") or 0)
                                            a_val = int(rr.get("A") or 0)
                                            dom_up = str(dom).upper()
                                            try:
                                                if "PII" in dom_up:
                                                    c_val = max(c_val, 2)
                                                if ("PHI" in dom_up) or ("SSN" in dom_up) or ("HEALTH" in dom_up) or ("HIPAA" in dom_up):
                                                    c_val = 3
                                                if ("FINANCIAL" in dom_up) or ("SOX" in dom_up) or ("REGULATORY" in dom_up) or ("GDPR" in dom_up) or ("CCPA" in dom_up):
                                                    c_val = 3
                                            except Exception:
                                                pass
                                            col_rows.append({
                                                "column": rr.get("Column Name"),
                                                "dominant_category": dom,
                                                "categories": [dom] if dom else [],
                                                "confidence": conf_pct,
                                                "suggested_cia": {"C": c_val, "I": i_val, "A": a_val},
                                                "regex_hits": [],
                                                "token_hits": [],
                                            })
                                        # Simple table metrics aggregation
                                        try:
                                            avg_conf = float(sum(int(r.get("confidence",0)) for r in col_rows)) / max(1, len(col_rows))
                                        except Exception:
                                            avg_conf = 0.0
                                        dom_tbl = None
                                        try:
                                            cats = [r.get("dominant_category") for r in col_rows if r.get("dominant_category")]
                                            freq = {}
                                            for c in cats:
                                                freq[c] = freq.get(c, 0) + 1
                                            dom_tbl = max(freq, key=freq.get) if freq else None
                                        except Exception:
                                            dom_tbl = None
                                        table_metrics = {
                                            "table_sensitivity_score": round(float(avg_conf)/100.0, 2),
                                            "dominant_table_category": dom_tbl,
                                            "table_categories": list({r.get("dominant_category") for r in col_rows if r.get("dominant_category")} ),
                                            "sensitive_columns_count": len([r for r in col_rows if r.get("dominant_category")]),
                                        }
                                        # Persist and refresh
                                        try:
                                            # Stash approved edits in session for immediate refresh-friendly view
                                            st.session_state.setdefault("ai_column_overrides", {})[sel] = col_rows
                                            ai_classification_service.persist_scan_results(sel, col_rows, table_metrics)
                                        except Exception:
                                            pass
                                        st.success("Classification approved and applied. Refreshing results...")
                                        # Removed st.rerun() to prevent no-op warning
                                    except Exception:
                                        st.warning("Failed to apply updated classifications.")  
                            except Exception:
                                # Fallback read-only view
                                show_cols = ["Column Name","Detected Category","Confidence","CIA","Recommended Policies","Review Flag","Bundle"]
                                st.dataframe(cdf[show_cols], width='stretch')
            except Exception:
                pass
        else:
            st.caption("No sensitive tables found for the selected scope.")
        # (AI Assist drilldown UI removed)

    # Bulk Upload
    with sub_bulk:
        st.markdown("#### Bulk Classification Tool")
        up = st.file_uploader("Upload CSV/XLSX template", type=["csv","xlsx"], key="nc_bulk_upl")
        if up is not None:
            import pandas as _pd
            try:
                if up.name.lower().endswith('.csv'):
                    bdf = _pd.read_csv(up)
                else:
                    bdf = _pd.read_excel(up)
            except Exception as e:
                st.error(f"Bulk parse failed: {e}")
                bdf = _pd.DataFrame()

            if not bdf.empty:
                cols_up = {c.strip().upper(): c for c in bdf.columns}
                if "FULL_NAME" not in cols_up:
                    def _is_fqn(val: str) -> bool:
                        try:
                            s = str(val or "").strip()
                            parts = s.split('.')
                            if len(parts) != 3:
                                return False
                            for p in parts:
                                if not p:
                                    return False
                                pp = p.replace('_', '')
                                if not pp.isalnum():
                                    return False
                            return True
                        except Exception:
                            return False
                    best_col = None; best_score = 0.0
                    for c in list(bdf.columns):
                        try:
                            series = bdf[c].dropna().astype(str)
                            n = int(len(series))
                            if n == 0:
                                continue
                            hits = sum(1 for v in series.head(min(2000, n)) if _is_fqn(v))
                            score = float(hits) / float(min(2000, n))
                            if score > best_score:
                                best_score = score; best_col = c
                        except Exception:
                            continue
                    if best_col and best_score >= 0.60:
                        cols_up["FULL_NAME"] = best_col
                    else:
                        header_hints = ["ASSET_FULL_NAME","ASSET","DATASET","TABLE","OBJECT","FULL NAME","FULL-NAME"]
                        for h in header_hints:
                            if h in cols_up:
                                cols_up["FULL_NAME"] = cols_up[h]
                                break
                if "FULL_NAME" not in cols_up:
                    st.error("Could not find dataset identifier column (FULL_NAME). Ensure a column with values like DB.SCHEMA.TABLE is present.")
                else:
                    _db_active2 = _active_db_from_filter()
                    _gv2 = st.session_state.get("governance_schema") or "DATA_CLASSIFICATION_GOVERNANCE"
                    @st.cache_data(ttl=30)
                    def _inv_lookup_many(db: str, gv: str, names: List[str]) -> Dict:
                        try:
                            if not names:
                                return {}
                            in_list = ",".join([f"'%(x)s'" for x in range(len(names))])
                        except Exception:
                            pass
                        gf = st.session_state.get('global_filters', {})
                        rows = _inventory_assets(db, gv, gf) or []
                        return {r.get("FULL_NAME"): r for r in rows}

                    inv_map2 = _inv_lookup_many(_db_active2, _gv2, bdf[cols_up["FULL_NAME"]].astype(str).tolist()) if _db_active2 else {}

                    view = []
                    violations = 0
                    for idx, row in bdf.iterrows():
                        full = str(row[cols_up["FULL_NAME"]]).strip()
                        def _is_fqn(val: str) -> bool:
                            try:
                                s = str(val or "").strip()
                                parts = s.split('.')
                                if len(parts) != 3:
                                    return False
                                for p in parts:
                                    if not p:
                                        return False
                                    pp = p.replace('_', '')
                                    if not pp.isalnum():
                                        return False
                                return True
                            except Exception:
                                return False
                        try:
                            c = int(row.get(cols_up.get("C", "C"), row.get("C", -1)))
                        except Exception:
                            c = -1
                        try:
                            i = int(row.get(cols_up.get("I", "I"), row.get("I", -1)))
                        except Exception:
                            i = -1
                        try:
                            a = int(row.get(cols_up.get("A", "A"), row.get("A", -1)))
                        except Exception:
                            a = -1
                        owner_email = None
                        try:
                            em_col = cols_up.get("OWNEREMAIL")
                            if em_col in row:
                                owner_email = str(row[em_col] or "").strip()
                        except Exception:
                            owner_email = None
                        rationale_txt = None
                        try:
                            ra_col = cols_up.get("RATIONALE")
                            if ra_col in row:
                                rationale_txt = str(row[ra_col] or "").strip()
                        except Exception:
                            rationale_txt = None
                        inv = inv_map2.get(full) or {}
                        det_types = []
                        try:
                            dets = ai_classification_service.detect_sensitive_columns(full)
                            det_types = sorted({t for d in (dets or []) for t in (d.get('categories') or [])})
                            det_types = ["SOX" if str(t).upper() == "FINANCIAL" else t for t in det_types]
                        except Exception:
                            det_types = []
                        auto_label = None
                        try:
                            cls = ai_classification_service.classify_sensitive(full)
                            tinfo = (cls or {}).get("table") or {}
                            cia_auto = tinfo.get("cia") or {}
                            if c < 0 or i < 0 or a < 0:
                                try:
                                    c = int(cia_auto.get("C", 0)); i = int(cia_auto.get("I", 0)); a = int(cia_auto.get("A", 0))
                                except Exception:
                                    c = 0; i = 0; a = 0
                            auto_label = tinfo.get("overall_classification_label") or None
                        except Exception:
                            auto_label = None
                        compliance = []
                        try:
                            _ctx = None
                            try:
                                _ctx = ai_classification_service.build_enriched_context(full, sample_rows=10)
                            except Exception:
                                _ctx = None
                            ct = ai_classification_service.classify_table(full, context=_ctx)
                            compliance = list(ct.get("compliance_frameworks") or [])
                        except Exception:
                            compliance = []
                        try:
                            det_up = [str(x).upper() for x in (det_types or [])]
                            comp_up = [str(x).upper() for x in (compliance or [])]
                            if ("PII" in det_up):
                                c = max(c, 2)
                            if ("PHI" in det_up) or ("HIPAA" in comp_up):
                                c = 3
                            if ("SOX" in det_up) or ("FINANCIAL" in det_up) or ("SOX" in comp_up) or ("PCI" in comp_up):
                                c = 3
                            if ("REGULATORY" in det_up) or ("GDPR" in comp_up) or ("CCPA" in comp_up):
                                c = 3
                            c = max(0, min(3, int(c)))
                        except Exception:
                            pass
                        try:
                            label = auto_label or ["Public","Internal","Restricted","Confidential"][max(0, min(max(c,i,a), 3))]
                        except Exception:
                            label = auto_label or "Internal"
                        try:
                            _sf_audit_log_classification(full, "BULK_AUTO_DETECTED", {
                                "auto_label": label,
                                "c": c, "i": i, "a": a,
                                "detected_types": det_types,
                                "compliance": compliance
                            })
                        except Exception:
                            pass
                        ok_dm3, reasons3 = (False, ["Invalid CIA"]) if (c < 0 or i < 0 or a < 0 or c>3 or i>3 or a>3) else dm_validate(label, c, i, a)
                        pre_issues = []
                        try:
                            if not _is_fqn(full):
                                pre_issues.append("Invalid FULL_NAME path")
                        except Exception:
                            pre_issues.append("Invalid FULL_NAME path")
                        try:
                            if owner_email:
                                ok_email = owner_email.lower().endswith("@avendra.com")
                                if not ok_email:
                                    pre_issues.append("OwnerEmail must be @avendra.com")
                        except Exception:
                            pass
                        try:
                            if rationale_txt is not None:
                                if len(rationale_txt) < 50:
                                    pre_issues.append("Rationale too short (<50 chars)")
                        except Exception:
                            pass
                        pre_ok = (len(pre_issues) == 0)
                        issue = None
                        if not ok_dm3:
                            violations += 1
                            issue = "; ".join([str(r) for r in (reasons3 or [])])
                        view.append({
                            "FULL_NAME": full,
                            "C": c, "I": i, "A": a,
                            "LABEL": label,
                            "ASSET_TYPE": inv.get("ASSET_TYPE"),
                            "DATA_DOMAIN": inv.get("DATA_DOMAIN"),
                            "OWNER": inv.get("OWNER"),
                            "SENSITIVE_TYPES": ", ".join(det_types),
                            "COMPLIANCE": ", ".join(compliance) if compliance else None,
                            "OWNEREMAIL": owner_email,
                            "RATIONALE": rationale_txt,
                            "PRE_VALIDATION_OK": pre_ok,
                            "PRE_ISSUE": "; ".join(pre_issues) if pre_issues else None,
                            "POLICY_OK": ok_dm3,
                            "ISSUE": issue,
                        })
                    vdf = _pd.DataFrame(view)
                    st.dataframe(vdf, width='stretch')
                    try:
                        df_failed = vdf[vdf["PRE_VALIDATION_OK"] == False] if "PRE_VALIDATION_OK" in vdf.columns else _pd.DataFrame()
                        df_manual = vdf[(vdf.get("PRE_VALIDATION_OK", True)) & (vdf.get("POLICY_OK", False) == False)] if not vdf.empty else _pd.DataFrame()
                        df_success = vdf[(vdf.get("PRE_VALIDATION_OK", True)) & (vdf.get("POLICY_OK", False) == True)] if not vdf.empty else _pd.DataFrame()
                    except Exception:
                        df_failed = _pd.DataFrame(); df_manual = _pd.DataFrame(); df_success = _pd.DataFrame()
                    try:
                        if not df_success.empty:
                            st.markdown("##### Successfully validated")
                            st.dataframe(df_success, use_container_width=True)
                            st.download_button("Download Success Report", df_success.to_csv(index=False), "bulk_success.csv", "text/csv", key="bulk_succ_dl")
                    except Exception:
                        pass
                    try:
                        if not df_manual.empty:
                            st.markdown("##### Requires manual review")
                            st.dataframe(df_manual, use_container_width=True)
                            st.download_button("Download Manual Review Report", df_manual.to_csv(index=False), "bulk_manual.csv", "text/csv", key="bulk_man_dl")
                    except Exception:
                        pass
                    try:
                        if not df_failed.empty:
                            st.markdown("##### Failed validations")
                            st.dataframe(df_failed, use_container_width=True)
                            st.download_button("Download Failed Report", df_failed.to_csv(index=False), "bulk_failed.csv", "text/csv", key="bulk_fail_dl")
                    except Exception:
                        pass

                    can_submit = (not df_success.empty and df_manual.empty and df_failed.empty and violations == 0 and (len(df_success) == len(vdf)))
                    st.caption("All rows must pass validation and policy checks before submission.")
                    if not can_submit:
                        st.warning("Fix policy violations or invalid CIA values in the upload before submitting.")

                    if st.button("Submit Batch", type="primary", disabled=not can_submit, key="bulk_submit_btn"):
                        success = 0; failed = 0
                        apply_df = df_success if not df_success.empty else vdf
                        for _, r in apply_df.iterrows():
                            full = r.get("FULL_NAME")
                            c = int(r.get("C") or 0); i = int(r.get("I") or 0); a = int(r.get("A") or 0)
                            label = str(r.get("LABEL") or "Internal")
                            try:
                                _sf_apply_tags(full, {
                                    "data_classification": label,
                                    "confidentiality_level": f"C{c}",
                                    "integrity_level": f"I{i}",
                                    "availability_level": f"A{a}",
                                })
                                _sf_audit_log_classification(full, "BULK_CLASSIFICATION_APPLIED", {"label": label, "c": c, "i": i, "a": a})
                                try:
                                    dbn = _active_db_from_filter()
                                    if dbn:
                                        snowflake_connector.execute_non_query(
                                            f"""
                                            create schema if not exists {dbn}.DATA_GOVERNANCE;
                                            create table if not exists {dbn}.DATA_GOVERNANCE.NOTIFICATIONS_OUTBOX (
                                              ID string,
                                              CREATED_AT timestamp_ntz default current_timestamp,
                                              CHANNEL string,
                                              TARGET string,
                                              SUBJECT string,
                                              BODY string,
                                              SENT_AT timestamp_ntz,
                                              SENT_RESULT string
                                            );
                                            """
                                        )
                                        to_email = str(r.get("OWNEREMAIL") or "").strip()
                                        if to_email and to_email.lower().endswith("@avendra.com"):
                                            subj = f"Classification applied: {full}"
                                            body = f"Label: {label} | CIA: C{c}/I{i}/A{a}"
                                            snowflake_connector.execute_non_query(
                                                f"""
                                                insert into {dbn}.DATA_GOVERNANCE.NOTIFICATIONS_OUTBOX (ID, CHANNEL, TARGET, SUBJECT, BODY)
                                                select %(id)s, 'EMAIL', %(t)s, %(s)s, %(b)s
                                                """,
                                                {"id": __import__("uuid").uuid4().hex, "t": to_email, "s": subj, "b": body},
                                            )
                                except Exception:
                                    pass
                                success += 1
                            except Exception:
                                failed += 1
                        if failed == 0:
                            st.success(f"Batch applied: {success} assets")
                        else:
                            st.warning(f"Batch completed with errors. Success: {success}, Failed: {failed}")

with tab_tasks:
    st.subheader("Classification Management")
    # Restore earlier sub-tabs
    sub_my, sub_pending, sub_history, sub_reclass = st.tabs([
        "My Tasks", "Pending Reviews", "History", "Reclassification Requests"
    ])

    # My Tasks (Unified)
    with sub_my:
        try:
            ident_tasks = authz.get_current_identity()
            me_user = (ident_tasks.user or "").strip()
        except Exception:
            me_user = str(st.session_state.get("user") or "")
        # Ensure the My Tasks view exists (create or replace to user's spec)
        try:
            db = st.session_state.get('sf_database') or _active_db_from_filter()
            gv = st.session_state.get('governance_schema') or 'DATA_CLASSIFICATION_GOVERNANCE'
            if db:
                snowflake_connector.execute_non_query(
                    f"""
                    create schema if not exists {db}.{gv};
                    create or replace view {db}.{gv}.VW_MY_CLASSIFICATION_TASKS as
                    select
                        TASK_ID,
                        coalesce(DATASET_NAME, split_part(coalesce(ASSET_FULL_NAME, ''), '.', 3)) as DATASET_NAME,
                        ASSET_FULL_NAME,
                        coalesce(ASSIGNED_TO, '') as OWNER,
                        coalesce(STATUS, 'Pending') as STATUS,
                        CONFIDENTIALITY_LEVEL,
                        INTEGRITY_LEVEL,
                        AVAILABILITY_LEVEL,
                        DUE_DATE,
                        CREATED_AT,
                        UPDATED_AT,
                        case 
                            when upper(coalesce(STATUS,'')) like '%PENDING%' then '🟡 Pending Review'
                            when upper(coalesce(STATUS,'')) like '%APPROVED%' then '🟢 Approved'
                            when upper(coalesce(STATUS,'')) like '%REJECTED%' then '🔴 Rejected'
                            when upper(coalesce(STATUS,'')) like '%COMPLETED%' then '✅ Completed'
                            else '⚪ Unknown'
                        end as STATUS_LABEL,
                        DETAILS
                    from {db}.{gv}.CLASSIFICATION_TASKS
                    """
                )
        except Exception:
            pass
        # Filters for My Tasks table
        f1, f2, f3, f4 = st.columns([1,1,1,2])
        with f1:
            status_map = {"All": None, "Draft": "draft", "Pending": "pending", "Completed": "completed"}
            sel_status = st.selectbox("Status", list(status_map.keys()), index=0)
        with f2:
            owner_q = st.text_input("Owner contains", value="")
        with f3:
            sel_level = st.selectbox("Classification Level", ["All","Public","Internal","Restricted","Confidential"], index=0)
        with f4:
            c1, c2 = st.columns(2)
            with c1:
                dr_start = st.date_input("Start", value=None)
            with c2:
                dr_end = st.date_input("End", value=None)

        svc_tasks = my_fetch_tasks(
            current_user=me_user,
            status=status_map.get(sel_status),
            owner=(owner_q or None),
            classification_level=(None if sel_level == "All" else sel_level),
            date_range=((str(dr_start) if dr_start else None), (str(dr_end) if dr_end else None)),
            limit=500,
        ) or []
        import pandas as _pd
        svc_df = _pd.DataFrame(svc_tasks)
        if svc_df.empty:
            # Fallback to Snowflake governance view VW_MY_CLASSIFICATION_TASKS if available
            try:
                db = st.session_state.get('sf_database') or _active_db_from_filter()
                gv = st.session_state.get('governance_schema') or 'DATA_CLASSIFICATION_GOVERNANCE'
                if db:
                    # Build only safe filters; avoid referencing columns that may not exist in the view
                    where = []
                    params = {}
                    if sel_status and sel_status != "All":
                        where.append("upper(STATUS) = upper(%(st)s)"); params["st"] = sel_status
                    # Do NOT push global filters server-side because the column name varies across deployments.
                    # Fetch rows first, then apply client-side filtering via _matches_global().
                    q = f"""
                        SELECT *
                        FROM {db}.{gv}.VW_MY_CLASSIFICATION_TASKS
                        {('WHERE ' + ' AND '.join(where)) if where else ''}
                        ORDER BY COALESCE(DUE_DATE, CURRENT_TIMESTAMP()) ASC
                        LIMIT 500
                    """
                    rows = snowflake_connector.execute_query(q, params) or []
                    svc_df = _pd.DataFrame(rows)
                    # Apply global filters client-side using best-effort matching
                    try:
                        gf = st.session_state.get('global_filters') or {}
                        if gf and not svc_df.empty:
                            svc_df = svc_df[[
                                _matches_global(row._asdict() if hasattr(row, '_asdict') else row.to_dict(), gf)
                                for _, row in svc_df.iterrows()
                            ]]
                    except Exception:
                        pass
            except Exception as e:
                st.caption(f"Tasks view fallback unavailable: {e}")
        # Second fallback: query CLASSIFICATION_TASKS table directly (if present)
        if svc_df.empty:
            try:
                db = st.session_state.get('sf_database') or _active_db_from_filter()
                gv = st.session_state.get('governance_schema') or 'DATA_CLASSIFICATION_GOVERNANCE'
                if db:
                    where = []
                    params = {}
                    # Status filter
                    if sel_status and sel_status != "All":
                        where.append("upper(STATUS) = upper(%(st)s)"); params["st"] = sel_status
                    # Owner filter: use explicit owner substring or default to current user
                    if owner_q:
                        where.append("ASSIGNED_TO ILIKE %(own)s"); params["own"] = f"%{owner_q}%"
                    elif me_user:
                        where.append("upper(ASSIGNED_TO) = upper(%(own_eq)s)"); params["own_eq"] = str(me_user)
                    # Classification level
                    if sel_level and sel_level != "All":
                        where.append("upper(CLASSIFICATION_LEVEL) = upper(%(lev)s)"); params["lev"] = sel_level
                    # Date range on CREATED_DATE
                    if dr_start:
                        where.append("CREATED_DATE >= %(ds)s"); params["ds"] = str(dr_start)
                    if dr_end:
                        where.append("CREATED_DATE <= %(de)s"); params["de"] = str(dr_end)
                    q2 = f"""
                        SELECT *
                        FROM {db}.{gv}.CLASSIFICATION_TASKS
                        {('WHERE ' + ' AND '.join(where)) if where else ''}
                        ORDER BY COALESCE(CREATED_DATE, CURRENT_TIMESTAMP()) DESC
                        LIMIT 500
                    """
                    rows2 = snowflake_connector.execute_query(q2, params) or []
                    svc_df = _pd.DataFrame(rows2)
            except Exception as e:
                st.caption(f"Tasks table fallback unavailable: {e}")
        if svc_df.empty:
            st.info("No tasks found for the selected filters.")
        else:
            # Normalize common column names from view/table variants
            svc_df.rename(columns={
                "asset_name":"Asset Name",
                "ASSET_NAME":"Asset Name",
                "object_type":"Type",
                "OBJECT_TYPE":"Type",
                "due_date":"Due Date",
                "DUE_DATE":"Due Date",
                "priority":"Priority",
                "PRIORITY":"Priority",
                "status":"Status",
                "STATUS":"Status",
                "ASSIGNED_TO":"Owner",
                "CLASSIFICATION_LEVEL":"Classification Level",
                "CREATED_DATE":"Created",
                "TASK_ID":"Task ID",
                "ASSET_ID":"Asset ID",
            }, inplace=True)
            display_cols = [
                c for c in [
                    "Asset Name","Type","Due Date","Priority","Status",
                    "Task ID","Asset ID","Owner","Classification Level","Created"
                ] if c in svc_df.columns
            ]
            if not display_cols:
                display_cols = list(svc_df.columns)
            # Derive CIA and Tag columns where possible
            def _cia_str_from_row(r):
                try:
                    c = r.get("c", r.get("C", 0))
                    i = r.get("i", r.get("I", 0))
                    a = r.get("a", r.get("A", 0))
                    return f"C{int(c)}/I{int(i)}/A{int(a)}"
                except Exception:
                    return None
            def _status_tag(v):
                s = str(v or "").strip().lower()
                if s == "draft":
                    return "Draft"
                if s in ("pending", "awaiting review"):
                    return "Pending"
                return "Assigned"
            def _style_tag(val):
                v = str(val)
                color = "#9ca3af" if v == "Draft" else ("#f59e0b" if v == "Pending" else "#3b82f6")
                return f"color: {color}; font-weight: 700;"
            def _derive_deadline_status_due(due_val):
                try:
                    if pd.isna(due_val):
                        return None
                    due_d = pd.to_datetime(due_val).date()
                    rem = _business_days_between(date.today(), due_d)
                    if rem <= 0:
                        return "Overdue"
                    if rem <= 5:
                        return "Due Soon"
                    return "On Track"
                except Exception:
                    return None
            def _style_deadline(val):
                v = str(val or "")
                color = "#ef4444" if v == "Overdue" else ("#f59e0b" if v == "Due Soon" else ("#10b981" if v == "On Track" else "#6b7280"))
                return f"color: {color}; font-weight: 700;"
            def _derive_policy_compliance(row):
                try:
                    for k in ["policy_compliance","POLICY_COMPLIANCE","Policy Compliance"]:
                        if k in row.index:
                            v = row.get(k)
                            if v is None or (isinstance(v, float) and pd.isna(v)):
                                continue
                            b = bool(v) if not isinstance(v, str) else (v.strip().lower() in ("true","1","yes","y","compliant"))
                            return "Compliant" if b else "Violation"
                except Exception:
                    pass
                return None
            def _style_compliance(val):
                v = str(val or "")
                color = "#10b981" if v == "Compliant" else ("#ef4444" if v == "Violation" else "#6b7280")
                return f"color: {color}; font-weight: 700;"

            disp = svc_df.copy()
            # CIA
            try:
                cia_series = disp.apply(lambda r: _cia_str_from_row(r), axis=1)
                if cia_series.notna().any():
                    disp["CIA"] = cia_series
            except Exception:
                pass
            # Tag from Status
            if "Status" in disp.columns:
                try:
                    disp["Tag"] = disp["Status"].apply(_status_tag)
                except Exception:
                    pass

            # Deadline Status (derived from Due Date when available)
            if "Due Date" in disp.columns:
                try:
                    disp["Deadline Status"] = disp["Due Date"].apply(_derive_deadline_status_due)
                except Exception:
                    pass
            # Policy Compliance (best-effort from available columns)
            try:
                pc_series = disp.apply(lambda r: _derive_policy_compliance(r), axis=1)
                if pc_series.notna().any():
                    disp["Policy Compliance"] = pc_series
            except Exception:
                pass

            # Sorting controls
            import pandas as _pd
            sort_opts = ["Due Date (asc)"]
            if "overall_risk" in disp.columns:
                sort_opts.append("Risk (High→Low)")
            if "Priority" in disp.columns:
                sort_opts.append("Priority")
            sort_by = st.selectbox("Sort by", options=sort_opts, index=0, key="mt_sort_mytasks")
            if sort_by.startswith("Risk") and "overall_risk" in disp.columns:
                risk_order = _pd.Categorical(disp["overall_risk"], categories=["High","Medium","Low"], ordered=True)
                disp = disp.assign(_risk=risk_order)
                if "Due Date" in disp.columns:
                    disp = disp.sort_values(["_risk","Due Date"])  # tie-breaker by due
                else:
                    disp = disp.sort_values(["_risk"]) 
                disp.drop(columns=["_risk"], inplace=True, errors='ignore')
            elif sort_by == "Priority" and "Priority" in disp.columns:
                pri_order = _pd.Categorical(disp["Priority"], categories=["High","Medium","Low"], ordered=True)
                disp = disp.assign(_pri=pri_order)
                if "Due Date" in disp.columns:
                    disp = disp.sort_values(["_pri","Due Date"]) 
                else:
                    disp = disp.sort_values(["_pri"]) 
                disp.drop(columns=["_pri"], inplace=True, errors='ignore')
            elif "Due Date" in disp.columns:
                disp = disp.sort_values("Due Date")

            # Choose final columns, including CIA and Tag if present
            final_cols = [c for c in [
                "Asset Name","Type","CIA","Due Date","Deadline Status","Priority","Status","Tag","Policy Compliance",
                "Task ID","Asset ID","Owner","Classification Level","Created"
            ] if c in disp.columns]
            if not final_cols:
                final_cols = display_cols
            st.dataframe(
                disp[final_cols]
                .style
                .map(_style_tag, subset=[c for c in ["Tag"] if c in disp.columns])
                .map(_style_deadline, subset=[c for c in ["Deadline Status"] if c in disp.columns])
                .map(_style_compliance, subset=[c for c in ["Policy Compliance"] if c in disp.columns])
                .hide(axis="index"),
                width='stretch',
            )

            # Click-to-open wizard
            # Prefer full name when available
            select_col = None
            for copt in ["ASSET_FULL_NAME","asset_full_name","Asset Name","asset_name"]:
                if copt in svc_df.columns:
                    select_col = copt
                    break
            options = disp[select_col].astype(str).unique().tolist() if select_col and select_col in disp.columns else []
            sel_asset = st.selectbox("Select an asset", options=options, key="mt_sel_asset_mytasks")
            if st.button("Open Classification Wizard", type="primary", key="mt_open_mytasks") and sel_asset:
                st.session_state["task_wizard_asset"] = sel_asset
                try:
                    st.experimental_set_query_params(sub="tasks", action="classify", asset=sel_asset)
                except Exception:
                    pass
                # Removed st.rerun() to prevent no-op warning
    # Pending Reviews (using VW_CLASSIFICATION_REVIEWS if available)
    with sub_pending:
        st.markdown("#### Pending Reviews")
        db = st.session_state.get('sf_database') or _active_db_from_filter()
        gv = st.session_state.get('governance_schema') or 'DATA_CLASSIFICATION_GOVERNANCE'
        fc1, fc2, fc3, fc4 = st.columns([1.2, 1.2, 1, 1])
        with fc1:
            reviewer_filter = st.text_input("Reviewer name/email", key="pr_reviewer2")
        with fc2:
            level_filter = st.selectbox("Classification level", options=["All", "Public", "Internal", "Restricted", "Confidential"], index=0, key="pr_level2")
        with fc3:
            status_filter = st.multiselect("Status", options=["Pending", "Approved", "Rejected", "Changes Requested"], default=["Pending"], key="pr_status2")
        with fc4:
            lookback = st.slider("Lookback (days)", min_value=7, max_value=120, value=30, step=1, key="pr_lookback2")

        df = pd.DataFrame()
        if db:
            # First attempt: use the view if it exists
            try:
                q = f"""
                    SELECT *
                    FROM {db}.{gv}.VW_CLASSIFICATION_REVIEWS
                    LIMIT 500
                """
                rows = snowflake_connector.execute_query(q) or []
                df = pd.DataFrame(rows)
            except Exception as e:
                st.caption(f"Review view unavailable: {e}")
            # Second attempt: try CLASSIFICATION_REVIEW with filters
            if df.empty:
                try:
                    where = []
                    params = {}
                    if reviewer_filter:
                        where.append("(REVIEWER ILIKE %(rev)s OR CREATED_BY ILIKE %(rev)s)"); params["rev"] = f"%{reviewer_filter}%"
                    if level_filter and level_filter != "All":
                        where.append("upper(coalesce(PROPOSED_CLASSIFICATION,'')) = upper(%(lev)s)"); params["lev"] = level_filter
                    if status_filter:
                        where.append("upper(STATUS) IN (" + ",".join([f"upper(%(st{i})s)" for i,_ in enumerate(status_filter)]) + ")")
                        for i, s in enumerate(status_filter):
                            params[f"st{i}"] = s
                    if lookback:
                        where.append("COALESCE(DATEDIFF(day, CREATED_AT, CURRENT_TIMESTAMP), 0) <= %(lb)s"); params["lb"] = int(lookback)
                    # Ensure the review table exists (best-effort)
                    try:
                        snowflake_connector.execute_non_query(f"create schema if not exists {db}.{gv}")
                    except Exception:
                        pass
                    try:
                        snowflake_connector.execute_non_query(
                            f"""
                            create table if not exists {db}.{gv}.CLASSIFICATION_REVIEW (
                                REVIEW_ID string default uuid_string(),
                                ASSET_FULL_NAME string,
                                PROPOSED_CLASSIFICATION string,
                                PROPOSED_C number,
                                PROPOSED_I number,
                                PROPOSED_A number,
                                REVIEWER string,
                                STATUS string,
                                CREATED_BY string,
                                CREATED_AT timestamp_tz default current_timestamp(),
                                UPDATED_AT timestamp_tz,
                                REVIEW_DUE_DATE timestamp_tz,
                                LAST_COMMENT string,
                                RISK_SCORE number(38,2),
                                primary key (REVIEW_ID)
                            )
                            """
                        )
                    except Exception:
                        pass
                    q_mid = f"""
                        SELECT 
                            CR.REVIEW_ID,
                            CR.ASSET_FULL_NAME,
                            CR.PROPOSED_CLASSIFICATION,
                            CR.PROPOSED_C,
                            CR.PROPOSED_I,
                            CR.PROPOSED_A,
                            CR.REVIEWER,
                            CR.STATUS,
                            CR.CREATED_BY,
                            CR.CREATED_AT,
                            CR.UPDATED_AT,
                            CR.REVIEW_DUE_DATE,
                            CR.LAST_COMMENT,
                            CR.RISK_SCORE
                        FROM {db}.{gv}.CLASSIFICATION_REVIEW CR
                        {('WHERE ' + ' AND '.join(where)) if where else ''}
                        ORDER BY COALESCE(CR.REVIEW_DUE_DATE, CR.CREATED_AT, CURRENT_TIMESTAMP()) ASC
                        LIMIT 500
                    """
                    rows_mid = snowflake_connector.execute_query(q_mid, params) or []
                    df = pd.DataFrame(rows_mid)
                except Exception as e:
                    st.caption(f"Classification review table unavailable: {e}")
            # Third attempt: RECLASSIFICATION_REQUESTS with broader default status
            if df.empty:
                try:
                    where = ["upper(coalesce(STATUS,'')) IN ('SUBMITTED','PENDING')"]
                    params = {}
                    if reviewer_filter:
                        where.append("(CREATED_BY ILIKE %(rev)s)"); params["rev"] = f"%{reviewer_filter}%"
                    if level_filter and level_filter != "All":
                        where.append("upper(coalesce(PROPOSED_CLASSIFICATION,'')) = upper(%(lev)s)"); params["lev"] = level_filter
                    if status_filter:
                        where.append("upper(STATUS) IN (" + ",".join([f"upper(%(st{i})s)" for i,_ in enumerate(status_filter)]) + ")")
                        for i, s in enumerate(status_filter):
                            params[f"st{i}"] = s
                    if lookback:
                        where.append("COALESCE(DATEDIFF(day, CREATED_AT, CURRENT_TIMESTAMP), 0) <= %(lb)s"); params["lb"] = int(lookback)
                    q2 = f"""
                        SELECT 
                            ID as REVIEW_ID,
                            ASSET_FULL_NAME,
                            REQUESTED_LABEL as PROPOSED_CLASSIFICATION,
                            NULL as PROPOSED_C,
                            NULL as PROPOSED_I,
                            NULL as PROPOSED_A,
                            NULL as REVIEWER,
                            STATUS,
                            REQUESTED_BY as CREATED_BY,
                            CREATED_AT,
                            UPDATED_AT,
                            NULL as REVIEW_DUE_DATE,
                            NULL as LAST_COMMENT,
                            NULL as RISK_SCORE
                        FROM {db}.{gv}.RECLASSIFICATION_REQUESTS
                        {('WHERE ' + ' AND '.join(where)) if where else ''}
                        ORDER BY COALESCE(CREATED_AT, CURRENT_TIMESTAMP()) ASC
                        LIMIT 500
                    """
                    rows2 = snowflake_connector.execute_query(q2, params) or []
                    df = pd.DataFrame(rows2)
                except Exception as e:
                    st.caption(f"Reviews table fallback unavailable: {e}")
        if df.empty:
            st.info("No pending reviews for the selected filters.")
        else:
            # Normalize expected columns
            df.rename(columns={
                "ASSET_FULL_NAME":"asset_name",
                "DATABASE":"database",
                "SCHEMA":"schema",
                "CURRENT_CLASSIFICATION":"current_classification",
                "PROPOSED_CLASSIFICATION":"proposed_classification",
                "PROPOSED_C":"c_level",
                "PROPOSED_I":"i_level",
                "PROPOSED_A":"a_level",
                "REVIEWER":"reviewer",
                "CREATED_AT":"submission_date",
                "UPDATED_AT":"last_update",
                "LAST_COMMENT":"last_comment",
                "REVIEW_DUE_DATE":"review_due_date",
                "REVIEW_TYPE":"review_type",
                "RISK_SCORE":"risk_score",
                "STATUS":"status",
                "CREATED_BY":"created_by",
                "REVIEW_ID":"review_id",
                "ID":"review_id",
            }, inplace=True)

            # Filters: review type, asset type, risk (by c_level)
            fc5, fc6, fc7 = st.columns([1.2, 1.2, 1])
            with fc5:
                rev_type = st.selectbox("Review Type", options=["All","Peer","Management","Technical"], index=0, key="pr_type2")
            with fc6:
                risk_sel = st.selectbox("Risk level (by C)", options=["All","C0-1","C2","C3"], index=0, key="pr_risk2")
            with fc7:
                asset_type = st.text_input("Asset type contains", value="", key="pr_asset_type2")

            view = df.copy()
            if rev_type != "All" and "review_type" in view.columns:
                view = view[view["review_type"].astype(str).str.upper() == rev_type.upper()]
            if risk_sel != "All" and "c_level" in view.columns:
                try:
                    cvals = view["c_level"].fillna(0).astype(int)
                    if risk_sel == "C0-1":
                        view = view[cvals <= 1]
                    elif risk_sel == "C2":
                        view = view[cvals == 2]
                    elif risk_sel == "C3":
                        view = view[cvals >= 3]
                except Exception:
                    pass
            if asset_type and "asset_name" in view.columns:
                view = view[view["asset_name"].astype(str).str.contains(asset_type, case=False, na=False)]

            # Derive CIA string and Tag
            try:
                if all(c in view.columns for c in ["c_level","i_level","a_level"]):
                    view["CIA"] = view.apply(lambda r: f"C{int(r['c_level'] or 0)}/I{int(r['i_level'] or 0)}/A{int(r['a_level'] or 0)}", axis=1)
            except Exception:
                pass

            def _status_tag(v: str) -> str:
                s = str(v or "").strip().lower()
                if "approved" in s:
                    return "Approved"
                if "reject" in s:
                    return "Rejected"
                return "Pending Review"

            def _style_status(val: str) -> str:
                v = str(val)
                return "color:#10b981;font-weight:700;" if v == "Approved" else ("color:#ef4444;font-weight:700;" if v == "Rejected" else "color:#3b82f6;font-weight:700;")

            view["Tag"] = view.get("status", "").apply(_status_tag)

            # Columns to display per spec
            disp_cols = [c for c in [
                "asset_name","database","schema","current_classification","proposed_classification","reviewer","submission_date","last_comment","review_due_date","review_type","risk_score","CIA","Tag"
            ] if c in view.columns]
            if not disp_cols:
                disp_cols = list(view.columns)
            st.dataframe(view[disp_cols].style.map(_style_status, subset=[c for c in ["Tag"] if c in view.columns]).hide(axis="index"), width='stretch')

            # Actions: Approve / Request Changes / Reject
            sel_id_col = "review_id" if "review_id" in view.columns else None
            sel_asset_col = "asset_name" if "asset_name" in view.columns else None
            options = view[sel_id_col].astype(str).tolist() if sel_id_col else []
            sel_review = st.selectbox("Select review", options=options, key="pr_sel_id2")
            comment = st.text_input("Comments (for audit)", key="pr_note2")
            # Derive details for approve
            row = view[view[sel_id_col].astype(str) == sel_review].iloc[0] if (sel_id_col and sel_review) else None
            asset_full = (row.get(sel_asset_col) if row is not None else "") or ""
            lbl = str(row.get("proposed_classification") or row.get("current_classification") or "Internal") if row is not None else "Internal"
            cval = int(row.get("c_level") or 0) if row is not None else 0
            ival = int(row.get("i_level") or 0) if row is not None else 0
            aval = int(row.get("a_level") or 0) if row is not None else 0

            c1, c2, c3 = st.columns(3)
            with c1:
                if st.button("Approve", type="primary", key="pr_btn_approve2") and sel_review and asset_full:
                    try:
                        ok = review_actions.approve_review(str(sel_review), str(asset_full), lbl, cval, ival, aval, comments=comment)
                        if ok:
                            st.success("Approved."); st.cache_data.clear()
                        else:
                            st.warning("Approve failed.")
                    except Exception as e:
                        st.error(f"Approve failed: {e}")
            with c2:
                if st.button("Request Changes", key="pr_btn_changes2") and sel_review and asset_full:
                    try:
                        ok = review_actions.request_changes(str(sel_review), str(asset_full), instructions=comment)
                        if ok:
                            st.success("Changes requested."); st.cache_data.clear()
                        else:
                            st.warning("Request changes failed.")
                    except Exception as e:
                        st.error(f"Request changes failed: {e}")
            with c3:
                if st.button("Reject/Escalate", key="pr_btn_reject2") and sel_review and asset_full:
                    try:
                        ok = review_actions.reject_review(str(sel_review), str(asset_full), justification=comment)
                        if ok:
                            st.success("Rejected/Escalated."); st.cache_data.clear()
                        else:
                            st.warning("Reject failed.")
                    except Exception as e:
                        st.error(f"Reject failed: {e}")

    # History (placeholder)
    with sub_history:
        st.markdown("#### Classification History & Audit")
        db = st.session_state.get('sf_database') or _active_db_from_filter()
        gv = st.session_state.get('governance_schema') or 'DATA_CLASSIFICATION_GOVERNANCE'
        h1, h2 = st.columns([1.5, 1])
        with h1:
            st.caption("Source: CLASSIFICATION_HISTORY (automatic)")
        with h2:
            days = st.slider("Lookback (days)", 7, 180, 30)
        # Ensure required governance objects exist (best-effort)
        def _ensure_history_objects(_db: str, _gv: str) -> None:
            try:
                if not _db:
                    return
                # Ensure schema
                try:
                    snowflake_connector.execute_non_query(f"create schema if not exists {_db}.{_gv}")
                except Exception:
                    pass
                # Ensure CLASSIFICATION_AUDIT (used across app)
                try:
                    snowflake_connector.execute_non_query(
                        f"""
                        create table if not exists {_db}.{_gv}.CLASSIFICATION_AUDIT (
                          ID string default uuid_string(),
                          RESOURCE_ID string,
                          ACTION string,
                          DETAILS string,
                          CREATED_AT timestamp_tz default current_timestamp()
                        )
                        """
                    )
                except Exception:
                    pass
                # Ensure CLASSIFICATION_HISTORY per requested schema
                try:
                    snowflake_connector.execute_non_query(
                        f"""
                        create or replace table {_db}.{_gv}.CLASSIFICATION_HISTORY (
                            HISTORY_ID varchar(100) not null,
                            ASSET_ID varchar(100),
                            PREVIOUS_CLASSIFICATION varchar(20),
                            NEW_CLASSIFICATION varchar(20),
                            PREVIOUS_CONFIDENTIALITY number(38,0),
                            NEW_CONFIDENTIALITY number(38,0),
                            PREVIOUS_INTEGRITY number(38,0),
                            NEW_INTEGRITY number(38,0),
                            PREVIOUS_AVAILABILITY number(38,0),
                            NEW_AVAILABILITY number(38,0),
                            CHANGED_BY varchar(150),
                            CHANGE_REASON varchar(1000),
                            CHANGE_TIMESTAMP timestamp_ntz(9) default current_timestamp(),
                            APPROVAL_REQUIRED boolean,
                            APPROVED_BY varchar(150),
                            APPROVAL_TIMESTAMP timestamp_ntz(9),
                            BUSINESS_JUSTIFICATION varchar(1000),
                            primary key (HISTORY_ID),
                            foreign key (ASSET_ID) references {_db}.{_gv}.ASSETS(ASSET_ID)
                        )
                        """
                    )
                except Exception:
                    # Fallback: create without FK if referenced table is missing or privilege issues
                    try:
                        snowflake_connector.execute_non_query(
                            f"""
                            create table if not exists {_db}.{_gv}.CLASSIFICATION_HISTORY (
                                HISTORY_ID varchar(100) not null,
                                ASSET_ID varchar(100),
                                PREVIOUS_CLASSIFICATION varchar(20),
                                NEW_CLASSIFICATION varchar(20),
                                PREVIOUS_CONFIDENTIALITY number(38,0),
                                NEW_CONFIDENTIALITY number(38,0),
                                PREVIOUS_INTEGRITY number(38,0),
                                NEW_INTEGRITY number(38,0),
                                PREVIOUS_AVAILABILITY number(38,0),
                                NEW_AVAILABILITY number(38,0),
                                CHANGED_BY varchar(150),
                                CHANGE_REASON varchar(1000),
                                CHANGE_TIMESTAMP timestamp_ntz(9) default current_timestamp(),
                                APPROVAL_REQUIRED boolean,
                                APPROVED_BY varchar(150),
                                APPROVAL_TIMESTAMP timestamp_ntz(9),
                                BUSINESS_JUSTIFICATION varchar(1000),
                                primary key (HISTORY_ID)
                            )
                            """
                        )
                    except Exception:
                        pass
                # Ensure VW_CLASSIFICATION_AUDIT (view over audit table)
                try:
                    snowflake_connector.execute_non_query(
                        f"""
                        create view if not exists {_db}.{_gv}.VW_CLASSIFICATION_AUDIT as
                        select ID, RESOURCE_ID, ACTION, DETAILS, CREATED_AT, null::timestamp_tz as UPDATED_AT
                        from {_db}.{_gv}.CLASSIFICATION_AUDIT
                        """
                    )
                except Exception:
                    pass
            except Exception:
                pass

        # Helpers for column discovery and safe queries
        def _get_object_columns(_db: str, _schema: str, _name: str) -> set:
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    select upper(COLUMN_NAME) as CN
                    from {_db}.INFORMATION_SCHEMA.COLUMNS
                    where TABLE_SCHEMA = %(s)s and TABLE_NAME = %(t)s
                    """,
                    {"s": _schema, "t": _name}
                ) or []
                return {r.get("CN") for r in rows}
            except Exception:
                return set()

        def _first_existing(cands: list, have: set) -> Optional[str]:
            for c in cands:
                if c.upper() in have:
                    return c
            return None

        # UI filters
        fc1, fc2, fc3 = st.columns([1.6, 1.2, 1.2])
        with fc1:
            f_asset = st.text_input("Filter: Asset contains", key="hist_f_asset")
        with fc2:
            f_user = st.text_input("Filter: User contains", key="hist_f_user")
        with fc3:
            f_action = st.multiselect("Filter: Action (audit)", options=["SUBMIT","APPROVE","REJECT","COMMENT","APPLY"], default=[], key="hist_f_action")

        # Ensure objects exist
        if db:
            _ensure_history_objects(db, gv)

        # Fetchers
        def _fetch_change_log(_db: str, _gv: str, lookback_days: int) -> pd.DataFrame:
            try:
                cols = _get_object_columns(_db, _gv, "CLASSIFICATION_HISTORY")
                ts_col = _first_existing(["CHANGE_TIMESTAMP"], cols)
                where = []
                params = {}
                if ts_col:
                    where.append(f"COALESCE(DATEDIFF(day, {ts_col}, CURRENT_TIMESTAMP()), 0) <= %(lb)s")
                    params["lb"] = int(lookback_days)
                # Apply text filters
                if f_asset:
                    # If ASSET_ID exists, use it; otherwise try ASSET_FULL_NAME if present
                    if "ASSET_ID" in cols:
                        where.append("ASSET_ID ILIKE %(fa)s"); params["fa"] = f"%{f_asset}%"
                if f_user and "CHANGED_BY" in cols:
                    where.append("CHANGED_BY ILIKE %(fu)s"); params["fu"] = f"%{f_user}%"
                sql = f"""
                    select *
                    from {_db}.{_gv}.CLASSIFICATION_HISTORY
                    {('WHERE ' + ' AND '.join(where)) if where else ''}
                    {('ORDER BY ' + ts_col + ' DESC') if ts_col else ''}
                    limit 1000
                """
                rows = snowflake_connector.execute_query(sql, params) or []
                return pd.DataFrame(rows)
            except Exception as e:
                st.info(f"Change Log unavailable: {e}")
                return pd.DataFrame()

        def _fetch_audit_trail(_db: str, _gv: str, lookback_days: int) -> pd.DataFrame:
            try:
                cols = _get_object_columns(_db, _gv, "CLASSIFICATION_AUDIT_VW")
                ts_col = _first_existing(["CREATED_AT","UPDATED_AT","EVENT_AT","TS","TIMESTAMP"], cols)
                where = []
                params = {}
                if ts_col:
                    where.append(f"COALESCE(DATEDIFF(day, {ts_col}, CURRENT_TIMESTAMP()), 0) <= %(lb)s")
                    params["lb"] = int(lookback_days)
                if f_asset:
                    if "ASSET_ID" in cols:
                        where.append("ASSET_ID ILIKE %(fa)s"); params["fa"] = f"%{f_asset}%"
                    elif "RESOURCE_ID" in cols:
                        where.append("RESOURCE_ID ILIKE %(fa)s"); params["fa"] = f"%{f_asset}%"
                if f_user and "DETAILS" in cols:
                    where.append("DETAILS ILIKE %(fu)s"); params["fu"] = f"%{f_user}%"
                if f_action and "ACTION" in cols:
                    where.append("upper(ACTION) IN (" + ",".join([f"upper(%(ac{i})s)" for i,_ in enumerate(f_action)]) + ")")
                    for i, a in enumerate(f_action):
                        params[f"ac{i}"] = a
                sql = f"""
                    select *
                    from {_db}.{_gv}.CLASSIFICATION_AUDIT_VW
                    {('WHERE ' + ' AND '.join(where)) if where else ''}
                    {('ORDER BY ' + ts_col + ' DESC') if ts_col else ''}
                    limit 1000
                """
                rows = snowflake_connector.execute_query(sql, params) or []
                return pd.DataFrame(rows)
            except Exception as e:
                st.info(f"Audit Trail unavailable: {e}")
                return pd.DataFrame()

        # Tabs
        t1, t2, t3 = st.tabs(["Change Log", "Audit Trail", "Version History"])

        # Change Log
        with t1:
            d1 = _fetch_change_log(db, gv, days) if db else pd.DataFrame()
            if d1.empty:
                st.info("No changes for the selected period.")
            else:
                show_cols = [c for c in [
                    "ASSET_ID","PREVIOUS_CLASSIFICATION","NEW_CLASSIFICATION",
                    "PREVIOUS_CONFIDENTIALITY","NEW_CONFIDENTIALITY",
                    "PREVIOUS_INTEGRITY","NEW_INTEGRITY",
                    "PREVIOUS_AVAILABILITY","NEW_AVAILABILITY",
                    "CHANGED_BY","CHANGE_REASON","CHANGE_TIMESTAMP"
                ] if c in d1.columns]
                st.dataframe(d1[show_cols] if show_cols else d1, width='stretch')
                try:
                    csv = (d1[show_cols] if show_cols else d1).to_csv(index=False).encode("utf-8")
                    st.download_button("Download Change Log (CSV)", data=csv, file_name="classification_change_log.csv", mime="text/csv")
                except Exception:
                    pass

        # Audit Trail
        with t2:
            d2 = _fetch_audit_trail(db, gv, days) if db else pd.DataFrame()
            if d2.empty:
                st.info("No audit activity for the selected period.")
            else:
                show_cols = [c for c in ["ASSET_ID","OBJECT_NAME","ACTION_TYPE","ACTION","DETAILS","CREATED_AT","ACTION_DATE"] if c in d2.columns]
                st.dataframe(d2[show_cols] if show_cols else d2, width='stretch')
                try:
                    csv = (d2[show_cols] if show_cols else d2).to_csv(index=False).encode("utf-8")
                    st.download_button("Download Audit Trail (CSV)", data=csv, file_name="classification_audit_trail.csv", mime="text/csv")
                except Exception:
                    pass

        # Version History
        with t3:
            base = _fetch_change_log(db, gv, max(days, 365)) if db else pd.DataFrame()
            if base.empty:
                st.info("No version data available.")
            else:
                try:
                    key = "ASSET_ID" if "ASSET_ID" in base.columns else None
                    ts = "CHANGE_TIMESTAMP" if "CHANGE_TIMESTAMP" in base.columns else None
                    if not key or not ts:
                        st.info("Version view requires ASSET_ID and CHANGE_TIMESTAMP columns.")
                    else:
                        bx = base.copy()
                        bx[ts] = pd.to_datetime(bx[ts], errors='coerce')
                        latest = bx.sort_values([key, ts], ascending=[True, False]).groupby(key, as_index=False).first()
                        cnts = bx.groupby(key).size().reset_index(name='VERSION_COUNT')
                        view = latest.merge(cnts, on=key, how='left')
                        cols_show = [c for c in [key, 'NEW_CLASSIFICATION','NEW_CONFIDENTIALITY','NEW_INTEGRITY','NEW_AVAILABILITY', ts, 'VERSION_COUNT'] if c in view.columns]
                        st.dataframe(view[cols_show] if cols_show else view, width='stretch')
                        try:
                            csv = (view[cols_show] if cols_show else view).to_csv(index=False).encode("utf-8")
                            st.download_button("Download Versions (CSV)", data=csv, file_name="classification_versions.csv", mime="text/csv")
                        except Exception:
                            pass
                        sel = st.selectbox("Inspect history for asset", options=view[key].tolist())
                        if sel:
                            timeline = bx[bx[key] == sel].sort_values(ts, ascending=True)
                            tcols = [c for c in [ts,'PREVIOUS_CLASSIFICATION','NEW_CLASSIFICATION','CHANGED_BY','CHANGE_REASON'] if c in timeline.columns]
                            st.markdown("**Timeline**")
                            st.dataframe(timeline[tcols] if tcols else timeline, width='stretch')
                except Exception as e:
                    st.info(f"Version history unavailable: {e}")

    # Reclassification Requests (placeholder)
    with sub_reclass:
        st.markdown("#### Reclassification Requests")
        if render_reclassification_requests:
            render_reclassification_requests(key_prefix="cm_reclass")
        else:
            st.warning("Reclassification Requests module unavailable.")

    # Pending Reviews sub-tab (disabled)
    if False:
        st.markdown("#### Pending Reviews")
        st.caption("View and act on classifications awaiting peer, management, or technical review. Uses real-time Snowflake data.")

        # Filters
        fc1, fc2, fc3, fc4 = st.columns([1.2, 1.2, 1, 1])
        with fc1:
            reviewer_filter = st.text_input("Reviewer name/email", key="pr_reviewer")
        with fc2:
            level_filter = st.selectbox("Classification level", options=["All", "Low (0-1)", "Medium (2)", "High (3)"], index=0, key="pr_level")
        with fc3:
            status_filter = st.multiselect("Status", options=["Pending", "Approved", "Rejected", "Changes Requested"], default=["Pending"], key="pr_status")
        with fc4:
            lookback = st.slider("Lookback (days)", min_value=7, max_value=120, value=30, step=1, key="pr_lookback")

        # Fetch data from Snowflake via service
        try:
            ident_reviews = authz.get_current_identity()
            me_user = str(ident_reviews.user or st.session_state.get("user") or "").strip()
        except Exception:
            me_user = str(st.session_state.get("user") or "").strip()

        reviews_payload = {"reviews": [], "error": None}
        if cr_list_reviews:
            # Note: Snowflake query happens inside classification_review_service.list_reviews
            try:
                reviews_payload = cr_list_reviews(
                    current_user=me_user,
                    review_filter="All",           # server-side keeps it broad; we filter more below
                    approval_status="All pending",  # show pending by default
                    lookback_days=int(lookback or 30),
                    page=1,
                    page_size=500,
                    database=st.session_state.get("sf_database"),
                ) or {"reviews": []}
            except Exception as e:
                reviews_payload = {"reviews": [], "error": str(e)}
        else:
            reviews_payload = {"reviews": [], "error": "review service unavailable"}

        rows = reviews_payload.get("reviews") or []
        error_msg = reviews_payload.get("error")
        if error_msg:
            st.error(f"Failed to load pending reviews from Snowflake: {error_msg}")

        # Convert to DataFrame and apply client-side filters
        df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=[
            "database","schema","asset_name","classification","c_level","created_by","approved_by","change_timestamp","id"
        ])

        # Derive helper columns
        if not df.empty:
            df["DATASET"] = (df.get("database").fillna("") + "." + df.get("schema").fillna("") + "." + df.get("asset_name").fillna("")).str.strip(".")
            # Robust CIA computation: handle missing i_level/a_level columns with Series defaults
            c_series = pd.to_numeric(df.get("c_level"), errors="coerce").fillna(0).astype(int)
            i_series = (
                pd.to_numeric(df["i_level"], errors="coerce").fillna(0).astype(int)
                if "i_level" in df.columns else pd.Series([0]*len(df), index=df.index, dtype="int64")
            )
            a_series = (
                pd.to_numeric(df["a_level"], errors="coerce").fillna(0).astype(int)
                if "a_level" in df.columns else pd.Series([0]*len(df), index=df.index, dtype="int64")
            )
            df["CIA_SCORES"] = c_series.astype(str) + "/" + i_series.astype(str) + "/" + a_series.astype(str)
            df["OVERALL_CLASSIFICATION"] = df.get("classification").fillna("")
            # Basic status from approved_by if present; otherwise Pending
            df["STATUS"] = df.apply(lambda r: "Approved" if str(r.get("approved_by") or "").strip() else "Pending", axis=1)
            # Reviewer field best-effort (approver_assigned then created_by), robust to missing columns
            reviewer_series = (
                df["approver_assigned"].astype(str).fillna("")
                if "approver_assigned" in df.columns else pd.Series([""]*len(df), index=df.index)
            )
            created_series = (
                df["created_by"].astype(str).fillna("")
                if "created_by" in df.columns else pd.Series([""]*len(df), index=df.index)
            )
            df["REVIEWER"] = reviewer_series
            df.loc[df["REVIEWER"].isin(["", "None", "nan"]), "REVIEWER"] = created_series
            # Due Date: simplistic SLA (5 days after change) if timestamp present
            try:
                df["DUE_DATE"] = pd.to_datetime(df.get("change_timestamp")) + pd.to_timedelta(5, unit="D")
            except Exception:
                df["DUE_DATE"] = None

            # Apply UI filters
            if reviewer_filter:
                df = df[df["REVIEWER"].str.contains(reviewer_filter, case=False, na=False)]
            if level_filter != "All":
                if level_filter == "High (3)":
                    df = df[df.get("c_level", 0).fillna(0).astype(int) == 3]
                elif level_filter == "Medium (2)":
                    df = df[df.get("c_level", 0).fillna(0).astype(int) == 2]
                elif level_filter == "Low (0-1)":
                    df = df[df.get("c_level", 0).fillna(0).astype(int).isin([0,1])]
            if status_filter:
                df = df[df["STATUS"].isin(status_filter)]

        # Display table
        show_cols = ["DATASET", "CIA_SCORES", "OVERALL_CLASSIFICATION", "REVIEWER", "STATUS", "DUE_DATE"]
        st.dataframe(df[show_cols] if not df.empty else pd.DataFrame(columns=show_cols), width='stretch')

        # Action panel for a selected review
        if not df.empty:
            st.markdown("---")
            left, right = st.columns([2, 3])
            with left:
                selection_options = df["id"].astype(str).tolist()
                selected_id = st.selectbox("Select Review ID", options=selection_options, key="pr_select")
                selected_row = df[df["id"].astype(str) == str(selected_id)].iloc[0] if selected_id else None
                st.caption(selected_row["DATASET"]) if selected_id is not None else None
            with right:
                if selected_id is not None:
                    st.write("Actions")
                    # Compose full asset name and default CIA
                    asset_full = selected_row["DATASET"]
                    default_c = int(pd.to_numeric(selected_row.get("c_level"), errors="coerce") or 0)
                    ci1, ci2, ci3 = st.columns(3)
                    with ci1:
                        c_val = st.number_input("C", min_value=0, max_value=3, value=default_c, key="pr_c")
                    with ci2:
                        i_val = st.number_input("I", min_value=0, max_value=3, value=1, key="pr_i")
                    with ci3:
                        a_val = st.number_input("A", min_value=0, max_value=3, value=1, key="pr_a")

                    comments = st.text_area("Comments / Instructions", placeholder="Add justification or change requests...", key="pr_comments")
                    b1, b2, b3 = st.columns([1,1,1])
                    with b1:
                        if st.button("Approve", type="primary", key="pr_approve_btn"):
                            try:
                                ok = review_actions.approve_review(
                                    review_id=str(selected_id),
                                    asset_full_name=asset_full,
                                    label=str(selected_row.get("classification") or ""),
                                    c=int(c_val), i=int(i_val), a=int(a_val),
                                    approver=me_user,
                                    comments=comments,
                                )
                                if ok:
                                    st.success("Approved. Logged for audit.")
                                    # Removed st.rerun() to prevent no-op warning
                                else:
                                    st.error("Approval failed. See logs.")
                            except Exception as e:
                                st.error(f"Approval failed: {e}")
                    with b2:
                        if st.button("Reject", key="pr_reject_btn"):
                            try:
                                ok = review_actions.reject_review(
                                    review_id=str(selected_id),
                                    asset_full_name=asset_full,
                                    approver=me_user,
                                    justification=comments,
                                )
                                if ok:
                                    st.success("Rejected. Logged for audit.")
                                    # Removed st.rerun() to prevent no-op warning
                                else:
                                    st.error("Rejection failed. See logs.")
                            except Exception as e:
                                st.error(f"Rejection failed: {e}")
                    with b3:
                        if st.button("Request Changes", key="pr_changes_btn"):
                            try:
                                ok = review_actions.request_changes(
                                    review_id=str(selected_id),
                                    asset_full_name=asset_full,
                                    approver=me_user,
                                    instructions=comments,
                                )
                                if ok:
                                    st.success("Change request sent. Logged for audit.")
                                    # Removed st.rerun() to prevent no-op warning
                                else:
                                    st.error("Request changes failed. See logs.")
                            except Exception as e:
                                st.error(f"Request changes failed: {e}")

    # History sub-tab (disabled)
    if False:
        # Displays audit trail with filters (date range, dataset, level, owner)
        # Sorting/searching handled client-side; Snowflake SQL lives in service module.
        # Snowflake query customization: edit `src/services/classification_audit_service.py` (CLASSIFICATION_AUDIT mapping).
        render_classification_history_tab(key_prefix="cm_hist")


    try:
        ident_tasks = authz.get_current_identity()
        me_user = (ident_tasks.user or "").strip()
    except Exception:
        me_user = str(st.session_state.get("user") or "")

    # My Tasks sub-tab (disabled)
    if False:
        st.markdown("#### My Tasks (Unified)")
        # Merge logic from service-backed tasks and inventory/reclassification signals
        import pandas as _pd

        # 1) Load service-backed tasks with existing filters
        f1, f2, f3, f4 = st.columns([1,1,1,2])
        with f1:
            status_map = {"All": None, "Draft": "draft", "Pending": "pending", "Completed": "completed"}
            sel_status = st.selectbox("Status", list(status_map.keys()), index=0)
        with f2:
            owner_q = st.text_input("Owner contains", value="")
        with f3:
            sel_level = st.selectbox("Classification Level", ["All","Public","Internal","Restricted","Confidential"], index=0)
        with f4:
            c1, c2 = st.columns(2)
            with c1:
                dr_start = st.date_input("Start", value=None, key="my_tasks_start")
            with c2:
                dr_end = st.date_input("End", value=None, key="my_tasks_end")

        svc_tasks = my_fetch_tasks(
            current_user=me_user,
            status=status_map.get(sel_status),
            owner=(owner_q or None),
            classification_level=(None if sel_level == "All" else sel_level),
            date_range=((str(dr_start) if dr_start else None), (str(dr_end) if dr_end else None)),
            limit=500,
        ) or []

        svc_df = _pd.DataFrame(svc_tasks)
        svc_df.rename(columns={
            "asset_name":"Asset Name",
            "object_type":"Type",
            "due_date":"Due Date",
            "priority":"Priority",
            "status":"Status",
        }, inplace=True)

        # 2) Load additional task signals (unclassified inventory + reclassification) similar to internal panel
        def _load_task_queue(limit_assets: int = 500, limit_reqs: int = 300) -> _pd.DataFrame:
            items = []
            try:
                db = _get_current_db()
                if db:
                    inv = snowflake_connector.execute_query(
                        f"""
                        SELECT 
                          FULLY_QUALIFIED_NAME AS FULL_NAME,
                          BUSINESS_UNIT AS OBJECT_DOMAIN,
                          COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP) AS FIRST_DISCOVERED,
                          (CLASSIFICATION_LABEL IS NOT NULL) AS CLASSIFIED
                        FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                        ORDER BY COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP) DESC
                        LIMIT {int(limit_assets)}
                        """
                    ) or []
                    for r in inv:
                        full = r.get("FULL_NAME")
                        if not full:
                            continue
                        classified = bool(r.get("CLASSIFIED"))
                        if classified:
                            continue
                        fd = _pd.to_datetime(r.get("FIRST_DISCOVERED")) if r.get("FIRST_DISCOVERED") else None
                        due_by = _sla_due(fd.tz_localize(None) if isinstance(fd, _pd.Timestamp) else datetime.utcnow()) if fd is not None else _sla_due(datetime.utcnow())
                        priority = "High" if (due_by - datetime.utcnow()).days < 0 else ("Medium" if (due_by - datetime.utcnow()).days <= 2 else "Low")
                        items.append({
                            "Asset Name": full,
                            "Type": r.get("OBJECT_DOMAIN") or "TABLE",
                            "Due Date": due_by.date(),
                            "Priority": priority,
                            "Status": "New",
                            "Source": "Inventory",
                        })
            except Exception:
                pass
            try:
                reqs = reclassification_service.list_requests(limit=int(limit_reqs)) or []
                for r in reqs:
                    full = r.get("ASSET_FULL_NAME") or r.get("ASSET") or r.get("FULL_NAME")
                    if not full:
                        continue
                    created = _pd.to_datetime(r.get("CREATED_AT") or r.get("CREATED"), errors='coerce')
                    due_by = _sla_due((created.to_pydatetime() if isinstance(created, _pd.Timestamp) else datetime.utcnow())) if created is not None else _sla_due(datetime.utcnow())
                    days_left = (due_by - datetime.utcnow()).days
                    priority = "High" if days_left < 0 else ("Medium" if days_left <= 2 else "Low")
                    status = r.get("STATUS") or r.get("state") or "In Progress"
                    items.append({
                        "Asset Name": full,
                        "Type": r.get("OBJECT_TYPE") or "TABLE",
                        "Due Date": due_by.date(),
                        "Priority": priority,
                        "Status": status,
                        "Source": "Reclassification",
                        "Request ID": r.get("ID"),
                    })
            except Exception:
                pass
            return _pd.DataFrame(items)

        aux_df = _load_task_queue()

        # 3) Combine and derive fields similar to internal renderer
        df = _pd.concat([svc_df, aux_df], ignore_index=True, sort=False)
        if df.empty:
            st.info("No tasks found for the selected filters.")
        else:
            # User identity for assignment
            try:
                ident = authz.get_current_identity()
                ident_user = getattr(ident, "user", "") or ""
            except Exception:
                ident_user = ""
            me = str(st.session_state.get("user") or ident_user).lower()
            now = datetime.utcnow()

            def _due_bucket(d):
                try:
                    d0 = _pd.to_datetime(d).to_pydatetime()
                except Exception:
                    return "Future"
                if d0.date() < now.date():
                    return "Overdue"
                if (d0 - now).days <= 7:
                    return "Due this week"
                return "Future"

            def _task_type(row):
                src = str(row.get("Source") or "")
                if src == "Reclassification":
                    return "Reclassification"
                try:
                    due = _pd.to_datetime(row.get("Due Date")).to_pydatetime()
                    if (due - now).days > 300:
                        return "Annual Review"
                except Exception:
                    pass
                return "Initial Classification"

            def _priority_map(p):
                if str(p) == "High":
                    return "Critical"
                if str(p) == "Medium":
                    return "High"
                return "Normal"

            def _assignment(row):
                created_by = str(row.get("Created By") or row.get("CREATED_BY") or "").lower()
                if created_by and me and created_by == me:
                    return "Assigned to me"
                return "Unassigned"

            df = df.copy()
            df["Due Bucket"] = df["Due Date"].apply(_due_bucket)
            df["Task Type"] = df.apply(_task_type, axis=1)
            df["Priority2"] = df["Priority"].apply(_priority_map)
            df["Assignment"] = df.apply(_assignment, axis=1)

            # Filters for derived fields
            g1, g2, g3 = st.columns([1,1,1])
            with g1:
                due_bucket = st.selectbox("Due Date", options=["All", "Overdue", "Due this week", "Future"], index=0)
            with g2:
                task_type = st.multiselect("Task Type", options=["Initial Classification","Reclassification","Annual Review"], default=[])
            with g3:
                priority_filter = st.multiselect("Priority", options=["Critical","High","Normal"], default=[])

            if due_bucket != "All":
                df = df[df["Due Bucket"] == due_bucket]
            if task_type:
                df = df[df["Task Type"].isin(task_type)]
            if priority_filter:
                df = df[df["Priority2"].isin(priority_filter)]

            # Present unified view (read-only for now); keep bulk actions minimal
            show_cols = [c for c in ["Asset Name","Type","Due Date","Priority2","Assignment","Task Type","Status","Source"] if c in df.columns]
            st.dataframe(df[show_cols].rename(columns={"Priority2":"Priority"}), width='stretch')

    st.markdown("---")
    st.caption("Use the New Classification wizard for detailed workflows. This My Tasks table supports quick updates and submissions.")

if False:
    st.subheader("Classification Review")
    # Filters
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        f_status = st.multiselect("Status", ["Pending","In Review","Changes Requested","Approved","Escalated"], [])
    with c2:
        f_level = st.multiselect("Classification Level", ["Public","Internal","Restricted","Confidential"], [])
    with c3:
        f_requestor = st.text_input("Requestor contains", "")
    with c4:
        f_domain = st.text_input("Domain contains", "")
    # Data
    reviews = []
    try:
        if cr_list_reviews:
            try:
                ident_rev = authz.get_current_identity()
                cur_user = (ident_rev.user or "")
            except Exception:
                cur_user = str(st.session_state.get("user") or "")
            out = cr_list_reviews(
                current_user=cur_user,
                review_filter="All",
                approval_status="All pending",
                lookback_days=30,
                page=1,
                page_size=500,
                database=st.session_state.get("sf_database"),
            )
            reviews = (out or {}).get("reviews", [])
    except Exception:
        reviews = []
    import pandas as _pd
    rdf = _pd.DataFrame(reviews)
    if not rdf.empty:
        # Apply global filters
        rdf = rdf[rdf.apply(lambda r: _matches_global(r, global_sel), axis=1)]
        # Apply local filters
        if f_status:
            rdf = rdf[rdf["status"].isin(f_status)] if "status" in rdf.columns else rdf
        if f_level:
            coln = "proposed_classification" if "proposed_classification" in rdf.columns else "classification"
            rdf = rdf[rdf[coln].isin(f_level)]
        if f_requestor:
            if "created_by" in rdf.columns:
                rdf = rdf[rdf["created_by"].str.contains(f_requestor, case=False, na=False)]
        if f_domain and "object_type" in rdf.columns:
            rdf = rdf[rdf["object_type"].str.contains(f_domain, case=False, na=False)]
        if rdf.empty:
            st.info("No review items for current filters.")
        else:
            st.dataframe(rdf, width='stretch', hide_index=True)
            # Reviewer actions
            sel_asset_rev = st.selectbox("Select asset to review", options=rdf.get("asset_name", _pd.Series(dtype=str)).dropna().unique().tolist() if "asset_name" in rdf.columns else [])
            colrv1, colrv2, colrv3 = st.columns(3)
            with colrv1:
                if st.button("Approve", disabled=not bool(sel_asset_rev)):
                    try:
                        dbx = st.session_state.get("sf_database")
                        req = snowflake_connector.execute_query(
                            f"select ID from {dbx}.DATA_CLASSIFICATION_GOVERNANCE.RECLASSIFICATION_REQUESTS where ASSET_FULL_NAME = %(a)s and upper(STATUS) in ('PENDING','SUBMITTED') order by CREATED_AT desc limit 1",
                            {"a": sel_asset_rev},
                        ) or []
                        rid = req[0].get("ID") if req else None
                        if rid:
                            reclassification_service.approve(rid, approver=str(st.session_state.get("user") or "reviewer@system"))
                            # Insert review history
                            snowflake_connector.execute_non_query(
                                f"""
                                create schema if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE;
                                create table if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE.REVIEW_HISTORY (
                                  ID string, REQUEST_ID string, ASSET_FULL_NAME string, ACTION string,
                                  DECISION string, DECIDED_BY string, DECIDED_AT timestamp_ntz default current_timestamp,
                                  RATIONALE string, DETAILS variant
                                );
                                insert into {dbx}.DATA_CLASSIFICATION_GOVERNANCE.REVIEW_HISTORY
                                  (ID, REQUEST_ID, ASSET_FULL_NAME, ACTION, DECISION, DECIDED_BY, RATIONALE, DETAILS)
                                select UUID_STRING(), %(rid)s, %(asset)s, 'REVIEW', 'Approved', %(by)s, %(rat)s, to_variant(parse_json(%(det)s))
                                """,
                                {"rid": rid, "asset": sel_asset_rev, "by": str(st.session_state.get("user") or "reviewer@system"), "rat": "Approved", "det": __import__("json").dumps({})},
                            )
                            st.success("Approved and recorded.")
                            st.cache_data.clear()
                        else:
                            st.info("No pending request found for this asset.")
                    except Exception as e:
                        st.error(f"Approve failed: {e}")
            with colrv2:
                reason = st.text_input("Change/Escalation reason", key="rev_reason")
                if st.button("Request Changes", disabled=not bool(sel_asset_rev)):
                    try:
                        dbx = st.session_state.get("sf_database")
                        req = snowflake_connector.execute_query(
                            f"select ID, CREATED_BY from {dbx}.DATA_CLASSIFICATION_GOVERNANCE.RECLASSIFICATION_REQUESTS where ASSET_FULL_NAME = %(a)s and upper(STATUS) in ('PENDING','SUBMITTED') order by CREATED_AT desc limit 1",
                            {"a": sel_asset_rev},
                        ) or []
                        rid = req[0].get("ID") if req else None
                        submitter = req[0].get("CREATED_BY") if req else None
                        if rid:
                            reclassification_service.reject(rid, approver=str(st.session_state.get("user") or "reviewer@system"), justification=reason or "Changes requested")
                            snowflake_connector.execute_non_query(
                                f"insert into {dbx}.DATA_CLASSIFICATION_GOVERNANCE.REVIEW_HISTORY (ID, REQUEST_ID, ASSET_FULL_NAME, ACTION, DECISION, DECIDED_BY, RATIONALE, DETAILS)\n                                 select UUID_STRING(), %(rid)s, %(asset)s, 'REVIEW', 'Changes Requested', %(by)s, %(rat)s, to_variant(parse_json(%(det)s))",
                                {"rid": rid, "asset": sel_asset_rev, "by": str(st.session_state.get("user") or "reviewer@system"), "rat": reason or "Changes requested", "det": __import__("json").dumps({})},
                            )
                            # Notify submitter
                            if submitter and dbx:
                                snowflake_connector.execute_non_query(
                                    f"insert into {dbx}.DATA_CLASSIFICATION_GOVERNANCE.NOTIFICATIONS_OUTBOX (ID, CHANNEL, TARGET, SUBJECT, BODY) select UUID_STRING(), 'EMAIL', %(t)s, %(s)s, %(b)s",
                                    {"t": submitter, "s": f"Changes requested: {sel_asset_rev}", "b": reason or "Please revise classification."},
                                )
                            st.warning("Changes requested.")
                            st.cache_data.clear()
                        else:
                            st.info("No pending request found for this asset.")
                    except Exception as e:
                        st.error(f"Request Changes failed: {e}")
            with colrv3:
                if st.button("Escalate", disabled=not bool(sel_asset_rev)):
                    try:
                        dbx = st.session_state.get("sf_database")
                        # Log escalation in review history
                        snowflake_connector.execute_non_query(
                            f"""
                            create schema if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE;
                            create table if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE.REVIEW_HISTORY (
                              ID string, REQUEST_ID string, ASSET_FULL_NAME string, ACTION string,
                              DECISION string, DECIDED_BY string, DECIDED_AT timestamp_ntz default current_timestamp,
                              RATIONALE string, DETAILS variant
                            );
                            insert into {dbx}.DATA_CLASSIFICATION_GOVERNANCE.REVIEW_HISTORY
                              (ID, REQUEST_ID, ASSET_FULL_NAME, ACTION, DECISION, DECIDED_BY, RATIONALE, DETAILS)
                            select UUID_STRING(), null, %(asset)s, 'ESCALATE', 'Escalated', %(by)s, %(rat)s, to_variant(parse_json(%(det)s))
                            """,
                            {"asset": sel_asset_rev, "by": str(st.session_state.get("user") or "reviewer@system"), "rat": reason or "Escalated", "det": __import__("json").dumps({})},
                        )
                        st.info("Escalated.")
                        st.cache_data.clear(); st.rerun()
                    except Exception as e:
                        st.error(f"Escalate failed: {e}")
    else:
        st.info("No review items available.")

if False:
    st.subheader("Reclassification Management")
    st.caption("Manage triggers, analyze impact, and run bulk operations.")
    from src.services.reclassification_service import reclassification_service as _reclass
    # Load requests
    reqs = _reclass.list_requests(limit=500) or []
    df = pd.DataFrame(reqs)
    if not df.empty:
        df = df[df.apply(lambda r: _matches_global(r, global_sel), axis=1)]
    # Controls
    colf1, colf2, colf3 = st.columns(3)
    with colf1:
        f_trigger = st.multiselect("Trigger Type", sorted(df["TRIGGER_TYPE"].dropna().unique().tolist()) if not df.empty and "TRIGGER_TYPE" in df.columns else [], [])
    with colf2:
        f_scope = st.text_input("Scope contains", "")
    with colf3:
        f_status2 = st.multiselect("Status", sorted(df["STATUS"].dropna().unique().tolist()) if not df.empty and "STATUS" in df.columns else [], [])
    if not df.empty:
        if f_trigger:
            df = df[df["TRIGGER_TYPE"].isin(f_trigger)] if "TRIGGER_TYPE" in df.columns else df
        if f_status2:
            df = df[df["STATUS"].isin(f_status2)] if "STATUS" in df.columns else df
        if f_scope:
            df = df[df.apply(lambda r: f_scope.lower() in str(r.get("ASSET_FULL_NAME") or r.get("ASSET") or r.get("FULL_NAME") or "").lower(), axis=1)]
        st.dataframe(df, width='stretch', hide_index=True)
        # Bulk ops
        st.markdown("---")
        sel_ids = st.multiselect("Select requests for bulk action", df["ID"].tolist() if "ID" in df.columns else [])
        bulk_reason = st.text_input("Reason (for Changes/Escalation)", key="reclass_bulk_reason")
        colb1, colb2, colb3 = st.columns(3)
        with colb1:
            if st.button("Request Changes", disabled=not sel_ids):
                try:
                    dbx = st.session_state.get("sf_database")
                    cur_user = str(st.session_state.get("user") or "reviewer@system")
                    for rid in sel_ids:
                        # Find record from dataframe for submitter/asset
                        rec = df[df["ID"] == rid].head(1)
                        asset = rec.iloc[0]["ASSET_FULL_NAME"] if (not rec.empty and "ASSET_FULL_NAME" in rec.columns) else None
                        submitter = rec.iloc[0]["CREATED_BY"] if (not rec.empty and "CREATED_BY" in rec.columns) else None
                        _reclass.reject(rid, approver=cur_user, justification=bulk_reason or "Changes requested")
                        if dbx:
                            # Review history
                            snowflake_connector.execute_non_query(
                                f"""
                                create schema if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE;
                                create table if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE.REVIEW_HISTORY (
                                  ID string, REQUEST_ID string, ASSET_FULL_NAME string, ACTION string,
                                  DECISION string, DECIDED_BY string, DECIDED_AT timestamp_ntz default current_timestamp,
                                  RATIONALE string, DETAILS variant
                                );
                                insert into {dbx}.DATA_CLASSIFICATION_GOVERNANCE.REVIEW_HISTORY
                                  (ID, REQUEST_ID, ASSET_FULL_NAME, ACTION, DECISION, DECIDED_BY, RATIONALE, DETAILS)
                                select UUID_STRING(), %(rid)s, %(asset)s, 'REVIEW', 'Changes Requested', %(by)s, %(rat)s, to_variant(parse_json(%(det)s))
                                """,
                                {"rid": rid, "asset": asset or "", "by": cur_user, "rat": bulk_reason or "Changes requested", "det": __import__("json").dumps({})},
                            )
                            # Notify submitter via outbox
                            if submitter:
                                snowflake_connector.execute_non_query(
                                    f"""
                                    create schema if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE;
                                    create table if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE.NOTIFICATIONS_OUTBOX (
                                      ID string, CREATED_AT timestamp_ntz default current_timestamp,
                                      CHANNEL string, TARGET string, SUBJECT string, BODY string,
                                      SENT_AT timestamp_ntz, SENT_RESULT string
                                    );
                                    insert into {dbx}.DATA_CLASSIFICATION_GOVERNANCE.NOTIFICATIONS_OUTBOX
                                      (ID, CHANNEL, TARGET, SUBJECT, BODY)
                                    select UUID_STRING(), 'EMAIL', %(t)s, %(s)s, %(b)s
                                    """,
                                    {"t": submitter, "s": f"Changes requested: {asset}", "b": bulk_reason or "Please revise classification."},
                                )
                    st.warning("Changes requested for selected request(s).")
                    st.cache_data.clear(); st.rerun()
                except Exception as e:
                    st.error(f"Bulk Request Changes failed: {e}")
        with colb2:
            if st.button("Approve", disabled=not sel_ids):
                try:
                    dbx = st.session_state.get("sf_database")
                    cur_user = str(st.session_state.get("user") or "reviewer@system")
                    for rid in sel_ids:
                        rec = df[df["ID"] == rid].head(1)
                        asset = rec.iloc[0]["ASSET_FULL_NAME"] if (not rec.empty and "ASSET_FULL_NAME" in rec.columns) else None
                        _reclass.approve(rid, approver=cur_user)
                        if dbx:
                            snowflake_connector.execute_non_query(
                                f"""
                                create schema if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE;
                                create table if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE.REVIEW_HISTORY (
                                  ID string, REQUEST_ID string, ASSET_FULL_NAME string, ACTION string,
                                  DECISION string, DECIDED_BY string, DECIDED_AT timestamp_ntz default current_timestamp,
                                  RATIONALE string, DETAILS variant
                                );
                                insert into {dbx}.DATA_CLASSIFICATION_GOVERNANCE.REVIEW_HISTORY
                                  (ID, REQUEST_ID, ASSET_FULL_NAME, ACTION, DECISION, DECIDED_BY, RATIONALE, DETAILS)
                                select UUID_STRING(), %(rid)s, %(asset)s, 'REVIEW', 'Approved', %(by)s, %(rat)s, to_variant(parse_json(%(det)s))
                                """,
                                {"rid": rid, "asset": asset or "", "by": cur_user, "rat": "Approved", "det": __import__("json").dumps({})},
                            )
                    st.success("Approved selected request(s).")
                    st.cache_data.clear(); st.rerun()
                except Exception as e:
                    st.error(f"Bulk Approve failed: {e}")
        with colb3:
            if st.button("Escalate", disabled=not sel_ids):
                try:
                    dbx = st.session_state.get("sf_database")
                    cur_user = str(st.session_state.get("user") or "reviewer@system")
                    for rid in sel_ids:
                        rec = df[df["ID"] == rid].head(1)
                        asset = rec.iloc[0]["ASSET_FULL_NAME"] if (not rec.empty and "ASSET_FULL_NAME" in rec.columns) else None
                        if dbx:
                            snowflake_connector.execute_non_query(
                                f"""
                                create schema if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE;
                                create table if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE.REVIEW_HISTORY (
                                  ID string, REQUEST_ID string, ASSET_FULL_NAME string, ACTION string,
                                  DECISION string, DECIDED_BY string, DECIDED_AT timestamp_ntz default current_timestamp,
                                  RATIONALE string, DETAILS variant
                                );
                                insert into {dbx}.DATA_CLASSIFICATION_GOVERNANCE.REVIEW_HISTORY
                                  (ID, REQUEST_ID, ASSET_FULL_NAME, ACTION, DECISION, DECIDED_BY, RATIONALE, DETAILS)
                                select UUID_STRING(), %(rid)s, %(asset)s, 'ESCALATE', 'Escalated', %(by)s, %(rat)s, to_variant(parse_json(%(det)s))
                                """,
                                {"rid": rid, "asset": asset or "", "by": cur_user, "rat": bulk_reason or "Escalated", "det": __import__("json").dumps({})},
                            )
                    st.info("Escalated selected request(s).")
                    st.cache_data.clear(); st.rerun()
                except Exception as e:
                    st.error(f"Bulk Escalate failed: {e}")
    else:
        st.info("No reclassification requests found.")

if False:
    st.subheader("Classification History & Audit")
    # Filters
    d1, d2 = st.columns(2)
    with d1:
        sd = st.date_input("Start Date", value=None, key="hist_sd")
    with d2:
        ed = st.date_input("End Date", value=None, key="hist_ed")
    lv = st.multiselect("Classification", ["Public","Internal","Restricted","Confidential"], [])
    cl = st.multiselect("C Level", [0,1,2,3], [])
    # Data
    res = classification_history_service.query_history(
        start_date=str(sd) if sd else None,
        end_date=str(ed) if ed else None,
        levels=lv or None,
        c_levels=cl or None,
        page=1,
        page_size=200,
        database=st.session_state.get("sf_database"),
    )
    items = (res or {}).get("history", [])
    hdf = pd.DataFrame(items)
    if not hdf.empty:
        hdf = hdf[hdf.apply(lambda r: _matches_global(r, global_sel), axis=1)]
    if hdf.empty:
        st.info("No history for current filters.")
    else:
        st.dataframe(hdf, width='stretch', hide_index=True)

if False:
    st.subheader("Snowflake Tag Management")
    out = tag_drift_service.analyze_tag_drift(database=st.session_state.get("sf_database"), limit=2000)
    items = (out or {}).get("items", [])
    tdf = pd.DataFrame(items)
    if not tdf.empty:
        tdf = tdf[tdf.apply(lambda r: _matches_global(r, global_sel), axis=1)]
    c1, c2 = st.columns(2)
    with c1:
        f_status3 = st.selectbox("Status", ["All","Drift Only","Tagged Only","Untagged Only"], index=0)
    with c2:
        f_env = st.text_input("Environment/Database contains", "")
    if not tdf.empty:
        if f_status3 == "Drift Only":
            tdf = tdf[tdf.get("drift") == True]
        elif f_status3 == "Tagged Only":
            tdf = tdf[tdf.get("tag_classification").fillna("") != ""]
        elif f_status3 == "Untagged Only":
            tdf = tdf[tdf.get("tag_classification").fillna("") == ""]
        if f_env:
            tdf = tdf[tdf["database"].str.contains(f_env, case=False, na=False)] if "database" in tdf.columns else tdf
    if tdf.empty:
        st.info("No items for current filters.")
    else:
        st.dataframe(tdf, use_container_width=True, hide_index=True)

        # Drift sync tools
        drift_assets = tdf[tdf.get("drift") == True]["asset_name"].dropna().unique().tolist() if "drift" in tdf.columns else []
        sel_drift = st.selectbox("Select drifted asset to sync", options=drift_assets)
        if sel_drift and st.button("Sync Governance → Tag"):
            try:
                row = tdf[tdf["asset_name"] == sel_drift].head(1)
                gov_val = row.iloc[0]["governance_classification"] if not row.empty else None
                dbn = row.iloc[0]["database"] if not row.empty else None
                sch = row.iloc[0]["schema"] if not row.empty else None
                if gov_val and dbn and sch:
                    full = f"{dbn}.{sch}.{sel_drift.split('.')[-1]}" if "." not in sel_drift else sel_drift
                    tagging_service.apply_tags_to_object(full, "TABLE", {"DATA_CLASSIFICATION": str(gov_val)})
                    # Log drift sync
                    dbx = st.session_state.get("sf_database")
                    if dbx:
                        snowflake_connector.execute_non_query(
                            f"""
                            create schema if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE;
                            create table if not exists {dbx}.DATA_CLASSIFICATION_GOVERNANCE.TAG_DRIFT_LOG (
                              ID string, ASSET_FULL_NAME string, ACTION string, RESULT string,
                              REQUESTED_BY string, REQUESTED_AT timestamp_ntz default current_timestamp, DETAILS variant
                            );
                            insert into {dbx}.DATA_CLASSIFICATION_GOVERNANCE.TAG_DRIFT_LOG
                              (ID, ASSET_FULL_NAME, ACTION, RESULT, REQUESTED_BY, DETAILS)
                            select UUID_STRING(), %(asset)s, 'SYNC', 'Applied', %(by)s, to_variant(parse_json(%(det)s))
                            """,
                            {"asset": full, "by": str(st.session_state.get("user") or "system"), "det": __import__("json").dumps({"target": gov_val})},
                        )
                    st.success("Tag synchronized to governance value.")
                    st.cache_data.clear(); st.rerun()
                else:
                    st.info("Missing governance value or object coordinates.")
            except Exception as e:
                st.error(f"Sync failed: {e}")

    # Ensure only the five primary tabs are rendered; prevent legacy/duplicate tabs below
    st.markdown("---")
    st.stop()

# ---------------------------
# Helpers and Models (CIA)
# ---------------------------
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict

@dataclass
class CIA:
    """Implements Section 5.2 CIA Scales: C0–C3, I0–I3, A0–A3."""
    c: int
    i: int
    a: int

    def normalized(self) -> Tuple[int, int, int]:
        return max(0, min(self.c, 3)), max(0, min(self.i, 3)), max(0, min(self.a, 3))

    def risk_level(self) -> str:
        """Implements Section 5.3 Overall Risk Classification (highest-of-CIA)."""
        c, i, a = self.normalized()
        highest = max(c, i, a)
        if highest >= 3:
            return "High"
        if highest == 2:
            return "Medium"
        return "Low"

def _get_current_db() -> Optional[str]:
    try:
        db = st.session_state.get("sf_database")
        # Treat placeholders as missing
        if not db or str(db).strip() == "" or str(db).upper() in {"NONE", "(NONE)", "NULL", "UNKNOWN"}:
            rows = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB") or []
            db = rows[0].get("DB") if rows else None
        # Final validation
        if not db or str(db).strip() == "" or str(db).upper() in {"NONE", "(NONE)", "NULL", "UNKNOWN"}:
            return None
        return db
    except Exception:
        return None

def _list_tables(limit: int = 300) -> List[str]:
    try:
        db = None
        try:
            db = _get_current_db()
        except Exception:
            db = None

        out: List[str] = []

        def _fetch_from_db(name: str, lim: int) -> List[str]:
            try:
                q = f"""
                SELECT "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS FULL_NAME
                FROM {name}.INFORMATION_SCHEMA.TABLES
                WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
                ORDER BY 1
                LIMIT {int(lim)}
                """
                rows = snowflake_connector.execute_query(q) or []
                return [r.get("FULL_NAME") for r in rows if r.get("FULL_NAME")]
            except Exception:
                return []

        if db:
            out = _fetch_from_db(db, limit)
        else:
            names: List[str] = []
            # Try active from session
            try:
                if _db_active:
                    names.append(_db_active)
            except Exception:
                pass
            # Try resolver
            try:
                r = resolve_governance_db()
                if r:
                    names.append(r)
            except Exception:
                pass
            # Try CURRENT_DATABASE
            try:
                row = snowflake_connector.execute_query("select current_database() as DB") or []
                d = row[0].get("DB") if row else None
                if d:
                    names.append(d)
            except Exception:
                pass
            # Fallback to SHOW DATABASES (cap to first 10)
            if not names:
                try:
                    db_rows = snowflake_connector.execute_query("show databases") or []
                    names = [r.get("name") or r.get("NAME") for r in db_rows if (r.get("name") or r.get("NAME"))][:10]
                except Exception:
                    names = []
            seen = set()
            for n in names:
                if not n or n in seen:
                    continue
                seen.add(n)
                out.extend(_fetch_from_db(n, limit))

        # De-duplicate and cap
        out = list(dict.fromkeys(out))[:int(limit)]
        return out
    except Exception:
        return []

def _apply_tags(asset_full_name: str, cia: CIA, risk: str, who: str, rationale: str = "") -> None:
    """Apply standardized Snowflake tags and record audit."""
    c, i, a = cia.normalized()
    # Apply lowercase policy tags and uppercase legacy tags for compatibility
    tags_lower = {
        "data_classification": risk,
        "confidentiality_level": str(c),
        "integrity_level": str(i),
        "availability_level": str(a),
    }
    tags_upper = {
        "DATA_CLASSIFICATION": risk,
        "CONFIDENTIALITY_LEVEL": str(c),
        "INTEGRITY_LEVEL": str(i),
        "AVAILABILITY_LEVEL": str(a),
    }
    if not authz.can_apply_tags_for_object(asset_full_name, object_type="TABLE"):
        st.error("Insufficient privileges to apply tags (ALTER/OWNERSHIP required).")
        st.stop()
    tagging_service.apply_tags_to_object(asset_full_name, "TABLE", tags_lower)
    tagging_service.apply_tags_to_object(asset_full_name, "TABLE", tags_upper)
    # Record decision summary (DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_DECISIONS)
    try:
        # Use asset DB for persistence to avoid DB mismatch
        try:
            _asset_db = str(asset_full_name).split(".")[0].strip('"')
        except Exception:
            _asset_db = None
        classification_decision_service.record(
            asset_full_name=asset_full_name,
            decision_by=who or "system",
            source="MANUAL",
            status="Applied",
            label=risk,
            c=int(c), i=int(i), a=int(a),
            rationale=rationale or "",
            details=None,
            database=_asset_db,
        )
    except Exception:
        pass
    # Insert history row (CLASSIFICATION_HISTORY.CLASSIFICATION_HISTORY)
    try:
        # Prefer the asset's database
        try:
            _asset_db = str(asset_full_name).split(".")[0].strip('"')
        except Exception:
            _asset_db = None
        db = _asset_db or (_active_db_from_filter() if ('_active_db_from_filter' in globals() or '_active_db_from_filter' in dir()) else st.session_state.get('sf_database'))
        try:
            from src.services.governance_db_resolver import resolve_governance_db as _res_gov
            db = db or _res_gov()
        except Exception:
            pass
        if db:
            from uuid import uuid4 as _uuid4
            snowflake_connector.execute_non_query(
                f"""
                insert into {db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_HISTORY
                (HISTORY_ID, ASSET_ID, PREVIOUS_CLASSIFICATION, NEW_CLASSIFICATION,
                 PREVIOUS_CONFIDENTIALITY, NEW_CONFIDENTIALITY,
                 PREVIOUS_INTEGRITY, NEW_INTEGRITY,
                 PREVIOUS_AVAILABILITY, NEW_AVAILABILITY,
                 CHANGED_BY, CHANGE_TIMESTAMP, APPROVAL_REQUIRED)
                values (%(id)s, %(full)s, NULL, %(lbl)s,
                        NULL, %(c)s,
                        NULL, %(i)s,
                        NULL, %(a)s,
                        %(by)s, current_timestamp, FALSE)
                """,
                {
                    "id": str(_uuid4()),
                    "full": asset_full_name,
                    "by": who or "system",
                    "lbl": risk,
                    "c": int(c), "i": int(i), "a": int(a),
                    "cats": __import__("json").dumps([]),
                    "det": __import__("json").dumps({"via": "MANUAL"}),
                },
            )
    except Exception:
        pass
    # Audit trail (service and governance table)
    audit_service.log(who or "system", "CLASSIFY_APPLY", "ASSET", asset_full_name,
                      {"risk": risk, "c": c, "i": i, "a": a, "rationale": rationale})
    try:
        _sf_audit_log_classification(asset_full_name, "MANUAL_APPLY", {"label": risk, "C": c, "I": i, "A": a, "rationale": rationale})
    except Exception:
        pass

def _sla_due(created_at: datetime, business_days: int = 5) -> datetime:
    days = 0
    cur = created_at
    while days < business_days:
        cur += timedelta(days=1)
        if cur.weekday() < 5:
            days += 1
    return cur

def _coverage_and_overdue() -> Tuple[pd.DataFrame, Dict[str, int]]:
    db = _get_current_db()
    if not db:
        return pd.DataFrame(), {"total": 0, "classified": 0, "overdue": 0}
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT 
              FULLY_QUALIFIED_NAME AS FULL_NAME,
              COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP) AS FIRST_DISCOVERED,
              (CLASSIFICATION_LABEL IS NOT NULL) AS CLASSIFIED,
              NULL AS CIA_CONF, NULL AS CIA_INT, NULL AS CIA_AVAIL
            FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
            ORDER BY COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP) DESC
            LIMIT 5000
            """
        ) or []
        df = pd.DataFrame(rows)
        if not df.empty:
            df["FIRST_DISCOVERED_DT"] = pd.to_datetime(df.get("FIRST_DISCOVERED"))
            df["DUE_BY"] = df["FIRST_DISCOVERED_DT"].apply(lambda d: _sla_due(d) if pd.notnull(d) else pd.NaT)
            now = datetime.utcnow()
            df["OVERDUE"] = (~df["CLASSIFIED"].fillna(False)) & (pd.to_datetime(df["DUE_BY"]).dt.tz_localize(None) < now)
        total = int(len(df))
        classified = int(df["CLASSIFIED"].fillna(False).sum()) if not df.empty else 0
        overdue = int(df["OVERDUE"].sum()) if not df.empty and "OVERDUE" in df.columns else 0
        return df, {"total": total, "classified": classified, "overdue": overdue}
    except Exception:
        return pd.DataFrame(), {"total": 0, "classified": 0, "overdue": 0}

# ---------------------------
# UI Panels
# ---------------------------
def _stepper_ui():
    st.subheader("Core Workflow (Classification Center)")
    tables = _list_tables(limit=300)
    asset = st.selectbox("Select data asset", options=tables if tables else ["No assets available"], index=0)
    if not asset or asset == "No assets available":
        st.info("Select an asset to continue the workflow.")
        return

    st.markdown("---")
    st.markdown("### Step 1: Business Context Assessment")
    with st.expander("Business Context", expanded=True):
        purpose = st.text_area("Purpose of the data", placeholder="Describe business purpose and usage")
        value = st.text_area("Business value", placeholder="Describe value (e.g., supports reporting, critical ops)")
        stakeholders = st.text_input("Key stakeholders", placeholder="Owners, SMEs, consumers")

    st.markdown("---")
    st.markdown("### Step 2: Confidentiality Assessment (C0–C3)")
    with st.expander("Confidentiality", expanded=True):
        c_q1 = st.selectbox("Would unauthorized disclosure cause harm?", ["No/Minimal", "Some", "Material", "Severe"], index=1)
        c_q2 = st.selectbox("Contains PII/financial/proprietary?", ["No", "Possible", "Likely", "Yes"], index=0)
        c_q3 = st.selectbox("Regulatory requirements present?", ["None", "Some", "Multiple", "Strict"], index=0)
        c_val = max(["No/Minimal","Some","Material","Severe"].index(c_q1),
                    ["No","Possible","Likely","Yes"].index(c_q2),
                    ["None","Some","Multiple","Strict"].index(c_q3))
        st.caption(f"Selected Confidentiality level: C{c_val}")

    st.markdown("---")
    st.markdown("### Step 3: Integrity Assessment (I0–I3)")
    with st.expander("Integrity", expanded=True):
        i_q1 = st.selectbox("How critical is accuracy to operations?", ["Low", "Moderate", "High", "Critical"], index=1)
        i_q2 = st.selectbox("Impact if data is corrupted?", ["Minor", "Moderate", "Major", "Severe"], index=1)
        i_val = max(["Low","Moderate","High","Critical"].index(i_q1),
                    ["Minor","Moderate","Major","Severe"].index(i_q2))
        st.caption(f"Selected Integrity level: I{i_val}")

    st.markdown("---")
    st.markdown("### Step 4: Availability Assessment (A0–A3)")
    with st.expander("Availability", expanded=True):
        a_q1 = st.selectbox("How quickly must data be accessible?", ["Days+", "Hours", "< 1 hour", "Near-realtime"], index=1)
        a_q2 = st.selectbox("Impact if unavailable?", ["Minor", "Moderate", "Major", "Severe"], index=1)
        a_val = max(["Days+","Hours","< 1 hour","Near-realtime"].index(a_q1),
                    ["Minor","Moderate","Major","Severe"].index(a_q2))
        st.caption(f"Selected Availability level: A{a_val}")

    st.markdown("---")
    st.markdown("### Step 5: Overall Risk Classification (Section 5.3)")
    cia = CIA(c=c_val, i=i_val, a=a_val)
    risk = cia.risk_level()
    ok_dm, reasons = dm_validate(risk, cia.c, cia.i, cia.a)
    cols = st.columns(4)
    cols[0].metric("Confidentiality", f"C{cia.c}")
    cols[1].metric("Integrity", f"I{cia.i}")
    cols[2].metric("Availability", f"A{cia.a}")
    cols[3].metric("Risk", risk)
    if not ok_dm and reasons:
        for r in reasons:
            st.error(r)
        st.stop()

    st.markdown("---")
    st.markdown("### Step 6: Documentation & Approval")
    rationale = st.text_area("Rationale (required)", placeholder="Explain the decision per policy and context")
    user_email = st.text_input("Your email (for audit)")
    requires_approval = (risk == "High")
    col_apply, col_submit = st.columns(2)
    with col_submit:
        if st.button("Submit for Review/Approval", type="primary"):
            if not user_email:
                st.warning("Enter your email.")
                st.stop()
            if not rationale or not rationale.strip():
                st.warning("Rationale is required.")
                st.stop()
            # Ensure DB context to avoid 'Database NONE' errors
            try:
                _db_ctx = asset.split('.')[0] if (isinstance(asset, str) and '.' in asset) else (_active_db_from_filter() or st.session_state.get('sf_database'))
                if _db_ctx:
                    snowflake_connector.execute_non_query(f"USE DATABASE {_db_ctx}")
                    st.session_state['sf_database'] = _db_ctx
            except Exception:
                pass
            rid = reclassification_service.submit_request(
                asset_full_name=asset,
                proposed=(risk, cia.c, cia.i, cia.a),
                justification=rationale,
                created_by=user_email,
                trigger_type="MANUAL_HIGH_RISK" if requires_approval else "MANUAL",
            )
            audit_service.log(user_email, "CLASSIFY_SUBMIT", "ASSET", asset,
                              {"risk": risk, "c": cia.c, "i": cia.i, "a": cia.a, "rationale": rationale, "request_id": rid})
            st.success(f"Submitted for {'approval' if requires_approval else 'review'}: {rid}")
    with col_apply:
        if st.button("Apply Classification Now"):
            if not user_email:
                st.warning("Enter your email.")
                st.stop()
            if not rationale or not rationale.strip():
                st.warning("Rationale is required.")
                st.stop()
            if requires_approval and not authz.can_approve_tags(authz.get_current_identity()):
                st.warning("High-risk requires approval; submitting request instead.")
                # Ensure DB context before submitting request
                try:
                    _db_ctx2 = asset.split('.')[0] if (isinstance(asset, str) and '.' in asset) else (_active_db_from_filter() or st.session_state.get('sf_database'))
                    if _db_ctx2:
                        snowflake_connector.execute_non_query(f"USE DATABASE {_db_ctx2}")
                        st.session_state['sf_database'] = _db_ctx2
                except Exception:
                    pass
                rid = reclassification_service.submit_request(
                    asset_full_name=asset,
                    proposed=(risk, cia.c, cia.i, cia.a),
                    justification=rationale,
                    created_by=user_email,
                    trigger_type="MANUAL_HIGH_RISK",
                )
                st.success(f"Submitted for approval: {rid}")
                st.stop()
            _apply_tags(asset, cia, risk, who=user_email, rationale=rationale)
            st.success("Classification applied and audited.")

def _ai_assistance_panel():
    st.subheader("AI Assistance (Sensitive Asset Detection)")
    # Resolve active DB from Global Filters/session
    db = _active_db_from_filter() or _get_current_db()
    if not db:
        st.info("Select a database from the 🌐 Global Filters to enable detection.")
        return

    # Track DB in session to trigger refresh on change
    prev_db = st.session_state.get("_ai_detect_prev_db")
    if prev_db and prev_db != db:
        # Clear cached results when DB changes
        st.session_state.pop("ai_detect", None)
    st.session_state["_ai_detect_prev_db"] = db

    # Container state for detections
    ai_ss = st.session_state.setdefault("ai_detect", {"db": db, "tables": pd.DataFrame(), "columns": {}})
    ai_ss["db"] = db

    # Ensure dynamic sensitivity config is loaded and available in session
    try:
        cfg = ai_classification_service.load_sensitivity_config()
        try:
            st.session_state["sensitivity_config"] = cfg
        except Exception:
            pass
    except Exception:
        cfg = {}

    # Admin control: seed sensitivity config and refresh in-memory cache
    with st.expander("Admin: Seed Sensitivity Config", expanded=False):
        seed_db = st.text_input("Target Database (optional)", value=st.session_state.get("sf_database") or "", key="seed_db_aiassist")
        if st.button("Run Seed and Refresh", key="btn_seed_refresh_aiassist"):
            try:
                if seed_db and seed_db.strip():
                    snowflake_connector.execute_non_query(f"USE DATABASE {seed_db}")
                path = os.path.join(_project_root, "sql", "011_seed_sensitivity_config.sql")
                with open(path, "r", encoding="utf-8") as f:
                    sql_text = f.read()
                for stmt in [s.strip() for s in sql_text.split(";") if s.strip()]:
                    snowflake_connector.execute_non_query(stmt)
                try:
                    ai_classification_service.load_sensitivity_config(force_refresh=True)
                except Exception:
                    pass
                st.success("Seed executed and configuration refreshed.")
            except Exception as e:
                st.error(f"Seed execution failed: {e}")

    # Controls
    c1, c2, c3, c4 = st.columns([1.2, 1, 1, 1])
    with c1:
        limit = st.slider("Max tables", 10, 1000, 200, 10, key="ai_max_tables")
    with c2:
        sample = st.slider("Sample size/col", 10, 200, 30, 10, key="ai_sample_size")
    with c3:
        refresh = st.button("Detect in Selected DB", type="primary", key="btn_detect_db")
    with c4:
        clear = st.button("Clear Results", key="btn_clear_ai_detect")

    if clear:
        st.session_state.pop("ai_detect", None)
        st.experimental_rerun()

    # Helper: build detection DF using dynamic catalog + exclusions + live AI
    def _run_detection(db_name: str, max_rows: int, sample_size: int) -> pd.DataFrame:
        # 1) Candidate tables from governed ASSETS
        try:
            rows = snowflake_connector.execute_query(
                f"""
                select DATABASE_NAME||'.'||SCHEMA_NAME||'.'||TABLE_NAME as FULL_NAME
                from {{db}}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                where coalesce(IS_ACTIVE, true) and upper(DATABASE_NAME)=upper(%(db)s)
                order by coalesce(RISK_SCORE,0) desc, coalesce(ROW_COUNT,0) desc, coalesce(LAST_MODIFIED_DATE, to_timestamp_ntz('1970-01-01')) desc, 1
                limit %(lim)s
                """.replace('{db}', db_name),
                {"db": db_name, "lim": int(max_rows)},
            ) or []
            candidates = [str(r.get("FULL_NAME")) for r in rows if r.get("FULL_NAME")]
        except Exception:
            candidates = []

        # 2) Dynamic exclusions
        exclude_tokens: Set[str] = set()
        exclude_exact: Set[str] = set()
        try:
            kws = (cfg.get("keywords") or [])
            for it in kws:
                try:
                    if str(it.get("category")).upper() == "EXCLUDE_TABLE_TOKEN":
                        tok = str(it.get("token") or it.get("keyword") or "").strip().upper()
                        if tok:
                            exclude_tokens.add(tok)
                except Exception:
                    continue
        except Exception:
            pass
        # Governance SENSITIVE_EXCLUSIONS (best-effort: support EXCLUDE_PATTERN or TABLE_NAME/FULL_NAME)
        try:
            gv_db = resolve_governance_db() or db_name
            rows = snowflake_connector.execute_query(
                f"""
                select coalesce(FULL_NAME, TABLE_NAME) as NAME, EXCLUDE_PATTERN
                from {gv_db}.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_EXCLUSIONS
                """
            ) or []
            for r in rows:
                nm = (r.get("NAME") or "").strip()
                pat = (r.get("EXCLUDE_PATTERN") or "").strip()
                if nm:
                    exclude_exact.add(nm.upper())
                if pat:
                    exclude_tokens.add(pat.upper())
        except Exception:
            pass

        def _excluded(fqn: str) -> bool:
            up = (fqn or "").upper()
            if up in exclude_exact:
                return True
            return any(tok and tok in up for tok in exclude_tokens)

        tables = [t for t in candidates if not _excluded(t)]
        if not tables:
            return pd.DataFrame(columns=[
                'Table Name','Detected Sensitivity Types','Row Count','AI_C','AI_I','AI_A','Compliance','_FQN'
            ])

        det_rows = []
        for fq in tables:
            # 3) Live detection per table
            try:
                col_rows = ai_classification_service.detect_sensitive_columns(fq, sample_size=sample_size) or []
            except Exception:
                col_rows = []
            # Aggregate table-level
            agg = ai_classification_service.aggregate_table_sensitivity(col_rows) if col_rows else {"table_sensitivity_score": 0.0, "dominant_table_category": None, "table_categories": []}
            # Table CIA as max across columns
            tC = max([int((r.get('suggested_cia') or {}).get('C', 0)) for r in (col_rows or [])] + [0])
            tI = max([int((r.get('suggested_cia') or {}).get('I', 0)) for r in (col_rows or [])] + [0])
            tA = max([int((r.get('suggested_cia') or {}).get('A', 0)) for r in (col_rows or [])] + [0])
            # Compliance mapping from dominant categories
            try:
                dom = agg.get('dominant_table_category')
                frameworks = ai_classification_service.map_compliance_categories(dom) if dom else []
            except Exception:
                frameworks = []
            # Persist audit and AI outputs
            try:
                table_metrics = {
                    "table_sensitivity_score": agg.get("table_sensitivity_score"),
                    "dominant_table_category": agg.get("dominant_table_category"),
                    "table_categories": agg.get("table_categories"),
                    "sensitive_columns_count": len(col_rows or []),
                    "table_cia_minimum": f"C{tC}/I{tI}/A{tA}",
                    "compliance_frameworks": frameworks,
                }
                ai_classification_service.persist_scan_results(fq, col_rows, table_metrics, sample_info={"sampling_method": "auto", "sample_size": int(sample_size)})
            except Exception:
                # best-effort; also log via audit_service
                try:
                    audit_service.log("UI", "PERSIST_FAIL", {"table": fq})
                except Exception:
                    pass

            det_rows.append({
                'Table Name': fq,
                'Detected Sensitivity Types': ','.join(sorted({c for d in (col_rows or []) for c in (d.get('categories') or [])})) if col_rows else '',
                'Row Count': None,
                'AI_C': tC,
                'AI_I': tI,
                'AI_A': tA,
                'Compliance': ",".join(frameworks) if frameworks else '',
                '_FQN': fq,
                '_columns': col_rows,
            })
        return pd.DataFrame(det_rows)

    # Run detection when requested or when no cached results
    if refresh or ai_ss.get("tables") is None or ai_ss.get("tables").empty:
        with st.spinner(f"Detecting sensitive tables in {db}…"):
            tdf = _run_detection(db, int(limit), int(sample))
            # Persist tables and per-table columns
            cols_map = {}
            for _, row in tdf.iterrows():
                cols_map[row['_FQN']] = row.get('_columns') or []
            ai_ss['tables'] = tdf.drop(columns=['_columns']) if not tdf.empty else tdf
            ai_ss['columns'] = cols_map

    tdf = ai_ss.get('tables') if isinstance(ai_ss.get('tables'), pd.DataFrame) else pd.DataFrame()
    if tdf.empty:
        st.info("No tables detected or ASSETS table unavailable.")
        return

    # Interactive table
    st.markdown("### Detected Sensitive Tables")
    st.dataframe(
        tdf[[
            'Table Name','Detected Sensitivity Types','AI_C','AI_I','AI_A','Compliance'
        ]],
        use_container_width=True,
        hide_index=True,
    )

    # Select table for column-level drilldown
    sel_tbl = st.selectbox("Action: View column details", options=tdf['Table Name'].tolist())
    if not sel_tbl:
        return

    # Build column-level DataFrame; display live detection outputs
    raw_cols = ai_ss.get('columns', {}).get(sel_tbl, []) or []
    col_rows = []
    for c in raw_cols:
        cname = c.get('column') or c.get('name')
        ctype = c.get('type') or c.get('data_type') or ''
        cats = ','.join(sorted(c.get('categories') or []))
        cia = c.get('suggested_cia') or {"C": 0, "I": 0, "A": 0}
        col_rows.append({
            'Column': cname,
            'Data Type': ctype,
            'Categories': cats,
            'Dominant': c.get('dominant_category'),
            'Confidence': int(c.get('confidence') or 0),
            'CIA': f"C{int(cia.get('C',0))}/I{int(cia.get('I',0))}/A{int(cia.get('A',0))}",
            'BundleBoost': bool(c.get('bundle_boost', False)),
            'Bundles': ",".join([str(x) for x in (c.get('bundles_detected') or [])]),
        })
    cols_df = pd.DataFrame(col_rows)

    st.markdown("### Column-Level Detection (live)")
    st.dataframe(
        cols_df,
        use_container_width=True,
        hide_index=True,
    )
    # Only show live detection; skip legacy editing UI
    return

    # Table-level suggestion (max across columns) with policy check
    if not edited_df.empty:
        try:
            tC = int(edited_df['C'].max()); tI = int(edited_df['I'].max()); tA = int(edited_df['A'].max())
        except Exception:
            tC = tI = tA = 0
        tLabel = 'Confidential' if tC >= 3 else ('Restricted' if tC >= 2 else ('Internal' if tC >= 1 else 'Public'))

        st.markdown("**Table-level Classification (editable)**")
        table_edit = st.data_editor(
            pd.DataFrame([{'Table Name': sel_tbl, 'Label': tLabel, 'C': tC, 'I': tI, 'A': tA}]),
            use_container_width=True,
            hide_index=True,
            num_rows="fixed",
            column_config={
                'Table Name': st.column_config.TextColumn(disabled=True),
                'Label': st.column_config.SelectboxColumn(options=["Public","Internal","Restricted","Confidential"]),
                'C': st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
                'I': st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
                'A': st.column_config.NumberColumn(min_value=0, max_value=3, step=1),
            },
            key=f"tbl_edit_{sel_tbl}",
        )
        try:
            tLabel = str(table_edit.iloc[0]['Label']); tC = int(table_edit.iloc[0]['C']); tI = int(table_edit.iloc[0]['I']); tA = int(table_edit.iloc[0]['A'])
        except Exception:
            pass

        # Policy validation summary
        try:
            tagging_service.validate_tags({
                'DATA_CLASSIFICATION': tLabel,
                'CONFIDENTIALITY_LEVEL': str(tC),
                'INTEGRITY_LEVEL': str(tI),
                'AVAILABILITY_LEVEL': str(tA),
            })
            tagging_service._enforce_policy_minimums(sel_tbl, {
                'DATA_CLASSIFICATION': tLabel,
                'CONFIDENTIALITY_LEVEL': str(tC),
            })
            st.success("Table classification passes policy validation.")
        except Exception as e:
            st.warning(f"Table policy: {e}")

        # Column-level policy issues
        issues = []
        for _, row in edited_df.iterrows():
            try:
                tagging_service.validate_tags({
                    'DATA_CLASSIFICATION': row['Label'],
                    'CONFIDENTIALITY_LEVEL': str(int(row['C'])),
                    'INTEGRITY_LEVEL': str(int(row['I'])),
                    'AVAILABILITY_LEVEL': str(int(row['A'])),
                })
                tagging_service._enforce_policy_minimums(sel_tbl, {
                    'DATA_CLASSIFICATION': row['Label'],
                    'CONFIDENTIALITY_LEVEL': str(int(row['C'])),
                })
            except Exception as e:
                issues.append({'column': row['Column Name'], 'error': str(e)})
        if issues:
            st.error({'policy_issues': issues})
        else:
            st.info("All column suggestions meet minimum policy requirements.")

        # Apply actions
        if st.button("Apply classification and log audit", key=f"apply_{sel_tbl}"):
            apply_errors = []
            user_id = str(st.session_state.get('user') or 'system')
            try:
                tagging_service.apply_tags_to_object(sel_tbl, "TABLE", {
                    'DATA_CLASSIFICATION': tLabel,
                    'CONFIDENTIALITY_LEVEL': str(tC),
                    'INTEGRITY_LEVEL': str(tI),
                    'AVAILABILITY_LEVEL': str(tA),
                })
                classification_decision_service.record(
                    asset_full_name=sel_tbl,
                    decision_by=user_id,
                    source="UI",
                    status="Applied",
                    label=tLabel,
                    c=int(tC), i=int(tI), a=int(tA),
                    rationale="AI Assistant submission",
                    details={'source': 'AI Assistant'},
                )
                audit_service.log(user_id, "UI_APPLY", "ASSET", sel_tbl, {"label": tLabel, "C": tC, "I": tI, "A": tA})
            except Exception as e:
                apply_errors.append(f"TABLE: {e}")

            for _, row in edited_df.iterrows():
                try:
                    tagging_service.apply_tags_to_column(sel_tbl, row['Column Name'], {
                        'DATA_CLASSIFICATION': row['Label'],
                        'CONFIDENTIALITY_LEVEL': str(int(row['C'])),
                        'INTEGRITY_LEVEL': str(int(row['I'])),
                        'AVAILABILITY_LEVEL': str(int(row['A'])),
                    })
                    classification_decision_service.record(
                        asset_full_name=f"{sel_tbl}.{row['Column Name']}",
                        decision_by=user_id,
                        source="UI",
                        status="Applied",
                        label=row['Label'],
                        c=int(row['C']), i=int(row['I']), a=int(row['A']),
                        rationale="AI Assistant submission",
                        details={'source': 'AI Assistant'},
                    )
                    audit_service.log(user_id, "UI_APPLY", "COLUMN", f"{sel_tbl}.{row['Column Name']}", {
                        'label': row['Label'], 'C': int(row['C']), 'I': int(row['I']), 'A': int(row['A'])
                    })
                except Exception as e:
                    apply_errors.append(f"{row['Column Name']}: {e}")

            if apply_errors:
                st.error({'apply_errors': apply_errors})
            else:
                st.success("Classification applied and logged.")
    with c2:
        if st.button("Get Recommendation"):
            try:
                _ctx = None
                try:
                    _ctx = ai_classification_service.build_enriched_context(asset, sample_rows=10)
                except Exception:
                    _ctx = None
                res = ai_classification_service.classify_table(asset, context=_ctx)
                st.success(f"Suggested: {res.get('classification')} | Confidence: {res.get('confidence')}")
                st.json({k: v for k, v in res.items() if k != 'features'})
            except Exception as e:
                st.error(f"Recommendation failed: {e}")

def _bulk_classification_panel():
    st.subheader("Bulk Classification")
    st.caption("Upload CSV with columns: FULL_NAME, C, I, A; optional: RATIONALE")
    f = st.file_uploader("Upload template (CSV)", type=["csv"], key="bulk_csv_center")
    dry_run = st.checkbox("Dry run (validate only)", value=True)
    if not f:
        return
    try:
        df = pd.read_csv(f)
    except Exception as e:
        st.error(f"Failed to read CSV: {e}")
        return
    st.dataframe(df.head(20), use_container_width=True)
    missing = [c for c in ["FULL_NAME","C","I","A"] if c not in [x.upper() for x in df.columns]]
    if missing:
        st.error(f"Missing required columns: {', '.join(missing)}")
        return
    df.columns = [c.upper() for c in df.columns]
    errors = []
    processed = 0
    if st.button("Process Bulk", type="primary"):
        for _, row in df.iterrows():
            full = str(row.get("FULL_NAME",""))
            try:
                c = int(row.get("C")); i = int(row.get("I")); a = int(row.get("A"))
            except Exception:
                errors.append(f"{full}: C/I/A must be integers 0..3")
                continue
            if not (0 <= c <= 3 and 0 <= i <= 3 and 0 <= a <= 3):
                errors.append(f"{full}: C/I/A must be within 0..3")
                continue
            risk = CIA(c, i, a).risk_level()
            ok_dm, reasons = dm_validate(risk, c, i, a)
            if not ok_dm:
                errors.extend([f"{full}: {r}" for r in reasons or []])
                continue
            if dry_run:
                processed += 1
                continue
            try:
                _apply_tags(full, CIA(c, i, a), risk, who=st.session_state.get("user") or "bulk@system", rationale=str(row.get("RATIONALE") or "Bulk classification"))
                processed += 1
            except Exception as e:
                errors.append(f"{full}: {e}")
        if dry_run:
            st.info(f"Dry run OK. {processed} row(s) validated. {len(errors)} error(s).")
        else:
            st.success(f"Processed {processed} row(s). {len(errors)} error(s).")
        if errors:
            st.error("\n".join(errors[:50]))
        st.caption("Reminder: Review all bulk-classified assets within 5 business days (SLA).")

def _management_panel():
    st.subheader("Classification Management")

    # --- Sub-tab functional components (placeholders wired to existing logic) ---
    def render_my_classification_tasks():
        st.caption("My Tasks: Assigned, Draft, Pending My Review")

        # Defaults
        try:
            from datetime import date
        except Exception:
            pass

        # Load inventory tasks (unclassified assets) and reclassification requests
        def _load_task_queue(limit_assets: int = 500, limit_reqs: int = 300):
            items = []
            # Unclassified assets as tasks
            try:
                db = _get_current_db()
                if db:
                    inv = snowflake_connector.execute_query(
                        f"""
                        SELECT 
                          FULLY_QUALIFIED_NAME AS FULL_NAME,
                          BUSINESS_UNIT AS OBJECT_DOMAIN,
                          COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP) AS FIRST_DISCOVERED,
                          (CLASSIFICATION_LABEL IS NOT NULL) AS CLASSIFIED
                        FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                        ORDER BY COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP) DESC
                        LIMIT {int(limit_assets)}
                        """
                    ) or []
                    for r in inv:
                        full = r.get("FULL_NAME")
                        if not full:
                            continue
                        classified = bool(r.get("CLASSIFIED"))
                        if classified:
                            continue
                        fd = pd.to_datetime(r.get("FIRST_DISCOVERED")) if r.get("FIRST_DISCOVERED") else None
                        due_by = _sla_due(fd.tz_localize(None) if isinstance(fd, pd.Timestamp) else datetime.utcnow()) if fd is not None else _sla_due(datetime.utcnow())
                        days_left = (due_by - datetime.utcnow()).days
                        priority = "High" if days_left < 0 else ("Medium" if days_left <= 2 else "Low")
                        status = "New"
                        items.append({
                            "Asset Name": full,
                            "Type": r.get("OBJECT_DOMAIN") or "TABLE",
                            "Due Date": due_by.date(),
                            "Priority": priority,
                            "Status": status,
                            "Source": "Inventory",
                        })
            except Exception:
                pass
            # Reclassification requests as tasks
            try:
                reqs = reclassification_service.list_requests(limit=int(limit_reqs)) or []
                for r in reqs:
                    full = r.get("ASSET_FULL_NAME") or r.get("ASSET") or r.get("FULL_NAME")
                    if not full:
                        continue
                    created = pd.to_datetime(r.get("CREATED_AT") or r.get("CREATED"), errors='coerce')
                    due_by = _sla_due((created.to_pydatetime() if isinstance(created, pd.Timestamp) else datetime.utcnow())) if created is not None else _sla_due(datetime.utcnow())
                    days_left = (due_by - datetime.utcnow()).days
                    priority = "High" if days_left < 0 else ("Medium" if days_left <= 2 else "Low")
                    status = r.get("STATUS") or r.get("state") or "In Progress"
                    items.append({
                        "Asset Name": full,
                        "Type": r.get("OBJECT_TYPE") or "TABLE",
                        "Due Date": due_by.date(),
                        "Priority": priority,
                        "Status": status,
                        "Source": "Reclassification",
                        "Request ID": r.get("ID"),
                    })
            except Exception:
                pass
            return pd.DataFrame(items)

        # Filters UI
        f1, f2, f3, f4 = st.columns([1.5, 1.8, 1.2, 1.5])
        with f1:
            due_bucket = st.selectbox(
                "Due Date",
                options=["All", "Overdue", "Due this week", "Future"],
                index=0,
                key="tasks_due_bucket",
            )
        with f2:
            task_type = st.multiselect(
                "Task Type",
                options=["Initial Classification", "Reclassification", "Annual Review"],
                default=[],
                key="tasks_task_type",
            )
        with f3:
            priority_filter = st.multiselect(
                "Priority",
                options=["Critical", "High", "Normal"],
                default=[],
                key="tasks_priority_new",
            )
        with f4:
            assignment_status = st.selectbox(
                "Assignment Status",
                options=["All", "Assigned to me", "Unassigned"],
                index=0,
                key="tasks_assignment",
            )

        df = _load_task_queue()
        if not df.empty:
            # Compute derived fields required by filters
            try:
                ident = authz.get_current_identity()
                ident_user = getattr(ident, "user", "") or ""
            except Exception:
                ident_user = ""
            me = str(st.session_state.get("user") or ident_user).lower()
            now = datetime.utcnow()

            # Due bucket
            def _due_bucket(d):
                try:
                    d0 = pd.to_datetime(d).to_pydatetime()
                except Exception:
                    return "Future"
                if d0.date() < now.date():
                    return "Overdue"
                # This week: within 7 days ahead (Mon-Sun rolling)
                if (d0 - now).days <= 7:
                    return "Due this week"
                return "Future"

            # Task Type
            def _task_type(row):
                src = str(row.get("Source") or "")
                if src == "Reclassification":
                    return "Reclassification"
                # Heuristic: annual review if due date > 30 days in future for classified assets in other views
                try:
                    due = pd.to_datetime(row.get("Due Date")).to_pydatetime()
                    if (due - now).days > 300:
                        return "Annual Review"
                except Exception:
                    pass
                return "Initial Classification"

            # Priority mapping to requested scale
            def _priority_map(p):
                if str(p) == "High":
                    return "Critical"
                if str(p) == "Medium":
                    return "High"
                return "Normal"

            # Assignment
            def _assignment(row):
                created_by = str(row.get("Created By") or row.get("CREATED_BY") or "").lower()
                if created_by and me and created_by == me:
                    return "Assigned to me"
                # Inventory tasks have no assignee
                return "Unassigned"

            df = df.copy()
            # Bring over creator info for reclass requests if available
            if "Request ID" in df.columns and "Created By" not in df.columns:
                # try to fetch created_by from reclassification_service in bulk is expensive; best-effort keep blank
                df["Created By"] = None
            df["Due Bucket"] = df["Due Date"].apply(_due_bucket)
            df["Task Type"] = df.apply(_task_type, axis=1)
            df["Priority2"] = df["Priority"].apply(_priority_map)
            df["Assignment"] = df.apply(_assignment, axis=1)

            # Apply filters
            if due_bucket != "All":
                df = df[df["Due Bucket"] == due_bucket]
            if task_type:
                df = df[df["Task Type"].isin(task_type)]
            if priority_filter:
                df = df[df["Priority2"].isin(priority_filter)]
            if assignment_status != "All":
                df = df[df["Assignment"] == assignment_status]

            # Style priority
            def _style_priority(val):
                # Map for new scale: Critical (red), High (amber), Normal (green)
                v = str(val)
                if v == "Critical":
                    color = "#ef4444"
                elif v == "High":
                    color = "#f59e0b"
                else:
                    color = "#10b981"
                return f"color: {color}; font-weight: 700;"
            styler = df[["Asset Name","Type","Due Date","Priority2","Assignment","Task Type","Status"]].rename(columns={"Priority2":"Priority"}).style.applymap(_style_priority, subset=["Priority"]).hide(axis="index")
            st.dataframe(styler, use_container_width=True)

            # Quick actions
            sel_asset = st.selectbox("Select a task", options=df["Asset Name"].tolist(), key="tasks_sel_asset")
            a1, a2 = st.columns(2)
            with a1:
                if st.button("Classify", type="primary", key="tasks_btn_classify") and sel_asset:
                    st.session_state["task_wizard_asset"] = sel_asset
                    try:
                        st.experimental_set_query_params(sub="tasks", action="classify", asset=sel_asset)
                    except Exception:
                        pass
                    # Removed st.rerun() to prevent no-op warning
            with a2:
                if st.button("View Details", key="tasks_btn_view") and sel_asset:
                    st.info(f"Details for {sel_asset} coming soon. Request/Inventory drill-down will appear here.")
        else:
            st.info("No tasks found.")

        # Wizard (conditional "modal" area)
        try:
            q = st.experimental_get_query_params() or {}
        except Exception:
            q = {}
        action = (q.get("action") or [None])[0]
        asset_q = (q.get("asset") or [None])[0]
        target_asset = st.session_state.get("task_wizard_asset") or asset_q

        if action == "classify" or target_asset:
            st.markdown("---")
            st.subheader(f"Classification Wizard — {target_asset}")
            with st.form(key="task_wizard_form", clear_on_submit=False):
                # Step A: Confidentiality
                st.markdown("### Step 1: Confidentiality Assessment (C0–C3)")
                c_q1 = st.selectbox("Unauthorized disclosure impact", ["No/Minimal","Some","Material","Severe"], index=1, key="wiz_cq1")
                c_q2 = st.selectbox("Contains sensitive data (PII/financial/proprietary)", ["No","Possible","Likely","Yes"], index=0, key="wiz_cq2")
                c_q3 = st.selectbox("Regulatory requirements present", ["None","Some","Multiple","Strict"], index=0, key="wiz_cq3")
                c_val = max(["No/Minimal","Some","Material","Severe"].index(c_q1), ["No","Possible","Likely","Yes"].index(c_q2), ["None","Some","Multiple","Strict"].index(c_q3))

                # Step B: Integrity
                st.markdown("### Step 2: Integrity Assessment (I0–I3)")
                i_q1 = st.selectbox("Accuracy criticality to operations", ["Low","Moderate","High","Critical"], index=1, key="wiz_iq1")
                i_q2 = st.selectbox("Impact if data is corrupted", ["Minor","Moderate","Major","Severe"], index=1, key="wiz_iq2")
                i_val = max(["Low","Moderate","High","Critical"].index(i_q1), ["Minor","Moderate","Major","Severe"].index(i_q2))

                # Step C: Availability
                st.markdown("### Step 3: Availability Assessment (A0–A3)")
                a_q1 = st.selectbox("Required accessibility timeframe", ["Days+","Hours","< 1 hour","Near-realtime"], index=1, key="wiz_aq1")
                a_q2 = st.selectbox("Impact if unavailable", ["Minor","Moderate","Major","Severe"], index=1, key="wiz_aq2")
                a_val = max(["Days+","Hours","< 1 hour","Near-realtime"].index(a_q1), ["Minor","Moderate","Major","Severe"].index(a_q2))

                cia = CIA(c=c_val, i=i_val, a=a_val)
                highest = max(c_val, i_val, a_val)
                allowed = globals().get("ALLOWED_CLASSIFICATIONS") or ["Public","Internal","Restricted","Confidential"]
                label = ["Public","Internal","Restricted","Confidential"][highest]
                ok_dm, reasons = dm_validate(label if label in allowed else "Internal", int(c_val), int(i_val), int(a_val))
                cols = st.columns(4)
                cols[0].metric("Confidentiality", f"C{c_val}")
                cols[1].metric("Integrity", f"I{i_val}")
                cols[2].metric("Availability", f"A{a_val}")
                cols[3].metric("Classification", label)
                if not ok_dm and reasons:
                    for r in reasons:
                        st.error(r)

                st.markdown("### Rationale & Collaboration")
                rationale = st.text_area("Business rationale (required)", placeholder="Explain policy-driven decision and context", key="wiz_rationale")
                # @mention selector (best-effort): read list from session or fallback to free text
                suggest_users = st.session_state.get("directory_users", ["dcls.specialist@company.com", "data.owner@company.com"]) or []
                mentions = st.multiselect("@Mention specialists (optional)", options=suggest_users, default=[], key="wiz_mentions")
                request_review = st.checkbox("Request review for complex case", value=False, key="wiz_review")

                c1, c2, c3 = st.columns(3)
                with c1:
                    save_draft = st.form_submit_button("Save as Draft")
                with c2:
                    submit = st.form_submit_button("Submit", type="primary")
                with c3:
                    cancel = st.form_submit_button("Cancel")

            # Handle form actions
            if 'submit' in locals() and submit:
                if not rationale or not rationale.strip():
                    st.warning("Rationale is required.")
                else:
                    try:
                        # Ensure DB context and normalize asset FQN
                        _db_ctx_w = _active_db_from_filter() or st.session_state.get('sf_database')
                        _asset_fqn = target_asset
                        if isinstance(target_asset, str) and target_asset.count('.') == 1 and _db_ctx_w:
                            _asset_fqn = f"{_db_ctx_w}.{target_asset}"
                        if _db_ctx_w:
                            snowflake_connector.execute_non_query(f"USE DATABASE {_db_ctx_w}")
                            st.session_state['sf_database'] = _db_ctx_w
                        rid = reclassification_service.submit_request(
                            asset_full_name=_asset_fqn,
                            proposed=(label, int(c_val), int(i_val), int(a_val)),
                            justification=rationale,
                            created_by=st.session_state.get("user") or "wizard@system",
                            trigger_type="MANUAL_REVIEW" if request_review else "MANUAL",
                        )
                        audit_service.log(st.session_state.get("user") or "wizard@system", "CLASSIFY_SUBMIT", "ASSET", target_asset, {"label": label, "c": c_val, "i": i_val, "a": a_val, "mentions": mentions, "request_review": request_review, "request_id": rid})
                        st.success(f"Submitted classification for {target_asset}: {rid}")
                        # Clear wizard state
                        st.session_state.pop("task_wizard_asset", None)
                        try:
                            st.experimental_set_query_params(sub="tasks")
                        except Exception:
                            pass
                    except Exception as e:
                        st.error(f"Submission failed: {e}")
            if 'save_draft' in locals() and save_draft:
                # Persist draft locally; systems without draft endpoint will still retain state
                drafts = st.session_state.get("task_drafts", {})
                drafts[target_asset] = {
                    "label": label,
                    "c": int(c_val), "i": int(i_val), "a": int(a_val),
                    "rationale": rationale, "mentions": mentions, "request_review": request_review,
                    "saved_at": datetime.utcnow().isoformat(),
                }
                st.session_state["task_drafts"] = drafts
                try:
                    audit_service.log(st.session_state.get("user") or "wizard@system", "CLASSIFY_DRAFT_SAVE", "ASSET", target_asset, drafts[target_asset])
                except Exception:
                    pass
                st.success("Draft saved locally for this session.")
            if 'cancel' in locals() and cancel:
                st.session_state.pop("task_wizard_asset", None)
                try:
                    st.experimental_set_query_params(sub="tasks")
                except Exception:
                    pass

    def render_classification_review():
        st.caption("Pending Reviews: Peer, Management, Quality Assurance")

        # ---------------------------
        # Filters
        # ---------------------------
        f1, f2, f3, f4 = st.columns([1.6, 1.6, 1.8, 1.4])
        with f1:
            review_level = st.selectbox(
                "Review Level",
                options=["All", "Management Review", "Peer Review", "Quality Check"],
                index=0,
                key="rev_level2",
            )
        with f2:
            approval_status = st.selectbox(
                "Approval Status",
                options=["All pending", "Pending my approval"],
                index=0,
                key="rev_approval_status",
            )
        with f3:
            submission_date = st.selectbox(
                "Submission Date",
                options=["All", "Last 7 days", "Last 30 days", "Custom"],
                index=0,
                key="rev_submit_date",
            )
        with f4:
            complexity = st.selectbox(
                "Complexity",
                options=["All", "Simple", "Complex", "Escalated"],
                index=0,
                key="rev_complexity",
            )
        sub_custom = None
        if submission_date == "Custom":
            sub_custom = st.date_input("Select submission date range", value=[], key="rev_submit_range")

        # Database context notice (consistency checks require a valid CURRENT_DATABASE)
        _db_ctx = _get_current_db()
        if not _db_ctx:
            st.warning("No active database context detected. Consistency checks will be limited until a database is selected.")
            # Removed inline DB selector here per UX request. Use Classification page Global Filters to set context.

        # ---------------------------
        # Load review queue
        # ---------------------------
        try:
            rows = reclassification_service.list_requests(status="Pending", limit=500) or []
        except Exception as e:
            msg = str(e)
            st.info(f"Reviews unavailable: {e}")
            # If error points to NONE database, present DB selector prominently and stop
            if "Database 'NONE'" in msg or "CURRENT_DATABASE" in msg:
                st.info("No active database selected. Set an active database from the Classification page's Global Filters.")
                return
            rows = []

        df = pd.DataFrame(rows) if rows else pd.DataFrame()

        # Normalize likely columns
        if not df.empty:
            # Map common fields if present
            df.rename(columns={
                "ASSET": "ASSET_FULL_NAME",
                "FULL_NAME": "ASSET_FULL_NAME",
                "CREATED": "CREATED_AT",
                "CREATEDBY": "CREATED_BY",
            }, inplace=True)
            # Derive proposed label/C/I/A when possible
            def _proposed_label(row):
                for k in ["PROPOSED_LABEL", "LABEL", "CLASSIFICATION", "PROPOSED_CLASSIFICATION"]:
                    if k in row and pd.notna(row[k]):
                        return str(row[k])
                return None
            def _proposed_int(row, key_opts):
                for k in key_opts:
                    if k in row and pd.notna(row[k]):
                        try:
                            return int(row[k])
                        except Exception:
                            pass
                return None
            if isinstance(df, pd.DataFrame):
                df["PROPOSED_LABEL_N"] = df.apply(lambda r: _proposed_label(r), axis=1)
                df["PC"] = df.apply(lambda r: _proposed_int(r, ["PROPOSED_C", "C", "CIA_C", "CIA_CONF"]), axis=1)
                df["PI"] = df.apply(lambda r: _proposed_int(r, ["PROPOSED_I", "I", "CIA_I", "CIA_INT"]), axis=1)
                df["PA"] = df.apply(lambda r: _proposed_int(r, ["PROPOSED_A", "A", "CIA_A", "CIA_AVAIL"]), axis=1)

        # Apply filters
        view = df.copy() if not df.empty else df
        if view is not None and not view.empty:
            # Map review level
            def _infer_type(row):
                lbl = str(row.get("PROPOSED_LABEL_N") or "")
                pc = row.get("PC")
                if (lbl.lower() == "confidential") or (isinstance(pc, int) and pc >= 3):
                    return "Management Review"
                return "Peer Review"
            view["Review Level"] = view.apply(_infer_type, axis=1)
            if review_level != "All":
                if review_level == "Quality Check":
                    # No explicit signal; treat none as Quality for now (results empty)
                    view = view[view["Review Level"] == "Quality Check"]
                else:
                    view = view[view["Review Level"] == review_level]

            # Approval status
            if approval_status == "Pending my approval":
                # Best-effort: show management reviews only if user can approve
                if authz.can_approve_tags(ident):
                    view = view[view["Review Level"] == "Management Review"]
                else:
                    view = view.iloc[0:0]

            # Submission date filter
            if submission_date in ("Last 7 days", "Last 30 days") and "CREATED_AT" in view.columns:
                days = 7 if submission_date == "Last 7 days" else 30
                cutoff = pd.Timestamp.utcnow() - pd.Timedelta(days=days)
                view = view[pd.to_datetime(view["CREATED_AT"], errors='coerce') >= cutoff]
            if submission_date == "Custom" and sub_custom and len(sub_custom) == 2 and "CREATED_AT" in view.columns:
                start, end = sub_custom
                view = view[(pd.to_datetime(view["CREATED_AT"], errors='coerce') >= pd.to_datetime(start)) & (pd.to_datetime(view["CREATED_AT"], errors='coerce') <= pd.to_datetime(end))]

            # Complexity filter
            def _complexity(row):
                stt = str(row.get("STATUS") or "").lower()
                if "escalat" in stt:
                    return "Escalated"
                pc, pi, pa = row.get("PC"), row.get("PI"), row.get("PA")
                if any([(isinstance(x, int) and x >= 3) for x in [pc, pi, pa]]):
                    return "Complex"
                return "Simple"
            view["Complexity"] = view.apply(_complexity, axis=1)
            if complexity != "All":
                view = view[view["Complexity"] == complexity]

        # ---------------------------
        # Dashboard cards
        # ---------------------------
        total_pending = int(len(view)) if view is not None and not view.empty else 0
        c3_count = int(((view["PROPOSED_LABEL_N"].astype(str).str.lower() == "confidential") | (view["PC"].fillna(-1) >= 3)).sum()) if total_pending else 0
        try:
            # Cycle time: time since CREATED_AT
            if view is not None and not view.empty and "CREATED_AT" in view.columns:
                ages = pd.to_datetime(view["CREATED_AT"], errors='coerce')
                age_days = (pd.Timestamp.utcnow() - ages).dt.total_seconds() / 86400.0
                avg_age = float(age_days.mean()) if len(age_days.dropna()) else 0.0
            else:
                avg_age = 0.0
        except Exception:
            avg_age = 0.0
        m1, m2, m3 = st.columns(3)
        m1.metric("Pending Reviews", total_pending)
        m2.metric("C3/Confidential (Mgmt)", c3_count)
        m3.metric("Avg Age (days)", f"{avg_age:.1f}")

        # Badges legend
        st.caption("Badges: Peer | Management | Quality")

        # Review queue table
        if view is not None and not view.empty:
            def _badge_type(row):
                lbl = str(row.get("PROPOSED_LABEL_N") or "")
                pc = row.get("PC")
                if (lbl.lower() == "confidential") or (isinstance(pc, int) and pc >= 3):
                    return "Management"
                return "Peer"
            view = view.copy()
            view["Review Type"] = view.apply(_badge_type, axis=1)
            cols_show = [c for c in ["ID","ASSET_FULL_NAME","PROPOSED_LABEL_N","PC","PI","PA","CREATED_BY","CREATED_AT","Review Type"] if c in view.columns]
            st.dataframe(view[cols_show], use_container_width=True)
        else:
            st.info("No pending reviews found for the selected filters.")

        # ---------------------------
        # Selection + Comparison Viewer + Actions
        # ---------------------------
        sel = None
        if view is not None and not view.empty:
            opts = view["ID"].tolist() if "ID" in view.columns else []
            sel = st.selectbox("Select Request", options=opts, key="rev_sel")

        if sel:
            r = next((x for x in rows if str(x.get("ID")) == str(sel)), None)
            asset = r.get("ASSET_FULL_NAME") if r else None
            st.markdown("---")
            st.subheader("Classification Comparison")
            c_left, c_right = st.columns(2)
            # Current classification (from tags)
            with c_left:
                st.caption("Current (from tags)")
                cur = {}
                try:
                    refs = tagging_service.get_object_tags(asset, "TABLE") if asset else []
                    for t in (refs or []):
                        nm = str((t.get("TAG_NAME") or t.get("TAG") or "")).upper()
                        val = t.get("TAG_VALUE") or t.get("VALUE")
                        if nm.endswith("DATA_CLASSIFICATION"): cur["Label"] = val
                        if nm.endswith("CONFIDENTIALITY_LEVEL"): cur["C"] = int(str(val)) if str(val).isdigit() else None
                        if nm.endswith("INTEGRITY_LEVEL"): cur["I"] = int(str(val)) if str(val).isdigit() else None
                        if nm.endswith("AVAILABILITY_LEVEL"): cur["A"] = int(str(val)) if str(val).isdigit() else None
                except Exception:
                    pass
                st.json(cur or {"info": "No current tags found"})
            # Proposed classification (from request)
            with c_right:
                st.caption("Proposed (from request)")
                proposed = {
                    "Label": r.get("PROPOSED_LABEL") or r.get("LABEL") or r.get("CLASSIFICATION") or r.get("PROPOSED_CLASSIFICATION"),
                    "C": r.get("PROPOSED_C") or r.get("C") or r.get("CIA_C") or r.get("CIA_CONF"),
                    "I": r.get("PROPOSED_I") or r.get("I") or r.get("CIA_I") or r.get("CIA_INT"),
                    "A": r.get("PROPOSED_A") or r.get("A") or r.get("CIA_A") or r.get("CIA_AVAIL"),
                }
                st.json(proposed)

            # Highlight CIA deltas
            try:
                deltas = {}
                for k in ["C","I","A"]:
                    cv = int(cur.get(k)) if cur.get(k) is not None else None
                    pv = int(proposed.get(k)) if proposed.get(k) is not None else None
                    if cv is not None and pv is not None and pv != cv:
                        deltas[k] = f"{cv} → {pv}"
                if deltas:
                    st.warning("Changes detected: " + ", ".join([f"{k}: {v}" for k, v in deltas.items()]))
            except Exception:
                pass

            # Rationale
            st.markdown("### Submitter Rationale")
            st.info(str(r.get("JUSTIFICATION") or r.get("RATIONALE") or "No rationale provided"))

            # Review actions
            st.markdown("### Review Actions")
            with st.form(key="review_actions_form"):
                approver = st.text_input("Your email (approver)", key="rev_approver")
                comment = st.text_area("Comments (required for rejection)", key="rev_comment")
                col_a, col_b, col_c = st.columns(3)
                approve_clicked = col_a.form_submit_button("Approve & Apply", type="primary")
                request_changes_clicked = col_b.form_submit_button("Request Changes")
                escalate_clicked = col_c.form_submit_button("Escalate to Governance Committee")

            # Business rules
            if approve_clicked and sel and approver:
                try:
                    reclassification_service.approve(sel, approver)
                    st.success("Approved and applied tags.")
                except Exception as e:
                    st.error(f"Approve failed: {e}")
            if request_changes_clicked and sel and approver:
                if not (comment and comment.strip()):
                    st.error("Comments are required for Request Changes (rejection).")
                else:
                    try:
                        reclassification_service.reject(sel, approver, comment)
                        st.success("Changes requested (rejected).")
                    except Exception as e:
                        st.error(f"Request changes failed: {e}")
            if escalate_clicked and sel and approver:
                # Best-effort escalate: call optional escalate(), else log
                did = False
                try:
                    if hasattr(reclassification_service, 'escalate'):
                        reclassification_service.escalate(sel, approver, comment or "Escalated to Governance Committee")
                        did = True
                except Exception:
                    did = False
                try:
                    audit_service.log(approver or "system", "REVIEW_ESCALATE", "REQUEST", str(sel), {"comment": comment or "", "target": "Governance Committee"})
                except Exception:
                    pass
                if did:
                    st.success("Escalated to Governance Committee.")
                else:
                    st.info("Escalation recorded in audit. Governance team will be notified externally.")

            # ---------------------------
            # Consistency Checker
            # ---------------------------
            st.markdown("### Consistency Checker")
            similar = []
            try:
                if asset:
                    db = _get_current_db()
                    if db:
                        # Find assets in same schema or with similar table names
                        parts = asset.split('.') if asset else []
                        sc = parts[1] if len(parts) >= 2 else None
                        tb = parts[2] if len(parts) >= 3 else None
                        q = f"""
                            SELECT 
                              FULLY_QUALIFIED_NAME AS FULL_NAME,
                              BUSINESS_UNIT AS OBJECT_DOMAIN,
                              (CLASSIFICATION_LABEL IS NOT NULL) AS CLASSIFIED,
                              NULL AS CIA_CONF, NULL AS CIA_INT, NULL AS CIA_AVAIL
                            FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                            WHERE (FULLY_QUALIFIED_NAME ILIKE %(p1)s OR (SCHEMA_NAME = %(sc)s))
                            ORDER BY FULLY_QUALIFIED_NAME
                            LIMIT 100
                        """
                        patt = f"%{tb.split('_')[0]}%" if tb else "%"
                        rows2 = snowflake_connector.execute_query(q, {"p1": patt, "sc": sc}) or []
                        similar = rows2
            except Exception:
                similar = []

            sim_df = pd.DataFrame(similar)
            if not sim_df.empty:
                # Fetch classification tag for each similar (best-effort)
                labels = []
                for fn in sim_df.get("FULL_NAME", []):
                    try:
                        refs = tagging_service.get_object_tags(fn, "TABLE")
                        lbl = None
                        for t in refs or []:
                            nm = str((t.get("TAG_NAME") or t.get("TAG") or "")).upper()
                            if nm.endswith("DATA_CLASSIFICATION"):
                                lbl = t.get("TAG_VALUE") or t.get("VALUE")
                                break
                        labels.append(lbl)
                    except Exception:
                        labels.append(None)
                sim_df["DATA_CLASSIFICATION"] = labels
                st.dataframe(sim_df[[c for c in ["FULL_NAME","OBJECT_DOMAIN","DATA_CLASSIFICATION","CIA_CONF","CIA_INT","CIA_AVAIL"] if c in sim_df.columns]], use_container_width=True)

                # Inconsistency hint
                try:
                    prop_lbl = (proposed.get("Label") or "").lower()
                    mismatches = sim_df[(sim_df["DATA_CLASSIFICATION"].astype(str).str.lower() != prop_lbl)]
                    if not mismatches.empty:
                        st.warning(f"Found {len(mismatches)} similar assets with different classifications. Consider consistency before approval.")
                except Exception:
                    pass

    def render_reclassification_management():
        st.caption("Reclassification Requests & Triggers")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Detect Triggers (auto)"):
                try:
                    created = reclassification_service.detect_triggers()
                    st.success(f"Created {created} trigger(s)")
                except Exception as e:
                    st.error(f"Trigger detection failed: {e}")
        with c2:
            st.caption("Triggers include regulatory/usage changes, errors, incidents, and SLA events.")
        st.markdown("---")
        tables = _list_tables(limit=300)
        asset = st.selectbox("Asset", options=tables if tables else ["No assets available"], key="reclass_asset_center")
        colc, coli, cola = st.columns(3)
        with colc:
            pc = st.number_input("Proposed C", 0, 3, 1)
        with coli:
            pi = st.number_input("Proposed I", 0, 3, 1)
        with cola:
            pa = st.number_input("Proposed A", 0, 3, 1)
        risk = CIA(pc, pi, pa).risk_level()
        pcls = st.selectbox("Proposed Risk (derived)", options=["Low","Medium","High"], index=["Low","Medium","High"].index(risk))
        impact = st.text_area("Impact Assessment & Stakeholders", placeholder="Describe business impact, stakeholders, approvals...")
        requester = st.text_input("Your email (requester)")
        if st.button("Submit Reclassification") and requester and asset and asset != "No assets available":
            rid = reclassification_service.submit_request(asset, (pcls, int(pc), int(pi), int(pa)), impact or "Reclassification request", requester, trigger_type="MANUAL")
            st.success(f"Submitted request {rid}")

        # Listing of reclassification requests with filters
        st.markdown("---")
        st.subheader("Requests")
        try:
            rows = reclassification_service.list_requests(limit=500) or []
        except Exception:
            rows = []
        rdf = pd.DataFrame(rows)
        if not rdf.empty:
            # Derive fields for filters
            def _risk_row(r):
                for k in ["PROPOSED_LABEL", "LABEL", "CLASSIFICATION"]:
                    v = r.get(k)
                    if v:
                        return str(v)
                pc = r.get("PROPOSED_C") or r.get("C")
                pi = r.get("PROPOSED_I") or r.get("I")
                pa = r.get("PROPOSED_A") or r.get("A")
                try:
                    return CIA(int(pc or 0), int(pi or 0), int(pa or 0)).risk_level()
                except Exception:
                    return None
            rdf["Risk"] = rdf.apply(_risk_row, axis=1)
            # Trigger source best-effort from TRIGGER_TYPE/REASON
            def _src(r):
                t = str(r.get("TRIGGER_TYPE") or r.get("REASON") or "").lower()
                if "reg" in t:
                    return "Regulatory Change"
                if "incident" in t or "security" in t:
                    return "Security Incident"
                if "annual" in t:
                    return "Annual Review"
                return "Business Process"
            rdf["Trigger Source"] = rdf.apply(_src, axis=1)
            # Impact scope placeholder from ASSET_FULL_NAME granularity
            def _scope(r):
                fn = str(r.get("ASSET_FULL_NAME") or "")
                if fn.count('.') >= 2:
                    return "Single Asset"
                return "Related Group"
            rdf["Impact Scope"] = rdf.apply(_scope, axis=1)
            # Implementation status from STATUS
            def _impl(r):
                s = str(r.get("STATUS") or "").lower()
                if "complete" in s:
                    return "Completed"
                if "progress" in s or "pending" in s:
                    return "In Progress"
                return "Not Started"
            rdf["Implementation Status"] = rdf.apply(_impl, axis=1)

            # Apply filters
            if trg_src:
                rdf = rdf[rdf["Trigger Source"].isin(trg_src)]
            if impact_scope != "All":
                rdf = rdf[rdf["Impact Scope"] == impact_scope]
            if impl_status != "All":
                rdf = rdf[rdf["Implementation Status"] == impl_status]
            if risk_level:
                rdf = rdf[rdf["Risk"].isin([r.replace("Impact", "").strip() for r in risk_level])]

            cols = [c for c in ["ID","ASSET_FULL_NAME","Risk","Trigger Source","Impact Scope","Implementation Status","STATUS","CREATED_AT"] if c in rdf.columns]
            st.dataframe(rdf[cols], use_container_width=True)
        else:
            st.info("No reclassification requests found.")

    def render_classification_history_audit():
        st.caption("History & Audit Trail")
        # Filters (unique)
        f1, f2, f3, f4 = st.columns([1.6, 1.6, 1.4, 1.6])
        with f1:
            activity_type = st.multiselect(
                "Activity Type",
                options=["Classified", "Reclassified", "Approved", "Rejected"],
                default=[],
                key="hist_activity",
            )
        with f2:
            time_period = st.selectbox(
                "Time Period",
                options=["All", "Today", "This week", "This month", "Custom range"],
                index=0,
                key="hist_time",
            )
        with f3:
            user_role = st.multiselect(
                "User Role",
                options=["Data Owner", "Manager", "Specialist", "Custodian"],
                default=[],
                key="hist_role",
            )
        with f4:
            change_mag = st.selectbox(
                "Change Magnitude",
                options=["All", "Major change", "Minor update", "Correction"],
                index=0,
                key="hist_change_mag",
            )

        tables = _list_tables(limit=300)
        asset = st.selectbox("Dataset", options=tables if tables else ["No assets available"], key="hist_asset_center")
        if asset and asset != "No assets available":
            try:
                reqs = reclassification_service.list_requests(limit=500)
                reqs_df = pd.DataFrame([r for r in reqs if r.get("ASSET_FULL_NAME") == asset])
                # Apply activity filters to requests (Reclassified/Approved/Rejected)
                if not reqs_df.empty:
                    if activity_type:
                        if "Reclassified" not in activity_type:
                            reqs_df = reqs_df.iloc[0:0]
                    if time_period != "All" and "CREATED_AT" in reqs_df.columns:
                        now = pd.Timestamp.utcnow()
                        if time_period == "Today":
                            cutoff = now.normalize()
                        elif time_period == "This week":
                            cutoff = now - pd.Timedelta(days=7)
                        else:
                            cutoff = now - pd.Timedelta(days=30)
                        reqs_df = reqs_df[pd.to_datetime(reqs_df["CREATED_AT"], errors='coerce') >= cutoff]
                st.dataframe(reqs_df, use_container_width=True)
            except Exception as e:
                st.info(f"No reclassification history: {e}")
            try:
                logs = audit_service.query(limit=500)
                logs_df = pd.DataFrame([l for l in (logs or []) if l.get("RESOURCE_ID") == asset])
                # Map activity type from EVENT
                if not logs_df.empty and "EVENT" in logs_df.columns:
                    def _act(ev):
                        evs = str(ev or "").upper()
                        if "APPLY" in evs or "CLASSIFY" in evs:
                            return "Classified"
                        if "APPROVE" in evs:
                            return "Approved"
                        if "REJECT" in evs or "REQUEST_CHANGES" in evs:
                            return "Rejected"
                        return None
                    logs_df["Activity Type"] = logs_df["EVENT"].apply(_act)
                # Time period filter
                if time_period != "All" and not logs_df.empty and "CREATED_AT" in logs_df.columns:
                    now = pd.Timestamp.utcnow()
                    if time_period == "Today":
                        cutoff = now.normalize()
                    elif time_period == "This week":
                        cutoff = now - pd.Timedelta(days=7)
                    elif time_period == "This month":
                        cutoff = now - pd.Timedelta(days=30)
                    else:
                        cutoff = None
                    if cutoff is not None:
                        logs_df = logs_df[pd.to_datetime(logs_df["CREATED_AT"], errors='coerce') >= cutoff]
                if activity_type and not logs_df.empty and "Activity Type" in logs_df.columns:
                    logs_df = logs_df[logs_df["Activity Type"].isin(activity_type)]
                # User role filter is best-effort without directory: show unchanged
                # Change magnitude placeholder: treat High CIA deltas as Major (not derivable here) -> skip
                st.dataframe(logs_df, use_container_width=True)
            except Exception as e:
                st.info(f"No audit logs: {e}")

    def render_snowflake_tag_management():
        st.caption("Snowflake Tag Management")
        # Filters per spec (unique)
        f1, f2, f3, f4 = st.columns([1.4, 1.4, 1.8, 1.4])
        with f1:
            sync_status = st.selectbox(
                "Sync Status",
                options=["All", "Success", "Failed", "In Progress", "Not Attempted"],
                index=0,
                key="tags_sync_status",
            )
        with f2:
            env_type = st.selectbox(
                "Environment Type",
                options=["All", "Production", "Development", "Test"],
                index=0,
                key="tags_env",
            )
        with f3:
            tag_category = st.multiselect(
                "Tag Category",
                options=["Classification", "Confidentiality", "Integrity", "Availability"],
                default=[],
                key="tags_category",
            )
        with f4:
            last_sync = st.selectbox(
                "Last Sync Attempt",
                options=["All", "Last hour", "Today", "This week", "Older"],
                index=0,
                key="tags_last_sync",
            )

        st.info("Manage Snowflake tags, tag schemas, and mappings to policy labels.")
        # Placeholder dataset from tag references; best-effort build
        try:
            sample_assets = _list_tables(limit=50)
            rows = []
            for a in sample_assets[:25]:
                try:
                    refs = tagging_service.get_object_tags(a, "TABLE")
                except Exception:
                    refs = []
                found = {"Asset": a, "Environment": "Production", "Sync": "Success", "Last Sync": pd.Timestamp.utcnow()}
                for t in refs or []:
                    nm = str((t.get("TAG_NAME") or t.get("TAG") or "")).upper()
                    val = t.get("TAG_VALUE") or t.get("VALUE")
                    if nm.endswith("DATA_CLASSIFICATION"):
                        found["Classification"] = val
                    if nm.endswith("CONFIDENTIALITY_LEVEL"):
                        found["Confidentiality"] = val
                    if nm.endswith("INTEGRITY_LEVEL"):
                        found["Integrity"] = val
                    if nm.endswith("AVAILABILITY_LEVEL"):
                        found["Availability"] = val
                rows.append(found)
            tdf = pd.DataFrame(rows)
        except Exception:
            tdf = pd.DataFrame()
        if not tdf.empty:
            # Apply filters
            if sync_status != "All":
                tdf = tdf[tdf["Sync"].astype(str) == sync_status]
            if env_type != "All" and "Environment" in tdf.columns:
                tdf = tdf[tdf["Environment"].astype(str) == env_type]
            if tag_category:
                mask = pd.Series([True] * len(tdf))
                for cat in tag_category:
                    mask = mask & tdf.columns.isin([cat]).any()
                # Simplify: show all regardless; category columns presence varies
            if last_sync != "All" and "Last Sync" in tdf.columns:
                now = pd.Timestamp.utcnow()
                if last_sync == "Last hour":
                    cutoff = now - pd.Timedelta(hours=1)
                elif last_sync == "Today":
                    cutoff = now.normalize()
                elif last_sync == "This week":
                    cutoff = now - pd.Timedelta(days=7)
                else:
                    cutoff = None
                if cutoff is not None:
                    tdf = tdf[pd.to_datetime(tdf["Last Sync"], errors='coerce') >= cutoff]
                else:
                    tdf = tdf[pd.to_datetime(tdf["Last Sync"], errors='coerce') < (now - pd.Timedelta(days=7))]
            st.dataframe(tdf, use_container_width=True)
        else:
            st.info("No tag data available to display.")

    # --- Deep-link integration via query params (select initial tab) ---
    try:
        q = st.experimental_get_query_params() or {}
    except Exception:
        q = {}
    sub = (q.get("sub") or ["tasks"])[:1][0].lower()

    # Define tab registry: (key, label, render_fn)
    registry = [
        ("tasks",   "My Classification Tasks",         render_my_classification_tasks),
        ("review",  "Classification Review",           render_classification_review),
        ("reclass", "Reclassification Management",     render_reclassification_management),
        ("history", "Classification History & Audit",  render_classification_history_audit),
        ("tags",    "Snowflake Tag Management",        render_snowflake_tag_management),
    ]

    # Rotate so that the requested 'sub' is first (Streamlit opens first tab by default)
    try:
        idx = next((i for i, (k, _, __) in enumerate(registry) if k == sub), 0)
    except Exception:
        idx = 0
    rotated = registry[idx:] + registry[:idx]

    tabs = st.tabs([label for _, label, __ in rotated])

    # Render each tab and sync URL param when active
    for i, (key, _label, renderer) in enumerate(rotated):
        with tabs[i]:
            try:
                st.experimental_set_query_params(sub=key)
            except Exception:
                pass
            renderer()

def _compliance_panel():
    st.subheader("Compliance & QA")
    df, metrics = _coverage_and_overdue()
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Assets", metrics.get("total", 0))
    c2.metric("Classified", metrics.get("classified", 0))
    c3.metric("Overdue (SLA 5d)", metrics.get("overdue", 0))
    if not df.empty:
        st.dataframe(df[[c for c in ["FULL_NAME","FIRST_DISCOVERED","CLASSIFIED","CIA_CONF","CIA_INT","CIA_AVAIL","DUE_BY","OVERDUE"] if c in df.columns]], use_container_width=True)

# ---------------------------
# Page Render
# ---------------------------
# Render main sub-tab architecture is handled within the tab sections above.

# Authorization guard: allow only Owners, Custodians, Specialists, Admins.
# Avoid forcing logout on reruns; if app user exists, warn and stop page rendering.
try:
    _ident = authz.get_current_identity()
    if not authz.can_access_classification(_ident):
        if getattr(st.session_state, 'user', None) is not None:
            st.warning("Snowflake session/role not sufficient for Classification. Re-authenticate from Home or switch role in sidebar.")
            st.stop()
        st.error("You do not have permission to access the Classification module. Please contact a Data Owner or Admin.")
        st.stop()
    # Capability flags used to gate actions within this page
    _can_classify = authz.can_classify(_ident)
    _can_approve = authz.can_approve_tags(_ident)
except Exception as _auth_err:
    if getattr(st.session_state, 'user', None) is not None:
        st.warning(f"Authorization check failed (continuing): {_auth_err}. Re-authenticate from Home if needed.")
        st.stop()
    st.warning(f"Authorization check failed: {_auth_err}")
    st.stop()

# Consolidated tabs (Discovery, Tagging, AI, Risk, Reclassification, History, Approvals) disabled per requirements
st.stop()

with tab0:
    st.subheader("Discovery")
    st.caption("Recent discoveries, search, full-scan, and quick health checks. Classification SLA (5 business days) is monitored on the Dashboard.")
    # Discovered assets (inventory)
    try:
        db = st.session_state.get('sf_database') or _get_current_db()
        if not db:
            st.warning("No database selected. Please select a database from the Dashboard.")
            st.stop()
        with st.spinner("Reading discovered assets from inventory..."):
            rows = snowflake_connector.execute_query(
                f"""
                SELECT 
                  FULLY_QUALIFIED_NAME AS FULL_NAME,
                  BUSINESS_UNIT AS OBJECT_DOMAIN,
                  COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP) AS FIRST_DISCOVERED,
                  (CLASSIFICATION_LABEL IS NOT NULL) AS CLASSIFIED
                FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
                ORDER BY COALESCE(LAST_MODIFIED_TIMESTAMP, CREATED_TIMESTAMP) DESC
                LIMIT 200
                """
            ) or []
        if rows:
            idf = pd.DataFrame(rows)
            idf.rename(columns={"FULL_NAME":"Asset","OBJECT_DOMAIN":"Type"}, inplace=True)
            idf["Status"] = idf["CLASSIFIED"].apply(lambda x: "Classified " if x else "Unclassified ")
            st.dataframe(idf[["Asset","Type","FIRST_DISCOVERED","LAST_SEEN","Status"]], use_container_width=True)
        else:
            st.info("No assets in inventory yet. Run a scan below.")
    except Exception as e:
        st.warning(f"Unable to read assets: {e}")
        st.caption("Ensure DATA_CLASSIFICATION_GOVERNANCE.ASSETS exists or refresh governance.")

    st.markdown("---")
    # Search panel
    st.subheader("")
    qcol1, qcol2, qcol3 = st.columns([3, 1, 1])
    with qcol1:
        query = st.text_input("Search by schema/table/column name", placeholder="e.g. users, customer, email", key="disc_query")
    with qcol2:
        limit_tables = st.number_input("Table results", min_value=10, max_value=1000, value=50, step=10, key="disc_tbl_lim")
    with qcol3:
        limit_cols = st.number_input("Column results", min_value=10, max_value=5000, value=200, step=50, key="disc_col_lim")

    @st.cache_data(ttl=1800)
    def search_tables_cached(q: str, limit: int):
        return testing_service.search_tables(q, limit)

    @st.cache_data(ttl=1800)
    def search_columns_cached(q: str, limit: int):
        return testing_service.search_columns(q, limit)

    if query:
        with st.spinner("Searching Snowflake..."):
            trows = search_tables_cached(query, int(limit_tables))
            crows = search_columns_cached(query, int(limit_cols))
        tdf = pd.DataFrame(trows)
        cdf = pd.DataFrame(crows)
        # Apply dataset filters best-effort by string matching on fully qualified names
        try:
            if sel.get("database") and not tdf.empty:
                for col in ["FULL_NAME","full_name","TABLE","Asset","NAME","TABLE_NAME"]:
                    if col in tdf.columns:
                        tdf = tdf[tdf[col].astype(str).str.contains(fr"^{sel['database']}\.", case=False, regex=True)]
                        break
            if sel.get("schema") and not tdf.empty:
                tdf = tdf[tdf.astype(str).apply(lambda r: f".{sel['schema']}." in " ".join(r.values), axis=1)]
            if sel.get("table") and not tdf.empty:
                tdf = tdf[tdf.astype(str).apply(lambda r: r.str.contains(fr"\.{sel['table']}$", case=False, regex=True).any(), axis=1)]
        except Exception:
            pass
        try:
            if sel.get("database") and not cdf.empty:
                cdf = cdf[cdf.astype(str).apply(lambda r: f"{sel['database']}." in " ".join(r.values), axis=1)]
            if sel.get("schema") and not cdf.empty:
                cdf = cdf[cdf.astype(str).apply(lambda r: f".{sel['schema']}." in " ".join(r.values), axis=1)]
            if sel.get("table") and not cdf.empty:
                # Correct dtype cast to string before endswith filter
                cdf = cdf[cdf.astype(str).apply(lambda r: r.astype(str).str.endswith(sel['table']).any(), axis=1)]
            if sel.get("column") and not cdf.empty:
                # Try to filter by column name column if present
                for col in ["COLUMN","COLUMN_NAME","name","Name"]:
                    if col in cdf.columns:
                        cdf = cdf[cdf[col].astype(str).str.contains(sel['column'], case=False, regex=False)]
                        break
        except Exception:
            pass
        st.markdown("**Tables**")
        st.dataframe(tdf, use_container_width=True)
        st.markdown("**Columns**")
        st.dataframe(cdf, use_container_width=True)
    else:
        st.info("Enter a search string above to find tables and columns.")

    st.markdown("---")
    # Full scan & health
    st.subheader("")
    colf1, colf2, colf3 = st.columns([2, 1, 1])
    with colf1:
        st.write("Run a full inventory scan to ensure all tables and views are discovered and upserted into the inventory queue.")
    with colf2:
        if st.button("Run Full Scan", key="disc_run_full"):
            with st.spinner("Scanning entire database in batches..."):
                total = discovery_service.full_scan(batch_size=1000)
            st.success(f"Full scan complete. Upserted {total} assets.")
    with colf3:
        if st.button("Connectivity Test", key="disc_conn_test"):
            ok = testing_service.connectivity_test()
            if ok:
                st.success("Connectivity OK: able to query Snowflake.")
            else:
                st.error("Connectivity failed. Check credentials/warehouse/role.")

with tab1:
    st.subheader("Tagging & CIA Labels")
    st.write("Select dataset(s), assign classification and CIA, validate against prior tags, and apply to Snowflake.")

    # Load assets from inventory or fallback to INFORMATION_SCHEMA
    try:
        from src.services.discovery_service import discovery_service
        with st.spinner("Loading assets from inventory..."):
            inv_rows = discovery_service.get_queue(limit=500) or []
            inv_assets = [r.get("FULL_NAME") for r in inv_rows if r.get("FULL_NAME")]
        if not inv_assets:
            tables = snowflake_connector.execute_query(
                f"""
                SELECT "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS full_name
                FROM {_get_current_db()}.INFORMATION_SCHEMA.TABLES
                WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
                ORDER BY "TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME"
                LIMIT 200
                """
            )
            inv_assets = [t['FULL_NAME'] for t in (tables or [])]
    except Exception as e:
        st.warning(f"Could not load assets: {e}")
        inv_assets = []

    # Search/filter across datasets (persisted via session state)
    search_q = st.text_input("Search datasets", placeholder="Type to filter by name...", key="manual_search")
    # Apply dataset filters to asset list
    def _match_sel(a: str) -> bool:
        try:
            db, sc, tb = a.split('.')[:3]
            if sel.get("database") and db.upper() != sel['database'].upper():
                return False
            if sel.get("schema") and sc.upper() != sel['schema'].upper():
                return False
            if sel.get("table") and tb.upper() != sel['table'].upper():
                return False
            return True
        except Exception:
            return True
    inv_assets2 = [a for a in inv_assets if _match_sel(a)]
    filtered_assets = [a for a in inv_assets2 if (search_q.lower() in a.lower())] if search_q else inv_assets2
    selected_assets = st.multiselect("Choose one or more assets", options=filtered_assets, default=filtered_assets[:1] if filtered_assets else [])

    # Auto-suggest CIA and Level
    def suggest_levels(name: str):
        up = (name or "").upper()
        c, i, a = 0, 0, 0
        try:
            from src.services.ai_classification_service import ai_classification_service as _svc
            cfg = _svc.load_sensitivity_config()
            kws = (cfg.get("keywords") or [])
            cats = (cfg.get("categories") or {})
            for kw in kws:
                token = str(kw.get("token") or "").upper()
                cat = str(kw.get("category") or "")
                if token and token in up:
                    m = cats.get(cat) or {}
                    c = max(int(c), int(m.get("C") or 0))
                    i = max(int(i), int(m.get("I") or 0))
                    a = max(int(a), int(m.get("A") or 0))
        except Exception:
            pass
        highest = max(c, i, a)
        level = "Confidential" if highest == 3 else ("Restricted" if highest == 2 else ("Public" if highest == 0 else "Internal"))
        return c, i, a, level

    base_c, base_i, base_a, base_cls = (suggest_levels(selected_assets[0]) if selected_assets else (0, 0, 0, "Internal"))
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        c_val = st.number_input("C (0-3)", min_value=0, max_value=3, value=int(base_c))
    with c2:
        i_val = st.number_input("I (0-3)", min_value=0, max_value=3, value=int(base_i))
    with c3:
        a_val = st.number_input("A (0-3)", min_value=0, max_value=3, value=int(base_a))
    with c4:
        cls_val = st.selectbox("Classification", options=ALLOWED_CLASSIFICATIONS, index=ALLOWED_CLASSIFICATIONS.index(base_cls) if base_cls in ALLOWED_CLASSIFICATIONS else 1)

    # Special Categories selection (affects minimum required levels per Policy 5.5)
    st.write("**Special Categories (Policy 5.5)**")
    # Align options with TaggingService definitions; fallback to common set
    try:
        from src.services.tagging_service import TAG_DEFINITIONS as _TAG_DEF
        special_options = list(_TAG_DEF.get("SPECIAL_CATEGORY", [])) if isinstance(_TAG_DEF, dict) else []
        if not special_options:
            special_options = ["PII","PHI","PCI","SOX","Financial"]
    except Exception:
        special_options = ["PII","PHI","PCI","SOX","Financial"]
    # Detect specials from sensitive column detections of selected assets (union)
    def _detect_specials_for_assets(_assets):
        found = set()
        try:
            token_map = {
                "PII": ["PII","SSN","NATIONAL_ID","PASSPORT","EMAIL","PHONE","ADDRESS","DOB","PERSON","EMPLOYEE","CUSTOMER","AADHAAR","PAN"],
                "PHI": ["PHI","HIPAA","MEDICAL","HEALTH","PATIENT"],
                "PCI": ["PCI","CARD","CREDIT","CVV"],
                "SOX": ["SOX","FINANCIAL_REPORT","AUDIT","IFRS","GAAP"],
                "Financial": ["FINANCIAL","PAYROLL","LEDGER","GL","REVENUE","EXPENSE"],
            }
            # Light sampling for performance
            max_assets = 3
            for asset in (_assets or [])[:max_assets]:
                try:
                    det = ai_classification_service.detect_sensitive_columns(asset, sample_size=200) or []
                except Exception:
                    det = []
                for r in det:
                    txt = " ".join([
                        str(r.get("Sensitivity Type") or ""),
                        str(r.get("Reason / Justification") or ""),
                        str(r.get("MATCHED_KEYWORD") or ""),
                        str(r.get("MATCHED_PATTERN") or ""),
                        str(r.get("Column Name") or r.get("COLUMN_NAME") or r.get("column") or ""),
                    ]).upper()
                    for cat, toks in token_map.items():
                        if any(t in txt for t in toks):
                            if cat in special_options:
                                found.add(cat)
        except Exception:
            pass
        return sorted(found)
    detected_specials = _detect_specials_for_assets(selected_assets)
    special_categories = st.multiselect(
        "Select all that apply",
        options=special_options,
        default=[s for s in detected_specials if s in special_options],
        help="These selections enforce minimum classification/Confidentiality (C) levels and controls.",
        key="manual_special_categories",
    )

    st.write("**Rationale / Notes (for audit)**")
    justification = st.text_area("Rationale", height=100, placeholder="Explain why this classification is appropriate...")

    # Validation against prior tags + SOX/SOC hints
    st.markdown("---")
    st.write("**Validation & Sensitivity Hints**")
    try:
        from src.services.tagging_service import tagging_service
        for asset in selected_assets[:10]:
            with st.expander(f"Validation: {asset}"):
                try:
                    refs = tagging_service.get_object_tags(asset, "TABLE")
                    prev = {}
                    for r in refs:
                        tname = r.get("TAG_NAME") or r.get("TAG") or r.get("TAG_DATABASE")
                        val = r.get("TAG_VALUE") or r.get("VALUE")
                        if tname:
                            prev[str(tname).split('.')[-1].upper()] = val
                    st.write("Previous tags:")
                    st.json(prev or {"info": "No tags found"})
                    incons = []
                    if prev.get("DATA_CLASSIFICATION") and prev.get("DATA_CLASSIFICATION") != cls_val:
                        incons.append("Classification differs from previous")
                    if prev.get("CONFIDENTIALITY_LEVEL") and int(prev.get("CONFIDENTIALITY_LEVEL", 0)) > c_val:
                        incons.append("C lower than previous")
                    if prev.get("INTEGRITY_LEVEL") and int(prev.get("INTEGRITY_LEVEL", 0)) > i_val:
                        incons.append("I lower than previous")
                    if prev.get("AVAILABILITY_LEVEL") and int(prev.get("AVAILABILITY_LEVEL", 0)) > a_val:
                        incons.append("A lower than previous")
                    if incons:
                        st.error("; ".join(incons))
                except Exception as ve:
                    st.info(f"No prior tags or validation unavailable: {ve}")
    except Exception:
        pass

    hints = []
    for asset in selected_assets:
        up = asset.upper()
        if any(k in up for k in ["SOX","FINANCIAL_REPORT","GAAP","IFRS","AUDIT"]):
            hints.append(f"{asset} may require SOX/SOC controls")
    if hints:
        for h in hints:
            st.warning(h)

    user_email = st.text_input("Your email (for audit)", key="manual_user_email")
    # Special Categories enforcement helper
    def required_minimum_for_asset(asset_name: str, categories: Optional[List[str]] = None):
        """Determine minimum required levels from both heuristics and explicit category selection.
        Returns: (min_c, min_cls, regulatory_label)
        """
        up = (asset_name or "").upper()
        categories = categories or []
        # Defaults
        min_c = 1  # C1 Internal
        min_cls = "Internal"
        regulatory = None
        # Explicit categories take precedence
        if "PII" in categories:
            min_c = max(min_c, 2)
            min_cls = "Restricted" if min_c < 3 else "Confidential"
            regulatory = (regulatory or "PII")
        if ("PHI/HIPAA" in categories) or ("PHI" in categories) or ("HIPAA" in categories):
            min_c = max(min_c, 2)
            min_cls = "Restricted" if min_c < 3 else "Confidential"
            regulatory = (regulatory or "HIPAA")
        if ("Financial/SOX" in categories) or ("Financial" in categories) or ("SOX" in categories):
            min_c = max(min_c, 2)
            # SOX-relevant often drives higher integrity and sometimes C3; keep C2 minimum here and allow heuristics to elevate
            min_cls = "Restricted" if min_c < 3 else "Confidential"
            regulatory = (regulatory or ("SOX" if "SOX" in categories else "Financial"))
        if "PCI" in categories:
            # PCI cardholder data generally requires C3
            min_c = max(min_c, 3)
            min_cls = "Confidential"
            regulatory = (regulatory or "PCI")
        # Heuristic name signals (fallbacks and elevation)
        if any(k in up for k in ["SSN","EMAIL","PHONE","ADDRESS","DOB","PII","PERSON","EMPLOYEE"]):
            min_c = max(min_c, 2)
            min_cls = "Restricted" if min_c < 3 else "Confidential"
            regulatory = (regulatory or "PII")
        if any(k in up for k in ["SSN","NATIONAL_ID","PASSPORT","PAN","AADHAAR"]):
            min_c = max(min_c, 3)
            min_cls = "Confidential"
            regulatory = (regulatory or "PII")
        if any(k in up for k in ["SOX","FINANCIAL_REPORT","GL","LEDGER","REVENUE","EXPENSE","PAYROLL","AUDIT"]):
            min_c = max(min_c, 2)
            # Some financial contexts may warrant C3; allow separate hints to elevate
            min_cls = "Restricted" if min_c < 3 else "Confidential"
            regulatory = (regulatory or "SOX")
        return min_c, min_cls, regulatory

    # Exception submission choice (only shown if enforcement blocks)
    request_exception = st.checkbox("Request exception if below required minimums", value=False)

    if st.button("Apply Tags to Selected", type="primary"):
        if not _can_classify:
            st.error("You do not have permission to apply classifications or tags. Contact a Data Owner or Admin.")
            st.stop()
        if not selected_assets:
            st.warning("Please select at least one asset")
        elif not user_email:
            st.warning("Please enter your email for audit")
        elif cls_val in ("Restricted", "Confidential") and not (justification and justification.strip()):
            st.warning("Provide a justification for Restricted/Confidential classifications (Policy 6.1.2 Step 6: Documentation).")
        else:
            # Additional guard: require justification if any CIA level increases vs previous tags
            try:
                from src.services.tagging_service import tagging_service as _tsvc
                needs_rationale = False
                for asset in selected_assets:
                    try:
                        refs = _tsvc.get_object_tags(asset, "TABLE")
                        prev_c = prev_i = prev_a = None
                        for r in refs:
                            tname = (r.get("TAG_NAME") or r.get("TAG") or r.get("TAG_DATABASE") or "").upper()
                            val = r.get("TAG_VALUE") or r.get("VALUE")
                            if tname.endswith("CONFIDENTIALITY_LEVEL"):
                                prev_c = int(str(val)) if str(val).isdigit() else None
                            if tname.endswith("INTEGRITY_LEVEL"):
                                prev_i = int(str(val)) if str(val).isdigit() else None
                            if tname.endswith("AVAILABILITY_LEVEL"):
                                prev_a = int(str(val)) if str(val).isdigit() else None
                        if ((prev_c is not None and int(c_val) > prev_c) or (prev_i is not None and int(i_val) > prev_i) or (prev_a is not None and int(a_val) > prev_a)) and not (justification and justification.strip()):
                            needs_rationale = True
                            break
                    except Exception:
                        continue
                if needs_rationale:
                    st.error("Provide a justification when increasing any CIA level compared to previous tags (Policy 6.2.2 Step 4).")
                    st.stop()
            except Exception:
                pass
            # Enforce Policy 5.5 minimums per asset name heuristics; allow exception path
            violations = []
            req_payloads = []
            for asset in selected_assets:
                req_min_c, req_min_cls, regulatory = required_minimum_for_asset(asset, categories=special_categories)
                # If proposed classification is below required minimums
                if (int(c_val) < int(req_min_c)) or (
                    (ALLOWED_CLASSIFICATIONS.index(cls_val) < ALLOWED_CLASSIFICATIONS.index(req_min_cls))
                ):
                    violations.append({
                        "asset": asset,
                        "required_c": req_min_c,
                        "required_cls": req_min_cls,
                        "reg": regulatory or "Policy",
                    })
                    if request_exception:
                        req_payloads.append((asset, regulatory or "Policy"))

            if violations and not request_exception:
                st.error("Classification below policy minimums for some assets (Policy 5.5). Enable 'Request exception' or adjust levels.")
                for v in violations[:10]:
                    st.warning(f"{v['asset']}: requires at least {v['required_cls']} (C≥{v['required_c']}) due to {v['reg']}")
                st.stop()

            # If exceptions requested, submit them first
            if req_payloads:
                try:
                    from src.services.exception_service import exception_service
                except Exception as e:
                    st.error(f"Exception service unavailable: {e}")
                    st.stop()
                created_exc = 0
                for asset, reg in req_payloads:
                    try:
                        eid = exception_service.submit(
                            asset_full_name=asset,
                            regulatory=reg,
                            justification=justification or f"Exception requested for class={cls_val}, C={c_val} below minimum",
                            risk_level="High" if reg in ("PII","SOX") else "Medium",
                            requested_by=user_email,
                            days_valid=90,
                            details={"proposed": {"classification": cls_val, "C": int(c_val), "I": int(i_val), "A": int(a_val)}},
                        )
                        created_exc += 1
                    except Exception as e:
                        st.error(f"Failed to submit exception for {asset}: {e}")
                if created_exc > 0:
                    st.success(f"Submitted {created_exc} exception request(s). Pending approval.")

            # Validate guardrails (label must meet/exceed minimum given CIA)
            ok, reasons = dm_validate(cls_val, int(c_val), int(i_val), int(a_val))
            if not ok:
                for r in reasons:
                    st.error(r)
                st.stop()

            # Gate C3/Confidential behind approval if user lacks approval capability
            requires_approval = (str(cls_val).lower() == "confidential" or int(c_val) == 3) and (not _can_approve)
            if requires_approval:
                try:
                    from src.services.reclassification_service import reclassification_service as _reclass
                    created = 0
                    for asset in selected_assets:
                        rid = _reclass.submit_request(
                            asset_full_name=asset,
                            proposed=(cls_val, int(c_val), int(i_val), int(a_val)),
                            justification=justification or "Manual submission requiring approval (C3/Confidential)",
                            created_by=user_email or "system",
                            trigger_type="MANUAL_HIGH_RISK",
                        )
                        created += 1 if rid else 0
                        # Record submitted decision for audit
                        try:
                            classification_decision_service.record(
                                asset_full_name=asset,
                                decision_by=user_email or "system",
                                source="MANUAL",
                                status="Submitted",
                                label=cls_val,
                                c=int(c_val), i=int(i_val), a=int(a_val),
                                rationale=justification or "",
                                details={"request_id": rid, "reason": "C3/Confidential requires approval"},
                            )
                        except Exception:
                            pass
                    st.success(f"Submitted {created} reclassification request(s) for approval (C3/Confidential).")
                except Exception as e:
                    st.error(f"Failed to submit for approval: {e}")
                st.stop()

            from src.services.audit_service import audit_service
            applied = 0
            enforced_cols = 0
            for asset in selected_assets:
                try:
                    # Privilege-based guard: require ALTER/OWNERSHIP on the object (no hardcoded roles)
                    if not authz.can_apply_tags_for_object(asset, object_type="TABLE"):
                        st.warning(f"Skipped {asset}: insufficient privileges to apply tags (ALTER/OWNERSHIP required)")
                        continue
                    tagging_service.apply_tags_to_object(
                        asset,
                        "TABLE",
                        {
                            "DATA_CLASSIFICATION": cls_val,
                            "CONFIDENTIALITY_LEVEL": str(int(c_val)),
                            "INTEGRITY_LEVEL": str(int(i_val)),
                            "AVAILABILITY_LEVEL": str(int(a_val)),
                        },
                    )
                    from src.services.discovery_service import discovery_service as _disc
                    _disc.mark_classified(asset, cls_val, int(c_val), int(i_val), int(a_val))
                    audit_service.log(user_email, "MANUAL_CLASSIFY_APPLY", "ASSET", asset, {"cls": cls_val, "c": c_val, "i": i_val, "a": a_val, "just": justification})
                    # Record applied decision
                    try:
                        classification_decision_service.record(
                            asset_full_name=asset,
                            decision_by=user_email or "system",
                            source="MANUAL",
                            status="Applied",
                            label=cls_val,
                            c=int(c_val), i=int(i_val), a=int(a_val),
                            rationale=justification or "",
                            details=None,
                        )
                    except Exception:
                        pass
                    applied += 1

                    # Auto-enforce masking policies for sensitive columns (tag-aware RBAC enforcement)
                    try:
                        detections = ai_classification_service.detect_sensitive_columns(asset)
                        result = policy_enforcement_service.auto_enforce_for_table(table=asset, detections=detections)
                        enforced_cols += len(result.get("applied", []))
                    except Exception:
                        pass
                except Exception as e:
                    st.error(f"Failed tagging {asset}: {e}")
            if enforced_cols > 0:
                st.success(f"Applied tags to {applied} asset(s) and enforced masking on {enforced_cols} column(s).")
            else:
                st.success(f"Applied tags to {applied} asset(s).")

    # CSV-based bulk assignment
    st.markdown("---")
    st.write("**Bulk Assignment via CSV**")
    st.caption("CSV columns required: FULL_NAME, DATA_CLASSIFICATION, C, I, A; optional: JUSTIFICATION. Rationale is REQUIRED for Restricted/Confidential.")
    bulk_file = st.file_uploader("Upload CSV for bulk tagging", type=["csv"], key="bulk_csv")
    dry_run = st.checkbox("Dry run (validate only)", value=True)
    if bulk_file is not None:
        try:
            df_bulk = pd.read_csv(bulk_file)
            st.dataframe(df_bulk.head(20))
            # Embedded policy checklist for bulk operations
            with st.expander("Policy Checklist (applies to this bulk operation)", expanded=False):
                _ck1 = st.checkbox("I have verified data purpose and usage for these assets (Business Context)", key="bulk_ck1")
                _ck2 = st.checkbox("Confidentiality: categories and access/scope considered", key="bulk_ck2")
                _ck3 = st.checkbox("Integrity: controls and impact assessed", key="bulk_ck3")
                _ck4 = st.checkbox("Availability: operational RTO expectations considered", key="bulk_ck4")
                _ck5 = st.checkbox("Regulatory mapping (GDPR/CCPA/HIPAA/PCI/SOX) reviewed where applicable", key="bulk_ck5")
                bulk_policy_ack = st.checkbox("I confirm the above checks for this bulk submission", key="bulk_policy_ack")

            if st.button("Process Bulk CSV", type="primary"):
                if not _can_classify:
                    st.error("You do not have permission to process bulk classification/tagging.")
                    st.stop()
                if not bulk_policy_ack:
                    st.error("Please confirm the Policy Checklist before processing the bulk CSV.")
                    st.stop()
                required_cols = {"FULL_NAME","DATA_CLASSIFICATION","C","I","A"}
                if not required_cols.issubset(set([c.upper() for c in df_bulk.columns])):
                    st.error(f"CSV must include columns: {', '.join(required_cols)}")
                else:
                    # Normalize column map for flexible casing
                    colmap = {c.upper(): c for c in df_bulk.columns}
                    errors = []
                    processed = 0
                    applied = 0
                    dry_run = st.checkbox("Dry run (validate only, no changes)", value=True, key="bulk_dry_run")
                    # Decision matrix validator is used elsewhere as dm_validate
                    try:
                        from src.services.tagging_service import tagging_service as _tag_service
                    except Exception:
                        _tag_service = None
                    user_email_bulk = st.session_state.get("manual_user_email") or str(st.session_state.get("user") or "system")
                    for _, row in df_bulk.iterrows():
                        try:
                            full = str(row.get(colmap["FULL_NAME"]))
                            label = str(row.get(colmap["DATA_CLASSIFICATION"]) or "Internal").title()
                            try:
                                c_val = int(row.get(colmap["C"]) or 0)
                                i_val = int(row.get(colmap["I"]) or 0)
                                a_val = int(row.get(colmap["A"]) or 0)
                            except Exception:
                                raise ValueError("C/I/A must be integers in range 0..3")
                            rationale = str(row.get(colmap["JUSTIFICATION"]) if "JUSTIFICATION" in colmap else row.get(colmap.get("RATIONALE","")) or "")

                            # Decision matrix validation per row
                            ok_dm, reasons_dm = dm_validate(label, int(c_val), int(i_val), int(a_val))
                            if not ok_dm:
                                for r in (reasons_dm or []):
                                    errors.append(f"{full}: {r}")
                                continue

                            # Enforce rationale for higher sensitivity
                            if label in ("Restricted", "Confidential") and not rationale.strip():
                                errors.append(f"{full}: rationale is required for {label}")
                                continue

                            processed += 1
                            try:
                                if dry_run:
                                    # In dry-run, only validate
                                    continue

                                # Apply tags via TaggingService when available for policy enforcement and lifecycle tags
                                tags = {
                                    "DATA_CLASSIFICATION": label,
                                    "CONFIDENTIALITY_LEVEL": str(c_val),
                                    "INTEGRITY_LEVEL": str(i_val),
                                    "AVAILABILITY_LEVEL": str(a_val),
                                }
                                if _tag_service is not None:
                                    _tag_service.apply_tags_to_object(full, "TABLE", tags)
                                else:
                                    # Fallback to internal helper if service unavailable
                                    _sf_apply_tags(full, {
                                        "data_classification": label,
                                        "confidentiality_level": str(c_val),
                                        "integrity_level": str(i_val),
                                        "availability_level": str(a_val),
                                    })
                                    applied += 1
                                    # Audit
                                    try:
                                        audit_service.log(user_email_bulk, "CLASSIFY_APPLY", "ASSET", full, {"risk": None, "c": c_val, "i": i_val, "a": a_val, "rationale": rationale})
                                    except Exception as e1:
                                        try:
                                            _sf_audit_log_classification(full, "BULK_CLASSIFICATION_APPLIED", {"label": label, "c": c_val, "i": i_val, "a": a_val, "rationale": rationale})
                                        except Exception as e2:
                                            errors.append(f"{full}: Audit logging failed - {str(e2)}")

                                # Show progress during dry run
                                if dry_run and processed > 0 and processed % 10 == 0:  # Update every 10 rows during dry run
                                    st.info(f"Validated {processed} row(s) so far. {len(errors)} error(s).")
                                
                            except Exception as e:
                                errors.append(f"Error processing row: {str(e)}")
                                continue
                        except Exception as e:
                            errors.append(f"Error processing row: {str(e)}")
                            continue

                    # Show final results after processing all rows
                    if dry_run:
                        st.info(f"Dry run complete. {processed} row(s) validated successfully. {len(errors)} error(s).")
                    else:
                        st.success(f"Processing complete. {processed} row(s) processed. {applied} tag(s) applied. {len(errors)} error(s).")
                    
                    if errors:
                        st.error("\n".join(errors[:50]))
        except Exception as e:
            st.error(f"Failed to read CSV: {e}")
            import traceback
            st.error(traceback.format_exc())

    # -------------------------------------------------------------
    # Column-level Tagging (Multiplayer)
    # -------------------------------------------------------------
    st.markdown("---")
    with st.expander("Column-level Tagging (Multiplayer)", expanded=True):
        st.caption("Filter down to a table, pick columns, review suggestions, and apply column-level classification tags. URL sync enabled for easy sharing.")

        # URL query param sync to facilitate shared context
        try:
            q = st.experimental_get_query_params() or {}
        except Exception:
            q = {}

        # Cached loaders
        @st.cache_data(ttl=1800)
        def list_databases():
            try:
                rows = snowflake_connector.execute_query(
                    """
                    SELECT DATABASE_NAME AS NAME
                    FROM SNOWFLAKE.ACCOUNT_USAGE.DATABASES
                    WHERE DELETED IS NULL OR DELETED = FALSE
                    ORDER BY NAME
                    LIMIT 200
                    """
                ) or []
                return [r.get("NAME") for r in rows if r.get("NAME")]
            except Exception:
                return []

        @st.cache_data(ttl=1800)
        def list_schemas(db: str):
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT SCHEMA_NAME AS NAME
                    FROM {db}.INFORMATION_SCHEMA.SCHEMATA
                    WHERE SCHEMA_NAME NOT IN ('INFORMATION_SCHEMA')
                    ORDER BY NAME
                    LIMIT 1000
                    """
                ) or []
                return [r.get("NAME") for r in rows if r.get("NAME")]
            except Exception:
                return []

        @st.cache_data(ttl=1800)
        def list_tables(db: str, schema: str):
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT TABLE_NAME AS NAME
                    FROM {db}.INFORMATION_SCHEMA.TABLES
                    WHERE TABLE_SCHEMA = %(sc)s AND TABLE_TYPE IN ('BASE TABLE','VIEW')
                    ORDER BY NAME
                    LIMIT 5000
                    """,
                    {"sc": schema},
                ) or []
                return [r.get("NAME") for r in rows if r.get("NAME")]
            except Exception:
                return []

        @st.cache_data(ttl=1800)
        def list_columns(db: str, schema: str, table: str):
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT COLUMN_NAME, DATA_TYPE, ORDINAL_POSITION
                    FROM {db}.INFORMATION_SCHEMA.COLUMNS
                    WHERE TABLE_SCHEMA = %(sc)s AND TABLE_NAME = %(tb)s
                    ORDER BY ORDINAL_POSITION
                    """,
                    {"sc": schema, "tb": table},
                ) or []
                return rows
            except Exception:
                return []

        # Controls row 1: database, schema, table + url sync
        dbs = list_databases()
        c1, c2, c3, c4 = st.columns([2,2,3,1])
        with c1:
            sel_db = st.selectbox("Database", options=dbs, index=(dbs.index(q.get('db',[sel.get('database') or ''])[0]) if (q.get('db') and q.get('db')[0] in dbs) else (dbs.index(sel.get('database')) if sel.get('database') in dbs else 0)) if dbs else None, key="col_db")
        schemas = list_schemas(sel_db) if sel_db else []
        with c2:
            sel_sc = st.selectbox("Schema", options=schemas, index=(schemas.index(q.get('sc',[sel.get('schema') or ''])[0]) if (q.get('sc') and q.get('sc')[0] in schemas) else (schemas.index(sel.get('schema')) if sel.get('schema') in schemas else 0)) if schemas else None, key="col_sc")
        tables = list_tables(sel_db, sel_sc) if (sel_db and sel_sc) else []
        with c3:
            sel_tb = st.selectbox("Table", options=tables, index=(tables.index(q.get('tb',[sel.get('table') or ''])[0]) if (q.get('tb') and q.get('tb')[0] in tables) else (tables.index(sel.get('table')) if sel.get('table') in tables else 0)) if tables else None, key="col_tb")
        with c4:
            sync = st.checkbox("Sync URL", value=True, help="Include db/schema/table in URL for sharing")
        if sync and sel_db and sel_sc and sel_tb:
            try:
                st.experimental_set_query_params(db=sel_db, sc=sel_sc, tb=sel_tb)
            except Exception:
                pass

        # Controls row 2: column search and multi-select
        cols = list_columns(sel_db, sel_sc, sel_tb) if (sel_db and sel_sc and sel_tb) else []
        table_full = f"{sel_db}.{sel_sc}.{sel_tb}" if (sel_db and sel_sc and sel_tb) else None
        f1, f2 = st.columns([3,2])
        with f1:
            col_search = st.text_input("Filter columns", placeholder="Search by name or data type...", key="col_search")
        col_names = [r.get("COLUMN_NAME") for r in cols]
        if col_search:
            cols_view = [r for r in cols if col_search.lower() in str(r.get("COLUMN_NAME","" )).lower() or col_search.lower() in str(r.get("DATA_TYPE","" )).lower()]
        else:
            cols_view = cols
        with f2:
            selected_columns = st.multiselect("Columns", options=[r.get("COLUMN_NAME") for r in cols_view], default=[r.get("COLUMN_NAME") for r in cols_view[:5]], key="col_pick")

        # Quick select actions (multiplayer-friendly)
        q1, q2, q3 = st.columns([1,1,2])
        with q1:
            if st.button("Select All", key="col_pick_all"):
                st.session_state["col_pick"] = [r.get("COLUMN_NAME") for r in cols_view]
                # Removed st.rerun() to prevent no-op warning
        with q2:
            if st.button("Clear", key="col_pick_clear"):
                st.session_state["col_pick"] = []
                # Removed st.rerun() to prevent no-op warning
        with q3:
            pii_keys = ["SSN","EMAIL","PHONE","ADDRESS","DOB","PII","PERSON","EMPLOYEE","CUSTOMER","CARD","PAN","AADHAAR","PASSPORT","NATIONAL_ID","NAME"]
            if st.button("Quick-select PII-like", key="col_pick_pii"):
                picks = []
                for r in cols_view:
                    nm = (r.get("COLUMN_NAME") or "").upper()
                    if any(k in nm for k in pii_keys):
                        picks.append(r.get("COLUMN_NAME"))
                st.session_state["col_pick"] = picks or st.session_state.get("col_pick", [])
                # Removed st.rerun() to prevent no-op warning

        # Suggested labels via AI detection (best-effort)
        suggestions = {}
        if table_full:
            try:
                det = ai_classification_service.detect_sensitive_columns(table_full, sample_size=200) or []
                colmap = {}
                if isinstance(det, list):
                    for d in det:
                        cname = str(d.get("column") or d.get("COLUMN_NAME") or "").upper()
                        if not cname:
                            continue
                        cat = d.get("dominant_category") or ((d.get("categories") or [None])[0])
                        conf = int(d.get("confidence") or 0)
                        colmap[cname] = {
                            "label": cat or "Internal",
                            "c": int((ai_classification_service._suggest_cia_from_type(cat or "").get("C") if cat else 1) or 1),
                            "i": int((ai_classification_service._suggest_cia_from_type(cat or "").get("I") if cat else 1) or 1),
                            "a": int((ai_classification_service._suggest_cia_from_type(cat or "").get("A") if cat else 1) or 1),
                            "reason": f"detected by AI; confidence={conf}",
                        }
                elif isinstance(det, dict):
                    colmap = det.get("columns") or det
                suggestions = colmap
            except Exception:
                pass

        # Fetch current tags for object/columns (best-effort) to show history/current state
        prev_tags = {}
        if table_full:
            try:
                refs = tagging_service.get_object_tags(table_full, "TABLE")
                # Build a map: COLUMN_NAME -> {TAG_NAME: value}
                for r in refs:
                    col = r.get("COLUMN_NAME") or r.get("COLUMN") or r.get("name")
                    tname = r.get("TAG_NAME") or r.get("TAG") or r.get("TAG_DATABASE")
                    val = r.get("TAG_VALUE") or r.get("VALUE")
                    if not tname:
                        continue
                    tkey = str(tname).split(".")[-1].upper()
                    if col:
                        prev_tags.setdefault(str(col).upper(), {})[tkey] = val
                    else:
                        prev_tags.setdefault("__OBJECT__", {})[tkey] = val
            except Exception:
                prev_tags = {}

        # Build editable grid: columns with type, suggestion, and chosen tagging
        import pandas as _pd  # safe inside block
        grid_rows = []
        for r in cols_view:
            nm = r.get("COLUMN_NAME")
            if nm not in selected_columns:
                continue
            typ = r.get("DATA_TYPE")
            sug = suggestions.get(str(nm).upper(), {})
            sc, si, sa = sug.get("c", 1), sug.get("i", 1), sug.get("a", 1)
            slabel = sug.get("label", "Internal")
            # Merge with previous tags to show current state
            cur = prev_tags.get(str(nm).upper(), {})
            cur_label = cur.get("DATA_CLASSIFICATION") or slabel
            try:
                cur_c = int(cur.get("CONFIDENTIALITY_LEVEL", sc))
                cur_i = int(cur.get("INTEGRITY_LEVEL", si))
                cur_a = int(cur.get("AVAILABILITY_LEVEL", sa))
            except Exception:
                cur_c, cur_i, cur_a = sc, si, sa
            grid_rows.append({
                "Column": nm,
                "Type": typ,
                "Suggested Label": slabel,
                "C": ["0 - Public","1 - Internal","2 - Restricted","3 - Confidential"][max(0, min(3, int(cur_c)))],
                "I": ["0 - Low","1 - Standard","2 - High","3 - Critical"][max(0, min(3, int(cur_i)))],
                "A": ["0 - Low","1 - Standard","2 - High","3 - Critical"][max(0, min(3, int(cur_a)))],
                "Label": cur_label if cur_label in ALLOWED_CLASSIFICATIONS else "Internal",
                "Reason": sug.get("reason", ""),
                "Current Tags": ", ".join([f"{k}={v}" for k, v in cur.items()]) if cur else "",
            })
        df_grid = _pd.DataFrame(grid_rows) if grid_rows else _pd.DataFrame(columns=["Column","Type","Suggested Label","C","I","A","Label","Reason","Current Tags"])
        if not df_grid.empty:
            try:
                # Force CIA columns to string/categorical for labeled select rendering
                for _col in ("C","I","A"):
                    if _col in df_grid.columns:
                        df_grid[_col] = df_grid[_col].astype(str)
                _c_opts = ["0 - Public","1 - Internal","2 - Restricted","3 - Confidential"]
                _ai_opts = ["0 - Low","1 - Standard","2 - High","3 - Critical"]
                if "C" in df_grid.columns:
                    df_grid["C"] = _pd.Categorical(df_grid["C"], categories=_c_opts, ordered=True)
                if "I" in df_grid.columns:
                    df_grid["I"] = _pd.Categorical(df_grid["I"], categories=_ai_opts, ordered=True)
                if "A" in df_grid.columns:
                    df_grid["A"] = _pd.Categorical(df_grid["A"], categories=_ai_opts, ordered=True)
            except Exception:
                pass

        # Bulk defaults for selected rows
        b1, b2, b3, b4, b5 = st.columns([2,1,1,1,1])
        with b1:
            bulk_label = st.selectbox("Set Label for selected", options=ALLOWED_CLASSIFICATIONS, index=1, key="col_bulk_label")
        with b2:
            bulk_c = st.number_input("C", 0, 3, int(1))
        with b3:
            bulk_i = st.number_input("I", 0, 3, int(1))
        with b4:
            bulk_a = st.number_input("A", 0, 3, int(1))
        with b5:
            if st.button("Apply to selected rows", key="col_bulk_apply_btn"):
                st.session_state.setdefault("col_bulk", {})
                st.session_state["col_bulk"].update({"apply": True, "label": bulk_label, "c": int(bulk_c), "i": int(bulk_i), "a": int(bulk_a), "target": set(selected_columns)})
                # Removed st.rerun() to prevent no-op warning

        # Interactive editor with constrained choices for Label and CIA
        editor_conf = {
            "Label": st.column_config.SelectboxColumn(options=ALLOWED_CLASSIFICATIONS, help="Classification label"),
            "C": st.column_config.SelectboxColumn(options=["0 - Public","1 - Internal","2 - Restricted","3 - Confidential"], help="Confidentiality: 0=Public, 1=Internal, 2=Restricted, 3=Confidential"),
            "I": st.column_config.SelectboxColumn(options=["0 - Low","1 - Standard","2 - High","3 - Critical"], help="Integrity: 0=Low, 1=Standard, 2=High, 3=Critical"),
            "A": st.column_config.SelectboxColumn(options=["0 - Low","1 - Standard","2 - High","3 - Critical"], help="Availability: 0=Low, 1=Standard, 2=High, 3=Critical"),
        }
        # If bulk apply flag set, override grid_rows before rendering
        _bulk = st.session_state.get("col_bulk") or {}
        if _bulk.get("apply") and grid_rows:
            tgt = _bulk.get("target") or set()
            for row in grid_rows:
                if row.get("Column") in tgt:
                    row["Label"] = _bulk.get("label")
                    row["C"] = ["0 - Public","1 - Internal","2 - Restricted","3 - Confidential"][max(0, min(3, int(_bulk.get("c", 1))))]
                    row["I"] = ["0 - Low","1 - Standard","2 - High","3 - Critical"][max(0, min(3, int(_bulk.get("i", 1))))]
                    row["A"] = ["0 - Low","1 - Standard","2 - High","3 - Critical"][max(0, min(3, int(_bulk.get("a", 1))))]
            # reset flag after applying
            st.session_state["col_bulk"]["apply"] = False
        df_grid = _pd.DataFrame(grid_rows) if grid_rows else _pd.DataFrame(columns=["Column","Type","Suggested Label","C","I","A","Label","Reason","Current Tags"])

        edited_df = st.data_editor(
            df_grid,
            num_rows="dynamic",
            use_container_width=True,
            column_config=editor_conf,
            disabled=["Column","Type","Suggested Label","Current Tags"],
            key="col_editor",
        )

        # Optional: Tag history drawer (last 5 decisions per selected column)
        show_hist = st.checkbox("Show tag history (last 5 / column)", value=False, key="col_hist_toggle")
        if show_hist and table_full and selected_columns:
            try:
                from datetime import datetime as _dt  # localize import
                DB = _get_current_db()
                for colnm in selected_columns[:10]:
                    with st.expander(f"History: {table_full}.{colnm}", expanded=False):
                        try:
                            rows = snowflake_connector.execute_query(
                                f"""
                                SELECT ID, DECIDED_AT, DECIDED_BY, SOURCE, STATUS, LABEL, C, I, A, RISK_LEVEL, RATIONALE
                                FROM {DB}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_DECISIONS
                                WHERE ASSET_FULL_NAME = %(afn)s
                                ORDER BY DECIDED_AT DESC
                                LIMIT 5
                                """,
                                {"afn": f"{table_full}.{colnm}"},
                            ) or []
                            st.dataframe(_pd.DataFrame(rows), use_container_width=True)
                        except Exception as e:
                            st.info(f"No history available: {e}")
            except Exception:
                pass

        # Apply actions
        user_email_cols = st.text_input("Your email (for audit)", key="col_user_email")
        col_just = st.text_area(
            "Rationale (required for Restricted/Confidential; stored in audit)",
            key="col_just",
            height=80,
        )
        apply_cols_btn = st.button("Apply Column Tags", type="primary", key="btn_apply_cols")

        if apply_cols_btn:
            if not _can_classify:
                st.error("You do not have permission to apply classifications or tags.")
                st.stop()
            if not table_full or not selected_columns:
                st.warning("Select a database, schema, table and at least one column.")
                st.stop()
            # Privilege check at table level
            if not authz.can_apply_tags_for_object(table_full, object_type="TABLE"):
                st.error("Insufficient privileges to tag columns on this table (ALTER/OWNERSHIP required)")
                st.stop()
            from src.services.audit_service import audit_service as _audit
            applied = 0
            errors = []
            # Iterate over edited grid rows to pick chosen values
            for _, row in edited_df.iterrows():
                colnm = row.get("Column")
                if colnm not in selected_columns:
                    continue
                try:
                    label = str(row.get("Label") or row.get("Suggested Label") or "Internal")
                    # Parse labeled values like "1 - Internal" back to integers 0..3
                    try:
                        c_b = int(str(row.get("C")).split('-')[0].strip())
                    except Exception:
                        c_b = int(row.get("C") or 1)
                    try:
                        i_b = int(str(row.get("I")).split('-')[0].strip())
                    except Exception:
                        i_b = int(row.get("I") or 1)
                    try:
                        a_b = int(str(row.get("A")).split('-')[0].strip())
                    except Exception:
                        a_b = int(row.get("A") or 1)
                    if label not in ALLOWED_CLASSIFICATIONS or not (0 <= c_b <= 3 and 0 <= i_b <= 3 and 0 <= a_b <= 3):
                        errors.append(f"{table_full}.{colnm}: invalid Label or CIA levels")
                        continue
                    # Enforce decision matrix (CIA-to-label minimums and special categories)
                    ok_dm, reasons_dm = dm_validate(label, int(c_b), int(i_b), int(a_b))
                    if not ok_dm:
                        for r in (reasons_dm or []):
                            errors.append(f"{table_full}.{colnm}: {r}")
                        continue
                    # Require rationale for higher sensitivity labels
                    if label in ("Restricted", "Confidential") and not (col_just and col_just.strip()):
                        errors.append(f"{table_full}.{colnm}: rationale is required for {label}")
                        continue
                    tagging_service.apply_tags_to_column(
                        table_full,
                        colnm,
                        {
                            "DATA_CLASSIFICATION": label,
                            "CONFIDENTIALITY_LEVEL": str(c_b),
                            "INTEGRITY_LEVEL": str(i_b),
                            "AVAILABILITY_LEVEL": str(a_b),
                        },
                    )
                    # Optional: record decision at column granularity
                    try:
                        classification_decision_service.record(
                            asset_full_name=f"{table_full}.{colnm}",
                            decision_by=user_email_cols or (user_email or "system"),
                            source="MANUAL",
                            status="Applied",
                            label=label,
                            c=c_b, i=i_b, a=a_b,
                            rationale=(col_just or justification or ""),
                            details={"scope": "COLUMN"},
                        )
                    except Exception:
                        pass
                    _audit.log(user_email_cols or (user_email or "system"), "COLUMN_CLASSIFY_APPLY", "COLUMN", f"{table_full}.{colnm}", {"cls": label, "c": c_b, "i": i_b, "a": a_b, "just": col_just})
                    applied += 1
                except Exception as e:
                    errors.append(f"{table_full}.{colnm}: {e}")
            if applied and not errors:
                st.success(f"Applied tags to {applied} column(s).")
            elif applied and errors:
                st.success(f"Applied tags to {applied} column(s). {len(errors)} error(s).")
                st.error("\n".join(errors[:50]))
            else:
                st.error("No column tags applied.")

with tab2:
    # AI Detection
    st.subheader("AI Detection")
    st.write("Use AI to suggest labels, CIA scores, evidence snippets, and applicable frameworks. Apply or submit for approval.")
    # Quick actions: run in-database Snowpark heuristic or native SYSTEM$CLASSIFY for a selected asset
    try:
        # Load a small asset list for selection
        aset_rows = snowflake_connector.execute_query(
            f"""
            SELECT "TABLE_CATALOG"||'.'||"TABLE_SCHEMA"||'.'||"TABLE_NAME" AS FULL
            FROM {_get_current_db()}.INFORMATION_SCHEMA.TABLES
            WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
            ORDER BY 1 LIMIT 100
            """
        ) or []
        aset_opts = [r.get('FULL') for r in aset_rows if r.get('FULL')]
    except Exception:
        aset_opts = []
    col_ai1, col_ai2 = st.columns([3,1])
    with col_ai1:
        target_asset = st.selectbox("Select asset for AI detection", options=aset_opts, index=0 if aset_opts else None, key="ai_det_asset")
    with col_ai2:
        run_sp = st.button("Snowpark Classify", key="btn_ai_sp")
        run_sys = st.button("SYSTEM$CLASSIFY", key="btn_ai_sys")
    if run_sp and target_asset:
        with st.spinner("Running Snowpark contextual classification..."):
            res = snowpark_udf_service.classify_table(target_asset)
        st.success(f"Label: {res.get('label')} | Confidence: {res.get('confidence')}")
        st.json({k: v for k, v in res.items() if k != 'features'})
    if run_sys and target_asset:
        with st.spinner("Running SYSTEM$CLASSIFY for selected asset..."):
            try:
                out = snowflake_connector.execute_query("SELECT SYSTEM$CLASSIFY('TABLE', %(f)s) AS R", {"f": target_asset}) or []
                st.json(out[0] if out else {})
            except Exception as e:
                st.error(f"SYSTEM$CLASSIFY failed: {e}")
    try:
        from src.services.ai_classification_service import ai_classification_service
        # Asset list
        try:
            with st.spinner("Loading assets from Snowflake..."):
                tables = snowflake_connector.execute_query(
                    f"""
                    SELECT "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS full_name
                    FROM {_get_current_db()}.INFORMATION_SCHEMA.TABLES
                    WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
                    ORDER BY "TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME"
                    LIMIT 200
                    """
                )
                asset_options = [t['FULL_NAME'] for t in tables] if tables else []
        except Exception as e:
            st.warning(f"Could not load assets: {e}")
            asset_options = []

        # Search/filter across datasets
        ai_search = st.text_input("Search datasets", placeholder="Type to filter by name...", key="ai_search")
        ai_options = [a for a in asset_options if (ai_search.lower() in a.lower())] if ai_search else asset_options
        selected_asset = st.selectbox("Select an asset", ai_options if ai_options else ["No assets available"]) 

        if st.button("Get AI Suggestion", type="primary") and selected_asset and selected_asset != "No assets available":
            with st.spinner("Analyzing data asset with AI..."):
                try:
                    _ctx = None
                    try:
                        _ctx = ai_classification_service.build_enriched_context(selected_asset, sample_rows=10)
                    except Exception:
                        _ctx = None
                    result = ai_classification_service.classify_table(selected_asset, context=_ctx)
                    st.success(f"AI Classification for {selected_asset}")
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Suggested Label", result.get('classification', 'Unknown'))
                    c2.metric("Confidence", f"{result.get('confidence', 0)*100:.1f}%")
                    c3.metric("Frameworks", ", ".join(result.get('compliance_frameworks', [])) or "None")

                    # Evidence snippets (sample rows)
                    try:
                        sample_df = ai_classification_service.get_sample_data(selected_asset, 5)
                        if not sample_df.empty:
                            st.caption("Evidence snippets (first 5 rows)")
                            st.dataframe(sample_df.head(5))
                    except Exception:
                        pass

                    # CIA defaults from label registry
                    suggested_cls = result.get('classification') or 'Internal'
                    try:
                        labels = label_service.list_labels()
                        defaults = next((l for l in (labels or []) if str(l.get('LABEL_NAME')).lower() == suggested_cls.lower()), None)
                        if defaults:
                            def_c = int(defaults.get('DEFAULT_C') or 1)
                            def_i = int(defaults.get('DEFAULT_I') or 1)
                            def_a = int(defaults.get('DEFAULT_A') or 1)
                        else:
                            mapping = {'Public': (0,0,0),'Internal':(1,1,1),'Restricted':(2,2,2),'Confidential':(3,3,3)}
                            def_c, def_i, def_a = mapping.get(suggested_cls, (1,1,1))
                    except Exception:
                        def_c, def_i, def_a = 1, 1, 1

                    st.markdown("---")
                    st.write("Suggested CIA (editable)")
                    cc, ii, aa = st.columns(3)
                    with cc:
                        sug_c = st.number_input("C", 0, 3, int(def_c))
                    with ii:
                        sug_i = st.number_input("I", 0, 3, int(def_i))
                    with aa:
                        sug_a = st.number_input("A", 0, 3, int(def_a))

                    default_just = f"AI suggested '{suggested_cls}' with frameworks: {', '.join(result.get('compliance_frameworks', []))}"
                    justification = st.text_area("Justification", value=default_just)
                    user_email = st.text_input("Your email (for audit)", key="ai_user_email")

                    col_left, col_right = st.columns(2)
                    with col_left:
                        if st.button("Submit for Approval") and user_email:
                            try:
                                rid = reclassification_service.submit_request(
                                    selected_asset,
                                    (suggested_cls if suggested_cls in ALLOWED_CLASSIFICATIONS else 'Internal', int(sug_c), int(sug_i), int(sug_a)),
                                    justification or default_just,
                                    user_email,
                                    trigger_type="AI_SUGGESTED",
                                )
                                st.success(f"Submitted reclassification request: {rid}")
                            except Exception as e:
                                st.error(f"Failed to submit request: {e}")
                    with col_right:
                        if st.button("Apply Now"):
                            if not _can_classify:
                                st.error("You do not have permission to apply classifications or tags. Contact a Data Owner or Admin.")
                                st.stop()
                            try:
                                # Validate guardrails
                                ok2, reasons2 = dm_validate(suggested_cls if suggested_cls in ALLOWED_CLASSIFICATIONS else 'Internal', int(sug_c), int(sug_i), int(sug_a))
                                if not ok2:
                                    for r in reasons2:
                                        st.error(r)
                                    st.stop()
                                # Gate C3/Confidential behind approval if user lacks approval capability
                                requires_approval_ai = ((result.get('classification') or '').lower() == 'confidential' or int(sug_c) == 3) and (not _can_approve)
                                if requires_approval_ai:
                                    from src.services.reclassification_service import reclassification_service as _reclass
                                    rid = _reclass.submit_request(
                                        selected_asset,
                                        (suggested_cls if suggested_cls in ALLOWED_CLASSIFICATIONS else 'Internal', int(sug_c), int(sug_i), int(sug_a)),
                                        justification or default_just or "AI suggested C3/Confidential - approval required",
                                        user_email or "system",
                                        trigger_type="AI_SUGGESTED_HIGH_RISK",
                                    )
                                    # Record submitted decision
                                    try:
                                        classification_decision_service.record(
                                            asset_full_name=selected_asset,
                                            decision_by=user_email or "system",
                                            source="AI_SUGGESTED",
                                            status="Submitted",
                                            label=suggested_cls if suggested_cls in ALLOWED_CLASSIFICATIONS else 'Internal',
                                            c=int(sug_c), i=int(sug_i), a=int(sug_a),
                                            rationale=justification or default_just or "",
                                            details={"request_id": rid},
                                        )
                                    except Exception:
                                        pass
                                    st.success(f"Submitted reclassification request for approval: {rid}")
                                    st.stop()
                                if not authz.can_apply_tags_for_object(selected_asset, object_type="TABLE"):
                                    st.error("Insufficient privileges to apply tags to this asset (ALTER/OWNERSHIP required).")
                                    st.stop()
                                tagging_service.apply_tags_to_object(
                                    selected_asset,
                                    "TABLE",
                                    {
                                        "DATA_CLASSIFICATION": suggested_cls if suggested_cls in ALLOWED_CLASSIFICATIONS else 'Internal',
                                        "CONFIDENTIALITY_LEVEL": str(int(sug_c)),
                                        "INTEGRITY_LEVEL": str(int(sug_i)),
                                        "AVAILABILITY_LEVEL": str(int(sug_a)),
                                    },
                                )
                                # Record applied decision from AI suggestion
                                try:
                                    classification_decision_service.record(
                                        asset_full_name=selected_asset,
                                        decision_by=user_email or "system",
                                        source="AI_SUGGESTED",
                                        status="Applied",
                                        label=suggested_cls if suggested_cls in ALLOWED_CLASSIFICATIONS else 'Internal',
                                        c=int(sug_c), i=int(sug_i), a=int(sug_a),
                                        rationale=justification or default_just or "",
                                        details=None,
                                    )
                                except Exception:
                                    pass
                                st.success("Applied suggested tags.")
                            except Exception as e:
                                st.error(f"Failed to apply tags: {e}")

                    with st.expander("View detailed AI features"):
                        st.json(result.get('features', {}))
                except Exception as e:
                    st.error(f"Error during AI classification: {str(e)}")
    except ImportError as e:
        st.error(f"AI classification service not available: {str(e)}")
        st.info("Please ensure all required dependencies are installed.")

with tab3:
    st.subheader("Risk Analysis")
    st.write("Compute overall risk based on highest CIA score. Highlight high-risk datasets.")
    try:
        only_classified = st.checkbox("Only classified assets", value=True, help="Show only assets with CLASSIFIED = TRUE")
        where_clause = "WHERE CLASSIFIED = TRUE" if only_classified else ""
        rows = snowflake_connector.execute_query(
            f"""
            SELECT 
              FULLY_QUALIFIED_NAME AS FULL_NAME,
              CLASSIFICATION_LABEL AS CLASSIFICATION_LEVEL,
              NULL AS CIA_CONF, NULL AS CIA_INT, NULL AS CIA_AVAIL
            FROM {_get_current_db()}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS
            {where_clause}
            LIMIT 500
            """
        ) or []
        df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=["FULL_NAME","CLASSIFICATION_LEVEL","CIA_CONF","CIA_INT","CIA_AVAIL"])
        if not df.empty:
            # Normalize CIA columns to integers; handle NaN/None safely
            for col in ["CIA_CONF", "CIA_INT", "CIA_AVAIL"]:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
            def risk_row(r):
                highest = max(int(r.get('CIA_CONF') or 0), int(r.get('CIA_INT') or 0), int(r.get('CIA_AVAIL') or 0))
                level = 'Low' if highest <= 1 else ('Medium' if highest == 2 else 'High')
                rationale = f"Highest CIA={highest} from C={r.get('CIA_CONF')}, I={r.get('CIA_INT')}, A={r.get('CIA_AVAIL')}"
                # Regulatory chips
                name = str(r.get('FULL_NAME') or '')
                up = name.upper()
                regs = []
                if any(k in up for k in ["SOX","FINANCE","GL","PAYROLL","INVOICE","AUDIT"]):
                    regs.append("SOX/SOC2")
                if any(k in up for k in ["GDPR","EU","DATA_SUBJECT","DSR"]):
                    regs.append("GDPR")
                if any(k in up for k in ["HIPAA","PHI","HEALTH","MEDICAL"]):
                    regs.append("HIPAA")
                # Risk indicator emoji
                emoji = '🟢' if level == 'Low' else ('🟠' if level == 'Medium' else '🔴')
                return pd.Series({"RISK": level, "RISK_IND": emoji, "Regulatory": ", ".join(regs), "RegsList": regs, "Rationale": rationale, "HIGHEST": highest})
            risk = df.apply(risk_row, axis=1)
            out = pd.concat([df, risk], axis=1)
            # Min CIA threshold filter
            min_threshold = st.slider("Min CIA threshold", min_value=0, max_value=3, value=0, help="Show assets with max(C,I,A) >= threshold")
            out = out[out["HIGHEST"] >= int(min_threshold)] if not out.empty else out
            st.markdown("**Legend:** 🔴 High  🟠 Medium  🟢 Low")
            show_cols = ["RISK_IND","FULL_NAME","CLASSIFICATION_LEVEL","CIA_CONF","CIA_INT","CIA_AVAIL","RISK","Regulatory","Rationale"]
            st.dataframe(out[show_cols], use_container_width=True)
            try:
                csv_bytes = out[show_cols].to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="Download Risk Analysis (CSV)",
                    data=csv_bytes,
                    file_name="risk_analysis.csv",
                    mime="text/csv",
                )
            except Exception:
                pass

            # Summary metrics
            high_count = (out['RISK'] == 'High').sum()
            med_count = (out['RISK'] == 'Medium').sum()
            low_count = (out['RISK'] == 'Low').sum()
            c1, c2, c3 = st.columns(3)
            c1.metric("High Risk", int(high_count))
            c2.metric("Medium Risk", int(med_count))
            c3.metric("Low Risk", int(low_count))
            if high_count:
                st.warning(f"{int(high_count)} high-risk datasets detected")
            # Risk distribution chart
            try:
                dist_df = pd.DataFrame({"Risk": ["High","Medium","Low"], "Count": [int(high_count), int(med_count), int(low_count)]})
                st.bar_chart(dist_df.set_index("Risk"))
            except Exception:
                pass

            # Pill-style regulatory chips (card view)
            with st.expander("Show chip-style view"):
                st.markdown(
                    """
                    <style>
                      .chip {display:inline-block;padding:2px 8px;margin:2px;border-radius:12px;font-size:12px;color:white}
                      .chip-sox {background-color:#6c5ce7}
                      .chip-gdpr {background-color:#0984e3}
                      .chip-hipaa {background-color:#00b894}
                      .chip-other {background-color:#636e72}
                      .card {border:1px solid #e0e0e0;border-radius:8px;padding:8px;margin-bottom:8px}
                      .risk-high {border-left:6px solid #e74c3c}
                      .risk-med {border-left:6px solid #e67e22}
                      .risk-low {border-left:6px solid #2ecc71}
                    </style>
                    """,
                    unsafe_allow_html=True,
                )
                # Limit number of cards for performance
                subset = out.head(100)
                for _, row in subset.iterrows():
                    regs = row.get("RegsList") or []
                    chips = []
                    for r in regs:
                        cls = "chip-other"
                        if r.startswith("SOX"): cls = "chip-sox"
                        elif r == "GDPR": cls = "chip-gdpr"
                        elif r == "HIPAA": cls = "chip-hipaa"
                        chips.append(f"<span class=\"chip {cls}\">{r}</span>")
                    chips_html = " ".join(chips) if chips else "<span class='chip chip-other'>None</span>"
                    risk_cls = "risk-high" if row.get("RISK") == "High" else ("risk-med" if row.get("RISK") == "Medium" else "risk-low")
                    risk_ind = row.get('RISK_IND','')
                    full_name = row.get('FULL_NAME','')
                    cls_level = row.get('CLASSIFICATION_LEVEL','-')
                    c_val = row.get('CIA_CONF',0)
                    i_val = row.get('CIA_INT',0)
                    a_val = row.get('CIA_AVAIL',0)
                    rationale = row.get('Rationale','')
                    html = f"""
                    <div class='card {risk_cls}'>
                      <div><b>{risk_ind} {full_name}</b></div>
                      <div>Classification: {cls_level} | C:{c_val} I:{i_val} A:{a_val}</div>
                      <div>Regulatory: {chips_html}</div>
                      <div style='color:#636e72;font-size:12px'>Rationale: {rationale}</div>
                    </div>
                    """
                    st.markdown(html, unsafe_allow_html=True)
        else:
            st.info("No inventory found. Run discovery scan to populate inventory.")
    except Exception as e:
        st.warning(f"Risk analysis unavailable: {e}")

with tab4:
    st.subheader("Reclassification")
    st.write("Track triggers, submit requests with impact assessment, and manage approvals.")

    # Ensure DB context is aligned to selection before running triggers/queries
    _set_db_from_filters_if_available()
    # Source: Reads FULLY_QUALIFIED_NAME rows from {DB}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS and applies your Global Filters.

    st.markdown("---")
    st.subheader("Provisional I/A Review")
    st.caption("Review assets where automated I/A assignment is provisional. Finalize Integrity and Availability with business rationale.")
    try:
        db = _get_current_db()
        prov = snowflake_connector.execute_query(
            f"""
            SELECT ID, ASSET_FULL_NAME, REASON, CONFIDENCE, SENSITIVE_CATEGORIES, CREATED_AT, DETAILS
            FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_QUEUE
            WHERE REASON = 'PROVISIONAL_IA'
            ORDER BY CREATED_AT ASC
            LIMIT 500
            """
        ) or []
    except Exception as e:
        prov = []
        st.info(f"Provisional queue unavailable: {e}")

    if prov:
        import pandas as _pd
        pdf = _pd.DataFrame(prov)
        st.dataframe(pdf[[c for c in ["ID","ASSET_FULL_NAME","REASON","CONFIDENCE","SENSITIVE_CATEGORIES","CREATED_AT"] if c in pdf.columns]], use_container_width=True)
        sel_id = st.selectbox("Select provisional item", options=[p.get("ID") for p in prov])
        chosen = next((p for p in prov if p.get("ID") == sel_id), None)
        if chosen:
            st.write(f"Asset: {chosen.get('ASSET_FULL_NAME')}")
            st.json({"detected_categories": chosen.get("SENSITIVE_CATEGORIES"), "details": chosen.get("DETAILS")})
            ccol1, ccol2, ccol3 = st.columns(3)
            with ccol1:
                i_fix = st.number_input("Finalize I (0-3)", min_value=0, max_value=3, value=2, key="prov_fix_i")
            with ccol2:
                a_fix = st.number_input("Finalize A (0-3)", min_value=0, max_value=3, value=2, key="prov_fix_a")
            with ccol3:
                cls_fix = st.selectbox("Classification", options=ALLOWED_CLASSIFICATIONS, index=1, key="prov_fix_cls")
            rat = st.text_area("Rationale (required)", height=80, key="prov_fix_rat")
            approver = st.text_input("Your email (approver)", key="prov_fix_user")
            if st.button("Finalize I/A & Apply", type="primary", key="prov_fix_apply"):
                if not approver:
                    st.warning("Please enter your email.")
                elif not rat or not rat.strip():
                    st.warning("Please provide rationale.")
                else:
                    full = chosen.get("ASSET_FULL_NAME")
                    try:
                        # Apply tags to object with finalized I/A, keep existing C/label from selection
                        tagging_service.apply_tags_to_object(
                            full,
                            "TABLE",
                            {
                                "DATA_CLASSIFICATION": cls_fix,
                                "CONFIDENTIALITY_LEVEL": str(max(int(i_fix), int(a_fix))) if cls_fix == "Internal" else ("2" if cls_fix == "Restricted" else ("3" if cls_fix == "Confidential" else "0")),
                                "INTEGRITY_LEVEL": str(int(i_fix)),
                                "AVAILABILITY_LEVEL": str(int(a_fix)),
                            },
                        )
                        # Persist decision for audit
                        try:
                            classification_decision_service.record(
                                asset_full_name=full,
                                decision_by=approver,
                                source="REVIEW",
                                status="Applied",
                                label=cls_fix,
                                c=int(max(int(i_fix), int(a_fix))),
                                i=int(i_fix),
                                a=int(a_fix),
                                rationale=rat,
                                details={"source": "PROVISIONAL_IA_REVIEW", "queue_id": chosen.get("ID")},
                            )
                        except Exception:
                            pass
                        # Remove from provisional queue
                        try:
                            snowflake_connector.execute_non_query(
                                f"DELETE FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_QUEUE WHERE ID = %(id)s",
                                {"id": chosen.get("ID")},
                            )
                        except Exception:
                            pass
                        st.success("Finalized I/A and applied tags. Queue item cleared.")
                    except Exception as e:
                        st.error(f"Failed to finalize I/A: {e}")
    else:
        st.info("No provisional I/A items pending review.")
    try:
        # Detect triggers
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Detect Triggers (auto)"):
                try:
                    created = reclassification_service.detect_triggers()
                    st.success(f"Created {created} reclassification trigger(s)")
                except Exception as e:
                    st.error(f"Trigger detection failed: {e}")
        with c2:
            st.caption("Auto-triggers: overdue classification, recent DDL changes")

        # Manual submission
        st.markdown("---")
        st.write("Submit a Reclassification Request")
        try:
            tables = snowflake_connector.execute_query(
                f"""
                SELECT "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS full_name
                FROM {_get_current_db()}.INFORMATION_SCHEMA.TABLES
                WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
                ORDER BY "TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME"
                LIMIT 200
                """
            )
            asset_options = [t['FULL_NAME'] for t in tables] if tables else []
        except Exception:
            asset_options = []
        asset = st.selectbox("Asset", options=asset_options if asset_options else ["No assets available"], key="reclass_asset")
        colc, coli, cola = st.columns(3)
        with colc:
            pc = st.number_input("Proposed C", 0, 3, 1)
        with coli:
            pi = st.number_input("Proposed I", 0, 3, 1)
        with cola:
            pa = st.number_input("Proposed A", 0, 3, 1)
        pcls = st.selectbox("Proposed Classification", options=ALLOWED_CLASSIFICATIONS)
        impact = st.text_area("Impact Assessment & Stakeholders", placeholder="Describe business impact, stakeholders to notify, approvals required...")
        requester = st.text_input("Your email (requester)", key="reclass_requester")
        if st.button("Submit Request") and requester and asset and asset != "No assets available":
            try:
                rid = reclassification_service.submit_request(
                    asset,
                    (pcls, int(pc), int(pi), int(pa)),
                    impact or "Manual reclassification request",
                    requester,
                    trigger_type="MANUAL",
                )
                st.success(f"Submitted request {rid}")
            except Exception as e:
                st.error(f"Failed to submit request: {e}")

        # Approvals queue
        st.markdown("---")
        st.write("Approvals (Data Owners/Admins)")
        status = st.selectbox("Status filter", ["All", "Pending", "Approved", "Rejected"], index=1, key="reclass_status")
        limit = st.slider("Max rows", 10, 500, 100, 10, key="reclass_limit")
        if status == "All":
            rows = reclassification_service.list_requests(limit=limit)
        else:
            rows = reclassification_service.list_requests(status=status, limit=limit)
        if rows:
            df = pd.DataFrame(rows)
            show_cols = [
                "ID","ASSET_FULL_NAME","TRIGGER_TYPE","CURRENT_CLASSIFICATION","CURRENT_C","CURRENT_I","CURRENT_A",
                "PROPOSED_CLASSIFICATION","PROPOSED_C","PROPOSED_I","PROPOSED_A","STATUS","CREATED_BY","CREATED_AT"
            ]
            for c in show_cols:
                if c not in df.columns:
                    df[c] = None
            # Defensive CIA normalization for display
            for col in ["CURRENT_C","CURRENT_I","CURRENT_A","PROPOSED_C","PROPOSED_I","PROPOSED_A"]:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
            st.dataframe(df[show_cols], use_container_width=True)
            sel = st.selectbox("Select Request", options=[r.get("ID") for r in rows])
            approver = st.text_input("Your email (approver)", key="reclass_approver")
            c1, c2 = st.columns(2)
            with c1:
                if st.button("Approve & Apply", type="primary") and sel and approver:
                    try:
                        reclassification_service.approve(sel, approver)
                        st.success("Approved and applied tags.")
                    except Exception as e:
                        st.error(f"Approval failed: {e}")
            with c2:
                justification = st.text_input("Rejection justification", key="reclass_reject_just")
                if st.button("Reject") and sel and approver:
                    try:
                        reclassification_service.reject(sel, approver, justification)
                        st.success("Rejected request.")
                    except Exception as e:
                        st.error(f"Rejection failed: {e}")
        else:
            st.info("No requests found.")
    except Exception as e:
        st.warning(f"Reclassification module unavailable: {e}")

with tab5:
    st.subheader("History")
    st.write("View historical classifications and audit trail for a dataset.")
    # Select dataset
    try:
        tables = snowflake_connector.execute_query(
            f"""
            SELECT "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS full_name
            FROM {_get_current_db()}.INFORMATION_SCHEMA.TABLES
            WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
            ORDER BY "TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME"
            LIMIT 200
            """
        )
        asset_options = [t['FULL_NAME'] for t in tables] if tables else []
    except Exception:
        asset_options = []
    hist_asset = st.selectbox("Select dataset", options=asset_options if asset_options else ["No assets available"], key="hist_asset")

    from src.services.audit_service import audit_service
    if hist_asset and hist_asset != "No assets available":
        # Show reclassification history
        try:
            reqs = reclassification_service.list_requests(limit=500)
            reqs_df = pd.DataFrame([r for r in reqs if r.get("ASSET_FULL_NAME") == hist_asset])
            if not reqs_df.empty:
                st.write("Reclassification Requests:")
                show_cols = [
                    "CREATED_AT","STATUS","TRIGGER_TYPE","CURRENT_CLASSIFICATION","CURRENT_C","CURRENT_I","CURRENT_A",
                    "PROPOSED_CLASSIFICATION","PROPOSED_C","PROPOSED_I","PROPOSED_A","CREATED_BY","APPROVED_BY","JUSTIFICATION"
                ]
                for c in show_cols:
                    if c not in reqs_df.columns:
                        reqs_df[c] = None
                # Defensive CIA normalization for display
                for col in ["CURRENT_C","CURRENT_I","CURRENT_A","PROPOSED_C","PROPOSED_I","PROPOSED_A"]:
                    if col in reqs_df.columns:
                        reqs_df[col] = pd.to_numeric(reqs_df[col], errors="coerce").fillna(0).astype(int)
                st.dataframe(reqs_df[show_cols], use_container_width=True)
                try:
                    req_csv = reqs_df[show_cols].to_csv(index=False).encode("utf-8")
                    st.download_button(
                        label="Download Requests (CSV)",
                        data=req_csv,
                        file_name="classification_history_requests.csv",
                        mime="text/csv",
                    )
                except Exception:
                    pass
            else:
                st.info("No reclassification requests found for this asset.")
        except Exception as e:
            st.warning(f"Failed to load reclassification history: {e}")

        # Show audit trail
        try:
            logs = audit_service.query(limit=500)
            logs_df = pd.DataFrame([l for l in (logs or []) if l.get("RESOURCE_ID") == hist_asset])
            if not logs_df.empty:
                st.write("Audit Trail:")
                log_cols = ["TIMESTAMP","USER_ID","ACTION","DETAILS"]
                for c in log_cols:
                    if c not in logs_df.columns:
                        logs_df[c] = None
                st.dataframe(logs_df[log_cols], use_container_width=True)
                try:
                    logs_csv = logs_df[log_cols].to_csv(index=False).encode("utf-8")
                    st.download_button(
                        label="Download Audit Logs (CSV)",
                        data=logs_csv,
                        file_name="classification_history_audit_logs.csv",
                        mime="text/csv",
                    )
                except Exception:
                    pass
            else:
                st.info("No audit logs for this asset.")
        except Exception as e:
            st.warning(f"Failed to load audit logs: {e}")
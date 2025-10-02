"""
Compliance page for the data governance application.
"""
import sys
import os

# Add the project root (parent of 'src') to the Python path so 'src.*' imports work
_here = os.path.abspath(__file__)
_src_dir = os.path.dirname(os.path.dirname(_here))  # .../src
_project_root = os.path.dirname(_src_dir)           # project root containing 'src'
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import streamlit as st
import plotly.express as px
import plotly.io as pio
import pandas as pd
import io
from src.ui.theme import apply_global_theme
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
try:
    from src.services.compliance_service import compliance_service
except Exception as _imp_err:
    compliance_service = None  # Fallback: disable compliance features if import fails
from src.services.exception_service import exception_service
from src.services.migration_service import migration_service
from src.services.ai_classification_service import ai_classification_service
from src.services.behavior_analytics_service import behavior_analytics_service
from src.services.federated_anomaly_service import federated_anomaly_service
from src.services.authorization_service import authz
from src.components.filters import render_data_filters, render_compliance_facets
from src.services.dynamic_query_service import dynamic_query_service
from src.services.dynamic_compliance_report_service import dynamic_compliance_report_service
from src.services.system_classify_service import system_classify_service
from src.ui.quick_links import render_quick_links
from src.services.sensitive_scan_service import sensitive_scan_service

# Use global Plotly template (set in src/app.py) for charts

# Page configuration
st.set_page_config(
    page_title="Compliance - Data Governance App",
    page_icon="✅",
    layout="wide"
)

# Apply centralized theme (fonts, CSS variables, Plotly template)
apply_global_theme()

# Page title
st.title("Compliance Monitoring")
render_quick_links()

# If compliance_service failed to import, inform the user and continue rendering the rest of the page
try:
    if compliance_service is None:
        try:
            _reason = str(_imp_err)
        except Exception:
            _reason = "Import failed"
        st.warning(
            "Compliance features are temporarily unavailable due to a service import issue. "
            f"Reason: {_reason}"
        )
except NameError:
    # _imp_err not defined (import succeeded), nothing to do
    pass

# RBAC guard: require at least consumer-level access
try:
    _ident = authz.get_current_identity()
    if not authz.is_consumer(_ident):
        st.error("You do not have permission to access the Compliance module. Please sign in and ensure your Snowflake role has at least consumer-level access.")
        st.stop()
except Exception as _auth_err:
    st.warning(f"Authorization check failed: {_auth_err}")
    st.stop()

# Health check for compliance service (explicit, no side-effects unless ensure=True)
comp_ok = False
comp_err = None
try:
    if compliance_service is not None:
        hc = compliance_service.health_check(ensure=True)
        comp_ok = bool(hc.get('ok'))
        comp_err = hc.get('error')
        if not comp_ok:
            st.warning(f"Compliance service is not ready. Some actions are disabled. Reason: {comp_err}")
    else:
        st.warning("Compliance service not available; actions will be disabled on this page.")
except Exception as _hc_err:
    comp_ok = False
    comp_err = str(_hc_err)
    st.warning(f"Compliance service health check failed; actions disabled. Reason: {comp_err}")
# Global filters and facets (applied best-effort to results)
with st.expander("🔎 Dataset Filters", expanded=True):
    sel = render_data_filters(key_prefix="comp")
with st.expander("🧭 Compliance Facets", expanded=False):
    facets = render_compliance_facets(key_prefix="comp")

# Manual refresh to clear cache and re-run queries
if st.button("🔄 Refresh now", help="Clear cached data (5 min TTL) and refresh from Snowflake"):
    st.cache_data.clear()
    st.rerun()

# Lightweight CSS for modern, rounded cards and soft shadows
st.markdown(
    """
    <style>
    /* Keep only KPI status accents; base styles come from global theme */
    .kpi-good {border-left: 6px solid #2ECC71;}
    .kpi-warn {border-left: 6px solid #F1C40F;}
    .kpi-bad  {border-left: 6px solid #E74C3C;}
    </style>
    """,
    unsafe_allow_html=True,
)

# Function to get real compliance data from Snowflake
@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_compliance_data():
    try:
        # Access governance metrics
        users_res = snowflake_connector.execute_query(
            """
            SELECT COUNT(*) AS CNT
            FROM "SNOWFLAKE"."ACCOUNT_USAGE"."USERS"
            WHERE "DELETED_ON" IS NULL
            """
        )
        roles_res = snowflake_connector.execute_query(
            """
            SELECT COUNT(*) AS CNT
            FROM "SNOWFLAKE"."ACCOUNT_USAGE"."ROLES"
            WHERE "DELETED_ON" IS NULL
            """
        )
        grants_res = snowflake_connector.execute_query(
            """
            SELECT COUNT(*) AS CNT
            FROM "SNOWFLAKE"."ACCOUNT_USAGE"."GRANTS_TO_ROLES"
            WHERE "DELETED_ON" IS NULL
            """
        )

        # Policy coverage
        masking_res = snowflake_connector.execute_query(
            """
            SELECT COUNT(*) AS CNT
            FROM "SNOWFLAKE"."ACCOUNT_USAGE"."MASKING_POLICIES"
            """
        )
        row_access_res = snowflake_connector.execute_query(
            """
            SELECT COUNT(*) AS CNT
            FROM "SNOWFLAKE"."ACCOUNT_USAGE"."ROW_ACCESS_POLICIES"
            """
        )

        # Tag usage overview (top 10)
        tag_usage = snowflake_connector.execute_query(
            """
            SELECT "TAG_NAME", COUNT(*) AS USAGE_COUNT
            FROM "SNOWFLAKE"."ACCOUNT_USAGE"."TAG_REFERENCES"
            GROUP BY "TAG_NAME"
            ORDER BY USAGE_COUNT DESC
            LIMIT 10
            """
        )

        return {
            'access': {
                'users': users_res[0]['CNT'] if users_res else 0,
                'roles': roles_res[0]['CNT'] if roles_res else 0,
                'grants': grants_res[0]['CNT'] if grants_res else 0,
            },
            'policies': {
                'masking_policies': masking_res[0]['CNT'] if masking_res else 0,
                'row_access_policies': row_access_res[0]['CNT'] if row_access_res else 0,
            },
            'tag_usage': tag_usage or []
        }
    except Exception as e:
        st.error(f"Error fetching compliance data from Snowflake: {str(e)}")
        return {
            'access': {
                'users': 0,
                'roles': 0,
                'grants': 0,
            },
            'policies': {
                'masking_policies': 0,
                'row_access_policies': 0,
            },
            'tag_usage': []
        }
# Helpers to surface an Overall Compliance Score with explicit tooltip
@st.cache_data(ttl=300)
def _get_latest_report():
    """Fetch the most recent record from COMPLIANCE_REPORTS.
    Returns a dict with keys: GENERATED_AT, METRICS. Fallbacks to {} on error.
    """
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT GENERATED_AT, METRICS
            FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.COMPLIANCE_REPORTS
            ORDER BY GENERATED_AT DESC
            LIMIT 1
            """
        ) or []
        return rows[0] if rows else {}
    except Exception:
        return {}


def _compute_overall_score(metrics, pending_exceptions=None):
    """Compute an explainable overall score in [0, 100].

    Formula (weights chosen for clarity, not certification):
    - 60% Coverage = coverage_rate (0..1)
    - 25% Health = (1 - violation_rate)
      where violation_rate = total_violations / max(total_assets, 1)
      and total_violations approximated by sum(risk_counts[High, Medium, Low]) if present
    - 15% Exception Backlog = (1 - min(pending_exceptions_per_asset, 1))

    Returns (score, human_readable_explainer)
    """
    m = metrics or {}
    try:
        coverage = float((m.get("coverage_rate") or 0) or 0)
    except Exception:
        coverage = 0.0
    try:
        total_assets = int((m.get("total_assets") or (m.get("asset_counts", {}) or {}).get("total", 0)) or 0)
    except Exception:
        total_assets = 0
    rc = (m.get("risk_counts") or {})
    try:
        total_viol = int((rc.get("High") or 0) + (rc.get("Medium") or 0) + (rc.get("Low") or 0))
    except Exception:
        total_viol = 0
    violation_rate = 0.0
    if total_assets > 0:
        try:
            violation_rate = min(max(total_viol / total_assets, 0.0), 1.0)
        except Exception:
            violation_rate = 0.0
    # exceptions per asset (bounded 0..1)
    pe = 0 if pending_exceptions is None else int(pending_exceptions)
    exc_per_asset = 0.0
    if total_assets > 0:
        try:
            exc_per_asset = min(max(pe / total_assets, 0.0), 1.0)
        except Exception:
            exc_per_asset = 0.0

    score_0_1 = (
        0.60 * coverage +
        0.25 * (1.0 - violation_rate) +
        0.15 * (1.0 - exc_per_asset)
    )
    try:
        score = round(100.0 * max(min(score_0_1, 1.0), 0.0), 1)
    except Exception:
        score = 0.0

    expl = (
        f"60% Coverage ({coverage:.0%}) + 25% Health (1 - violation rate {violation_rate:.0%}) + "
        f"15% Exceptions (1 - backlog/asset {exc_per_asset:.0%})."
    )
    return score, expl

# Get compliance data
with st.spinner("Loading compliance data from your Snowflake database..."):
    compliance_data = get_compliance_data()

# Quick refresh for latest coverage and metrics
ref_cov = st.button("🔄 Refresh Coverage & Metrics")
if ref_cov:
    st.cache_data.clear()
    st.rerun()

# Tabs for Compliance modules
tab_overview, tab_alerts, tab_reports_viol, tab_matrix, tab_exceptions, tab_qa, tab_audit, tab_fw = st.tabs([
    "Overview", "Alerts", "Reports & Violations", "Matrix & Evidence", "Exceptions", "QA Review", "Audit Logs", "Frameworks & Controls"
])

with tab_overview:
    # Connected role indicator (best effort)
    try:
        from src.connectors.snowflake_connector import snowflake_connector
        role_row = snowflake_connector.execute_query("select current_role() as ROLE")
        wh_row = snowflake_connector.execute_query("select current_warehouse() as WAREHOUSE")
        db_row = snowflake_connector.execute_query("select current_database() as DATABASE")
        role = role_row[0]['ROLE'] if role_row else None
        wh = wh_row[0]['WAREHOUSE'] if wh_row else None
        db = db_row[0]['DATABASE'] if db_row else None
        st.caption(f"Connected as role: {role or 'Unknown'} | Warehouse: {wh or 'Unknown'} | Database: {db or 'Unknown'}")
    except Exception:
        st.caption("Connected role/warehouse/database: unavailable (insufficient privileges)")

    # Overall Compliance Score with explicit tooltip (latest report + live exceptions)
    try:
        latest = _get_latest_report() or {}
        metrics = latest.get("METRICS") or {}
        generated_at = latest.get("GENERATED_AT")
    except Exception:
        metrics = {}
        generated_at = None

    try:
        pending = len(exception_service.list(status="Pending", limit=10000) or [])
    except Exception:
        pending = 0

    score, expl = _compute_overall_score(metrics, pending)
    help_txt = (
        "Overall Compliance Score\n\n"
        "Formula: 60% Coverage + 25% (1 - Violation rate) + 15% (1 - Pending exceptions per asset).\n"
        "Basis: Latest generated compliance report for coverage and violations"
        f"{' (generated at ' + str(generated_at) + ')' if generated_at else ''}"
        ", plus live Pending exception backlog. Data cached for 5 minutes."
    )
    st.metric("Overall Compliance Score", f"{score}%", help=help_txt)

    st.subheader("📊 Summary KPIs")
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    def kpi_card(container, title, value, status="good"):
        cls = {"good": "kpi-good", "warn": "kpi-warn", "bad": "kpi-bad"}.get(status, "kpi-good")
        with container:
            st.markdown(f"<div class='card {cls}'><div class='kpi'><div class='kpi-title'>{title}</div><div class='kpi-value'>{value}</div></div></div>", unsafe_allow_html=True)

    users = int(compliance_data['access']['users'])
    roles = int(compliance_data['access']['roles'])
    grants = int(compliance_data['access']['grants'])
    masking = int(compliance_data['policies']['masking_policies'])
    rowacc = int(compliance_data['policies']['row_access_policies'])
    total_policies = masking + rowacc

    kpi_card(c1, "Active Users", f"{users}")
    kpi_card(c2, "Active Roles", f"{roles}")
    kpi_card(c3, "Role Grants", f"{grants}", "warn" if grants > (roles * 5) else "good")
    kpi_card(c4, "Masking Policies", f"{masking}", "good" if masking > 0 else "warn")
    kpi_card(c5, "Row Access Policies", f"{rowacc}", "good" if rowacc > 0 else "warn")
    kpi_card(c6, "Total Policies", f"{total_policies}", "good" if total_policies > 0 else "warn")

    # Latest Compliance Coverage (from view)
    st.subheader("📑 Latest Compliance Coverage")
    try:
        rows_cov = snowflake_connector.execute_query(
            f"""
            SELECT FRAMEWORK, GENERATED_AT, METRICS
            FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.COMPLIANCE_COVERAGE
            ORDER BY FRAMEWORK
            """
        ) or []
        if rows_cov:
            # Render compact KPI-style list
            for rec in rows_cov:
                fw = rec.get('FRAMEWORK')
                gen = rec.get('GENERATED_AT')
                m = rec.get('METRICS') or {}
                try:
                    total = int(m.get('total_assets', 0))
                    comp = int(m.get('compliant_assets', 0))
                    nonc = int(m.get('non_compliant_assets', 0))
                except Exception:
                    total = comp = nonc = 0
                st.markdown(f"- **{fw}** — Generated: {gen} — Total: {total} | Compliant: {comp} | Non-compliant: {nonc}")
        else:
            st.info("No compliance coverage found yet. Generate a report using the section below.")
    except Exception as e:
        st.warning(f"Unable to read COMPLIANCE_COVERAGE: {e}")

    # Dynamic Queries: always-up-to-date sensitive/critical lists
    with st.expander("🤖 Dynamic Queries: Sensitive & Critical Assets", expanded=False):
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Run: Sensitive Objects (C>=2 or Restricted/Confidential)"):
                try:
                    sql = dynamic_query_service.build_sensitive_objects_query()
                    st.code(sql, language="sql")
                    rows = dynamic_query_service.run_query(sql)
                    if rows:
                        import pandas as pd
                        st.dataframe(pd.DataFrame(rows), width='stretch')
                    else:
                        st.info("No sensitive objects found.")
                except Exception as e:
                    st.warning(f"Query failed: {e}")

    # Native runs for classification and dynamic compliance
    with st.expander("🧪 Native Runs: SYSTEM$CLASSIFY & Dynamic Reports", expanded=False):
        st.caption("Execute native Snowflake classification and framework-aligned dynamic compliance reporting without hardcoded mappings.")
        colr1, colr2 = st.columns(2)
        with colr1:
            low_thr = st.slider("Low-confidence threshold", 0.0, 1.0, 0.5, 0.05, key="comp_thr")
            limit = st.number_input("Max tables to scan", 1, 1000, 100, 10, key="comp_lim")
            run_sys = st.button("Run SYSTEM$CLASSIFY Scan", key="comp_run_sys")
        with colr2:
            gen = st.button("Generate Dynamic Compliance Reports", key="comp_gen_reports")
        if run_sys:
            with st.spinner("Executing SYSTEM$CLASSIFY across target schemas..."):
                try:
                    res = system_classify_service.run(low_conf_threshold=float(low_thr), limit=int(limit))
                    st.success(f"Tables: {res.get('tables')} | History: {res.get('history_rows')} | Decisions: {res.get('decisions')} | Queued: {res.get('queued')}")
                    st.json(res)
                except Exception as e:
                    st.error(f"SYSTEM$CLASSIFY failed: {e}")
        if gen:
            with st.spinner("Generating dynamic compliance reports..."):
                try:
                    author = getattr(getattr(st.session_state, 'user', None), 'username', None) or 'system'
                    out = dynamic_compliance_report_service.generate_reports(author=author)
                    st.success(f"Reports: {out.get('reports', 0)} | Violations: {out.get('violations', 0)}")
                    st.json(out)
                except Exception as e:
                    st.error(f"Report generation failed: {e}")
        with c2:
            if st.button("Run: Critical Assets (Risk Score)"):
                try:
                    sql2 = dynamic_query_service.build_critical_assets_query()
                    st.code(sql2, language="sql")
                    rows2 = dynamic_query_service.run_query(sql2)
                    if rows2:
                        import pandas as pd
                        st.dataframe(pd.DataFrame(rows2).head(200), width='stretch')
                    else:
                        st.info("No critical assets detected.")
                except Exception as e:
                    st.warning(f"Query failed: {e}")

        # Automated Sensitive Scan Orchestrator (Steps 1–5)
        with st.expander("🤖 Automated Sensitive Scan (hybrid)", expanded=False):
            st.caption("Scan tables/columns, sample values, classify (regex + semantic), aggregate to column, map to compliance, and tag automatically.")
            db = st.text_input("Database", value=settings.SNOWFLAKE_DATABASE, key="sens_db")
            schema_glob = st.text_input("Schema filter (SQL ILIKE)", value="%", help="e.g., SALES%", key="sens_schema_glob")
            sample_rows = st.number_input("Sample rows per column", min_value=20, max_value=1000, value=200, step=20, key="sens_sample_rows")
            table_limit = st.number_input("Max tables per run", min_value=1, max_value=2000, value=200, step=10, key="sens_table_limit")
            go = st.button("Run Automated Sensitive Scan", key="sens_scan_go")
            if go:
                with st.spinner("Running sensitive scan orchestrator..."):
                    try:
                        out = sensitive_scan_service.run_full(db=db, schema_glob=schema_glob or "%", sample_rows=int(sample_rows), table_limit=int(table_limit))
                        st.success("Sensitive scan completed.")
                        st.json(out)
                    except Exception as e:
                        st.error(f"Sensitive scan failed: {e}")

# Classification rules overview
    st.subheader("🏷️ Tag Usage Overview")

    if compliance_data['tag_usage']:
        tag_df = pd.DataFrame(compliance_data['tag_usage'])
        tag_df.rename(columns={'TAG_NAME': 'Tag', 'USAGE_COUNT': 'Usage'}, inplace=True)
        fig = px.bar(tag_df, x='Tag', y='Usage', title='Top Tag Usage Across Objects')
        st.plotly_chart(fig, use_container_width=True)
        # Executives prefer expanded views by default
        is_exec = False
        try:
            is_exec = getattr(getattr(st.session_state, 'user', None), 'role', 'Viewer') in ("Executive","CDO")
        except Exception:
            is_exec = False
        with st.expander("View Tag Usage Table", expanded=is_exec):
            st.dataframe(tag_df, width='stretch')
    else:
        st.info("No tag usage data available or insufficient privileges to access ACCOUNT_USAGE.TAG_REFERENCES.")

    # Behavioral analytics & anomalies (integrated)
    with st.expander("📈 Behavioral Analytics & Anomalies", expanded=False):
        col_b1, col_b2 = st.columns([1,1])
        with col_b1:
            days = st.slider("Lookback days", 1, 30, 7, key="comp_days")
        with col_b2:
            fetch = st.button("Fetch & Detect Anomalies", key="comp_fetch_anom")
        if fetch:
            with st.spinner("Fetching access events and computing anomalies..."):
                df_ev = behavior_analytics_service.fetch_access_events(days=days)
                cnts = behavior_analytics_service.aggregate_user_object_counts(df_ev)
                anomalies = behavior_analytics_service.zscore_anomalies(cnts)
            if df_ev is None or df_ev.empty:
                st.warning("No events available or insufficient privileges.")
            else:
                try:
                    st.metric("Events", len(df_ev))
                    st.metric("Distinct users", df_ev['USER_NAME'].nunique())
                    st.metric("Distinct objects", df_ev['FULL_NAME'].nunique())
                except Exception:
                    pass
                if cnts is not None and not cnts.empty:
                    st.dataframe(cnts.head(200), width='stretch')
                if anomalies:
                    a_df = pd.DataFrame([a.__dict__ for a in anomalies])
                    st.subheader("Top Anomalies (z-score)")
                    st.dataframe(a_df, use_container_width=True)
                else:
                    st.info("No significant anomalies detected with current threshold.")

    # Federated anomaly detection per schema (integrated)
    with st.expander("🤝 Federated Anomaly Detection (per schema)", expanded=False):
        fed_go = st.button("Train per-schema models and score", key="comp_fed_go")
        if fed_go:
            with st.spinner("Building feature matrix and training models..."):
                df_ev = behavior_analytics_service.fetch_access_events(days=st.session_state.get('comp_days', 7))
                feats = behavior_analytics_service.build_feature_matrix(df_ev)
                models = federated_anomaly_service.train_partition_models(feats)
                scored = federated_anomaly_service.score_anomalies(feats, models)
            if not scored:
                st.info("No partitions/models scored (need more data).")
            else:
                st.success(f"Scored {len(scored)} events across {len(models)} partitions.")
                try:
                    st.dataframe(pd.DataFrame([s.__dict__ for s in scored]), width='stretch')
                except Exception:
                    st.json([s.__dict__ for s in scored][:20])

    # Executive/CDO BU scorecard
    try:
        role_exec = getattr(getattr(st.session_state, 'user', None), 'role', 'Viewer') if hasattr(st.session_state, 'user') else 'Viewer'
    except Exception:
        role_exec = 'Viewer'
    if role_exec in ["Executive", "CDO"]:
        st.markdown("---")
    st.subheader("🤖 AI Non-compliance (on-demand)")
    st.caption("Runs a quick AI scan on a small sample to surface potential policy violations (PII/PHI/Financial with C below minimum).")
    # Candidate assets: small sample from INFORMATION_SCHEMA
    try:
        cand_rows = snowflake_connector.execute_query(
            f"""
            SELECT "TABLE_CATALOG"||'.'||"TABLE_SCHEMA"||'.'||"TABLE_NAME" AS FULL
            FROM {settings.SNOWFLAKE_DATABASE}.INFORMATION_SCHEMA.TABLES
            WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
            LIMIT 30
            """
        ) or []
        cand = [r.get('FULL') for r in cand_rows if r.get('FULL')]
    except Exception:
        cand = []

    @st.cache_data(ttl=300)
    def _ai_find_non_compliance(fqtns: list) -> list:
        items = []
        for full in fqtns[:30]:
            try:
                found = ai_classification_service.detect_sensitive_columns(full, sample_size=60)
                cats = sorted({c for r in (found or []) for c in (r.get('categories') or [])})
                # Fetch current C from inventory if available
                c_level = 0
                try:
                    inv = snowflake_connector.execute_query(
                        f"""
                        SELECT CIA_CONF AS C
                        FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ASSET_INVENTORY
                        WHERE FULL_NAME = %(f)s
                        LIMIT 1
                        """,
                        {"f": full}
                    ) or []
                    if inv:
                        c_level = int(pd.to_numeric(inv[0].get('C'), errors='coerce') or 0)
                except Exception:
                    c_level = 0
                comp = ai_classification_service.assess_compliance('Internal', c_level, cats)
                if cats and not comp.get('compliant'):
                    items.append({
                        'Asset': full,
                        'Detected Categories': cats,
                        'C_Level': c_level,
                        'Issues': [i.get('reason') for i in (comp.get('issues') or [])]
                    })
            except Exception:
                continue
        return items

    if st.button("Run AI Non-compliance Scan", key="ai_noncomp"):
        rows = _ai_find_non_compliance(cand)
        if rows:
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True)
            st.caption("Quick actions")
            colx1, colx2 = st.columns(2)
            with colx1:
                sel_asset = st.selectbox("Asset to Reclassify", options=[r['Asset'] for r in rows])
                if st.button("Open Reclassification", key="ai_open_reclass"):
                    st.session_state['reclass_asset'] = sel_asset
                    st.success("Go to Classification → Reclassification tab; asset pre-selected.")
            with colx2:
                sel_asset2 = st.selectbox("Asset to Exception", options=[r['Asset'] for r in rows], key="ai_exc_sel")
                req = st.text_input("Business justification", key="ai_exc_just")
                if st.button("Create Exception", key="ai_create_exc") and sel_asset2 and req:
                    try:
                        eid = exception_service.submit(sel_asset2, 'Other', req, 'Medium', st.session_state.get('user', 'system'), 90)
                        st.success(f"Exception submitted: {eid}")
                    except Exception as e:
                        st.error(f"Failed: {e}")
        else:
            st.info("No potential AI-detected non-compliance found in the sample.")
        

    

with tab_alerts:
    st.subheader("🚨 Alerts & Notifications")
    st.write("Real-time and periodic alerts for non-compliance, pending exceptions, and regulatory updates.")
    role = getattr(getattr(st.session_state, 'user', None), 'role', 'Viewer') if hasattr(st.session_state, 'user') else 'Viewer'
    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Run Violation Detection", disabled=not comp_ok):
            if role not in ["Admin","Compliance Officer"]:
                st.warning("You do not have permission to run detection.")
            else:
                try:
                    created = compliance_service.detect_violations()
                    st.success(f"Detection complete. {created} violation(s) recorded.")
                except Exception as e:
                    st.error(f"Detection failed: {e}")
    with c2:
        if st.button("Expire Past-Due Exceptions"):
            if role not in ["Admin","Compliance Officer"]:
                st.warning("You do not have permission to expire exceptions.")
            else:
                try:
                    expired = exception_service.expire_auto()
                    st.success(f"Marked {expired} exception(s) as Expired.")
                except Exception as e:
                    st.error(f"Expire failed: {e}")
    with c3:
        st.caption("Automated email/in-app notifications can be wired to your alerting system.")

    st.markdown("---")
    st.write("Non-compliant dataset alerts")
    if comp_ok and compliance_service is not None:
        try:
            viols = compliance_service.list_open_violations(limit=500)
            vdf = pd.DataFrame(viols)
            if not vdf.empty:
                st.dataframe(vdf, use_container_width=True)
            else:
                st.info("No open violations.")
        except Exception as e:
            st.warning(f"Unable to retrieve violations: {e}")
    else:
        st.info("Compliance service unavailable; cannot list open violations.")

    st.markdown("---")
    st.write("Pending exception requests")
    try:
        ex = exception_service.list(status="Pending", limit=200)
        exdf = pd.DataFrame(ex)
        if not exdf.empty:
            st.dataframe(exdf, use_container_width=True)
        else:
            st.info("No pending exceptions.")
    except Exception as e:
        st.warning(f"Unable to retrieve exceptions: {e}")


with tab_reports_viol:
    st.subheader("📑 Compliance Reports")
    # Review scheduling moved from Administration to consolidate reporting here
    st.markdown("---")
    st.subheader("📅 Schedule Periodic Review")
    col_sr1, col_sr2 = st.columns(2)
    with col_sr1:
        asset_full = st.text_input("Asset (DATABASE.SCHEMA.OBJECT)", key="comp_rev_asset")
        frequency = st.selectbox("Frequency", ["Monthly", "Quarterly", "Semiannually", "Annually"], index=1, key="comp_rev_freq")
        owner = st.text_input("Owner (email)", key="comp_rev_owner")
        if st.button("Schedule Review", key="comp_rev_btn") and asset_full and owner:
            try:
                rid = compliance_service.schedule_review(asset_full, frequency, owner)
                st.success(f"Review scheduled. ID: {rid}")
            except Exception as e:
                st.error(f"Failed to schedule review: {e}")
    with col_sr2:
        st.caption("Scheduled reviews:")
        try:
            schedules = snowflake_connector.execute_query(
                f"SELECT * FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.REVIEW_SCHEDULES ORDER BY NEXT_RUN ASC LIMIT 200"
            ) or []
            if schedules:
                st.dataframe(pd.DataFrame(schedules), use_container_width=True)
            else:
                st.info("No schedules yet.")
        except Exception as e:
            st.warning(f"Unable to list schedules: {e}")
    st.markdown("---")
    st.write(f"Generated reports are stored in {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.COMPLIANCE_REPORTS")
    try:
        reports = snowflake_connector.execute_query(
            f"""
            SELECT ID, FRAMEWORK, GENERATED_AT, GENERATED_BY, METRICS, LOCATION
            FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.COMPLIANCE_REPORTS
            ORDER BY GENERATED_AT DESC
            LIMIT 200
            """
        )
        if reports:
            rdf = pd.DataFrame(reports)
            st.dataframe(rdf, use_container_width=True)
            selected_report = st.selectbox(
                "Select a report to view details",
                options=[r.get('ID') for r in reports],
            )
            if selected_report:
                match = [r for r in reports if r.get('ID') == selected_report]
                if match:
                    st.write("Report Details:")
                    st.json(match[0].get('METRICS') or {})
                    try:
                        csv_bytes = pd.json_normalize(match[0].get('METRICS') or {}).to_csv(index=False).encode('utf-8')
                        st.download_button("Download Metrics (CSV)", data=csv_bytes, file_name="compliance_report_metrics.csv", mime="text/csv")
                        # Excel export
                        xls_buf = io.BytesIO()
                        with pd.ExcelWriter(xls_buf, engine="openpyxl") as writer:
                            pd.json_normalize(match[0].get('METRICS') or {}).to_excel(writer, index=False, sheet_name="metrics")
                        st.download_button(
                            "Download Metrics (Excel)", data=xls_buf.getvalue(), file_name="compliance_report_metrics.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        )
                    except Exception:
                        pass
        else:
            st.info("No reports found. Generate a report using the controls below.")
    except Exception as e:
        st.warning(f"Unable to fetch reports: {e}")

    st.subheader("🚫 Open Violations")
    if comp_ok and compliance_service is not None:
        try:
            violations = compliance_service.list_open_violations(limit=500)
            if violations:
                vdf = pd.DataFrame(violations)
                st.dataframe(vdf, use_container_width=True)
                sel = st.selectbox(
                    "Select a violation to drill into",
                    options=[v.get('ID') for v in violations],
                )
                if sel:
                    row = [v for v in violations if v.get('ID') == sel]
                    if row:
                        st.write("Violation Details:")
                        st.json(row[0].get('DETAILS') or {})
            else:
                st.info("No open violations.")
        except Exception as e:
            st.warning(f"Unable to list violations: {e}")
    else:
        st.info("Compliance service unavailable; cannot list violations.")

    st.markdown("---")
    st.write("Generate a new report")
    framework = st.selectbox("Framework", ["SOX","SOC 2","GDPR","HIPAA","ISO 27001"], index=0)
    requester = st.text_input("Your email (report requester)")
    if st.button("Generate Report", disabled=not comp_ok):
        if not requester:
            st.warning("Please enter your email.")
        else:
            try:
                rid = compliance_service.generate_report(framework, requester)
                st.success(f"Report generated: {rid}")
            except Exception as e:
                st.error(f"Report generation failed: {e}")

    st.markdown("---")
    st.subheader("📈 Historical Trends")
    st.caption("Coverage and risk changes over time from past reports")
    try:
        hist = snowflake_connector.execute_query(
            f"""
            SELECT GENERATED_AT, METRICS
            FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.COMPLIANCE_REPORTS
            ORDER BY GENERATED_AT ASC
            LIMIT 1000
            """
        ) or []
        if hist:
            hdf = pd.DataFrame(hist)
            # Flatten metrics
            hdf["coverage_rate"] = hdf["METRICS"].apply(lambda m: (m or {}).get("coverage_rate", None))
            def risk_val(m, k):
                try:
                    return (m or {}).get("risk_counts", {}).get(k, None)
                except Exception:
                    return None
            hdf["risk_high"] = hdf["METRICS"].apply(lambda m: risk_val(m, "High"))
            hdf["risk_med"] = hdf["METRICS"].apply(lambda m: risk_val(m, "Medium"))
            hdf["risk_low"] = hdf["METRICS"].apply(lambda m: risk_val(m, "Low"))
            # Charts
            c1, c2 = st.columns(2)
            with c1:
                st.plotly_chart(px.line(hdf, x="GENERATED_AT", y="coverage_rate", title="Coverage Rate Over Time"), use_container_width=True)
            with c2:
                risk_melt = hdf.melt(id_vars=["GENERATED_AT"], value_vars=["risk_high","risk_med","risk_low"], var_name="risk", value_name="count")
                risk_melt["risk"] = risk_melt["risk"].map({"risk_high":"High","risk_med":"Medium","risk_low":"Low"})
                st.plotly_chart(px.line(risk_melt, x="GENERATED_AT", y="count", color="risk", title="Risk Counts Over Time"), use_container_width=True)
            # Export trends to Excel
            try:
                buf = io.BytesIO()
                with pd.ExcelWriter(buf, engine="openpyxl") as writer:
                    hdf[["GENERATED_AT","coverage_rate","risk_high","risk_med","risk_low"]].to_excel(writer, index=False, sheet_name="trends")
                st.download_button("Download Trends (Excel)", data=buf.getvalue(), file_name="compliance_trends.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            except Exception:
                pass
        else:
            st.info("No historical reports found.")
    except Exception as e:
        st.warning(f"Unable to build trends: {e}")

with tab_fw:
    st.subheader("🧭 Frameworks & Controls")
    st.caption("Register compliance frameworks and maintain a simple control library. Detailed matrices and evidence are available in other tabs.")
    # Ensure registry tables
    try:
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.FRAMEWORKS (
              ID STRING,
              NAME STRING,
              VERSION STRING,
              EFFECTIVE_DATE DATE,
              NEXT_REVIEW_DATE DATE,
              OWNER STRING,
              CREATED_AT TIMESTAMP_NTZ
            )
            """
        )
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.CONTROLS (
              ID STRING,
              FRAMEWORK STRING,
              CONTROL_ID STRING,
              TITLE STRING,
              DESCRIPTION STRING,
              STATUS STRING,
              OWNER STRING,
              UPDATED_AT TIMESTAMP_NTZ
            )
            """
        )
        snowflake_connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.CHECKS (
              ID STRING,
              FRAMEWORK STRING,
              CODE STRING,
              DESCRIPTION STRING,
              RULE STRING,
              CREATED_AT TIMESTAMP_NTZ
            )
            """
        )
    except Exception:
        pass

    colf1, colf2 = st.columns(2)
    with colf1:
        st.markdown("**Framework Registry**")
        try:
            rows = snowflake_connector.execute_query(
                f"""
                SELECT ID, NAME, VERSION, EFFECTIVE_DATE, NEXT_REVIEW_DATE, OWNER, CREATED_AT
                FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.FRAMEWORKS
                ORDER BY CREATED_AT DESC
                LIMIT 500
                """
            ) or []
            if rows:
                st.dataframe(pd.DataFrame(rows), use_container_width=True)
            else:
                st.info("No frameworks registered yet. Add one below.")
        except Exception as e:
            st.warning(f"Unable to list frameworks: {e}")

        with st.expander("Add Framework"):
            import uuid
            name = st.text_input("Name (e.g., SOC2, SOX, ISO 27001)")
            version = st.text_input("Version", value="1.0")
            eff = st.date_input("Effective Date", key="fw_eff")
            next_r = st.date_input("Next Review Date", key="fw_next")
            owner = st.text_input("Owner (email)", key="fw_owner")
            if st.button("Save Framework") and name:
                try:
                    snowflake_connector.execute_non_query(
                        f"""
                        INSERT INTO {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.FRAMEWORKS
                        (ID, NAME, VERSION, EFFECTIVE_DATE, NEXT_REVIEW_DATE, OWNER, CREATED_AT)
                        SELECT %(id)s, %(n)s, %(v)s, %(e)s, %(r)s, %(o)s, CURRENT_TIMESTAMP
                        """,
                        {"id": str(uuid.uuid4()), "n": name, "v": version, "e": str(eff), "r": str(next_r), "o": owner}
                    )
                    st.success("Framework saved.")
                    st.cache_data.clear()
                    st.rerun()
                except Exception as e:
                    st.error(f"Save failed: {e}")

    with colf2:
        st.markdown("**Control Library (summary)**")
        try:
            rows = snowflake_connector.execute_query(
                f"""
                SELECT FRAMEWORK, CONTROL_ID, TITLE, STATUS, OWNER, UPDATED_AT
                FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.CONTROLS
                ORDER BY UPDATED_AT DESC
                LIMIT 1000
                """
            ) or []
            if rows:
                st.dataframe(pd.DataFrame(rows), use_container_width=True)
            else:
                st.info("No controls recorded. Populate via Policy → Generation or manual insert.")
        except Exception as e:
            st.warning(f"Unable to read controls: {e}")

        st.markdown("**Automated Checks (summary)**")
        try:
            crows = snowflake_connector.execute_query(
                f"""
                SELECT FRAMEWORK, CODE, DESCRIPTION, RULE, CREATED_AT
                FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.CHECKS
                ORDER BY CREATED_AT DESC
                LIMIT 1000
                """
            ) or []
            if crows:
                st.dataframe(pd.DataFrame(crows), use_container_width=True)
            else:
                st.info("No checks recorded. Publish from Policy → Control/Check Generation.")
        except Exception as e:
            st.warning(f"Unable to read checks: {e}")

        st.markdown("**Run Checks Now**")
        fsel = st.text_input("Framework filter (optional)", value="", key="fw_checks_filter")
        if st.button("Run Checks Now", disabled=not comp_ok):
            try:
                cnt = compliance_service.run_checks(fsel or None)
                st.success(f"Executed checks and wrote {cnt} result rows.")
            except Exception as e:
                st.error(f"Run failed: {e}")

        st.markdown("**Seed Starter Controls & Checks**")
        seed_fw = st.selectbox("Framework to seed", ["SOC 2","SOX"], index=0, key="fw_seed_sel")
        if st.button("Seed Controls & Checks", disabled=not comp_ok):
            try:
                inserted = compliance_service.seed_controls_and_checks(seed_fw)
                st.success(f"Seeded {inserted} item(s) for {seed_fw}.")
                st.cache_data.clear()
                st.rerun()
            except Exception as e:
                st.error(f"Seed failed: {e}")

        st.markdown("**Check Results (latest)**")
        if comp_ok and compliance_service is not None:
            try:
                results = compliance_service.list_check_results(fsel or None, limit=500)
                if results:
                    st.dataframe(pd.DataFrame(results), use_container_width=True)
                else:
                    st.info("No check results yet. Run checks above.")
            except Exception as e:
                st.warning(f"Unable to list check results: {e}")
        else:
            st.info("Compliance service unavailable; cannot list check results.")

with tab_matrix:
    st.subheader("📋 Compliance Matrix & Evidence Packs")
    st.caption("Drill into violations by rule and business unit (or schema), then export an evidence pack.")
    try:
        # Fetch violations and inventory join for BU/Schema
        vio = snowflake_connector.execute_query(
            f"""
            SELECT ID, RULE_CODE, SEVERITY, DESCRIPTION, ASSET_FULL_NAME, DETECTED_AT, STATUS
            FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.VIOLATIONS
            ORDER BY DETECTED_AT DESC
            LIMIT 1000
            """
        ) or []
        inv = snowflake_connector.execute_query(
            f"""
            SELECT FULL_NAME, COALESCE(BUSINESS_UNIT, SPLIT_PART(FULL_NAME,'.',2)) AS BU_OR_SCHEMA,
                   CLASSIFICATION_LEVEL, CIA_CONF, CIA_INT, CIA_AVAIL
            FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ASSET_INVENTORY
            """
        ) or []
        vdf = pd.DataFrame(vio)
        idf = pd.DataFrame(inv)
        # Apply dataset + facet filters (best-effort)
        try:
            if not vdf.empty:
                # Dataset filter on FULL_NAME/ASSET_FULL_NAME
                if sel.get("database"):
                    vdf = vdf[vdf['ASSET_FULL_NAME'].astype(str).str.startswith(f"{sel['database']}.")]
                if sel.get("schema"):
                    vdf = vdf[vdf['ASSET_FULL_NAME'].astype(str).str.contains(fr"\.({sel['schema']})\.", regex=True, case=False)]
                if sel.get("table"):
                    vdf = vdf[vdf['ASSET_FULL_NAME'].astype(str).str.endswith(f".{sel['table']}")]
                # Severity facet
                if facets.get('severity') and 'SEVERITY' in vdf.columns:
                    vdf = vdf[vdf['SEVERITY'].isin(facets['severity'])]
                # Time range facet
                if 'DETECTED_AT' in vdf.columns:
                    vdf['DETECTED_AT'] = pd.to_datetime(vdf['DETECTED_AT'], errors='coerce')
                    now = pd.Timestamp.utcnow()
                    rng = facets.get('time') or 'Last 7 days'
                    if rng == 'Current':
                        start = now.normalize()
                        vdf = vdf[vdf['DETECTED_AT'] >= start]
                    elif rng == 'Last 7 days':
                        vdf = vdf[vdf['DETECTED_AT'] >= now - pd.Timedelta(days=7)]
                    elif rng == 'Last 30 days':
                        vdf = vdf[vdf['DETECTED_AT'] >= now - pd.Timedelta(days=30)]
                    else:
                        pass
        except Exception:
            pass
        if not vdf.empty:
            # Join to get BU/Schema
            if not idf.empty:
                vdf = vdf.merge(idf, left_on='ASSET_FULL_NAME', right_on='FULL_NAME', how='left')
                vdf['BU_OR_SCHEMA'] = vdf['BU_OR_SCHEMA'].fillna(vdf['ASSET_FULL_NAME'].str.split('.').str[1])
            else:
                vdf['BU_OR_SCHEMA'] = vdf['ASSET_FULL_NAME'].str.split('.').str[1]

            # Matrix: rows = RULE_CODE, cols = BU_OR_SCHEMA
            mat = vdf.pivot_table(index='RULE_CODE', columns='BU_OR_SCHEMA', values='ID', aggfunc='count', fill_value=0)
            st.dataframe(mat, use_container_width=True)

            st.markdown("---")
            st.subheader("🔎 Drill-down & Evidence Export")
            rule_opt = st.selectbox("Rule", options=sorted(vdf['RULE_CODE'].unique().tolist()))
            bu_opts = sorted(vdf['BU_OR_SCHEMA'].dropna().unique().tolist())
            bu_opt = st.selectbox("Business Unit / Schema", options=["All"] + bu_opts)
            sub = vdf[(vdf['RULE_CODE'] == rule_opt) & ((vdf['BU_OR_SCHEMA'] == bu_opt) if bu_opt != "All" else True)]
            st.dataframe(sub[['ID','SEVERITY','DESCRIPTION','ASSET_FULL_NAME','DETECTED_AT','STATUS','CLASSIFICATION_LEVEL','CIA_CONF','CIA_INT','CIA_AVAIL']], use_container_width=True)

            # Evidence pack export (zip): include CSVs and JSON summary + signature file
            if st.button("Export Evidence Pack (ZIP)") and not sub.empty:
                try:
                    import io, json, zipfile, hashlib
                    buf = io.BytesIO()
                    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
                        # Prepare files
                        vio_csv = sub.to_csv(index=False)
                        zf.writestr('violations.csv', vio_csv)
                        summary = {
                            'rule': rule_opt,
                            'bu_or_schema': bu_opt,
                            'count': int(len(sub)),
                            'generated_at': pd.Timestamp.utcnow().isoformat(),
                        }
                        summary_json = json.dumps(summary, indent=2)
                        zf.writestr('summary.json', summary_json)
                        # Optionally include current policy settings snapshot
                        try:
                            pol = snowflake_connector.execute_query(
                                f"SELECT COUNT(*) AS MASK_POL FROM SNOWFLAKE.ACCOUNT_USAGE.MASKING_POLICIES"
                            ) or []
                            policy_json = json.dumps({'masking_policies': int(pol[0].get('MASK_POL',0)) if pol else 0}, indent=2)
                            zf.writestr('policy_snapshot.json', policy_json)
                        except Exception:
                            pass
                        # Signatures: SHA256 of each file
                        sig_lines = []
                        sig_lines.append(f"violations.csv  sha256  {hashlib.sha256(vio_csv.encode('utf-8')).hexdigest()}")
                        sig_lines.append(f"summary.json    sha256  {hashlib.sha256(summary_json.encode('utf-8')).hexdigest()}")
                        try:
                            sig_lines.append(f"policy_snapshot.json  sha256  {hashlib.sha256(policy_json.encode('utf-8')).hexdigest()}")
                        except Exception:
                            pass
                        # Include daily audit digest for today (tamper-evident linkage)
                        try:
                            from src.services.audit_service import audit_service as _aud
                            dig = _aud.compute_daily_digest()
                            zf.writestr('audit_digest.json', json.dumps(dig, indent=2))
                            sig_lines.append(f"audit_digest.json  sha256  {hashlib.sha256(json.dumps(dig, sort_keys=True).encode('utf-8')).hexdigest()}")
                        except Exception:
                            pass
                        zf.writestr('SIGNATURES.txt', "\n".join(sig_lines) + "\n")
                    st.download_button(
                        label="Download ZIP",
                        data=buf.getvalue(),
                        file_name=f"evidence_{rule_opt}_{(bu_opt or 'ALL')}.zip",
                        mime="application/zip",
                    )
                except Exception as e:
                    st.error(f"Failed to create evidence pack: {e}")
        else:
            st.info("No violations found. Run detection from Dashboard or ensure tasks are enabled.")
    except Exception as e:
        st.warning(f"Matrix/evidence view unavailable: {e}")

with tab_exceptions:
    st.subheader("📝 Exception Management")
    role = getattr(getattr(st.session_state, 'user', None), 'role', 'Viewer') if hasattr(st.session_state, 'user') else 'Viewer'
    st.write("Track, document, approve, and expire policy exceptions.")
    st.markdown("**Submit an Exception Request**")
    try:
        tables = snowflake_connector.execute_query(
            f"""
            SELECT "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS full_name
            FROM {settings.SNOWFLAKE_DATABASE}.INFORMATION_SCHEMA.TABLES
            WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
            ORDER BY "TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME"
            LIMIT 200
            """
        )
        asset_options = [t['FULL_NAME'] for t in (tables or [])]
    except Exception:
        asset_options = []
    ec1, ec2 = st.columns(2)
    with ec1:
        ex_asset = st.selectbox("Asset", options=asset_options if asset_options else ["No assets available"], key="ex_asset")
        ex_reg = st.selectbox("Regulatory", ["SOX","SOC","GDPR","HIPAA","Other"], index=0)
        ex_risk = st.selectbox("Risk Level", ["Low","Medium","High"], index=1)
    with ec2:
        ex_days = st.number_input("Days Valid", min_value=7, max_value=365, value=90)
        ex_req_by = st.text_input("Your email")
    ex_just = st.text_area("Justification & Risk Assessment", height=120)
    if st.button("Submit Exception", type="primary"):
        if not ex_req_by or not ex_asset or ex_asset == "No assets available":
            st.warning("Please provide your email and choose an asset.")
        else:
            try:
                eid = exception_service.submit(ex_asset, ex_reg, ex_just, ex_risk, ex_req_by, int(ex_days))
                st.success(f"Submitted exception {eid}")
            except Exception as e:
                st.error(f"Submission failed: {e}")

    st.markdown("---")
    st.write("Approval Workflow")
    status_filter = st.selectbox("Status", ["Pending","Approved","Rejected","Expired","All"], index=0)
    rows = exception_service.list(status=None if status_filter=="All" else status_filter, limit=300)
    if rows:
        edf = pd.DataFrame(rows)
        st.dataframe(edf, use_container_width=True)
        # Export exceptions
        try:
            csv_bytes = edf.to_csv(index=False).encode('utf-8')
            st.download_button("Download Exceptions (CSV)", data=csv_bytes, file_name="exceptions.csv", mime="text/csv")
            xbuf = io.BytesIO()
            with pd.ExcelWriter(xbuf, engine="openpyxl") as writer:
                edf.to_excel(writer, index=False, sheet_name="exceptions")
            st.download_button("Download Exceptions (Excel)", data=xbuf.getvalue(), file_name="exceptions.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        except Exception:
            pass
        sel_eid = st.selectbox("Select Exception", options=[r.get("ID") for r in rows])
        approver = st.text_input("Approver email")
        a1, a2 = st.columns(2)
        with a1:
            if st.button("Approve", type="primary"):
                if role not in ["Admin","Compliance Officer"]:
                    st.warning("Only Compliance Officer/Admin may approve.")
                elif not approver or not sel_eid:
                    st.warning("Provide approver email and select an exception.")
                else:
                    try:
                        exception_service.approve(sel_eid, approver)
                        st.success("Approved.")
                    except Exception as e:
                        st.error(f"Approval failed: {e}")
        with a2:
            rej_reason = st.text_input("Rejection justification")
            if st.button("Reject"):
                if role not in ["Admin","Compliance Officer"]:
                    st.warning("Only Compliance Officer/Admin may reject.")
                elif not approver or not sel_eid:
                    st.warning("Provide approver email and select an exception.")
                else:
                    try:
                        exception_service.reject(sel_eid, approver, rej_reason)
                        st.success("Rejected.")
                    except Exception as e:
                        st.error(f"Rejection failed: {e}")

with tab_qa:
    st.subheader("🔎 QA Review of Classification Decisions")
    st.write("Identify potential under-classified assets based on policy minimums (Section 5.5).")
    try:
        # Pull from inventory if available
        inv = snowflake_connector.execute_query(
            f"""
            SELECT FULL_NAME, CLASSIFICATION_LEVEL, CIA_CONF as C, CIA_INT as I, CIA_AVAIL as A
            FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ASSET_INVENTORY
            LIMIT 2000
            """
        ) or []
        df = pd.DataFrame(inv)
        if not df.empty:
            df['UP_FULL'] = df['FULL_NAME'].str.upper()
            pii_mask = df['UP_FULL'].str.contains(r"SSN|EMAIL|PHONE|ADDRESS|DOB|PII|CUSTOMER|PERSON|EMPLOYEE", regex=True, na=False)
            fin_mask = df['UP_FULL'].str.contains(r"FINANCE|GL|LEDGER|INVOICE|PAYROLL|AR|AP|REVENUE|EXPENSE", regex=True, na=False)
            sox_mask = df['UP_FULL'].str.contains(r"SOX|FINANCIAL_REPORT|GAAP|IFRS|AUDIT", regex=True, na=False)
            under_pii = df[pii_mask & (df['C'].fillna(0).astype(int) < 2)]
            under_fin = df[fin_mask & (df['C'].fillna(0).astype(int) < 2)]
            under_sox = df[sox_mask & (df['C'].fillna(0).astype(int) < 3)]
            col1, col2, col3 = st.columns(3)
            col1.metric("PII Under-Classified", len(under_pii))
            col2.metric("Financial Under-Classified", len(under_fin))
            col3.metric("SOX Under-Classified", len(under_sox))
            with st.expander("Review Details"):
                st.write("PII Candidates")
                st.dataframe(under_pii[['FULL_NAME','CLASSIFICATION_LEVEL','C','I','A']], use_container_width=True)
                st.write("Financial Candidates")
                st.dataframe(under_fin[['FULL_NAME','CLASSIFICATION_LEVEL','C','I','A']], use_container_width=True)
                st.write("SOX Candidates")
                st.dataframe(under_sox[['FULL_NAME','CLASSIFICATION_LEVEL','C','I','A']], use_container_width=True)
        else:
            st.info("Inventory not available; run discovery scan to populate.")
    except Exception as e:
        st.warning(f"QA review unavailable: {e}")

with tab_audit:
    st.subheader("📜 Audit Logs")
    st.write("Export logs for compliance reports and investigations.")
    try:
        from src.services.audit_service import audit_service
        logs = audit_service.query(limit=500)
        ldf = pd.DataFrame(logs)
        if not ldf.empty:
            st.dataframe(ldf, use_container_width=True)
            csv = ldf.to_csv(index=False).encode('utf-8')
            st.download_button("Download Audit CSV", data=csv, file_name="audit_logs.csv", mime="text/csv")
            # Daily Digest tools
            st.markdown("---")
            st.subheader("🔐 Daily Audit Digest (Tamper-evident)")
            day = st.text_input("Day (UTC, YYYY-MM-DD)", value=pd.Timestamp.utcnow().strftime('%Y-%m-%d'))
            col_d1, col_d2 = st.columns(2)
            with col_d1:
                if st.button("Compute Digest") and day:
                    try:
                        dig = audit_service.compute_daily_digest(day)
                        st.success(f"Digest computed for {dig.get('date_key')}: {dig.get('sha256')} (rows={dig.get('count')})")
                        st.json(dig)
                    except Exception as e:
                        st.error(f"Digest failed: {e}")
            with col_d2:
                if st.button("Get Saved Digest") and day:
                    try:
                        rec = audit_service.get_daily_digest(day)
                        if rec:
                            st.info(f"Saved digest for {rec.get('DATE_KEY')}: {rec.get('SHA256_HEX')} (rows={rec.get('RECORD_COUNT')})")
                            st.json(rec)
                        else:
                            st.warning("No digest found for that date.")
                    except Exception as e:
                        st.error(f"Lookup failed: {e}")
        else:
            st.info("No audit logs found.")
    except Exception as e:
        st.warning(f"Audit log retrieval failed: {e}")


# Explanation for non-technical users
st.info("""💡 **What you're seeing:**
- This page pulls compliance-related signals directly from Snowflake metadata (ACCOUNT_USAGE and INFORMATION_SCHEMA)
- No new tables or schemas are created; we only query existing views
- Access governance shows counts of users, roles, and grants
- Policy coverage shows masking and row access policies present
- Tag usage highlights which governance tags are applied across objects
- QA Review identifies potential under-classified assets based on policy minimums
- Audit Logs export logs for compliance reports and investigations
""")
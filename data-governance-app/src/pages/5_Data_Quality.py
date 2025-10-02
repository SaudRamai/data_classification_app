"""
Data Quality page for the data governance application.
Refactored to:
- Discover tables dynamically from Snowflake (no hardcoded schemas/tables)
- Let users pick which tables power the overview cards
- Compute generic completeness/uniqueness based on detected ID-like columns
- Provide interactive charts and human-friendly AI-style suggestions
"""
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import plotly.express as px
import plotly.io as pio
import pandas as pd
import re
from datetime import datetime, timezone
from src.ui.theme import apply_global_theme
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.lineage_service import lineage_service
from src.services.ai_classification_service import ai_classification_service
from src.ui.quick_links import render_quick_links


# Use global Plotly template (set in src/app.py)

# Page configuration
st.set_page_config(
    page_title="Data Quality - Data Governance App",
    page_icon="📈",
    layout="wide"
)

# Apply centralized theme (fonts, CSS variables, Plotly template)
apply_global_theme()

# Page title
st.title("Data Quality Management")
render_quick_links()

# Styles for this page are provided by the centralized theme; no extra overrides needed
st.markdown("<!-- Using global theme, no page-specific CSS overrides -->", unsafe_allow_html=True)

# Sidebar Filters
st.sidebar.header("Filters")
time_window = st.sidebar.selectbox(
    "Time Window",
    options=["Today", "Last 7 days", "Last 30 days", "All"],
    index=1,
)
dimension_filter = st.sidebar.multiselect(
    "Quality Dimensions",
    options=["Completeness", "Validity", "Uniqueness", "Consistency", "Accuracy", "Timeliness"],
    default=["Completeness", "Validity", "Uniqueness", "Consistency", "Accuracy", "Timeliness"],
)
severity_filter = st.sidebar.multiselect(
    "Issue Severity",
    options=["Critical", "High", "Medium", "Low"],
    default=["Critical", "High", "Medium", "Low"],
)
framework_filter = st.sidebar.multiselect(
    "Compliance Framework",
    options=["SOC 2", "SOX", "GDPR", "HIPAA", "CCPA"],
)
class_tag_filter = st.sidebar.multiselect(
    "Classification Tag",
    options=["Public", "Internal", "Restricted", "Confidential", "PII", "PHI", "PCI", "Financial"],
)

# (moved below, after helper definitions to avoid NameError)

# Utilities for Snowflake metadata and metrics
@st.cache_data(ttl=300)
def list_accessible_tables(db_name: str, limit: int = 50):
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT 
                "TABLE_CATALOG" || '.' || "TABLE_SCHEMA" || '.' || "TABLE_NAME" AS FULL_NAME,
                "TABLE_CATALOG" AS DB,
                "TABLE_SCHEMA" AS SCHEMA,
                "TABLE_NAME" AS NAME,
                NVL("ROW_COUNT", 0) AS ROW_COUNT
            FROM {db_name}.INFORMATION_SCHEMA.TABLES
            WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
            ORDER BY ROW_COUNT DESC, DB, SCHEMA, NAME
            LIMIT {limit}
            """
        )
        return rows or []
    except Exception as e:
        st.warning(f"Could not list tables from Snowflake: {e}")
        return []

# Lineage scope filters (DB/Schema/Table/Column)
st.sidebar.markdown("---")
st.sidebar.caption("Lineage Scope")
_tables_for_lin = list_accessible_tables(settings.SNOWFLAKE_DATABASE, limit=200) or []
_db_options = sorted({r.get('DB') for r in _tables_for_lin if r.get('DB')})
if settings.SNOWFLAKE_DATABASE and settings.SNOWFLAKE_DATABASE not in _db_options:
    _db_options = [settings.SNOWFLAKE_DATABASE] + _db_options
lin_db = st.sidebar.selectbox(
    "Database (for lineage)",
    options=_db_options or [settings.SNOWFLAKE_DATABASE] if settings.SNOWFLAKE_DATABASE else [],
    index=0 if (_db_options or settings.SNOWFLAKE_DATABASE) else 0,
)
lin_schema = st.sidebar.text_input("Schema (optional)", value="")
lin_table = st.sidebar.text_input("Table (optional)", value="")
lin_column = st.sidebar.text_input("Column contains (optional)", value="")

@st.cache_data(ttl=300)
def list_column_tags(db_name: str) -> list:
    """Return column-level tag references if available."""
    try:
        rows = snowflake_connector.execute_query(
            """
            SELECT OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME, TAG_NAME, TAG_VALUE
            FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
            WHERE COLUMN_NAME IS NOT NULL
            """
        ) or []
    except Exception:
        rows = []
    return rows

@st.cache_data(ttl=300)
def get_last_updated(db_name: str) -> dict:
    """Approximate timeliness by LAST_ALTERED from INFORMATION_SCHEMA.TABLES."""
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT "TABLE_CATALOG"||'.'||"TABLE_SCHEMA"||'.'||"TABLE_NAME" AS FULL_NAME,
                   "LAST_ALTERED" AS LAST_ALTERED
            FROM {db_name}.INFORMATION_SCHEMA.TABLES
            WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
            """
        ) or []
        return {r['FULL_NAME']: r.get('LAST_ALTERED') for r in rows}
    except Exception:
        return {}

def _pick_col(cols: list, preferences: list, contains_any: list | None = None):
    cols_up = [c.upper() for c in cols]
    for p in preferences:
        if p.upper() in cols_up:
            return p.upper()
    if contains_any:
        for c in cols_up:
            if any(token in c for token in contains_any):
                return c
    return None

@st.cache_data(ttl=300)
def get_columns(database: str, schema: str, table: str) -> list:
    cols = snowflake_connector.execute_query(
        f"""
        SELECT "COLUMN_NAME"
        FROM {database}.INFORMATION_SCHEMA.COLUMNS
        WHERE "TABLE_SCHEMA" = '{schema}' AND "TABLE_NAME" = '{table}'
        ORDER BY "ORDINAL_POSITION"
        """
    )
    return [c['COLUMN_NAME'].upper() for c in cols] if cols else []

# Function to get generic data quality metrics for selected tables
@st.cache_data(ttl=300)
def get_quality_metrics(selected_fqtns: list[str]):
    db_name = settings.SNOWFLAKE_DATABASE
    results = {}
    for fqtn in selected_fqtns:
        try:
            db, schema, table = fqtn.split('.')
            cols = get_columns(db, schema, table)
            id_col = _pick_col(cols, ['ID', f'{table}_ID', 'PK_ID', 'ROW_ID', 'USER_ID', 'CUSTOMER_ID', 'ORDER_ID', 'PRODUCT_ID'], contains_any=['ID'])

            select_parts = ["COUNT(*) AS TOTAL_ROWS"]
            if id_col:
                select_parts.append(f"COUNT({id_col}) AS NON_NULL_ID")
                select_parts.append(f"COUNT(DISTINCT {id_col}) AS DISTINCT_ID")

            q = f"SELECT {', '.join(select_parts)} FROM {fqtn}"
            data = snowflake_connector.execute_query(q)
            results[fqtn] = data[0] if data else {}
        except Exception as e:
            st.warning(f"Could not compute metrics for {fqtn}: {e}")
            results[fqtn] = {}
    return results

# Validity presets for common sensitive types
VALIDITY_PRESETS = {
    'email': r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
    'ssn': r"^(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}$",
    'ccn': r"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})$",
    'phone': r"^\\+?[0-9 .()-]{7,}$",
    'ip': r"^(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$",
}

# Preset inference helper
def _infer_preset_from_colname(col_name: str) -> str | None:
    name_up = (col_name or '').upper()
    if 'EMAIL' in name_up:
        return 'email'
    if 'SSN' in name_up or 'SOCIAL' in name_up:
        return 'ssn'
    if 'CARD' in name_up or 'CCN' in name_up:
        return 'ccn'
    if 'PHONE' in name_up or 'MOBILE' in name_up:
        return 'phone'
    if name_up == 'IP' or ' IP' in name_up or name_up.endswith('_IP'):
        return 'ip'
    return None

@st.cache_data(ttl=300)
def get_table_validity(fqtn: str) -> float | None:
    """Estimate table-level validity by averaging preset-validated columns (email, ssn, ccn, phone, ip).
    Returns percentage or None if no applicable columns.
    """
    try:
        db, schema, table = fqtn.split('.')
        cols_meta = snowflake_connector.execute_query(
            f"""
            SELECT "COLUMN_NAME"
            FROM {db}.INFORMATION_SCHEMA.COLUMNS
            WHERE "TABLE_SCHEMA" = '{schema}' AND "TABLE_NAME" = '{table}'
            ORDER BY "ORDINAL_POSITION"
            """
        ) or []
        targets = []
        for r in cols_meta:
            preset = _infer_preset_from_colname(r['COLUMN_NAME'])
            if preset and VALIDITY_PRESETS.get(preset):
                targets.append((r['COLUMN_NAME'], preset))
        if not targets:
            return None
        scores = []
        for col, preset in targets[:10]:  # cap to 10 columns
            res = snowflake_connector.execute_query(
                f"""
                SELECT COUNT(*) AS TOTAL,
                       COUNT_IF(REGEXP_LIKE({col}, '{VALIDITY_PRESETS[preset]}')) AS VALID
                FROM {fqtn}
                """
            ) or []
            total = res[0]['TOTAL'] if res else 0
            valid = res[0]['VALID'] if res else 0
            score = round((valid/total)*100,2) if total else 100.0
            scores.append(score)
        return round(sum(scores)/len(scores), 2) if scores else None
    except Exception:
        return None

# Helper: compute Top Values for a column (Top N + Other) with counts and %
@st.cache_data(ttl=300)
def get_top_values(fqtn: str, col: str, total_rows: int, top_n: int = 5) -> list[dict]:
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT "{col}" AS V, COUNT(*) AS C
            FROM {fqtn}
            GROUP BY "{col}"
            ORDER BY C DESC NULLS LAST
            LIMIT {top_n}
            """
        ) or []
    except Exception:
        rows = []
    taken = sum(int(r.get('C') or 0) for r in rows)
    other = max(int(total_rows) - taken, 0)
    results = []
    for r in rows:
        v = r.get('V')
        c = int(r.get('C') or 0)
        pct = round((c/total_rows)*100,1) if total_rows else 0.0
        label = '***MASKED***' if isinstance(v, str) and v.upper().startswith('***MASKED') else (str(v) if v is not None else 'NULL')
        if isinstance(label, str) and len(label) > 64:
            label = label[:61] + '...'
        results.append({'value': label, 'count': c, 'percent': pct})
    if total_rows and other > 0:
        results.append({'value': 'Other', 'count': other, 'percent': round((other/total_rows)*100,1)})
    return results

# Function to calculate completeness score
def calculate_completeness(total, non_null):
    if total == 0:
        return 100.0
    return round((non_null / total) * 100, 2)

# Discover tables and let user pick for overview
with st.spinner("Discovering tables from Snowflake..."):
    available = list_accessible_tables(settings.SNOWFLAKE_DATABASE, limit=50)

sample_assets = [row['FULL_NAME'] for row in available] if available else []

# Schema filter derived from available assets
schemas = sorted({r['SCHEMA'] for r in available}) if available else []
sel_schema = st.sidebar.selectbox("Schema", options=["All"] + schemas, index=0)
if sel_schema != "All":
    sample_assets = [a for a in sample_assets if f".{sel_schema}." in a]

st.subheader("📋 Select Tables for Overview")
if sample_assets:
    default_selection = sample_assets[:3]
    selected_overview_tables = st.multiselect(
        "Choose up to 3 tables to summarize",
        options=sample_assets,
        default=default_selection,
        help="These tables will power the Quality Overview cards below."
    )
else:
    selected_overview_tables = []
    st.info("No accessible tables found. Please check Snowflake permissions and database settings.")

# Get quality metrics for selected tables
with st.spinner("Analyzing data quality for selected tables..."):
    quality_data = get_quality_metrics(selected_overview_tables) if selected_overview_tables else {}

# Data quality overview - Using real data
st.subheader("📊 Overall Data Quality Score")

# Calculate overall quality score based on real data
if quality_data:
    # Aggregate a simple overall score from selected tables
    comp_scores = []
    uniq_scores = []
    per_table_cards = []
    for fqtn, vals in quality_data.items():
        total = vals.get('TOTAL_ROWS', 0)
        non_null_id = vals.get('NON_NULL_ID', 0)
        distinct_id = vals.get('DISTINCT_ID', 0)
        comp = calculate_completeness(total, non_null_id) if 'NON_NULL_ID' in vals else 0.0
        uniq = calculate_completeness(total, distinct_id) if 'DISTINCT_ID' in vals else 0.0
        comp_scores.append(comp)
        uniq_scores.append(uniq)
        per_table_cards.append((fqtn, comp, uniq, total))

    avg_quality_score = round(((sum(comp_scores)/len(comp_scores) if comp_scores else 0) + (sum(uniq_scores)/len(uniq_scores) if uniq_scores else 0)) / 2, 1)

    # Freshness (Timeliness) KPI using INFORMATION_SCHEMA.LAST_ALTERED
    last_updated_map = get_last_updated(settings.SNOWFLAKE_DATABASE)
    freshness_days = []
    now = datetime.now(timezone.utc)
    for fqtn, _, _, _ in per_table_cards:
        lu = last_updated_map.get(fqtn)
        try:
            ts = pd.to_datetime(lu)
            if ts.tzinfo is None:
                ts = ts.tz_localize('UTC')
            freshness_days.append(max((now - ts).days, 0))
        except Exception:
            continue
    avg_freshness = (sum(freshness_days) / len(freshness_days)) if freshness_days else None

    # KPI strip
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.metric("Average Quality Score", f"{avg_quality_score}%", "Based on selected tables")
    with k2:
        st.metric("% Classified Columns Passing", "—")
    with k3:
        st.metric("Sensitive Columns with Issues", "—")
    with k4:
        st.metric("Avg Freshness (days)", f"{avg_freshness:.1f}" if avg_freshness is not None else "N/A")
else:
    st.metric("Average Quality Score", "Awaiting selection", "Pick tables above")

st.subheader("📈 Quality Dimensions")
if quality_data:
    # Tabular summary with multiple dimensions
    rows = []
    # Window for timeliness score
    window_days = 1 if time_window == "Today" else (7 if time_window == "Last 7 days" else (30 if time_window == "Last 30 days" else 30))
    for fqtn, vals in quality_data.items():
        total = vals.get('TOTAL_ROWS', 0)
        non_null_id = vals.get('NON_NULL_ID', None)
        distinct_id = vals.get('DISTINCT_ID', None)
        comp = calculate_completeness(total, non_null_id) if non_null_id is not None else None
        uniq = calculate_completeness(total, distinct_id) if distinct_id is not None else None
        # Validity (avg across detected preset columns)
        validity = get_table_validity(fqtn)
        # Accuracy heuristic: reuse validity as a proxy when no ground truth exists
        accuracy = validity
        # Timeliness (days since last altered) and score
        lu = None
        try:
            lu = last_updated_map.get(fqtn)  # computed above in KPI block
        except Exception:
            lu = None
        days_since = None
        timeliness_score = None
        try:
            if lu is not None:
                ts = pd.to_datetime(lu)
                if ts.tzinfo is None:
                    ts = ts.tz_localize('UTC')
                days_since = max((datetime.now(timezone.utc) - ts).days, 0)
                # Convert to percent: 100 if within window, linear decay after
                if days_since <= window_days:
                    timeliness_score = 100.0
                else:
                    timeliness_score = max(0.0, round(100.0 - (days_since - window_days) * (100.0 / (window_days or 1)), 2))
        except Exception:
            pass
        row = {
            'Table': fqtn,
            'Rows': total,
            'Completeness(ID)%': comp,
            'Uniqueness(ID)%': uniq,
            'Validity%': validity,
            'Consistency%': None,  # Not computed without specific cross-field rules; placeholder for visibility
            'Accuracy%': accuracy,
            'Timeliness (days)': days_since,
            'Timeliness%': timeliness_score,
        }
        # Always show all calculated dimensions in the table
        rows.append(row)
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True)
    # Threshold alerts
    threshold = st.slider("Alert threshold (Average Quality %)", min_value=50, max_value=100, value=85, step=1)
    if avg_quality_score < threshold:
        st.error(f"Overall quality {avg_quality_score}% is below threshold {threshold}%")
else:
    st.info("Select tables to see quality dimensions.")

# Quality Rules Dashboard
st.subheader("🔍 Quality Rules & Profiling")

st.info("No preconfigured quality rules. Use the ad-hoc assessment below to run live checks against your Snowflake data.")

# Column-level profiles tied to classification tags
st.subheader("Column-Level Profiles (by classification tags)")
with st.container():
    col_tags = list_column_tags(settings.SNOWFLAKE_DATABASE)
    prof_rows = []
    if col_tags:
        focus = set(quality_data.keys()) if quality_data else set(sample_assets[:5])
        try:
            tag_df = pd.DataFrame(col_tags)
            tag_df['FULL_NAME'] = tag_df['OBJECT_DATABASE'].str.upper() + '.' + tag_df['OBJECT_SCHEMA'].str.upper() + '.' + tag_df['OBJECT_NAME'].str.upper()
            tag_df = tag_df[tag_df['FULL_NAME'].isin({f.upper() for f in focus})]
            tag_df = tag_df[tag_df['TAG_NAME'].str.upper().isin(['DATA_CLASSIFICATION', 'SENSITIVE_TYPE', 'DATA_SENSITIVITY'])]
            for _, r in tag_df.iterrows():
                fqtn = r['FULL_NAME']
                col = r['COLUMN_NAME']
                tag_name = r['TAG_NAME']
                tag_val = r['TAG_VALUE']
                try:
                    stats = snowflake_connector.execute_query(
                        f"""
                        SELECT COUNT(*) AS TOTAL,
                               COUNT({col}) AS NON_NULL,
                               COUNT(DISTINCT {col}) AS DISTINCT_CNT
                        FROM {fqtn}
                        """
                    ) or []
                    total = stats[0]['TOTAL'] if stats else 0
                    non_null = stats[0]['NON_NULL'] if stats else 0
                    distinct_cnt = stats[0]['DISTINCT_CNT'] if stats else 0
                    comp = round((non_null/total)*100,2) if total else 100.0
                    uniq = round((distinct_cnt/total)*100,2) if total else 100.0
                    # Infer preset
                    preset = None
                    name_up = str(col).upper()
                    if 'EMAIL' in name_up:
                        preset = 'email'
                    elif 'SSN' in name_up or 'SOCIAL' in name_up:
                        preset = 'ssn'
                    elif 'CARD' in name_up or 'CCN' in name_up:
                        preset = 'ccn'
                    elif 'PHONE' in name_up or 'MOBILE' in name_up:
                        preset = 'phone'
                    elif 'IP' in name_up:
                        preset = 'ip'
                    validity = None
                    invalid_rows = None
                    if preset and VALIDITY_PRESETS.get(preset):
                        vr = snowflake_connector.execute_query(
                            f"""
                            SELECT COUNT(*) AS TOTAL,
                                   COUNT_IF(REGEXP_LIKE({col}, '{VALIDITY_PRESETS[preset]}')) AS VALID
                            FROM {fqtn}
                            """
                        ) or []
                        tot = vr[0]['TOTAL'] if vr else 0
                        val = vr[0]['VALID'] if vr else 0
                        validity = round((val/tot)*100,2) if tot else 100.0
                        invalid_rows = max(tot - val, 0)
                    prof_rows.append({
                        'Table': fqtn,
                        'Column': col,
                        'Tag': f"{tag_name}={tag_val}",
                        'Completeness%': comp,
                        'Uniqueness%': uniq,
                        'Validity%': validity,
                        'Invalid Rows': invalid_rows
                    })
                except Exception:
                    continue
        except Exception:
            pass
    if prof_rows:
        df_prof = pd.DataFrame(prof_rows)
        # Build type map per table (cached)
        @st.cache_data(ttl=300)
        def _types_for_table(fqtn: str) -> dict:
            try:
                db, schema, table = fqtn.split('.')
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT "COLUMN_NAME", UPPER("DATA_TYPE") AS DT
                    FROM {db}.INFORMATION_SCHEMA.COLUMNS
                    WHERE "TABLE_SCHEMA" = '{schema}' AND "TABLE_NAME" = '{table}'
                    """
                ) or []
                return {r['COLUMN_NAME']: r['DT'] for r in rows}
            except Exception:
                return {}

        tables_in_prof = sorted(df_prof['Table'].dropna().unique().tolist())
        type_maps = {t: _types_for_table(t) for t in tables_in_prof[:10]}

        # Controls similar to Snowsight
        c1, c2, c3 = st.columns([3,1,1])
        with c1:
            prof_search = st.text_input("Search columns", value="", key="prof_search")
        with c2:
            all_types = sorted({dt for tm in type_maps.values() for dt in tm.values()})
            prof_type = st.selectbox("Column type", options=["All"] + all_types, index=0, key="prof_type")
        with c3:
            issues_only = st.checkbox("Issues only", value=False, key="prof_issues_only")

        df_view = df_prof.copy()
        if prof_search:
            df_view = df_view[df_view['Column'].str.contains(prof_search, case=False, na=False)]
        if prof_type != "All":
            mask_rows = []
            for _, r in df_view.iterrows():
                tmap = type_maps.get(r['Table'], {})
                mask_rows.append(tmap.get(r['Column']) == prof_type)
            import numpy as _np
            df_view = df_view[_np.array(mask_rows, dtype=bool)]
        if class_tag_filter:
            df_view = df_view[df_view['Tag'].apply(lambda s: any(ct in str(s) for ct in class_tag_filter))]
        if issues_only:
            def _has_issue_row(rr):
                dims = [v for v in [rr.get('Completeness%'), rr.get('Uniqueness%'), rr.get('Validity%')] if v is not None]
                return (len(dims) > 0) and any(v < 95 for v in dims)
            df_view = df_view[df_view.apply(_has_issue_row, axis=1)]

        st.dataframe(df_view, use_container_width=True)

        # On-demand detailed stats (min/max/top values) for filtered rows
        st.caption("Compute detailed stats (min/max/top values) for filtered columns")
        if st.button("Compute detailed stats", key="btn_prof_details"):
            detailed = []
            subset = df_view.head(100)
            for _, row in subset.iterrows():
                fqtn = row['Table']
                col = row['Column']
                dtype = type_maps.get(fqtn, {}).get(col, '—')
                try:
                    tot_res = snowflake_connector.execute_query(f"SELECT COUNT(*) AS T FROM {fqtn}")
                    total_rows = int(tot_res[0]['T']) if tot_res else 0
                except Exception:
                    total_rows = 0
                nulls = 0
                null_pct = '—'
                try:
                    s = snowflake_connector.execute_query(f"SELECT COUNT(*) AS TOTAL, COUNT(\"{col}\") AS NON_NULL FROM {fqtn}") or []
                    total = int(s[0]['TOTAL']) if s else total_rows
                    non_null = int(s[0]['NON_NULL']) if s else 0
                    nulls = max(total - non_null, 0)
                    null_pct = f"{round((nulls/total)*100,2) if total else 0.0}%"
                except Exception:
                    pass
                min_val = '—'
                max_val = '—'
                if any(t in dtype for t in ['NUMBER','DECIMAL','INT','FLOAT','DOUBLE','DATE','TIME','TIMESTAMP']):
                    try:
                        r = snowflake_connector.execute_query(f"SELECT MIN(\"{col}\") AS MINV, MAX(\"{col}\") AS MAXV FROM {fqtn}") or []
                        min_val = r[0].get('MINV') if r else '—'
                        max_val = r[0].get('MAXV') if r else '—'
                    except Exception:
                        pass
                # Top values using helper (Top N + Other)
                try:
                    topvals = get_top_values(fqtn, col, total_rows, top_n=5)
                    parts = [f"{tv['value']}  {tv['count']}  {tv['percent']}%" for tv in topvals]
                    top_display = "\n".join(parts) if parts else '—'
                except Exception:
                    top_display = '—'
                detailed.append({
                    'TABLE': fqtn,
                    'COLUMN NAME': col,
                    'DATA TYPE': dtype,
                    'NULL COUNT': nulls,
                    'NULL %': null_pct,
                    'MIN': min_val,
                    'MAX': max_val,
                    'TOP VALUES': top_display,
                    'Completeness%': row.get('Completeness%'),
                    'Uniqueness%': row.get('Uniqueness%'),
                    'Validity%': row.get('Validity%'),
                })
            st.dataframe(pd.DataFrame(detailed), use_container_width=True)

        # KPIs derived from filtered profiles
        try:
            total_cols = len(df_view)
            def _is_passing(row):
                dims = []
                for k in ['Completeness%','Uniqueness%','Validity%']:
                    v = row.get(k)
                    if v is not None:
                        dims.append(v)
                return (len(dims) > 0) and all(v >= 95 for v in dims)
            passing = int(df_view.apply(_is_passing, axis=1).sum()) if total_cols else 0
            sensitive_issue_count = total_cols - passing if total_cols else 0
            pct_passing = round((passing/total_cols)*100,1) if total_cols else 0.0
            m1, m2 = st.columns(2)
            with m1:
                st.metric("% Classified Columns Passing", f"{pct_passing}%")
            with m2:
                st.metric("Sensitive Columns with Issues", sensitive_issue_count)
        except Exception:
            pass
    else:
        st.caption("No column-level tag references available or insufficient privileges.")

    st.markdown("---")

    # Column Profile (similar to Snowsight) for a selected table
    st.subheader("🧬 Column Profile (selected table)")
    selected_profile_asset = st.selectbox(
        "Select table to profile",
        options=sample_assets,
        index=0 if sample_assets else 0,
        help="Choose a table to view per-column statistics"
    ) if sample_assets else None

    if selected_profile_asset:
        @st.cache_data(ttl=300)
        def _profile_table_columns(fqtn: str):
            try:
                db, schema, table = fqtn.split('.')
                cols_meta = snowflake_connector.execute_query(f"""
                    SELECT "COLUMN_NAME", "DATA_TYPE"
                    FROM {db}.INFORMATION_SCHEMA.COLUMNS
                    WHERE "TABLE_SCHEMA" = '{schema}' AND "TABLE_NAME" = '{table}'
                    ORDER BY "ORDINAL_POSITION"
                """) or []
                # total rows once
                tot_res = snowflake_connector.execute_query(f"SELECT COUNT(*) AS T FROM {fqtn}")
                total_rows = int(tot_res[0]['T']) if tot_res else 0
                out = []
                # limit to 50 columns to avoid heavy scans
                for cm in cols_meta[:50]:
                    col = cm['COLUMN_NAME']
                    dtype = str(cm['DATA_TYPE']).upper()
                    q_stats = f"SELECT COUNT(*) AS TOTAL, COUNT(\"{col}\") AS NON_NULL FROM {fqtn}"
                    try:
                        s = snowflake_connector.execute_query(q_stats) or []
                        total = int(s[0]['TOTAL']) if s else total_rows
                        non_null = int(s[0]['NON_NULL']) if s else 0
                        nulls = max(total - non_null, 0)
                        null_pct = round((nulls/total)*100,2) if total else 0.0
                    except Exception:
                        total = total_rows
                        nulls = None
                        null_pct = None
                    min_val = None
                    max_val = None
                    # Only attempt min/max for comparable types
                    if any(t in dtype for t in ['NUMBER','DECIMAL','INT','FLOAT','DOUBLE','DATE','TIME','TIMESTAMP']):
                        try:
                            r = snowflake_connector.execute_query(f"SELECT MIN(\"{col}\") AS MINV, MAX(\"{col}\") AS MAXV FROM {fqtn}") or []
                            min_val = r[0].get('MINV') if r else None
                            max_val = r[0].get('MAXV') if r else None
                        except Exception:
                            pass
                    # Top values using helper (Top N + Other)
                    try:
                        topvals = get_top_values(fqtn, col, total_rows, top_n=5)
                        parts = [f"{tv['value']}  {tv['count']}  {tv['percent']}%" for tv in topvals]
                        top_display = "\n".join(parts)
                    except Exception:
                        top_display = ""
                    out.append({
                        'COLUMN NAME': col,
                        'DATA TYPE': dtype,
                        'NULL COUNT': nulls if nulls is not None else 0,
                        'NULL %': f"{null_pct}%" if null_pct is not None else '—',
                        'MIN': min_val if min_val is not None else '—',
                        'MAX': max_val if max_val is not None else '—',
                        'TOP VALUES': top_display or '—'
                    })
                return out, cols_meta
            except Exception:
                return [], []

        data_rows, meta_rows = _profile_table_columns(selected_profile_asset)
        # Controls similar to screenshot
        c1, c2 = st.columns([3,1])
        with c1:
            search_q = st.text_input("Search", value="", key="profile_search")
        with c2:
            type_options = ["All"] + sorted({str(r['DATA_TYPE']).upper() for r in (meta_rows or [])})
            type_filter = st.selectbox("Column type", options=type_options, index=0, key="profile_type")
        dfp = pd.DataFrame(data_rows)
        if not dfp.empty:
            if search_q:
                dfp = dfp[dfp['COLUMN NAME'].str.contains(search_q, case=False, na=False)]
            if type_filter != "All":
                dfp = dfp[dfp['DATA TYPE'] == type_filter]
            st.dataframe(dfp, use_container_width=True)
        else:
            st.caption("No columns to profile or insufficient privileges.")

        # AI Tag Suggestions for selected table
        with st.expander("🤖 AI Tag Suggestions (column-level)", expanded=False):
            try:
                det = ai_classification_service.detect_sensitive_columns(selected_profile_asset, sample_size=80)
                if det:
                    import pandas as pd
                    sdf = pd.DataFrame(det)
                    # Suggested classification: Restricted if categories present else Internal
                    sdf['suggested_classification'] = sdf['categories'].apply(lambda cs: 'Restricted' if cs else 'Internal')
                    sdf['suggested_C'] = sdf['categories'].apply(lambda cs: 2 if cs else 1)
                    st.dataframe(sdf[['column','categories','confidence','suggested_classification','suggested_C']], use_container_width=True)
                    st.caption("Heuristic: Any detected PII/Financial/Auth => Restricted (C2); otherwise Internal (C1).")
                else:
                    st.info("No sensitive columns detected or insufficient privileges.")
            except Exception as e:
                st.warning(f"AI suggestions unavailable: {e}")

# Compliance Integration
# Compliance section removed per request

# Issues & Remediation removed per request

# AI-style suggestions based on metrics
st.subheader("🤖 AI Suggestions")
def suggest_actions(vals: dict) -> list[str]:
    suggestions = []
    total = vals.get('TOTAL_ROWS', 0)
    comp = calculate_completeness(total, vals.get('NON_NULL_ID', 0)) if 'NON_NULL_ID' in vals else None
    uniq = calculate_completeness(total, vals.get('DISTINCT_ID', 0)) if 'DISTINCT_ID' in vals else None
    if comp is None and uniq is None:
        suggestions.append("Could not detect an ID-like column. Consider defining a primary key or consistent identifier.")
        return suggestions
    if comp is not None and comp < 98:
        suggestions.append("Add NOT NULL constraint or upstream validation for the primary identifier; investigate null-generating pipelines.")
    if uniq is not None and uniq < 99.5:
        suggestions.append("Implement primary key/unique index and deduplication jobs; review merge keys in ELT processes.")
    if total and total > 0 and (comp or 0) >= 98 and (uniq or 0) >= 99.5:
        suggestions.append("Quality for ID looks healthy. Add semantic checks (referential integrity, format validations, range checks).")
    return suggestions

if quality_data:
    for fqtn, vals in quality_data.items():
        st.write(f"Suggestions for `{fqtn}`:")
        s = suggest_actions(vals)
        for item in s:
            st.write(f"- {item}")
else:
    st.info("Select tables to generate AI suggestions.")

# Explanation for non-technical users
st.info("""[Info] What you're seeing:
- This page analyzes the ACTUAL quality of your business data in Snowflake
- Tables are discovered dynamically based on your permissions
- All quality scores are calculated from your actual data, not mock values
- Issues detected here represent real problems in your Snowflake database

This is NOT simulated data - it's your actual data quality metrics!""")
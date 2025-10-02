"""
Data Discovery & Health page
- User-friendly search for tables and columns
- Data preview for selected table
- Run built-in tests to verify connectivity, tags, and row counts
- Trigger full inventory scan to ensure complete DB processing
"""
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import pandas as pd
from src.ui.theme import apply_global_theme

from src.services.discovery_service import discovery_service
from src.services.testing_service import testing_service
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

# Page configuration
st.set_page_config(
    page_title="Data Discovery & Health - Data Governance App",
    page_icon="🔎",
    layout="wide"
)

# Apply centralized theme (fonts, CSS variables, Plotly template)
apply_global_theme()

st.title("Data Discovery & Health")

# Deprecation notice and redirect to consolidated Classification page
st.info("This page has been consolidated into the Classification module. Please use 'Classification' for Discovery, AI Detection, Tagging & Reclassification.")
try:
    # Prefer programmatic switch when available
    if hasattr(st, "switch_page"):
        st.switch_page("pages/3_Classification.py")
except Exception:
    pass
st.markdown("- Go to: [Classification](/3_Classification)")
st.stop()

# Discovered assets list (from Inventory) with first/last seen
st.subheader("📋 Discovered Assets (Inventory)")
try:
    with st.spinner("Reading discovered assets from inventory..."):
        rows = snowflake_connector.execute_query(
            f"""
            SELECT FULL_NAME, OBJECT_DOMAIN, FIRST_DISCOVERED, LAST_SEEN, CLASSIFIED
            FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ASSET_INVENTORY
            ORDER BY COALESCE(LAST_SEEN, FIRST_DISCOVERED) DESC
            LIMIT 200
            """
        ) or []
    if rows:
        idf = pd.DataFrame(rows)
        idf.rename(columns={"FULL_NAME":"Asset","OBJECT_DOMAIN":"Type"}, inplace=True)
        # Status badge
        idf["Status"] = idf["CLASSIFIED"].apply(lambda x: "Classified ✅" if x else "Unclassified ❌")
        st.dataframe(idf[["Asset","Type","FIRST_DISCOVERED","LAST_SEEN","Status"]], use_container_width=True)
    else:
        st.info("No assets in inventory yet. Run a scan below.")
except Exception as e:
    st.warning(f"Unable to read inventory: {e}")
    st.caption("Ensure DATA_GOVERNANCE.ASSET_INVENTORY exists or run a Discovery scan.")

# Search panel
st.subheader("🔍 Search Tables & Columns")
qcol1, qcol2, qcol3 = st.columns([3, 1, 1])
with qcol1:
    query = st.text_input("Search by schema/table/column name", placeholder="e.g. users, customer, email")
with qcol2:
    limit_tables = st.number_input("Table results", min_value=10, max_value=1000, value=100, step=10)
with qcol3:
    limit_cols = st.number_input("Column results", min_value=10, max_value=5000, value=500, step=50)

@st.cache_data(ttl=120)
def search_tables_cached(q: str, limit: int):
    return testing_service.search_tables(q, limit)

@st.cache_data(ttl=120)
def search_columns_cached(q: str, limit: int):
    return testing_service.search_columns(q, limit)

if query:
    with st.spinner("Searching Snowflake..."):
        trows = search_tables_cached(query, limit_tables)
        crows = search_columns_cached(query, limit_cols)
    tdf = pd.DataFrame(trows)
    cdf = pd.DataFrame(crows)
    st.markdown("**Tables**")
    st.dataframe(tdf, use_container_width=True)
    st.markdown("**Columns**")
    st.dataframe(cdf, use_container_width=True)
else:
    st.info("Enter a search string above to find tables and columns.")

st.markdown("---")

# Data preview & tests
st.subheader("👁️ Data Preview & Tests")
selected_table = st.text_input("Enter full table name (DATABASE.SCHEMA.TABLE)")

colp1, colp2 = st.columns(2)
with colp1:
    if st.button("Preview Data") and selected_table:
        try:
            with st.spinner("Fetching sample data..."):
                sample = testing_service.sample_table(selected_table, limit=50)
            if sample:
                st.dataframe(pd.DataFrame(sample), use_container_width=True)
            else:
                st.info("No rows returned (table may be empty).")
        except Exception as e:
            st.error(f"Preview failed: {e}")

with colp2:
    if st.button("Run Tests") and selected_table:
        with st.spinner("Running connectivity, row count, tag presence tests..."):
            res = testing_service.run_table_tests(selected_table)
        st.write("Test Results:")
        st.json(res)

st.markdown("---")

# Complete DB processing
st.subheader("📦 Complete Database Processing")
colf1, colf2 = st.columns([2, 1])
with colf1:
    st.write("Run a full inventory scan to ensure all tables and views are discovered and upserted into the inventory queue.")
with colf2:
    if st.button("Run Full Scan"):
        with st.spinner("Scanning entire database in batches..."):
            total = discovery_service.full_scan(batch_size=1000)
        st.success(f"Full scan complete. Upserted {total} assets.")

# Health checks
st.subheader("🩺 Quick Health Check")
if st.button("Connectivity Test"):
    ok = testing_service.connectivity_test()
    if ok:
        st.success("Connectivity OK: able to query Snowflake.")
    else:
        st.error("Connectivity failed. Check credentials/warehouse/role.")

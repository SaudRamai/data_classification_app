"""
AI Classification (Snowflake Cortex)
- Use AISQL to recommend classification/CIA tags for a selected table
- Optionally apply tags and persist an audit record
"""
from __future__ import annotations

import sys
import os

_here = os.path.abspath(__file__)
_src_dir = os.path.dirname(os.path.dirname(_here))
_project_root = os.path.dirname(_src_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import streamlit as st
import pandas as pd

from src.ui.theme import apply_global_theme
from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.ai_orchestrator_service import ai_orchestrator
from src.services.authorization_service import authz
from src.ui.quick_links import render_quick_links

# Page config and theming
st.set_page_config(page_title="AI Classification", page_icon="🤖", layout="wide")
apply_global_theme()

st.title("AI Classification (Cortex AISQL)")
render_quick_links()

# Authz guard
try:
    ident = authz.get_current_identity()
    st.caption(f"Signed in as: {ident.user or 'Unknown'} | Current role: {ident.current_role or 'Unknown'}")
    if not authz.can_classify(ident):
        st.error("You do not have permission to classify datasets.")
        st.stop()
except Exception as e:
    st.warning(f"Authorization check failed: {e}")
    st.stop()

# Table selector
@st.cache_data(ttl=600)
def list_tables(limit: int = 500):
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME
            FROM {settings.SNOWFLAKE_DATABASE}.INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA')
            ORDER BY TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME
            LIMIT {int(limit)}
            """
        ) or []
        return [f"{r['TABLE_CATALOG']}.{r['TABLE_SCHEMA']}.{r['TABLE_NAME']}" for r in rows]
    except Exception:
        return []

options = list_tables()
sel = st.selectbox("Select a table", options=options if options else ["No tables found"], index=0)

col1, col2 = st.columns([1,1])
with col1:
    if st.button("Get AI Recommendation", type="primary", use_container_width=True) and options and sel != "No tables found":
        with st.spinner("Calling Cortex AISQL for recommendation..."):
            try:
                rec = ai_orchestrator.recommend_only(sel, acting_user=(ident.user or "user"))
                st.session_state["ai_rec_tags"] = rec.get("tags") or {}
                st.session_state["ai_rec_rationale"] = rec.get("rationale") or ""
                st.success("Received AI recommendation")
            except Exception as e:
                st.error(f"AISQL recommend failed: {e}")

with col2:
    if st.button("Apply Recommended Tags", use_container_width=True) and options and sel != "No tables found":
        tags = st.session_state.get("ai_rec_tags") or {}
        if not tags:
            st.warning("No AI recommendation found. Click 'Get AI Recommendation' first.")
        else:
            with st.spinner("Applying tags and recording audit..."):
                try:
                    ai_orchestrator.recommend_and_apply(sel, acting_user=(ident.user or "user"), object_type="TABLE")
                    st.success("Tags applied and audit recorded")
                except Exception as e:
                    st.error(f"Apply failed: {e}")

st.markdown("---")

# Show last recommendation
tags = st.session_state.get("ai_rec_tags") or {}
rationale = st.session_state.get("ai_rec_rationale") or ""

st.subheader("Recommendation")
if tags:
    tdf = pd.DataFrame([{"Tag": k, "Value": v} for k, v in tags.items()])
    st.dataframe(tdf, use_container_width=True)
else:
    st.info("No recommendation yet. Click 'Get AI Recommendation'.")

if rationale:
    st.markdown("**Rationale**")
    st.write(rationale)

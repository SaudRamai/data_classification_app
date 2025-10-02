"""
Executive Visualization Dashboard (Template)
- Focused on visualization layer only
- No static values and no SQL inside
- Wire your Snowflake data into the placeholders later
"""
import streamlit as st
import plotly.express as px
import plotly.io as pio
import plotly.graph_objects as go
import altair as alt
import pandas as pd

# Page configuration
st.set_page_config(
    page_title="Executive Visualization Dashboard",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Dark themes for charts
pio.templates.default = "plotly_dark"
try:
    alt.themes.enable('dark')
except Exception:
    pass

st.title("Executive Visualization Dashboard")
st.caption("Template-only visuals. Plug in your Snowflake data later.")

# 1) Summary KPIs (Top Row) — 6 rectangular metric cards
st.markdown("---")
col_kpi1, col_kpi2, col_kpi3, col_kpi4, col_kpi5, col_kpi6 = st.columns(6)
with col_kpi1:
    st.metric(label="Total Datasets", value="—")
with col_kpi2:
    st.metric(label="Classified", value="—")
with col_kpi3:
    st.metric(label="Unclassified", value="—")
with col_kpi4:
    st.metric(label="High-Risk", value="—")
with col_kpi5:
    st.metric(label="Pending Reviews", value="—")
with col_kpi6:
    st.metric(label="Avg Risk Score", value="—")

# 2) Unified Risk & Violations — compact KPI grid
st.markdown("---")
st.subheader("Unified Risk & Violations")
rv1, rv2, rv3, rv4 = st.columns(4)
with rv1:
    st.metric("Avg Risk Score", "—")
with rv2:
    st.metric("High-Risk Assets", "—")
with rv3:
    st.metric("Open Violations", "—")
with rv4:
    st.metric("Top Risky Assets", "—")

# 3) Classification Distribution — Donut chart (placeholder)
st.markdown("---")
chart_row1_left, chart_row1_mid, chart_row1_right = st.columns([1,1,1])
with chart_row1_left:
    st.subheader("Classification Distribution")
    # Empty donut chart placeholder
    fig_donut = go.Figure()
    fig_donut.update_layout(
        showlegend=True,
        margin=dict(l=0, r=0, t=10, b=0),
        annotations=[dict(text='—', x=0.5, y=0.5, font_size=16, showarrow=False)],
    )
    st.plotly_chart(fig_donut, use_container_width=True)

# 4) Executive Summary – Predictive Overlay (Line)
with chart_row1_mid:
    st.subheader("Executive Summary – Predictive Overlay")
    # Empty line chart placeholder
    fig_line = go.Figure()
    fig_line.update_layout(margin=dict(l=0, r=0, t=10, b=0))
    st.plotly_chart(fig_line, use_container_width=True)

# 5) Classification Coverage by Business Unit — Horizontal bar
with chart_row1_right:
    st.subheader("Coverage by Business Unit")
    # Empty horizontal bar placeholder
    fig_bu = go.Figure()
    fig_bu.update_layout(margin=dict(l=0, r=0, t=10, b=0))
    st.plotly_chart(fig_bu, use_container_width=True)

# 6) Top Tag Usage — Bar chart (preferred over word cloud here)
st.markdown("---")
st.subheader("Top Tag Usage")
fig_tags = go.Figure()
fig_tags.update_layout(margin=dict(l=0, r=0, t=10, b=0))
st.plotly_chart(fig_tags, use_container_width=True)

# 7) Asset Type Analysis — Pie chart or stacked bar (placeholder)
st.markdown("---")
st.subheader("Asset Type Analysis")
fig_asset_types = go.Figure()
fig_asset_types.update_layout(margin=dict(l=0, r=0, t=10, b=0))
st.plotly_chart(fig_asset_types, use_container_width=True)

# 8) Reviews & Reclassification — 3 KPI counters
st.markdown("---")
st.subheader("Reviews & Reclassification")
rc1, rc2, rc3 = st.columns(3)
with rc1:
    st.metric("Upcoming Reviews (7d)", "—")
with rc2:
    st.metric("Pending Approvals", "—")
with rc3:
    st.metric("Overdue Reviews", "—")

# 9) Classification Deadline Monitor — traffic-light style KPI
st.markdown("---")
st.subheader("Classification Deadline Monitor")
col_deadline = st.container()
with col_deadline:
    # Placeholder metric with neutral value
    st.metric("Unclassified vs Deadlines", "—")

# 10) Recent Classification Activity — Table placeholder
st.markdown("---")
st.subheader("Recent Classification Activity")
placeholder_df = pd.DataFrame(columns=[
    "Asset Name", "Old Classification", "New Classification", "User", "Timestamp"
])
st.dataframe(placeholder_df, use_container_width=True)

st.caption("Layout-only template. Replace placeholders by wiring Snowflake query results into the above components.")

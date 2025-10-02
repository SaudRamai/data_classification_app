"""
ML Compliance Operations

Orchestrates continuous ML-based classification, behavioral analytics, federated
anomaly detection, NLP compliance checks, and automated policy enforcement.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import pandas as pd

from src.services.continuous_classifier_service import continuous_classifier_service
from src.services.behavior_analytics_service import behavior_analytics_service
from src.services.federated_anomaly_service import federated_anomaly_service
from src.services.ai_classification_service import ai_classification_service
from src.services.nlp_compliance_service import nlp_compliance_service

st.set_page_config(page_title="ML Compliance Ops", page_icon="🧠", layout="wide")

st.title("🧠 ML Compliance Operations")

st.markdown("Run continuous classification, monitor access behavior, detect anomalies, and enforce protection policies.")

with st.expander("▶️ Continuous Classification Runner", expanded=True):
    c1, c2, c3 = st.columns([2,1,1])
    with c1:
        limit = st.slider("Max tables to scan", min_value=5, max_value=200, value=50, step=5)
    with c2:
        enforce = st.checkbox("Apply protection policies (masking)", value=False,
                              help="If enabled, applies a default masking policy to sensitive columns.")
    with c3:
        run = st.button("Run Scan", type="primary")

    if run:
        with st.spinner("Running continuous classification scan..."):
            out = continuous_classifier_service.run_scan(limit=limit, apply_policies=enforce)
        st.success(f"Scanned {out['count_tables']} tables. Sensitive columns: {out['sensitive_columns']}. Policies applied: {out['policies_applied']}.")
        st.json(out['classification_distribution'])
        df = pd.DataFrame(out['results'])
        if not df.empty:
            st.dataframe(df[['table','classification','frameworks','confidence','policies_applied']].head(200), use_container_width=True)
        with st.expander("Per-table details"):
            for r in out['results']:
                with st.container(border=True):
                    st.subheader(r['table'])
                    st.caption(f"Class: {r['classification']} | Frameworks: {', '.join(r['frameworks'])} | Confidence: {r['confidence']}")
                    s = pd.DataFrame(r['sensitive_columns'])
                    if not s.empty:
                        st.dataframe(s.head(200), use_container_width=True)
                    else:
                        st.write("No sensitive columns detected by heuristics.")

with st.expander("📈 Behavioral Analytics & Anomalies", expanded=False):
    days = st.slider("Lookback days", 1, 30, 7)
    fetch = st.button("Fetch & Detect Anomalies")
    if fetch:
        with st.spinner("Fetching access events and computing anomalies..."):
            df_ev = behavior_analytics_service.fetch_access_events(days=days)
            cnts = behavior_analytics_service.aggregate_user_object_counts(df_ev)
            anomalies = behavior_analytics_service.zscore_anomalies(cnts)
        if df_ev is None or df_ev.empty:
            st.warning("No events available or insufficient privileges.")
        else:
            st.metric("Events", len(df_ev))
            st.metric("Distinct users", df_ev['USER_NAME'].nunique())
            st.metric("Distinct objects", df_ev['FULL_NAME'].nunique())
            st.dataframe(cnts.head(200), use_container_width=True)
            if anomalies:
                a_df = pd.DataFrame([a.__dict__ for a in anomalies])
                st.subheader("Top Anomalies (z-score)")
                st.dataframe(a_df, use_container_width=True)
            else:
                st.info("No significant anomalies detected with current threshold.")

with st.expander("🤝 Federated Anomaly Detection (per schema)", expanded=False):
    fed_go = st.button("Train partition models and score")
    if fed_go:
        with st.spinner("Building feature matrix and training per-schema models..."):
            df_ev = behavior_analytics_service.fetch_access_events(days=days)
            feats = behavior_analytics_service.build_feature_matrix(df_ev)
            models = federated_anomaly_service.train_partition_models(feats)
            scored = federated_anomaly_service.score_anomalies(feats, models)
        if not scored:
            st.info("No partitions/models scored (need more data).")
        else:
            st.success(f"Scored {len(scored)} events across {len(models)} partitions.")
            st.dataframe(pd.DataFrame([s.__dict__ for s in scored]), use_container_width=True)

with st.expander("🗂 NLP Compliance (unstructured text)", expanded=False):
    sample_text = st.text_area("Paste sample text to analyze", height=150, placeholder="e.g., Customer email is john.doe@acme.com and phone +1-555-123-4567")
    if st.button("Analyze Text"):
        res = nlp_compliance_service.analyze_text(sample_text)
        st.json(res)

    st.divider()
    st.caption("Analyze a table's text columns (sample rows)")
    fqtn = st.text_input("Full table name (DB.SCHEMA.TABLE)")
    sample_rows = st.number_input("Sample rows", min_value=10, max_value=500, value=100, step=10)
    if st.button("Analyze Table Text"):
        if fqtn:
            from src.connectors.snowflake_connector import snowflake_connector
            rows = snowflake_connector.execute_query(f"SELECT * FROM {fqtn} LIMIT {int(sample_rows)}") or []
            res = nlp_compliance_service.analyze_table_rows(rows)
            st.json(res)
        else:
            st.warning("Enter a table name.")

st.caption("All analysis is executed locally using Snowflake samples; no external data egress.")

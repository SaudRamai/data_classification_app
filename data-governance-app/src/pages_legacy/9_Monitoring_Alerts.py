"""
Monitoring & Alerts page
- Real-time compliance monitoring
- Policy violation detection and remediation tasks
- Discovery scans, reclassification triggers, and unified risk view
"""
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import pandas as pd

from src.services.discovery_service import discovery_service
from src.services.compliance_service import compliance_service
from src.services.reclassification_service import reclassification_service
from src.services.metadata_service import metadata_service
from src.services.audit_service import audit_service

# Page configuration
st.set_page_config(
    page_title="Monitoring & Alerts - Data Governance App",
    page_icon="🚨",
    layout="wide"
)

st.title("Monitoring & Alerts")

# Actions row
c1, c2, c3, c4 = st.columns(4)
with c1:
    if st.button("🔍 Scan Discovery", help="Scan Snowflake for new/changed assets"):
        with st.spinner("Scanning INFORMATION_SCHEMA..."):
            count = discovery_service.scan()
        st.success(f"Discovery scan complete. Upserted {count} assets.")
with c2:
    if st.button("⚖️ Detect Violations", help="Run compliance violation rules"):
        with st.spinner("Running violation rules..."):
            created = compliance_service.detect_violations()
        st.success(f"Detected and logged {created} violations.")
with c3:
    if st.button("♻️ Detect Reclass Triggers", help="Detect SLA/DDL triggers for reclassification"):
        with st.spinner("Detecting reclassification triggers..."):
            created = reclassification_service.detect_triggers()
        st.success(f"Submitted {created} reclassification requests.")
with c4:
    if st.button("📈 Refresh Risk View"):
        st.cache_data.clear()
        st.success("Refreshed cached data.")

st.markdown("---")

# Unified Risk View
st.subheader("📊 Unified Lineage-Quality-Classification Risk View")
with st.spinner("Loading unified metadata view..."):
    unified = metadata_service.get_unified_records(limit=200)

if unified:
    df = pd.DataFrame(unified)
    st.dataframe(df, use_container_width=True)
else:
    st.info("No unified metadata available. Run a discovery scan first.")

st.markdown("---")

# Open Violations and Remediation
v1, v2 = st.columns([2, 1])
with v1:
    st.subheader("🚫 Open Violations")
    violations = compliance_service.list_open_violations(limit=200)
    if violations:
        vdf = pd.DataFrame(violations)
        st.dataframe(vdf, use_container_width=True)
    else:
        st.info("No open violations detected.")
with v2:
    st.subheader("🛠️ Create Remediation Task")
    violation_id = st.text_input("Violation ID")
    assignee = st.text_input("Assign to (email)")
    due_date = st.date_input("Due date")
    if st.button("Create Task") and violation_id and assignee and due_date:
        tid = compliance_service.create_remediation_task(violation_id, assignee, str(due_date))
        st.success(f"Created remediation task {tid}")

st.markdown("---")

# Reclassification Requests Queue
st.subheader("📝 Reclassification Requests")
status_filter = st.selectbox("Filter by status", ["All", "Pending", "Approved", "Rejected"], index=1)
if status_filter == "All":
    reqs = reclassification_service.list_requests(limit=200)
else:
    reqs = reclassification_service.list_requests(status=status_filter, limit=200)

if reqs:
    rdf = pd.DataFrame(reqs)
    st.dataframe(rdf, use_container_width=True)
    selected_id = st.text_input("Request ID to approve/reject")
    approver = st.text_input("Approver (email)")
    colA, colB = st.columns(2)
    with colA:
        if st.button("✅ Approve") and selected_id and approver:
            reclassification_service.approve(selected_id, approver)
            st.success(f"Approved request {selected_id}")
    with colB:
        reject_reason = st.text_input("Rejection reason")
        if st.button("❌ Reject") and selected_id and approver:
            reclassification_service.reject(selected_id, approver, reject_reason)
            st.success(f"Rejected request {selected_id}")
else:
    st.info("No reclassification requests found.")

st.markdown("---")

# Audit Logs
st.subheader("📜 Recent Audit Trail")
logs = audit_service.query(limit=50)
if logs:
    st.dataframe(pd.DataFrame(logs), use_container_width=True)
else:
    st.info("No audit logs yet. Actions you take here will be recorded.")

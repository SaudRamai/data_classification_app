"""
Controls Management page for the data governance application.
This page provides visibility into SOC 2 and SOX control frameworks.
"""
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import plotly.express as px
import pandas as pd
from src.connectors.snowflake_connector import snowflake_connector

# Page configuration
st.set_page_config(
    page_title="Controls Management - Data Governance App",
    page_icon="✅",
    layout="wide"
)

# Page title
st.title("Controls Management")

# Notice: This module has been merged into primary sections per Data Classification Policy
st.info(
    "This page is deprecated. Use the consolidated sections instead: "
    "- Compliance & Audit (SOC 2/SOX posture, QA, reports)\n"
    "- Admin & Roles (governance settings, role management)\n\n"
    "Toggle below to access the legacy view if needed."
)

show_legacy = st.checkbox("Show legacy Controls Management (deprecated)", value=False)
if not show_legacy:
    st.markdown("- Go to: [Compliance & Audit](/4_Compliance) | [Administration](/10_Administration)")
    st.stop()

# Tabs for different control frameworks
tab1, tab2, tab3 = st.tabs(["SOC 2 Controls", "SOX Controls", "Control Testing"])

with tab1:
    st.subheader("SOC 2 Trust Service Criteria")
    
    # SOC 2 control matrix
    soc2_controls = [
        {"Category": "CC1", "Name": "Control Environment", "Description": "The entity demonstrates a commitment to integrity and ethical values.", "Status": "✅ Implemented", "Evidence": "Policy documents, training records"},
        {"Category": "CC2", "Name": "Communication", "Description": "The entity communicates with external parties regarding matters affecting the suitability of its system, services, and related processing.", "Status": "✅ Implemented", "Evidence": "Communication protocols, documentation"},
        {"Category": "CC3", "Name": "Risk Assessment", "Description": "The entity identifies and analyzes risks to the achievement of objectives.", "Status": "✅ Implemented", "Evidence": "Risk assessment reports, mitigation plans"},
        {"Category": "CC4", "Name": "Monitoring Activities", "Description": "The entity selects and develops ongoing and/or separate evaluations.", "Status": "⚠️ In Progress", "Evidence": "Monitoring procedures, audit findings"},
        {"Category": "CC5", "Name": "Control Activities", "Description": "The entity selects and develops control activities that contribute to the mitigation of risks.", "Status": "✅ Implemented", "Evidence": "Control procedures, access logs"},
        {"Category": "CC6", "Name": "Logical and Physical Access Controls", "Description": "The entity implements logical and physical access controls to meet objectives.", "Status": "✅ Implemented", "Evidence": "Access policies, audit logs"},
        {"Category": "CC7", "Name": "System Operations", "Description": "The entity uses detection and monitoring procedures to identify changes to systems.", "Status": "✅ Implemented", "Evidence": "Monitoring tools, incident reports"},
        {"Category": "CC8", "Name": "Change Management", "Description": "The entity authorizes, designs, develops or acquires, configures, and tests changes to systems.", "Status": "✅ Implemented", "Evidence": "Change management procedures, approval logs"},
        {"Category": "CC9", "Name": "Risk Mitigation", "Description": "The entity identifies, selects, and develops risk mitigation activities.", "Status": "⚠️ In Progress", "Evidence": "Risk mitigation plans, insurance policies"}
    ]
    
    soc2_df = pd.DataFrame(soc2_controls)
    
    # Display controls in a table
    st.dataframe(soc2_df, width='stretch')
    
    # Compliance score
    total_controls = len(soc2_controls)
    implemented_controls = len([c for c in soc2_controls if c['Status'] == '✅ Implemented'])
    compliance_percentage = (implemented_controls / total_controls) * 100
    
    st.metric("SOC 2 Compliance", f"{compliance_percentage:.1f}%", f"{implemented_controls}/{total_controls} controls implemented")
    
    # Visualization
    status_counts = soc2_df['Status'].value_counts()
    fig = px.pie(values=status_counts.values, names=status_counts.index, title='SOC 2 Control Status')
    st.plotly_chart(fig)

with tab2:
    st.subheader("SOX Control Framework")
    
    # SOX control matrix
    sox_controls = [
        {"Category": "ELC", "Name": "Entity Level Controls", "Description": "Controls at the entity level that affect the company's control environment.", "Status": "✅ Implemented", "Evidence": "Corporate governance policies, board minutes"},
        {"Category": "GITC", "Name": "General IT Controls", "Description": "Controls over IT governance, access to programs and data, and computer operations.", "Status": "✅ Implemented", "Evidence": "IT policies, access reviews"},
        {"Category": "AC", "Name": "Application Controls", "Description": "Controls over the initiation, recording, processing, and reporting of financial data.", "Status": "✅ Implemented", "Evidence": "Application documentation, testing results"},
        {"Category": "BPC", "Name": "Business Process Controls", "Description": "Controls over business processes that affect financial reporting.", "Status": "✅ Implemented", "Evidence": "Process documentation, control testing"},
        {"Category": "MDC", "Name": "Manual Deficiency Controls", "Description": "Controls to address deficiencies identified in automated controls.", "Status": "⚠️ In Progress", "Evidence": "Deficiency tracking, remediation plans"}
    ]
    
    sox_df = pd.DataFrame(sox_controls)
    
    # Display controls in a table
    st.dataframe(sox_df, width='stretch')
    
    # Compliance score
    total_controls = len(sox_controls)
    implemented_controls = len([c for c in sox_controls if c['Status'] == '✅ Implemented'])
    compliance_percentage = (implemented_controls / total_controls) * 100
    
    st.metric("SOX Compliance", f"{compliance_percentage:.1f}%", f"{implemented_controls}/{total_controls} controls implemented")
    
    # Visualization
    status_counts = sox_df['Status'].value_counts()
    fig = px.pie(values=status_counts.values, names=status_counts.index, title='SOX Control Status')
    st.plotly_chart(fig)

with tab3:
    st.subheader("Control Testing & Evidence")
    
    # Sample testing schedule
    testing_schedule = [
        {"Control": "CC6 - Access Controls", "Frequency": "Monthly", "Last Tested": "2023-10-15", "Next Due": "2023-11-15", "Status": "✅ Passed"},
        {"Control": "GITC - User Access Reviews", "Frequency": "Quarterly", "Last Tested": "2023-09-30", "Next Due": "2023-12-31", "Status": "✅ Passed"},
        {"Control": "AC - Financial Data Processing", "Frequency": "Monthly", "Last Tested": "2023-10-10", "Next Due": "2023-11-10", "Status": "⚠️ In Progress"},
        {"Control": "BPC - Revenue Recognition", "Frequency": "Quarterly", "Last Tested": "2023-08-15", "Next Due": "2023-11-15", "Status": "✅ Scheduled"}
    ]
    
    schedule_df = pd.DataFrame(testing_schedule)
    st.dataframe(schedule_df, width='stretch')
    
    # Evidence repository
    st.subheader("Evidence Repository")
    evidence_items = [
        {"Document": "Access Policy v2.1.pdf", "Control": "CC6", "Uploaded": "2023-10-01", "Uploader": "admin@company.com"},
        {"Document": "User Access Review Q3.xlsx", "Control": "GITC", "Uploaded": "2023-09-30", "Uploader": "security@company.com"},
        {"Document": "Change Management Log.csv", "Control": "CC8", "Uploaded": "2023-10-15", "Uploader": "itops@company.com"}
    ]
    
    evidence_df = pd.DataFrame(evidence_items)
    st.dataframe(evidence_df, width='stretch')
    
    # Upload new evidence
    st.subheader("Upload New Evidence")
    uploaded_file = st.file_uploader("Choose a file", type=['pdf', 'xlsx', 'csv', 'docx'])
    if uploaded_file is not None:
        st.success(f"File {uploaded_file.name} uploaded successfully!")

# Explanation for non-technical users
st.info("""💡 **What you're seeing:**
- This page shows your organization's compliance with SOC 2 and SOX frameworks
- Controls are marked as Implemented, In Progress, or Pending
- Evidence documents support each control's implementation
- Regular testing ensures controls remain effective

**This helps demonstrate your compliance posture to auditors!**""")

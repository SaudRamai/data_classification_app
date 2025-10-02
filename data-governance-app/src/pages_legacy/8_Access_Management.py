"""
Access Management page for the data governance application.
This page provides tools for user provisioning, access reviews, and privilege management.
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
    page_title="Access Management - Data Governance App",
    page_icon="👥",
    layout="wide"
)

# Page title
st.title("Access Management")

# Notice: This module is consolidated under Administration (Roles & Permissions)
st.info(
    "This page is deprecated. Use the consolidated section instead: "
    "- Admin & Roles (role assignments, governance settings)\n\n"
    "Toggle below to access the legacy view if needed."
)
show_legacy = st.checkbox("Show legacy Access Management (deprecated)", value=False)
if not show_legacy:
    st.markdown("- Go to: [Administration](/10_Administration)")
    st.stop()

# Tabs for different access management functions
tab1, tab2, tab3, tab4 = st.tabs(["User Provisioning", "Access Reviews", "Privileged Access", "Role Management"])

with tab1:
    st.subheader("User Provisioning")
    
    # Get real user data from Snowflake
    try:
        with st.spinner("Loading user data from Snowflake..."):
            users_query = """
                SELECT "NAME" as USER_NAME, "CREATED_ON", "DISABLED", "DEFAULT_ROLE"
                FROM "SNOWFLAKE"."ACCOUNT_USAGE"."USERS"
                WHERE "DELETED_ON" IS NULL
                ORDER BY "CREATED_ON" DESC
                LIMIT 20
            """
            users_data = snowflake_connector.execute_query(users_query)
            
            if users_data:
                users_df = pd.DataFrame(users_data)
                users_df['CREATED_ON'] = pd.to_datetime(users_df['CREATED_ON'])
                users_df['Status'] = users_df['DISABLED'].apply(lambda x: '❌ Disabled' if x else '✅ Active')
                
                # Display users
                st.dataframe(users_df[['USER_NAME', 'CREATED_ON', 'Status', 'DEFAULT_ROLE']], width='stretch')
                
                # User metrics
                total_users = len(users_df)
                active_users = len(users_df[users_df['DISABLED'] == False])
                disabled_users = len(users_df[users_df['DISABLED'] == True])
                
                col1, col2, col3 = st.columns(3)
                col1.metric("Total Users", total_users)
                col2.metric("Active Users", active_users)
                col3.metric("Disabled Users", disabled_users)
            else:
                st.info("No user data available from Snowflake.")
    except Exception as e:
        st.warning(f"Could not load user data: {e}")
        
        # Sample data for demonstration
        sample_users = [
            {"USER_NAME": "john.doe@company.com", "CREATED_ON": "2023-01-15", "Status": "✅ Active", "DEFAULT_ROLE": "ANALYST"},
            {"USER_NAME": "jane.smith@company.com", "CREATED_ON": "2023-02-20", "Status": "✅ Active", "DEFAULT_ROLE": "DATA_SCIENTIST"},
            {"USER_NAME": "bob.wilson@company.com", "CREATED_ON": "2023-03-10", "Status": "❌ Disabled", "DEFAULT_ROLE": "DEVELOPER"},
            {"USER_NAME": "sarah.jones@company.com", "CREATED_ON": "2023-04-05", "Status": "✅ Active", "DEFAULT_ROLE": "ADMIN"}
        ]
        sample_df = pd.DataFrame(sample_users)
        st.dataframe(sample_df, width='stretch')
    
    # User provisioning form
    st.subheader("Provision New User")
    with st.form("user_provisioning_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            user_name = st.text_input("User Name/Email")
            first_name = st.text_input("First Name")
            last_name = st.text_input("Last Name")
        
        with col2:
            role = st.selectbox("Default Role", ["ANALYST", "DATA_SCIENTIST", "DEVELOPER", "ADMIN", "READER"])
            warehouse = st.selectbox("Default Warehouse", ["COMPUTE_WH", "ANALYTICS_WH", "DEV_WH"])
            
        # Custom roles
        custom_roles = st.multiselect("Additional Roles", ["FINANCE_ROLE", "HR_ROLE", "MARKETING_ROLE", "SECURITY_ROLE"])
        
        # Access expiration
        expiration_date = st.date_input("Access Expiration Date (optional)")
        
        # Submit button
        submitted = st.form_submit_button("Provision User")
        if submitted:
            if user_name:
                st.success(f"User {user_name} provisioned successfully with role {role}!")
                st.info("In a real implementation, this would create the user in Snowflake with the specified roles and settings.")
            else:
                st.warning("Please provide a user name.")

with tab2:
    st.subheader("Access Reviews")
    
    # Sample access review data
    access_reviews = [
        {"Review Name": "Q3 2023 User Access Review", "Status": "✅ Completed", "Due Date": "2023-10-31", "Reviewed By": "security@company.com", "Findings": "2 excessive access cases"},
        {"Review Name": "Q4 2023 User Access Review", "Status": "⚠️ In Progress", "Due Date": "2023-12-31", "Reviewed By": "security@company.com", "Findings": "In progress"},
        {"Review Name": "Privileged Access Review", "Status": "📅 Scheduled", "Due Date": "2024-01-15", "Reviewed By": "security@company.com", "Findings": "Scheduled"}
    ]
    
    reviews_df = pd.DataFrame(access_reviews)
    st.dataframe(reviews_df, width='stretch')
    
    # Access review form
    st.subheader("Initiate New Access Review")
    with st.form("access_review_form"):
        review_name = st.text_input("Review Name", "Q1 2024 User Access Review")
        review_type = st.selectbox("Review Type", ["User Access Review", "Role Access Review", "Privileged Access Review", "Application Access Review"])
        reviewers = st.multiselect("Reviewers", ["security@company.com", "itops@company.com", "compliance@company.com"])
        due_date = st.date_input("Due Date")
        
        submitted = st.form_submit_button("Start Review")
        if submitted:
            st.success(f"Access review '{review_name}' initiated successfully!")
            st.info("In a real implementation, this would create a review task and notify the reviewers.")

with tab3:
    st.subheader("Privileged Access Monitoring")
    
    # Sample privileged users
    privileged_users = [
        {"User": "admin@company.com", "Role": "ACCOUNTADMIN", "Last Login": "2023-10-15", "Access Type": "Permanent", "Status": "✅ Active"},
        {"User": "security@company.com", "Role": "SECURITYADMIN", "Last Login": "2023-10-14", "Access Type": "Permanent", "Status": "✅ Active"},
        {"User": "dbadmin@company.com", "Role": "SYSADMIN", "Last Login": "2023-10-10", "Access Type": "Time-based", "Status": "✅ Active"},
        {"User": "analyst@company.com", "Role": "ACCOUNTADMIN", "Last Login": "2023-09-01", "Access Type": "Just-in-time", "Status": "⚠️ Review Needed"}
    ]
    
    privileged_df = pd.DataFrame(privileged_users)
    st.dataframe(privileged_df, width='stretch')
    
    # Privileged access metrics
    total_privileged = len(privileged_users)
    review_needed = len([u for u in privileged_users if u['Status'] == '⚠️ Review Needed'])
    
    col1, col2 = st.columns(2)
    col1.metric("Total Privileged Users", total_privileged)
    col2.metric("Users Needing Review", review_needed)
    
    # Just-in-time access request
    st.subheader("Request Just-in-Time Access")
    with st.form("jit_access_form"):
        user = st.text_input("User Name")
        role = st.selectbox("Role to Access", ["ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN"])
        duration = st.select_slider("Access Duration", options=["1 hour", "4 hours", "8 hours", "1 day", "3 days"])
        reason = st.text_area("Business Justification")
        
        submitted = st.form_submit_button("Request Access")
        if submitted:
            st.success(f"Just-in-time access request for {user} submitted successfully!")
            st.info("In a real implementation, this would create an access request that requires approval.")

with tab4:
    st.subheader("Role Management")
    
    # Get real role data from Snowflake
    try:
        with st.spinner("Loading role data from Snowflake..."):
            roles_query = """
                SELECT "NAME", "CREATED_ON", "ASSIGNED_TO_USERS" as IS_DEFAULT
                FROM "SNOWFLAKE"."ACCOUNT_USAGE"."ROLES"
                WHERE "DELETED_ON" IS NULL
                ORDER BY "CREATED_ON" DESC
                LIMIT 20
            """
            roles_data = snowflake_connector.execute_query(roles_query)
            
            if roles_data:
                roles_df = pd.DataFrame(roles_data)
                roles_df['CREATED_ON'] = pd.to_datetime(roles_df['CREATED_ON'])
                roles_df['Type'] = roles_df['IS_DEFAULT'].apply(lambda x: 'Default' if x else 'Custom')
                
                # Display roles
                st.dataframe(roles_df[['NAME', 'CREATED_ON', 'Type']], width='stretch')
                
                # Role metrics
                total_roles = len(roles_df)
                custom_roles = len(roles_df[roles_df['IS_DEFAULT'] == False])
                default_roles = len(roles_df[roles_df['IS_DEFAULT'] == True])
                
                col1, col2, col3 = st.columns(3)
                col1.metric("Total Roles", total_roles)
                col2.metric("Custom Roles", custom_roles)
                col3.metric("Default Roles", default_roles)
            else:
                st.info("No role data available from Snowflake.")
    except Exception as e:
        st.warning(f"Could not load role data: {e}")
        
        # Sample data for demonstration
        sample_roles = [
            {"NAME": "ACCOUNTADMIN", "CREATED_ON": "2020-01-01", "Type": "Default"},
            {"NAME": "SECURITYADMIN", "CREATED_ON": "2020-01-01", "Type": "Default"},
            {"NAME": "SYSADMIN", "CREATED_ON": "2020-01-01", "Type": "Default"},
            {"NAME": "FINANCE_ROLE", "CREATED_ON": "2023-05-15", "Type": "Custom"},
            {"NAME": "HR_ROLE", "CREATED_ON": "2023-06-20", "Type": "Custom"}
        ]
        sample_df = pd.DataFrame(sample_roles)
        st.dataframe(sample_df, width='stretch')
    
    # Create new role
    st.subheader("Create New Role")
    with st.form("role_creation_form"):
        role_name = st.text_input("Role Name")
        role_description = st.text_area("Role Description")
        
        # Role hierarchy
        parent_roles = st.multiselect("Parent Roles", ["ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN", "FINANCE_ROLE", "HR_ROLE"])
        
        # Role attributes
        st.subheader("Role Attributes")
        col1, col2 = st.columns(2)
        with col1:
            can_create_users = st.checkbox("Can Create Users")
            can_create_roles = st.checkbox("Can Create Roles")
        with col2:
            can_manage_warehouses = st.checkbox("Can Manage Warehouses")
            can_manage_databases = st.checkbox("Can Manage Databases")
        
        submitted = st.form_submit_button("Create Role")
        if submitted:
            if role_name:
                st.success(f"Role {role_name} created successfully!")
                st.info("In a real implementation, this would create the role in Snowflake with the specified attributes.")
            else:
                st.warning("Please provide a role name.")

# Explanation for non-technical users
st.info("""💡 **What you're seeing:**
- This page helps you manage user access to your Snowflake environment
- User provisioning creates new users with appropriate roles and permissions
- Access reviews ensure users only have the access they need
- Privileged access monitoring helps control powerful administrative accounts
- Role management allows you to create and organize access roles

**This helps maintain least-privilege access and meets compliance requirements!**""")

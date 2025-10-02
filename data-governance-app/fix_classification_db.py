with open('src/pages/3_Classification.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the problematic database reference with proper fallback
old_code = """    try:
        with st.spinner("Reading discovered assets from inventory..."):
            rows = snowflake_connector.execute_query(
                f\"\"\"
                SELECT FULL_NAME, OBJECT_DOMAIN, FIRST_DISCOVERED, LAST_SEEN, CLASSIFIED
                FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ASSET_INVENTORY
                ORDER BY COALESCE(LAST_SEEN, FIRST_DISCOVERED) DESC
                LIMIT 200
                \"\"\"
            ) or []"""

new_code = """    try:
        db = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
        if not db:
            st.warning("No database selected. Please select a database from the Dashboard.")
            st.stop()
        with st.spinner("Reading discovered assets from inventory..."):
            rows = snowflake_connector.execute_query(
                f\"\"\"
                SELECT FULL_NAME, OBJECT_DOMAIN, FIRST_DISCOVERED, LAST_SEEN, CLASSIFIED
                FROM {db}.DATA_GOVERNANCE.ASSET_INVENTORY
                ORDER BY COALESCE(LAST_SEEN, FIRST_DISCOVERED) DESC
                LIMIT 200
                \"\"\"
            ) or []"""

if old_code in content:
    content = content.replace(old_code, new_code)
    with open('src/pages/3_Classification.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ Fixed database reference in Classification page")
else:
    print("❌ Could not find the code to replace")

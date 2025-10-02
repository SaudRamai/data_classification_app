with open('src/pages/3_Classification.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Add a helper function at the top after imports
insert_after_line = None
for i, line in enumerate(lines):
    if 'label_service = get_label_service()' in line:
        insert_after_line = i + 1
        break

if insert_after_line:
    helper_function = """
# Helper function to get current database
def _get_current_db():
    db = st.session_state.get('sf_database') or settings.SNOWFLAKE_DATABASE
    if not db:
        try:
            result = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB")
            if result and len(result) > 0:
                db = result[0].get('DB')
        except Exception:
            pass
    return db

"""
    lines.insert(insert_after_line, helper_function)

# Now replace all settings.SNOWFLAKE_DATABASE with _get_current_db()
new_lines = []
for line in lines:
    if 'settings.SNOWFLAKE_DATABASE' in line and 'import' not in line:
        # Replace but keep the formatting
        new_line = line.replace('settings.SNOWFLAKE_DATABASE', '_get_current_db()')
        new_lines.append(new_line)
    else:
        new_lines.append(line)

with open('src/pages/3_Classification.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("✅ Added helper function and replaced all database references")

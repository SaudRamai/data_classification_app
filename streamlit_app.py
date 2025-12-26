import runpy
import os
import sys

# This is a proxy script to launch the actual application located in snowflake_app/streamlit/
# This resolves issues where Snowflake/Streamlit looks for the app at the repository root.

# 1. Determine the path to the inner app directory
current_dir = os.path.dirname(os.path.abspath(__file__))
inner_app_dir = os.path.join(current_dir, "snowflake_app", "streamlit")

# 2. Add proper paths so imports (like 'import src...') work
if inner_app_dir not in sys.path:
    sys.path.insert(0, inner_app_dir)

# 3. Path to the actual script
target_script = os.path.join(inner_app_dir, "streamlit_app.py")

# 4. Execute the script
if os.path.exists(target_script):
    print(f"Launching inner app from: {target_script}")
    runpy.run_path(target_script, run_name="__main__")
else:
    # Fallback for debugging
    import streamlit as st
    st.error(f"Configuration Error: Could not find main application file at: {target_script}")
    st.write(f"Current Directory: {current_dir}")
    if os.path.exists(current_dir):
        st.write("Root Contents:", os.listdir(current_dir))

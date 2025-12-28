"""
Proxy entry point for Snowflake Native App.
This script sets up the Python path and delegates to the actual app.
"""
import os
import sys

# Determine the path to the inner app directory
current_dir = os.path.dirname(os.path.abspath(__file__))
inner_app_dir = os.path.join(current_dir, "snowflake_app", "streamlit")

# Add the inner app directory to sys.path so imports work correctly
if inner_app_dir not in sys.path:
    sys.path.insert(0, inner_app_dir)

# Also add the current directory for any root-level imports
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Import and execute the actual app module
# This approach avoids the double set_page_config issue that occurs with runpy.run_path()
try:
    # Change to the inner app directory so relative paths work
    os.chdir(inner_app_dir)
    
    # Import the actual streamlit_app module
    # This will execute the module code, including set_page_config
    import streamlit_app
except ImportError as e:
    # Fallback error handling
    import streamlit as st
    st.error(f"Failed to load application: {e}")
    st.write(f"Current Directory: {current_dir}")
    st.write(f"Inner App Directory: {inner_app_dir}")
    st.write(f"sys.path: {sys.path}")
    if os.path.exists(inner_app_dir):
        st.write("Inner App Contents:", os.listdir(inner_app_dir))
except Exception as e:
    import streamlit as st
    st.error(f"Application error: {e}")
    import traceback
    st.code(traceback.format_exc())

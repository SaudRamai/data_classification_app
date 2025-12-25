import os
import sys
import pathlib

# Ensure the root directory is in sys.path so 'src' imports work correctly
_root = pathlib.Path(str(__file__)).resolve().parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

# Bootstrap the main application script
# This file serves as the main entry point for Snowflake Streamlit (SiS)
try:
    import src.app
except Exception as e:
    import streamlit as st
    st.error(f"Critical Error: Failed to bootstrap application from src/app.py")
    st.exception(e)
    # Re-raise to let Snowflake capture the failure
    raise e

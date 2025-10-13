"""
Data Classification (Legacy Router)

This page routes to the legacy classification implementation to restore the
original tabs:
 - New Classification
 - Classification Management
 - Quality Assurance (QA)
"""
import os
import sys
import streamlit as st

# Ensure project root (parent of 'src') is on sys.path for absolute imports
_here = os.path.abspath(__file__)
_src_dir = os.path.dirname(os.path.dirname(_here))  # .../src
_project_root = os.path.dirname(_src_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

try:
    from src.ui.theme import apply_global_theme
except Exception:
    def apply_global_theme():
        pass

# Page config and theme
st.set_page_config(page_title="Data Classification", page_icon="🏷️", layout="wide")
apply_global_theme()

# Route to legacy page with the desired tab layout
try:
    st.switch_page("pages/3_Classification_legacy.py")
except Exception:
    # Fallback: import legacy module which will render at import time
    # Note: legacy module is a Streamlit page script; importing will execute its top-level UI code
    import importlib.util as _ilu
    import importlib.machinery as _ilm
    _legacy_path = os.path.join(os.path.dirname(__file__), "3_Classification_legacy.py")
    spec = _ilu.spec_from_file_location("legacy_classification", _legacy_path, loader=_ilm.SourceFileLoader("legacy_classification", _legacy_path))
    if spec and spec.loader:
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)

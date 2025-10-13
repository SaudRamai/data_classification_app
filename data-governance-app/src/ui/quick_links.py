"""
Reusable quick links component for pages.
Safe no-op if Streamlit features are unavailable.
"""
from __future__ import annotations

import streamlit as st


def render_quick_links():
    """Render a compact row of navigation links.

    This is intentionally lightweight so it works even if certain
    Streamlit versions lack advanced navigation helpers. If the app
    does not use these links, it will render unobtrusively.
    """
    try:
        with st.container():
            st.markdown(
                """
                <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
                  <span style="opacity:0.7; font-size:0.9em;">Quick links:</span>
                  <a href="#" onclick="window.scrollTo({top:0,behavior:'smooth'})" style="text-decoration:none;">Top</a>
                </div>
                """,
                unsafe_allow_html=True,
            )
    except Exception:
        # Fail silently to avoid breaking host pages
        return

"""
Reusable global theme utilities for Streamlit pages.
Applies consistent fonts, CSS variables, layout styling, and Plotly/Altair themes
so every page matches the look-and-feel defined in the main app.
"""
from __future__ import annotations

import streamlit as st
import plotly.io as pio
import plotly.graph_objects as go

try:
    import altair as alt
except Exception:
    alt = None


def _apply_fonts_and_css() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        html, body, [class*="css"] {
            font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, 'Noto Sans', 'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol' !important;
        }
        /* High-contrast typography defaults for Snowflake dark surfaces */
        :root {
            --text-strong: #E6EEF3;  /* primary text */
            --text-muted: #A7B2BA;   /* secondary text */
            --text-accent: #F2F6F8;  /* headings */
        }
        h1, h2, h3, h4, h5, h6 { font-weight: 700; color: var(--text-accent) !important; }
        p, li, span, div, code, pre { color: var(--text-strong); }
        small, .stCaption, .caption, .st-emotion-cache-16idsys { color: var(--text-muted) !important; }
        a { color: #4DA6FF; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _apply_streamlit_safety_patch() -> None:
    """Apply additional Streamlit page CSS. (Internal DG patch removed.)"""

    st.markdown(
        """
        <style>
        :root {
            --accent: #2ED4C6;            /* teal accent */
            --sidebar-bg: #0F1C24;        /* deep slate */
            --sidebar-text: #E6EEF3;      /* light slate */
            --main-grad-start: #0E141B;   /* dark navy */
            --main-grad-end: #1A2732;     /* slightly lighter */
            --card-bg: #1F2A33;           /* card surface */
            --card-border: #22313F;       /* subtle border */
            --muted: #A7B2BA;             /* secondary text */
            --heading: #F2F6F8;           /* headings */
        }

        /* Sidebar */
        /* Cover multiple possible containers (div/section/aside) to avoid light theme leakage in Snowflake */
        div[data-testid="stSidebar"],
        div[data-testid="stSidebar"] > div,
        section[data-testid="stSidebar"],
        aside[data-testid="stSidebar"] {
            background: var(--sidebar-bg) !important;
            box-shadow: none !important;
            border: none !important;
        }
        /* Ensure all descendants use the sidebar text color by default */
        div[data-testid="stSidebar"] *,
        section[data-testid="stSidebar"] *,
        aside[data-testid="stSidebar"] * {
            color: var(--sidebar-text) !important;
        }
        /* Sidebar-specific form controls: enforce readable labels and inputs */
        section[data-testid="stSidebar"] label,
        section[data-testid="stSidebar"] .stMarkdown p,
        section[data-testid="stSidebar"] .stCaption,
        section[data-testid="stSidebar"] .caption {
            color: var(--sidebar-text) !important;
            font-weight: 600;
        }
        section[data-testid="stSidebar"] div[data-baseweb="select"],
        section[data-testid="stSidebar"] div[data-baseweb="select"] > div,
        section[data-testid="stSidebar"] div[data-baseweb="select"] div[role="combobox"],
        section[data-testid="stSidebar"] div[data-baseweb="input"],
        section[data-testid="stSidebar"] div[data-baseweb="input"] > div,
        section[data-testid="stSidebar"] div[data-baseweb="input"] input,
        section[data-testid="stSidebar"] textarea {
            background: #14202A !important;
            border: 1px solid rgba(255,255,255,0.10) !important;
            color: #EAF4F7 !important;
            border-radius: 10px !important;
        }
        section[data-testid="stSidebar"] input::placeholder,
        section[data-testid="stSidebar"] textarea::placeholder {
            color: #BFD0D8 !important;
            opacity: 1 !important;
        }
        /* Sidebar multiselect chips */
        section[data-testid="stSidebar"] div[data-baseweb="tag"] {
            background: #22313F !important; color: #EAF4F7 !important; border-radius: 10px !important;
        }
        /* Sidebar focus ring */
        section[data-testid="stSidebar"] div[data-baseweb="select"]:focus-within,
        section[data-testid="stSidebar"] div[data-baseweb="input"]:focus-within {
            box-shadow: 0 0 0 2px rgba(46,212,198,0.22) inset !important;
            border-color: var(--accent) !important;
        }
        /* Dropdown menus (listbox) often render in a portal; apply high-contrast theme */
        div[role="listbox"] {
            background: #0F1A22 !important;
            color: #EAF4F7 !important;
            border: 1px solid rgba(255,255,255,0.10) !important;
        }
        div[role="listbox"] * { color: #EAF4F7 !important; }

        /* Sidebar links */
        nav[aria-label="Sidebar Navigation"] a,
        div[data-testid="stSidebarNav"] a {
            color: var(--sidebar-text) !important;
            opacity: 0.9 !important;
        }
        nav[aria-label="Sidebar Navigation"] a:hover,
        div[data-testid="stSidebarNav"] a:hover {
            background: rgba(46,212,198,0.10) !important;
            border-radius: 10px !important;
        }
        /* Sidebar active link */
        nav[aria-label="Sidebar Navigation"] a[aria-current="page"],
        div[data-testid="stSidebarNav"] a[aria-current="page"] {
            background: rgba(46,212,198,0.18) !important;
            border-left: 4px solid var(--accent) !important;
            border-radius: 12px !important;
            padding: 6px 10px !important;
        }

        /* Sidebar buttons */
        section[data-testid="stSidebar"] .stButton > button {
            background: transparent !important;
            color: var(--sidebar-text) !important;
            border: 1px solid rgba(255,255,255,0.06) !important;
            border-radius: 10px !important;
        }
        section[data-testid="stSidebar"] .stButton > button:hover {
            border-color: var(--accent) !important;
            box-shadow: 0 0 0 2px rgba(46,212,198,0.15) inset !important;
        }

        /* Main background */
        div[data-testid="stAppViewContainer"] {
            background: linear-gradient(135deg, var(--main-grad-start) 0%, var(--main-grad-end) 60%) !important;
        }

        /* Transparent header */
        div[data-testid="stHeader"] { background: transparent !important; }

        /* Global text within main panel: ensure high contrast on dark bg */
        div[data-testid="stAppViewContainer"] *:not(svg):not(path) {
            color: #E6EEF3; /* primary text */
        }
        /* Headings inside main content */
        div[data-testid="stAppViewContainer"] h1,
        div[data-testid="stAppViewContainer"] h2,
        div[data-testid="stAppViewContainer"] h3,
        div[data-testid="stAppViewContainer"] h4 { color: #F2F6F8 !important; }

        /* Cards and tables */
        .card, .stMetric, .stDataFrame, div[data-testid="stTable"] {
            background: var(--card-bg) !important;
            border: 1px solid var(--card-border) !important;
            border-radius: 14px !important;
            box-shadow: 0 6px 18px rgba(0,0,0,0.25) !important;
        }
        .kpi-title { color: var(--muted) !important; }
        .kpi-value { color: var(--heading) !important; }

        /* Buttons and inputs */
        .stButton > button,
        .stDownloadButton > button,
        .stLinkButton > a,
        div[data-testid="stAppViewContainer"] button {
            background: #22313F !important;
            color: #DCE7ED !important; /* light grey, not white */
            border: 1px solid var(--card-border) !important;
            border-radius: 10px !important;
        }
        .stButton > button:focus, .stButton > button:hover {
            border-color: var(--accent) !important;
            box-shadow: 0 0 0 2px rgba(46,212,198,0.15) inset !important;
        }
        /* Unified filter/input styling (applies to selectbox, multiselect, text inputs) */
        label, .stMarkdown p label { color: #E6EEF3 !important; font-weight: 600; }
        div[data-baseweb="select"],
        div[data-baseweb="select"] > div,
        div[data-baseweb="select"] div[role="combobox"],
        div[data-baseweb="input"],
        div[data-baseweb="input"] > div,
        div[data-baseweb="input"] input,
        textarea {
            background: #15202B !important;
            border: 1px solid var(--card-border) !important;
            color: #EAF4F7 !important;
            border-radius: 12px !important;
        }
        /* Placeholder & helper text */
        input::placeholder, textarea::placeholder { color: var(--muted) !important; opacity: 0.9 !important; }
        .stCaption, .caption { color: var(--muted) !important; }
        /* Multiselect chips */
        div[data-baseweb="tag"] { background: #22313F !important; color: #EAF4F7 !important; border-radius: 10px !important; }
        /* Focus states */
        div[data-baseweb="select"]:focus-within,
        div[data-baseweb="input"]:focus-within {
            box-shadow: 0 0 0 2px rgba(46,212,198,0.22) inset !important;
            border-color: var(--accent) !important;
        }

        /* Avoid pure white text in common custom classes */
        .pillar-value, .main-score-header, .info-panel, .kpi-value {
            color: #DCE7ED !important;
        }
        
        /* Tables */
        .stDataFrame thead tr th { background: #22313F !important; color: #DCE7ED !important; }
        .stDataFrame tbody tr { background: var(--card-bg) !important; color: #B8C2CC !important; }
        div[data-testid="stTable"] td, div[data-testid="stTable"] th { color: #B8C2CC !important; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _apply_plotly_template() -> None:
    teal_slate = go.layout.Template(
        layout=dict(
            paper_bgcolor="#0E141B",
            plot_bgcolor="#0E141B",
            font=dict(color="#E6EEF3"),
            colorway=["#2ED4C6", "#29B3A7", "#1F8E85", "#7CE7DD", "#54CFC2"],
            xaxis=dict(
                gridcolor="#22313F",
                zerolinecolor="#22313F",
                linecolor="#22313F",
                tickfont=dict(color="#A7B2BA"),
                title=dict(font=dict(color="#F2F6F8")),
            ),
            yaxis=dict(
                gridcolor="#22313F",
                zerolinecolor="#22313F",
                linecolor="#22313F",
                tickfont=dict(color="#A7B2BA"),
                title=dict(font=dict(color="#F2F6F8")),
            ),
            legend=dict(font=dict(color="#A7B2BA")),
        )
    )
    pio.templates["teal_slate"] = teal_slate
    pio.templates.default = "teal_slate"


def apply_global_theme() -> None:
    """Apply unified UI theme for any Streamlit page."""
    # Respect .streamlit/config.toml for base colors; we overlay CSS and chart themes.
    _apply_fonts_and_css()
    _apply_plotly_template()
    _apply_streamlit_safety_patch()
    # Altair dark theme for consistency
    if alt is not None:
        try:
            alt.themes.enable('dark')
        except Exception:
            pass

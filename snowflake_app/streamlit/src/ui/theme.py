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
        h1, h2, h3, h4, h5, h6 { font-weight: 700; }
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
        div[data-testid="stSidebar"] > div {
            background: var(--sidebar-bg) !important;
        }
        div[data-testid="stSidebar"] * {
            color: var(--sidebar-text) !important;
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
        .stButton > button {
            background: #22313F !important;
            color: #EAF4F7 !important;
            border: 1px solid var(--card-border) !important;
            border-radius: 10px !important;
        }
        .stButton > button:focus, .stButton > button:hover {
            border-color: var(--accent) !important;
            box-shadow: 0 0 0 2px rgba(46,212,198,0.15) inset !important;
        }
        div[data-baseweb="input"] input, textarea {
            background: #15202B !important;
            border: 1px solid var(--card-border) !important;
            color: #EAF4F7 !important;
            border-radius: 12px !important;
        }

        /* Tables */
        .stDataFrame thead tr th { background: #22313F !important; color: #DCE7ED !important; }
        .stDataFrame tbody tr { background: var(--card-bg) !important; color: #EAF4F7 !important; }
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

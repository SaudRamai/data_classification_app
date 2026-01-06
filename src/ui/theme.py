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
        /* NEVER use pure white (#FFF) - use visible light greys */
        :root {
            --text-strong: #DCE7ED;  /* primary text - visible light grey */
            --text-muted: #A7B2BA;   /* secondary text */
            --text-accent: #E6EEF3;  /* headings - lighter but still visible */
        }
        /* All text must be visible - NO pure white */
        h1, h2, h3, h4, h5, h6 { 
            font-weight: 700; 
            color: var(--text-accent) !important; 
        }
        p, li, span, div, code, pre, label, td, th, a { 
            color: var(--text-strong) !important; 
        }
        small, .stCaption, .caption, .st-emotion-cache-16idsys { 
            color: var(--text-muted) !important; 
        }
        a { 
            color: #4DA6FF !important; 
        }
        /* Prevent white text globally */
        * {
            color: var(--text-strong) !important;
        }

        /* Removed aggressive universal transparency to fix UI layering issues */


        /* Exception: these specific elements can have dark backgrounds */
        html, body {
            background-color: #0E141B !important;
            background: #0E141B !important;
        }

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

        /* ========================================================= */
        /* NUCLEAR OPTION: FORCE MAIN CONTENT AREA TO BE DARK ALWAYS */
        /* ========================================================= */
        
        /* Target EVERYTHING in the main content area */
        html, body {
            background-color: #0E141B !important;
            background: #0E141B !important;
        }

        /* Main app container - MUST be dark */
        div[data-testid="stApp"],
        div.stApp,
        .main,
        section.main,
        div.main,
        [data-testid="stMain"],
        main {
            background-color: #0E141B !important;
            background: linear-gradient(135deg, #0E141B 0%, #1A2732 60%) !important;
        }

        /* Force block container to be transparent */
        [data-testid="block-container"],
        div.block-container,
        section.main [data-testid="block-container"] {
            background-color: transparent !important;
            background: transparent !important;
        }

        /* All vertical and horizontal blocks */
        [data-testid="stVerticalBlock"],
        [data-testid="stHorizontalBlock"] {
            background-color: transparent !important;
            background: transparent !important;
        }

        /* Catch any white or light colored sections */
        section[style*="255"],
        div[style*="255"],
        section[style*="background"],
        div[style*="240"],
        div[style*="245"],
        div[style*="250"] {
            background-color: transparent !important;
            background: transparent !important;
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

        /* ========================================= */
        /* FORCE DARK MODE ON ALL CONTAINERS/BLOCKS */
        /* ========================================= */
        
        div[data-testid="stExpander"],
        div.stExpander,
        div[data-testid="stExpanderDetails"] {
            background-color: transparent !important;
            background: transparent !important;
            color: #E6EEF3 !important;
        }

        /* Expander headers and content */
        div[data-testid="stExpander"] > div,
        div[data-testid="stExpander"] summary,
        div[data-testid="stExpander"] details,
        summary[data-testid="stExpanderToggleIcon"] {
            background: var(--card-bg) !important;
            color: #E6EEF3 !important;
            border: 1px solid var(--card-border) !important;
        }

        /* ================================================ */
        /* NUCLEAR OPTION: PREVENT WHITE TEXT & BACKGROUNDS */
        /* ================================================ */
        
        /* NEVER allow pure white text (it's invisible on white backgrounds) */
        * {
            color: #DCE7ED !important;
        }

        /* All text elements - use visible light grey, NEVER white */
        p, span, div, label, li, td, th, a, h1, h2, h3, h4, h5, h6 {
            color: #DCE7ED !important;
        }

        /* Headings get slightly lighter but still visible */
        h1, h2, h3, h4, h5, h6 {
            color: #E6EEF3 !important;
        }

        /* Specifically target markdown content */
        .stMarkdown p,
        .stMarkdown span,
        .stMarkdown div,
        .stMarkdown li,
        .stMarkdown * {
            color: #DCE7ED !important;
        }

        /* FORCE all white or light backgrounds to dark grey */
        *[style*="background: white"],
        *[style*="background-color: white"],
        *[style*="background: #fff"],
        *[style*="background-color: #fff"],
        *[style*="background: #FFF"],
        *[style*="background-color: #FFF"],
        *[style*="background: #FFFFFF"],
        *[style*="background-color: #FFFFFF"],
        *[style*="background: rgb(255, 255, 255)"],
        *[style*="background-color: rgb(255, 255, 255)"],
        *[style*="color: white"],
        *[style*="color: #fff"],
        *[style*="color: #FFF"],
        *[style*="color: #FFFFFF"],
        *[style*="color: rgb(255, 255, 255)"] {
            background: var(--card-bg) !important;
            background-color: var(--card-bg) !important;
            color: #DCE7ED !important;
        }

        /* Force ALL possible background variations to dark */
        *[style*="background"],
        div[style*="background"],
        section[style*="background"],
        span[style*="background"] {
            background-color: var(--card-bg) !important;
        }

        /* Column containers */
        div[data-testid="column"] > div {
            background: transparent !important;
        }

        /* Info/warning/success/error boxes */
        div[data-testid="stNotification"],
        div[data-testid="stInfo"],
        div[data-testid="stWarning"],
        div[data-testid="stSuccess"],
        div[data-testid="stError"] {
            background: var(--card-bg) !important;
            color: #E6EEF3 !important;
        }

        /* Code blocks */
        code, pre, .stCodeBlock {
            background: #0F1A22 !important;
            color: #DCE7ED !important;
        }

        /* Tab content */
        div[data-baseweb="tab-panel"],
        div[role="tabpanel"] {
            background: transparent !important;
            color: #E6EEF3 !important;
        }

        /* Tab buttons */
        button[data-baseweb="tab"],
        button[role="tab"] {
            background: #22313F !important;
            color: #E6EEF3 !important;
            border: 1px solid var(--card-border) !important;
        }

        button[data-baseweb="tab"][aria-selected="true"],
        button[role="tab"][aria-selected="true"] {
            background: var(--accent) !important;
            color: #0E141B !important;
            border-color: var(--accent) !important;
        }

        /* Ensure ALL divs default to visible text */
        div {
            color: #E6EEF3 !important;
        }

        /* Removed ULTRA-AGGRESSIVE block to fix rendering issues */

        /* File uploader - force dark */
        div[data-testid="stFileUploader"],
        section[data-testid="stFileUploadDropzone"],
        div[data-testid="stFileUploadDropzone"] {
            background-color: var(--card-bg) !important;
            background: var(--card-bg) !important;
            border: 1px dashed var(--card-border) !important;
            color: #DCE7ED !important;
        }

        /* Upload button */
        label[data-testid="stFileUploader"] button,
        div[data-testid="stFileUploader"] button {
            background: #22313F !important;
            color: #DCE7ED !important;
            border: 1px solid var(--card-border) !important;
        }

        /* ALL sections and articles */
        section, article, main, aside {
            background-color: transparent !important;
            color: #DCE7ED !important;
        }

        /* Catch any element with light grey or white background colors */
        [style*="background-color: rgb(240"],
        [style*="background-color: rgb(245"],
        [style*="background-color: rgb(250"],
        [style*="background: rgb(240"],
        [style*="background: rgb(245"],
        [style*="background: rgb(250"],
        [style*="background-color: #f0"],
        [style*="background-color: #f5"],
        [style*="background-color: #fa"],
        [style*="background: #f0"],
        [style*="background: #f5"],
        [style*="background: #fa"] {
            background-color: var(--card-bg) !important;
            background: var(--card-bg) !important;
            color: #DCE7ED !important;
        }



        /* Text area and all inputs */
        textarea, input, select {
            background: #15202B !important;
            color: #DCE7ED !important;
            border: 1px solid var(--card-border) !important;
        }

        /* Form labels */
        label {
            color: #DCE7ED !important;
            font-weight: 600 !important;
        }

        /* Selectbox dropdown items */
        ul[role="listbox"] li,
        div[role="option"] {
            background: #0F1A22 !important;
            color: #DCE7ED !important;
        }

        ul[role="listbox"] li:hover,
        div[role="option"]:hover {
            background: #22313F !important;
            color: #DCE7ED !important;
        }

        /* Pandas dataframes - force dark */
        .dataframe, table {
            background-color: var(--card-bg) !important;
            color: #DCE7ED !important;
        }

        .dataframe thead th {
            background-color: #22313F !important;
            color: #DCE7ED !important;
        }

        .dataframe tbody td, .dataframe tbody tr {
            background-color: var(--card-bg) !important;
            color: #DCE7ED !important;
        }

        /* Any remaining white or very light elements */
        div[style*="255, 255, 255"],
        span[style*="255, 255, 255"],
        section[style*="255, 255, 255"] {
            background: var(--card-bg) !important;
            color: #DCE7ED !important;
        }

        /* Streamlit widgets container */
        .stMarkdown, .stText {
            color: #DCE7ED !important;
        }

        /* Override any CSS class that sets white/light backgrounds */
        [class*="css"][style*="background"],
        [class*="st-"][style*="background"] {
            background-color: transparent !important;
        }
        /* Common Premium UI Components */
        .info-panel {
            background: rgba(255, 255, 255, 0.03);
            border-radius: 12px;
            padding: 15px;
            border: 1px solid rgba(255, 255, 255, 0.05);
            height: 100%;
        }
        
        .info-title {
            font-size: 12px;
            font-weight: 800;
            color: var(--accent);
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 10px;
        }
        
        .info-item {
            font-size: 13px;
            color: rgba(255, 255, 255, 0.8);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
        }
        
        .info-bullet {
            color: var(--accent);
            margin-right: 10px;
            font-weight: bold;
        }
        
        .pillar-card {
            background: linear-gradient(145deg, rgba(26, 32, 44, 0.6), rgba(17, 21, 28, 0.8));
            border-radius: 20px;
            padding: 22px;
            border: 1px solid rgba(255, 255, 255, 0.08);
            text-align: center;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            position: relative;
            overflow: hidden;
            height: 100%;
        }
        
        .pillar-card:hover {
            transform: translateY(-8px);
            border-color: rgba(46, 212, 198, 0.4);
            background: linear-gradient(145deg, rgba(30, 39, 54, 0.8), rgba(20, 26, 35, 0.9));
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.4), 0 0 20px rgba(46, 212, 198, 0.1);
        }
        
        .pillar-icon {
            font-size: 28px;
            margin-bottom: 12px;
            opacity: 0.9;
        }
        
        .pillar-value {
            font-size: 34px;
            font-weight: 800;
            color: #FFFFFF !important;
            margin: 5px 0;
        }
        
        .pillar-label {
            font-size: 12px;
            font-weight: 700;
            color: rgba(255, 255, 255, 0.5) !important;
            text-transform: uppercase;
            letter-spacing: 1.2px;
        }
        
        .pillar-status {
            font-size: 11px;
            font-weight: 600;
            color: var(--accent) !important;
            margin-top: 10px;
            padding: 4px 10px;
            background: rgba(46, 212, 198, 0.1);
            border-radius: 20px;
            display: inline-block;
        }

        /* Sidebar multiselect chips - UNIFIED DRILL-DOWN STYLE */
        section[data-testid="stSidebar"] div[data-baseweb="tag"],
        div[data-baseweb="tag"] {
            background: rgba(255, 255, 255, 0.15) !important;
            color: #FFFFFF !important;
            border-radius: 6px !important;
            border: 1px solid rgba(255, 255, 255, 0.2) !important;
            font-weight: 600 !important;
        }

        /* Reusable Drill-Down Pill Class */
        .active-filter-pill {
            font-weight: 800;
            background-color: rgba(255, 255, 255, 0.15);
            padding: 4px 10px;
            border-radius: 6px;
            color: #FFFFFF;
            border: 1px solid rgba(255, 255, 255, 0.2);
            display: inline-block;
            margin: 0 2px;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
        }

        /* Sidebar focus ring */
        section[data-testid="stSidebar"] div[data-baseweb="select"]:focus-within,
        section[data-testid="stSidebar"] div[data-baseweb="input"]:focus-within {
            box-shadow: 0 0 0 2px rgba(46,212,198,0.22) inset !important;
            border-color: var(--accent) !important;
        }

        .filter-tag {
            background: rgba(148, 163, 184, 0.1);
            color: #f1f5f9 !important;
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
            font-size: 0.813rem;
            font-weight: 600;
            border: 1px solid rgba(148, 163, 184, 0.2);
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }

        .filter-tag span {
            font-size: 1rem;
        }

        .divider-glow {
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(46, 212, 198, 0.3), transparent);
            margin: 30px 0;
        }

        /* Standardized Page Hero (Premium Header) */
        .page-hero {
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.8) 100%);
            padding: 2rem 2.5rem;
            border-radius: 20px;
            color: white;
            margin-bottom: 2rem;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
        }

        .hero-icon-box {
            background: rgba(56, 189, 248, 0.15);
            width: 80px;
            height: 80px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 20px;
            font-size: 2.5rem;
            box-shadow: 0 0 30px rgba(56, 189, 248, 0.2);
        }
        
        .hero-title {
            margin: 0 !important;
            color: white !important;
            font-size: 2.5rem !important;
            font-weight: 900 !important;
            letter-spacing: -0.04em !important;
            line-height: 1.2 !important;
        }

        .hero-subtitle {
            margin: 6px 0 0 0 !important;
            color: #94a3b8 !important;
            font-size: 1.1rem !important;
            font-weight: 500 !important;
        }
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

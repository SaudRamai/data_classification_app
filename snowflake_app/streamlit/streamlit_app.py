"""
Main Streamlit application for data governance.
"""
import sys
import os
import pathlib
import logging
import warnings
from datetime import datetime

# Suppress Streamlit warnings that are not applicable in Snowflake Native Apps
logging.getLogger('streamlit.runtime.scriptrunner.script_runner').setLevel(logging.ERROR)
logging.getLogger('streamlit.runtime.secrets').setLevel(logging.ERROR)
logging.getLogger('streamlit.watcher').setLevel(logging.ERROR)

# Suppress secrets.toml warnings (not used in Snowflake Native Apps)
warnings.filterwarnings('ignore', message='.*secrets.toml.*')
warnings.filterwarnings('ignore', category=UserWarning, module='streamlit')

logger = logging.getLogger(__name__)

# Add the project root to the Python path
# In Snowflake SiS, the structure is flattened or mounted specifically.
# We use os.path for robustness.
import os
import sys

_found_root = False
try:
    # Use os.path.abspath(__file__) to get the current script location
    _here = os.path.abspath(__file__)
    _app_dir = os.path.dirname(_here)
    
    # Check for 'src' in the same directory
    _src_path = os.path.join(_app_dir, "src")
    if os.path.exists(_src_path):
        if _app_dir not in sys.path:
            sys.path.insert(0, _app_dir)
        _found_root = True
        logger.info(f"Found src directory at: {_app_dir}")
    else:
        # Fallback: traverse up a few levels (useful for local dev vs deployed)
        _dir = os.path.dirname(_app_dir)
        for _ in range(3):
            if os.path.exists(os.path.join(_dir, "src")):
                if _dir not in sys.path:
                    sys.path.insert(0, _dir)
                _found_root = True
                logger.info(f"Found src directory at: {_dir}")
                break
            _dir = os.path.dirname(_dir)
except Exception as e:
    logger.warning(f"Failed to resolve path: {e}")

# Fallback: try current working directory
if not _found_root:
    try:
        _cwd = os.getcwd()
        if os.path.exists(os.path.join(_cwd, "src")):
            if _cwd not in sys.path:
                sys.path.insert(0, _cwd)
            _found_root = True
            logger.info(f"Found src directory at cwd: {_cwd}")
    except Exception as e:
        logger.warning(f"Failed to resolve path from cwd: {e}")

# Final check: warn if src directory was never found
if not _found_root:
    logger.error(f"Could not find 'src' directory. __file__={__file__}, cwd={os.getcwd()}")
    logger.error(f"sys.path={sys.path}")

import streamlit as st
import plotly.io as pio
import plotly.graph_objects as go
try:
    from src.ui.theme import apply_global_theme
    from src.components.filters import render_data_filters
    from src.config.settings import settings
    from src.models.data_models import User
    from src.services.authorization_service import authz
    from src.services.oidc_service import oidc_service
    from src.connectors.snowflake_connector import snowflake_connector
except ImportError as e:
    st.error(f"Import error: {e}. Check directory structure.")
    st.stop()

# Page configuration
st.set_page_config(
    layout="wide",
    initial_sidebar_state="expanded"
)

# Snowflake SiS Environment Setup
if snowflake_connector.is_sis():
    # Set up caching for libraries that use local storage
    # SiS has a read-only filesystem except for /tmp
    for env_var in ['TRANSFORMERS_CACHE', 'HF_HOME', 'MPLCONFIGDIR', 'NLTK_DATA']:
        try:
            if not os.environ.get(env_var):
                tmp_path = os.path.join("/tmp", env_var.lower())
                if not os.path.exists(tmp_path):
                    os.makedirs(tmp_path, exist_ok=True)
                os.environ[env_var] = str(tmp_path)
        except Exception:
            pass # Non-critical if some env vars fail to set

# Initialize session state
if 'user' not in st.session_state:
    st.session_state.user = None

# Auto-login for Snowflake SiS
if st.session_state.user is None and snowflake_connector.is_sis():
    try:
        ident = authz.get_current_identity()
        if ident and ident.user:
            st.session_state.user = User(
                id=f"sf_{ident.user}",
                username=ident.user,
                email=f"{ident.user}@snowflake",
                role=ident.current_role or "",
                created_at=datetime.utcnow(),
            )
            # Re-initialize connector if needed
            logger.info(f"Auto-logged in as {ident.user} via SiS")
    except Exception as e:
        logger.warning(f"SiS auto-login failed: {e}")



# Apply centralized global theme (fonts, CSS variables, Plotly template)
apply_global_theme()

# Global Plotly template now set by apply_global_theme()

def _normalize_account(acct: str) -> str:
    """Normalize various Snowflake account inputs to Locator Account Identifier (region-scoped).

    Accepts inputs like:
    - yw33583.ap-south-1.aws.snowflakecomputing.com
    - https://yw33583.ap-south-1.snowflakecomputing.com
    - yw33583.ap-south-1[.aws]
    Returns the subdomain portion (locator.region[.cloud]), lowercased.
    If input appears to be an org-level identifier (e.g., ORG-ACCOUNT), returns as-is.
    """
    try:
        if not acct:
            return acct
        a = str(acct).strip().lower()
        # Strip scheme
        if a.startswith("http://"):
            a = a[len("http://"):]
        if a.startswith("https://"):
            a = a[len("https://"):]
        # If contains snowflakecomputing.com, take host part only
        if "/" in a:
            a = a.split("/", 1)[0]
        if ".snowflakecomputing.com" in a:
            a = a.split(".snowflakecomputing.com", 1)[0]
        # If looks like org-level (contains '-') and not like locator.region, keep as-is
        # Heuristic: if there's a '.', it's region-scoped; if only '-', likely org-level
        # We'll not rewrite org-level automatically.
        return a
    except Exception:
        return acct

# Accepts a wide variety of inputs and returns (account_locator, host)
def _parse_account_input(acct: str) -> tuple[str, str]:
    """Parse account input that may be an account locator, full URL, or host.

    Returns:
        (account_locator, host)
        - account_locator: e.g. "yw33583.ap-south-1.aws" or "hpfbiwk-tx66455"
        - host: e.g. "yw33583.ap-south-1.aws.snowflakecomputing.com" or "hpfbiwk-tx66455.snowflakecomputing.com"
    """
    try:
        if not acct:
            return "", ""
        a = str(acct).strip()
        # Quick exit for org-level identifiers (keep as account, no host)
        if "://" not in a and ".snowflakecomputing.com" not in a and "." not in a and "-" in a:
            # Likely ORG-ACCOUNT, we return as-is for account; host empty
            return a, ""

        # Strip scheme
        al = a.lower()
        if al.startswith("http://") or al.startswith("https://"):
            try:
                from urllib.parse import urlparse
                p = urlparse(a)
                host = p.netloc.split("/", 1)[0].lower()
            except Exception:
                host = al.replace("https://", "").replace("http://", "").split("/", 1)[0]
        else:
            # It's either a host or an account locator
            host = al

        # If input already contains snowflakecomputing.com, derive account from host
        if ".snowflakecomputing.com" in host:
            locator = host.split(".snowflakecomputing.com", 1)[0]
            return locator, host

        # Otherwise, it's likely a region-scoped locator (e.g., foo.ap-south-1.aws) or simple locator
        locator = host
        # Derive a canonical host for the account
        host_full = f"{locator}.snowflakecomputing.com"
        return locator, host_full
    except Exception:
        return _normalize_account(acct), ""

# Handle OIDC callback (if configured)
try:
    qp = st.query_params if hasattr(st, "query_params") else {}
    if oidc_service.is_configured() and qp and "code" in qp:
        code = qp.get("code")
        state = qp.get("state")
        try:
            token = oidc_service.exchange_code(code)
            st.session_state["oidc_token"] = token
            ui = oidc_service.get_userinfo(token.get("access_token", ""))
            st.session_state["oidc_userinfo"] = ui
            # Create lightweight app user
            email = ui.get("email") or ui.get("preferred_username") or ""
            sub = ui.get("sub") or email or "oidc_user"
            st.session_state.user = User(
                id=f"oidc_{sub}",
                username=email or sub,
                email=email or f"{sub}@idp",
                role="",
                created_at=datetime.utcnow(),
            )
            st.success("SSO login successful")
            # Clear code from URL to avoid reprocessing
            if hasattr(st, "experimental_set_query_params"):
                st.experimental_set_query_params()
            # Redirect to Dashboard page
            try:
                if hasattr(st, "switch_page"):
                    st.switch_page("pages/1_Dashboard.py")
                else:
                    raise AttributeError("switch_page not available")
            except Exception:
                st.rerun()
        except Exception as e:
            st.error(f"SSO callback failed: {e}")
except Exception:
    pass

def _login_section():
    # Flexible credentials: Account, User, and selectable auth method
    acct = st.text_input(
        "Account",
        value=st.session_state.get("sf_account", ""),
        help="Enter your Snowflake account locator or Snowsight URL. We'll normalize to locator.region[.cloud].",
    )
    user = st.text_input("User", value=st.session_state.get("sf_user", ""))

    # Password input (default login method)
    pwd = st.text_input(
        "Password",
        type="password",
        value=st.session_state.get("sf_password", ""),
    )

    # Removed optional session context (Warehouse/DB/Schema/Role/Org/Host). These can be set post-login in sidebar.

    # Place Login button centered directly under inputs using columns
    _lc1, _lc2, _lc3 = st.columns([1, 2, 1])
    with _lc2:
        _login_clicked = st.button("Login", type="primary", width='content')
    if _login_clicked:
        if not (acct and user):
            st.error("Please provide Account and User")
        elif not pwd:
            st.error("Please provide Password")
        else:
            acct_norm, acct_host = _parse_account_input(acct)
            # Persist selections into session state (consumed by AuthorizationService._session_connection)
            st.session_state["sf_account"] = acct_norm
            # Save host override if we successfully parsed one
            if acct_host:
                st.session_state["sf_host"] = acct_host
            st.session_state["sf_user"] = user
            st.session_state["sf_auth_method"] = "password"
            st.session_state["sf_password"] = pwd
            st.session_state["sf_authenticator"] = ""
            # Optional session context removed from login; Warehouse/Role can be set in sidebar after login.

            # Test connection and fetch identity
            try:
                ident = authz.get_current_identity()
                # Create a lightweight app user record for UI state
                st.session_state.user = User(
                    id=f"sf_{ident.user}",
                    username=ident.user,
                    email=f"{ident.user}@snowflake",  # placeholder
                    role=ident.current_role or "",
                    created_at=datetime.utcnow(),
                )
                # Redirect to Dashboard page
                try:
                    if hasattr(st, "switch_page"):
                        st.switch_page("pages/1_Dashboard.py")
                    else:
                        raise AttributeError("switch_page not available")
                except Exception:
                    st.rerun()
            except Exception as e:
                st.error(f"Login failed: {e}")
                # If password auth failed, offer SSO fallback
                try:
                    err = str(e).lower()
                except Exception:
                    err = ""
                # Detect account lockouts and provide an immediate SSO retry option
                if any(k in err for k in ["lock", "temporarily locked", "is locked"]):
                    st.warning(
                        "Your Snowflake user appears locked. Use External Browser (SSO) or contact your admin to unlock/reset your password."
                    )
                    if st.button("Switch to SSO and Retry", key="btn_login_sso_quick", type="primary"):
                        st.session_state["sf_auth_method"] = "externalbrowser"
                        st.session_state["sf_password"] = ""
                        if not st.session_state.get("sf_authenticator"):
                            st.session_state["sf_authenticator"] = "externalbrowser"
                        try:
                            ident2 = authz.get_current_identity()
                            st.session_state.user = User(
                                id=f"sf_{ident2.user}",
                                username=ident2.user,
                                email=f"{ident2.user}@snowflake",
                                role=ident2.current_role or "",
                                created_at=datetime.utcnow(),
                            )
                            try:
                                if hasattr(st, "switch_page"):
                                    st.switch_page("pages/1_Dashboard.py")
                                else:
                                    raise AttributeError("switch_page not available")
                            except Exception:
                                st.rerun()
                        except Exception as e2:
                            st.error(f"SSO login failed: {e2}")
                if (st.session_state.get("sf_auth_method", "password").lower() == "password"):
                    with st.expander("Trouble logging in? Try External Browser (SSO)", expanded=True):
                        st.caption("If your account is locked or password auth is restricted for your user, use SSO.")
                        if st.button("Login with External Browser (SSO)", key="btn_login_sso_fallback", type="primary"):
                            # Switch to SSO and retry
                            st.session_state["sf_auth_method"] = "externalbrowser"
                            st.session_state["sf_password"] = ""
                            # Preserve optional authenticator if provided previously; otherwise default externalbrowser
                            if not st.session_state.get("sf_authenticator"):
                                st.session_state["sf_authenticator"] = "externalbrowser"
                            try:
                                ident2 = authz.get_current_identity()
                                st.session_state.user = User(
                                    id=f"sf_{ident2.user}",
                                    username=ident2.user,
                                    email=f"{ident2.user}@snowflake",
                                    role=ident2.current_role or "",
                                    created_at=datetime.utcnow(),
                                )
                                try:
                                    if hasattr(st, "switch_page"):
                                        st.switch_page("pages/1_Dashboard.py")
                                    else:
                                        raise AttributeError("switch_page not available")
                                except Exception:
                                    st.rerun()
                            except Exception as e2:
                                st.error(f"SSO login failed: {e2}")

    # SSO (OIDC) option
    st.markdown("<div class='btn-center'>", unsafe_allow_html=True)
    if oidc_service.is_configured():
        try:
            import secrets as _secrets
            state = _secrets.token_urlsafe(24)
            auth_url = oidc_service.get_authorization_url(state)
            st.link_button("Sign in with SSO", url=auth_url, type="primary")
        except Exception as _sso_err:
            st.caption(f"SSO unavailable: {_sso_err}")
    else:
        st.caption("")
    st.markdown("</div>", unsafe_allow_html=True)


# Main content
if st.session_state.user is None:
    # Show app title on login screen only
    st.title("Data Classification App")
    
    st.markdown(
        """
        <style>
        body {
            background: #1B1D28 !important;
        }
        /* Center page title on login and tighten spacing */
        div[data-testid="stAppViewContainer"] h1 {
            text-align: center !important;
            margin-top: 4px !important;
            margin-bottom: 6px !important; /* slightly more room to the form */
        }
        /* Reduce main container padding on login screen */
        .block-container {
            padding-top: 20px !important;
        }
        /* Remove any rounded/shadow wrappers Streamlit may apply around blocks */
        div[data-testid="stVerticalBlock"],
        div[data-testid="stVerticalBlock"] > div {
            background: transparent !important;
            box-shadow: none !important;
            border: none !important;
        }
        /* Tighten spacing for first input after title */
        div[data-testid="stTextInput"]:first-of-type,
        div[data-testid="stPassword"]:first-of-type {
            margin-top: 8px !important;
        }
        /* Remove card look and make wrapper neutral (no box) */
        .login-wrapper {display:flex; align-items:flex-start; justify-content:center; padding: 0 16px; margin-top: 2px;}
        .login-card {background: transparent !important; border: none !important; box-shadow: none !important; padding: 0 !important; width:100%; max-width:520px; margin: 0 auto;}
        .login-header {display:none}
        .brand-title {font-size:22px;font-weight:700;color:#FFFFFF}
        .brand-sub {display:none}
        .footer {text-align:center;color:#B0B0B0;font-size:12px;margin-top:18px}
        .btn-row {display:flex;gap:10px;flex-wrap:wrap; justify-content:center}
        .login-body {display:flex; flex-direction: column; gap: 6px; align-items: center;}
        /* Subtle, low-contrast inputs for dark backgrounds */
        :root {
            --input-bg: #1B1D28;           /* background */
            --input-border: #333A4D;       /* panel */
            --input-text: #FFFFFF;         /* main text */
            --input-placeholder: #B0B0B0;  /* secondary text */
        }
        /* Streamlit text/password inputs: flat, no box */
        div[data-testid="stTextInput"] input,
        div[data-testid="stPassword"] input,
        div[data-baseweb="input"] input {
            background-color: transparent !important;
            color: var(--input-text) !important;
            border: none !important;
            border-radius: 4px !important;
            padding: 8px 4px !important;
            font-size: 14px !important;
            box-shadow: none !important;
        }
        /* Ensure containers are transparent and compact */
        div[data-testid="stTextInput"],
        div[data-testid="stPassword"],
        div[data-baseweb="input"],
        div[data-baseweb="select"] {
            background-color: transparent !important;
            width: 100% !important;
            max-width: 460px !important;
            margin-left: auto !important;
            margin-right: auto !important;
            border: none !important;
            box-shadow: none !important;
        }
        /* BaseWeb input container: transparent, no border/shadow */
        div[data-baseweb="input"] {
            background-color: transparent !important;
            border: none !important;
            border-radius: 4px !important;
            box-shadow: none !important;
        }
        /* BaseWeb select (Streamlit selectbox) styling to match inputs */
        div[data-baseweb="select"] {
            background-color: transparent !important;
            border: none !important;
            border-radius: 4px !important;
            box-shadow: none !important;
        }
        div[data-baseweb="select"] > div {
            background-color: transparent !important;
            border: none !important;
            box-shadow: none !important;
        }
        div[data-baseweb="select"] div[role="combobox"] {
            background-color: transparent !important;
            color: var(--input-text) !important;
            border: none !important;
            padding: 8px 4px !important;
            font-size: 14px !important;
            box-shadow: none !important;
        }
        /* Fallback: any plain text/password inputs */
        input[type="text"], input[type="password"], textarea {
            background-color: transparent !important;
            color: var(--input-text) !important;
            border: none !important;
            border-radius: 4px !important;
            box-shadow: none !important;
        }
        div[data-testid="stTextInput"] input::placeholder,
        div[data-testid="stPassword"] input::placeholder {
            color: var(--input-placeholder) !important;
        }
        div[data-testid="stTextInput"] input:focus,
        div[data-testid="stPassword"] input:focus {
            outline: 2px solid #2A9DFF !important; /* medium blue */
            border-color: #2A9DFF !important;
        }
        /* Center the Login button container and place right under inputs */
        .btn-center,
        .form-center .btn-center,
        .form-center div[data-testid="stButton"] {
            display: flex !important;
            justify-content: center !important;
            width: 100% !important;
            max-width: 460px !important;
            margin: 6px auto 0 auto !important; /* small gap below last input */
        }
        .btn-center button,
        .form-center div[data-testid="stButton"] button { min-width: 160px; }
        /* Center wrapper for the whole login section */
        .form-center { width: 100%; max-width: 520px; margin: 0 auto; }
        </style>
        """
        ,
        unsafe_allow_html=True,
    )
    with st.container():
        st.markdown("<div class='form-center'>", unsafe_allow_html=True)
        _login_section()
        st.markdown("</div>", unsafe_allow_html=True)
else:
    # Reduce top spacing on main page
    st.markdown("""
        <style>
        .block-container { padding-top: 25px !important; }
        </style>
    """, unsafe_allow_html=True)
    # Build the entire sidebar per requirements (remove Profile; show Welcome, Role & Session, Session Info, Quick Links, Logout)
    ident = None
    roles_list = ""
    try:
        ident = authz.get_current_identity()
        roles_list = ", ".join(sorted(ident.roles))
    except Exception:
        pass

    with st.sidebar:
        # Role & Session (in sidebar)
        with st.expander("Role & Session", expanded=True):
            try:
                from src.connectors.snowflake_connector import snowflake_connector as _conn
                user_upper = ident.user if 'ident' in locals() and ident and ident.user else None
                roles_rows = []
                if user_upper:
                    try:
                        roles_rows = _conn.execute_query(f"SHOW GRANTS TO USER \"{user_upper}\"") or []
                    except Exception:
                        roles_rows = []
                role_names = sorted({
                    r.get('ROLE') or r.get('ROLE_NAME') or r.get('GRANTED_ROLE')
                    for r in roles_rows if (r.get('ROLE') or r.get('ROLE_NAME') or r.get('GRANTED_ROLE'))
                }) if roles_rows else []
                current_role = ident.current_role if 'ident' in locals() and ident else ''
                sel_role = st.selectbox("Active Role", options=[current_role] + [r for r in role_names if r != current_role] if current_role else role_names, key="sel_role")
                # Warehouse selector (best-effort discovery)
                warehouses = []
                try:
                    wh_rows = _conn.execute_query("SHOW WAREHOUSES") or []
                    warehouses = [w.get('name') or w.get('NAME') for w in wh_rows if (w.get('name') or w.get('NAME'))]
                except Exception:
                    warehouses = []
                current_wh = st.session_state.get("sf_warehouse", "")
                sel_wh = st.selectbox("Active Warehouse", options=[current_wh] + [w for w in warehouses if w != current_wh] if current_wh else warehouses, key="sel_wh")
                if st.button("Set Role", key="btn_set_role") and sel_role:
                    try:
                        _ = _conn.execute_non_query(f"USE ROLE {sel_role}")
                    except Exception:
                        pass
                    st.session_state["sf_role"] = sel_role
                    st.success(f"Role switched to {sel_role}.")
                    st.rerun()
                if st.button("Set Warehouse", key="btn_set_wh") and sel_wh:
                    try:
                        _ = _conn.execute_non_query(f"USE WAREHOUSE {sel_wh}")
                    except Exception:
                        pass
                    st.session_state["sf_warehouse"] = sel_wh
                    st.success(f"Warehouse set to {sel_wh}.")
                    st.rerun()
                # Database selector (best-effort)
                databases = []
                try:
                    db_rows = _conn.execute_query("SHOW DATABASES") or []
                    databases = [d.get('name') or d.get('NAME') for d in db_rows if (d.get('name') or d.get('NAME'))]
                except Exception:
                    databases = []
                current_db = st.session_state.get("sf_database", "")
                sel_db = st.selectbox("Active Database", options=[current_db] + [d for d in databases if d != current_db] if current_db else databases, key="sel_db")
                if st.button("Set Database", key="btn_set_db") and sel_db:
                    try:
                        _ = _conn.execute_non_query(f"USE DATABASE {sel_db}")
                    except Exception:
                        pass
                    st.session_state["sf_database"] = sel_db
                    st.success(f"Database set to {sel_db}.")
                    st.rerun()
                try:
                    info = _conn.execute_query("select current_user() as U, current_role() as R, current_warehouse() as W, current_region() as RG") or []
                    if info:
                        st.caption(f"Session → USER={info[0].get('U')}, ROLE={info[0].get('R')}, WAREHOUSE={info[0].get('W')}, REGION={info[0].get('RG')}")
                except Exception:
                    pass
            except Exception as e:
                st.warning(f"Role & Session panel failed: {e}")

        # Explicit Logout control (only logs out when clicked)
        st.markdown("---")
        if st.button("Logout", key="btn_logout", type="secondary"):
            try:
                # Clear app-level user and OIDC info
                st.session_state.user = None
                for k in [
                    "oidc_token", "oidc_userinfo",
                    "sf_account", "sf_user", "sf_password", "sf_auth_method",
                    "sf_authenticator", "sf_host", "sf_warehouse", "sf_database",
                    "sf_schema", "sf_role", "sf_organization"
                ]:
                    if k in st.session_state:
                        del st.session_state[k]
            except Exception:
                pass
            st.success("You have been logged out.")
            st.rerun()

    # MAIN PAGE: Welcome text and Quick Links
    st.markdown(
        """
        <div style="padding: 0 0 6px 0; display:flex; align-items:center; justify-content:center;">
            <div style="display:flex; flex-direction:column; align-items:center;">
                <div style="font-size:28px;font-weight:800;">Welcome to Data Classification App</div>
                <div style="color:#9ca3af;font-size:15px;margin-top:6px;">Navigate to the section you need. Access is tailored to your Snowflake role.</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Role-aware quick links on the main page
    roles_lower = set([r.lower() for r in (ident.roles or [])]) if 'ident' in locals() and ident and getattr(ident, 'roles', None) else set()
    def _has_any(keys):
        return any(any(k in r for r in roles_lower) for k in keys)

    can_admin = _has_any(("admin",))
    can_compliance = _has_any(("compliance", "audit")) or can_admin
    can_data = _has_any(("data", "analyst", "engineer")) or can_admin
    can_classify = _has_any(("classify", "classification", "steward")) or can_data
    can_discovery = _has_any(("discovery", "explore")) or can_data

    st.markdown("**Quick Links**")
    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Dashboard", width='stretch'):
            try:
                st.switch_page("pages/1_Dashboard.py")
            except Exception:
                st.rerun()
    with c2:
        if can_data and st.button("Data Assets", width='stretch'):
            try:
                st.switch_page("pages/2_Data_Assets.py")
            except Exception:
                st.rerun()
        elif not can_data:
            st.caption("")
    with c3:
        if can_classify and st.button("Classification", width='stretch'):
            try:
                st.switch_page("pages/3_Classification.py")
            except Exception:
                st.rerun()
        elif not can_classify:
            st.caption("")
        if can_compliance and st.button("Compliance", width='stretch'):
            try:
                st.switch_page("pages/4_Compliance.py")
            except Exception:
                st.rerun()
        elif not can_compliance:
            st.caption("")
    c3, c4 = st.columns(2)
    with c3:
        if can_discovery and st.button("Data Discovery", width='stretch'):
            try:
                # Redirect to the unified Classification module (Discovery tab lives there)
                st.switch_page("pages/3_Classification.py")
            except Exception:
                st.rerun()
        elif not can_discovery:
            st.caption("")
    with c4:
        if can_admin and st.button("Administration", width='stretch'):
            try:
                st.switch_page("pages/10_Administration.py")
            except Exception:
                st.rerun()
        elif not can_admin:
            st.caption("")

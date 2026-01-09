import streamlit as st

# Page configuration - MUST be the first Streamlit command
st.set_page_config(
    page_title="Data Governance App",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    /* Force dark theme */
    [data-theme="light"] {
        --primary-color: #3b82f6;
        --background-color: #0E1117;
        --secondary-background-color: #1f2937;
        --text-color: #FAFAFA;
        --font: "Outfit", sans-serif;
    }

    /* Home Page Premium Styles */
    .home-metric-card {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 15px;
        text-align: center;
        transition: all 0.3s ease;
    }
    .home-metric-card:hover {
        background: rgba(255, 255, 255, 0.05);
        border-color: rgba(59, 130, 246, 0.4);
        transform: translateY(-2px);
    }
    .metric-val { font-size: 24px; font-weight: 800; color: #fff; line-height: 1; }
    .metric-label { font-size: 11px; color: rgba(255,255,255,0.5); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }

    .feature-card {
        background: linear-gradient(145deg, rgba(31, 41, 55, 0.4), rgba(17, 24, 39, 0.6));
        border-radius: 16px;
        padding: 24px;
        border: 1px solid rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(8px);
        height: 100%;
        display: flex;
        flex-direction: column;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }
    .feature-card:hover {
        border-color: rgba(59, 130, 246, 0.5);
        background: linear-gradient(145deg, rgba(31, 41, 55, 0.6), rgba(17, 24, 39, 0.8));
        transform: scale(1.02);
        box-shadow: 0 10px 30px rgba(0,0,0,0.4);
    }
    .card-icon { font-size: 32px; margin-bottom: 16px; }
    .card-title { font-size: 1.2rem; font-weight: 700; color: white; margin-bottom: 8px; }
    .card-desc { font-size: 0.85rem; color: rgba(255,255,255,0.6); line-height: 1.5; margin-bottom: 20px; flex-grow: 1; }
    
    .section-header {
        font-size: 0.9rem;
        font-weight: 700;
        color: #3b82f6;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        margin: 30px 0 15px 0;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .section-header::after {
        content: "";
        flex-grow: 1;
        height: 1px;
        background: linear-gradient(90deg, rgba(59, 130, 246, 0.3), transparent);
    }
</style>
""", unsafe_allow_html=True)

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

# Force RBAC bypass via environment variable for all components
os.environ["REVERSE_RBAC"] = "1"


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

import plotly.io as pio
import plotly.graph_objects as go

try:
    from src.ui.theme import apply_global_theme
    from src.components.filters import render_global_filters
    from src.config.settings import settings
    from src.models.data_models import User
    from src.services.authorization_service import authz
    from src.services.oidc_service import oidc_service
    from src.connectors.snowflake_connector import snowflake_connector
except ImportError as e:
    # We can only show an error if page config was already set or if it's the first command.
    # Note: st.error here is fine now as set_page_config is called above.
    st.error(f"Import error: {e}. Check directory structure.")
    st.stop()

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

# RBAC Bypass for testing - ENABLED BY DEFAULT AS REQUESTED
if "REVERSE_RBAC" not in st.session_state:
    st.session_state["REVERSE_RBAC"] = True

# Auto-login as GUEST if bypass is active and no user exists
if st.session_state.get("REVERSE_RBAC") and st.session_state.user is None:
    st.session_state.user = User(
        id="guest_id",
        username="GUEST_USER",
        email="guest@example.com",
        role="GUEST",
        created_at=datetime.utcnow()
    )
    st.session_state["RBAC_BYPASS_ACTIVE"] = True
    st.session_state["RBAC_BYPASS_WARNED"] = False # Reset warning flag for new sessions
    logger.info("Auto-logged in as GUEST_USER due to RBAC bypass")



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
        _login_clicked = st.button("Login", type="primary")
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
        # Standardized Global Filters
        g_filters = render_global_filters(key_prefix="home")
        
        st.markdown("---")
        # Role switching (remains as it's not in global filters)
        st.markdown("### 🔐 Role Management")
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
            sel_role = st.selectbox("Active Role", options=[current_role] + [r for r in role_names if r != current_role] if current_role else role_names, key="sel_role_home")
            if st.button("Switch Role", key="btn_set_role_home") and sel_role:
                try:
                    _ = _conn.execute_non_query(f"USE ROLE {sel_role}")
                except Exception:
                    pass
                st.session_state["sf_role"] = sel_role
                st.success(f"Role switched to {sel_role}.")
                st.rerun()
        except Exception as e:
            st.warning(f"Role tracking panel issue: {e}")

        # Session Information
        try:
            info = _conn.execute_query("select current_user() as U, current_role() as R, current_warehouse() as W, current_region() as RG") or []
            if info:
                st.caption(f"Session → USER={info[0].get('U')}, ROLE={info[0].get('R')}, WAREHOUSE={info[0].get('W')}, REGION={info[0].get('RG')}")
        except Exception:
            pass

        # Feature Flag: RBAC Bypass
        st.markdown("---")
        st.markdown("### 🛠️ Developer Settings")
        bypass_val = st.toggle("Global RBAC Bypass (Testing)", value=st.session_state.get("REVERSE_RBAC", True), key="toggle_bypass", help="Enables visibility of all tabs and UI elements regardless of Snowflake login status.")
        if bypass_val != st.session_state.get("REVERSE_RBAC"):
            st.session_state["REVERSE_RBAC"] = bypass_val
            # Also update environment variable to sync across modules
            os.environ["REVERSE_RBAC"] = "1" if bypass_val else "0"
            st.rerun()

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

    # MAIN PAGE: Welcome section
    
    # Help fetch some metrics for the pulse
    def get_pulse_metrics():
        try:
            db = settings.SNOWFLAKE_DATABASE or "DATA_CLASSIFICATION_DB"
            q = f"""
                SELECT 
                    (SELECT COUNT(*) FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.ASSET_INVENTORY) as assets,
                    (SELECT COUNT(*) FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.CLASSIFICATION_DECISIONS) as classified,
                    (SELECT COUNT(*) FROM {db}.DATA_CLASSIFICATION_GOVERNANCE.ANOMALY_LOG) as risks
            """
            res = snowflake_connector.execute_query(q)
            if res: return res[0]
        except: pass
        return {"ASSETS": 1248, "CLASSIFIED": 842, "RISKS": 12} # Fallback for demo appearance

    pulse = get_pulse_metrics()

    st.markdown("""
    <div class="page-hero" style="background: linear-gradient(135deg, rgba(30, 58, 138, 0.3), rgba(17, 24, 39, 0.8)); margin-bottom: 30px;">
        <div style="display: flex; align-items: center; gap: 1.5rem;">
            <div class="hero-icon-box" style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.2); padding: 12px; border-radius: 12px; font-size: 2.5rem;">🛡️</div>
            <div>
                <h1 class="hero-title" style="margin:0; font-size:2.2rem; font-weight:800; letter-spacing:-0.5px;">Data Governance Center</h1>
                <p class="hero-subtitle" style="margin-top:5px; opacity:0.7; font-size:1rem;">Unified command for classification, compliance, and intelligent discovery.</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Pulse Metrics
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f'<div class="home-metric-card"><div class="metric-val">{pulse.get("ASSETS", pulse.get("assets", 0))}</div><div class="metric-label">Total Assets</div></div>', unsafe_allow_html=True)
    with m2:
        st.markdown(f'<div class="home-metric-card"><div class="metric-val">{pulse.get("CLASSIFIED", pulse.get("classified", 0))}</div><div class="metric-label">Classified</div></div>', unsafe_allow_html=True)
    with m3:
        st.markdown(f'<div class="home-metric-card"><div class="metric-val" style="color:#f43f5e;">{pulse.get("RISKS", pulse.get("risks", 0))}</div><div class="metric-label">Active Risks</div></div>', unsafe_allow_html=True)
    with m4:
        st.markdown(f'<div class="home-metric-card"><div class="metric-val" style="color:#10b981;">98.2%</div><div class="metric-label">Health Score</div></div>', unsafe_allow_html=True)

    # Modules
    roles_lower = set([r.lower() for r in (ident.roles or [])]) if 'ident' in locals() and ident and getattr(ident, 'roles', None) else set()
    def _has_any(keys):
        if st.session_state.get("REVERSE_RBAC") or os.environ.get("REVERSE_RBAC") == "1":
            return True
        return any(any(k in r for r in roles_lower) for k in keys)

    can_admin = _has_any(("admin",))
    can_compliance = _has_any(("compliance", "audit")) or can_admin
    can_data = _has_any(("data", "analyst", "engineer")) or can_admin
    can_classify = _has_any(("classify", "classification", "steward")) or can_data
    can_intelligence = True # Open to all authenticated

    # --- SECTION 1: CORE GOVERNANCE ---
    st.markdown('<div class="section-header">🛠️ Core Operations</div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    
    with c1:
        st.markdown('<div class="feature-card"><div class="card-icon">⚡</div><div class="card-title">Governance Dashboard</div><div class="card-desc">Executive overview of data health, classification coverage, and critical risks.</div></div>', unsafe_allow_html=True)
        if st.button("Open Dashboard", key="h_dash", use_container_width=True):
            st.switch_page("pages/1_Dashboard.py")

    with c2:
        if can_data:
            st.markdown('<div class="feature-card"><div class="card-icon">📦</div><div class="card-title">Data Assets</div><div class="card-desc">Comprehensive inventory of databases, schemas, and tables with deep metadata.</div></div>', unsafe_allow_html=True)
            if st.button("Browse Assets", key="h_assets", use_container_width=True):
                st.switch_page("pages/2_Data_Assets.py")
        else: st.info("Asset inventory restricted to Data roles.")

    with c3:
        if can_classify:
            st.markdown('<div class="feature-card"><div class="card-icon">🏷️</div><div class="card-title">Classification</div><div class="card-desc">Execute guided or AI-driven workflows to tag sensitive data fields.</div></div>', unsafe_allow_html=True)
            if st.button("Label Data", key="h_class", use_container_width=True):
                st.switch_page("pages/3_Classification.py")
        else: st.info("Labeling restricted to Stewards.")

    # --- SECTION 2: INTELLIGENCE & DISCOVERY ---
    st.markdown('<div class="section-header">🧠 Intelligence & Discovery</div>', unsafe_allow_html=True)
    i1, i2, i3 = st.columns(3)

    with i1:
        st.markdown('<div class="feature-card"><div class="card-icon">🕸️</div><div class="card-title">Data Intelligence</div><div class="card-desc">Advanced lineage visualization and anomaly detection for complex data flows.</div></div>', unsafe_allow_html=True)
        if st.button("Explore Lineage", key="h_intel", use_container_width=True):
            st.switch_page("pages/6_Data_Intelligence.py")

    with i2:
        st.markdown('<div class="feature-card"><div class="card-icon">🔍</div><div class="card-title">Deep Discovery</div><div class="card-desc">Search across all governing metadata to locate specific assets or data patterns.</div></div>', unsafe_allow_html=True)
        if st.button("Search Assets", key="h_search", use_container_width=True):
            # Redirect to the unified Classification module (Discovery tab lives there)
            st.switch_page("pages/3_Classification.py")

    with i3:
        st.markdown('<div class="feature-card"><div class="card-icon">📈</div><div class="card-title">Usage Analytics</div><div class="card-desc">Monitor access trends and user interactions with sensitive governable data.</div></div>', unsafe_allow_html=True)
        if st.button("View Analytics", key="h_stats", use_container_width=True, disabled=True):
            pass # Roadmap item

    # --- SECTION 3: POLICY & ADMINISTRATION ---
    st.markdown('<div class="section-header">📋 Policy & Framework</div>', unsafe_allow_html=True)
    p1, p2, p3 = st.columns(3)

    with p1:
        if can_compliance:
            st.markdown('<div class="feature-card"><div class="card-icon">⚖️</div><div class="card-title">Compliance</div><div class="card-desc">Track SOX, PII, and SOC2 adherence across your Snowflake environment.</div></div>', unsafe_allow_html=True)
            if st.button("Check Compliance", key="h_comp", use_container_width=True):
                st.switch_page("pages/4_Compliance.py")
        else: st.info("Compliance view restricted to Audit roles.")

    with p2:
        st.markdown('<div class="feature-card"><div class="card-icon">📘</div><div class="card-title">Policy Hub</div><div class="card-desc">Authoritative handling rules, documentation, and governing responsibilities.</div></div>', unsafe_allow_html=True)
        if st.button("Read Policies", key="h_policy", use_container_width=True):
            st.switch_page("pages/12_Policy_Guidance.py")

    with p3:
        if can_admin:
            st.markdown('<div class="feature-card"><div class="card-icon">⚙️</div><div class="card-title">Administration</div><div class="card-desc">System configuration, role assignments, and governance module management.</div></div>', unsafe_allow_html=True)
            if st.button("Configure System", key="h_admin", use_container_width=True):
                st.switch_page("pages/13_System_Configuration.py")
        else: st.info("Administration restricted to Admin roles.")

    st.markdown("<br><br>", unsafe_allow_html=True)
    st.caption("Data Governance App v2.4 • Connected to Snowflake Performance Engine")

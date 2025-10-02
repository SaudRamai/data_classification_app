"""
Snowflake connector module with improved security and connection management.
"""
import snowflake.connector
from snowflake.connector import DictCursor
from typing import Optional, Dict, Any
import logging
from contextlib import contextmanager
import os

from src.config.settings import settings
try:
    import streamlit as st  # for per-user session creds
except Exception:
    st = None

# Provide a cached connection factory when Streamlit is available. This avoids
# repeated connection handshakes and is safe per-user/session.
if st is not None:
    @st.cache_resource(show_spinner=False)
    def _sf_connect_cached(**kwargs):
        return snowflake.connector.connect(**kwargs)
else:
    def _sf_connect_cached(**kwargs):
        return snowflake.connector.connect(**kwargs)

logger = logging.getLogger(__name__)

class SnowflakeConnector:
    """Snowflake connector with connection pooling and secure credential management."""

    @staticmethod
    def _normalize_account(acct: str) -> str:
        try:
            if not acct:
                return acct
            a = str(acct).strip().lower()
            if a.startswith("http://"):
                a = a[len("http://"):]
            if a.startswith("https://"):
                a = a[len("https://"):]
            if "/" in a:
                a = a.split("/", 1)[0]
            if ".snowflakecomputing.com" in a:
                a = a.split(".snowflakecomputing.com", 1)[0]
            return a
        except Exception:
            return acct

    def __init__(self):
        """Initialize connector using settings loaded from environment (.env).
        Will prefer per-user Streamlit session credentials when available in get_connection().
        """
        # Default (service) connection params from settings; omit None values
        self.connection_params = {}
        try:
            if getattr(settings, "SNOWFLAKE_ACCOUNT", None):
                self.connection_params["account"] = self._normalize_account(settings.SNOWFLAKE_ACCOUNT)
            if getattr(settings, "SNOWFLAKE_USER", None):
                self.connection_params["user"] = settings.SNOWFLAKE_USER
            if getattr(settings, "SNOWFLAKE_PASSWORD", None):
                self.connection_params["password"] = settings.SNOWFLAKE_PASSWORD
            if getattr(settings, "SNOWFLAKE_WAREHOUSE", None):
                self.connection_params["warehouse"] = settings.SNOWFLAKE_WAREHOUSE
            if getattr(settings, "SNOWFLAKE_DATABASE", None):
                self.connection_params["database"] = settings.SNOWFLAKE_DATABASE
            if getattr(settings, "SNOWFLAKE_SCHEMA", None):
                self.connection_params["schema"] = settings.SNOWFLAKE_SCHEMA
        except Exception:
            # If settings is partially configured, leave whatever we could set
            pass
        
    @contextmanager
    def get_connection(self):
        """Context manager for one-off database connections (non-cached)."""
        connection = None
        try:
            # Prefer per-user session credentials for RBAC-correct execution
            params = dict(self.connection_params)
            if st is not None:
                acct = st.session_state.get("sf_account")
                user = st.session_state.get("sf_user")
                pwd = st.session_state.get("sf_password")
                wh = st.session_state.get("sf_warehouse")
                db = st.session_state.get("sf_database")
                sc = st.session_state.get("sf_schema")
                role = st.session_state.get("sf_role")
                authenticator = st.session_state.get("sf_authenticator")
                organization = st.session_state.get("sf_organization")
                host_override = st.session_state.get("sf_host")
                auth_method = (st.session_state.get("sf_auth_method") or "password").lower()
                if acct and user:
                    # Normalize account
                    acct_norm = acct
                    try:
                        a = str(acct).strip().lower()
                        if a.startswith("http://"):
                            a = a[len("http://"):]
                        if a.startswith("https://"):
                            a = a[len("https://"):]
                        if "/" in a:
                            a = a.split("/", 1)[0]
                        if ".snowflakecomputing.com" in a:
                            a = a.split(".snowflakecomputing.com", 1)[0]
                        acct_norm = a
                    except Exception:
                        acct_norm = acct
                    if auth_method == "externalbrowser":
                        # Prefer explicit authenticator URL if provided
                        if authenticator and str(authenticator).strip().lower().startswith("http"):
                            params = {"account": acct_norm, "user": user, "authenticator": str(authenticator).strip()}
                        else:
                            params = {"account": acct_norm, "user": user, "authenticator": "externalbrowser"}
                    else:
                        # default password auth
                        params = {"account": acct_norm, "user": user, "password": pwd}
                    if wh:
                        params["warehouse"] = wh
                    if db:
                        params["database"] = db
                    if sc:
                        params["schema"] = sc
                    if role:
                        params["role"] = role
                    if organization:
                        params["organization"] = str(organization).strip()
                    if host_override:
                        try:
                            h = str(host_override).strip().lower()
                            if h.startswith("http://"):
                                h = h[len("http://"):]
                            if h.startswith("https://"):
                                h = h[len("https://"):]
                            if "/" in h:
                                h = h.split("/", 1)[0]
                            params["host"] = h
                        except Exception:
                            params["host"] = str(host_override)
            # Keep session alive to avoid auto-logout while the app is open
            params["client_session_keep_alive"] = True
            connection = snowflake.connector.connect(**params)
            yield connection
        except Exception as e:
            logger.error(f"Error connecting to Snowflake: {e}")
            raise
        finally:
            if connection:
                connection.close()

    def _get_cached_connection(self):
        """Return a per-session cached connection (does not auto-close)."""
        params = dict(self.connection_params)
        if st is not None:
            acct = st.session_state.get("sf_account")
            user = st.session_state.get("sf_user")
            pwd = st.session_state.get("sf_password")
            wh = st.session_state.get("sf_warehouse")
            db = st.session_state.get("sf_database")
            sc = st.session_state.get("sf_schema")
            role = st.session_state.get("sf_role")
            authenticator = st.session_state.get("sf_authenticator")
            organization = st.session_state.get("sf_organization")
            host_override = st.session_state.get("sf_host")
            auth_method = (st.session_state.get("sf_auth_method") or "password").lower()
            if acct and user:
                # Normalize account
                acct_norm = acct
                try:
                    a = str(acct).strip().lower()
                    if a.startswith("http://"):
                        a = a[len("http://"):]
                    if a.startswith("https://"):
                        a = a[len("https://"):]
                    if "/" in a:
                        a = a.split("/", 1)[0]
                    if ".snowflakecomputing.com" in a:
                        a = a.split(".snowflakecomputing.com", 1)[0]
                    acct_norm = a
                except Exception:
                    acct_norm = acct
                if auth_method == "externalbrowser":
                    if authenticator and str(authenticator).strip().lower().startswith("http"):
                        params = {"account": acct_norm, "user": user, "authenticator": str(authenticator).strip()}
                    else:
                        params = {"account": acct_norm, "user": user, "authenticator": "externalbrowser"}
                else:
                    params = {"account": acct_norm, "user": user, "password": pwd}
                if wh:
                    params["warehouse"] = wh
                if db:
                    params["database"] = db
                if sc:
                    params["schema"] = sc
                if role:
                    params["role"] = role
                if organization:
                    params["organization"] = str(organization).strip()
                if host_override:
                    try:
                        h = str(host_override).strip().lower()
                        if h.startswith("http://"):
                            h = h[len("http://"):]
                        if h.startswith("https://"):
                            h = h[len("https://"):]
                        if "/" in h:
                            h = h.split("/", 1)[0]
                        params["host"] = h
                    except Exception:
                        params["host"] = str(host_override)
        # Use cached connection factory
        # Keep session alive on cached connections as well
        params["client_session_keep_alive"] = True
        conn = _sf_connect_cached(**params)
        return conn
    
    def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> list:
        """
        Execute a query and return results.
        
        Args:
            query: SQL query to execute
            params: Query parameters for parameterized queries
            
        Returns:
            List of query results
        """
        conn = self._get_cached_connection()
        cursor = conn.cursor(DictCursor)
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return cursor.fetchall()
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            raise
        finally:
            cursor.close()
    
    def execute_non_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> int:
        """
        Execute a non-query statement (INSERT, UPDATE, DELETE).
        
        Args:
            query: SQL statement to execute
            params: Statement parameters
            
        Returns:
            Number of affected rows
        """
        conn = self._get_cached_connection()
        cursor = conn.cursor()
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return cursor.rowcount
        except Exception as e:
            logger.error(f"Error executing statement: {e}")
            raise
        finally:
            cursor.close()

# Create a global instance
snowflake_connector = SnowflakeConnector()
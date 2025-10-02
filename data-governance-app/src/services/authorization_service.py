"""
Authorization service for role-aware page and feature access using Snowflake roles.
"""
from __future__ import annotations
from typing import Dict, List, Set

from src.connectors.snowflake_connector import snowflake_connector
from src.services.oidc_service import oidc_service
from src.services.privilege_service import can_apply_tags_to_object as _ps_can_apply_tags_to_object, can_read_table as _ps_can_read_table
from src.config.settings import settings
import snowflake.connector
try:
    import streamlit as st  # optional, used only if app provides per-user login
except Exception:
    st = None


class Identity:
    def __init__(self, user: str, current_role: str, roles: Set[str]):
        self.user = (user or "").upper()
        self.current_role = (current_role or "").upper()
        self.roles = {r.upper() for r in (roles or set())}

    def has_any(self, candidates: Set[str]) -> bool:
        cset = {c.upper() for c in candidates}
        return bool(self.roles.intersection(cset) or (self.current_role in cset))


class AuthorizationService:
    """Derives app permissions from Snowflake role membership.

    Supports both org-specific roles (e.g., CDO_ROLE, DATA_OWNER_ROLE) and
    repo-defined roles (ROLE_DATA_OWNER, ROLE_CONFIDENTIAL_OWNER, etc.).
    """

    # Logical role groups (customize as needed)
    ADMIN_ROLES = {
        "ADMIN", "CDO_ROLE", "ROLE_CDO_ADMIN", "ACCOUNTADMIN", "SECURITY_ADMIN", "SYSADMIN", "DATA_GOV_COMMITTEE_ROLE"
    }
    OWNER_ROLES = {
        "DATA_OWNER_ROLE", "ROLE_DATA_OWNER", "ROLE_CONFIDENTIAL_OWNER"
    }
    CUSTODIAN_ROLES = {
        "DATA_CUSTODIAN_ROLE", "ROLE_DATA_CUSTODIAN", "SECURITY_ADMIN", "SYSADMIN"
    }
    SPECIALIST_ROLES = {
        "DATA_CLASS_SPECIALIST_ROLE"
    }
    CONSUMER_ROLES = {
        "DATA_CONSUMER_ROLE", "ROLE_DATA_CONSUMER", "ROLE_PUBLIC_VIEWER", "ROLE_INTERNAL_USER", "ROLE_RESTRICTED_ANALYST"
    }

    def _session_connection(self):
        """Build a connection using per-user creds from Streamlit session if present; else return None."""
        if st is None:
            return None
        try:
            u = st.session_state.get("sf_user")
            acct = st.session_state.get("sf_account")
            auth_method = (st.session_state.get("sf_auth_method") or "password").lower()
            p = st.session_state.get("sf_password")
            wh = st.session_state.get("sf_warehouse")
            db = st.session_state.get("sf_database")
            sc = st.session_state.get("sf_schema")
            role = st.session_state.get("sf_role")
            authenticator = st.session_state.get("sf_authenticator")
            organization = st.session_state.get("sf_organization")
            host_override = st.session_state.get("sf_host")
            # Basic validation (require at least account + user)
            if not (u and acct):
                return None
            # Normalize account to locator.region[.cloud]
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
            # Build params depending on auth method
            if auth_method == "externalbrowser":
                # Prefer explicit authenticator URL if provided
                if authenticator and str(authenticator).strip().lower().startswith("http"):
                    params = {"user": u, "account": acct_norm, "authenticator": str(authenticator).strip()}
                else:
                    params = {"user": u, "account": acct_norm, "authenticator": "externalbrowser"}
            else:
                # Default to password auth
                if not p:
                    return None
                params = {"user": u, "password": p, "account": acct_norm}
            # Optional settings
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
            return snowflake.connector.connect(**params)
        except Exception:
            return None

    def get_current_identity(self) -> Identity:
        # Try per-user session connection first
        conn = self._session_connection()
        if conn is not None:
            try:
                cur = conn.cursor(snowflake.connector.DictCursor)
                cur.execute("SELECT CURRENT_USER() AS USERNAME, CURRENT_ROLE() AS ROLE")
                meta = cur.fetchall() or []
                user = (meta[0].get("USERNAME") if meta else None) or ""
                current_role = (meta[0].get("ROLE") if meta else None) or ""
                roles: Set[str] = set()
                try:
                    cur.execute(f"SHOW GRANTS TO USER \"{user}\"")
                    show_rows = cur.fetchall() or []
                    for r in show_rows:
                        role_name = r.get("role") or r.get("ROLE") or r.get("ROLE_NAME") or r.get("GRANTED_ROLE")
                        if role_name:
                            roles.add(str(role_name))
                except Exception:
                    pass
                # Augment with application-level roles from governance tables and IdP groups
                try:
                    app_email = None
                    idp_groups: Set[str] = set()
                    if st is not None:
                        # Prefer OIDC userinfo email; fallback to st.session_state.user.email
                        ui = st.session_state.get("oidc_userinfo") or {}
                        app_email = (ui.get("email") or ui.get("preferred_username") or None)
                        if not app_email:
                            uobj = st.session_state.get("user")
                            app_email = getattr(uobj, "email", None)
                        # Capture IdP groups if present for mapping
                        try:
                            g = ui.get("groups") or []
                            if isinstance(g, list):
                                idp_groups = {str(x) for x in g if x}
                        except Exception:
                            idp_groups = set()
                    # Map IdP groups → roles via IDP_GROUP_MAP
                    if idp_groups:
                        try:
                            in_list = ",".join(["%(g"+str(i)+")s" for i, _ in enumerate(idp_groups)])
                            params = {"g"+str(i): v for i, v in enumerate(idp_groups)}
                            rows = snowflake_connector.execute_query(
                                f"SELECT ROLE_NAME FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.IDP_GROUP_MAP WHERE GROUP_NAME IN ({in_list})",
                                params
                            ) or []
                            for r in rows:
                                rn = r.get("ROLE_NAME")
                                if rn:
                                    roles.add(str(rn))
                        except Exception:
                            pass
                    # Add roles from ROLE_ASSIGNMENTS by email
                    if app_email:
                        try:
                            rows = snowflake_connector.execute_query(
                                f"SELECT ROLE_NAME FROM {settings.SNOWFLAKE_DATABASE}.DATA_GOVERNANCE.ROLE_ASSIGNMENTS WHERE USER_EMAIL = %(e)s",
                                {"e": app_email}
                            ) or []
                            for r in rows:
                                rn = r.get("ROLE_NAME")
                                if rn:
                                    roles.add(str(rn))
                        except Exception:
                            pass
                except Exception:
                    pass
                if current_role:
                    roles.add(current_role)
                return Identity(user=user, current_role=current_role, roles=roles)
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()

        # Fallback behavior: if no per-user session, do NOT inherit app credentials for RBAC
        # To explicitly allow limited debugging with app credentials, set ALLOW_DEBUG_RBAC=True
        # (separate from DEBUG to avoid accidental privilege exposure).
        if getattr(settings, "ALLOW_DEBUG_RBAC", False):
            meta = snowflake_connector.execute_query(
                "SELECT CURRENT_USER() AS USERNAME, CURRENT_ROLE() AS ROLE"
            ) or []
            user = (meta[0].get("USERNAME") if meta else None) or ""
            current_role = (meta[0].get("ROLE") if meta else None) or ""
            roles: Set[str] = set()
            try:
                show_rows = snowflake_connector.execute_query(f"SHOW GRANTS TO USER \"{user}\"") or []
                for r in show_rows:
                    role_name = r.get("ROLE") or r.get("ROLE_NAME") or r.get("GRANTED_ROLE")
                    if role_name:
                        roles.add(str(role_name))
            except Exception:
                pass
            if current_role:
                roles.add(current_role)
            return Identity(user=user, current_role=current_role, roles=roles)
        # Otherwise, return an unauthenticated identity (no roles)
        return Identity(user="", current_role="", roles=set())

    # Convenience checks
    def is_admin(self, ident: Identity) -> bool:
        return ident.has_any(self.ADMIN_ROLES)

    def is_owner(self, ident: Identity) -> bool:
        return ident.has_any(self.OWNER_ROLES) or self.is_admin(ident)

    def is_custodian(self, ident: Identity) -> bool:
        return ident.has_any(self.CUSTODIAN_ROLES) or self.is_admin(ident)

    def is_specialist(self, ident: Identity) -> bool:
        return ident.has_any(self.SPECIALIST_ROLES) or self.is_admin(ident)

    def is_consumer(self, ident: Identity) -> bool:
        # Any authenticated identity with at least a consumer role, or elevated roles.
        # Include Admins explicitly so pure admins (e.g., ACCOUNTADMIN) can access consumer-gated pages.
        return (
            ident.has_any(self.CONSUMER_ROLES)
            or self.is_owner(ident)
            or self.is_custodian(ident)
            or self.is_admin(ident)
        )

    def can_access_classification(self, ident: Identity) -> bool:
        # Owners, custodians, specialists, admins
        return self.is_owner(ident) or self.is_custodian(ident) or self.is_specialist(ident) or self.is_admin(ident)

    def can_see_admin_actions(self, ident: Identity) -> bool:
        # Custodians and admins
        return self.is_custodian(ident) or self.is_admin(ident)

    # Action-level convenience checks
    def can_classify(self, ident: Identity) -> bool:
        """Users who may classify/tag assets.
        Defaults: Data Owners, Custodians, Specialists, Admins.
        """
        return self.is_owner(ident) or self.is_custodian(ident) or self.is_specialist(ident) or self.is_admin(ident)

    def can_approve_tags(self, ident: Identity) -> bool:
        """Users who may approve tag/classification decisions.
        Defaults: Data Owners, Admins, and Governance Committee.
        """
        # Treat committee as admin-aligned for approvals
        has_committee = ident.has_any({"DATA_GOV_COMMITTEE_ROLE"})
        return self.is_owner(ident) or self.is_admin(ident) or has_committee

    # Object-specific, privilege-based checks (no role-name hardcoding)
    def can_apply_tags_for_object(self, fq_object: str, object_type: str = "TABLE") -> bool:
        try:
            return _ps_can_apply_tags_to_object(fq_object, object_type=object_type)
        except Exception:
            return False

    def can_read_table(self, fq_table: str) -> bool:
        try:
            return _ps_can_read_table(fq_table)
        except Exception:
            return True


authz = AuthorizationService()

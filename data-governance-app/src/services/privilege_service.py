"""
Privilege-based RBAC helpers for Snowflake.

This service avoids hard-coding role names. It inspects the current session's role
privileges using SHOW GRANTS and, where helpful, simple object-level checks.

Best-effort: Snowflake is the source of truth. The app uses these checks to hide/disable
controls, but final enforcement is left to Snowflake (server-side try/except remains).
"""
from __future__ import annotations
import re
from typing import Dict, List, Optional, Set, Tuple

import streamlit as st
from src.connectors.snowflake_connector import snowflake_connector


def _cached_role_grants() -> List[dict]:
    """Return SHOW GRANTS TO ROLE CURRENT_ROLE() results, cached per session."""
    cache_key = "_ps_role_grants"
    if cache_key in st.session_state:
        return st.session_state[cache_key] or []
    try:
        rows = snowflake_connector.execute_query("SHOW GRANTS TO ROLE CURRENT_ROLE()") or []
        st.session_state[cache_key] = rows
        return rows
    except Exception:
        st.session_state[cache_key] = []
        return []


def refresh_cache() -> None:
    st.session_state.pop("_ps_role_grants", None)


def _norm(name: Optional[str]) -> Optional[str]:
    return str(name).strip().upper() if name is not None else None


def has_account_priv(priv: str) -> bool:
    """Check if CURRENT_ROLE() has a given account-level privilege (best-effort)."""
    p = _norm(priv)
    for r in _cached_role_grants():
        if _norm(r.get("privilege")) == p and _norm(r.get("granted_on")) == "ACCOUNT":
            return True
    return False


def list_object_privs(fq_object: str, object_type: str = "TABLE") -> Set[str]:
    """List CURRENT_ROLE() privileges on a specific object (best-effort via SHOW GRANTS ON OBJECT).
    fq_object should be fully qualified e.g., DB.SCHEMA.OBJECT.
    """
    try:
        object_type = object_type.strip().upper()
        # SHOW GRANTS ON <object_type> <name>
        sql = f"SHOW GRANTS ON {object_type} {fq_object}"
        rows = snowflake_connector.execute_query(sql) or []
        privs = set()
        # Typical columns: privilege, grantee_name, granted_on, name
        for r in rows:
            if _norm(r.get("grantee_name")) == _norm(_current_role()):
                pr = _norm(r.get("privilege"))
                if pr:
                    privs.add(pr)
        return privs
    except Exception:
        return set()


def has_priv_on_object(priv: str, fq_object: str, object_type: str = "TABLE") -> bool:
    return _norm(priv) in list_object_privs(fq_object, object_type)


def _current_role() -> Optional[str]:
    try:
        row = snowflake_connector.execute_query("select current_role() as R") or []
        return row[0].get("R") if row else None
    except Exception:
        return None


def can_read_table(fq_table: str) -> bool:
    """Best-effort check if SELECT is granted on a table.
    If grants query fails, return True and let Snowflake enforce at query time.
    """
    try:
        return has_priv_on_object("SELECT", fq_table, "TABLE") or has_priv_on_object("OWNERSHIP", fq_table, "TABLE")
    except Exception:
        return True


def can_alter_object(fq_object: str, object_type: str = "TABLE") -> bool:
    try:
        privs = list_object_privs(fq_object, object_type)
        return ("ALTER" in privs) or ("OWNERSHIP" in privs)
    except Exception:
        return False


def can_apply_tags_to_object(fq_object: str, tag_names: Optional[List[str]] = None, object_type: str = "TABLE") -> bool:
    """Heuristic: require ability to ALTER/OWN the object. Tag APPLY privilege is typically granted on TAG objects,
    but many orgs centralize this; if tag names are fully qualified, we could also verify APPLY on each TAG.
    For now, enforce ALTER/OWNERSHIP on the target object; leave APPLY-on-TAG to Snowflake at execution time.
    """
    return can_alter_object(fq_object, object_type)


def has_schema_write(schema_fq: str) -> bool:
    """Check if the current role can write to a schema (CREATE/USAGE/OWNERSHIP)."""
    try:
        privs = list_object_privs(schema_fq, "SCHEMA")
        return any(p in privs for p in {"OWNERSHIP", "USAGE", "CREATE"})
    except Exception:
        return False


def can_manage_labels(governance_schema_fq: Optional[str]) -> bool:
    """Ability to manage label registry (assumes tables under a governance schema)."""
    if governance_schema_fq:
        return has_schema_write(governance_schema_fq)
    # Fallback to account-level privilege (broad)
    return has_account_priv("MANAGE GRANTS") or has_account_priv("MONITOR")


def can_manage_roles_account_level() -> bool:
    """Check if role can create/alter roles (account-level)."""
    return any(has_account_priv(p) for p in ["CREATE ROLE", "MANAGE GRANTS", "USERADMIN", "SECURITYADMIN"])  # best-effort

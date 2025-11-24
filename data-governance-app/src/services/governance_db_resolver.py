"""
Governance DB Resolver

Auto-detect the Snowflake governance database by probing for the presence of
standard governance schema and tables. Provides a single function
`resolve_governance_db()` that callers can use instead of hardcoding a DB name.

Priority:
1) Explicit session override: st.session_state["sf_database"]
2) settings.SNOWFLAKE_DATABASE
3) Probe CURRENT_DATABASE() for expected artifacts
4) Probe all accessible databases via SHOW DATABASES

Caches the result in-memory (module var) and in Streamlit session to avoid
repeated probes.
"""
from __future__ import annotations

from typing import Optional, Iterable

try:
    import streamlit as st  # type: ignore
except Exception:  # pragma: no cover
    st = None

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
import logging

# Module cache
_CACHED_DB: Optional[str] = None
_LAST_INFO: dict = {}
INVALID_DB_VALUES = {"NONE", "NULL", "UNKNOWN", "(NONE)"}
logger = logging.getLogger(__name__)

# Expected governance schema and at least one of these tables
_EXPECTED_SCHEMA = "DATA_CLASSIFICATION_GOVERNANCE"
_EXPECTED_TABLES = (
    "ASSETS",
    "CLASSIFICATION_HISTORY",
    "RECLASSIFICATION_REQUESTS",
)


def _has_any_table(db: str, tables: Iterable[str]) -> bool:
    try:
        # Use INFORMATION_SCHEMA to verify presence of the governance schema and tables
        rows = snowflake_connector.execute_query(
            f"""
            select count(*) as CNT
            from {db}.INFORMATION_SCHEMA.TABLES
            where TABLE_SCHEMA = %%(schema)s
              and TABLE_NAME in ({', '.join(["%(t" + str(i) + ")s" for i, _ in enumerate(tables)])})
            """,
            {"schema": _EXPECTED_SCHEMA, **{f"t{i}": t for i, t in enumerate(tables)}},
        ) or []
        cnt = int(rows[0].get("CNT", 0)) if rows else 0
        logger.debug(f"governance_db_resolver: {_EXPECTED_SCHEMA} tables present in {db}: {cnt}")
        return cnt > 0
    except Exception:
        logger.debug("governance_db_resolver: _has_any_table failed", exc_info=True)
        return False


def _probe_current_database() -> Optional[str]:
    try:
        rows = snowflake_connector.execute_query("select current_database() as DB") or []
        db = rows[0].get("DB") if rows else None
        if db and _has_any_table(db, _EXPECTED_TABLES):
            _LAST_INFO.update({"method": "CURRENT_DATABASE", "db": db})
            return str(db)
    except Exception:
        logger.debug("governance_db_resolver: _probe_current_database failed", exc_info=True)
        return None
    return None


def _probe_all_databases() -> Optional[str]:
    try:
        db_rows = snowflake_connector.execute_query("show databases") or []
        # Some accounts return column as NAME, some as name
        names = [r.get("name") or r.get("NAME") for r in db_rows if (r.get("name") or r.get("NAME"))]
        for db in names:
            if not db:
                continue
            if _has_any_table(db, _EXPECTED_TABLES):
                _LAST_INFO.update({"method": "SHOW DATABASES", "db": db})
                return str(db)
    except Exception:
        logger.debug("governance_db_resolver: _probe_all_databases failed", exc_info=True)
        return None
    return None


def resolve_governance_db(force_refresh: bool = False) -> Optional[str]:
    global _CACHED_DB
    try:
        if st is not None and not force_refresh:
            v = st.session_state.get("sf_database")
            if v:
                vv = str(v).strip()
                if vv and vv.upper() not in INVALID_DB_VALUES:
                    _CACHED_DB = vv
                    _LAST_INFO.update({"method": "SESSION_STATE", "db": _CACHED_DB})
                    return _CACHED_DB
    except Exception:
        pass

    if not force_refresh and _CACHED_DB:
        if str(_CACHED_DB).strip().upper() in INVALID_DB_VALUES:
            # Invalidate bad cache values
            _LAST_INFO.update({"method": "MODULE_CACHE_INVALID", "db": _CACHED_DB})
        else:
            _LAST_INFO.update({"method": "MODULE_CACHE", "db": _CACHED_DB})
            return _CACHED_DB

    # Settings default
    try:
        conf = getattr(settings, "SNOWFLAKE_DATABASE", None)
        if conf:
            val = str(conf).strip()
            if val and val.upper() not in INVALID_DB_VALUES:
                _CACHED_DB = val
                _LAST_INFO.update({"method": "SETTINGS", "db": _CACHED_DB})
                return _CACHED_DB
    except Exception:
        pass

    # Probe CURRENT_DATABASE then SHOW DATABASES
    db = _probe_current_database() or _probe_all_databases()
    if db:
        _CACHED_DB = db
        try:
            if st is not None:
                st.session_state["sf_database"] = db
        except Exception:
            pass
        logger.info(f"governance_db_resolver: resolved governance DB: {db} via {_LAST_INFO.get('method')}")
        return db

    # Fallback to default if resolution fails completely
    default_db = "DATA_CLASSIFICATION_DB"
    logger.warning(f"governance_db_resolver: resolution failed, falling back to default: {default_db}")
    _CACHED_DB = default_db
    _LAST_INFO.update({"method": "FALLBACK_DEFAULT", "db": default_db})
    return default_db


def get_last_resolution_info() -> dict:
    """Return last resolution diagnostics: {method, db}."""
    return dict(_LAST_INFO)

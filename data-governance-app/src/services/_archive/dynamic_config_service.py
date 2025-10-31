from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import time

try:
    from src.connectors.snowflake_connector import snowflake_connector  # type: ignore
except Exception:
    snowflake_connector = None  # type: ignore

# Optional settings for governance schema override
try:
    from src.config.settings import settings  # type: ignore
except Exception:
    settings = None  # type: ignore

try:
    import streamlit as st  # type: ignore
except Exception:
    st = None  # type: ignore

# Module-level cache
_CACHE: Dict[str, Any] = {"loaded_at": 0.0, "config": None}
_CACHE_TTL_SEC = 60.0


def _get_cache() -> Tuple[Optional[Dict[str, Any]], float]:
    # Prefer Streamlit session_state if available
    if st is not None:
        ss = st.session_state.setdefault("_dyn_config_cache", {"loaded_at": 0.0, "config": None})
        return ss.get("config"), float(ss.get("loaded_at", 0.0))
    return _CACHE.get("config"), float(_CACHE.get("loaded_at") or 0.0)


def _set_cache(cfg: Dict[str, Any]) -> None:
    now = time.time()
    if st is not None:
        st.session_state["_dyn_config_cache"] = {"loaded_at": now, "config": cfg}
    _CACHE["loaded_at"] = now
    _CACHE["config"] = cfg


def _table_exists(db: str, schema: str, table: str) -> bool:
    if snowflake_connector is None:
        return False
    try:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT 1
            FROM {db}.INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = %(sc)s AND TABLE_NAME = %(tb)s
            LIMIT 1
            """,
            {"sc": schema, "tb": table},
        ) or []
        return bool(rows)
    except Exception:
        return False


def _prefer_sources() -> List[Tuple[str, str]]:
    # If settings specifies a single governance location, enforce it exclusively
    try:
        if settings is not None:
            gov_db = getattr(settings, "GOVERNANCE_DB", None) or getattr(settings, "DATA_GOVERNANCE_DB", None)
            gov_sc = getattr(settings, "GOVERNANCE_SCHEMA", None) or getattr(settings, "DATA_GOVERNANCE_SCHEMA", None)
            if gov_db and gov_sc:
                return [(str(gov_db), str(gov_sc))]
    except Exception:
        pass
    # Default (exclusive) if not configured: DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE
    return [("DATA_CLASSIFICATION_DB", "DATA_CLASSIFICATION_GOVERNANCE")]


def _first_existing(tables: List[str]) -> Optional[Tuple[str, str, str]]:
    for db, sc in _prefer_sources():
        for tb in tables:
            if _table_exists(db, sc, tb):
                return db, sc, tb
    return None


def _load_patterns() -> Dict[str, List[Dict[str, Any]]]:
    """
    Returns: {category: [{regex, active, owner, version}], ...}
    Expected table candidates: SENSITIVE_PATTERNS or DETECTION_PATTERNS
    Columns supported: CATEGORY, REGEX, ACTIVE(bool), OWNER, VERSION, WEIGHT(optional)
    """
    if snowflake_connector is None:
        return {}
    loc = _first_existing(["SENSITIVE_PATTERNS", "DETECTION_PATTERNS"])
    if not loc:
        return {}
    db, sc, tb = loc
    # Try variants for active flag to support schemas that use IS_ACTIVE or no flag
    query_variants = [
        f"SELECT CATEGORY, REGEX, ACTIVE as ACTIVE, OWNER, VERSION, COALESCE(WEIGHT, 0.5) AS WEIGHT FROM {db}.{sc}.{tb}",
        f"SELECT CATEGORY, REGEX, IS_ACTIVE as ACTIVE, OWNER, VERSION, COALESCE(WEIGHT, 0.5) AS WEIGHT FROM {db}.{sc}.{tb}",
        f"SELECT CATEGORY, REGEX, TRUE as ACTIVE, OWNER, VERSION, COALESCE(WEIGHT, 0.5) AS WEIGHT FROM {db}.{sc}.{tb}",
    ]
    rows: List[Dict[str, Any]] = []
    for q in query_variants:
        try:
            rows = snowflake_connector.execute_query(q) or []
            break
        except Exception:
            rows = []
    out: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        cat = str(r.get("CATEGORY") or "").strip()
        rx = str(r.get("REGEX") or "").strip()
        if not cat or not rx:
            continue
        item = {
            "regex": rx,
            "active": bool(r.get("ACTIVE", True)),
            "owner": r.get("OWNER"),
            "version": r.get("VERSION"),
            "weight": float(r.get("WEIGHT") or 0.5),
        }
        out.setdefault(cat, []).append(item)
    return out


def _load_keywords() -> Dict[str, List[Dict[str, Any]]]:
    """
    Returns: {category: [{keyword, match_type('exact'|'fuzzy'), weight, active, version}], ...}
    Expected table candidates: SENSITIVE_KEYWORDS or DETECTION_KEYWORDS
    Columns: CATEGORY, KEYWORD, MATCH_TYPE, ACTIVE, VERSION, WEIGHT
    """
    if snowflake_connector is None:
        return {}
    loc = _first_existing(["SENSITIVE_KEYWORDS", "DETECTION_KEYWORDS"])
    if not loc:
        return {}
    db, sc, tb = loc
    query_variants = [
        f"SELECT CATEGORY, KEYWORD, COALESCE(MATCH_TYPE,'FUZZY') AS MATCH_TYPE, ACTIVE as ACTIVE, VERSION, COALESCE(WEIGHT,0.5) AS WEIGHT FROM {db}.{sc}.{tb}",
        f"SELECT CATEGORY, KEYWORD, COALESCE(MATCH_TYPE,'FUZZY') AS MATCH_TYPE, IS_ACTIVE as ACTIVE, VERSION, COALESCE(WEIGHT,0.5) AS WEIGHT FROM {db}.{sc}.{tb}",
        f"SELECT CATEGORY, KEYWORD, COALESCE(MATCH_TYPE,'FUZZY') AS MATCH_TYPE, TRUE as ACTIVE, VERSION, COALESCE(WEIGHT,0.5) AS WEIGHT FROM {db}.{sc}.{tb}",
    ]
    rows: List[Dict[str, Any]] = []
    for q in query_variants:
        try:
            rows = snowflake_connector.execute_query(q) or []
            break
        except Exception:
            rows = []
    out: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        cat = str(r.get("CATEGORY") or "").strip()
        kw = str(r.get("KEYWORD") or "").strip()
        if not cat or not kw:
            continue
        item = {
            "keyword": kw,
            "match_type": (str(r.get("MATCH_TYPE") or "FUZZY").lower()),
            "active": bool(r.get("ACTIVE", True)),
            "version": r.get("VERSION"),
            "weight": float(r.get("WEIGHT") or 0.5),
        }
        out.setdefault(cat, []).append(item)
    return out


def _load_categories() -> List[str]:
    """
    Returns: [category, ...]
    Expected table: SENSITIVITY_CATEGORIES
    Columns: CATEGORY, ACTIVE
    """
    if snowflake_connector is None:
        return []
    loc = _first_existing(["SENSITIVITY_CATEGORIES"])
    if not loc:
        return []
    db, sc, tb = loc
    query_variants = [
        f"SELECT CATEGORY, ACTIVE as ACTIVE FROM {db}.{sc}.{tb}",
        f"SELECT CATEGORY, IS_ACTIVE as ACTIVE FROM {db}.{sc}.{tb}",
        f"SELECT CATEGORY, TRUE as ACTIVE FROM {db}.{sc}.{tb}",
    ]
    rows: List[Dict[str, Any]] = []
    for q in query_variants:
        try:
            rows = snowflake_connector.execute_query(q) or []
            break
        except Exception:
            rows = []
    return [str(r.get("CATEGORY")).strip() for r in rows if r.get("CATEGORY") and bool(r.get("ACTIVE", True))]


def _load_bundles() -> List[Dict[str, Any]]:
    """
    Returns: [{name, category, boost, columns: [token,...], active, version}], ...
    Expected table: SENSITIVE_BUNDLES
    Columns: NAME, CATEGORY, BOOST(0..1 or 0..100), COLUMNS(list or comma string), ACTIVE, VERSION
    """
    if snowflake_connector is None:
        return []
    loc = _first_existing(["SENSITIVE_BUNDLES"])
    if not loc:
        return []
    db, sc, tb = loc
    query_variants = [
        f"SELECT NAME, CATEGORY, COALESCE(BOOST, 0.1) AS BOOST, COLUMNS, ACTIVE as ACTIVE, VERSION FROM {db}.{sc}.{tb}",
        f"SELECT NAME, CATEGORY, COALESCE(BOOST, 0.1) AS BOOST, COLUMNS, IS_ACTIVE as ACTIVE, VERSION FROM {db}.{sc}.{tb}",
        f"SELECT NAME, CATEGORY, COALESCE(BOOST, 0.1) AS BOOST, COLUMNS, TRUE as ACTIVE, VERSION FROM {db}.{sc}.{tb}",
    ]
    rows: List[Dict[str, Any]] = []
    for q in query_variants:
        try:
            rows = snowflake_connector.execute_query(q) or []
            break
        except Exception:
            rows = []
    out: List[Dict[str, Any]] = []
    for r in rows:
        cols_raw = r.get("COLUMNS")
        cols: List[str] = []
        if isinstance(cols_raw, list):
            cols = [str(x) for x in cols_raw]
        elif isinstance(cols_raw, str):
            cols = [c.strip() for c in cols_raw.split(',') if c.strip()]
        item = {
            "name": r.get("NAME"),
            "category": r.get("CATEGORY"),
            "boost": float(r.get("BOOST") or 0.1),
            "columns": cols,
            "active": bool(r.get("ACTIVE", True)),
            "version": r.get("VERSION"),
        }
        out.append(item)
    return out


def _load_cia_rules() -> Dict[str, Dict[str, int]]:
    """
    Returns: {category: {C: int, I: int, A: int, MIN_THRESHOLD(optional)} }
    Expected table: CIA_RULES
    Columns: CATEGORY, C, I, A, MIN_THRESHOLD
    """
    if snowflake_connector is None:
        return {}
    loc = _first_existing(["CIA_RULES"])
    if not loc:
        return {}
    db, sc, tb = loc
    rows = snowflake_connector.execute_query(
        f"SELECT CATEGORY, COALESCE(C,0) AS C, COALESCE(I,0) AS I, COALESCE(A,0) AS A, COALESCE(MIN_THRESHOLD, 0.5) AS MIN_THRESHOLD FROM {db}.{sc}.{tb}"
    ) or []
    out: Dict[str, Dict[str, int]] = {}
    for r in rows:
        cat = str(r.get("CATEGORY") or "").strip()
        if not cat:
            continue
        out[cat] = {"C": int(r.get("C", 0)), "I": int(r.get("I", 0)), "A": int(r.get("A", 0)), "MIN_THRESHOLD": float(r.get("MIN_THRESHOLD", 0.5))}  # type: ignore
    return out


def load_config(force_refresh: bool = False) -> Dict[str, Any]:
    """
    Load dynamic configuration from Snowflake with simple caching.
    Structure:
    {
      "categories": [str],
      "patterns": {category: [{regex, active, owner, version, weight}]},
      "keywords": {category: [{keyword, match_type, active, version, weight}]},
      "bundles": [{name, category, boost, columns, active, version}],
      "cia_rules": {category: {C,I,A, MIN_THRESHOLD}},
      "version": {"ts": unix_time, "sources": {...}}
    }
    """
    cfg_cached, ts = _get_cache()
    if (not force_refresh) and cfg_cached and (time.time() - ts < _CACHE_TTL_SEC):
        return cfg_cached

    cfg: Dict[str, Any] = {
        "categories": _load_categories(),
        "patterns": _load_patterns(),
        "keywords": _load_keywords(),
        "bundles": _load_bundles(),
        "cia_rules": _load_cia_rules(),
        "version": {"ts": time.time()},
    }
    _set_cache(cfg)
    return cfg


def clear_cache() -> None:
    _set_cache({})

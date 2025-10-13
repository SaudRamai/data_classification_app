"""
Tag Drift Service

Detects drift between governance table classification (`ASSETS.CLASSIFICATION_TAG`) and
actual Snowflake tags applied to objects.

Approach:
- Read asset rows from DATA_CLASSIFICATION_GOVERNANCE.ASSETS
- Read tag references from SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES (best-effort)
- Infer object FQN for comparison: DATABASE_NAME.SCHEMA_NAME.ASSET_NAME
- Extract tag value for DATA_CLASSIFICATION (case-insensitive) and compare
- Produce drift summary and per-asset status
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    import streamlit as st
except Exception:  # pragma: no cover
    st = None

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings


def _active_db() -> str:
    try:
        if st is not None and st.session_state.get("sf_database"):
            return str(st.session_state.get("sf_database"))
    except Exception:
        pass
    try:
        if getattr(settings, "SNOWFLAKE_DATABASE", None):
            return str(settings.SNOWFLAKE_DATABASE)
    except Exception:
        pass
    raise ValueError("Snowflake database is not set in session or settings.")


def _cache(ttl: int = 120):
    def deco(fn):
        if st is not None:
            return st.cache_data(ttl=ttl, show_spinner=False)(fn)
        return fn
    return deco


@_cache(ttl=120)
def analyze_tag_drift(database: Optional[str] = None, limit: int = 1000) -> Dict[str, Any]:
    db = str(database or _active_db())
    sc = "DATA_CLASSIFICATION_GOVERNANCE"

    # Pull subset of assets
    assets_sql = f"""
        select 
          ASSET_ID, DATABASE_NAME, SCHEMA_NAME, ASSET_NAME,
          coalesce(CLASSIFICATION_TAG, '') as CLASSIFICATION_TAG
        from {db}.{sc}.ASSETS
        qualify row_number() over (order by DATABASE_NAME, SCHEMA_NAME, ASSET_NAME) <= %(lim)s
    """
    rows = snowflake_connector.execute_query(assets_sql, {"lim": int(limit)}) or []

    # Pull tag references for candidate objects from ACCOUNT_USAGE
    # This may be large; we limit by the set of DBs present in the sample to reduce scope
    dbs = sorted({r.get("DATABASE_NAME") for r in rows if r.get("DATABASE_NAME")})
    tag_rows: List[Dict[str, Any]] = []
    if dbs:
        try:
            # Fetch common tag values for DATA_CLASSIFICATION tag names (lower/upper)
            # We also consider CONFIDENTIALITY_LEVEL etc., but for drift we compare classification only.
            tag_sql = """
                select OBJECT_DATABASE as DATABASE_NAME,
                       OBJECT_SCHEMA   as SCHEMA_NAME,
                       OBJECT_NAME     as ASSET_NAME,
                       TAG_NAME,
                       TAG_VALUE
                from SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                where upper(TAG_NAME) in ('DATA_CLASSIFICATION','data_classification')
                  and OBJECT_DATABASE in ({placeholders})
            """.replace("{placeholders}", ",".join([f"%(db{i})s" for i, _ in enumerate(dbs)]))
            params = {f"db{i}": d for i, d in enumerate(dbs)}
            tag_rows = snowflake_connector.execute_query(tag_sql, params) or []
        except Exception:
            tag_rows = []

    # Build lookup for tag value per object
    tag_lookup: Dict[tuple, str] = {}
    for t in tag_rows:
        key = (t.get("DATABASE_NAME"), t.get("SCHEMA_NAME"), t.get("ASSET_NAME"))
        val = t.get("TAG_VALUE")
        # prefer non-null
        if key not in tag_lookup or (val is not None and str(val) != ""):
            tag_lookup[key] = val

    items: List[Dict[str, Any]] = []
    drift_count = 0
    tagged = 0
    for r in rows:
        key = (r.get("DATABASE_NAME"), r.get("SCHEMA_NAME"), r.get("ASSET_NAME"))
        gov = (r.get("CLASSIFICATION_TAG") or "").strip()
        actual = (tag_lookup.get(key) or "").strip()
        is_tagged = actual != ""
        drift = False
        if gov and actual and (gov.lower() != actual.lower()):
            drift = True
        if not gov and actual:
            # Tag exists but governance empty — also drift
            drift = True
        if gov and not actual:
            # Governance says classified but tag not applied — drift
            drift = True
        if is_tagged:
            tagged += 1
        if drift:
            drift_count += 1
        items.append({
            "database": key[0],
            "schema": key[1],
            "asset_name": key[2],
            "governance_classification": gov,
            "tag_classification": actual,
            "drift": drift,
        })

    total = len(rows)
    return {
        "items": items,
        "summary": {
            "total_assets_sampled": total,
            "tagged_assets": tagged,
            "drift_assets": drift_count,
            "drift_pct": round(100.0 * (drift_count / total), 2) if total > 0 else 0.0,
        }
    }

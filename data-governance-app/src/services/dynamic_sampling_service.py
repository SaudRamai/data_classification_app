from __future__ import annotations

from typing import Any, Dict, Optional, Tuple, List
import math
import hashlib
import json
import time

try:
    import pandas as pd  # type: ignore
except Exception:  # pragma: no cover
    pd = None  # type: ignore

try:
    from src.connectors.snowflake_connector import snowflake_connector  # type: ignore
except Exception:  # pragma: no cover
    snowflake_connector = None  # type: ignore

# Preferred locations for MODEL_CONFIG and SAMPLE_METADATA
_PREFERRED: List[Tuple[str, str]] = []
try:
    from src.config.settings import settings  # type: ignore
except Exception:
    settings = None  # type: ignore

def _preferred_locations() -> List[Tuple[str, str]]:
    try:
        if settings is not None:
            gov_db = getattr(settings, "GOVERNANCE_DB", None) or getattr(settings, "DATA_GOVERNANCE_DB", None) or "DATA_CLASSIFICATION_DB"
            gov_sc = getattr(settings, "GOVERNANCE_SCHEMA", None) or getattr(settings, "DATA_GOVERNANCE_SCHEMA", None) or "DATA_CLASSIFICATION_GOVERNANCE"
            return [(str(gov_db), str(gov_sc))]
    except Exception:
        pass
    return [("DATA_CLASSIFICATION_DB", "DATA_CLASSIFICATION_GOVERNANCE")]


def _first_existing(db_objects: List[Tuple[str, str, str]]) -> Optional[Tuple[str, str, str]]:
    if snowflake_connector is None:
        return None
    for db, sc, tb in db_objects:
        try:
            rows = snowflake_connector.execute_query(
                f"""
                SELECT 1 FROM {db}.INFORMATION_SCHEMA.TABLES
                WHERE TABLE_SCHEMA = %(sc)s AND TABLE_NAME = %(tb)s
                LIMIT 1
                """,
                {"sc": sc, "tb": tb},
            ) or []
            if rows:
                return db, sc, tb
        except Exception:
            continue
    return None


def _locate_model_config() -> Optional[Tuple[str, str, str]]:
    pref = _preferred_locations()
    candidates = [(db, sc, "MODEL_CONFIG") for db, sc in pref] + [(db, sc, "SAMPLING_CONFIG") for db, sc in pref]
    return _first_existing(candidates)


def _locate_sample_metadata() -> Tuple[str, str, str]:
    # Default to DATA_GOVERNANCE.SAMPLE_METADATA; create if missing
    pref = _preferred_locations()
    db, sc, tb = pref[0][0], pref[0][1], "SAMPLE_METADATA"
    try:
        if snowflake_connector is not None:
            snowflake_connector.execute_non_query(
                f"""
                CREATE SCHEMA IF NOT EXISTS {db}.{sc};
                CREATE TABLE IF NOT EXISTS {db}.{sc}.{tb} (
                  TABLE_NAME STRING,
                  SAMPLE_HASH STRING,
                  SAMPLE_SIZE NUMBER,
                  SAMPLING_METHOD STRING,
                  STRATIFY_COLUMN STRING,
                  WEIGHT_COLUMN STRING,
                  SAMPLING_TIMESTAMP TIMESTAMP_NTZ,
                  CONFIG_VERSION NUMBER,
                  DETAILS VARIANT
                )
                """
            )
    except Exception:
        pass
    return db, sc, tb


def _fetch_table_rows(table_fqn: str) -> Optional[int]:
    if snowflake_connector is None:
        return None
    try:
        parts = (table_fqn or "").split(".")
        if len(parts) != 3:
            return None
        db, sc, tb = parts
        rows = snowflake_connector.execute_query(
            f"""
            SELECT ROW_COUNT AS TABLE_ROWS
            FROM {db}.INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = %(sc)s AND TABLE_NAME = %(tb)s
            LIMIT 1
            """,
            {"sc": sc, "tb": tb},
        ) or []
        if rows:
            rc = rows[0].get("TABLE_ROWS")
            try:
                return int(rc)
            except Exception:
                return None
        return None
    except Exception:
        return None


def _match_rule(table_fqn: str, row: Dict[str, Any]) -> bool:
    try:
        patt = str(row.get("TABLE_PATTERN") or row.get("table_pattern") or "").strip()
        if not patt:
            return False
        fqn = table_fqn.upper()
        p = patt.upper()
        # Simple wildcard support: '*' => any substring
        if p == "*":
            return True
        if "*" in p:
            parts = [x for x in p.split("*") if x]
            idx = 0
            for part in parts:
                j = fqn.find(part, idx)
                if j < 0:
                    return False
                idx = j + len(part)
            return True
        # Regex: if pattern is enclosed with '/'...'/' treat as regex
        if p.startswith("/") and p.endswith("/"):
            import re as _re
            rx = p[1:-1]
            return _re.search(rx, fqn) is not None
        return fqn == p or fqn.endswith("." + p) or fqn.split(".")[-1] == p
    except Exception:
        return False


def get_rule_for_table(table_fqn: str) -> Optional[Dict[str, Any]]:
    if snowflake_connector is None:
        return None
    loc = _locate_model_config()
    if not loc:
        return None
    db, sc, tb = loc
    try:
        rows = snowflake_connector.execute_query(f"SELECT * FROM {db}.{sc}.{tb} WHERE COALESCE(ACTIVE_FLAG, TRUE)") or []
    except Exception:
        rows = []
    # Pick the last updated active rule that matches
    matches = [r for r in rows if _match_rule(table_fqn, r)]
    if not matches:
        return None
    # Prefer higher version; fallback to latest updated_at
    def _key(r: Dict[str, Any]):
        v = r.get("VERSION") or r.get("version") or 0
        u = r.get("UPDATED_AT") or r.get("updated_at") or 0
        return (int(v) if isinstance(v, (int, float)) else 0, str(u))
    matches.sort(key=_key, reverse=True)
    return matches[0]


def compute_sample_size(table_rows: Optional[int], rule: Optional[Dict[str, Any]]) -> int:
    if not rule:
        return 200  # default cap
    min_rows = int(rule.get("MIN_ROWS") or rule.get("min_rows") or 100)
    max_rows = int(rule.get("MAX_ROWS") or rule.get("max_rows") or 1000)
    pct = float(rule.get("PERCENTAGE") or rule.get("percentage") or 0.01)
    if not table_rows or table_rows <= 0:
        return min(max_rows, max(min_rows, 200))
    calc = int(math.ceil(float(table_rows) * max(0.0, min(1.0, pct))))
    return max(min_rows, min(max_rows, calc))


def _hash_sample(rows: List[Dict[str, Any]]) -> str:
    try:
        payload = json.dumps(rows, sort_keys=True, default=str)
    except Exception:
        payload = json.dumps([str(r) for r in rows], sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _persist_sample_metadata(table_fqn: str, sample_rows: int, method: str, stratify: Optional[str], weight: Optional[str], config_version: Optional[int], details: Dict[str, Any], rows_preview: List[Dict[str, Any]]) -> None:
    if snowflake_connector is None:
        return
    db, sc, tb = _locate_sample_metadata()
    try:
        sample_hash = _hash_sample(rows_preview[:50])  # store small preview hash to keep cost down
        dj = json.dumps(details or {}, default=str).replace("'", "''")
        snowflake_connector.execute_non_query(
            f"""
            INSERT INTO {db}.{sc}.{tb}
            (TABLE_NAME, SAMPLE_HASH, SAMPLE_SIZE, SAMPLING_METHOD, STRATIFY_COLUMN, WEIGHT_COLUMN, SAMPLING_TIMESTAMP, CONFIG_VERSION, DETAILS)
            SELECT %(t)s, %(h)s, %(n)s, %(m)s, %(sc)s, %(wc)s, CURRENT_TIMESTAMP, %(cv)s, PARSE_JSON(%(dj)s)
            """,
            {"t": table_fqn, "h": sample_hash, "n": int(sample_rows), "m": method, "sc": stratify, "wc": weight, "cv": (config_version if config_version is not None else None), "dj": dj},
        )
    except Exception:
        pass


def sample_table(table_fqn: str) -> Optional[pd.DataFrame]:  # type: ignore
    """
    Apply dynamic sampling strategy for a table. Returns DataFrame or None on failure.
    """
    if snowflake_connector is None or pd is None:
        return None
    rule = get_rule_for_table(table_fqn)
    table_rows = _fetch_table_rows(table_fqn)
    n = compute_sample_size(table_rows, rule)
    method = str((rule or {}).get("SAMPLING_METHOD") or (rule or {}).get("sampling_method") or "random").lower()
    strat = (rule or {}).get("STRATIFY_COLUMN") or (rule or {}).get("stratify_column")
    weight = (rule or {}).get("WEIGHT_COLUMN") or (rule or {}).get("weight_column")
    cfg_version = (rule or {}).get("VERSION") or (rule or {}).get("version")

    db, sc, tb = (table_fqn or "").split(".") if table_fqn and table_fqn.count(".") == 2 else (None, None, None)
    if not (db and sc and tb):
        return None

    def _q(i: str) -> str:
        return '"' + str(i).replace('"', '""') + '"'

    fq = f"{_q(db)}.{_q(sc)}.{_q(tb)}"

    df: Optional[pd.DataFrame] = None
    sql: Optional[str] = None
    params: Dict[str, Any] = {"n": int(n)}

    try:
        if method == "stratified" and strat:
            # Proportional stratified sample by value count
            sql = (
                f"WITH base AS (SELECT {strat} AS strv, * FROM {fq}), cnt AS (SELECT strv, COUNT(*) c FROM base GROUP BY 1), "
                f"alloc AS (SELECT strv, GREATEST(1, CAST(ROUND(c * {float(n)}/NULLIF(SUM(c) OVER(),0)) AS INTEGER)) AS take FROM cnt), "
                f"ranked AS (SELECT base.*, ROW_NUMBER() OVER (PARTITION BY base.strv ORDER BY RANDOM()) AS rn FROM base) "
                f"SELECT * FROM ranked r JOIN alloc a ON r.strv = a.strv WHERE r.rn <= a.take"
            )
            rows = snowflake_connector.execute_query(sql) or []
            df = pd.DataFrame(rows)
        elif method == "weighted" and weight:
            # Weight via normalized rank on weight column (recent-first typical)
            # Use ORDER BY weight DESC NULLS LAST, then random tie-breaker
            sql = f"SELECT * FROM {fq} ORDER BY {weight} DESC NULLS LAST, RANDOM() LIMIT %(n)s"
            rows = snowflake_connector.execute_query(sql, params) or []
            df = pd.DataFrame(rows)
        else:
            # Random default
            sql = f"SELECT * FROM {fq} ORDER BY RANDOM() LIMIT %(n)s"
            rows = snowflake_connector.execute_query(sql, params) or []
            df = pd.DataFrame(rows)
    except Exception:
        # Fallback to naive limit if ORDER BY RANDOM not allowed
        try:
            sql = f"SELECT * FROM {fq} LIMIT %(n)s"
            rows = snowflake_connector.execute_query(sql, params) or []
            df = pd.DataFrame(rows)
        except Exception:
            df = None

    # Persist sample metadata for audit
    try:
        if df is not None:
            preview_rows = df.head(10).to_dict(orient="records") if hasattr(df, "to_dict") else []
            _persist_sample_metadata(
                table_fqn,
                sample_rows=len(df),
                method=(method or "random").upper(),
                stratify=str(strat) if strat else None,
                weight=str(weight) if weight else None,
                config_version=int(cfg_version) if isinstance(cfg_version, (int, float)) else None,
                details={"table_rows": table_rows, "rule": rule, "sql": sql},
                rows_preview=preview_rows,
            )
    except Exception:
        pass

    return df

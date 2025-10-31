import os
from typing import Dict, Any, List, Optional

from src.connectors.snowflake_connector import snowflake_connector
try:
    from src.services.ai_classification_service import ai_classification_service  # type: ignore
except Exception:
    ai_classification_service = None  # type: ignore

SQL_FILE_DEFAULT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "sql", "011_seed_sensitivity_config.sql")

TABLES = [
    "SENSITIVE_PATTERNS",
    "SENSITIVE_KEYWORDS",
    "SENSITIVITY_CATEGORIES",
    "SENSITIVITY_THRESHOLDS",
    "SENSITIVITY_WEIGHTS",
    "SENSITIVE_BUNDLES",
    "COMPLIANCE_MAPPING",
    "SENSITIVITY_MODEL_CONFIG",
]


def _split_sql(sql_text: str) -> List[str]:
    # Simple splitter; seed file is statements separated by ';' without embedded JS/SQL procs.
    return [s.strip() for s in sql_text.split(";") if s.strip()]


def _ensure_active_flags(database: str, schema: str = "DATA_CLASSIFICATION_GOVERNANCE") -> None:
    for t in [
        "SENSITIVE_PATTERNS", "SENSITIVE_KEYWORDS", "SENSITIVITY_CATEGORIES",
        "SENSITIVITY_THRESHOLDS", "SENSITIVITY_WEIGHTS", "SENSITIVE_BUNDLES",
        "COMPLIANCE_MAPPING"
    ]:
        try:
            snowflake_connector.execute_non_query(
                f"update {database}.{schema}.{t} set IS_ACTIVE = true where coalesce(IS_ACTIVE, false) = false"
            )
        except Exception:
            # Some tables may not have IS_ACTIVE; ignore
            pass


def refresh_governance(database: Optional[str] = None, sql_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Create/seed or upsert governance tables by executing the seed SQL.
    Returns a dict with counts per table and a summary.
    """
    db = database
    if db:
        snowflake_connector.execute_non_query(f"create database if not exists {db}")
        snowflake_connector.execute_non_query(f"use database {db}")
    path = sql_file or SQL_FILE_DEFAULT
    with open(path, "r", encoding="utf-8") as f:
        sql_text = f.read()
    stmts = _split_sql(sql_text)

    success = 0
    failures: List[str] = []
    for s in stmts:
        try:
            snowflake_connector.execute_non_query(s)
            success += 1
        except Exception as e:
            failures.append(f"{str(e)} | STMT: {s[:120]}")

    # Post step: ensure is_active true
    if db:
        try:
            _ensure_active_flags(db)
        except Exception:
            pass

    # Counts
    counts: Dict[str, int] = {}
    if db:
        for t in TABLES:
            try:
                rows = snowflake_connector.execute_query(f"select count(*) as C from {db}.DATA_CLASSIFICATION_GOVERNANCE.{t}")
                counts[t] = int(rows[0]["C"]) if rows else 0
            except Exception:
                counts[t] = -1  # missing or error

    # Force refresh AI config
    try:
        if ai_classification_service is not None:
            ai_classification_service.load_sensitivity_config(force_refresh=True)
    except Exception:
        pass

    return {
        "success_statements": success,
        "failure_count": len(failures),
        "failures": failures,
        "counts": counts,
    }

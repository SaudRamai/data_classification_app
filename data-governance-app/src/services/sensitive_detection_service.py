"""
Sensitive Data Detection Service
- Scans Snowflake tables for potential sensitive data (PII/Financial/Secrets)
- Uses a combination of column-name heuristics, regex on sample rows, and optional AISQL summarization
- Can persist findings to DATA_GOVERNANCE.ASSET_SIGNALS for monitoring and review
"""
from __future__ import annotations

from typing import Dict, Any, List, Optional
import re
import json
from datetime import datetime

from src.connectors.snowflake_connector import snowflake_connector

# Basic regex patterns (tunable)
PATTERNS = {
    "EMAIL": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}") ,
    "PHONE": re.compile(r"(?:(?:\+\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d{3}[\s-]?\d{4})") ,
    "SSN_US": re.compile(r"\b\d{3}-\d{2}-\d{4}\b") ,
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,16}\b") ,
    "IPV4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b") ,
}

NAME_CUES = {
    "EMAIL": ["EMAIL", "E_MAIL", "MAIL"],
    "PHONE": ["PHONE", "MOBILE", "CELL", "CONTACT_NUMBER"],
    "SSN_US": ["SSN", "SOCIAL_SECURITY"],
    "CREDIT_CARD": ["CARD", "CREDIT", "PAN"],
    "PII": ["FIRST_NAME", "LAST_NAME", "FULL_NAME", "ADDRESS", "DOB", "BIRTH", "AADHAAR", "PASSPORT"],
}

SIGNAL_TYPES = ["EMAIL", "PHONE", "SSN_US", "CREDIT_CARD", "IPV4", "PII"]


class SensitiveDetectionService:
    def _split_fqn(self, full_name: str) -> tuple[str, str, str]:
        parts = full_name.split(".")
        if len(parts) != 3:
            raise ValueError(f"Expected DB.SCHEMA.TABLE, got: {full_name}")
        return parts[0], parts[1], parts[2]

    def _fetch_columns(self, db: str, schema: str, table: str) -> List[Dict[str, Any]]:
        rows = snowflake_connector.execute_query(
            f"""
            SELECT COLUMN_NAME, DATA_TYPE
            FROM {db}.INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = '{schema}' AND TABLE_NAME = '{table}'
            ORDER BY ORDINAL_POSITION
            """
        ) or []
        return rows

    def _sample_rows(self, full_name: str, limit: int = 50) -> List[Dict[str, Any]]:
        try:
            rows = snowflake_connector.execute_query(
                f"SELECT * FROM {full_name} LIMIT {int(limit)}"
            ) or []
            return [dict(r) for r in rows]
        except Exception:
            return []

    def detect_in_table(self, full_name: str, sample_rows: int = 50, use_ai: bool = False) -> List[Dict[str, Any]]:
        """Return list of findings: [{column, signal_type, evidence, confidence, source}]."""
        db, schema, table = self._split_fqn(full_name)
        cols = self._fetch_columns(db, schema, table)
        samples = self._sample_rows(full_name, sample_rows)

        findings: List[Dict[str, Any]] = []

        # Column-name heuristics
        for c in cols:
            cname = str(c.get("COLUMN_NAME", ""))
            up = cname.upper()
            for sig, cues in NAME_CUES.items():
                if any(tok in up for tok in cues):
                    findings.append({
                        "column": cname,
                        "signal_type": sig if sig in SIGNAL_TYPES else "PII",
                        "evidence": "column_name_cue",
                        "confidence": 0.6,
                        "source": "HEURISTIC_NAME",
                    })

        # Regex on samples (string-like)
        for row in samples:
            for cname, val in row.items():
                sval = "" if val is None else str(val)
                if not sval:
                    continue
                # Skip obvious non-text types by simple length/charset heuristic
                if len(sval) > 2048:
                    continue
                for sig, rx in PATTERNS.items():
                    if rx.search(sval):
                        findings.append({
                            "column": cname,
                            "signal_type": sig,
                            "evidence": "regex_match",
                            "sample": sval[:128],
                            "confidence": 0.8,
                            "source": "REGEX",
                        })

        # Optional: AISQL summarization for hints
        if use_ai:
            try:
                import json as _json
                ctx = {
                    "table": full_name,
                    "columns": [{"name": r.get("COLUMN_NAME"), "type": r.get("DATA_TYPE")} for r in cols],
                    "samples": samples[:10],
                }
                ctx_json = _json.dumps(ctx, default=str)
                safe = ctx_json.replace("'", "''")
                sql = (
                    "SELECT SNOWFLAKE.CORTEX.AISQL('Identify columns that likely contain PII or secrets. "
                    "Return STRICT JSON with keys: findings:[{column, signal_type, confidence}]. Context: ' || '" + safe + "' ) AS RESPONSE"
                )
                rows = snowflake_connector.execute_query(sql) or []
                raw = rows[0].get("RESPONSE") if rows else ""
                parsed = _json.loads(raw) if raw else {}
                for item in (parsed.get("findings") or []):
                    col = item.get("column")
                    stype = item.get("signal_type") or "PII"
                    conf = float(item.get("confidence") or 0.7)
                    if col:
                        findings.append({
                            "column": col,
                            "signal_type": stype,
                            "evidence": "aisql_hint",
                            "confidence": conf,
                            "source": "AISQL",
                        })
            except Exception:
                # ignore AISQL errors
                pass

        # Deduplicate by (column, signal_type, source)
        dedup: Dict[tuple, Dict[str, Any]] = {}
        for f in findings:
            key = (f["column"], f["signal_type"], f.get("source"))
            if key not in dedup or f.get("confidence", 0) > dedup[key].get("confidence", 0):
                dedup[key] = f
        return list(dedup.values())

    def ensure_signals_table(self, database: str) -> None:
        snowflake_connector.execute_non_query(
            f"""
            CREATE SCHEMA IF NOT EXISTS {database}.DATA_GOVERNANCE;
            CREATE TABLE IF NOT EXISTS {database}.DATA_GOVERNANCE.ASSET_SIGNALS (
              ID STRING,
              ASSET_FULL_NAME STRING,
              COLUMN_NAME STRING,
              SIGNAL_TYPE STRING,
              CONFIDENCE FLOAT,
              EVIDENCE STRING,
              SAMPLE STRING,
              DETECTED_AT TIMESTAMP_NTZ,
              DETAILS VARIANT
            )
            """
        )

    def persist_findings(self, database: str, asset_full_name: str, findings: List[Dict[str, Any]]) -> int:
        if not findings:
            return 0
        self.ensure_signals_table(database)
        inserted = 0
        for f in findings:
            details = {
                k: v for k, v in f.items() if k not in {"column", "signal_type", "confidence", "evidence", "sample"}
            }
            dj = json.dumps(details, default=str).replace("'", "''")
            col = f.get("column")
            stype = f.get("signal_type")
            conf = float(f.get("confidence") or 0.5)
            evidence = f.get("evidence") or ""
            sample = (f.get("sample") or "")[:512]
            sql = f"""
                INSERT INTO {database}.DATA_GOVERNANCE.ASSET_SIGNALS
                (ID, ASSET_FULL_NAME, COLUMN_NAME, SIGNAL_TYPE, CONFIDENCE, EVIDENCE, SAMPLE, DETECTED_AT, DETAILS)
                SELECT UUID_STRING(), '{asset_full_name}', '{col}', '{stype}', {conf}, '{evidence}', '{sample.replace("'","''")}', CURRENT_TIMESTAMP,
                       PARSE_JSON('{dj}')
            """
            snowflake_connector.execute_non_query(sql)
            inserted += 1
        return inserted

    def scan_and_persist(self, table_full_name: str, database: Optional[str] = None, use_ai: bool = False) -> Dict[str, Any]:
        db, schema, table = self._split_fqn(table_full_name)
        target_db = database or db
        findings = self.detect_in_table(table_full_name, use_ai=use_ai)
        count = self.persist_findings(target_db, table_full_name, findings)
        return {"asset": table_full_name, "count": count, "findings": findings}


sensitive_detection_service = SensitiveDetectionService()

"""
System Classify Service

Integrates Snowflake native SYSTEM$CLASSIFY for sensitive data detection across target schemas
(RAW, STAGING, DATA_VAULT). Persists outputs to:
- DATA_GOVERNANCE.CLASSIFICATION_DECISIONS (final decisions summary per table)
- CLASSIFICATION_HISTORY.CLASSIFICATION_HISTORY (detailed, historical record per column)
- DATA_GOVERNANCE.CLASSIFICATION_QUEUE (unclassified or low-confidence items)
Also applies Snowflake tags (DATA_CLASSIFICATION, CONFIDENTIALITY_LEVEL) using TaggingService,
validating values against CLASSIFICATION_METADATA.ALLOWED_TAG_VALUES when present.
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional
import uuid
import json
import logging

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.tagging_service import tagging_service
from src.services.audit_service import audit_service

logger = logging.getLogger(__name__)

DB = settings.SNOWFLAKE_DATABASE

TARGET_SCHEMAS = [
    'RAW', 'STAGING', 'DATA_VAULT'
]


class SystemClassifyService:
    def __init__(self) -> None:
        self.connector = snowflake_connector
        self._ia_rules: list[dict] | None = None  # cached optional rules from DB

    def _load_ia_rules(self) -> list[dict]:
        """Load optional I/A inference rules from {DB}.DATA_GOVERNANCE.IA_RULES.
        Expected columns: TYPE, PATTERN, I_LEVEL, A_LEVEL, PRIORITY (optional)
        - TYPE can correlate to detected categories (e.g., 'FINANCIAL','PII','AUTH','PHI','PCI')
        - PATTERN is applied to ASSET_FULL_NAME (case-insensitive substring match or regex if delimited by /.../)
        """
        if self._ia_rules is not None:
            return self._ia_rules
        try:
            rows = self.connector.execute_query(
                f"""
                SELECT COALESCE(TYPE,'') AS TYPE,
                       COALESCE(PATTERN,'') AS PATTERN,
                       COALESCE(I_LEVEL, 1) AS I_LEVEL,
                       COALESCE(A_LEVEL, 1) AS A_LEVEL,
                       COALESCE(PRIORITY, 0) AS PRIORITY
                FROM {DB}.DATA_GOVERNANCE.IA_RULES
                LIMIT 10000
                """
            ) or []
            # sort by priority desc to allow stronger rules first
            rows.sort(key=lambda r: int(r.get('PRIORITY', 0)), reverse=True)
            self._ia_rules = rows
        except Exception:
            self._ia_rules = []
        return self._ia_rules

    # --- Policy-aligned helpers for I/A inference ---
    def _infer_ia_levels(self, asset_full_name: str, categories: list[str]) -> tuple[int, int, str, bool]:
        """Infer Integrity (I) and Availability (A) using data-driven rules when available.
        Returns: (I, A, rationale, provisional)
        Rule sources (in order):
          1) IA_RULES table patterns and types
          2) Category correlation to IA_RULES.TYPE
          3) Fallback heuristic → provisional
        """
        cats = {str(c).upper() for c in (categories or [])}
        name = str(asset_full_name or "")
        upname = name.upper()
        rationale_parts: list[str] = []
        # 1) Try DB rules (pattern match on name)
        rules = self._load_ia_rules()
        best_i = None
        best_a = None
        matched: list[str] = []
        for r in rules:
            patt = str(r.get('PATTERN') or '')
            rtype = str(r.get('TYPE') or '').upper()
            try:
                hit = False
                if patt:
                    if len(patt) >= 2 and patt.startswith('/') and patt.endswith('/'):
                        import re as _re
                        try:
                            if _re.search(patt.strip('/'), name, flags=_re.IGNORECASE):
                                hit = True
                        except Exception:
                            pass
                    else:
                        if patt.upper() in upname:
                            hit = True
                # Correlate via TYPE to categories if not matched by pattern
                if not hit and rtype and rtype in cats:
                    hit = True
                if hit:
                    matched.append(rtype or patt or 'rule')
                    try:
                        i_lv = int(r.get('I_LEVEL', 1))
                        a_lv = int(r.get('A_LEVEL', 1))
                        best_i = max(best_i or i_lv, i_lv)
                        best_a = max(best_a or a_lv, a_lv)
                    except Exception:
                        continue
            except Exception:
                continue
        if best_i is not None and best_a is not None:
            rationale_parts.append(f"IA_RULES matched: {', '.join([m for m in matched if m])}")
            return int(best_i), int(best_a), "; ".join(rationale_parts), False
        # 2) Category-based default elevations (conservative)
        pii_like = {"PII", "PHI", "PCI", "AUTH", "PERSONAL", "SENSITIVE", "FINANCIAL", "SOX"}
        if cats.intersection(pii_like):
            rationale_parts.append("Categories indicate elevated I/A")
            i_lv = 3 if ("FINANCIAL" in cats or "SOX" in cats) else 2
            a_lv = 3 if ("FINANCIAL" in cats or "SOX" in cats) else 2
            return i_lv, a_lv, "; ".join(rationale_parts), False
        # 3) Fallback provisional (requires review)
        rationale_parts.append("No matching IA_RULES or categories; default I/A pending business review")
        return 1, 1, "; ".join(rationale_parts), True

    def _list_tables(self) -> List[str]:
        try:
            rows = self.connector.execute_query(
                f"""
                SELECT "TABLE_CATALOG"||'.'||"TABLE_SCHEMA"||'.'||"TABLE_NAME" AS FULL
                FROM {DB}.INFORMATION_SCHEMA.TABLES
                WHERE UPPER("TABLE_SCHEMA") IN ({', '.join([f"'{s.upper()}'" for s in TARGET_SCHEMAS])})
                ORDER BY 1
                """
            ) or []
            return [r.get('FULL') for r in rows if r.get('FULL')]
        except Exception as e:
            logger.error(f"Failed to list tables: {e}")
            return []

    def _allowed_value(self, tag_name: str, proposed: str) -> bool:
        try:
            rows = self.connector.execute_query(
                f"SELECT 1 FROM {DB}.CLASSIFICATION_METADATA.ALLOWED_TAG_VALUES WHERE TAG_NAME=%(t)s AND ALLOWED_VALUE=%(v)s LIMIT 1",
                {"t": tag_name, "v": str(proposed)}
            ) or []
            return len(rows) > 0
        except Exception:
            # If registry missing, fall back to TaggingService's own validation
            return True

    def _map_conf_level(self, label: str) -> int:
        lbl = (label or 'Internal').title()
        return 0 if lbl == 'Public' else 1 if lbl == 'Internal' else 2 if lbl == 'Restricted' else 3

    def run(self, low_conf_threshold: float = 0.5, limit: int = 200) -> Dict[str, Any]:
        tables = self._list_tables()[:int(limit)]
        total_hist_rows = 0
        queued = 0
        decisions = 0
        for full in tables:
            try:
                # Call SYSTEM$CLASSIFY at table level; returns JSON per column
                res = self.connector.execute_query(
                    "SELECT SYSTEM$CLASSIFY('TABLE', %(full)s) AS R",
                    {"full": full}
                ) or []
                raw = res[0].get('R') if res else None
                if not raw:
                    continue
                parsed = json.loads(raw) if isinstance(raw, str) else raw
                # parsed is expected as list of column dicts
                by_col = parsed if isinstance(parsed, list) else []
                sensitive_any = False
                max_conf = 0.0
                cats_agg = set()
                # Persist to history
                for c in by_col:
                    col = c.get('column') or c.get('COLUMN_NAME') or c.get('name')
                    cats = c.get('categories') or c.get('CATEGORY') or c.get('labels') or []
                    conf = float(c.get('confidence') or c.get('CONFIDENCE') or 0.0)
                    lbl = 'Restricted' if cats else 'Internal'
                    C = self._map_conf_level(lbl)
                    try:
                        self.connector.execute_non_query(
                            f"""
                            INSERT INTO {DB}.CLASSIFICATION_HISTORY.CLASSIFICATION_HISTORY
                            (ID, ASSET_FULL_NAME, COLUMN_NAME, SOURCE, DECISION_BY, DECISION_AT, LABEL, C, I, A, CONFIDENCE, SENSITIVE_CATEGORIES, DETAILS)
                            SELECT %(id)s, %(full)s, %(col)s, 'SYSTEM_CLASSIFY', 'system', CURRENT_TIMESTAMP,
                                   %(lbl)s, %(c)s, 1, 1, %(conf)s, PARSE_JSON(%(cats)s), TO_VARIANT(PARSE_JSON(%(det)s))
                            """,
                            {
                                "id": str(uuid.uuid4()),
                                "full": full,
                                "col": col,
                                "lbl": lbl,
                                "c": C,
                                "conf": conf,
                                "cats": json.dumps(cats or []),
                                "det": json.dumps(c),
                            }
                        )
                        total_hist_rows += 1
                    except Exception as e:
                        logger.warning(f"History insert failed for {full}.{col}: {e}")
                    if cats:
                        sensitive_any = True
                        cats_agg |= set([str(x) for x in cats])
                    max_conf = max(max_conf, conf)

                # Apply object-level decision and tags
                label = 'Restricted' if sensitive_any else 'Internal'
                C = self._map_conf_level(label)
                I, A, ia_rationale, provisional = self._infer_ia_levels(full, sorted(list(cats_agg)))
                try:
                    tagging_service.apply_tags_to_object(
                        full, 'TABLE', {
                            'DATA_CLASSIFICATION': label,
                            'CONFIDENTIALITY_LEVEL': str(C),
                            'INTEGRITY_LEVEL': str(I),
                            'AVAILABILITY_LEVEL': str(A),
                        }
                    )
                except Exception as e:
                    logger.warning(f"Tagging failed for {full}: {e}")
                # Record decision summary into DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
                try:
                    self.connector.execute_non_query(
                        f"""
                        INSERT INTO {DB}.DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
                        (ID, ASSET_FULL_NAME, USER_ID, ACTION, CLASSIFICATION_LEVEL, CIA_CONF, CIA_INT, CIA_AVAIL, RATIONALE, CREATED_AT, DETAILS)
                        SELECT %(id)s, %(full)s, 'system', 'AUTO', %(lbl)s, %(c)s, %(i)s, %(a)s,
                               %(rat)s, CURRENT_TIMESTAMP,
                               TO_VARIANT(PARSE_JSON(%(det)s))
                        """,
                        {
                            "id": str(uuid.uuid4()),
                            "full": full,
                            "lbl": label,
                            "c": C,
                            "i": I,
                            "a": A,
                            "rat": f"SYSTEM$CLASSIFY summary; IA rationale: {ia_rationale}; provisional={provisional}",
                            "det": json.dumps({"categories": sorted(list(cats_agg)), "max_confidence": max_conf, "provisional": provisional}),
                        }
                    )
                    decisions += 1
                except Exception as e:
                    logger.warning(f"Decision insert failed for {full}: {e}")
                # Queue for review if uncertain
                if max_conf < float(low_conf_threshold) or not sensitive_any or provisional:
                    try:
                        self.connector.execute_non_query(
                            f"""
                            INSERT INTO {DB}.DATA_GOVERNANCE.CLASSIFICATION_QUEUE
                            (ID, ASSET_FULL_NAME, COLUMN_NAME, REASON, SUGGESTED_LABEL, CONFIDENCE, SENSITIVE_CATEGORIES, CREATED_AT, DETAILS)
                            SELECT %(id)s, %(full)s, NULL, %(reason)s, %(lbl)s, %(conf)s, PARSE_JSON(%(cats)s), CURRENT_TIMESTAMP,
                                   TO_VARIANT(PARSE_JSON(%(det)s))
                            """,
                            {
                                "id": str(uuid.uuid4()),
                                "full": full,
                                "reason": ('UNCLASSIFIED' if not sensitive_any else ('LOW_CONFIDENCE' if max_conf < float(low_conf_threshold) else 'PROVISIONAL_IA')),
                                "lbl": label,
                                "conf": max_conf,
                                "cats": json.dumps(sorted(list(cats_agg))),
                                "det": json.dumps({"system_classify": True, "provisional": provisional, "I": I, "A": A, "ia_rationale": ia_rationale}),
                            }
                        )
                        queued += 1
                    except Exception as e:
                        logger.warning(f"Queue insert failed for {full}: {e}")
                # Audit
                try:
                    audit_service.log('system', 'SYSTEM_CLASSIFY', 'TABLE', full, {"label": label, "C": C, "cats": sorted(list(cats_agg)), "confidence": max_conf})
                except Exception:
                    pass
            except Exception as e:
                logger.error(f"SYSTEM$CLASSIFY failed for {full}: {e}")
                continue
        return {"tables": len(tables), "history_rows": total_hist_rows, "queued": queued, "decisions": decisions}


system_classify_service = SystemClassifyService()

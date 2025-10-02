"""
AI Rule Mining Service

Learns dynamic labeling rules from existing tag assignments in Snowflake and
predicts labels for new/untagged columns or tables. Avoids hardcoded lookup tables
by inferring regex/token patterns from observed labeled data.

Capabilities:
- mine_rules(): build regex/name-token heuristics from TAG_REFERENCES and COLUMN metadata
- predict_for_table(): suggest labels (classification and CIA) for a table and its columns
- persist_rules(): optional persistence to DATA_GOVERNANCE.RULES for transparency/audit

Notes:
- Works best when there is an initial critical mass of tags applied
- Produces human-readable rules (regexes and token sets) with weights and support
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple
import re
import json
from collections import defaultdict, Counter

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

DB = settings.SNOWFLAKE_DATABASE
SCHEMA = "DATA_GOVERNANCE"


@dataclass
class LearnedRule:
    scope: str  # 'COLUMN' or 'TABLE'
    pattern: str  # regex applied to column or table full name
    label: str  # DATA_CLASSIFICATION (e.g., Confidential)
    c: int
    i: int
    a: int
    support: int  # number of matches in training
    confidence: float  # precision from training

    def to_row(self) -> Dict[str, Any]:
        return {
            "SCOPE": self.scope,
            "PATTERN": self.pattern,
            "LABEL": self.label,
            "C": int(self.c),
            "I": int(self.i),
            "A": int(self.a),
            "SUPPORT": int(self.support),
            "CONFIDENCE": float(self.confidence),
        }


class AIRuleMiningService:
    def __init__(self) -> None:
        self.connector = snowflake_connector

    def _fetch_labeled_columns(self) -> List[Dict[str, Any]]:
        """Fetch column-level tag references with CIA and classification."""
        try:
            rows = self.connector.execute_query(
                """
                SELECT 
                  OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME,
                  MAX(CASE WHEN TAG_NAME='DATA_CLASSIFICATION' THEN TAG_VALUE END) AS CLASSIFICATION,
                  MAX(CASE WHEN TAG_NAME='CONFIDENTIALITY_LEVEL' THEN TAG_VALUE END) AS C,
                  MAX(CASE WHEN TAG_NAME='INTEGRITY_LEVEL' THEN TAG_VALUE END) AS I,
                  MAX(CASE WHEN TAG_NAME='AVAILABILITY_LEVEL' THEN TAG_VALUE END) AS A
                FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                WHERE COLUMN_NAME IS NOT NULL
                GROUP BY OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME
                """
            ) or []
        except Exception:
            rows = []
        return rows

    def _fetch_labeled_tables(self) -> List[Dict[str, Any]]:
        try:
            rows = self.connector.execute_query(
                """
                SELECT 
                  OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME,
                  MAX(CASE WHEN TAG_NAME='DATA_CLASSIFICATION' THEN TAG_VALUE END) AS CLASSIFICATION,
                  MAX(CASE WHEN TAG_NAME='CONFIDENTIALITY_LEVEL' THEN TAG_VALUE END) AS C,
                  MAX(CASE WHEN TAG_NAME='INTEGRITY_LEVEL' THEN TAG_VALUE END) AS I,
                  MAX(CASE WHEN TAG_NAME='AVAILABILITY_LEVEL' THEN TAG_VALUE END) AS A
                FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                WHERE COLUMN_NAME IS NULL
                GROUP BY OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME
                """
            ) or []
        except Exception:
            rows = []
        return rows

    def _name_tokens(self, s: str) -> List[str]:
        s = (s or "").upper()
        s = re.sub(r"[^A-Z0-9_]+", "_", s)
        parts = re.split(r"[_\s]+", s)
        return [p for p in parts if p]

    def mine_rules(self, min_support: int = 3, max_rules: int = 200) -> List[LearnedRule]:
        """Learn regex/name-token rules from labeled columns and tables.
        Returns a list of LearnedRule sorted by confidence and support.
        """
        col_rows = self._fetch_labeled_columns()
        tbl_rows = self._fetch_labeled_tables()

        rules: List[LearnedRule] = []

        # Column patterns: derive from column names associated with high-sensitivity labels
        by_label_tokens: Dict[str, Counter] = defaultdict(Counter)
        by_label_support: Counter = Counter()
        for r in col_rows:
            lbl = (r.get("CLASSIFICATION") or "").title()
            c_val = int((r.get("C") or 0))
            a_val = int((r.get("A") or 0))
            # Focus on restricted/confidential or high-C columns
            if lbl in ("Restricted", "Confidential") or c_val >= 2 or a_val >= 2:
                toks = self._name_tokens(r.get("COLUMN_NAME") or "")
                for t in toks:
                    by_label_tokens[lbl][t] += 1
                    by_label_support[lbl] += 1
        # Build regexes for top tokens per label
        for lbl, cnt in by_label_tokens.items():
            top = [tok for tok, n in cnt.most_common(30) if n >= min_support]
            for tok in top:
                pattern = rf".*\b{re.escape(tok)}\b.*"
                support = cnt[tok]
                conf = min(1.0, support / float(by_label_support[lbl] or 1))
                rules.append(LearnedRule(scope="COLUMN", pattern=pattern, label=lbl, c=2 if lbl=="Restricted" else 3 if lbl=="Confidential" else 1, i=1, a=1, support=int(support), confidence=round(conf,2)))

        # Table patterns: derive from table names and schemas
        tbl_tokens: Dict[str, Counter] = defaultdict(Counter)
        tbl_support: Counter = Counter()
        for r in tbl_rows:
            lbl = (r.get("CLASSIFICATION") or "").title()
            if not lbl:
                continue
            full = f"{r.get('OBJECT_DATABASE')}.{r.get('OBJECT_SCHEMA')}.{r.get('OBJECT_NAME')}"
            toks = self._name_tokens(full)
            for t in toks:
                tbl_tokens[lbl][t] += 1
                tbl_support[lbl] += 1
        for lbl, cnt in tbl_tokens.items():
            top = [tok for tok, n in cnt.most_common(30) if n >= min_support]
            for tok in top:
                pattern = rf".*\b{re.escape(tok)}\b.*"
                support = cnt[tok]
                conf = min(1.0, support / float(tbl_support[lbl] or 1))
                rules.append(LearnedRule(scope="TABLE", pattern=pattern, label=lbl, c=2 if lbl=="Restricted" else 3 if lbl=="Confidential" else 1, i=1, a=1, support=int(support), confidence=round(conf,2)))

        # Sort and limit
        rules.sort(key=lambda r: (r.confidence, r.support), reverse=True)
        return rules[:max_rules]

    def persist_rules(self, rules: List[LearnedRule]) -> int:
        """Create a governance table and persist rules for transparency."""
        self.connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {DB}.{SCHEMA}")
        self.connector.execute_non_query(
            f"""
            CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.LEARNED_RULES (
                SCOPE STRING,
                PATTERN STRING,
                LABEL STRING,
                C NUMBER,
                I NUMBER,
                A NUMBER,
                SUPPORT NUMBER,
                CONFIDENCE FLOAT,
                CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # Truncate and insert fresh rules
        self.connector.execute_non_query(f"TRUNCATE TABLE {DB}.{SCHEMA}.LEARNED_RULES")
        count = 0
        for r in rules:
            self.connector.execute_non_query(
                f"""
                INSERT INTO {DB}.{SCHEMA}.LEARNED_RULES
                (SCOPE, PATTERN, LABEL, C, I, A, SUPPORT, CONFIDENCE)
                VALUES (%(s)s, %(p)s, %(l)s, %(c)s, %(i)s, %(a)s, %(sup)s, %(conf)s)
                """,
                {"s": r.scope, "p": r.pattern, "l": r.label, "c": r.c, "i": r.i, "a": r.a, "sup": r.support, "conf": r.confidence}
            )
            count += 1
        return count

    def predict_for_table(self, table: str, rules: Optional[List[LearnedRule]] = None, sample_columns: Optional[List[str]] = None) -> Dict[str, Any]:
        """Apply learned rules to a table and its columns to suggest labels."""
        if rules is None:
            rules = self.mine_rules()
        # Fetch columns if not provided
        if sample_columns is None:
            try:
                db, sc, tb = table.split(".")
                rows = self.connector.execute_query(
                    f"""
                    SELECT COLUMN_NAME
                    FROM {db}.INFORMATION_SCHEMA.COLUMNS
                    WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
                    ORDER BY ORDINAL_POSITION
                    """,
                    {"s": sc, "t": tb}
                ) or []
                sample_columns = [r["COLUMN_NAME"] for r in rows]
            except Exception:
                sample_columns = []
        # Score matches
        tbl_score: Counter = Counter()
        col_scores: Dict[str, Counter] = {c: Counter() for c in sample_columns}
        full_upper = table.upper()
        for r in rules:
            try:
                rx = re.compile(r.pattern)
            except Exception:
                continue
            if r.scope == "TABLE" and rx.match(full_upper):
                tbl_score[r.label] += r.confidence
            if r.scope == "COLUMN":
                for c in sample_columns:
                    if rx.match(c.upper()):
                        col_scores[c][r.label] += r.confidence
        # Decide labels
        table_label = tbl_score.most_common(1)[0][0] if tbl_score else None
        column_labels = {c: (sc.most_common(1)[0][0] if sc else None) for c, sc in col_scores.items()}
        return {
            "table": table,
            "table_label": table_label,
            "column_labels": column_labels,
            "rules_applied": len(rules),
        }


ai_rule_mining_service = AIRuleMiningService()

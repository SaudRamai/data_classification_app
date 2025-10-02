"""
Sensitive Scan Service

End-to-end orchestrator for Steps 1–6:
1) Data sampling for each column
2) Value-level AI/ML detection (hybrid)
3) Column-level aggregation (dominant type, coverage, risk, CIA)
4) Compliance mapping
5) Snowflake tagging (column + table)
6) Monitoring interface via a single callable (for manual or scheduled runs)

This service reuses existing building blocks across the app and is conservative on
privileges and error handling. It favors best-effort execution and continues on
non-critical failures to maximize coverage.
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional, Tuple
import logging

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings
from src.services.ai_classification_service import ai_classification_service
from src.services.tagging_service import tagging_service
from src.services.policy_enforcement_service import policy_enforcement_service
from src.services.classification_decision_service import classification_decision_service
from src.services.audit_service import audit_service
from src.services.authorization_service import authz

logger = logging.getLogger(__name__)


def _split_fqn(fq: str) -> Tuple[str, str, str]:
    """Split a fully qualified name DB.SCHEMA.TABLE with support for quoted identifiers containing dots.
    Accepts inputs like DB.SCHEMA.TABLE or "DB"."SC.HEMA"."TAB.LE".
    """
    s = str(fq or "")
    if not s:
        raise ValueError("Empty FQN")
    parts: list[str] = []
    buf = []
    in_q = False
    esc = False
    for ch in s:
        if in_q:
            if esc:
                buf.append(ch)
                esc = False
            elif ch == '"':
                # Lookahead for doubled quotes
                in_q = False
                parts_char = ''.join(buf)
                buf = [parts_char]
            else:
                buf.append(ch)
        else:
            if ch == '"':
                in_q = True
            elif ch == '.':
                parts.append(''.join(buf).strip('"'))
                buf = []
            else:
                buf.append(ch)
    if buf:
        parts.append(''.join(buf).strip('"'))
    if len(parts) != 3:
        # Fallback to naive split for safety
        parts = s.split('.')
        if len(parts) != 3:
            raise ValueError(f"Expected fully qualified name 'DB.SCHEMA.TABLE', got: {fq}")
    return parts[0], parts[1], parts[2]


class SensitiveScanService:
    def __init__(self) -> None:
        self.connector = snowflake_connector
        self.database = settings.SNOWFLAKE_DATABASE

    # ---------- Step 1: discovery & sampling ----------
    def list_target_tables(self, db: Optional[str] = None, schema_glob: Optional[str] = None, limit: int = 5000) -> List[str]:
        """Return FQ table names DB.SCHEMA.TABLE for the target database and schema pattern.
        Views are included to maximize coverage.
        """
        database = (db or self.database)
        where_sc = ""
        if schema_glob and schema_glob != "%":
            where_sc = "AND TABLE_SCHEMA ILIKE %(sc)s"
        try:
            rows = self.connector.execute_query(
                f"""
                SELECT "TABLE_CATALOG"||'.'||"TABLE_SCHEMA"||'.'||"TABLE_NAME" AS FULL
                FROM {database}.INFORMATION_SCHEMA.TABLES
                WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
                {where_sc}
                ORDER BY 1
                LIMIT %(lim)s
                """,
                {"sc": schema_glob, "lim": int(limit)} if where_sc else {"lim": int(limit)},
            ) or []
            return [r.get("FULL") for r in rows if r.get("FULL")]
        except Exception as e:
            logger.error(f"list_target_tables failed: {e}")
            return []

    def list_table_columns(self, fq_table: str) -> List[Dict[str, Any]]:
        try:
            db, sc, tb = _split_fqn(fq_table)
            rows = self.connector.execute_query(
                f"""
                SELECT COLUMN_NAME, DATA_TYPE, ORDINAL_POSITION
                FROM {db}.INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = %(sc)s AND TABLE_NAME = %(tb)s
                ORDER BY ORDINAL_POSITION
                """,
                {"sc": sc, "tb": tb},
            ) or []
            return rows
        except Exception as e:
            logger.warning(f"list_table_columns failed for {fq_table}: {e}")
            return []

    def sample_column_values(self, fq_table: str, column: str, limit: int = 200) -> List[str]:
        """Sample values from a column using TABLESAMPLE or LIMIT.
        Applies LEFT() on textual types to cap value length for NLP.
        """
        try:
            db, sc, tb = _split_fqn(fq_table)
            def _q(ident: str) -> str:
                ident = str(ident)
                return '"' + ident.replace('"', '""') + '"'
            fqid = f"{_q(db)}.{_q(sc)}.{_q(tb)}"
            colid = _q(column)
            # Use LIMIT on sampled order. If TABLESAMPLE not permitted, fallback to simple LIMIT.
            # Snowflake: Sampling can be done via TABLESAMPLE BERNOULLI/ROW; we keep it simple here.
            rows = self.connector.execute_query(
                f"SELECT {colid} AS V FROM {fqid} LIMIT %(lim)s",
                {"lim": int(limit)},
            ) or []
            vals = [str(r.get("V")) for r in rows if r.get("V") is not None]
            # Truncate text to reduce NLP overhead
            return [v[:512] for v in vals]
        except Exception as e:
            logger.debug(f"sample_column_values failed for {fq_table}.{column}: {e}")
            return []

    # ---------- Step 2–5: detection → aggregation → mapping → tagging ----------
    def _apply_column_tags(
        self,
        fq_table: str,
        column: str,
        col_agg: Dict[str, Any],
    ) -> bool:
        try:
            # Privilege check: require ability to apply tags on parent table
            if not authz.can_apply_tags_for_object(fq_table, object_type="TABLE"):
                return False
            dom = col_agg.get("dominant_type")
            cia = col_agg.get("suggested_cia", {"C": 0, "I": 0, "A": 0})
            comp = ai_classification_service.map_compliance_categories(dom or "")
            comp_val = ",".join(comp) if comp else "Internal/Other"
            label = "Confidential" if cia.get("C", 0) == 3 else ("Restricted" if cia.get("C", 0) == 2 else ("Internal" if cia.get("C", 0) == 1 else "Public"))
            # Dual-control: queue high-risk changes (C>=3 or PCI/PHI) unless approver
            is_high_risk = (int(cia.get("C", 0)) >= 3) or (str(dom).upper() in {"PCI","PHI"})
            if is_high_risk and not authz.can_approve_tags():
                try:
                    classification_decision_service.record(
                        asset_full_name=f"{fq_table}.{column}",
                        decision_by="system",
                        source="AUTO",
                        status="PendingApproval",
                        label=label,
                        c=int(cia.get("C", 0)), i=int(cia.get("I", 0)), a=int(cia.get("A", 0)),
                        rationale="High-risk change requires approval",
                        details={"dominant_type": dom, "frameworks": comp},
                    )
                except Exception:
                    pass
                try:
                    audit_service.log("system", "AUTO_CLASSIFY_QUEUE", "COLUMN", f"{fq_table}.{column}", {"label": label, "cia": cia, "frameworks": comp})
                except Exception:
                    pass
                return False
            tagging_service.apply_tags_to_column(
                fq_table,
                column,
                {
                    "DATA_CLASSIFICATION": label,
                    "CONFIDENTIALITY_LEVEL": str(int(cia.get("C", 0))),
                    "INTEGRITY_LEVEL": str(int(cia.get("I", 0))),
                    "AVAILABILITY_LEVEL": str(int(cia.get("A", 0))),
                    "SPECIAL_CATEGORY": (dom or "Other") if dom else "Other",
                    "COMPLIANCE_CATEGORY": comp_val,
                },
            )
            try:
                audit_service.log("system", "AUTO_CLASSIFY_APPLY", "COLUMN", f"{fq_table}.{column}", {"label": label, "cia": cia, "frameworks": comp})
            except Exception:
                pass
            return True
        except Exception as e:
            logger.warning(f"Column tagging failed for {fq_table}.{column}: {e}")
            return False

    def _apply_table_tags_and_record(self, fq_table: str, cia_table: Dict[str, int], dom_types: List[str]) -> bool:
        try:
            if not authz.can_apply_tags_for_object(fq_table, object_type="TABLE"):
                return False
            C, I, A = int(cia_table.get("C", 0)), int(cia_table.get("I", 0)), int(cia_table.get("A", 0))
            label = "Confidential" if C == 3 else ("Restricted" if C == 2 else ("Internal" if C == 1 else "Public"))
            # Dual-control: queue high-risk table-level (C>=3 or contains PCI/PHI types)
            has_pci_phi = any(str(t).upper() in {"PCI","PHI"} for t in (dom_types or []))
            if (C >= 3 or has_pci_phi) and not authz.can_approve_tags():
                try:
                    classification_decision_service.record(
                        asset_full_name=fq_table,
                        decision_by="system",
                        source="AUTO",
                        status="PendingApproval",
                        label=label,
                        c=C, i=I, a=A,
                        rationale="High-risk table classification requires approval",
                        details={"dominant_types": dom_types},
                    )
                except Exception:
                    pass
                try:
                    audit_service.log("system", "AUTO_CLASSIFY_QUEUE", "ASSET", fq_table, {"cia": cia_table, "types": dom_types})
                except Exception:
                    pass
                return False
            tagging_service.apply_tags_to_object(
                fq_table,
                "TABLE",
                {
                    "DATA_CLASSIFICATION": label,
                    "CONFIDENTIALITY_LEVEL": str(C),
                    "INTEGRITY_LEVEL": str(I),
                    "AVAILABILITY_LEVEL": str(A),
                },
            )
            # Record decision & audit
            try:
                classification_decision_service.record(
                    asset_full_name=fq_table,
                    decision_by="system",
                    source="AUTO",
                    status=("Approved" if authz.can_approve_tags() else "Applied"),
                    label=label,
                    c=C,
                    i=I,
                    a=A,
                    rationale="Automated sensitive scan",
                    details={"dominant_types": dom_types},
                )
            except Exception:
                pass
            try:
                audit_service.log("system", "AUTO_CLASSIFY_APPLY", "ASSET", fq_table, {"cia": cia_table, "types": dom_types})
            except Exception:
                pass
            return True
        except Exception as e:
            logger.warning(f"Table tagging failed for {fq_table}: {e}")
            return False

    # ---------- Public orchestration ----------
    def run_full(self, db: Optional[str] = None, schema_glob: Optional[str] = None, sample_rows: int = 200, table_limit: int = 500) -> Dict[str, Any]:
        """Run the full scan for target tables and columns; return summary counts."""
        database = (db or self.database)
        targets = self.list_target_tables(database, schema_glob or "%", limit=table_limit)
        total_tables = 0
        total_columns = 0
        tagged_columns = 0
        table_updates = 0
        enforcement_cols = 0
        for fq in targets:
            total_tables += 1
            cols = self.list_table_columns(fq)
            if not cols:
                continue
            cia_table = {"C": 0, "I": 0, "A": 0}
            dom_types: List[str] = []
            for cm in cols:
                total_columns += 1
                cname = cm.get("COLUMN_NAME")
                vals = self.sample_column_values(fq, cname, limit=sample_rows)
                if not vals:
                    continue
                agg = ai_classification_service.aggregate_column_from_values(vals)
                if agg.get("dominant_type"):
                    dom_types.append(str(agg["dominant_type"]))
                # Raise table CIA if column CIA suggests higher
                scia = agg.get("suggested_cia") or {"C": 0, "I": 0, "A": 0}
                for k in ("C", "I", "A"):
                    try:
                        cia_table[k] = max(int(cia_table.get(k, 0)), int(scia.get(k, 0)))
                    except Exception:
                        pass
                if self._apply_column_tags(fq, cname, agg):
                    tagged_columns += 1
            # Table-level tags & decision
            if self._apply_table_tags_and_record(fq, cia_table, dom_types):
                table_updates += 1
            # Enforcement (idempotent): attempt masking on detected columns using existing detector
            try:
                detections = ai_classification_service.detect_sensitive_columns(fq)
                res = policy_enforcement_service.auto_enforce_for_table(table=fq, detections=detections, table_cia=cia_table)
                enforcement_cols += len(res.get("applied", []))
            except Exception:
                pass
        return {
            "database": database,
            "tables_scanned": total_tables,
            "columns_scanned": total_columns,
            "column_tags_applied": tagged_columns,
            "table_updates": table_updates,
            "enforced_columns": enforcement_cols,
        }

    def run_for_tables(self, fq_tables: List[str], sample_rows: int = 200) -> Dict[str, Any]:
        """Scan only the provided fully-qualified tables (DB.SCHEMA.TABLE)."""
        total_tables = 0
        total_columns = 0
        tagged_columns = 0
        table_updates = 0
        enforcement_cols = 0
        for fq in fq_tables or []:
            try:
                _ = _split_fqn(fq)  # validate FQN
            except Exception:
                continue
            total_tables += 1
            cols = self.list_table_columns(fq)
            if not cols:
                continue
            cia_table = {"C": 0, "I": 0, "A": 0}
            dom_types: List[str] = []
            for cm in cols:
                total_columns += 1
                cname = cm.get("COLUMN_NAME")
                vals = self.sample_column_values(fq, cname, limit=sample_rows)
                if not vals:
                    continue
                agg = ai_classification_service.aggregate_column_from_values(vals)
                if agg.get("dominant_type"):
                    dom_types.append(str(agg["dominant_type"]))
                scia = agg.get("suggested_cia") or {"C": 0, "I": 0, "A": 0}
                for k in ("C", "I", "A"):
                    try:
                        cia_table[k] = max(int(cia_table.get(k, 0)), int(scia.get(k, 0)))
                    except Exception:
                        pass
                if self._apply_column_tags(fq, cname, agg):
                    tagged_columns += 1
            if self._apply_table_tags_and_record(fq, cia_table, dom_types):
                table_updates += 1
            try:
                detections = ai_classification_service.detect_sensitive_columns(fq)
                res = policy_enforcement_service.auto_enforce_for_table(table=fq, detections=detections, table_cia=cia_table)
                enforcement_cols += len(res.get("applied", []))
            except Exception:
                pass
        return {
            "tables_scanned": total_tables,
            "columns_scanned": total_columns,
            "column_tags_applied": tagged_columns,
            "table_updates": table_updates,
            "enforced_columns": enforcement_cols,
        }


sensitive_scan_service = SensitiveScanService()

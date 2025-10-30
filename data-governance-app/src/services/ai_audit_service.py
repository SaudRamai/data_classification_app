"""
AI Audit Service
- Persists AI recommendations and user actions into DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
- Enables compliance/audit trails of AI-driven classification
"""
from __future__ import annotations

from typing import Dict, Any, Optional, List
from datetime import datetime
import json

from src.connectors.snowflake_connector import snowflake_connector
try:
    from src.config.settings import settings  # type: ignore
except Exception:  # pragma: no cover
    settings = None  # type: ignore


def _esc(v: Optional[str]) -> str:
    s = "" if v is None else str(v)
    return s.replace("'", "''")


def _num_str_to_int(v: Any, default: int = 0) -> int:
    try:
        return int(str(v))
    except Exception:
        return default


class AIAuditService:
    def log_decision(
        self,
        asset_full_name: str,
        user_id: str,
        action: str,
        tags: Optional[Dict[str, Any]] = None,
        rationale: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        t = tags or {}
        cia_conf = _num_str_to_int(t.get("CONFIDENTIALITY_LEVEL"), 0)
        cia_int = _num_str_to_int(t.get("INTEGRITY_LEVEL"), 0)
        cia_avail = _num_str_to_int(t.get("AVAILABILITY_LEVEL"), 0)
        classification = t.get("DATA_CLASSIFICATION") or ""
        rj = json.dumps(details or {}, default=str)
        sql = f"""
            INSERT INTO DATA_GOVERNANCE.CLASSIFICATION_DECISIONS
            (ID, ASSET_FULL_NAME, USER_ID, ACTION, CLASSIFICATION_LEVEL, CIA_CONF, CIA_INT, CIA_AVAIL, RATIONALE, CREATED_AT, DETAILS)
            SELECT UUID_STRING(), '{_esc(asset_full_name)}', '{_esc(user_id)}', '{_esc(action)}', '{_esc(classification)}',
                   {cia_conf}, {cia_int}, {cia_avail}, '{_esc(rationale or '')}', CURRENT_TIMESTAMP,
                   PARSE_JSON('{_esc(rj)}')
        """
        snowflake_connector.execute_non_query(sql)

    def _gov_schema_fqn(self) -> str:
        try:
            if settings is not None:
                db = getattr(settings, "SCAN_CATALOG_DB", None) or getattr(settings, "SNOWFLAKE_DATABASE", None) or getattr(settings, "GOVERNANCE_DB", None)
                if db:
                    return f"{db}.DATA_CLASSIFICATION_GOVERNANCE"
        except Exception:
            pass
        return "DATA_CLASSIFICATION_GOVERNANCE"

    def _ensure_audit_tables(self) -> None:
        sc = self._gov_schema_fqn()
        ddl_block = f"""
        create schema if not exists {sc};
        create table if not exists {sc}.SENSITIVE_AUDIT (
            audit_id number autoincrement,
            table_name string,
            column_name string,
            detected_category string,
            confidence float,
            cia_confidentiality string,
            cia_integrity string,
            cia_availability string,
            detection_methods array,
            bundle_detected string,
            model_version string,
            config_version string,
            scan_timestamp timestamp_ntz default current_timestamp(),
            scan_user string,
            sample_hash string,
            unique (table_name, column_name, scan_timestamp)
        );
        create table if not exists {sc}.CLASSIFICATION_AI_RESULTS (
            result_id number autoincrement,
            table_name string,
            column_name string,
            regex_conf float,
            keyword_conf float,
            ml_conf float,
            semantic_conf float,
            final_conf float,
            dominant_category string,
            related_columns array,
            bundle_name string,
            detection_vector variant,
            model_version string,
            run_timestamp timestamp_ntz default current_timestamp()
        );
        create table if not exists {sc}.MODEL_METADATA (
            model_version string primary key,
            embedding_model string,
            training_data_snapshot string,
            feature_set_version string,
            config_version string,
            accuracy float,
            precision float,
            recall float,
            last_trained_on timestamp_ntz
        );
        -- Dynamic configuration key/value store for model thresholds, weights, sampling, flags
        create table if not exists {sc}.SENSITIVITY_MODEL_CONFIG (
            key string primary key,
            value string,
            updated_at timestamp_ntz default current_timestamp()
        )
        """
        try:
            stmts = [s.strip() for s in ddl_block.split(';') if s.strip()]
        except Exception:
            stmts = [ddl_block]
        for _stmt in stmts:
            try:
                snowflake_connector.execute_non_query(_stmt)
            except Exception:
                continue

    def _apply_snowflake_tags(self, table_fqn: str, column: str, category: str, cia: Dict[str, Any]) -> None:
        try:
            sc = self._gov_schema_fqn()
            # Create tags if missing
            ddl_block = f"""
                create tag if not exists {sc}.sensitive_type;
                create tag if not exists {sc}.confidentiality_level;
                create tag if not exists {sc}.integrity_level;
                create tag if not exists {sc}.availability_level;
            """
            try:
                stmts = [s.strip() for s in ddl_block.split(';') if s.strip()]
            except Exception:
                stmts = [ddl_block]
            for _stmt in stmts:
                try:
                    snowflake_connector.execute_non_query(_stmt)
                except Exception:
                    continue
        except Exception:
            pass
        try:
            db, sch, tbl = table_fqn.split(".") if table_fqn.count(".") == 2 else (None, None, None)
            if not (db and sch and tbl):
                return
            q = lambda s: '"' + s.replace('"', '""') + '"'
            fq = f"{q(db)}.{q(sch)}.{q(tbl)}"
            colq = q(column)
            snowflake_connector.execute_non_query(
                f"""
                alter table {fq} alter column {colq}
                set tag {sc}.sensitive_type = %(cat)s,
                        {sc}.confidentiality_level = %(c)s,
                        {sc}.integrity_level = %(i)s,
                        {sc}.availability_level = %(a)s
                """,
                {"cat": str(category), "c": str(cia.get("C")), "i": str(cia.get("I")), "a": str(cia.get("A"))},
            )
        except Exception:
            pass

    def persist_scan_results(
        self,
        table_name: str,
        column_results: List[Dict[str, Any]],
        table_metrics: Optional[Dict[str, Any]] = None,
        model_metadata: Optional[Dict[str, Any]] = None,
        config_version: Optional[str] = None,
        scan_user: str = "ai_service",
        sample_hash: Optional[str] = None,
        apply_tags: bool = False,
    ) -> None:
        """Persist detailed AI results and audit rows, with optional Snowflake tags.

        - column_results: each row should include
          {column, dominant_category, confidence, suggested_cia{C,I,A}, regex_hits, token_hits,
           semantic_category, semantic_confidence, bundle_boost, related_columns}
        """
        self._ensure_audit_tables()
        sc = self._gov_schema_fqn()

        # Upsert model metadata if provided
        if model_metadata:
            try:
                mm = dict(model_metadata)
                snowflake_connector.execute_non_query(
                    f"""
                    merge into {sc}.MODEL_METADATA t
                    using (select %(mv)s as model_version) s
                    on t.model_version = s.model_version
                    when matched then update set
                        embedding_model = %(em)s,
                        training_data_snapshot = %(tds)s,
                        feature_set_version = %(fsv)s,
                        config_version = %(cv)s,
                        accuracy = %(acc)s,
                        precision = %(pre)s,
                        recall = %(rec)s,
                        last_trained_on = current_timestamp
                    when not matched then insert (model_version, embedding_model, training_data_snapshot, feature_set_version, config_version, accuracy, precision, recall, last_trained_on)
                    values (%(mv)s, %(em)s, %(tds)s, %(fsv)s, %(cv)s, %(acc)s, %(pre)s, %(rec)s, current_timestamp)
                    """,
                    {
                        "mv": str(mm.get("model_version") or "v1.0"),
                        "em": str(mm.get("embedding_model") or ""),
                        "tds": str(mm.get("training_data_snapshot") or ""),
                        "fsv": str(mm.get("feature_set_version") or ""),
                        "cv": str(config_version or mm.get("config_version") or ""),
                        "acc": float(mm.get("accuracy") or 0.0),
                        "pre": float(mm.get("precision") or 0.0),
                        "rec": float(mm.get("recall") or 0.0),
                    },
                )
            except Exception:
                pass

        # Insert SENSITIVE_AUDIT and CLASSIFICATION_AI_RESULTS rows
        for r in (column_results or []):
            try:
                col = str(r.get("column") or "")
                cat = str(r.get("dominant_category") or r.get("semantic_category") or "")
                conf = float(r.get("confidence") or 0.0)
                cia = r.get("suggested_cia") or {"C": 0, "I": 0, "A": 0}
                regex_hits = r.get("regex_hits") or []
                token_hits = r.get("token_hits") or []
                sem_conf = float(r.get("semantic_confidence") or 0.0)
                ml_conf = float(r.get("ml_confidence") or 0.0) if r.get("ml_confidence") is not None else None
                kw_conf = float(r.get("keyword_confidence") or 0.0) if r.get("keyword_confidence") is not None else None
                rx_conf = float(r.get("regex_confidence") or 0.0) if r.get("regex_confidence") is not None else None
                related = r.get("related_columns") or []
                bundle = ",".join(related[:1]) if r.get("bundle_boost") else None
                model_ver = str((model_metadata or {}).get("model_version") or "v1.0")
                cfg_ver = str(config_version or (model_metadata or {}).get("config_version") or "")

                # SENSITIVE_AUDIT
                snowflake_connector.execute_non_query(
                    f"""
                    insert into {sc}.SENSITIVE_AUDIT (
                        table_name, column_name, detected_category, confidence,
                        cia_confidentiality, cia_integrity, cia_availability,
                        detection_methods, bundle_detected, model_version, config_version,
                        scan_user, sample_hash
                    ) values (
                        %(t)s, %(c)s, %(cat)s, %(conf)s,
                        %(cC)s, %(cI)s, %(cA)s,
                        %(dm)s, %(bd)s, %(mv)s, %(cv)s,
                        %(user)s, %(sh)s
                    )
                    """,
                    {
                        "t": table_name,
                        "c": col,
                        "cat": cat,
                        "conf": float(conf),
                        "cC": str(cia.get("C")),
                        "cI": str(cia.get("I")),
                        "cA": str(cia.get("A")),
                        "dm": json.dumps([m for m in ["regex","keyword","ml","semantic"] if (m!="ml" or ml_conf is not None)]),
                        "bd": bundle,
                        "mv": model_ver,
                        "cv": cfg_ver,
                        "user": scan_user,
                        "sh": sample_hash,
                    },
                )

                # CLASSIFICATION_AI_RESULTS
                det = {
                    "regex_hits": regex_hits,
                    "token_hits": token_hits,
                    "semantic_category": r.get("semantic_category"),
                }
                snowflake_connector.execute_non_query(
                    f"""
                    insert into {sc}.CLASSIFICATION_AI_RESULTS (
                        table_name, column_name, regex_conf, keyword_conf, ml_conf, semantic_conf, final_conf,
                        dominant_category, related_columns, bundle_name, detection_vector, model_version
                    ) values (
                        %(t)s, %(c)s, %(rx)s, %(kw)s, %(ml)s, %(sem)s, %(final)s,
                        %(dom)s, PARSE_JSON(%(rel)s), %(bn)s, PARSE_JSON(%(det)s), %(mv)s
                    )
                    """,
                    {
                        "t": table_name,
                        "c": col,
                        "rx": float(rx_conf if rx_conf is not None else 0.0),
                        "kw": float(kw_conf if kw_conf is not None else 0.0),
                        "ml": float(ml_conf if ml_conf is not None else 0.0),
                        "sem": float(sem_conf),
                        "final": float(conf),
                        "dom": cat,
                        "rel": json.dumps(related),
                        "bn": bundle,
                        "det": json.dumps(det),
                        "mv": model_ver,
                    },
                )

                # Optional Snowflake tags
                if apply_tags and cat:
                    self._apply_snowflake_tags(table_name, col, cat, cia)
            except Exception:
                # continue on row errors
                continue

    def record_feedback(
        self,
        table_name: str,
        column_name: str,
        ai_category: str,
        ai_confidence: float,
        user_category: Optional[str],
        user_confidence: Optional[float],
        action: str,  # CONFIRM / SUPPRESS / CORRECT
        comment: Optional[str],
        reviewer: str,
    ) -> None:
        """Persist a single feedback action into SENSITIVE_FEEDBACK_LOG."""
        self._ensure_audit_tables()
        sc = self._gov_schema_fqn()
        try:
            snowflake_connector.execute_non_query(
                f"""
                insert into {sc}.SENSITIVE_FEEDBACK_LOG (
                  table_name, column_name, ai_category, user_category, confidence, feedback_action, reviewer
                ) values (
                  %(t)s, %(c)s, %(ai)s, %(uc)s, %(conf)s, %(act)s, %(rev)s
                )
                """,
                {
                    "t": table_name,
                    "c": column_name,
                    "ai": ai_category,
                    "uc": (user_category or ai_category),
                    "conf": float(user_confidence if user_confidence is not None else ai_confidence),
                    "act": action,
                    "rev": reviewer,
                },
            )
        except Exception:
            pass

    def load_feedback_overrides(self) -> List[Dict[str, Any]]:
        """Load recent feedback entries for suppression/correction application."""
        self._ensure_audit_tables()
        sc = self._gov_schema_fqn()
        try:
            rows = snowflake_connector.execute_query(
                f"""
                select table_name, column_name, ai_category, user_category, confidence, feedback_action, reviewer, feedback_timestamp
                from {sc}.SENSITIVE_FEEDBACK_LOG
                where feedback_timestamp >= dateadd(day, -180, current_date())
                order by feedback_timestamp desc
                """
            ) or []
            return rows
        except Exception:
            return []


ai_audit = AIAuditService()

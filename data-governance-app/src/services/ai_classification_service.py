"""
AI Classification Service for Data Governance Application.

Platform-agnostic redesign: removes Snowflake dependencies and relies on
AI-driven inference (virtual metadata, NLP semantics, pattern intelligence,
and contextual signals) without any database calls.
"""
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
import re
import math
import json
import hashlib
import os
from datetime import datetime, timezone
try:
    import numpy as np
except Exception:  # numpy may not be installed in minimal deployments
    np = None  # type: ignore

from src.ml.classifier import classifier
from src.services.sensitive_detection import classify_table_sensitivity as _sd_classify
from src.services.metadata_catalog_service import MetadataCatalogService

# Optional Snowflake connector (hybrid mode)
try:
    from src.connectors.snowflake_connector import snowflake_connector  # type: ignore
    from src.config.settings import settings  # type: ignore
except Exception:
    snowflake_connector = None  # type: ignore
    settings = None  # type: ignore
try:
    import streamlit as st  # type: ignore
except Exception:
    st = None  # type: ignore
try:
    # Governance DB resolver to locate seeded glossary/policy artifacts
    from src.services.governance_db_resolver import resolve_governance_db  # type: ignore
except Exception:
    resolve_governance_db = None  # type: ignore

# Optional dynamic sampling (MODEL_CONFIG-driven)
try:
    from src.services.dynamic_sampling_service import sample_table as _dyn_sample_table  # type: ignore
except Exception:
    _dyn_sample_table = None  # type: ignore


class AIClassificationService:
    """
    Service for AI-based data classification and compliance mapping.
    """
    
    def __init__(self):
        """Initialize the service with the classifier.

        Adds an internal virtual catalog for metadata and sample data, enabling
        platform-agnostic operation. Populate via `set_virtual_table_profile()`.
        """
        self.classifier = classifier
        # Virtual catalog structure:
        # { "db.schema.table": { "columns": [ {"name": str, "type": Optional[str]} , ...],
        #                        "samples": pd.DataFrame or List[Dict[str,Any]] } }
        self._virtual_catalog: Dict[str, Dict[str, Any]] = {}
        # Hybrid mode toggle: when True and connector available, use Snowflake as primary
        # Default to False to avoid schema-dependent errors unless explicitly enabled
        self.use_snowflake: bool = False
        # Embedding backend (lazy): 'none'|'st'
        self._embedding_backend: str = 'none'
        self._embedder: Any = None
        # Cache of category token embeddings: {category: [(token, vec), ...]}
        self._category_embeds: Dict[str, List[Tuple[str, Any]]] = {}
        # Category centroid embeddings: {category: np.ndarray}
        self._category_centroids: Dict[str, Any] = {}
        # Simple text->embedding cache for performance
        self._embedding_cache: Dict[str, Any] = {}
        # Optional zero-shot classifier (lazy)
        self._zsc = None
        # Feedback store (persisted to JSON)
        self._feedback: Dict[str, Any] = {}
        # Canonical category embeddings cache for local SBERT
        self._canonical_cat_vecs: Dict[str, Any] = {}
        # Governance-derived category embeddings and thresholds cache
        self._gov_cat_vecs: Dict[str, Any] = {}
        self._gov_cat_thresholds: Dict[str, float] = {}
        self._gov_cat_compliance: Dict[str, List[str]] = {}
        self._gov_cat_sig: Optional[str] = None
        
        # Initialize empty sensitivity configuration - fully config-driven from governance tables
        # All patterns, keywords, thresholds, categories, bundles, and compliance mappings
        # must be loaded from governance tables via load_sensitivity_config()
        self._sensitivity_config: Optional[Dict[str, Any]] = None
        
        # Try to load feedback and config
        try:
            self._load_feedback()
        except Exception as e:
            print(f"Warning: Could not load feedback: {str(e)}")
            self._feedback = {}
            
        try:
            if self.use_snowflake:
                self.load_feedback_from_snowflake()
                # Try to load sensitivity config
                try:
                    self.load_sensitivity_config(force_refresh=True)
                except Exception as e:
                    print(f"Warning: Could not load initial sensitivity config: {str(e)}")
        except Exception as e:
            print(f"Warning: Could not initialize Snowflake components: {str(e)}")

    def _persist_audit(self, records: List[Dict[str, Any]]) -> None:
        """Persist table-level audit records into Snowflake SENSITIVE_AUDIT, with local JSONL fallback.

        Each record should include: table_name, dominant_category, table_sensitivity_score,
        threshold_applied, requires_review, flags_active, run_id, timestamp_utc, suggestions.
        """
        try:
            if not records:
                return
            # Prefer centralized Snowflake audit table
            if self.use_snowflake and snowflake_connector is not None:
                sc = self._gov_schema_fqn()
                for r in records:
                    det = {
                        "table_name": r.get("table_name"),
                        "dominant_category": r.get("dominant_category"),
                        "table_sensitivity_score": r.get("table_sensitivity_score"),
                        "threshold_applied": r.get("threshold_applied"),
                        "requires_review": r.get("requires_review"),
                        "flags_active": r.get("flags_active"),
                        "run_id": r.get("run_id"),
                        "timestamp_utc": r.get("timestamp_utc"),
                        "suggestions": r.get("suggestions"),
                        "scope": "table",
                    }
                    try:
                        # Minimal insert using DETAILS only (embed escaped JSON to avoid param binding issues)
                        det_sql = json.dumps(det).replace("'", "''")
                        snowflake_connector.execute_non_query(
                            f"insert into {sc}.SENSITIVE_AUDIT (DETAILS) select parse_json('{det_sql}')"
                        )
                    except Exception:
                        # Fallback: try a generic audit table if present
                        try:
                            det_sql = json.dumps(det).replace("'", "''")
                            snowflake_connector.execute_non_query(
                                f"insert into {sc}.CLASSIFICATION_AUDIT (DETAILS) select parse_json('{det_sql}')"
                            )
                        except Exception:
                            continue
                return
            # Fallback: local JSONL
            try:
                os.makedirs("audit_logs", exist_ok=True)
                path = os.path.join("audit_logs", "sensitive_audit.jsonl")
                with open(path, "a", encoding="utf-8") as fp:
                    for r in records:
                        fp.write(json.dumps(r) + "\n")
            except Exception:
                pass
        except Exception:
            pass

    def aggregate_table_sensitivity(self, column_features: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate table-level sensitivity from classified column rows.

        Input rows are expected to have: dominant_category, confidence (0-100).
        Returns a dict with score (0..1), dominant_category, sensitive_categories list.
        """
        try:
            if not column_features:
                return {"table_sensitivity_score": 0.0, "dominant_table_category": None, "table_categories": []}
            # Weighted by confidence; preserve categories contributing meaningfully
            from collections import defaultdict
            sums = defaultdict(float)
            counts = defaultdict(int)
            for r in column_features:
                conf = float(int(r.get("confidence", 0))) / 100.0
                cats: List[str] = list(r.get("categories") or [])
                dom = r.get("dominant_category")
                if dom and dom not in cats:
                    cats.append(dom)
                for c in cats:
                    sums[c] += conf
                    counts[c] += 1
            # Score: average of top per-column weighted signal
            try:
                col_scores = []
                for r in column_features:
                    conf = float(int(r.get("confidence", 0))) / 100.0
                    col_scores.append(conf)
                score = float(sum(col_scores) / max(1, len(col_scores)))
            except Exception:
                score = 0.0
            # Dominant by total sum, fallback to most frequent
            dom = None
            if sums:
                dom = sorted(sums.items(), key=lambda kv: (-kv[1], -counts.get(kv[0], 0)))[0][0]
            cats_sorted = [k for k, _ in sorted(sums.items(), key=lambda kv: -kv[1]) if sums[k] > 0]
            return {
                "table_sensitivity_score": round(score, 2),
                "dominant_table_category": dom,
                "table_categories": cats_sorted,
            }
        except Exception:
            return {"table_sensitivity_score": 0.0, "dominant_table_category": None, "table_categories": []}

    def persist_scan_results(self, table_name: str, column_rows: List[Dict[str, Any]], table_metrics: Dict[str, Any], sample_info: Optional[Dict[str, Any]] = None) -> None:
        """Persist column-level results to centralized audit with minimal schema assumptions.

        Writes into {GOV}.SENSITIVE_AUDIT using DETAILS only when possible; falls back to a local JSONL file.
        """
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                # Local fallback
                os.makedirs("audit_logs", exist_ok=True)
                path = os.path.join("audit_logs", "sensitive_column_audit.jsonl")
                with open(path, "a", encoding="utf-8") as fp:
                    for r in (column_rows or []):
                        entry = {
                            "table_name": table_name,
                            "column": r.get("column"),
                            "categories": r.get("categories"),
                            "dominant_category": r.get("dominant_category"),
                            "confidence": r.get("confidence"),
                            "details": {
                                "pattern_ids": r.get("pattern_ids"),
                                "token_hits": r.get("token_hits"),
                                "bundles": r.get("bundles_detected"),
                                "sample": sample_info,
                            },
                        }
                        fp.write(json.dumps(entry) + "\n")
                return
            # Snowflake path: insert DETAILS only
            sc = self._gov_schema_fqn()
            for r in (column_rows or []):
                try:
                    det = {
                        "table_name": table_name,
                        "column_name": r.get("column"),
                        "categories": r.get("categories"),
                        "dominant_category": r.get("dominant_category"),
                        "confidence": r.get("confidence"),
                        "pattern_ids": r.get("pattern_ids"),
                        "token_hits": r.get("token_hits"),
                        "bundles": r.get("bundles_detected"),
                        "sample": sample_info,
                        "scope": "column",
                    }
                    det_sql = json.dumps(det).replace("'", "''")
                    snowflake_connector.execute_non_query(
                        f"insert into {sc}.SENSITIVE_AUDIT (DETAILS) select parse_json('{det_sql}')"
                    )
                except Exception:
                    try:
                        det_sql = json.dumps(det).replace("'", "''")
                        snowflake_connector.execute_non_query(
                            f"insert into {sc}.CLASSIFICATION_AUDIT (DETAILS) select parse_json('{det_sql}')"
                        )
                    except Exception:
                        continue
        except Exception:
            pass

    def _gov_schema_fqn(self) -> str:
        try:
            if (st is not None) and hasattr(st, "session_state"):
                sel = st.session_state.get("db_filter") or st.session_state.get("global_db_filter")
                if sel:
                    return f"{sel}.DATA_CLASSIFICATION_GOVERNANCE"
        except Exception:
            pass
        try:
            if settings is not None:
                db = getattr(settings, "SCAN_CATALOG_DB", None) or getattr(settings, "SNOWFLAKE_DATABASE", None)
                if db:
                    return f"{db}.DATA_CLASSIFICATION_GOVERNANCE"
        except Exception:
            pass
        return "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE"

    def ensure_governance_tables(self) -> None:
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                return
            schema_fqn = self._gov_schema_fqn()
            ddl = f"""
            create schema if not exists {schema_fqn};
            create table if not exists {schema_fqn}.ASSETS (
              ASSET_ID VARCHAR(50) PRIMARY KEY NOT NULL,
              ASSET_NAME VARCHAR(255) NOT NULL,
              DATABASE_NAME VARCHAR(100) NOT NULL,
              SCHEMA_NAME VARCHAR(100) NOT NULL,
              TABLE_NAME VARCHAR(100) NOT NULL,
              TABLE_TYPE VARCHAR(50),
              CLASSIFICATION_TAG VARCHAR(20),
              CONFIDENTIALITY_LEVEL NUMBER(38,0),
              INTEGRITY_LEVEL NUMBER(38,0),
              AVAILABILITY_LEVEL NUMBER(38,0),
              RISK_SCORE NUMBER(3,0),
              BUSINESS_UNIT VARCHAR(100),
              DATA_OWNER VARCHAR(150),
              DATA_STEWARD VARCHAR(150),
              CREATED_DATE DATE,
              LAST_MODIFIED_DATE TIMESTAMP_NTZ(9),
              LAST_CLASSIFIED_DATE DATE,
              LAST_REVIEW_DATE DATE,
              NEXT_REVIEW_DATE DATE,
              DYNAMIC_SENSITIVE_FLAGS VARIANT,
              USAGE_FREQUENCY VARCHAR(20),
              ROW_COUNT NUMBER(38,0),
              SIZE_GB NUMBER(10,2),
              DATA_QUALITY_SCORE NUMBER(3,0),
              TAGS VARIANT,
              DESCRIPTION VARCHAR(1000),
              IS_ACTIVE BOOLEAN DEFAULT TRUE,
              CREATED_TIMESTAMP TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
              UPDATED_TIMESTAMP TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP()
            );
            create table if not exists {schema_fqn}.ASSETS (
              ASSET_ID VARCHAR(100) NOT NULL,
              ASSET_NAME VARCHAR(500) NOT NULL,
              ASSET_TYPE VARCHAR(50) NOT NULL,
              DATABASE_NAME VARCHAR(255),
              SCHEMA_NAME VARCHAR(255),
              OBJECT_NAME VARCHAR(255),
              FULLY_QUALIFIED_NAME VARCHAR(1000),
              BUSINESS_UNIT VARCHAR(100),
              DATA_OWNER VARCHAR(100) NOT NULL,
              DATA_OWNER_EMAIL VARCHAR(255),
              DATA_CUSTODIAN VARCHAR(100),
              DATA_CUSTODIAN_EMAIL VARCHAR(255),
              BUSINESS_PURPOSE VARCHAR(2000),
              DATA_DESCRIPTION VARCHAR(4000),
              CLASSIFICATION_LABEL VARCHAR(20),
              CLASSIFICATION_LABEL_COLOR VARCHAR(20),
              CONFIDENTIALITY_LEVEL VARCHAR(2),
              INTEGRITY_LEVEL VARCHAR(2),
              AVAILABILITY_LEVEL VARCHAR(2),
              OVERALL_RISK_CLASSIFICATION VARCHAR(20),
              CONTAINS_PII BOOLEAN DEFAULT FALSE,
              CONTAINS_FINANCIAL_DATA BOOLEAN DEFAULT FALSE,
              SOX_RELEVANT BOOLEAN DEFAULT FALSE,
              SOC_RELEVANT BOOLEAN DEFAULT FALSE,
              REGULATORY_DATA BOOLEAN DEFAULT FALSE,
              CLASSIFICATION_RATIONALE VARCHAR(4000),
              CONFIDENTIALITY_IMPACT_ASSESSMENT VARCHAR(2000),
              INTEGRITY_IMPACT_ASSESSMENT VARCHAR(2000),
              AVAILABILITY_IMPACT_ASSESSMENT VARCHAR(2000),
              CLASSIFICATION_DATE TIMESTAMP_NTZ(9),
              CLASSIFIED_BY VARCHAR(100),
              CLASSIFICATION_METHOD VARCHAR(50),
              CLASSIFICATION_REVIEWED_BY VARCHAR(100),
              CLASSIFICATION_REVIEW_DATE TIMESTAMP_NTZ(9),
              CLASSIFICATION_APPROVED_BY VARCHAR(100),
              CLASSIFICATION_APPROVAL_DATE TIMESTAMP_NTZ(9),
              LAST_RECLASSIFICATION_DATE TIMESTAMP_NTZ(9),
              RECLASSIFICATION_TRIGGER VARCHAR(500),
              RECLASSIFICATION_COUNT NUMBER(10,0) DEFAULT 0,
              PREVIOUS_CLASSIFICATION_LABEL VARCHAR(20),
              LAST_REVIEW_DATE TIMESTAMP_NTZ(9),
              NEXT_REVIEW_DATE TIMESTAMP_NTZ(9),
              REVIEW_FREQUENCY_DAYS NUMBER(10,0) DEFAULT 365,
              REVIEW_STATUS VARCHAR(20),
              PEER_REVIEW_COMPLETED BOOLEAN DEFAULT FALSE,
              PEER_REVIEWER VARCHAR(100),
              MANAGEMENT_REVIEW_COMPLETED BOOLEAN DEFAULT FALSE,
              MANAGEMENT_REVIEWER VARCHAR(100),
              TECHNICAL_REVIEW_COMPLETED BOOLEAN DEFAULT FALSE,
              TECHNICAL_REVIEWER VARCHAR(100),
              CONSISTENCY_CHECK_DATE TIMESTAMP_NTZ(9),
              CONSISTENCY_CHECK_STATUS VARCHAR(20),
              DATA_CREATION_DATE TIMESTAMP_NTZ(9),
              DATA_SOURCE_SYSTEM VARCHAR(255),
              DATA_RETENTION_PERIOD_DAYS NUMBER(10,0),
              DATA_DISPOSAL_DATE TIMESTAMP_NTZ(9),
              SENSITIVE_DATA_USAGE_COUNT NUMBER(10,0) DEFAULT 0,
              LAST_ACCESSED_DATE TIMESTAMP_NTZ(9),
              ACCESS_FREQUENCY VARCHAR(20),
              NUMBER_OF_CONSUMERS NUMBER(10,0),
              HAS_EXCEPTION BOOLEAN DEFAULT FALSE,
              EXCEPTION_TYPE VARCHAR(100),
              EXCEPTION_JUSTIFICATION VARCHAR(2000),
              EXCEPTION_APPROVED_BY VARCHAR(100),
              EXCEPTION_APPROVAL_DATE TIMESTAMP_NTZ(9),
              EXCEPTION_EXPIRY_DATE TIMESTAMP_NTZ(9),
              EXCEPTION_MITIGATION_MEASURES VARCHAR(2000),
              COMPLIANCE_STATUS VARCHAR(20),
              NON_COMPLIANCE_REASON VARCHAR(1000),
              CORRECTIVE_ACTION_REQUIRED BOOLEAN DEFAULT FALSE,
              CORRECTIVE_ACTION_DESCRIPTION VARCHAR(2000),
              CORRECTIVE_ACTION_DUE_DATE TIMESTAMP_NTZ(9),
              CREATED_TIMESTAMP TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
              CREATED_BY VARCHAR(100),
              LAST_MODIFIED_TIMESTAMP TIMESTAMP_NTZ(9) DEFAULT CURRENT_TIMESTAMP(),
              LAST_MODIFIED_BY VARCHAR(100),
              RECORD_VERSION NUMBER(10,0) DEFAULT 1,
              ADDITIONAL_NOTES VARCHAR(4000),
              STAKEHOLDER_COMMENTS VARCHAR(4000),
              primary key (ASSET_ID)
            );
            create table if not exists {schema_fqn}.CLASSIFICATION_DECISIONS (
              decision_id number autoincrement,
              table_name string,
              column_name string,
              category string,
              label string,
              confidence number,
              cia string,
              decided_by string,
              decided_at timestamp_ntz default current_timestamp(),
              primary key (decision_id)
            );
            create table if not exists {schema_fqn}.CLASSIFICATION_TASKS (
              TASK_ID STRING,
              DATASET_NAME STRING,
              ASSET_FULL_NAME STRING,
              ASSIGNED_TO STRING,
              STATUS STRING,
              CONFIDENTIALITY_LEVEL STRING,
              INTEGRITY_LEVEL STRING,
              AVAILABILITY_LEVEL STRING,
              DUE_DATE DATE,
              CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
              UPDATED_AT TIMESTAMP_NTZ,
              DETAILS VARIANT
            );
            create table if not exists {schema_fqn}.CLASSIFICATION_REVIEWS (
              review_id number autoincrement,
              table_name string,
              column_name string,
              reviewer string,
              status string,
              comments string,
              reviewed_at timestamp_ntz,
              primary key (review_id)
            );
            create table if not exists {schema_fqn}.RECLASSIFICATION_REQUESTS (
              request_id number autoincrement,
              table_name string,
              column_name string,
              requested_by string,
              reason string,
              requested_at timestamp_ntz default current_timestamp(),
              status string,
              primary key (request_id)
            );
            create table if not exists {schema_fqn}.CLASSIFICATION_AUDIT (
              audit_id number autoincrement,
              resource_id string,
              action string,
              details string,
              created_at timestamp_ntz default current_timestamp(),
              primary key (audit_id)
            );
            create table if not exists {schema_fqn}.SENSITIVE_PATTERNS (
              category string,
              pattern string,
              priority number default 0,
              is_active boolean default true,
              updated_at timestamp_ntz default current_timestamp()
            );
            create table if not exists {schema_fqn}.SENSITIVE_KEYWORDS (
              category string,
              keyword string,
              priority number default 0,
              is_active boolean default true,
              updated_at timestamp_ntz default current_timestamp()
            );
            create table if not exists {schema_fqn}.SENSITIVITY_CATEGORIES (
              category string,
              confidentiality number default 0,
              integrity number default 0,
              availability number default 0,
              cia_c number default 0,
              cia_i number default 0,
              cia_a number default 0,
              is_active boolean default true,
              updated_at timestamp_ntz default current_timestamp()
            );
            create table if not exists {schema_fqn}.SENSITIVE_BUNDLES (
              bundle_name string,
              category string,
              column_name string,
              columns variant,
              boost float default 0,
              is_active boolean default true,
              updated_at timestamp_ntz default current_timestamp()
            );
            create table if not exists {schema_fqn}.SENSITIVE_AUDIT (
              audit_id number autoincrement,
              full_name string,
              table_name string,
              column_name string,
              category string,
              confidence number,
              cia string,
              bundle_detected boolean,
              sample_hash string,
              sampling_method string,
              sample_fraction float,
              details variant,
              scanned_at timestamp_ntz default current_timestamp(),
              primary key (audit_id)
            );
            create table if not exists {schema_fqn}.SAMPLE_METADATA (
              TABLE_NAME STRING,
              SAMPLE_HASH STRING,
              SAMPLE_SIZE NUMBER,
              SAMPLING_METHOD STRING,
              STRATIFY_COLUMN STRING,
              WEIGHT_COLUMN STRING,
              SAMPLING_TIMESTAMP TIMESTAMP_NTZ,
              CONFIG_VERSION NUMBER,
              DETAILS VARIANT
            );
            create table if not exists {schema_fqn}.SAMPLING_CONFIG (
              TABLE_NAME string,
              METHOD string,
              FRACTION float,
              STRATIFY_COLUMN string,
              WEIGHT_COLUMN string,
              CONFIG_VERSION string,
              UPDATED_AT timestamp_ntz default current_timestamp(),
              UPDATED_BY string default current_user()
            );
            create table if not exists {schema_fqn}.SENSITIVE_FEEDBACK (
              feedback_id number autoincrement,
              table_name string,
              column_name string,
              corrected_category string,
              corrected_confidence number,
              payload variant,
              timestamp_ntz timestamp_ntz default current_timestamp(),
              primary key (feedback_id)
            );
            create table if not exists {schema_fqn}.CLASSIFICATION_AI_RESULTS (
              result_id number autoincrement,
              table_name string,
              column_name string,
              ai_category string,
              regex_confidence float,
              keyword_confidence float,
              ml_confidence float,
              semantic_confidence float,
              final_confidence float,
              semantic_category string,
              model_version string,
              details variant,
              created_at timestamp_ntz default current_timestamp(),
              primary key (result_id)
            );
            create table if not exists {schema_fqn}.SENSITIVE_FEEDBACK_LOG (
              feedback_id number autoincrement,
              table_name string,
              column_name string,
              ai_category string,
              user_category string,
              confidence float,
              feedback_action string,
              reviewer string,
              feedback_timestamp timestamp_ntz default current_timestamp(),
              primary key (feedback_id)
            );
            create table if not exists {schema_fqn}.MODEL_METADATA (
              model_name string,
              model_version string,
              embedding_model string,
              thresholds variant,
              updated_at timestamp_ntz default current_timestamp()
            );
            create table if not exists {schema_fqn}.COMPLIANCE_MAPPING (
              detected_category string,
              framework string,
              rule string,
              priority number default 100,
              is_active boolean default true,
              updated_at timestamp_ntz default current_timestamp()
            );
            create table if not exists {schema_fqn}.SENSITIVITY_RESULTS (
              full_name string,
              table_sensitivity_score float,
              dominant_category string,
              table_cia_minimum string,
              sensitive_columns_count number,
              details variant,
              created_at timestamp_ntz default current_timestamp()
            );
            create table if not exists {schema_fqn}.CLASSIFICATION_HISTORY (
              full_name string,
              run_id string,
              classification string,
              confidence float,
              details variant,
              created_at timestamp_ntz default current_timestamp()
            );
            create table if not exists {schema_fqn}.ALERT_LOGS (
              log_id number autoincrement,
              level string,
              component string,
              message string,
              details variant,
              created_at timestamp_ntz default current_timestamp(),
              primary key (log_id)
            );
            """
            # Execute each statement separately to satisfy drivers that only allow one statement per call
            try:
                stmts = [s.strip() for s in ddl.split(';') if s.strip()]
            except Exception:
                stmts = [ddl]
            for _stmt in stmts:
                try:
                    snowflake_connector.execute_non_query(_stmt)
                except Exception:
                    # Continue on best-effort so one failing DDL doesn't stop the rest
                    continue

            # Ensure required columns exist for deterministic sampling metadata (best-effort)
            try:
                self._ensure_sampling_metadata_columns()
            except Exception:
                pass
        except Exception:
            pass

    def _ensure_sampling_metadata_columns(self) -> None:
        """Adds deterministic metadata columns to SAMPLE_METADATA if missing."""
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                return
            sc = self._gov_schema_fqn()
            snowflake_connector.execute_non_query(
                f"alter table if exists {sc}.SAMPLE_METADATA add column if not exists SAMPLE_QUERY_TEXT string"
            )
            snowflake_connector.execute_non_query(
                f"alter table if exists {sc}.SAMPLE_METADATA add column if not exists SAMPLE_SEED number"
            )
            snowflake_connector.execute_non_query(
                f"alter table if exists {sc}.SAMPLE_METADATA add column if not exists SAMPLE_HASH string"
            )
            snowflake_connector.execute_non_query(
                f"alter table if exists {sc}.SAMPLE_METADATA add column if not exists SAMPLING_METHOD string"
            )
            snowflake_connector.execute_non_query(
                f"alter table if exists {sc}.SAMPLE_METADATA add column if not exists SAMPLE_SIZE number"
            )
            snowflake_connector.execute_non_query(
                f"alter table if exists {sc}.SAMPLE_METADATA add column if not exists CREATED_AT timestamp_ntz default current_timestamp()"
            )
        except Exception:
            pass

    def _persist_sample_metadata(self, table_name: str, sample_query_text: str, sample_seed: int, sample_hash: str, sampling_method: str, sample_size: int) -> None:
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                return
            sc = self._gov_schema_fqn()
            # Ensure target table has required columns
            try:
                self._ensure_sampling_metadata_columns()
            except Exception:
                pass
            snowflake_connector.execute_non_query(
                f"""
                insert into {sc}.SAMPLE_METADATA (
                  TABLE_NAME, SAMPLE_QUERY_TEXT, SAMPLE_SEED, SAMPLE_HASH, SAMPLING_METHOD, SAMPLE_SIZE, CREATED_AT
                )
                values (%(t)s, %(q)s, %(seed)s, %(h)s, %(m)s, %(n)s, current_timestamp())
                """,
                {
                    "t": table_name,
                    "q": sample_query_text,
                    "seed": int(sample_seed),
                    "h": sample_hash,
                    "m": sampling_method,
                    "n": int(sample_size),
                },
            )
        except Exception:
            pass

    # -------- Dynamic Sampling Utilities --------
    def _read_sampling_policy(self, table_name: str) -> Dict[str, Any]:
        """Best-effort load of sampling policy from governance. Falls back to heuristics.

        Expected table: {gov}.SAMPLING_CONFIG (TABLE_NAME, METHOD, FRACTION, STRATIFY_COLUMN, WEIGHT_COLUMN, CONFIG_VERSION)
        """
        policy: Dict[str, Any] = {}
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                return policy
            sc = self._gov_schema_fqn()
            rows = snowflake_connector.execute_query(
                f"""
                select TABLE_NAME, METHOD, FRACTION, STRATIFY_COLUMN, WEIGHT_COLUMN, CONFIG_VERSION
                from {sc}.SAMPLING_CONFIG
                where upper(TABLE_NAME) = upper(%(t)s)
                limit 1
                """,
                {"t": table_name},
            ) or []
            if rows:
                r = rows[0]
                policy = {
                    "method": (r.get("METHOD") or "").lower() or None,
                    "fraction": float(r.get("FRACTION") or 0) or None,
                    "stratify_column": r.get("STRATIFY_COLUMN") or None,
                    "weight_column": r.get("WEIGHT_COLUMN") or None,
                    "config_version": r.get("CONFIG_VERSION") or None,
                }
        except Exception:
            pass
        return policy

    def _estimate_row_count(self, table_name: str) -> Optional[int]:
        try:
            parts = (table_name or "").split(".")
            if len(parts) != 3:
                return None
            db, sch, tbl = parts
            rows = snowflake_connector.execute_query(
                f"""
                select coalesce(ROW_COUNT,0) as ROW_COUNT
                from {db}.INFORMATION_SCHEMA.TABLES
                where TABLE_SCHEMA=%(s)s and TABLE_NAME=%(t)s
                limit 1
                """,
                {"s": sch, "t": tbl},
            ) or []
            if rows:
                rc = rows[0].get("ROW_COUNT")
                return int(rc) if rc is not None else None
        except Exception:
            return None
        return None

    def _persist_sample_metadata(self, table_name: str, sample_query_text: str, sample_seed: int, sample_hash: str, sampling_method: str, sample_size: int) -> None:
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                return
            sc = self._gov_schema_fqn()
            # Ensure target table has required columns
            try:
                self._ensure_sampling_metadata_columns()
            except Exception:
                pass
            snowflake_connector.execute_non_query(
                f"""
                insert into {sc}.SAMPLE_METADATA (
                  TABLE_NAME, SAMPLE_QUERY_TEXT, SAMPLE_SEED, SAMPLE_HASH, SAMPLING_METHOD, SAMPLE_SIZE, CREATED_AT
                )
                values (%(t)s, %(q)s, %(seed)s, %(h)s, %(m)s, %(n)s, current_timestamp())
                """,
                {
                    "t": table_name,
                    "q": sample_query_text,
                    "seed": int(sample_seed),
                    "h": sample_hash,
                    "m": sampling_method,
                    "n": int(sample_size),
                },
            )
        except Exception:
            pass

    def _ensure_sampling_metadata_columns(self) -> None:
        """Adds deterministic metadata columns to SAMPLE_METADATA if missing."""
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                return
            sc = self._gov_schema_fqn()
            snowflake_connector.execute_non_query(
                f"alter table if exists {sc}.SAMPLE_METADATA add column if not exists SAMPLE_QUERY_TEXT string"
            )
            snowflake_connector.execute_non_query(
                f"alter table if exists {sc}.SAMPLE_METADATA add column if not exists SAMPLE_SEED number"
            )
            snowflake_connector.execute_non_query(
                f"alter table if exists {sc}.SAMPLE_METADATA add column if not exists SAMPLE_HASH string"
            )
            snowflake_connector.execute_non_query(
                f"alter table if exists {sc}.SAMPLE_METADATA add column if not exists SAMPLING_METHOD string"
            )
            snowflake_connector.execute_non_query(
                f"alter table if exists {sc}.SAMPLE_METADATA add column if not exists SAMPLE_SIZE number"
            )
            snowflake_connector.execute_non_query(
                f"alter table if exists {sc}.SAMPLE_METADATA add column if not exists CREATED_AT timestamp_ntz default current_timestamp()"
            )
        except Exception:
            pass

    def _dynamic_sample(self, table_name: str, min_rows: int, max_rows: int, seed: Optional[int] = None) -> Optional[pd.DataFrame]:
        """Deterministic table sampling with full metadata persistence.

        Returns a DataFrame or None on failure.
        """
        if not (self.use_snowflake and snowflake_connector is not None):
            return None
        try:
            # Estimate row count and read policy
            rc = self._estimate_row_count(table_name) or 0
            pol = self._read_sampling_policy(table_name)
            method = (pol.get("method") or "").lower() if pol else None
            fraction = pol.get("fraction") if pol else None
            strat_col = pol.get("stratify_column") if pol else None

            # Dynamic config, full-scan toggle, and caps
            try:
                cfg = self.load_sensitivity_config()
            except Exception:
                cfg = {}
            model_meta = (cfg.get("model_metadata") or cfg.get("thresholds") or {})
            full_scan_toggle = False
            force_full_once = False
            try:
                if st is not None and hasattr(st, "session_state"):
                    full_scan_toggle = bool(st.session_state.get("ai_full_table_scan", False))
                    force_full_once = bool(st.session_state.get("ai_force_full_scan", False))
                    # Reset the one-shot flag
                    if force_full_once:
                        st.session_state["ai_force_full_scan"] = False
            except Exception:
                full_scan_toggle = False
                force_full_once = False
            cap_small_full = int(model_meta.get("full_scan_max_rows", 200000))
            cap_high_risk_full = int(model_meta.get("full_scan_high_risk_max_rows", 100000))

            # Governance flags for high-risk assets (best-effort)
            is_high_risk_asset = False
            try:
                sc = self._gov_schema_fqn()
                rows = snowflake_connector.execute_query(
                    f"select DYNAMIC_SENSITIVE_FLAGS from {sc}.ASSETS where upper(FULL_NAME)=upper(%(f)s) limit 1",
                    {"f": table_name},
                ) or []
                if rows:
                    flags = rows[0].get("DYNAMIC_SENSITIVE_FLAGS") or {}
                    is_high_risk_asset = any(bool(v) for v in (flags.values() if isinstance(flags, dict) else []))
            except Exception:
                is_high_risk_asset = False

            # Seed normalization
            if seed is None:
                seed = int.from_bytes(os.urandom(8), "big") % (10**9)

            # Decide sampling method
            if not method:
                if (force_full_once or full_scan_toggle) and rc and ((rc <= cap_small_full) or (is_high_risk_asset and rc <= cap_high_risk_full)):
                    method = "full"
                elif rc and rc <= max_rows:
                    method = "full"
                elif rc and rc > max_rows * 20:
                    method = "stratified" if strat_col else "random"
                else:
                    method = "random"

            if not fraction:
                if method == "full":
                    fraction = 1.0
                elif rc:
                    fraction = min(0.25, max(0.001, float(max_rows) / float(rc)))
                else:
                    fraction = 0.02

            q = lambda s: '"' + str(s).replace('"', '""') + '"'
            parts = table_name.split(".")
            if len(parts) != 3:
                return None
            db, sch, tbl = parts
            fqn = f"{q(db)}.{q(sch)}.{q(tbl)}"

            sample_sql = ""
            if method == "full":
                sample_sql = f"select * from {fqn}"
            elif method == "random":
                pct = max(0.01, min(100.0, (fraction or 0.02) * 100.0))
                sample_sql = f"select * from {fqn} tablesample bernoulli ({pct}) repeatable ({int(seed)})"
            elif method == "stratified" and strat_col:
                pct = max(0.0001, min(100.0, (fraction or 0.02)))
                sample_sql = (
                    "with t as (\n"
                    f"  select t1.*, row_number() over (partition by {q(strat_col)} order by random({int(seed)})) as rn,\n"
                    f"         count(*) over (partition by {q(strat_col)}) as cn\n"
                    f"  from {fqn} as t1\n"
                    ")\n"
                    f"select * from t where rn <= greatest(1, floor(cn * {pct}))"
                )
            else:
                pct = max(0.01, min(100.0, (fraction or 0.02) * 100.0))
                method = "random"
                sample_sql = f"select * from {fqn} tablesample bernoulli ({pct}) repeatable ({int(seed)})"

            # Execute and enforce min/max rows post-filter if needed
            rows = snowflake_connector.execute_query(sample_sql) or []
            df = pd.DataFrame(rows)
            if df is not None and hasattr(df, 'shape'):
                if df.shape[0] < min_rows and method != "full" and rc:
                    limit_n = min(max_rows, max(min_rows, int(float(max_rows))))
                    boost_sql = f"select * from ({sample_sql}) limit {int(limit_n)}"
                    rows = snowflake_connector.execute_query(boost_sql) or []
                    df = pd.DataFrame(rows)

            # Persist sample metadata
            try:
                sample_hash = hashlib.md5((sample_sql + "|" + str(int(seed))).encode("utf-8")).hexdigest()
                self._persist_sample_metadata(table_name, sample_sql, int(seed), sample_hash, method, int(df.shape[0] if hasattr(df, 'shape') else 0))
            except Exception:
                pass

            return df
        except Exception:
            return None

    def reexecute_sample(self, sample_hash: str) -> Optional[pd.DataFrame]:
        """Helper to re-run a stored deterministic sample by its sample_hash."""
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                return None
            sc = self._gov_schema_fqn()
            # Ensure columns exist before selecting
            try:
                self._ensure_sampling_metadata_columns()
            except Exception:
                pass
            rows = []
            try:
                rows = snowflake_connector.execute_query(
                    f"select sample_query_text from {sc}.SAMPLE_METADATA where sample_hash = %(h)s limit 1",
                    {"h": sample_hash},
                ) or []
            except Exception:
                rows = []
            if not rows:
                return None
            qtext = rows[0].get("SAMPLE_QUERY_TEXT") or rows[0].get("sample_query_text")
            if not qtext:
                return None
            data = snowflake_connector.execute_query(qtext) or []
            return pd.DataFrame(data)
        except Exception:
            return None

    def load_sensitivity_config(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Load dynamic sensitivity configuration from Snowflake and cache it.
        
        Sources (DATA_CLASSIFICATION_GOVERNANCE schema):
        - SENSITIVE_PATTERNS - Pattern-based detection rules
        - SENSITIVE_KEYWORDS - Keyword-based detection
        - SENSITIVITY_CATEGORIES - Category definitions and CIA ratings
        - SENSITIVE_BUNDLES - Multi-column pattern bundles
        - SENSITIVITY_WEIGHTS - Weights for different sensitivity factors
        - SENSITIVITY_THRESHOLDS - Confidence thresholds for classification
        - SENSITIVITY_MODEL_CONFIG - Model configuration parameters
        - COMPLIANCE_MAPPING - Compliance framework mappings

        Returns:
            Dict containing all sensitivity configuration parameters
        """
        # Check for cached configuration in session state if not forcing refresh
        try:
            if not force_refresh and st is not None and hasattr(st, "session_state"):
                sc = st.session_state.get("sensitivity_config")
                if sc:
                    return sc
        except Exception:
            pass
            
        # If we have a cached config and not forcing refresh, return it
        if not force_refresh and self._sensitivity_config:
            return self._sensitivity_config
            
        # Empty configuration structure - fully config-driven from governance tables
        # No hardcoded defaults to ensure all config comes from governance tables
        empty_config = {
            "patterns": [],
            "keywords": [],
            "categories": {},
            "bundles": [],
            "compliance_mapping": {},
            "model_metadata": {},
            "thresholds": {},
            "weights": {},
            "name_tokens": {}
        }

        # Set empty config - will be populated from database
        self._sensitivity_config = empty_config
        
        # If Snowflake is not available, return empty config (no hardcoded fallbacks)
        if not (self.use_snowflake and snowflake_connector is not None):
            return self._sensitivity_config
            
        try:
            # Try to load from database
            cfg = self._load_config_from_database(force_refresh)
            if cfg:
                self._sensitivity_config = cfg
                # Update session state if available
                try:
                    if st is not None and hasattr(st, "session_state"):
                        st.session_state["sensitivity_config"] = cfg
                except Exception:
                    pass
                return cfg
                
        except Exception as e:
            print(f"Warning: Could not load sensitivity configuration: {str(e)}. Configuration must be loaded from governance tables.")
            
        return self._sensitivity_config

        # Load patterns
        patterns = []
        try:
            rows = snowflake_connector.execute_query(
                f"""
                SELECT 
                    category, 
                    pattern, 
                    COALESCE(priority, 0) as priority,
                    COALESCE(is_negative, false) as is_negative
                FROM {schema_fqn}.SENSITIVE_PATTERNS
                WHERE COALESCE(is_active, true)
                ORDER BY is_negative, priority DESC
                """
            ) or []

            # Process patterns
            try:
                for row in rows:
                    try:
                        pattern = {
                            "category": str(row["CATEGORY"]),
                            "pattern": str(row["PATTERN"]),
                            "priority": int(row["PRIORITY"]),
                            "is_negative": bool(row["IS_NEGATIVE"])
                        }
                        patterns.append(pattern)
                    except Exception:
                        continue
            except Exception as e:
                print(f"Warning: Could not process SENSITIVE_PATTERNS: {str(e)}")
            
            # Load keywords
            keywords = []
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT 
                        category, 
                        keyword, 
                        COALESCE(priority, 0) as priority
                    FROM {schema_fqn}.SENSITIVE_KEYWORDS
                    WHERE COALESCE(is_active, true)
                    ORDER BY priority DESC
                    """
                ) or []
                
                for row in rows:
                    try:
                        keyword = {
                            "category": str(row["CATEGORY"]),
                            "keyword": str(row["KEYWORD"]).lower(),
                            "priority": int(row["PRIORITY"])
                        }
                        keywords.append(keyword)
                    except Exception:
                        continue
            except Exception as e:
                print(f"Warning: Could not load SENSITIVE_KEYWORDS: {str(e)}")
            
            # Load categories
            categories = {}
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT 
                        category_name as category,
                        COALESCE(confidentiality_level, 1) as c,
                        COALESCE(integrity_level, 1) as i,
                        COALESCE(availability_level, 1) as a
                    FROM {schema_fqn}.SENSITIVITY_CATEGORIES
                    WHERE COALESCE(is_active, true)
                    """
                ) or []
                
                for row in rows:
                    try:
                        category = str(row["CATEGORY"])
                        categories[category] = {
                            "C": int(row["C"]),
                            "I": int(row["I"]),
                            "A": int(row["A"])
                        }
                    except Exception:
                        continue
            except Exception as e:
                print(f"Warning: Could not load SENSITIVITY_CATEGORIES: {str(e)}")
            
            # Load bundles
            bundles = []
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT 
                        bundle_name,
                        category,
                        column_name,
                        COALESCE(boost, 0.1) as boost
                    FROM {schema_fqn}.SENSITIVE_BUNDLES
                    WHERE COALESCE(is_active, true)
                    ORDER BY COALESCE(priority, 100) DESC
                    """
                ) or []
                
                for row in rows:
                    try:
                        bundle = {
                            "bundle_name": str(row["BUNDLE_NAME"]),
                            "category": str(row["CATEGORY"]),
                            "column_name": str(row["COLUMN_NAME"]),
                            "boost": float(row["BOOST"])
                        }
                        bundles.append(bundle)
                    except Exception:
                        continue
            except Exception as e:
                print(f"Warning: Could not load SENSITIVE_BUNDLES: {str(e)}")
            
            # Load thresholds
            thresholds = {}
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT 
                        threshold_name as name,
                        confidence_level as threshold,
                        sensitivity_level as level
                    FROM {schema_fqn}.SENSITIVITY_THRESHOLDS
                    WHERE COALESCE(is_active, true)
                    """
                ) or []
                
                for row in rows:
                    try:
                        name = str(row["NAME"])
                        thresholds[name] = {
                            "threshold": float(row["THRESHOLD"]),
                            "level": str(row["LEVEL"])
                        }
                    except Exception:
                        continue
            except Exception as e:
                print(f"Warning: Could not load SENSITIVITY_THRESHOLDS: {str(e)}")
            
            # Load weights
            weights = {}
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT 
                        sensitivity_type as type,
                        weight
                    FROM {schema_fqn}.SENSITIVITY_WEIGHTS
                    WHERE COALESCE(is_active, true)
                    """
                ) or []
                
                for row in rows:
                    try:
                        weights[str(row["TYPE"])] = float(row["WEIGHT"])
                    except Exception:
                        continue
            except Exception as e:
                print(f"Warning: Could not load SENSITIVITY_WEIGHTS: {str(e)}")
            
            # Load model config
            model_config = {}
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT 
                        model_name as name,
                        model_version as version,
                        model_type as type,
                        configuration
                    FROM {schema_fqn}.SENSITIVITY_MODEL_CONFIG
                    WHERE COALESCE(is_active, true)
                    """
                ) or []
                
                for row in rows:
                    try:
                        config = row["CONFIGURATION"]
                        if isinstance(config, str):
                            config = json.loads(config)
                        model_config[str(row["NAME"])] = {
                            "version": str(row["VERSION"]),
                            "type": str(row["TYPE"]),
                            "config": config
                        }
                    except Exception:
                        continue
            except Exception as e:
                print(f"Warning: Could not load SENSITIVITY_MODEL_CONFIG: {str(e)}")
            
            # Load compliance mapping
            compliance_mapping = {}
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT 
                        detected_category as category,
                        framework,
                        rule,
                        COALESCE(priority, 100) as priority
                    FROM {schema_fqn}.COMPLIANCE_MAPPING
                    WHERE COALESCE(is_active, true)
                    ORDER BY priority DESC
                    """
                ) or []
                
                for row in rows:
                    try:
                        category = str(row["CATEGORY"])
                        if category not in compliance_mapping:
                            compliance_mapping[category] = []
                        compliance_mapping[category].append({
                            "framework": str(row["FRAMEWORK"]),
                            "rule": str(row["RULE"]) if row["RULE"] else None,
                            "priority": int(row["PRIORITY"])
                        })
                    except Exception:
                        continue
            except Exception as e:
                print(f"Warning: Could not load COMPLIANCE_MAPPING: {str(e)}")
            
            # Internal patterns functionality has been removed
            # Update configuration with loaded data
            cfg.update({
                "patterns": patterns,
                "keywords": keywords,
                "categories": categories,
                "bundles": bundles,
                "thresholds": thresholds,
                "weights": weights,
                "model_config": model_config,
                "compliance_mapping": compliance_mapping
            })
            
            # Update cache
            try:
                if st is not None and hasattr(st, "session_state"):
                    st.session_state["sensitivity_config"] = cfg
            except Exception:
                pass
                
        except Exception as e:
            print(f"Error loading sensitivity configuration: {str(e)}")
        
        return cfg
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                raise RuntimeError("Snowflake connector unavailable")

            # Resolve fully-qualified schema, prefer configured DB if available
            db = None
            try:
                if settings is not None:
                    db = getattr(settings, "SCAN_CATALOG_DB", None) or getattr(settings, "SNOWFLAKE_DATABASE", None)
            except Exception:
                db = None
            
            # Default to DATA_CLASSIFICATION_DB if no database is configured
            db = db or "DATA_CLASSIFICATION_DB"
            schema_fqn = f"{db}.DATA_CLASSIFICATION_GOVERNANCE"
            
            # Ensure database and schema exist
            try:
                if snowflake_connector:
                    # Check if database exists
                    db_check = snowflake_connector.execute_query(
                        f"SELECT 1 FROM INFORMATION_SCHEMA.DATABASES WHERE DATABASE_NAME = '{db}'"
                    )
                    if not db_check:
                        raise ValueError(f"Database '{db}' does not exist or is not accessible")
                        
                    # Check if schema exists
                    schema_check = snowflake_connector.execute_query(
                        f"SELECT 1 FROM {db}.INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = 'DATA_CLASSIFICATION_GOVERNANCE'"
                    )
                    if not schema_check:
                        raise ValueError(f"Schema 'DATA_CLASSIFICATION_GOVERNANCE' does not exist in database '{db}'")
            except Exception as e:
                logger.error(f"Error verifying database/schema: {str(e)}")
                raise

            # Ensure schema and tables exist (best-effort)
            try:
                ddl_block = f"""
                    create schema if not exists {schema_fqn};
                    create table if not exists {schema_fqn}.SENSITIVE_PATTERNS (
                      category string,
                      pattern string,
                      priority number default 0,
                      is_active boolean default true,
                      is_negative boolean default false,
                      updated_at timestamp_ntz default current_timestamp()
                    );
                    comment on column {schema_fqn}.SENSITIVE_PATTERNS.is_negative is 
                    'When TRUE, this pattern is used to reduce false positives by matching non-sensitive data';
                    create table if not exists {schema_fqn}.SENSITIVE_KEYWORDS (
                      category string,
                      keyword string,
                      priority number default 0,
                      is_active boolean default true,
                      updated_at timestamp_ntz default current_timestamp()
                    );
                    create table if not exists {schema_fqn}.SENSITIVITY_CATEGORIES (
                      category string,
                      cia_c number default 0,
                      cia_i number default 0,
                      cia_a number default 0,
                      is_active boolean default true,
                      updated_at timestamp_ntz default current_timestamp()
                    );
                    create table if not exists {schema_fqn}.SENSITIVE_BUNDLES (
                      bundle_name string,
                      category string,
                      column_name string,
                      boost float default 0,
                      is_active boolean default true,
                      updated_at timestamp_ntz default current_timestamp()
                    );
                    create table if not exists {schema_fqn}.COLUMN_BUNDLES (
                      bundle_name string,
                      category string,
                      columns array,
                      boost float default 0,
                      is_active boolean default true,
                      updated_at timestamp_ntz default current_timestamp()
                    );
                    create table if not exists {schema_fqn}.SENSITIVE_FLAGS (
                      flag_name string,
                      category string,
                      is_active boolean default true,
                      updated_at timestamp_ntz default current_timestamp()
                    );
                    create table if not exists {schema_fqn}.SENSITIVITY_THRESHOLDS (
                      category string,
                      threshold float,
                      is_active boolean default true,
                      updated_at timestamp_ntz default current_timestamp()
                    );
                    create table if not exists {schema_fqn}.SENSITIVITY_WEIGHTS (
                      factor string,
                      weight float,
                      is_active boolean default true,
                      updated_at timestamp_ntz default current_timestamp()
                    );
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

            # Only active rows; order by priority desc and updated_at desc when available
            rows_patterns = snowflake_connector.execute_query(
                f"""
                select 
                    category, 
                    pattern, 
                    coalesce(priority, 0) as priority,
                    coalesce(is_negative, false) as is_negative
                from {schema_fqn}.SENSITIVE_PATTERNS
                where coalesce(is_active, true)
                order by is_negative, priority desc
                """
            ) or []
            
            # Load negative patterns
            rows_negative = snowflake_connector.execute_query(
                f"""
                select 
                    category, 
                    pattern,
                    'NEG_' || row_number() over (order by priority desc) as pattern_name,
                    coalesce(priority, 0) as priority
                from {schema_fqn}.SENSITIVE_PATTERNS
                where coalesce(is_negative, false) and coalesce(is_active, true)
                order by priority desc
                """
            ) or []
            
            # Group negative patterns by category
            negative_patterns = {}
            for row in rows_negative:
                cat = row.get('CATEGORY')
                if not cat:
                    continue
                if cat not in negative_patterns:
                    negative_patterns[cat] = {'name_tokens': [], 'value_regex': []}
                
                pattern = row.get('PATTERN')
                if not pattern:
                    continue
                    
                # If pattern looks like a simple token (no regex special chars), add to name_tokens
                if re.match(r'^[A-Z0-9_]+$', pattern):
                    negative_patterns[cat]['name_tokens'].append(pattern)
                else:
                    negative_patterns[cat]['value_regex'].append(pattern)
            
            cfg["negative_patterns"] = negative_patterns
            rows_keywords = snowflake_connector.execute_query(
                f"""
                select category, keyword, coalesce(priority, 0) as priority
                from {schema_fqn}.SENSITIVE_KEYWORDS
                where coalesce(is_active, true)
                order by priority desc
                """
            ) or []
            rows_cats = snowflake_connector.execute_query(
                f"""
                select category, coalesce(cia_c,0) as cia_c, coalesce(cia_i,0) as cia_i, coalesce(cia_a,0) as cia_a
                from {schema_fqn}.SENSITIVITY_CATEGORIES
                where coalesce(is_active, true)
                """
            ) or []
            rows_bundles = snowflake_connector.execute_query(
                f"""
                select bundle_name, category, column_name, coalesce(boost,0.0) as boost
                from {schema_fqn}.SENSITIVE_BUNDLES
                where coalesce(is_active, true)
                order by bundle_name
                """
            ) or []
            # Column bundles (preferred)
            rows_col_bundles = []
            try:
                rows_col_bundles = snowflake_connector.execute_query(
                    f"""
                    select bundle_name, category, columns, coalesce(boost,0.0) as boost
                    from {schema_fqn}.COLUMN_BUNDLES
                    where coalesce(is_active, true)
                    order by bundle_name
                    """
                ) or []
            except Exception:
                rows_col_bundles = []

            # Load negative patterns (previously in INTERNAL_DATA_PATTERNS)
            rows_negative = []
            try:
                rows_negative = snowflake_connector.execute_query(
                    f"""
                    select pattern_type, pattern, coalesce(max_confidence,30) as max_confidence
                    from {schema_fqn}.SENSITIVE_PATTERNS
                    where coalesce(is_active, true) and is_negative = true
                    """
                ) or []
            except Exception as e:
                print(f"Warning: Could not load negative patterns: {str(e)}")
                rows_negative = []

            # Negative patterns functionality has been removed
            rows_meta = []
            try:
                rows_meta = snowflake_connector.execute_query(
                    f"""
                    select model_name, model_version, thresholds
                    from {schema_fqn}.MODEL_METADATA
                    where thresholds is not null
                    qualify row_number() over (partition by model_name order by coalesce(updated_at, current_timestamp()) desc) = 1
                    """
                ) or []
            except Exception:
                rows_meta = []

            # Build patterns with compiled regex
            patterns: List[Dict[str, Any]] = []
            for r in rows_patterns:
                try:
                    cat = str(r.get("CATEGORY") or r.get("category") or "").strip()
                    rx = str(r.get("PATTERN") or r.get("pattern") or "").strip()
                    if not cat or not rx:
                        continue
                    compiled = re.compile(rx)
                    patterns.append({"category": cat, "regex": rx, "compiled": compiled})
                except Exception:
                    continue

            # Build keywords (lowercased tokens)
            keywords: List[Dict[str, Any]] = []
            for r in rows_keywords:
                try:
                    cat = str(r.get("CATEGORY") or r.get("category") or "").strip()
                    tok = str(r.get("KEYWORD") or r.get("keyword") or "").strip().lower()
                    if not cat or not tok:
                        continue
                    keywords.append({"category": cat, "token": tok})
                except Exception:
                    continue

            # Build categories CIA mapping
            categories: Dict[str, Dict[str, int]] = {}
            for r in rows_cats:
                try:
                    cat = str(r.get("CATEGORY") or r.get("category") or "")
                    if not cat:
                        continue
                    categories[cat] = {
                        "C": int(r.get("CIA_C") if r.get("CIA_C") is not None else r.get("cia_c", 0)),
                        "I": int(r.get("CIA_I") if r.get("CIA_I") is not None else r.get("cia_i", 0)),
                        "A": int(r.get("CIA_A") if r.get("CIA_A") is not None else r.get("cia_a", 0)),
                    }
                except Exception:
                    continue

            # Build bundles aggregated by bundle_name
            from collections import defaultdict
            bundle_map: Dict[str, Dict[str, Any]] = {}
            for r in rows_bundles:
                try:
                    bname = str(r.get("BUNDLE_NAME") or r.get("bundle_name") or "").strip()
                    cat = str(r.get("CATEGORY") or r.get("category") or "").strip()
                    col = str(r.get("COLUMN_NAME") or r.get("column_name") or "").strip()
                    boost = float(r.get("BOOST") if r.get("BOOST") is not None else r.get("boost", 0.0))
                    if not bname or not cat or not col:
                        # Even if COLUMN_NAME is empty, try to pull from COLUMNS variant
                        pass
                    entry = bundle_map.setdefault(bname, {"bundle_name": bname, "category": cat, "columns": [], "boost": boost})
                    # Add single column_name if present
                    if col:
                        entry["columns"].append(col)
                    # Also extend with COLUMNS variant if provided (array of names)
                    try:
                        cols_var = r.get("COLUMNS") or r.get("columns")
                        if isinstance(cols_var, list):
                            for cval in cols_var:
                                cv = str(cval or "").strip()
                                if cv and cv not in entry["columns"]:
                                    entry["columns"].append(cv)
                        elif isinstance(cols_var, str) and cols_var.strip():
                            # If driver returns JSON string
                            import json as _json
                            try:
                                arr = _json.loads(cols_var)
                                if isinstance(arr, list):
                                    for cv in arr:
                                        s = str(cv or "").strip()
                                        if s and s not in entry["columns"]:
                                            entry["columns"].append(s)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    # If multiple rows disagree on boost/category, prefer the first (priority could be added later)
                except Exception:
                    continue
            bundles = list(bundle_map.values())

            thresholds = {}
            try:
                if rows_meta:
                    # Merge/flatten thresholds from latest model rows
                    for rm in rows_meta:
                        th = rm.get("THRESHOLDS") or rm.get("thresholds") or {}
                        if isinstance(th, str):
                            try:
                                th = json.loads(th)
                            except Exception:
                                th = {}
                        if isinstance(th, dict):
                            thresholds.update(th)
            except Exception:
                thresholds = {}

            # New governance tables
            # Per-category thresholds
            thresholds_cat = {}
            try:
                _thr_rows = snowflake_connector.execute_query(
                    f"select category, coalesce(threshold,0.5) as threshold from {schema_fqn}.SENSITIVITY_THRESHOLDS where coalesce(is_active,true)"
                ) or []
                for r in _thr_rows:
                    cat = str(r.get("CATEGORY") or r.get("category") or "").strip()
                    if cat:
                        thresholds_cat[cat] = float(r.get("THRESHOLD") if r.get("THRESHOLD") is not None else r.get("threshold", 0.5))
            except Exception:
                thresholds_cat = {}
            # Ensemble weights table
            weights_table = {}
            try:
                _w_rows = snowflake_connector.execute_query(
                    f"select factor, coalesce(weight,0.0) as weight from {schema_fqn}.SENSITIVITY_WEIGHTS where coalesce(is_active,true)"
                ) or []
                for r in _w_rows:
                    fct = str(r.get("FACTOR") or r.get("factor") or "").strip().lower()
                    if fct:
                        weights_table[fct] = float(r.get("WEIGHT") if r.get("WEIGHT") is not None else r.get("weight", 0.0))
            except Exception:
                weights_table = {}
            # Sensitive flags
            flags = []
            try:
                flags = snowflake_connector.execute_query(
                    f"select flag_name, category from {schema_fqn}.SENSITIVE_FLAGS where coalesce(is_active,true)"
                ) or []
            except Exception:
                flags = []

            # Flatten views for downstream components expecting list forms
            patterns_flat: List[Dict[str, Any]] = []
            try:
                for _cat, _items in (patterns or {}).items():
                    for _it in (_items or []):
                        patterns_flat.append({
                            "category": _cat,
                            "regex": _it.get("regex"),
                            "weight": _it.get("weight"),
                            "priority": _it.get("priority"),
                        })
            except Exception:
                patterns_flat = []
            keywords_flat: List[Dict[str, Any]] = []
            try:
                for _cat, _items in (keywords or {}).items():
                    for _it in (_items or []):
                        keywords_flat.append({
                            "category": _cat,
                            "token": _it.get("keyword") or _it.get("token"),
                            "match_type": _it.get("match_type"),
                            "weight": _it.get("weight"),
                            "priority": _it.get("priority"),
                        })
            except Exception:
                keywords_flat = []

            # Compose model metadata with ensemble weights and thresholds
            model_meta_out: Dict[str, Any] = {}
            try:
                ew: Dict[str, float] = {}
                for k, v in (weights_table or {}).items():
                    try:
                        ew[str(k).lower()] = float(v)
                    except Exception:
                        continue
                model_meta_out["ensemble_weights"] = ew
                model_meta_out["per_category_thresholds"] = dict(thresholds_cat or {})
                # Preserve any thresholds loaded from MODEL_METADATA as top-level map
                if isinstance(thresholds, dict):
                    model_meta_out.update({"thresholds": thresholds})
            except Exception:
                model_meta_out = {}

            cfg = {
                "patterns": patterns,
                "patterns_flat": patterns_flat,
                "keywords": keywords,
                "keywords_flat": keywords_flat,
                "categories": categories,
                "bundles": bundles,
                "column_bundles": [
                    {
                        "bundle_name": str(r.get("BUNDLE_NAME") or r.get("bundle_name") or "").strip(),
                        "category": str(r.get("CATEGORY") or r.get("category") or "").strip(),
                        "columns": (r.get("COLUMNS") or r.get("columns") or []),
                        "boost": float(r.get("BOOST") if r.get("BOOST") is not None else r.get("boost", 0.0)),
                    }
                    for r in (rows_col_bundles or [])
                ],
                "thresholds": thresholds,
                "model_metadata": model_meta_out,
                "thresholds_category": thresholds_cat,
                "weights_table": weights_table,
                "flags": [
                    {
                        "flag_name": str(r.get("FLAG_NAME") or r.get("flag_name") or ""),
                        "category": str(r.get("CATEGORY") or r.get("category") or ""),
                    }
                    for r in (flags or [])
                ],
            }
        except Exception:
            # If dynamic config cannot be loaded, return empty config to avoid hardcoded fallbacks
            cfg = dict(cfg_default)

        # Cache in session state (per-fqn)
        try:
            if st is not None and hasattr(st, "session_state"):
                st.session_state["sensitivity_config"] = cfg
                st.session_state["sensitivity_config_ts"] = int(__import__("time").time())
                cache = st.session_state.get("sensitivity_config_cache_v2") or {}
                cache[sc_fqn] = {"ts": int(__import__("time").time()), "data": cfg}
                st.session_state["sensitivity_config_cache_v2"] = cache
        except Exception:
            pass
        # Invalidate embedding caches on refresh to rebuild centroids from new config
        try:
            if force_refresh:
                self._category_embeds = {}
                self._category_centroids = {}
                self._embedding_cache = {}
        except Exception:
            pass
        return cfg

    def _log_alert(self, level: str, component: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                return
            sc = self._gov_schema_fqn()
            snowflake_connector.execute_non_query(
                f"""
                insert into {sc}.ALERT_LOGS (LEVEL, COMPONENT, MESSAGE, DETAILS)
                values (%(lvl)s, %(comp)s, %(msg)s, parse_json(%(det)s))
                """,
                {"lvl": level, "comp": component, "msg": message, "det": json.dumps(details or {})},
            )
        except Exception:
            pass

    def _persist_sensitive_audit(self, table_name: str, result: Dict[str, Any]) -> None:
        """Deprecated: table-level audit is handled by _persist_audit; keep as no-op to avoid syntax issues."""
        try:
            return
        except Exception:
            return

    def _load_config_from_database(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Load sensitivity configuration from the database.
        
        Returns:
            Dict containing the loaded configuration or None if loading fails
        """
        try:
            # Default configuration structure
            cfg = {
                "patterns": [],
                "keywords": [],
                "categories": {},
                "bundles": [],
                "compliance_mapping": {},
                "model_metadata": {
                    "thresholds": {}
                },
                "name_tokens": {}
            }
            
            # Load patterns
            patterns = snowflake_connector.execute_query(
                "SELECT * FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS WHERE IS_ACTIVE = TRUE"
            )
            if patterns:
                cfg["patterns"] = patterns
                
            # Load keywords
            keywords = snowflake_connector.execute_query(
                "SELECT * FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_KEYWORDS WHERE IS_ACTIVE = TRUE"
            )
            if keywords:
                cfg["keywords"] = keywords
                
            # Load categories
            categories = snowflake_connector.execute_query(
                "SELECT * FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_CATEGORIES"
            )
            if categories:
                cfg["categories"] = {cat["CATEGORY"]: cat for cat in categories}
                
            # Load bundles
            bundles = snowflake_connector.execute_query(
                "SELECT * FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_BUNDLES WHERE IS_ACTIVE = TRUE"
            )
            if bundles:
                cfg["bundles"] = bundles
                
            # Load model metadata
            model_metadata = snowflake_connector.execute_query(
                "SELECT * FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_MODEL_CONFIG"
            )
            if model_metadata:
                cfg["model_metadata"].update(model_metadata[0] if model_metadata else {})
                
            return cfg
            
        except Exception as e:
            print(f"Error loading configuration from database: {str(e)}")
            return None
            
    def _load_feedback(self) -> None:
        """Load feedback from JSON file."""
        try:
            if os.path.exists(self._feedback_file):
                with open(self._feedback_file, 'r') as f:
                    self._feedback = json.load(f) or {}
            else:
                self._feedback = {}
        except Exception:
            self._feedback = {}

    def _save_feedback(self) -> None:
        try:
            path = self._feedback_file_path()
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._feedback or {}, f, indent=2, sort_keys=True)
        except Exception:
            pass

    def load_sensitivity_config(self, force_refresh: bool = False, ttl_seconds: int = 120, schema_fqn: Optional[str] = None) -> Dict[str, Any]:
        """Load dynamic AI sensitivity configuration from Snowflake governance tables.

        Tables (expected under <DB>.DATA_CLASSIFICATION_GOVERNANCE):
        - SENSITIVE_PATTERNS (CATEGORY, PATTERN, [WEIGHT], [PRIORITY], [IS_ACTIVE], [OWNER], [VERSION])
        - SENSITIVE_KEYWORDS (CATEGORY, KEYWORD, [MATCH_TYPE], [WEIGHT], [PRIORITY], [IS_ACTIVE], [VERSION])
        - SENSITIVITY_CATEGORIES (CATEGORY, [C|CIA_C|CONFIDENTIALITY], [I|CIA_I|INTEGRITY], [A|CIA_A|AVAILABILITY], [MIN_THRESHOLD])
        - SENSITIVE_BUNDLES (BUNDLE_NAME, CATEGORY, COLUMNS(list or comma-string), [BOOST], [PRIORITY], [IS_ACTIVE], [VERSION])

        Returns: {patterns, keywords, categories, bundles, compliance_mapping, model_metadata, name_tokens}
        Caches in Streamlit session_state and simple in-memory cache to avoid frequent queries.
        """
        # Cache check (per-governance FQN)
        try:
            fqn = schema_fqn or self._gov_schema_fqn()
        except Exception:
            fqn = self._gov_schema_fqn()
        try:
            if st is not None and hasattr(st, "session_state") and not force_refresh:
                cache = st.session_state.get("sensitivity_config_cache_v2") or {}
                entry = cache.get(fqn) or {}
                ts = float(entry.get("ts") or 0.0)
                if ts and (__import__("time").time() - ts) < float(ttl_seconds):
                    cfg = entry.get("data") or {}
                    if cfg:
                        return cfg
        except Exception:
            pass

        sc_fqn = fqn

        def _q(sqls: list[str], params: Optional[dict] = None) -> list[dict]:
            if (snowflake_connector is None) or (not self.use_snowflake):
                return []
            for q in sqls:
                try:
                    rows = snowflake_connector.execute_query(q, params or {}) or []
                    return rows
                except Exception:
                    continue
            return []

        # Patterns (PATTERN_STRING column; IS_ACTIVE flag). Provide REGEX alias.
        patt_rows = _q([
            f"SELECT sc.CATEGORY_NAME AS CATEGORY, sp.PATTERN_STRING AS REGEX, COALESCE(sp.SENSITIVITY_WEIGHT,0.5) AS WEIGHT, 100 AS PRIORITY, COALESCE(sp.IS_ACTIVE, TRUE) AS ACTIVE, 'system' AS OWNER, sp.VERSION_NUMBER AS VERSION FROM {sc_fqn}.SENSITIVE_PATTERNS sp JOIN {sc_fqn}.SENSITIVITY_CATEGORIES sc ON sp.CATEGORY_ID = sc.CATEGORY_ID WHERE COALESCE(sp.IS_ACTIVE, TRUE) = TRUE",
            f"SELECT sc.CATEGORY_NAME AS CATEGORY, sp.PATTERN_STRING AS REGEX, COALESCE(sp.SENSITIVITY_WEIGHT,0.5) AS WEIGHT, 100 AS PRIORITY, TRUE AS ACTIVE, 'system' AS OWNER, sp.VERSION_NUMBER AS VERSION FROM {sc_fqn}.SENSITIVE_PATTERNS sp JOIN {sc_fqn}.SENSITIVITY_CATEGORIES sc ON sp.CATEGORY_ID = sc.CATEGORY_ID",
        ])
        patterns: Dict[str, List[Dict[str, Any]]] = {}
        for r in patt_rows:
            try:
                if not bool(r.get("ACTIVE", True)):
                    continue
                cat = str(r.get("CATEGORY") or "").strip()
                rx = str(r.get("REGEX") or "").strip()
                if not cat or not rx:
                    continue
                patterns.setdefault(cat, []).append({
                    "regex": rx,
                    "weight": float(r.get("WEIGHT") or 0.5),
                    "priority": int(r.get("PRIORITY") or 100),
                    "owner": r.get("OWNER"),
                    "version": r.get("VERSION"),
                })
            except Exception:
                continue
        for cat in list(patterns.keys()):
            patterns[cat] = sorted(patterns[cat], key=lambda x: (-int(x.get("priority", 100)), -float(x.get("weight", 0.5))))

        # Keywords (MATCH_TYPE may not exist; default to 'FUZZY'). Use IS_ACTIVE.
        kw_rows = _q([
            f"SELECT sc.CATEGORY_NAME AS CATEGORY, sk.KEYWORD_STRING AS KEYWORD, COALESCE(sk.MATCH_TYPE, 'FUZZY') AS MATCH_TYPE, COALESCE(sk.SENSITIVITY_WEIGHT,0.5) AS WEIGHT, 100 AS PRIORITY, COALESCE(sk.IS_ACTIVE, TRUE) AS ACTIVE, sk.VERSION_NUMBER AS VERSION FROM {sc_fqn}.SENSITIVE_KEYWORDS sk JOIN {sc_fqn}.SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID WHERE COALESCE(sk.IS_ACTIVE, TRUE) = TRUE",
            f"SELECT sc.CATEGORY_NAME AS CATEGORY, sk.KEYWORD_STRING AS KEYWORD, 'FUZZY' AS MATCH_TYPE, COALESCE(sk.SENSITIVITY_WEIGHT,0.5) AS WEIGHT, 100 AS PRIORITY, TRUE AS ACTIVE, sk.VERSION_NUMBER AS VERSION FROM {sc_fqn}.SENSITIVE_KEYWORDS sk JOIN {sc_fqn}.SENSITIVITY_CATEGORIES sc ON sk.CATEGORY_ID = sc.CATEGORY_ID",
        ])
        keywords: Dict[str, List[Dict[str, Any]]] = {}
        for r in kw_rows:
            try:
                if not bool(r.get("ACTIVE", True)):
                    continue
                cat = str(r.get("CATEGORY") or "").strip()
                kw = str(r.get("KEYWORD") or "").strip()
                if not cat or not kw:
                    continue
                keywords.setdefault(cat, []).append({
                    "keyword": kw,
                    "match_type": str(r.get("MATCH_TYPE") or "fuzzy").lower(),
                    "weight": float(r.get("WEIGHT") or 0.5),
                    "priority": int(r.get("PRIORITY") or 100),
                    "version": r.get("VERSION"),
                })
            except Exception:
                continue
        for cat in list(keywords.keys()):
            keywords[cat] = sorted(keywords[cat], key=lambda x: (-int(x.get("priority", 100)), -float(x.get("weight", 0.5))))

        # Categories → CIA map (support C/I/A, CIA_*, or CONFIDENTIALITY/INTEGRITY/AVAILABILITY)
        cat_rows = _q([
            f"SELECT CATEGORY_NAME AS CATEGORY, COALESCE(CONFIDENTIALITY_LEVEL, 0) AS C, COALESCE(INTEGRITY_LEVEL, 0) AS I, COALESCE(AVAILABILITY_LEVEL, 0) AS A, COALESCE(DETECTION_THRESHOLD, 0.5) AS MIN_THRESHOLD FROM {sc_fqn}.SENSITIVITY_CATEGORIES WHERE COALESCE(IS_ACTIVE, TRUE) = TRUE",
            f"SELECT CATEGORY_NAME AS CATEGORY, COALESCE(CONFIDENTIALITY_LEVEL, 0) AS C, COALESCE(INTEGRITY_LEVEL, 0) AS I, COALESCE(AVAILABILITY_LEVEL, 0) AS A, 0.5 AS MIN_THRESHOLD FROM {sc_fqn}.SENSITIVITY_CATEGORIES",
        ])
        categories: Dict[str, Dict[str, Any]] = {}
        for r in cat_rows:
            try:
                cat = str(r.get("CATEGORY") or "").strip()
                if not cat:
                    continue
                categories[cat] = {
                    "C": int(r.get("C", 0)),
                    "I": int(r.get("I", 0)),
                    "A": int(r.get("A", 0)),
                    "MIN_THRESHOLD": float(r.get("MIN_THRESHOLD", 0.5)),
                }
            except Exception:
                continue

        # Bundles (BUNDLE_NAME; IS_ACTIVE). Alias to NAME for downstream usage.
        bun_rows = _q([
            f"SELECT BUNDLE_NAME AS NAME, CATEGORY, COLUMNS, COALESCE(BOOST, 0.1) AS BOOST, COALESCE(PRIORITY, 100) AS PRIORITY, COALESCE(IS_ACTIVE, TRUE) AS ACTIVE, VERSION FROM {sc_fqn}.SENSITIVE_BUNDLES",
            f"SELECT BUNDLE_NAME AS NAME, CATEGORY, COLUMNS, COALESCE(BOOST, 0.1) AS BOOST, 100 AS PRIORITY, TRUE AS ACTIVE, VERSION FROM {sc_fqn}.SENSITIVE_BUNDLES",
        ])
        bundles: List[Dict[str, Any]] = []
        for r in bun_rows:
            try:
                if not bool(r.get("ACTIVE", True)):
                    continue
                cols_raw = r.get("COLUMNS")
                cols: List[str] = []
                if isinstance(cols_raw, list):
                    cols = [str(x) for x in cols_raw]
                elif isinstance(cols_raw, str):
                    cols = [c.strip() for c in cols_raw.split(',') if c.strip()]
                bundles.append({
                    "name": r.get("NAME"),
                    "category": r.get("CATEGORY"),
                    "columns": cols,
                    "boost": float(r.get("BOOST") or 0.1),
                    "priority": int(r.get("PRIORITY") or 100),
                    "active": True,
                    "version": r.get("VERSION"),
                })
            except Exception:
                continue
        bundles = sorted(bundles, key=lambda x: (-int(x.get("priority", 100)), -float(x.get("boost", 0.1))))

        # Initialize the config dictionary with all required keys and default values
        cfg = {
            "patterns": patterns or [],
            "keywords": keywords or {},
            "categories": categories or {},
            "bundles": bundles or [],
            "compliance_mapping": {},  # Will be populated below
            "model_metadata": {},      # Will be populated below
            "name_tokens": {},         # Will be populated below
            "thresholds": {},          # Will be populated below
            "cia_rules": {}            # Will be populated below
        }
        
        # Negative patterns functionality has been removed
        # Compliance mapping (prefer IS_ACTIVE; fallback to TRUE)
        cmp_rows = _q([
            f"SELECT CATEGORY_ID AS DETECTED_CATEGORY, COMPLIANCE_STANDARD AS FRAMEWORK, DESCRIPTION AS RULE, 100 AS PRIORITY, COALESCE(IS_ACTIVE, TRUE) AS ACTIVE FROM {sc_fqn}.COMPLIANCE_MAPPING",
            f"SELECT CATEGORY_ID AS DETECTED_CATEGORY, COMPLIANCE_STANDARD AS FRAMEWORK, DESCRIPTION AS RULE, 100 AS PRIORITY, TRUE AS ACTIVE FROM {sc_fqn}.COMPLIANCE_MAPPING",
        ])
        compliance_mapping: Dict[str, List[Dict[str, Any]]] = {}
        for r in cmp_rows:
            try:
                if not bool(r.get("ACTIVE", True)):
                    continue
                dc = str(r.get("DETECTED_CATEGORY") or "").strip()
                fw = str(r.get("FRAMEWORK") or "").strip()
                rl = r.get("RULE")
                pr = int(r.get("PRIORITY") or 100)
                if dc and fw:
                    compliance_mapping.setdefault(dc, []).append({"framework": fw, "rule": rl, "priority": pr})
            except Exception:
                continue
        for k in list(compliance_mapping.keys()):
            compliance_mapping[k] = sorted(compliance_mapping[k], key=lambda x: -int(x.get("priority", 100)))

        # Model config (key/value) → nested metadata
        cfg_rows = _q([
            f"SELECT MODEL_NAME AS KEY, CONFIGURATION AS VALUE FROM {sc_fqn}.SENSITIVITY_MODEL_CONFIG WHERE COALESCE(IS_ACTIVE, TRUE) = TRUE",
        ])
        def _parse_cfg(rows: list[dict]) -> Dict[str, Any]:
            out: Dict[str, Any] = {"ensemble_weights": {}, "thresholds": {}, "sampling": {}, "flags": {}}
            for r in (rows or []):
                try:
                    k = str(r.get("KEY") or "").strip().lower()
                    v_raw = r.get("VALUE")
                    v: Any = v_raw
                    try:
                        # try JSON first
                        v = json.loads(v_raw) if isinstance(v_raw, str) and v_raw.strip().startswith(('{','[')) else v_raw
                    except Exception:
                        pass
                    # simple casting for numerics/bools
                    if isinstance(v, str):
                        vl = v.lower().strip()
                        if vl in ("true","false"):
                            v = (vl == "true")
                        else:
                            try:
                                if "." in vl:
                                    v = float(vl)
                                else:
                                    v = int(vl)
                            except Exception:
                                pass
                    if k.startswith("ensemble."):
                        out["ensemble_weights"][k.split(".",1)[1]] = v
                    elif k.startswith("thresholds."):
                        out["thresholds"][k.split(".",1)[1]] = v
                    elif k.startswith("sampling."):
                        out["sampling"][k.split(".",1)[1]] = v
                    elif k.startswith("flags."):
                        out["flags"][k.split(".",1)[1]] = v
                    else:
                        out[k] = v
                except Exception:
                    continue
            # Invalidate embedding caches if forced refresh or model metadata changed
            try:
                if force_refresh:
                    self._category_embeds = {}
                    self._category_centroids = {}
                    self._embedding_cache = {}
            except Exception:
                pass
            return out
        
        model_metadata: Dict[str, Any] = _parse_cfg(cfg_rows)

        # Name tokens have been removed in favor of SENSITIVE_KEYWORDS
        name_tokens: Dict[str, List[Dict[str, Any]]] = {}

        cfg: Dict[str, Any] = {
            "patterns": patterns,
            "keywords": keywords,
            "categories": categories,
            "bundles": bundles,
            "compliance_mapping": compliance_mapping,
            "model_metadata": model_metadata,
            "name_tokens": name_tokens
        }

        # Save to caches
        try:
            if st is not None and hasattr(st, "session_state"):
                st.session_state["sensitivity_config"] = cfg
                st.session_state["sensitivity_config_cache_v2"] = {"ts": __import__("time").time(), "data": cfg}
        except Exception:
            pass
        return cfg

    def load_feedback_from_snowflake(self) -> None:
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                return
            rows = snowflake_connector.execute_query(
                """
                select 
                  table_name,
                  column_name,
                  corrected_category,
                  corrected_confidence,
                  payload,
                  created_at
                from {schema_fqn}.SENSITIVE_FEEDBACK
                order by created_at desc
                limit 10000
                """
            ) or []
            fb = self._feedback or {}
            fb.setdefault("tables", {})
            for r in rows:
                t = (r.get("TABLE_NAME") or "").split(".")[-1].upper()
                c = r.get("COLUMN_NAME")
                pl = r.get("PAYLOAD")
                corr_cat = r.get("CORRECTED_CATEGORY")
                corr_conf = r.get("CORRECTED_CONFIDENCE")
                try:
                    if isinstance(pl, str):
                        pl = json.loads(pl)
                except Exception:
                    pl = {}
                tentry = fb["tables"].setdefault(t, {"columns": {}, "suppress": []})
                if c:
                    cu = str(c).upper()
                    centry = tentry["columns"].setdefault(cu, {})
                    if corr_cat:
                        centry["set_categories"] = [str(corr_cat)]
                    if corr_conf is not None:
                        try:
                            centry["set_confidence"] = int(float(corr_conf))
                        except Exception:
                            pass
                # table-level suppress not modeled in SENSITIVE_FEEDBACK; skip
            self._feedback = fb
            self._save_feedback()
        except Exception:
            pass

    def record_feedback(self, table_name: str, column_name: Optional[str], action: str, payload: Optional[Dict[str, Any]] = None) -> None:
        """Record a user correction for a table/column.

        action examples:
        - "suppress": payload={"categories":["PII"]}
        - "set_categories": payload={"categories":["Operational"]}
        - "set_confidence": payload={"confidence": 0..100}
        Applies at column level when column_name provided, else table-level.
        """
        try:
            t = (table_name or "").split(".")[-1].upper()
            c = (column_name or "").upper() if column_name else None
            fb = self._feedback or {}
            fb.setdefault("tables", {})
            tentry = fb["tables"].setdefault(t, {"columns": {}, "suppress": []})
            if c:
                centry = tentry["columns"].setdefault(c, {})
                if action == "suppress":
                    cats = [str(x) for x in (payload or {}).get("categories", [])]
                    prev = set([str(x) for x in centry.get("suppress", [])])
                    centry["suppress"] = sorted(list(prev.union(set(cats))))
                elif action == "set_categories":
                    centry["set_categories"] = [str(x) for x in (payload or {}).get("categories", [])]
                elif action == "set_confidence":
                    centry["set_confidence"] = int((payload or {}).get("confidence", 0))
            else:
                if action == "suppress":
                    cats = [str(x) for x in (payload or {}).get("categories", [])]
                    prev = set([str(x) for x in tentry.get("suppress", [])])
                    tentry["suppress"] = sorted(list(prev.union(set(cats))))
            self._feedback = fb
            self._save_feedback()
            # Persist to Snowflake feedback table when enabled
            try:
                if self.use_snowflake and snowflake_connector is not None:
                    user_id = None
                    username = None
                    if st is not None:
                        try:
                            user_id = st.session_state.get("user_id") or st.session_state.get("username")
                            username = st.session_state.get("username") or st.session_state.get("user")
                        except Exception:
                            pass
                    if not username:
                        try:
                            username = os.environ.get("USERNAME") or os.environ.get("USER")
                        except Exception:
                            username = None
                    # Persist governed feedback record
                    pl = payload or {}
                    corr_cat = None
                    corr_conf = None
                    if action == "set_categories":
                        try:
                            cats = [str(x) for x in (pl or {}).get("categories", [])]
                            corr_cat = cats[0] if cats else None
                        except Exception:
                            corr_cat = None
                    elif action == "set_confidence":
                        try:
                            corr_conf = int((pl or {}).get("confidence", 0))
                        except Exception:
                            corr_conf = None
                    payload_sql = json.dumps(pl).replace("'", "''")
                    snowflake_connector.execute_non_query(
                        f"""
                        insert into {schema_fqn}.SENSITIVE_FEEDBACK
                          (TABLE_NAME, COLUMN_NAME, CORRECTED_CATEGORY, CORRECTED_CONFIDENCE, PAYLOAD, CREATED_BY)
                        select %(tb_full)s, %(col)s, %(ccat)s, %(cconf)s, parse_json('{payload_sql}'), %(uname)s
                        """,
                        {
                            "tb_full": table_name,
                            "col": column_name,
                            "ccat": corr_cat,
                            "cconf": corr_conf,
                            "uname": username,
                        },
                    )
                    # Append to immutable feedback log (best-effort)
                    try:
                        ai_cat = (pl or {}).get("ai_category")
                        snowflake_connector.execute_non_query(
                            """
                            insert into {schema_fqn}.SENSITIVE_FEEDBACK_LOG
                              (TABLE_NAME, COLUMN_NAME, AI_CATEGORY, USER_CATEGORY, CONFIDENCE, FEEDBACK_ACTION, REVIEWER)
                            select %(tb_full)s, %(col)s, %(ai)s, %(uc)s, %(conf)s, %(act)s, %(uname)s
                            """,
                            {
                                "tb_full": table_name,
                                "col": column_name,
                                "ai": ai_cat,
                                "uc": corr_cat,
                                "conf": corr_conf,
                                "act": action,
                                "uname": username,
                            },
                        )
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass

    def _apply_feedback_overrides(self, table_name: str, column_name: str, categories: List[str], conf_0_1: float) -> Tuple[List[str], float]:
        """Apply table/column-level feedback overrides to categories and confidence (0..1)."""
        try:
            t = (table_name or "").split(".")[-1].upper()
            c = (column_name or "").upper()
            fb = self._feedback or {}
            tentry = (fb.get("tables", {}) or {}).get(t)
            cats = list(categories or [])
            conf = float(conf_0_1 or 0.0)
            if tentry:
                # table-level suppress
                ts = set([str(x) for x in (tentry.get("suppress") or [])])
                if ts:
                    cats = [x for x in cats if x not in ts]
                # column-level overrides
                centry = (tentry.get("columns", {}) or {}).get(c)
                if centry:
                    csup = set([str(x) for x in (centry.get("suppress") or [])])
                    if csup:
                        cats = [x for x in cats if x not in csup]
                    set_cats = centry.get("set_categories")
                    if set_cats is not None:
                        cats = [str(x) for x in set_cats]
                    if "set_confidence" in centry:
                        try:
                            conf = max(0.0, min(1.0, float(int(centry.get("set_confidence", 0)))/100.0))
                        except Exception:
                            pass
            return sorted(list(set(cats))), max(0.0, min(1.0, conf))
        except Exception:
            return categories, conf_0_1

    def set_mode(self, use_snowflake: bool = True) -> None:
        """Set acquisition mode. If False or connector unavailable, virtual mode is used."""
        self.use_snowflake = bool(use_snowflake)

    # ---- Virtual Catalog Management ----
    def set_virtual_table_profile(
        self,
        table_name: str,
        columns: Optional[List[Dict[str, Any]]] = None,
        samples: Optional[Any] = None,
    ) -> None:
        """Register or update a virtual profile for a table.

        columns: list of {"name": str, "type": Optional[str]}
        samples: pandas.DataFrame or list of row dicts
        """
        prof: Dict[str, Any] = self._virtual_catalog.get(table_name, {})
        if columns is not None:
            prof["columns"] = columns
        if samples is not None:
            if isinstance(samples, pd.DataFrame):
                prof["samples"] = samples.reset_index(drop=True)
            else:
                try:
                    prof["samples"] = pd.DataFrame(samples)
                except Exception:
                    prof["samples"] = pd.DataFrame()
        self._virtual_catalog[table_name] = prof

    def clear_virtual_catalog(self) -> None:
        self._virtual_catalog.clear()
    
    def discover_candidate_tables(
        self,
        include_schemas: Optional[List[str]] = None,
        exclude_name_tokens: Optional[List[str]] = None,
        min_row_count: int = 0,
    ) -> List[Dict[str, Any]]:
        """Discover candidate tables for classification.

        - Snowflake mode: query INFORMATION_SCHEMA.TABLES and filter.
        - Virtual mode: list from internal `_virtual_catalog`.

        Returns rows with: FULL_NAME, TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, ROW_COUNT, LAST_ALTERED, PRE_FLAGGED
        """
        tokens_ex = set([t.upper() for t in (exclude_name_tokens or [
            "LOOKUP","REFERENCE","CONFIG","PRODUCT","DIM_","DIM","REF_","MAP_","CODE","CURRENCY"
        ])])
        out: List[Dict[str, Any]] = []
        # Snowflake path
        if self.use_snowflake and snowflake_connector is not None:
            try:
                # Attempt to read all tables with basic stats
                db = None
                if settings is not None:
                    db = getattr(settings, "SCAN_CATALOG_DB", None) or getattr(settings, "SNOWFLAKE_DATABASE", None)
                if not db:
                    # Fallback to current DB; INFORMATION_SCHEMA without DB may fail in some drivers
                    rows_db = snowflake_connector.execute_query("select current_database() as DB") or []
                    db = rows_db[0].get("DB") if rows_db else None
                if not db:
                    raise RuntimeError("No database context available for discovery")
                schema_filter_sql = ""
                params: Dict[str, Any] = {}
                if include_schemas:
                    schema_filter_sql = " and upper(TABLE_SCHEMA) in (" + ",".join(["%(s"+str(i)+")s" for i,_ in enumerate(include_schemas)]) + ")"
                    for i, s in enumerate(include_schemas):
                        params[f"s{i}"] = str(s).upper()
                rows = snowflake_connector.execute_query(
                    f"""
                    select TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, ROW_COUNT, LAST_ALTERED
                    from {db}.INFORMATION_SCHEMA.TABLES
                    where TABLE_TYPE in ('BASE TABLE','VIEW') {schema_filter_sql}
                    """,
                    params,
                ) or []
                # Merge pre-flags from ASSETS when present
                pre_flags: Dict[str, Dict[str, Any]] = {}
                try:
                    sc = self._gov_schema_fqn()
                    inv = snowflake_connector.execute_query(
                        f"select FULLY_QUALIFIED_NAME AS FULL_NAME, CONTAINS_PII AS PII_DETECTED, CONTAINS_FINANCIAL_DATA AS FINANCIAL_DATA_DETECTED, REGULATORY_DATA AS IP_DATA_DETECTED, SOC_RELEVANT, SOX_RELEVANT from {sc}.ASSETS"
                    ) or []
                    for r in inv:
                        pre_flags[str(r.get("FULL_NAME") or "").upper()] = r
                except Exception:
                    pre_flags = {}
                for r in rows:
                    sch = str(r.get("TABLE_SCHEMA") or "")
                    tbl = str(r.get("TABLE_NAME") or "")
                    full = f"{r.get('TABLE_CATALOG')}.{sch}.{tbl}"
                    base = tbl.upper()
                    if any(tok and (tok in base or base.startswith(tok)) for tok in tokens_ex):
                        # Skip low-risk by name unless row count is extremely high
                        if int(r.get("ROW_COUNT") or 0) < max(1000, min_row_count):
                            continue
                    if int(r.get("ROW_COUNT") or 0) < int(min_row_count):
                        continue
                    pf = pre_flags.get(full.upper()) or {}
                    out.append({
                        "FULL_NAME": full,
                        "TABLE_CATALOG": r.get("TABLE_CATALOG"),
                        "TABLE_SCHEMA": sch,
                        "TABLE_NAME": tbl,
                        "ROW_COUNT": r.get("ROW_COUNT"),
                        "LAST_ALTERED": r.get("LAST_ALTERED"),
                        "PRE_FLAGGED": bool(any(bool(pf.get(k)) for k in ["PII_DETECTED","FINANCIAL_DATA_DETECTED","IP_DATA_DETECTED","SOC_RELEVANT","SOX_RELEVANT"])),
                    })
                return out
            except Exception:
                # Fall through to virtual
                pass
        # Virtual discovery from internal catalog
        try:
            for full, prof in (self._virtual_catalog or {}).items():
                try:
                    parts = str(full).split('.')
                    if len(parts) == 3:
                        cat, sch, tbl = parts
                    else:
                        cat, sch, tbl = "VIRTUAL_DB", "PUBLIC", parts[-1]
                    base = tbl.upper()
                    if any(tok and (tok in base or base.startswith(tok)) for tok in tokens_ex):
                        # Skip unless there is significant data
                        sample_df = prof.get("samples") if isinstance(prof, dict) else None
                        if isinstance(sample_df, pd.DataFrame) and len(sample_df) < max(100, min_row_count):
                            continue
                    row_count = 0
                    try:
                        if isinstance(prof.get("samples"), pd.DataFrame):
                            row_count = int(len(prof.get("samples")))
                    except Exception:
                        row_count = 0
                    if row_count < int(min_row_count):
                        continue
                    out.append({
                        "FULL_NAME": full,
                        "TABLE_CATALOG": cat,
                        "TABLE_SCHEMA": sch,
                        "TABLE_NAME": tbl,
                        "ROW_COUNT": row_count,
                        "LAST_ALTERED": None,
                        "PRE_FLAGGED": False,
                    })
                except Exception:
                    continue
        except Exception:
            return []
        return out
    
    def get_table_metadata(self, table_name: str) -> Dict[str, Any]:
        """
        Get metadata for a specific table.
        
        Args:
            table_name: Full table name (schema.table)
            
        Returns:
            Dictionary containing table metadata
        """
        # Try Snowflake first (hybrid mode)
        if self.use_snowflake and snowflake_connector is not None:
            try:
                parts_sf = table_name.split('.')
                if len(parts_sf) != 3:
                    raise ValueError("Table name must be in format database.schema.table")
                database, schema, table = parts_sf
                q = f"""
                SELECT 
                    TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, CREATED, LAST_ALTERED
                FROM {database}.INFORMATION_SCHEMA.TABLES
                WHERE TABLE_SCHEMA = '{schema}' AND TABLE_NAME = '{table}'
                LIMIT 1
                """
                res = snowflake_connector.execute_query(q) or []
                if res:
                    meta = dict(res[0])
                    # Basic domain from table name as enrichment
                    up = (meta.get("TABLE_NAME") or "").upper()
                    if any(k in up for k in ["EMP","HR","PAYROLL","STAFF","WORKER"]):
                        meta["TABLE_DOMAIN"] = "HR"
                    elif any(k in up for k in ["INV","GL","LEDGER","AR","AP","FIN","BANK"]):
                        meta["TABLE_DOMAIN"] = "Finance"
                    elif any(k in up for k in ["PATIENT","MED","HEALTH","ICD","RX"]):
                        meta["TABLE_DOMAIN"] = "Healthcare"
                    else:
                        meta["TABLE_DOMAIN"] = "General"
                    return meta
            except Exception:
                # Fallback to virtual
                pass

        # AI-inferred metadata: derive basic components and consult virtual catalog
        parts = table_name.split('.')
        if len(parts) == 3:
            database, schema, table = parts
        elif len(parts) == 2:
            database, schema = parts[0], parts[0]
            table = parts[1]
        else:
            # Keep tolerant: accept bare table and synthesize
            database, schema, table = "VIRTUAL_DB", "PUBLIC", parts[0]

        meta = {
            "TABLE_CATALOG": database,
            "TABLE_SCHEMA": schema,
            "TABLE_NAME": table,
            "TABLE_TYPE": "BASE TABLE",
            "CREATED": None,
            "LAST_ALTERED": None,
        }
        # If a virtual profile exists, enrich type using common naming cues
        prof = self._virtual_catalog.get(table_name) or {}
        cols = prof.get("columns") or []
        # Simple table context inference from name
        up = (table or "").upper()
        if any(k in up for k in ["EMP", "HR", "PAYROLL", "STAFF", "WORKER"]):
            meta["TABLE_DOMAIN"] = "HR"
        elif any(k in up for k in ["INV", "GL", "LEDGER", "AR", "AP", "FIN", "BANK"]):
            meta["TABLE_DOMAIN"] = "Finance"
        elif any(k in up for k in ["PATIENT", "MED", "HEALTH", "ICD", "RX"]):
            meta["TABLE_DOMAIN"] = "Healthcare"
        else:
            meta["TABLE_DOMAIN"] = "General"
        meta["COLUMN_COUNT"] = len(cols)
        return meta
    
    def get_column_metadata(self, table_name: str) -> List[Dict[str, Any]]:
        """
        Get column metadata for a specific table.
        
        Args:
            table_name: Full table name (schema.table)
            
        Returns:
            List of dictionaries containing column metadata
        """
        # Try Snowflake first for column metadata (hybrid mode)
        if self.use_snowflake and snowflake_connector is not None:
            try:
                parts_sf = table_name.split('.')
                if len(parts_sf) != 3:
                    raise ValueError("Table name must be in format database.schema.table")
                database, schema, table = parts_sf
                q = f"""
                SELECT 
                    COLUMN_NAME,
                    DATA_TYPE,
                    IS_NULLABLE,
                    COLUMN_DEFAULT,
                    CHARACTER_MAXIMUM_LENGTH,
                    COMMENT as COLUMN_COMMENT,
                    ORDINAL_POSITION
                FROM {database}.INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = '{schema}' AND TABLE_NAME = '{table}'
                ORDER BY ORDINAL_POSITION
                """
                res = snowflake_connector.execute_query(q) or []
                if res:
                    return res
            except Exception:
                pass

        # Return virtual metadata (if present), or infer from samples / naming
        prof = self._virtual_catalog.get(table_name) or {}
        cols: List[Dict[str, Any]] = prof.get("columns") or []
        if cols:
            # Normalize keys to match former shape
            out: List[Dict[str, Any]] = []
            for c in cols:
                out.append({
                    "COLUMN_NAME": c.get("name") or c.get("COLUMN_NAME"),
                    "DATA_TYPE": c.get("type") or c.get("DATA_TYPE") or self._infer_type_from_name(c.get("name")),
                    "IS_NULLABLE": c.get("IS_NULLABLE", "YES"),
                    "COLUMN_DEFAULT": c.get("COLUMN_DEFAULT"),
                    "CHARACTER_MAXIMUM_LENGTH": c.get("CHARACTER_MAXIMUM_LENGTH"),
                })
            return out

    # ---- Embedding support (optional) ----
    def _ensure_embedder(self) -> None:
        """Lazily initialize an embedding backend if available. Non-fatal on failure."""
        if self._embedding_backend != 'none' and self._embedder is not None:
            return
        # Try sentence-transformers first
        try:
            if np is None:
                raise RuntimeError("numpy not available")
            from sentence_transformers import SentenceTransformer  # type: ignore
            self._embedder = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
            self._embedding_backend = 'st'
            return
        except Exception:
            self._embedder = None
            self._embedding_backend = 'none'

    def _get_embedding(self, text: str):
        try:
            if self._embedding_backend == 'st' and self._embedder is not None and np is not None:
                key = str(text or "").strip()
                if key in self._embedding_cache:
                    return self._embedding_cache[key]
                vec = self._embedder.encode([key], normalize_embeddings=True)
                out = np.array(vec[0], dtype=float)
                self._embedding_cache[key] = out
                return out
        except Exception:
            return None
        return None

    def _preprocess_text(self, txt: Optional[str]) -> str:
        t = (txt or "").lower()
        t = re.sub(r"[^a-z0-9_\s]+", " ", t)
        t = re.sub(r"\s+", " ", t).strip()
        # Basic stopwords removal (minimal, offline)
        sw = {
            "the","a","an","of","and","or","to","in","for","on","at","by","with","from","is","are","as","be","this","that","these","those","it","its","their","our","your","my"
        }
        tokens = [w for w in t.split() if w not in sw]
        return " ".join(tokens)

    def _validate_semantic_evidence(self, table_name: str, predicted_category: str, table_metadata: Dict[str, Any], sample_data: pd.DataFrame) -> List[str]:
        """
        Validate semantic prediction against column-level evidence.
        Checks column names and sample data for consistency with predicted category.
        Returns list of validation notes (positive/negative evidence).
        """
        evidence: List[str] = []
        try:
            # Get column metadata
            columns = self.get_column_metadata(table_name) or []
            col_names = [str(c.get("COLUMN_NAME") or "").lower() for c in columns]
            col_comments = [str(c.get("COLUMN_COMMENT") or "").lower() for c in columns]

            # Category-specific keywords for validation
            cat_keywords = {
                "PERSONAL_DATA": ["name", "email", "phone", "address", "ssn", "dob", "passport", "id", "identifier", "customer", "individual"],
                "FINANCIAL_DATA": ["salary", "payroll", "account", "bank", "credit", "debit", "transaction", "ledger", "sox", "revenue", "expense", "invoice", "payment"],
                "REGULATORY_DATA": ["compliance", "gdpr", "ccpa", "hipaa", "pci", "law", "regulation", "consent", "data subject", "rights"],
                "PROPRIETARY_DATA": ["trade secret", "intellectual", "property", "confidential", "design", "source code", "roadmap", "pricing"],
                "INTERNAL_DATA": ["internal", "business", "operational", "non sensitive", "standard", "general", "reference", "lookup", "config"]
            }
            keywords = cat_keywords.get(predicted_category, [])

            # Check column names for matching keywords
            name_matches = sum(1 for name in col_names for kw in keywords if kw in name)
            comment_matches = sum(1 for comment in col_comments for kw in keywords if kw in comment)
            if name_matches > 0:
                evidence.append(f"Column names match: {name_matches} columns contain category keywords")
            if comment_matches > 0:
                evidence.append(f"Column comments match: {comment_matches} columns have relevant comments")

            # Check sample data for patterns (e.g., email-like for PERSONAL_DATA)
            if isinstance(sample_data, pd.DataFrame) and not sample_data.empty:
                sample_str = sample_data.astype(str).values.flatten()
                sample_text = " ".join([str(v).lower() for v in sample_str[:100]])  # limit to avoid overload
                sample_matches = sum(1 for kw in keywords if kw in sample_text)
                if sample_matches > 0:
                    evidence.append(f"Sample data patterns match: found {sample_matches} keyword occurrences")

            # Negative evidence if no matches
            if not evidence:
                evidence.append("No strong column-level evidence supporting prediction")

        except Exception as e:
            evidence.append(f"Validation error: {e}")
        return evidence

    def _canonical_category_texts(self) -> Dict[str, str]:
        return {
            "PERSONAL_DATA": "personal data pii name email phone address ssn passport dob identifier customer individual",
            "FINANCIAL_DATA": "financial salary payroll account bank credit debit transaction ledger sox revenue expense invoice payment",
            "REGULATORY_DATA": "regulatory compliance gdpr ccpa hipaa pci law regulation consent data subject rights",
            "PROPRIETARY_DATA": "proprietary trade secret intellectual property confidential design source code roadmap pricing",
            "INTERNAL_DATA": "internal business operational non sensitive standard data general reference lookup config"
        }

    def _ensure_canonical_category_embeddings(self) -> None:
        # Prefer governance-derived embeddings if available; fallback to static texts
        try:
            self._ensure_gov_category_embeddings()
            if self._gov_cat_vecs:
                self._canonical_cat_vecs = dict(self._gov_cat_vecs)
                return
        except Exception:
            pass
        if self._canonical_cat_vecs:
            return
        try:
            if self._embedding_backend != 'st' or self._embedder is None or np is None:
                return
            texts = self._canonical_category_texts()
            out: Dict[str, Any] = {}
            for k, v in texts.items():
                pv = self._preprocess_text(v)
                vec = self._get_embedding(pv)
                if vec is not None:
                    out[k] = vec
            self._canonical_cat_vecs = out
        except Exception:
            self._canonical_cat_vecs = {}

    def _ensure_gov_category_embeddings(self, force_refresh: bool = False) -> None:
        """Build and cache category embeddings from governance tables (name, description, examples, threshold).

        Caches in-memory and in st.session_state with a signature of category defs to avoid recompute.
        Populates self._gov_cat_vecs and self._gov_cat_thresholds when backend is available.
        """
        try:
            # Need embedding backend
            if self._embedding_backend != 'st' or self._embedder is None or np is None:
                return
            cfg = self.load_sensitivity_config(force_refresh=force_refresh) or {}
            cats_cfg = cfg.get("categories") or {}
            if not isinstance(cats_cfg, dict) or not cats_cfg:
                return
            # Build canonical strings and thresholds from config rows (best-effort)
            names: List[str] = []
            canon: Dict[str, str] = {}
            thresholds: Dict[str, float] = {}
            compliance_map: Dict[str, List[str]] = {}
            ex_map: Dict[str, List[str]] = {}
            for name, row in cats_cfg.items():
                try:
                    cname = str(name).strip()
                    if not cname:
                        continue
                    desc = str(row.get("DESCRIPTION") or row.get("DESC") or row.get("DETAILS") or "")
                    # EXAMPLES may be array, JSON, or CSV string; flatten to short list
                    ex_raw = row.get("EXAMPLES") or row.get("EXAMPLE") or []
                    examples: List[str] = []
                    if isinstance(ex_raw, list):
                        examples = [str(x) for x in ex_raw if str(x).strip()][:3]
                    elif isinstance(ex_raw, str):
                        examples = [e.strip() for e in ex_raw.split(',') if e.strip()][:3]
                    thr = None
                    for k in ("DETECTION_THRESHOLD", "MIN_THRESHOLD", "THRESHOLD"):
                        if row.get(k) is not None:
                            try:
                                thr = float(row.get(k))
                                break
                            except Exception:
                                pass
                    if thr is None:
                        # fallback to model metadata default
                        mm = (cfg.get("model_metadata") or cfg.get("thresholds") or {})
                        try:
                            thr = float(mm.get("default_threshold", 0.7))
                        except Exception:
                            thr = 0.7
                    thresholds[cname] = float(thr)
                    parts = [f"Category: {cname}"]
                    if desc:
                        parts.append(desc)
                    if examples:
                        parts.append("Examples: " + "; ".join([str(e)[:80] for e in examples]))
                    # Add compliance frameworks
                    compliance_raw = row.get("COMPLIANCE_FRAMEWORKS") or row.get("COMPLIANCE") or []
                    compliance = [str(c).strip() for c in compliance_raw] if isinstance(compliance_raw, list) else [str(compliance_raw).strip()] if compliance_raw else []
                    compliance_map[cname] = compliance
                    canon[cname] = ". ".join(parts)
                    names.append(cname)
                    ex_list: List[str] = []
                    if desc:
                        ex_list.append(desc)
                    if examples:
                        ex_list.extend(examples)
                    if ex_list:
                        ex_map[cname] = ex_list
                except Exception:
                    continue
            if not canon:
                return
            # Compute signature of config to cache embeddings
            try:
                sig_src = json.dumps({"names": names, "canon": canon, "thr": thresholds, "comp": compliance_map}, sort_keys=True)[:4096]
                sig = hashlib.sha1(sig_src.encode("utf-8")).hexdigest()
            except Exception:
                sig = None
            # Check st.session_state cache
            cache_hit = False
            if st is not None and hasattr(st, "session_state") and not force_refresh:
                cache = st.session_state.get("cat_embed_cache_v1") or {}
                entry = cache.get("data") if cache.get("sig") == sig else None
                if entry and isinstance(entry, dict):
                    self._gov_cat_vecs = entry.get("vecs") or {}
                    self._gov_cat_thresholds = entry.get("thr") or {}
                    self._gov_cat_compliance = entry.get("comp") or {}
                    self._gov_cat_exemplars = entry.get("ex") or {}
                    self._gov_cat_sig = sig
                    if self._gov_cat_vecs:
                        return
            # Compute embeddings
            out: Dict[str, Any] = {}
            ex_out: Dict[str, List[Any]] = {}
            for cname, text in canon.items():
                pv = self._preprocess_text(text)
                vec = self._get_embedding(pv)
                if vec is not None:
                    out[cname] = vec
                ex_vecs: List[Any] = []
                for ex in ex_map.get(cname, [])[:5]:
                    ev = self._get_embedding(self._preprocess_text(ex))
                    if ev is not None:
                        ex_vecs.append(ev)
                if ex_vecs:
                    ex_out[cname] = ex_vecs
            self._gov_cat_vecs = out
            self._gov_cat_thresholds = thresholds
            self._gov_cat_compliance = compliance_map
            self._gov_cat_exemplars = ex_out
            self._gov_cat_sig = sig
            # Store in st.session_state
            if st is not None and hasattr(st, "session_state") and sig:
                st.session_state["cat_embed_cache_v1"] = {"sig": sig, "data": {"vecs": out, "thr": thresholds, "comp": compliance_map, "ex": ex_out}}
        except Exception:
            # Keep previous cache if any
            return

    def _get_semantic_matches_gov(self, enriched_context: str, categories: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get semantic category matches using governance-derived MiniLM embeddings (Step 3).

        Prefers governance vectors/thresholds; falls back to legacy if unavailable.
        Returns {'category': str, 'confidence': float, 'threshold': float, 'compliance': List[str]} or error dict.
        """
        try:
            # Ensure embedding backend is ready
            self._ensure_embedder()
            # Ensure governance embeddings are loaded (caches in session state)
            self._ensure_gov_category_embeddings()
            cat_vecs, cat_thresholds, cat_compliance = self.get_category_embeddings_and_thresholds()
            ex = getattr(self, "_gov_cat_exemplars", {}) or {}
            if categories:
                cat_vecs = {k: v for k, v in cat_vecs.items() if k in categories}
                cat_thresholds = {k: v for k, v in cat_thresholds.items() if k in categories}
                cat_compliance = {k: v for k, v in cat_compliance.items() if k in categories}
                ex = {k: v for k, v in ex.items() if k in categories}
            if not cat_vecs:
                return {'category': 'UNKNOWN', 'confidence': 0.0, 'reason': 'No matching governance category embeddings available'}

            # Preprocess context to improve cosine similarity quality
            context_vec = self._get_embedding(self._preprocess_text(enriched_context))
            if context_vec is None:
                return {'category': 'UNKNOWN', 'confidence': 0.0, 'reason': 'Failed to embed context'}

            semantic_scores = {}
            for cat, vec in cat_vecs.items():
                try:
                    base = float(np.dot(context_vec, vec))
                except Exception:
                    base = 0.0
                best = base
                for ev in ex.get(cat, [])[:5]:
                    try:
                        s2 = float(np.dot(context_vec, ev))
                        if s2 > best:
                            best = s2
                    except Exception:
                        continue
                semantic_scores[cat] = best

            # Get pattern boosts
            cfg = self.load_sensitivity_config() or {}
            pattern_boosts = self._detect_patterns_in_context(enriched_context, cfg.get('patterns', {}))

            # Combine scores: weighted average (semantic 0.7, pattern 0.3)
            combined_scores = {}
            for cat in cat_vecs.keys():
                sem = semantic_scores.get(cat, 0.0)
                pat = pattern_boosts.get(cat, 0.0)
                combined = 0.7 * sem + 0.3 * pat
                combined_scores[cat] = combined

            # Find best category
            best_cat = max(combined_scores, key=combined_scores.get) if combined_scores else None
            best_score = combined_scores.get(best_cat, 0.0) if best_cat else 0.0

            # Return as list for compatibility
            threshold = cat_thresholds.get(best_cat, 0.7) if best_cat else 0.7
            compliance = cat_compliance.get(best_cat, []) if best_cat else []
            if best_cat and best_score >= threshold:
                return [{'category': best_cat, 'confidence': float(best_score), 'threshold': threshold, 'compliance': compliance}]
            else:
                return []

        except Exception as e:
            return []

    def _detect_patterns_in_context(self, enriched_context: str, category_patterns: Dict[str, Any]) -> Dict[str, float]:
        """Detect regex/pattern matches in enriched context and return category confidence boosts.

        Returns dict of category -> confidence boost (0-1), based on pattern hits.
        """
        boosts = {}
        try:
            if not category_patterns or not enriched_context:
                return boosts
            context_lower = enriched_context.lower()
            for cat, patterns in category_patterns.items():
                if not isinstance(patterns, dict):
                    continue
                boost = 0.0
                # Check keyword matches
                keywords = patterns.get('keywords', []) or patterns.get('keyword_list', [])
                if isinstance(keywords, list):
                    for kw in keywords:
                        if str(kw).lower() in context_lower:
                            boost += 0.3  # Keyword hit boost
                # Check regex patterns
                regexes = patterns.get('patterns', []) or patterns.get('regex_list', [])
                if isinstance(regexes, list):
                    for rex in regexes:
                        try:
                            import re
                            if re.search(str(rex), enriched_context, re.IGNORECASE):
                                boost += 0.5  # Regex hit boost
                        except Exception:
                            pass
                if boost > 0:
                    boosts[cat] = min(boost, 1.0)  # Cap at 1.0
        except Exception:
            pass
        return boosts

    def _ensure_category_embeddings(self, patterns: Dict[str, Any]) -> None:
        if self._category_embeds and self._category_centroids:
            return
        # Build token lists per category
        cat_map: Dict[str, List[str]] = {}
        for cat, spec in (patterns or {}).items():
            toks = [str(t) for t in (spec.get('name_tokens') or [])]
            # Add common synonyms for better recall
            if cat == 'PII':
                toks.extend(['dob', 'birth date', 'date of birth', 'given name', 'surname'])
            if cat == 'Financial':
                toks.extend(['account number', 'card number', 'routing number'])
            # De-dup and sanitize
            tokens = []
            seen = set()
            for t in toks:
                tt = re.sub(r"[_\-]+", " ", t).strip()
                if tt and tt.lower() not in seen:
                    tokens.append(tt)
                    seen.add(tt.lower())
            cat_map[cat] = tokens
        # Compute embeddings
        out: Dict[str, List[Tuple[str, Any]]] = {}
        centroids: Dict[str, Any] = {}
        for cat, toks in cat_map.items():
            vecs = []
            for t in toks:
                v = self._get_embedding(t)
                if v is not None:
                    vecs.append((t, v))
            out[cat] = vecs
            try:
                if vecs and np is not None:
                    mat = np.stack([v for (_tok, v) in vecs], axis=0)
                    c = np.mean(mat, axis=0)
                    # Normalize centroid to unit for cosine similarity
                    n = float(np.linalg.norm(c) or 0.0)
                    if n > 0:
                        c = c / n
                    centroids[cat] = c
            except Exception:
                centroids[cat] = None
        self._category_embeds = out
        self._category_centroids = centroids

    def initialize_sensitive_detection(self, categories: Optional[List[str]] = None) -> Dict[str, Any]:
        """Initialize optional semantic embedding backend and precompute reusable category embeddings.

        Args:
            categories: Optional list of category names to include. Defaults to
                ["PII", "PHI", "Financial", "SOX", "Regulatory", "Operational", "TradeSecret"].

        Returns:
            A dict with backend info and loaded categories, e.g. {"backend": "st"|"none", "categories": [...]}
        """
        # Ensure embedding backend (non-fatal if unavailable)
        self._ensure_embedder()
        # Resolve categories and patterns
        default_cats = ["PII", "PHI", "Financial", "SOX", "Regulatory", "Operational", "TradeSecret"]
        include = [str(c) for c in (categories or default_cats)]
        patterns = self._sensitivity_patterns() or {}
        # Build embeddings only when backend available
        if self._embedding_backend != 'none' and self._embedder is not None and np is not None:
            # Build token lists per requested category
            cat_map: Dict[str, List[str]] = {}
            for cat, spec in patterns.items():
                if cat not in include:
                    continue
                toks = [str(t) for t in (spec.get('name_tokens') or [])]
                if cat == 'PII':
                    toks.extend(['dob', 'birth date', 'date of birth', 'given name', 'surname'])
                if cat == 'Financial':
                    toks.extend(['account number', 'card number', 'routing number'])
                # normalize and deduplicate
                tokens: List[str] = []
                seen = set()
                for t in toks:
                    tt = re.sub(r"[_\-]+", " ", t).strip()
                    if tt and tt.lower() not in seen:
                        tokens.append(tt)
                        seen.add(tt.lower())
                cat_map[cat] = tokens
            # Compute embeddings per category
            out: Dict[str, List[Tuple[str, Any]]] = {}
            for cat, toks in cat_map.items():
                vecs: List[Tuple[str, Any]] = []
                for t in toks:
                    v = self._get_embedding(t)
                    if v is not None:
                        vecs.append((t, v))
                out[cat] = vecs
            self._category_embeds = out
            # Compute centroids
            cents: Dict[str, Any] = {}
            for cat, pairs in out.items():
                try:
                    if pairs:
                        mat = np.stack([v for (_t, v) in pairs], axis=0)
                        c = np.mean(mat, axis=0)
                        n = float(np.linalg.norm(c) or 0.0)
                        if n > 0:
                            c = c / n
                        cents[cat] = c
                except Exception:
                    cents[cat] = None
            self._category_centroids = cents
        else:
            # Backend unavailable; keep empty embeds for graceful fallback
            self._category_embeds = {}
            self._category_centroids = {}
        return {"backend": self._embedding_backend, "categories": include}

    def _ensure_zsc(self) -> None:
        try:
            if self._zsc is not None:
                return
            from transformers import pipeline  # type: ignore
            self._zsc = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
        except Exception:
            self._zsc = None

    def get_embedding_backend(self) -> str:
        """Return the current embedding backend identifier: 'st' or 'none'."""
        return self._embedding_backend
    
    def get_sample_data(self, table_name: str, sample: Any = 100) -> pd.DataFrame:
        """
        Get sample data from a table for analysis with flexible configuration.

        Usage modes:
        - Legacy: sample is int => number of rows to fetch (existing behavior)
        - Advanced: sample is dict => sample_config with keys:
            min_rows, max_rows, stratify_column, weight_column, sample_fraction

        Returns DataFrame containing sample rows.
        """
        # Advanced dict mode when talking to Snowflake
        if isinstance(sample, dict) and self.use_snowflake and snowflake_connector is not None:
            cfg = sample or {}
            min_rows = int(cfg.get("min_rows", 1000))
            max_rows = int(cfg.get("max_rows", 100000))
            sample_fraction = float(cfg.get("sample_fraction", 0.05))  # 5% default
            stratify = cfg.get("stratify_column")
            weight = cfg.get("weight_column")
            method = "random"
            frac_used = None
            try:
                # Count rows
                cnt_row = snowflake_connector.execute_query(f"SELECT COUNT(*) AS TOTAL_ROWS FROM {table_name}") or []
                total_rows = int(list(cnt_row[0].values())[0]) if cnt_row else 0
                if total_rows <= min_rows:
                    method = "full"
                    q = f"SELECT * FROM {table_name}"
                    res = snowflake_connector.execute_query(q) or []
                else:
                    # Decide fraction
                    if total_rows > max_rows:
                        # 1-5% cap, or provided
                        frac_used = min(0.05, max(0.01, float(sample_fraction or 0.02)))
                    else:
                        frac_used = min(0.10, max(0.02, float(sample_fraction or 0.05)))
                    percent = int(round(frac_used * 100))
                    # Strategy selection
                    if stratify:
                        method = "stratified"
                        # Approximate stratified sampling using QUALIFY with ROW_NUMBER per partition
                        q = (
                            f"SELECT * FROM {table_name} "
                            f"QUALIFY ROW_NUMBER() OVER (PARTITION BY {stratify} ORDER BY RANDOM()) "
                            f"<= CEIL({frac_used} * COUNT(*) OVER (PARTITION BY {stratify}))"
                        )
                        res = snowflake_connector.execute_query(q) or []
                    elif weight:
                        method = "weighted"
                        limit_n = max(1, int(frac_used * total_rows))
                        q = f"SELECT * FROM {table_name} ORDER BY {weight} DESC LIMIT {limit_n}"
                        res = snowflake_connector.execute_query(q) or []
                    else:
                        method = "random"
                        q = f"SELECT * FROM {table_name} SAMPLE BERNOULLI ({percent})"
                        res = snowflake_connector.execute_query(q) or []
                df_out = pd.DataFrame(res) if res else pd.DataFrame()
                # Persist sampling metadata
                try:
                    schema_fqn = "DATA_CLASSIFICATION_GOVERNANCE"
                    if settings is not None:
                        db = getattr(settings, "SCAN_CATALOG_DB", None) or getattr(settings, "SNOWFLAKE_DATABASE", None)
                        if db:
                            schema_fqn = f"{db}.DATA_CLASSIFICATION_GOVERNANCE"
                    snowflake_connector.execute_non_query(
                        f"""
                        create table if not exists {schema_fqn}.SENSITIVE_AUDIT (
                          audit_id number autoincrement,
                          table_name string,
                          sample_hash string,
                          sampling_method string,
                          sample_fraction float,
                          scanned_at timestamp_ntz default current_timestamp(),
                          primary key (audit_id)
                        )
                        """
                    )
                    # Compute sample hash
                    try:
                        payload = df_out.to_csv(index=False).encode("utf-8") if not df_out.empty else b""
                        sample_hash = hashlib.sha256(payload).hexdigest()
                    except Exception:
                        sample_hash = None
                    snowflake_connector.execute_non_query(
                        f"""
                        insert into {schema_fqn}.SENSITIVE_AUDIT (table_name, sample_hash, sampling_method, sample_fraction)
                        values (%(t)s, %(h)s, %(m)s, %(f)s)
                        """,
                        {"t": table_name, "h": sample_hash, "m": method, "f": float(frac_used or 1.0)},
                    )
                except Exception:
                    pass
                return df_out.reset_index(drop=True)
            except Exception:
                # Fall through to legacy behavior below
                pass

        prof = self._virtual_catalog.get(table_name) or {}
        df: Optional[pd.DataFrame] = prof.get("samples")
        if df is None:
            # Legacy Snowflake simple sampling (when sample is int)
            if self.use_snowflake and snowflake_connector is not None and isinstance(sample, int):
                try:
                    # Prefer dynamic sampling if service is available
                    if _dyn_sample_table is not None:
                        df_dyn = _dyn_sample_table(table_name)
                        if df_dyn is not None and not df_dyn.empty:
                            if sample and sample > 0:
                                return df_dyn.head(int(sample)).reset_index(drop=True)
                            return df_dyn.reset_index(drop=True)
                    # Randomized sampling to reduce head() bias when dynamic sampler isn't available
                    q = (
                        f"SELECT * FROM {table_name} "
                        f"ORDER BY UNIFORM(0::float,1::float,RANDOM()) "
                        f"LIMIT {max(0, int(sample or 0))}"
                    )
                    res = snowflake_connector.execute_query(q) or []
                    if res:
                        return pd.DataFrame(res)
                except Exception:
                    pass
            return pd.DataFrame()
        if isinstance(sample, int) and sample > 0:
            return df.head(sample).reset_index(drop=True)
        return df.reset_index(drop=True)

    # --- Public semantic utilities for special category detection ---
    def get_semantic_matches(self, text: str, categories: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Compute semantic similarity of the given text against category centroids and
        return ranked matches. Relies on initialize_sensitive_detection() to set up
        the embedding backend and centroids. Non-fatal if embeddings are unavailable.

        Returns list of {category, confidence} with confidence in [0,1].
        """
        try:
            # Normalize categories mapping to internal keys
            requested = categories or [
                "PII", "Financial", "Regulatory", "TradeSecret", "Internal", "Public"
            ]
            # Initialize embeddings (no-op if backend not available)
            self.initialize_sensitive_detection(categories=requested)
            if self._embedding_backend == 'none' or self._embedder is None:
                return []
            v = self._get_embedding(text)
            if v is None:
                return []
            # Unit normalize for cosine
            try:
                if np is not None:
                    n = float(np.linalg.norm(v) or 0.0)
                    if n > 0:
                        v = v / n
            except Exception:
                pass
            out: List[Dict[str, Any]] = []
            cents = self._category_centroids or {}
            for cat, c in cents.items():
                if cat not in requested:
                    continue
                try:
                    if c is None:
                        continue
                    # Cosine similarity ~ dot due to normalization
                    sim = float(np.dot(v, c)) if np is not None else 0.0
                    # Clamp to [0,1]
                    conf = max(0.0, min(1.0, (sim + 1.0) / 2.0))  # map [-1,1] -> [0,1]
                    out.append({"category": cat, "confidence": conf})
                except Exception:
                    continue
            out.sort(key=lambda r: r.get("confidence", 0.0), reverse=True)
            return out
        except Exception:
            return []

    def build_semantic_context(self, table_name: str, max_sample_values: int = 5) -> str:
        """
        Build contextual text from table/column metadata, descriptions, and sample values
        to support semantic detection. Non-fatal if Snowflake is unavailable.
        """
        parts: List[str] = []
        try:
            meta = self.get_table_metadata(table_name) or {}
            t_db = str(meta.get("TABLE_CATALOG") or "")
            t_sc = str(meta.get("TABLE_SCHEMA") or "")
            t_nm = str(meta.get("TABLE_NAME") or "")
            t_desc = str(meta.get("COMMENT") or meta.get("DESCRIPTION") or "")
            if t_db or t_sc or t_nm:
                parts.append(f"Table {t_db}.{t_sc}.{t_nm}")
            if t_desc:
                parts.append(f"Description: {t_desc}")
            # Columns
            cols = self.get_column_metadata(table_name) or []
            col_names = [str(c.get("COLUMN_NAME") or "") for c in cols]
            if col_names:
                parts.append("Columns: " + ", ".join([c for c in col_names if c]))
            # Sample values
            df = self.get_sample_data(table_name, 100)
            if df is not None and not df.empty:
                for c in df.columns:
                    try:
                        vals = [str(v) for v in pd.Series(df[c]).dropna().astype(str).unique().tolist()[:max_sample_values]]
                        if vals:
                            parts.append(f"{c} samples: " + ", ".join(vals))
                    except Exception:
                        continue
            # Optional governance glossary/policy snippets from governance DB; fallback to config
            try:
                gov_db = None
                try:
                    if resolve_governance_db is not None:
                        gov_db = resolve_governance_db()
                except Exception:
                    gov_db = None
                use_gloss = bool(getattr(self, "use_governance_glossary", True))
                if use_gloss and gov_db and self.use_snowflake and snowflake_connector is not None:
                    try:
                        gloss = snowflake_connector.execute_query(
                            f"SELECT TERM_NAME, DEFINITION FROM {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.BUSINESS_GLOSSARY LIMIT 5"
                        ) or []
                        if gloss:
                            parts.append(
                                "Glossary: "
                                + "; ".join([f"{g.get('TERM_NAME')}: {str(g.get('DEFINITION') or '')[:80]}" for g in gloss[:3]])
                            )
                    except Exception:
                        pass
                    try:
                        pol = snowflake_connector.execute_query(
                            f"SELECT POLICY_NAME, EXCERPT FROM {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.POLICY_TEXT LIMIT 5"
                        ) or []
                        if pol:
                            parts.append(
                                "Policy: "
                                + "; ".join([f"{p.get('POLICY_NAME')}: {str(p.get('EXCERPT') or '')[:80]}" for p in pol[:2]])
                            )
                    except Exception:
                        pass
                else:
                    cfg = self.load_sensitivity_config()
                    glossary = cfg.get("glossary") or []
                    policy_texts = cfg.get("policies") or []
                    if isinstance(glossary, list):
                        parts.extend([str(g.get("definition") or g.get("term") or "") for g in glossary[:3]])
                    if isinstance(policy_texts, list):
                        parts.extend([str(p.get("text") or p.get("policy") or "") for p in policy_texts[:3]])
            except Exception:
                pass
        except Exception:
            pass
        return "\n".join([p for p in parts if p])

    def collect_metadata_and_samples(self, table_name: str, sample_rows: int = 10) -> Dict[str, Any]:
        """
        Step 1: Collect metadata and sample data for a table from Snowflake INFORMATION_SCHEMA
        and enrich with glossary/policy context. Returns a structure suitable for embedding.

        Output keys:
          - table: table metadata dict (TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, COMMENT, CREATED, LAST_ALTERED)
          - columns: list of column metadata dicts (COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, CHARACTER_MAXIMUM_LENGTH, COLUMN_COMMENT, ORDINAL_POSITION)
          - samples: List[Dict[str, Any]] of up to sample_rows
          - glossary: optional list of glossary snippets
          - policies: optional list of policy snippets
          - context_text: concatenated text summary for embedding
        """
        out: Dict[str, Any] = {
            "table": {},
            "columns": [],
            "samples": [],
            "glossary": [],
            "policies": [],
            "context_text": "",
        }
        try:
            parts = (table_name or "").split(".")
            if len(parts) != 3:
                return out
            database, schema, table = parts
            q = lambda s: '"' + str(s).replace('"', '""') + '"'
            fqn = f"{q(database)}.{q(schema)}.{q(table)}"

            # Table metadata
            tbl_rows = []
            try:
                if self.use_snowflake and snowflake_connector is not None:
                    tbl_rows = snowflake_connector.execute_query(
                        f"""
                        SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, COMMENT, CREATED, LAST_ALTERED
                        FROM {database}.INFORMATION_SCHEMA.TABLES
                        WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
                        LIMIT 1
                        """,
                        {"s": schema, "t": table},
                    ) or []
            except Exception:
                tbl_rows = []
            if tbl_rows:
                out["table"] = dict(tbl_rows[0])

            # Column metadata with comments
            col_rows = []
            try:
                if self.use_snowflake and snowflake_connector is not None:
                    col_rows = snowflake_connector.execute_query(
                        f"""
                        SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, CHARACTER_MAXIMUM_LENGTH, COMMENT as COLUMN_COMMENT, ORDINAL_POSITION
                        FROM {database}.INFORMATION_SCHEMA.COLUMNS
                        WHERE TABLE_SCHEMA = %(s)s AND TABLE_NAME = %(t)s
                        ORDER BY ORDINAL_POSITION
                        """,
                        {"s": schema, "t": table},
                    ) or []
            except Exception:
                col_rows = []
            out["columns"] = col_rows

            # Sample rows (top N). Prefer Snowflake SAMPLE (n ROWS), fallback to LIMIT
            rows = []
            try:
                if self.use_snowflake and snowflake_connector is not None:
                    n = max(1, int(sample_rows or 10))
                    try:
                        rows = snowflake_connector.execute_query(
                            f"SELECT * FROM {fqn} SAMPLE ({n} ROWS)"
                        ) or []
                    except Exception:
                        rows = snowflake_connector.execute_query(
                            f"SELECT * FROM {fqn} LIMIT {n}"
                        ) or []
            except Exception:
                rows = []
            out["samples"] = rows[: max(0, int(sample_rows or 10))]

            # Governance glossary/policy enrichment if available; else config fallback
            gloss_snips: List[str] = []
            pol_snips: List[str] = []
            try:
                gov_db = None
                try:
                    if resolve_governance_db is not None:
                        gov_db = resolve_governance_db()
                except Exception:
                    gov_db = None
                if gov_db and self.use_snowflake and snowflake_connector is not None:
                    try:
                        gloss = snowflake_connector.execute_query(
                            f"SELECT TERM_NAME, DEFINITION FROM {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.BUSINESS_GLOSSARY LIMIT 5"
                        ) or []
                        gloss_snips = [f"{g.get('TERM_NAME')}: {str(g.get('DEFINITION') or '')[:120]}" for g in gloss[:3]]
                    except Exception:
                        gloss_snips = []
                    try:
                        pol = snowflake_connector.execute_query(
                            f"SELECT POLICY_NAME, EXCERPT FROM {gov_db}.DATA_CLASSIFICATION_GOVERNANCE.POLICY_TEXT LIMIT 5"
                        ) or []
                        pol_snips = [f"{p.get('POLICY_NAME')}: {str(p.get('EXCERPT') or '')[:120]}" for p in pol[:3]]
                    except Exception:
                        pol_snips = []
                else:
                    cfg = self.load_sensitivity_config()
                    glossary = cfg.get("glossary") or []
                    policy_texts = cfg.get("policies") or []
                    if isinstance(glossary, list):
                        gloss_snips = [str(g.get("definition") or g.get("term") or "") for g in glossary[:3]]
                    if isinstance(policy_texts, list):
                        pol_snips = [str(p.get("text") or p.get("policy") or "") for p in policy_texts[:3]]
            except Exception:
                gloss_snips, pol_snips = [], []
            out["glossary"] = gloss_snips
            out["policies"] = pol_snips

            # Build context text
            ctx_parts: List[str] = []
            tmeta = out.get("table") or {}
            if tmeta:
                ctx_parts.append(
                    f"Table {tmeta.get('TABLE_CATALOG')}.{tmeta.get('TABLE_SCHEMA')}.{tmeta.get('TABLE_NAME')}"
                )
                if tmeta.get("COMMENT"):
                    ctx_parts.append(f"Description: {tmeta.get('COMMENT')}")
            # Columns with comments
            if out["columns"]:
                cols_txt = []
                for c in out["columns"][:50]:
                    nm = str(c.get("COLUMN_NAME") or "")
                    ty = str(c.get("DATA_TYPE") or "")
                    cm = c.get("COLUMN_COMMENT")
                    seg = nm
                    if ty:
                        seg += f" : {ty}"
                    if cm:
                        seg += f" ({str(cm)[:60]})"
                    cols_txt.append(seg)
                if cols_txt:
                    ctx_parts.append("Columns: " + ", ".join(cols_txt))
            if rows and out["columns"]:
                try:
                    from collections import Counter
                    top_map: Dict[str, List[str]] = {}
                    for c in out["columns"][:20]:
                        nm = str(c.get("COLUMN_NAME") or "")
                        vals: List[str] = []
                        for r in rows:
                            if isinstance(r, dict) and nm in r and r[nm] is not None:
                                vals.append(str(r[nm]))
                        if vals:
                            freq = Counter(vals)
                            top_vals = [k for (k, _cnt) in freq.most_common(2)]
                            if top_vals:
                                top_map[nm] = top_vals
                    if top_map:
                        pairs = []
                        for k in list(top_map.keys())[:5]:
                            pairs.append(f"{k}=" + "|".join([str(v)[:32] for v in top_map[k]]))
                        if pairs:
                            ctx_parts.append("ColumnSamples: " + "; ".join(pairs))
                except Exception:
                    try:
                        first = rows[0]
                        if isinstance(first, dict):
                            sv = "; ".join([f"{k}={str(v)[:64]}" for k, v in first.items()])
                            if sv:
                                ctx_parts.append("Samples: " + sv)
                    except Exception:
                        pass
            if gloss_snips:
                ctx_parts.append("Glossary: " + "; ".join(gloss_snips))
            if pol_snips:
                ctx_parts.append("Policy: " + "; ".join(pol_snips))
            out["context_text"] = " \n".join([p for p in ctx_parts if p])
        except Exception:
            return out
        return out

    # ---- Step 2: Preprocessing & Context Enrichment ----
    def _normalize_text(self, text: Optional[str]) -> str:
        """
        Normalize textual fields:
        - lowercase
        - insert spaces for camelCase and digit-alpha boundaries
        - replace underscores and multiple spaces with single spaces
        - remove most punctuation (keep alphanumerics and spaces)
        - expand common abbreviations (best-effort)
        """
        try:
            s = str(text or "")
            # Insert spaces between camelCase and around digits/letters boundaries
            s = re.sub(r"([a-z])([A-Z])", r"\1 \2", s)
            s = re.sub(r"([A-Za-z])(\d)", r"\1 \2", s)
            s = re.sub(r"(\d)([A-Za-z])", r"\1 \2", s)
            # Replace underscores/dots with spaces
            s = s.replace("_", " ").replace(".", " ")
            # Lowercase
            s = s.lower()
            # Remove punctuation except spaces and alphanumerics
            s = re.sub(r"[^a-z0-9\s]", " ", s)
            # Collapse whitespace
            s = re.sub(r"\s+", " ", s).strip()
            # Abbreviation expansions (lightweight)
            abbr = {
                "dob": "date of birth",
                "ssn": "social security number",
                "addr": "address",
                "cust": "customer",
                "acct": "account",
                "tel": "telephone",
                "ph": "phone",
                "qty": "quantity",
                "amt": "amount",
                "num": "number",
                "txn": "transaction",
                "emp": "employee",
            }
            tokens = s.split()
            s = " ".join([abbr.get(t, t) for t in tokens])
            return s
        except Exception:
            return str(text or "")

    def _tokenize(self, text: str) -> List[str]:
        try:
            return re.findall(r"\b\w+\b", (text or "").lower())
        except Exception:
            return []

    def _value_fingerprint(self, values: List[str]) -> List[str]:
        feats: List[str] = []
        try:
            has_email = False
            has_phone = False
            high_digit = False
            for v in values[:50]:
                s = str(v)
                if not has_email and re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", s):
                    has_email = True
                if not has_phone and re.search(r"\b\+?\d[\d\s().-]{6,}\b", s):
                    has_phone = True
                ds = sum(ch.isdigit() for ch in s)
                if len(s) >= 8 and ds / max(1, len(s)) >= 0.6:
                    high_digit = True
            if has_email:
                feats.append("email_like")
            if has_phone:
                feats.append("phone_like")
            if high_digit:
                feats.append("high_digit_ratio")
        except Exception:
            return feats
        return feats

    def _top_relevant(self, query_text: str, candidates: List[str], limit: int) -> List[str]:
        """
        Return top-N candidates by simple token-overlap relevance to query_text.
        Deterministic and lightweight (no embedding requirement).
        """
        try:
            q_tokens = set(self._tokenize(self._normalize_text(query_text)))
            scored: List[Tuple[float, str]] = []
            for c in candidates or []:
                c_norm = self._normalize_text(c)
                c_tokens = set(self._tokenize(c_norm))
                if not c_tokens:
                    continue
                inter = len(q_tokens & c_tokens)
                score = inter / max(1, len(c_tokens))
                if inter > 0:
                    scored.append((score, str(c)))
            scored.sort(key=lambda x: x[0], reverse=True)
            return [s for _, s in scored[: max(0, int(limit or 0))]]
        except Exception:
            return (candidates or [])[: max(0, int(limit or 0))]

    def build_column_contexts(self, table_name: str, sample_rows: int = 10) -> Dict[str, str]:
        """
        Build enriched context strings per column using table/column metadata, comments,
        small sample values, and top relevant glossary/policy excerpts.

        Returns: { column_name: context_string }
        """
        contexts: Dict[str, str] = {}
        try:
            data = self.collect_metadata_and_samples(table_name, sample_rows=sample_rows) or {}
            tbl = data.get("table") or {}
            cols = data.get("columns") or []
            rows = data.get("samples") or []
            gloss = data.get("glossary") or []
            pol = data.get("policies") or []

            t_db = str(tbl.get("TABLE_CATALOG") or "")
            t_sc = str(tbl.get("TABLE_SCHEMA") or "")
            t_nm = str(tbl.get("TABLE_NAME") or "")
            table_fqn = f"{t_db}.{t_sc}.{t_nm}" if (t_db and t_sc and t_nm) else str(table_name)

            # Prebuild per-column sample strings (first 2 non-empty values)
            def sample_for_column(col_name: str, max_vals: int = 2) -> List[str]:
                out: List[str] = []
                try:
                    for r in rows:
                        if not isinstance(r, dict):
                            continue
                        # Try exact, then case-insensitive match
                        if col_name in r and r[col_name] is not None:
                            out.append(str(r[col_name]))
                        else:
                            # Find key matching case-insensitively
                            for k, v in r.items():
                                if str(k).lower() == str(col_name).lower() and v is not None:
                                    out.append(str(v))
                                    break
                        if len(out) >= max_vals:
                            break
                except Exception:
                    return out[:max_vals]
                return out[:max_vals]

            for c in cols:
                try:
                    cname = str(c.get("COLUMN_NAME") or "")
                    ctype = str(c.get("DATA_TYPE") or "")
                    ccomm = str(c.get("COLUMN_COMMENT") or "")

                    # Build query text for relevance (table + column names/comments)
                    qtxt = " ".join([table_fqn, cname, ctype, ccomm])
                    top_gloss = self._top_relevant(qtxt, gloss, limit=3)
                    top_pol = self._top_relevant(qtxt, pol, limit=2)

                    # Prepare normalized fields for insertion
                    norm_comm = self._normalize_text(ccomm)
                    samples = sample_for_column(cname, max_vals=2)
                    samples_norm = [self._normalize_text(s) for s in samples if s]
                    fps = self._value_fingerprint(samples)

                    # Compose context per spec
                    parts: List[str] = []
                    parts.append(f"Table: {table_fqn}")
                    parts.append(f"Column: {cname} ({ctype})")
                    parts.append(f"Column comment: {norm_comm}" if norm_comm else "Column comment: ")
                    if samples_norm:
                        parts.append("Samples: " + "; ".join(samples_norm))
                    if fps:
                        parts.append("Signals: " + ",".join(fps))
                    if top_gloss:
                        parts.append("Glossary: " + "; ".join([str(g)[:160] for g in top_gloss]))
                    if top_pol:
                        parts.append("Policy: " + "; ".join([str(p)[:160] for p in top_pol]))

                    contexts[cname] = "; ".join(parts)
                except Exception:
                    continue
        except Exception:
            return contexts
        return contexts

    def build_enriched_context(self, table_name: str, sample_rows: int = 10) -> str:
        """
        Step 2: Construct a single enriched context string for semantic understanding.

        Format example:
          "Table CUSTOMERS in schema SALES. Columns: EMAIL STRING, DOB DATE. Sample row: EMAIL=a@corp.com; DOB=1990-01-01. Glossary: Customer. Policy: GDPR Art.6, Art.9."
        """
        try:
            pkg = self.collect_metadata_and_samples(table_name, sample_rows=sample_rows) or {}
            t = pkg.get("table") or {}
            cols = pkg.get("columns") or []
            rows = pkg.get("samples") or []
            glossary = pkg.get("glossary") or []
            policies = pkg.get("policies") or []

            parts: List[str] = []
            # Table sentence
            tnm = str(t.get("TABLE_NAME") or "")
            tsc = str(t.get("TABLE_SCHEMA") or "")
            if tnm and tsc:
                parts.append(f"Table {tnm} in schema {tsc}.")
            elif tnm:
                parts.append(f"Table {tnm}.")

            # Columns sentence (name type)
            if cols:
                col_bits: List[str] = []
                for c in cols[:20]:
                    nm = str(c.get("COLUMN_NAME") or "")
                    ty = str(c.get("DATA_TYPE") or "")
                    if nm and ty:
                        col_bits.append(f"{nm} {ty}")
                    elif nm:
                        col_bits.append(nm)
                if col_bits:
                    parts.append("Columns: " + ", ".join(col_bits) + ".")

            # Sample row sentence
            if rows and isinstance(rows[0], dict):
                first = rows[0]
                kvs = [f"{k}={str(v)[:64]}" for k, v in first.items()]
                if kvs:
                    parts.append("Sample row: " + "; ".join(kvs) + ".")

            # Glossary sentence
            if glossary:
                parts.append("Glossary: " + ", ".join(glossary[:5]) + ".")

            # Policy sentence
            if policies:
                parts.append("Policy: " + ", ".join(policies[:5]) + ".")

            return " ".join(parts).strip()
        except Exception:
            return ""

    def semantic_detect_for_table(self, table_name: str, categories: Optional[List[str]] = None,
                                  min_confidence: float = 0.5) -> Dict[str, Any]:
        """
        Run semantic detection for a table and return a compact result with scores and
        top prediction. Provides failure_reason when embeddings are unavailable or low-confidence.
        """
        ctx = self.build_semantic_context(table_name)
        if not ctx:
            return {
                "table_name": table_name,
                "category_scores": {},
                "detected_category": None,
                "confidence": 0.0,
                "method": "semantic",
                "failure_reason": "insufficient metadata"
            }
        matches = self._get_semantic_matches_gov(ctx, categories=categories)
        if not matches:
            reason = "embedding backend unavailable" if (self._embedding_backend == 'none' or self._embedder is None) else "low confidence embedding"
            return {
                "table_name": table_name,
                "category_scores": {},
                "detected_category": None,
                "confidence": 0.0,
                "method": "semantic",
                "failure_reason": reason
            }
        top = matches[0]
        cat_scores = {m["category"]: float(m.get("confidence", 0.0)) for m in matches}
        result = {
            "table_name": table_name,
            "category_scores": cat_scores,
            "detected_category": top.get("category"),
            "confidence": float(top.get("confidence", 0.0)),
            "method": "semantic"
        }
        if float(top.get("confidence", 0.0)) < float(min_confidence):
            result["failure_reason"] = "low confidence embedding"
        return result

    # ---- Type Inference Helpers ----
    def _infer_type_from_name(self, name: Optional[str]) -> str:
        up = (name or "").upper()
        if any(k in up for k in ["DATE", "DOB", "DT", "TIME"]):
            return "DATE"
        if any(k in up for k in ["ID", "UUID", "GUID", "KEY"]):
            return "STRING"
        if any(k in up for k in ["AMOUNT", "PRICE", "TOTAL", "CNT", "COUNT", "NUM"]):
            return "NUMBER"
        if any(k in up for k in ["EMAIL", "PHONE", "ADDRESS", "NAME", "CARD", "ACCOUNT"]):
            return "STRING"
        return "STRING"

    def _infer_type_from_series(self, s: pd.Series) -> str:
        try:
            if pd.api.types.is_integer_dtype(s):
                return "NUMBER"
            if pd.api.types.is_float_dtype(s):
                return "FLOAT"
            # rudimentary date detection
            sample = s.dropna().astype(str).head(20).tolist()
            date_like = 0
            for v in sample:
                if re.match(r"^\d{4}[-/]\d{1,2}[-/]\d{1,2}", v):
                    date_like += 1
            if sample and date_like / len(sample) >= 0.3:
                return "DATE"
        except Exception:
            pass
        return "STRING"
    
    def classify_table(self, table_name: str, context: Optional[str] = None) -> Dict[str, Any]:
        """
        Classify a table using AI techniques.
        
        Args:
            table_name: Full table name (database.schema.table)
            
        Returns:
            Dictionary containing classification results
        """
        # AI-only path: virtual metadata + local ML classifier
        table_metadata = self.get_table_metadata(table_name) or {}
        # Configurable sample size for table-level features (defaults to 50)
        try:
            _tbl_sample_sz = 50
            if st is not None and hasattr(st, "session_state"):
                _tbl_sample_sz = int(st.session_state.get("ai_table_sample_size", 50))
                _tbl_sample_sz = max(10, min(2000, _tbl_sample_sz))
        except Exception:
            _tbl_sample_sz = 50
        sample_data = self.get_sample_data(table_name, _tbl_sample_sz)

        # Enrich features with semantic and pattern summaries
        features: Dict[str, Any] = {}
        # --- Semantic embeddings scoring (name/comment/columns/samples/glossary/policy) ---
        semantic_scores: Dict[str, float] = {}
        semantic_selected: Optional[str] = None
        semantic_score: float = 0.0
        semantic_threshold: Optional[float] = None
        semantic_failure_reason: Optional[str] = None
        semantic_method: str = 'CTE_FALLBACK'
        try:
            # Build enriched context if not supplied
            if context is None:
                ctx_parts: List[str] = []
                if table_metadata.get('TABLE_NAME') or table_metadata.get('table_name'):
                    ctx_parts.append(str(table_metadata.get('TABLE_NAME') or table_metadata.get('table_name')))
                if table_metadata.get('COMMENT'):
                    ctx_parts.append(str(table_metadata.get('COMMENT')))
                try:
                    if isinstance(sample_data, pd.DataFrame) and not sample_data.empty:
                        cols = list(sample_data.columns)[:10]
                        if cols:
                            ctx_parts.append("Columns: " + ", ".join([str(c) for c in cols]))
                        # include a couple of sample values
                        row0 = sample_data.iloc[0].to_dict()
                        sv = "; ".join([f"{k}={str(v)[:64]}" for k, v in row0.items() if k in cols])
                        if sv:
                            ctx_parts.append("Samples: " + sv)
                except Exception:
                    pass
                context_text = " \n".join([p for p in ctx_parts if p])
            else:
                context_text = str(context)

            # Prefer local SBERT embeddings if available
            v_ctx_arr = None
            try:
                self._ensure_embedder()
                self._ensure_canonical_category_embeddings()
                if self._embedding_backend == 'st' and self._embedder is not None and np is not None:
                    v_ctx_arr = self._get_embedding(self._preprocess_text(context_text))
            except Exception:
                v_ctx_arr = None

            # Load canonical categories and thresholds from config
            cfg_cats = self.load_sensitivity_config() or {}
            categories_cfg = cfg_cats.get('categories', {}) or {}
            model_meta = (cfg_cats.get('model_metadata') or cfg_cats.get('thresholds') or {})
            default_thr = float(model_meta.get('default_threshold', 0.7))

            # Canonical definitions fallback and vectors
            canonical_defs = self._canonical_category_texts()
            cat_vecs_sbert: Dict[str, Any] = dict(self._canonical_cat_vecs)
            # Build bag-of-words vectors only if SBERT unavailable
            cat_vecs_bow: Dict[str, Dict[str, float]] = {}
            cat_thresholds: Dict[str, float] = {}
            for key, text in canonical_defs.items():
                thr = default_thr
                cfg = categories_cfg.get(key) or categories_cfg.get(key.title()) or categories_cfg.get(key.replace('_', ' ').title())
                if cfg and isinstance(cfg, dict):
                    try:
                        thr = float(cfg.get('detection_threshold', default_thr))
                    except Exception:
                        pass
                cat_thresholds[key] = thr
                if not cat_vecs_sbert.get(key):
                    # Fallback bow vector
                    toks = re.findall(r"[a-z0-9_]+", text.lower())
                    vec: Dict[str, float] = {}
                    for t in toks:
                        vec[t] = vec.get(t, 0.0) + 1.0
                    nrm = sum(v*v for v in vec.values()) ** 0.5 or 1.0
                    for k2 in list(vec.keys()):
                        vec[k2] = vec[k2] / nrm
                    cat_vecs_bow[key] = vec

            # Compute similarities
            if v_ctx_arr is not None and cat_vecs_sbert:
                for k, v in cat_vecs_sbert.items():
                    try:
                        sim = float(np.dot(v_ctx_arr, v)) if np is not None else 0.0
                        semantic_scores[k] = round(max(0.0, min(1.0, (sim + 1.0) / 2.0)), 3)
                    except Exception:
                        continue
                semantic_method = 'SEMANTIC'
            else:
                # Bag-of-words cosine fallback
                def _cos(a: Dict[str, float], b: Dict[str, float]) -> float:
                    if not a or not b:
                        return 0.0
                    if len(a) > len(b):
                        a, b = b, a
                    s = 0.0
                    for kk, vv in a.items():
                        bv = b.get(kk)
                        if bv:
                            s += vv * bv
                    return float(max(0.0, min(1.0, s)))
                # Build bow for context
                tokens = re.findall(r"[a-z0-9_]+", (context_text or '').lower())
                v_ctx_bow: Dict[str, float] = {}
                for tkn in tokens:
                    v_ctx_bow[tkn] = v_ctx_bow.get(tkn, 0.0) + 1.0
                nrm2 = sum(v*v for v in v_ctx_bow.values()) ** 0.5 or 1.0
                for k2 in list(v_ctx_bow.keys()):
                    v_ctx_bow[k2] = v_ctx_bow[k2] / nrm2
                for k, vec in cat_vecs_bow.items():
                    semantic_scores[k] = round(_cos(v_ctx_bow, vec), 3)

            # Select best category and compare to threshold
            semantic_confidence_level: str = 'low'
            semantic_requires_review: bool = False
            semantic_auto_tag_candidate: bool = False
            semantic_validation_evidence: List[str] = []
            if semantic_scores:
                semantic_selected = max(semantic_scores.keys(), key=lambda c: semantic_scores[c])
                semantic_score = float(semantic_scores[semantic_selected])
                semantic_threshold = float(cat_thresholds.get(semantic_selected, default_thr))
                if semantic_score >= 0.85:
                    semantic_confidence_level = 'high'
                    semantic_auto_tag_candidate = True
                elif semantic_score >= 0.7:
                    semantic_confidence_level = 'medium'
                    semantic_requires_review = True
                else:
                    semantic_confidence_level = 'low'
                    semantic_requires_review = True  # or fallback
                # Validate column-level evidence
                semantic_validation_evidence = self._validate_semantic_evidence(table_name, semantic_selected, table_metadata, sample_data)
                if semantic_score >= semantic_threshold:
                    semantic_method = 'SEMANTIC'
                else:
                    semantic_failure_reason = 'LOW_CONFIDENCE'
            else:
                semantic_failure_reason = 'NO_METADATA'
        except Exception:
            semantic_failure_reason = 'CLASSIFICATION_ERROR'
        detections: List[Dict[str, Any]] = []
        try:
            # Perform column sampling before assigning any table sensitivity
            # Configurable column sample size (defaults to 100)
            try:
                _col_sample_sz = 100
                if st is not None and hasattr(st, "session_state"):
                    _col_sample_sz = int(st.session_state.get("ai_table_sample_size", 100))
                    _col_sample_sz = max(50, min(2000, _col_sample_sz))
            except Exception:
                _col_sample_sz = 100
            detections = self.detect_sensitive_columns(table_name, sample_size=_col_sample_sz) or []
            features["column_detections"] = detections
            # Compute table sensitivity from columns with multi-category preservation
            cfg = self.load_sensitivity_config()
            model_meta = cfg.get("model_metadata") or cfg.get("thresholds") or {}
            CAT_WEIGHTS = model_meta.get("category_weights") or {
                "PCI": 1.0,
                "PHI": 1.0,
                "Financial": 0.9,
                "SOX": 0.8,
                "PII": 0.85,
                "Regulatory": 0.6,
                "TradeSecret": 0.5,
                "Operational": 0.4,
                "SOC": 0.4,
            }
            PRIORITY = model_meta.get("category_priority") or [
                "PHI", "PCI", "Financial", "SOX", "PII", "Regulatory", "TradeSecret", "Operational", "SOC"
            ]

            ncols = max(1, len(detections))
            conf_sum = 0.0

            # Per-category aggregates
            per_cat_score: Dict[str, float] = {k: 0.0 for k in CAT_WEIGHTS}
            per_cat_count: Dict[str, int] = {k: 0 for k in CAT_WEIGHTS}
            per_cat_conf_sum: Dict[str, float] = {k: 0.0 for k in CAT_WEIGHTS}
            per_cat_high_conf: Dict[str, int] = {k: 0 for k in CAT_WEIGHTS}

            # Column-wise weighted max for overall table sensitivity
            acc_weighted_max = 0.0

            sensitive_set = set(model_meta.get("sensitive_categories", ["PCI", "PHI", "PII", "Financial"]))
            sensitive_cols = 0

            for d in detections:
                try:
                    conf = float(int(d.get("confidence", 0))) / 100.0
                except Exception:
                    conf = 0.0
                cats = list(d.get("categories") or [])
                dom = d.get("dominant_category") or (cats[0] if cats else None)

                # Track overall confidence
                conf_sum += conf

                # Weighted max for the column (dominant gets primary weight)
                col_weighted_max = 0.0
                if cats:
                    for c in cats:
                        w = float(CAT_WEIGHTS.get(str(c), 0.0))
                        if w > 0:
                            per_cat_score[c] += conf * w
                            per_cat_count[c] += 1
                            per_cat_conf_sum[c] += conf
                            if conf >= float(model_meta.get("high_conf_threshold", 0.6)):
                                per_cat_high_conf[c] += 1
                            col_weighted_max = max(col_weighted_max, conf * w)
                else:
                    if dom:
                        w = float(CAT_WEIGHTS.get(str(dom), 0.0))
                        col_weighted_max = max(col_weighted_max, conf * w)

                acc_weighted_max += col_weighted_max

                if (str(dom) in sensitive_set) and (conf >= float(model_meta.get("high_conf_threshold", 0.6))):
                    sensitive_cols += 1

            # Table sensitivity score: average of column weighted maxima
            table_sensitivity_score = acc_weighted_max / float(ncols)
            # Boost for multiple high-risk columns (heavier risk footprint)
            try:
                boosts = model_meta.get("table_sensitive_cols_boosts") or [
                    {"min": 3, "boost": 0.10},
                    {"min": 2, "boost": 0.05},
                ]
                for b in sorted(boosts, key=lambda x: -int(x.get("min", 0))):
                    if sensitive_cols >= int(b.get("min", 0)):
                        table_sensitivity_score = min(1.0, table_sensitivity_score + float(b.get("boost", 0.0)))
                        break
            except Exception:
                pass

            # Determine category scores and multi-category set
            # Normalize scores to 0..1 by dividing by max possible (count * weight)
            norm_scores: Dict[str, float] = {}
            for cat in CAT_WEIGHTS:
                cnt = per_cat_count.get(cat, 0)
                if cnt > 0:
                    max_possible = cnt * float(CAT_WEIGHTS[cat])
                    norm_scores[cat] = round(min(1.0, per_cat_score.get(cat, 0.0) / max(1e-9, max_possible)), 3)
            # Select table categories with meaningful contribution
            multi_threshold = float(model_meta.get("table_category_min_contribution", 0.2))  # require at least modest normalized contribution
            table_categories = [c for c, s in sorted(norm_scores.items(), key=lambda kv: (-kv[1], PRIORITY.index(kv[0]) if kv[0] in PRIORITY else 99)) if s >= multi_threshold]
            # Ensure preservation: include any category that has at least one high-confidence column
            for cat, hc in per_cat_high_conf.items():
                if hc > 0 and cat not in table_categories:
                    table_categories.append(cat)
            # Re-sort after inclusion
            table_categories = sorted(set(table_categories), key=lambda c: (-norm_scores.get(c, 0.0), PRIORITY.index(c) if c in PRIORITY else 99))

            # Merge inventory flags if available to reinforce category and score
            try:
                inv_flags = {}
                if self.use_snowflake and snowflake_connector is not None:
                    parts = (table_name or "").split(".")
                    if len(parts) == 3:
                        db, sch, tbl = parts
                        # Prefer configured DB through _gov_schema_fqn
                        schema_fqn = self._gov_schema_fqn()
                        rows_inv = snowflake_connector.execute_query(
                            f"""
                            select coalesce(CONTAINS_PII,false) as PII,
                                   coalesce(CONTAINS_FINANCIAL_DATA,false) as FINANCIAL,
                                   coalesce(REGULATORY_DATA,false) as IP,
                                   coalesce(SOC_RELEVANT,false) as SOC,
                                   coalesce(SOX_RELEVANT,false) as SOX
                            from {schema_fqn}.ASSETS
                            where upper(FULLY_QUALIFIED_NAME) = upper(%(f)s)
                            limit 1
                            """,
                            {"f": table_name},
                        ) or []
                        if rows_inv:
                            inv = rows_inv[0]
                            inv_flags = {k: bool(inv.get(k) or inv.get(k.lower())) for k in ["PII","FINANCIAL","IP","SOC","SOX"]}
                if inv_flags:
                    features["inventory_flags"] = inv_flags
                    # Apply a modest boost to table_sensitivity_score if any strong flags
                    if any(inv_flags.get(k) for k in ["PII","FINANCIAL","SOX"]):
                        table_sensitivity_score = min(1.0, table_sensitivity_score + 0.05)
                    # Nudge category priorities
                    for cat in ["PII","Financial","SOX"]:
                        if inv_flags.get(cat.upper() if cat != "Financial" else "FINANCIAL"):
                            per_cat_high_conf[cat] = per_cat_high_conf.get(cat, 0) + 1
            except Exception:
                pass

            # Dominant category resolution
            # Only default to PII if it dominates both count and average confidence
            def _avg_conf(cat: str) -> float:
                cnt = per_cat_count.get(cat, 0)
                return (per_cat_conf_sum.get(cat, 0.0) / float(cnt)) if cnt else 0.0

            dominant_table_category: Optional[str] = None
            if table_categories:
                # Candidate by weighted score then priority
                cand = sorted(table_categories, key=lambda c: (-per_cat_score.get(c, 0.0), PRIORITY.index(c) if c in PRIORITY else 99))[0]
                # PII dominance rule
                if "PII" in per_cat_count and per_cat_count["PII"] > 0:
                    top_count_cat = max((k for k in per_cat_count.keys()), key=lambda k: per_cat_count[k])
                    top_conf_cat = max((k for k in per_cat_conf_sum.keys()), key=lambda k: _avg_conf(k))
                    if top_count_cat == "PII" and top_conf_cat == "PII":
                        dominant_table_category = "PII"
                    else:
                        dominant_table_category = cand
                else:
                    dominant_table_category = cand

            # Populate features
            features["table_sensitivity_score"] = round(table_sensitivity_score, 2)
            features["ai_confidence_avg"] = round((conf_sum / float(ncols)) if ncols else 0.0, 2)
            features["sensitive_columns_count"] = int(sensitive_cols)
            features["table_category_scores"] = norm_scores
            features["table_categories"] = table_categories
            features["sensitivity_multi"] = ",".join(table_categories) if table_categories else ""
            features["dominant_table_category"] = dominant_table_category
            # Table-level context and composite bundle influences
            features["table_domain"] = table_metadata.get("TABLE_DOMAIN")
            # Low-risk reference/master table skip logic
            base_table = (table_name.split('.')[-1] if table_name else '').upper()
            low_ctx = set(model_meta.get("low_risk_table_name_tokens", [
                "CURRENCY", "CURRENCIES", "LOOKUP", "LOOKUPS", "REFERENCE", "REFERENCES", "CONFIG", "CONFIGS", "PRODUCT", "PRODUCTS", "INVENTORY", "INVENTORIES"
            ]))
            is_low_risk_table = any(k in base_table for k in low_ctx)

            # Attach semantic signals to features
            try:
                features['semantic_scores'] = semantic_scores
                features['semantic_selected'] = semantic_selected
                features['semantic_score'] = semantic_score
                features['semantic_threshold'] = semantic_threshold
                features['semantic_failure_reason'] = semantic_failure_reason
                features['semantic_method'] = semantic_method
                features['semantic_confidence_level'] = semantic_confidence_level
                features['semantic_requires_review'] = semantic_requires_review
                features['semantic_auto_tag_candidate'] = semantic_auto_tag_candidate
                features['semantic_validation_evidence'] = semantic_validation_evidence
                # If semantic succeeded, prefer its category as dominant when present
                if semantic_method == 'SEMANTIC' and semantic_selected:
                    features['dominant_table_category'] = features.get('dominant_table_category') or semantic_selected.replace('_DATA','')
                # Step 6: CIA minimums and suggested policy label
                cat_for_policy = None
                try:
                    if semantic_selected:
                        cat_for_policy = str(semantic_selected).upper()
                    else:
                        cat_for_policy = str(features.get('dominant_table_category') or '').upper()
                    norm = 'INTERNAL_DATA'
                    if cat_for_policy:
                        if ('PERSONAL' in cat_for_policy) or ('PII' in cat_for_policy):
                            norm = 'PERSONAL_DATA'
                        elif ('FINANCIAL' in cat_for_policy) or ('SOX' in cat_for_policy) or ('PCI' in cat_for_policy):
                            norm = 'FINANCIAL_DATA'
                        elif ('REGULATORY' in cat_for_policy) or ('GDPR' in cat_for_policy) or ('HIPAA' in cat_for_policy) or ('CCPA' in cat_for_policy):
                            norm = 'REGULATORY_DATA'
                        elif ('PROPRIETARY' in cat_for_policy) or ('TRADE' in cat_for_policy):
                            norm = 'PROPRIETARY_DATA'
                        elif ('INTERNAL' in cat_for_policy):
                            norm = 'INTERNAL_DATA'
                    cia_min, pol_lab = self._policy_cia_minimum_from_category(norm)
                    features['cia_minimum'] = cia_min
                    if pol_lab:
                        features['policy_label_suggested'] = pol_lab
                except Exception:
                    pass
            except Exception:
                pass
            # Table-level boosts must be governance-config driven; no static boosts here
        except Exception:
            table_sensitivity_score = 0.0
            sensitive_cols = 0
            is_low_risk_table = False

        # Local ML classifier remains the final arbiter, but we gate final label by sampled evidence
        base_result = self.classifier.classify_asset(table_metadata, sample_data)
        base_result = base_result or {}
        # Ensure expected keys exist
        base_result.setdefault('classification', 'Internal')
        base_result.setdefault('compliance_frameworks', [])
        base_result.setdefault('confidence', 0.5)
        feats = base_result.get('features') or {}
        feats.update(features)
        base_result['features'] = feats

        # Map table sensitivity to labels with thresholds from governance tables
        try:
            # Load thresholds from governance configuration (no hardcoded defaults)
            cfg_thr = self.load_sensitivity_config()
            thresholds_config = cfg_thr.get('thresholds', {})
            
            # Extract thresholds from SENSITIVITY_THRESHOLDS table
            thr_public = None
            thr_restricted = None
            thr_confidential = None
            
            # Map threshold names to values from governance table
            for threshold_name, threshold_data in thresholds_config.items():
                level = str(threshold_data.get('sensitivity_level', '')).upper()
                conf = float(threshold_data.get('confidence_level', 0))
                if level == 'LOW':
                    thr_public = conf
                elif level in ('MEDIUM', 'MODERATE'):
                    thr_restricted = conf
                elif level == 'HIGH':
                    thr_confidential = conf
            
            # Get category-specific thresholds from SENSITIVITY_CATEGORIES
            categories_config = cfg_thr.get('categories', {})
            dom = str(base_result['features'].get('dominant_table_category') or '')
            if dom and dom in categories_config:
                dom_cat = categories_config[dom]
                dom_thr = float(dom_cat.get('detection_threshold', 0.7))
                if thr_restricted is None:
                    thr_restricted = dom_thr
                if thr_confidential is None:
                    thr_confidential = min(0.99, dom_thr + 0.2)
                if thr_public is None:
                    thr_public = max(0.0, dom_thr - 0.4)
            
            # If still no thresholds found, use the first available from governance
            if thr_restricted is None and thresholds_config:
                first_threshold = next(iter(thresholds_config.values()))
                thr_restricted = float(first_threshold.get('confidence_level', 0.7))
                if thr_confidential is None:
                    thr_confidential = min(0.99, thr_restricted + 0.2)
                if thr_public is None:
                    thr_public = max(0.0, thr_restricted - 0.4)
            
            # No hardcoded fallbacks - thresholds must come from governance tables
            if thr_restricted is None:
                # If no governance config, use None to indicate config must be set
                thr_restricted = None
                thr_confidential = None
                thr_public = None
        except Exception:
            # If governance loading fails, set to None (config-driven approach)
            thr_public = None
            thr_restricted = None
            thr_confidential = None
            if is_low_risk_table and int(base_result['features'].get('sensitive_columns_count', 0)) == 0:
                # Skip classifying low-risk reference/master tables as sensitive when no sensitive columns detected
                base_result['classification'] = 'Internal'
                base_result['confidence'] = min(float(base_result.get('confidence', 0.0)), 0.2)
                base_result['features']['skip_reason'] = 'low_risk_reference_no_sensitive_columns'
            else:
                score = float(table_sensitivity_score)
                if score >= thr_confidential:
                    label = 'Confidential'
                elif score >= thr_restricted:
                    label = 'Restricted'
                elif score >= thr_public:
                    label = 'Internal'
                else:
                    label = 'Public'
                # Step 6: enforce minimum policy label if suggested
                try:
                    pol_lab = feats.get('policy_label_suggested')
                    if pol_lab:
                        order = {'Public': 0, 'Internal': 1, 'Restricted': 2, 'Confidential': 3}
                        if order.get(str(pol_lab), 0) > order.get(str(label), 0):
                            label = str(pol_lab)
                except Exception:
                    pass
                base_result['classification'] = label
                base_result['confidence'] = max(float(base_result.get('confidence', 0.0)), round(score, 2))
        except Exception:
            pass

        # Governance-driven only: do not apply hard-coded compliance/CIA rules here
        try:
            base_result['compliance_frameworks'] = list(base_result.get('compliance_frameworks') or [])
        except Exception:
            pass

        # Step 7: Workflow decision routing
        try:
            feats = base_result.get('features') or {}
            sem_level = str(feats.get('semantic_confidence_level') or '').lower()
            tbl_score = float(feats.get('table_sensitivity_score') or 0.0)
            evid = feats.get('semantic_validation_evidence') or []
            no_support = any(isinstance(x, str) and 'no strong' in x.lower() for x in evid)
            route = 'MANUAL_REVIEW'
            # High-confidence: semantic high or strong CTE score
            if sem_level == 'high' or tbl_score >= 0.85:
                route = 'AUTO_APPROVE'
            # Medium confidence: semantic medium or table between 0.7 and 0.85
            elif sem_level == 'medium' or (0.7 <= tbl_score < 0.85):
                route = 'REVIEW'
            # Conflict/insufficient evidence: keep MANUAL_REVIEW
            if no_support and route == 'AUTO_APPROVE':
                route = 'REVIEW'
            feats['workflow_route'] = route
            base_result['features'] = feats
            base_result['workflow_route'] = route
        except Exception:
            pass

        # Populate display-oriented fields in features
        try:
            base_result['features']['full_name'] = table_name
            base_result['features']['sensitivity_level'] = base_result.get('classification', 'Internal')
        except Exception:
            pass

        result = {
            'table_name': table_name,
            'classification': base_result['classification'],
            'compliance_frameworks': base_result['compliance_frameworks'],
            'confidence': base_result['confidence'],
            'features': base_result['features']
        }
        # Near-threshold auto-escalation and live metrics panel
        try:
            cfg = self.load_sensitivity_config()
            model_meta = (cfg.get('model_metadata') or cfg.get('thresholds') or {})
            per_cat_thr = model_meta.get('per_category_thresholds') or {}
            band = float(model_meta.get('review_band', 0.05))
            dom = result['features'].get('dominant_table_category')
            tbl_score = float(result['features'].get('table_sensitivity_score') or 0.0)
            thr = float(per_cat_thr.get(str(dom), model_meta.get('default_threshold', 0.7)))

            # Compute metrics locally (do not push to UI session state)
            metrics = {
                'dominant_table_category': dom,
                'table_sensitivity_score': round(tbl_score, 2),
                'threshold_applied': thr,
                'requires_review': bool(near),
                'flags_active': result['features'].get('inventory_flags') or result['features'].get('flags_active'),
                'suggested_keywords': (cfg.get('suggested_keywords') if isinstance(cfg, dict) else None),
            }
            # Optionally store internally if needed in future: result['features']['latest_metrics'] = metrics
        except Exception:
            pass
        # Low-confidence logging for review
        try:
            avg_conf = float(result.get('features', {}).get('ai_confidence_avg') or 0.0)
            sens_cols = int(result.get('features', {}).get('sensitive_columns_count') or 0)
            tbl_score = float(result.get('features', {}).get('table_sensitivity_score') or 0.0)
            if (sens_cols > 0 and avg_conf < 0.4) or (tbl_score < 0.35 and sens_cols > 0):
                self._log_alert(
                    level="INFO",
                    component="AI_CLASSIFY",
                    message="Low-confidence table classification",
                    details={
                        "table": table_name,
                        "avg_conf": avg_conf,
                        "sensitive_cols": sens_cols,
                        "table_score": tbl_score,
                        "label": result.get("classification"),
                    },
                )
        except Exception:
            pass
        # Persist to SENSITIVE_AUDIT (best-effort)
        try:
            feats = result.get('features', {}) or {}
            # Pull metrics from session if available, else recompute minimal fields
            metrics = None
            if st is not None and hasattr(st, 'session_state'):
                metrics = st.session_state.get('latest_classification_metrics')
            if not metrics:
                try:
                    cfg = self.load_sensitivity_config()
                    model_meta = (cfg.get('model_metadata') or cfg.get('thresholds') or {})
                    per_cat_thr = model_meta.get('per_category_thresholds') or {}
                    dom = feats.get('dominant_table_category')
                    tbl_score = float(feats.get('table_sensitivity_score') or 0.0)
                    # Get threshold from governance config (no hardcoded default)
                    default_thr = model_meta.get('default_threshold')
                    if default_thr is None:
                        # Try to get from global thresholds if available
                        thresholds_global = cfg.get('thresholds', {})
                        if thresholds_global:
                            # Use the first available threshold value
                            default_thr = next(iter(thresholds_global.values())).get('confidence_level') if isinstance(next(iter(thresholds_global.values())), dict) else None
                    thr = float(per_cat_thr.get(str(dom), default_thr)) if default_thr is not None else None
                    band = float(model_meta.get('review_band', 0.05))
                    near = (thr - band) <= tbl_score < thr
                    metrics = {
                        'dominant_table_category': dom,
                        'table_sensitivity_score': tbl_score,
                        'threshold_applied': thr,
                        'requires_review': bool(near),
                        'flags_active': feats.get('inventory_flags') or feats.get('flags_active'),
                        'suggested_keywords': (cfg.get('suggested_keywords') if isinstance(cfg, dict) else None),
                    }
                except Exception:
                    metrics = {
                        'dominant_table_category': feats.get('dominant_table_category'),
                        'table_sensitivity_score': float(feats.get('table_sensitivity_score') or 0.0),
                        'threshold_applied': None,
                        'requires_review': False,
                        'flags_active': feats.get('inventory_flags') or feats.get('flags_active'),
                        'suggested_keywords': None,
                    }
            # Build suggestions from detections: high-confidence rows without pattern_ids
            suggestions = {'suggested_keywords': [], 'suggested_patterns': []}
            try:
                cfg = self.load_sensitivity_config()
                model_meta = (cfg.get('model_metadata') or cfg.get('thresholds') or {})
                hc_thr = float(model_meta.get('high_conf_threshold', 0.6))
                for r in (feats.get('column_detections') or []):
                    try:
                        conf = float(int(r.get('confidence') or 0)) / 100.0
                        if conf >= hc_thr and not (r.get('pattern_ids') or []):
                            cname = r.get('column')
                            cats = r.get('categories') or ([] if not r.get('dominant_category') else [r.get('dominant_category')])
                            toks = r.get('token_hits') or []
                            if toks:
                                for t in toks:
                                    suggestions['suggested_keywords'].append({
                                        'category': cats[0] if cats else None,
                                        'keyword': t,
                                        'source': 'column_name_token',
                                        'column': cname,
                                    })
                            else:
                                suggestions['suggested_keywords'].append({
                                    'category': cats[0] if cats else None,
                                    'keyword': cname,
                                    'source': 'column_name',
                                    'column': cname,
                                })
                    except Exception:
                        continue
                # de-dup
                seen = set()
                uniq = []
                for it in suggestions['suggested_keywords']:
                    key = (str(it.get('category')), str(it.get('keyword')).upper())
                    if key in seen:
                        continue
                    seen.add(key)
                    uniq.append(it)
                suggestions['suggested_keywords'] = uniq
            except Exception:
                pass
            run_id = hashlib.md5(f"{table_name}:{datetime.now(timezone.utc).isoformat()}".encode('utf-8')).hexdigest()[:16]
            self._persist_audit([
                {
                    'table_name': table_name,
                    'dominant_category': metrics.get('dominant_table_category'),
                    'table_sensitivity_score': metrics.get('table_sensitivity_score'),
                    'threshold_applied': metrics.get('threshold_applied'),
                    'requires_review': metrics.get('requires_review'),
                    'flags_active': metrics.get('flags_active'),
                    'method': feats.get('method') or 'CTE',
                    'semantic_failure_reason': feats.get('semantic_failure_reason'),
                    'semantic_scores': feats.get('semantic_scores'),
                    'fallback_used': feats.get('fallback_used', False),
                    'run_id': run_id,
                    'timestamp_utc': datetime.now(timezone.utc).isoformat(),
                    'suggestions': suggestions,
                }
            ])
        except Exception:
            pass
        return result

    def classify_and_persist(self, table_name: str, sample_size: int = 200) -> Dict[str, Any]:
        """Run full classification for a table and persist audit outputs.

        - Column-level signals to SENSITIVE_AUDIT (DETAILS) with CIA and policies
        - Table-level summary persisted via _persist_audit
        - Updates ASSET_INVENTORY AI_* columns when available
        """
        # Run CTE detection first
        cte_cols = self.detect_sensitive_columns(table_name, sample_size=sample_size) or []
        # Compute CTE table score
        if cte_cols:
            table_sensitivity_score = sum(d['confidence'] for d in cte_cols) / len(cte_cols)
            dominant_category = max(set(d['categories'][0] for d in cte_cols if d.get('categories')), key=lambda c: sum(d['confidence'] for d in cte_cols if d.get('categories') and d['categories'][0] == c))
        else:
            table_sensitivity_score = 0.0
            dominant_category = 'INTERNAL'
        if table_sensitivity_score >= 0.7:
            # Use CTE results
            res = {
                'classification': dominant_category,
                'confidence': table_sensitivity_score,
                'features': {
                    'dominant_table_category': dominant_category,
                    'table_sensitivity_score': table_sensitivity_score,
                    'column_detections': cte_cols,
                    'method': 'CTE'
                }
            }
        else:
            # Run semantic classification
            try:
                ctx_text = self.build_enriched_context(table_name, sample_rows=min(10, max(1, int(sample_size/10))))
            except Exception:
                ctx_text = None
            res = self.classify_table(table_name, context=ctx_text) or {}
            feats = res.get("features") or {}
            # Merge CTE columns
            feats['column_detections'] = cte_cols  # keep CTE columns
            if 'dominant_table_category' not in feats or not feats['dominant_table_category']:
                feats['dominant_table_category'] = dominant_category
            feats['method'] = 'SEMANTIC_FALLBACK'
            res['features'] = feats
        feats = res.get("features") or {}
        cols = feats.get("column_detections") or []
        # Build column audit rows with suggested CIA/policies
        col_rows: List[Dict[str, Any]] = []
        for r in cols:
            try:
                dom = str(r.get("dominant_category") or "")
                cia = self._suggest_cia_from_type(dom)
                pol = self._policy_recommendations(dom, cia)
                col_rows.append({
                    "column": r.get("column"),
                    "categories": r.get("categories"),
                    "dominant_category": dom,
                    "confidence": r.get("confidence"),
                    "pattern_ids": r.get("pattern_ids"),
                    "token_hits": r.get("token_hits"),
                    "bundles_detected": r.get("bundles_detected"),
                    "suggested_cia": cia,
                    "policy_suggestions": pol,
                })
            except Exception:
                continue
        # Persist column audits with details
        try:
            self.persist_scan_results(table_name, col_rows, {
                "table_sensitivity_score": feats.get("table_sensitivity_score"),
                "dominant_table_category": feats.get("dominant_table_category"),
            }, sample_info={"sample_size": sample_size})
        except Exception:
            pass
        # Step 9: Audit logging to CLASSIFICATION_AUDIT
        try:
            if self.use_snowflake and snowflake_connector is not None:
                sc = self._gov_schema_fqn()
                feats = res.get("features") or {}
                # Determine source of decision
                route = str(res.get("workflow_route") or feats.get("workflow_route") or "").upper()
                src = "UNKNOWN"
                if str(feats.get("semantic_method") or "").upper() == "SEMANTIC":
                    src = "SEMANTIC"
                elif str(feats.get("method") or "").upper() == "CTE":
                    src = "CTE"
                elif route in ("REVIEW","MANUAL_REVIEW"):
                    src = "REVIEW"
                # Build evidence snapshot (truncate to avoid oversized payloads)
                col_ev = []
                for r in (feats.get("column_detections") or [])[:10]:
                    try:
                        col_ev.append({
                            "column": r.get("column"),
                            "category": r.get("dominant_category"),
                            "confidence": r.get("confidence"),
                            "pattern_ids": r.get("pattern_ids"),
                        })
                    except Exception:
                        continue
                details = {
                    "table": table_name,
                    "final_label": res.get("classification"),
                    "workflow_route": route or None,
                    "source": src,
                    "cia_minimum": feats.get("cia_minimum"),
                    "policy_label_suggested": feats.get("policy_label_suggested"),
                    "semantic": {
                        "selected": feats.get("semantic_selected"),
                        "score": feats.get("semantic_score"),
                        "confidence_level": feats.get("semantic_confidence_level"),
                        "requires_review": feats.get("semantic_requires_review"),
                        "validation_evidence": (feats.get("semantic_validation_evidence") or [])[:20],
                    },
                    "cte": {
                        "table_sensitivity_score": feats.get("table_sensitivity_score"),
                        "dominant_table_category": feats.get("dominant_table_category"),
                        "sensitive_columns_count": feats.get("sensitive_columns_count"),
                        "column_evidence": col_ev,
                    },
                    "rationale": {
                        "suggestions": res.get("suggestions"),
                    },
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }
                try:
                    det_sql = json.dumps(details).replace("'", "''")
                    snowflake_connector.execute_non_query(
                        f"insert into {sc}.CLASSIFICATION_AUDIT (DETAILS) select parse_json('{det_sql}')"
                    )
                except Exception:
                    pass
        except Exception:
            pass
        return res

    def _policy_recommendations(self, dominant_type: str, cia: Dict[str, int]) -> List[str]:
        """Minimal policy suggestion mapping from dominant type and CIA levels."""
        try:
            dt = (dominant_type or "").upper()
            C, I, A = int(cia.get("C", 0)), int(cia.get("I", 0)), int(cia.get("A", 0))
        except Exception:
            dt, C, I, A = "", 0, 0, 0
        rec: List[str] = []
        if dt in ("FINANCIAL","PCI","SOX"):
            rec.extend(["Encryption at rest and in transit","RBAC with least privilege","Audit & monitoring"])
            if C >= 2:
                rec.append("Segregation of duties")
        elif dt in ("PII","PHI"):
            rec.extend(["Dynamic masking/tokenization","RBAC with least privilege","Access audit & anomaly detection"])
            if C >= 2:
                rec.append("Customer data minimization & retention policies")
        elif dt in ("REGULATORY",):
            rec.extend(["Retention controls","DLP & egress controls","Regulatory audit trails"])
        else:
            rec.extend(["Standard controls","RBAC","Basic audit"])
        return rec

    def apply_object_tagging(self, table_name: str, label: str) -> None:
        """Best-effort Snowflake object tagging for table classification label."""
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                return
            # Tag name can be configured externally; try a common default
            tag_fqn = None
            if settings is not None:
                db = getattr(settings, "SCAN_CATALOG_DB", None) or getattr(settings, "SNOWFLAKE_DATABASE", None)
                if db:
                    tag_fqn = f"{db}.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY"
            tag_fqn = tag_fqn or "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY"
            try:
                snowflake_connector.execute_non_query(f"create tag if not exists {tag_fqn} allowed_values 'Public','Internal','Restricted','Confidential'")
            except Exception:
                pass
            snowflake_connector.execute_non_query(
                f"alter table {table_name} set tag {tag_fqn} = %(v)s",
                {"v": str(label)},
            )
        except Exception:
            pass

    def apply_human_feedback(self) -> Dict[str, Any]:
        """Ingest human reviews/tasks and update dynamic keyword/pattern stores.

        Reads CLASSIFICATION_REVIEWS for approved corrections and inserts as inactive suggestions into
        SENSITIVE_KEYWORDS or SENSITIVE_PATTERNS for curation. Returns counts updated.
        """
        updated = {"keywords": 0, "patterns": 0}
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                return updated
            sc = self._gov_schema_fqn()
            rows = snowflake_connector.execute_query(
                f"""
                select table_name, column_name, status, coalesce(comments,'') as comments
                from {sc}.CLASSIFICATION_REVIEWS
                where upper(status) in ('APPROVED','CONFIRMED')
                limit 500
                """
            ) or []
            if not rows:
                return updated
            # Ensure target tables exist
            snowflake_connector.execute_non_query(
                f"create table if not exists {sc}.SENSITIVE_KEYWORDS (category string, keyword string, priority number default 0, is_active boolean default true, source string, updated_at timestamp_ntz default current_timestamp())"
            )
            snowflake_connector.execute_non_query(
                f"create table if not exists {sc}.SENSITIVE_PATTERNS (category string, pattern string, priority number default 0, is_active boolean default true, updated_at timestamp_ntz default current_timestamp())"
            )
            for r in rows:
                try:
                    cmt = str(r.get("comments") or "")
                    # Expect formats like: "keyword: PII=email" or "pattern: PII=^\\d{3}-\\d{2}-\\d{4}$"
                    if ":" in cmt and "=" in cmt:
                        kind, rest = cmt.split(":", 1)
                        kind = kind.strip().lower()
                        cat, val = (rest.split("=", 1) + [None])[:2]
                        cat = (cat or "").strip()
                        val = (val or "").strip()
                        if kind == "keyword" and cat and val:
                            snowflake_connector.execute_non_query(
                                f"insert into {sc}.SENSITIVE_KEYWORDS (category, keyword, priority, is_active, source) values (%(c)s, %(k)s, 0, false, 'review')",
                                {"c": cat, "k": val},
                            )
                            updated["keywords"] += 1
                        elif kind == "pattern" and cat and val:
                            snowflake_connector.execute_non_query(
                                f"insert into {sc}.SENSITIVE_PATTERNS (category, pattern, priority, is_active) values (%(c)s, %(p)s, 0, false)",
                                {"c": cat, "p": val},
                            )
                            updated["patterns"] += 1
                except Exception:
                    continue
        except Exception:
            return updated
        return updated
    
    def classify_multiple_tables(self, table_names: List[str]) -> List[Dict[str, Any]]:
        """
        Classify multiple tables.
        
        Args:
            table_names: List of full table names
            
        Returns:
            List of classification results
        """
        results = []
        
        for table_name in table_names:
            try:
                result = self.classify_table(table_name)
                results.append(result)
            except Exception as e:
                results.append({
                    'table_name': table_name,
                    'error': str(e),
                    'classification': 'Unknown',
                    'compliance_frameworks': [],
                    'confidence': 0.0
                })
        
        return results
    
    def get_classification_summary(self) -> Dict[str, Any]:
        """
        Get a summary of classifications across all tables.
        
        Returns:
            Dictionary containing classification summary
        """
        # Platform-agnostic: summarize only virtual catalog tables
        table_names = list(self._virtual_catalog.keys())
        
        # Classify all tables
        classifications = self.classify_multiple_tables(table_names)
        
        # Generate summary statistics
        classification_counts = {}
        framework_counts = {}
        total_classified = len([c for c in classifications if 'error' not in c])
        
        for classification in classifications:
            if 'error' not in classification:
                # Count classifications
                cls = classification['classification']
                classification_counts[cls] = classification_counts.get(cls, 0) + 1
                
                # Count frameworks
                for framework in classification['compliance_frameworks']:
                    framework_counts[framework] = framework_counts.get(framework, 0) + 1
        
        return {
            'total_tables': len(table_names),
            'total_classified': total_classified,
            'classification_distribution': classification_counts,
            'framework_distribution': framework_counts,
            'classifications': classifications
        }

    # --- Sensitive Column Detection & Compliance (AI-lite) ---
    def _sensitivity_patterns(self) -> Dict[str, Any]:
        """Build sensitivity patterns from dynamic configuration (no hardcoded keywords)."""
        try:
            cfg = self.load_sensitivity_config()
        except Exception:
            cfg = {}

        out: Dict[str, Any] = {}

        # Keywords → name_tokens
        kws = (cfg.get("keywords") or {})
        if isinstance(kws, dict):
            for cat, items in (kws or {}).items():
                toks: List[str] = []
                for it in (items or []):
                    try:
                        tok = str(it.get("keyword") or it.get("token") or "").strip().upper()
                        if tok:
                            toks.append(tok)
                    except Exception:
                        continue
                out.setdefault(str(cat), {"name_tokens": sorted(list(set(toks))), "value_regex": []})
        elif isinstance(kws, list):
            tmp: Dict[str, set] = {}
            for it in (kws or []):
                try:
                    cat = str(it.get("category") or "").strip()
                    tok = str(it.get("keyword") or it.get("token") or "").strip().upper()
                    if cat and tok:
                        tmp.setdefault(cat, set()).add(tok)
                except Exception:
                    continue
            for cat, toks in tmp.items():
                out.setdefault(cat, {"name_tokens": sorted(list(toks)), "value_regex": []})

        # Patterns → value_regex
        pats = (cfg.get("patterns") or {})
        if isinstance(pats, dict):
            for cat, items in (pats or {}).items():
                vrs: List[str] = []
                for it in (items or []):
                    try:
                        rx = str(it.get("regex") or it.get("pattern") or "").strip()
                        if rx:
                            vrs.append(rx)
                    except Exception:
                        continue
                entry = out.setdefault(str(cat), {"name_tokens": [], "value_regex": []})
                entry["value_regex"] = (entry.get("value_regex") or []) + vrs
        elif isinstance(pats, list):
            for it in (pats or []):
                try:
                    cat = str(it.get("category") or "").strip()
                    rx = str(it.get("regex") or it.get("pattern") or "").strip()
                    if not cat or not rx:
                        continue
                    entry = out.setdefault(cat, {"name_tokens": [], "value_regex": []})
                    entry["value_regex"].append(rx)
                except Exception:
                    continue

        return out

    def _negative_patterns(self) -> Dict[str, Any]:
        """Return negative (counter) patterns that should lower confidence when present.

        These are loaded from the SENSITIVE_PATTERNS table where is_negative = true.
        """
        cfg = self.load_sensitivity_config()
        return cfg.get("negative_patterns", {})

    def detect_sensitive_columns(self, table_name: str, sample_size: int = 100) -> List[Dict[str, Any]]:
        """
        Enhanced sensitive column detection using dynamic config (patterns/keywords/bundles),
        stratified sampling, and statistical signals.

        Returns list of dicts: {column, dominant_category, confidence, suggested_cia, bundle_boost}
        """
        # Load dynamic config
        cfg = self.load_sensitivity_config()
        dyn_patterns = cfg.get("patterns") or []
        dyn_keywords = cfg.get("keywords") or []
        # Prefer COLUMN_BUNDLES; fallback to legacy bundles
        dyn_bundles = (cfg.get("column_bundles") or (cfg.get("bundles") or []))
        cia_rules = cfg.get("cia_rules") or {}
        # Pull model metadata (weights/thresholds) from config, fallback to legacy key
        model_meta = cfg.get("model_metadata") or cfg.get("thresholds") or {}
        # Defaults for ensemble weights and knobs when not present in DB
        # Load weights from governance config (no hardcoded defaults)
        weights_raw = model_meta.get("weights") or {}
        # If no weights configured, use empty dict (config-driven approach)
        weights = weights_raw if weights_raw else {}
        # Override from SENSITIVITY_WEIGHTS when available
        try:
            wt = cfg.get("weights_table") or {}
            if isinstance(wt, dict) and wt:
                # Use weights from governance table (no hardcoded defaults)
                weights.update({
                    "regex": float(wt.get("regex", 0.0)) if "regex" in wt else weights.get("regex", 0.0),
                    "token": float(wt.get("token", 0.0)) if "token" in wt else weights.get("token", 0.0),
                    "semantic": float(wt.get("semantic", 0.0)) if "semantic" in wt else weights.get("semantic", 0.0),
                    "ml": float(wt.get("ml", 0.0)) if "ml" in wt else weights.get("ml", 0.0),
                })
        except Exception:
            pass
        # Get weights from config (0.0 if not configured - no hardcoded defaults)
        w_regex = float(weights.get("regex", 0.0))
        w_token = float(weights.get("token", 0.0))
        w_sem = float(weights.get("semantic", 0.0))
        w_ml = float(weights.get("ml", 0.0))
        bundle_max_boost = float(model_meta.get("bundle_max_boost", 0.25))
        generic_id_cap = float(model_meta.get("generic_id_names_only_cap", 0.35))
        require_multi = bool(model_meta.get("require_multiple_evidence", True))
        require_multi_scale = float(model_meta.get("require_multi_evidence_scale", 0.6))
        # No-op: defaults applied above. Keep backward-compat for any callers referencing old key.

        # Semantic embeddings toggle (optional)
        try:
            enable_sem = False
            if st is not None and hasattr(st, 'session_state'):
                enable_sem = bool(st.session_state.get('ai_enable_semantic', False))
            enable_sem = bool(enable_sem or (model_meta.get('enable_semantic', False)))
            if enable_sem:
                self._ensure_embedder()
        except Exception:
            pass

        # Get columns and enhanced sample data (try dynamic sampling service first)
        cols_meta = self.get_column_metadata(table_name)
        df = None
        try:
            # Prefer internal dynamic sampler (full/random/stratified)
            df = self._dynamic_sample(table_name, min_rows=max(100, int(sample_size)), max_rows=max(300, int(sample_size) * 2))
        except Exception:
            df = None
        if df is None:
            # Fallback to generic sampler
            df = self.get_sample_data(table_name, sample_size)
            try:
                if hasattr(df, 'shape') and (df.shape[0] < min(100, int(sample_size or 0))) and (self.use_snowflake and snowflake_connector is not None):
                    df = self.get_sample_data(table_name, min(500, max(300, int(sample_size or 0))))
            except Exception:
                pass

        # Helper: basic feature extraction from values
        def extract_column_features(values: List[Any]) -> Dict[str, float]:
            vals = [str(v) for v in values if v is not None]
            n = len(vals)
            if n == 0:
                return {"null_ratio": 1.0, "uniq_ratio": 0.0, "avg_len": 0.0, "avg_entropy": 0.0, "alpha_ratio": 0.0, "digit_ratio": 0.0, "punc_ratio": 0.0}
            uniq_ratio = len(set(vals)) / float(n)
            lens = [len(v) for v in vals]
            avg_len = sum(lens) / float(n)
            def entropy(s: str) -> float:
                from collections import Counter
                c = Counter(s)
                n2 = float(len(s))
                return -sum((cnt/n2) * math.log2(cnt/n2) for cnt in c.values()) if n2 else 0.0
            avg_entropy = sum(entropy(v) for v in vals) / float(n)
            al = sum(sum(ch.isalpha() for ch in v) for v in vals)
            dg = sum(sum(ch.isdigit() for ch in v) for v in vals)
            pc = sum(sum((not ch.isalnum()) for ch in v) for v in vals)
            total = sum(len(v) for v in vals) or 1.0
            return {
                "null_ratio": 0.0,
                "uniq_ratio": round(uniq_ratio, 3),
                "avg_len": round(avg_len, 2),
                "avg_entropy": round(avg_entropy, 3),
                "alpha_ratio": round(al/total, 3),
                "digit_ratio": round(dg/total, 3),
                "punc_ratio": round(pc/total, 3),
            }

        # Removed table-name context adjustments to avoid hardcoded boosts/penalties

        out: List[Dict[str, Any]] = []
        if not cols_meta:
            return out

        def _luhn_ok(num: str) -> bool:
            try:
                s = ''.join([c for c in num if c.isdigit()])
                if len(s) < 13 or len(s) > 19:
                    return False
                total = 0
                alt = False
                for ch in s[::-1]:
                    d = ord(ch) - ord('0')
                    if alt:
                        d *= 2
                        if d > 9:
                            d -= 9
                    total += d
                    alt = not alt
                return (total % 10) == 0
            except Exception:
                return False

        # Removed semantic hardcoded hints to rely solely on dynamic configuration

        # Precompute uppercased table column names once
        table_cols_up: List[str] = [str(c.get('COLUMN_NAME') or '').upper() for c in (cols_meta or [])]
        # Precompute bundle presence and present columns per bundle
        bundle_present_cols: Dict[str, List[str]] = {}
        for b in (dyn_bundles or []):
            try:
                bname = str(b.get("bundle_name") or b.get("name") or "").strip()
                bcols = [str(x).upper() for x in (b.get("columns") or [])]
                if not bname or not bcols:
                    continue
                present = [tc for tc in table_cols_up if any(tok in tc for tok in bcols)]
                if present and len(present) >= max(2, int(len(bcols) * 0.6)):
                    bundle_present_cols[bname] = present
            except Exception:
                continue

        # Pre-compile regex patterns per category and detect if they target numeric formats
        compiled_patterns: Dict[str, List[Tuple[str, Any, bool]]] = {}
        try:
            for p in (dyn_patterns or []):
                rx = str(p.get("regex") or "").strip()
                cat = str(p.get("category") or "").strip() or "Other"
                if not rx:
                    continue
                try:
                    cre = re.compile(rx)
                except Exception:
                    continue
                # Heuristic: pattern targets numeric-only formats
                rx_lower = rx.lower()
                numeric_hint = bool(re.search(r"\\d", rx)) and not bool(re.search(r"[a-zA-Z]", rx))
                compiled_patterns.setdefault(cat, []).append((rx, cre, numeric_hint))
        except Exception:
            compiled_patterns = {}

        # Build a category token map from dynamic keywords (for semantic category embeddings)
        cat_token_map: Dict[str, List[str]] = {}
        try:
            for it in (dyn_keywords or []):
                c = str(it.get("category") or "").strip()
                t = str(it.get("token") or it.get("keyword") or "").strip()
                if c and t:
                    cat_token_map.setdefault(c, []).append(t)
        except Exception:
            cat_token_map = {}
        # Prepare a minimal patterns dict shape for _ensure_category_embeddings
        sem_patterns: Dict[str, Dict[str, Any]] = {k: {"name_tokens": v} for k, v in cat_token_map.items()}
        # Initialize embedder and precompute category embeddings (cached on self)
        try:
            self._ensure_embedder()
            if self._embedding_backend != 'none':
                self._ensure_category_embeddings(sem_patterns)
        except Exception:
            pass

        # Batch-encode normalized column names for semantic scoring (performance)
        name_vecs: Dict[str, Any] = {}
        try:
            if self._embedding_backend != 'none' and self._embedder is not None and np is not None and getattr(self, "_category_embeds", None):
                # Build normalized names list
                norm_names: List[str] = []
                idx_to_col: List[str] = []
                for col in (cols_meta or []):
                    cname0 = str(col.get('COLUMN_NAME') or '')
                    idx_to_col.append(cname0)
                    norm_names.append(re.sub(r"[\W_]+", " ", cname0.lower()).strip())
                if norm_names:
                    # Batch encode with normalization; rely on ST internal batching
                    vecs = self._embedder.encode(norm_names, normalize_embeddings=True, batch_size=32)
                    try:
                        # Convert to numpy once
                        vecs_np = np.array(vecs)
                    except Exception:
                        vecs_np = vecs
                    for i, cname0 in enumerate(idx_to_col):
                        try:
                            name_vecs[cname0] = np.array(vecs_np[i], dtype=float)
                        except Exception:
                            continue
        except Exception:
            name_vecs = {}

        for col in cols_meta:
            cname = str(col.get('COLUMN_NAME') or '')
            dtype = str(col.get('DATA_TYPE') or '').upper()
            up = cname.upper()
            categories: List[str] = []
            name_hits = 0
            value_hits = 0
            regex_hits_count = 0
            regex_hits_map: Dict[str, int] = {}
            stats_signal = 0.0
            ml_score = 0.0
            semantic_score_dict: Dict[str, float] = {}
            semantic_top_cat: Optional[str] = None
            semantic_top_conf: float = 0.0
            bundle_boost = False
            bundles_detected: List[str] = []
            pattern_ids: List[str] = []
            token_hits: List[str] = []
            negative_caps: List[str] = []
            luhn_flag = False
            # Precompute sample
            series_vals: List[Any] = []
            try:
                if isinstance(df, pd.DataFrame) and cname in df.columns:
                    # Adaptive sampling size
                    col_non_null = df[cname].dropna()
                    row_count = int(getattr(col_non_null, 'shape', [0])[0] if hasattr(col_non_null, 'shape') else len(col_non_null))
                    base_n = int(min(max(500, int(math.sqrt(max(1, row_count)) * 25)), 5000))
                    # Rare-value categories heuristic: if any category has few but critical patterns, increase
                    rare_boost = 0
                    try:
                        rare_boost = int((cfg.get("weights_table") or {}).get("rare_sample_boost", 0))
                    except Exception:
                        rare_boost = 0
                    sample_n = int(min(5000, max(base_n + rare_boost, sample_size)))
                    series_vals = col_non_null.astype(str).head(sample_n).tolist()
            except Exception:
                series_vals = []
            feats = extract_column_features(series_vals)
            # Name keyword matches (dynamic, case-insensitive), avoid generic tokens
            try:
                import re as _re
                parts = [p for p in _re.split(r"[^A-Za-z0-9]+", up) if p]
                GENERIC_TOKENS = {"ID","NO","NUM","NUMBER","CODE","TYPE"}
                for kw in (dyn_keywords or []):
                    try:
                        tok_up = str(kw.get("token") or kw.get("keyword") or "").upper()
                        if not tok_up:
                            continue
                        if tok_up in GENERIC_TOKENS:
                            continue
                        mt = str(kw.get("match_type") or "FUZZY").upper()
                        # EXACT requires whole-token match; FUZZY allows substring on length>2
                        is_exact_match = tok_up in parts
                        is_fuzzy_ok = (len(tok_up) > 2 and tok_up in up)
                        matched = is_exact_match if mt == "EXACT" else (is_exact_match or is_fuzzy_ok)
                        if matched:
                            categories.append(str(kw.get("category")))
                            name_hits += 1
                            token_hits.append(tok_up)
                    except Exception:
                        continue
            except Exception:
                pass
            # Regex value matches (dynamic) with adaptive thresholds and numeric dtype skip
            regex_match_rows = 0
            try:
                # Skip numeric-only columns unless any regex explicitly targets numeric formats
                regex_targets_numeric = any(nhint for lst in compiled_patterns.values() for (_, _, nhint) in lst)
                if dtype in ["NUMBER", "NUMERIC", "INT", "INTEGER", "BIGINT", "SMALLINT", "FLOAT", "DOUBLE", "DECIMAL"] and not regex_targets_numeric:
                    pass
                else:
                    # Determine adaptive threshold based on observed non-null count
                    row_count = max(0, len(series_vals))
                    if row_count < 500:
                        threshold = 0.05
                    elif row_count < 2000:
                        threshold = 0.10
                    else:
                        threshold = 0.15
                    # Evaluate per-category: count ROWS that match any pattern in that category
                    for cat, lst in (compiled_patterns or {}).items():
                        try:
                            if not lst:
                                continue
                            cat_matched_rows = 0
                            for v in series_vals:
                                try:
                                    sv = str(v)
                                    if any(cre.search(sv) for (_rx_str, cre, _nhint) in lst):
                                        cat_matched_rows += 1
                                except Exception:
                                    continue
                            if cat_matched_rows > 0:
                                regex_hits_map[cat] = int(cat_matched_rows)
                                # record one pattern id example for transparency
                                try:
                                    example_rx = lst[0][0]
                                    pattern_ids.append(str(example_rx))
                                except Exception:
                                    pass
                                regex_match_rows = max(regex_match_rows, cat_matched_rows)
                                # Category inclusion decision by matched ROW ratio
                                regex_hits_ratio = float(cat_matched_rows) / float(max(1, row_count))
                                if regex_hits_ratio >= threshold and cat not in categories:
                                    categories.append(cat)
                                # accumulate counts for confidence
                                value_hits += 1
                                regex_hits_count += 1
                        except Exception:
                            continue
                    regex_threshold_applied = threshold
            except Exception:
                regex_threshold_applied = None
            # Statistical signal (simple): high uniqueness + medium entropy suggests identifiers
            try:
                stats_signal = 0.0
                if feats["uniq_ratio"] >= 0.8 and feats["avg_entropy"] >= 2.5:
                    stats_signal += 0.6
                elif feats["uniq_ratio"] >= 0.6 and feats["avg_entropy"] >= 2.0:
                    stats_signal += 0.3
            except Exception:
                stats_signal = 0.0
            # ML-like score (proxy): combine uniqueness, entropy, digit ratio
            try:
                # Normalize to 0..1 with thresholds
                u = float(feats.get("uniq_ratio", 0.0))
                e = float(feats.get("avg_entropy", 0.0))
                d = float(feats.get("digit_ratio", 0.0))
                # heuristic blend
                ml_score = 0.0
                if u >= 0.8 and e >= 2.0:
                    ml_score += 0.5
                elif u >= 0.6 and e >= 1.5:
                    ml_score += 0.3
                if d >= 0.5:
                    ml_score += 0.2
                ml_score = max(0.0, min(1.0, ml_score))
            except Exception:
                ml_score = 0.0
            # Special handling for card numbers via Luhn
            try:
                if any(_luhn_ok(v) for v in series_vals[:200]):
                    categories.append('Financial')
                    value_hits += 1
                    luhn_flag = True
            except Exception:
                pass
            # Categories rely solely on dynamic keywords/patterns; no hardcoded semantic hints
            categories = sorted(set(categories))

            # Heuristic: reduce PII false positives for generic identifier columns
            try:
                import re as _re
                parts = [p for p in _re.split(r"[^A-Za-z0-9]+", up) if p]
                SPECIFIC_PII_TOKENS = {"EMAIL","PHONE","MOBILE","DOB","DATE_OF_BIRTH","SSN","SURNAME","FIRST","LAST","FIRST_NAME","LAST_NAME","ADDRESS"}
                GENERIC_CONTEXT = {"USER","ORDER","CUSTOMER","CLIENT","PRODUCT","ITEM","ENTITY","ID","UID"}
                has_specific_pii = any(tok in parts for tok in SPECIFIC_PII_TOKENS)
                only_generic_context = any(tok in parts for tok in GENERIC_CONTEXT) and not has_specific_pii
                # If PII was inferred only from generic context and no value/regex evidence, drop PII
                if ("PII" in categories) and only_generic_context and (value_hits == 0) and (regex_hits_count == 0):
                    categories = [c for c in categories if c != "PII"]
                    name_hits = max(0, name_hits - 1)
                # For *_ID or columns ending with ID-like tokens without value regex, bias to Operational
                if (up.endswith("_ID") or up.endswith("ID") or up.endswith("_NO") or up.endswith("_NUM")) and (value_hits == 0) and (regex_hits_count == 0):
                    if "Operational" not in categories:
                        categories.append("Operational")
                        ml_score = max(0.0, ml_score - 0.1)
            except Exception:
                pass
            # Bundle detection using dynamic bundles only
            try:
                for b in (dyn_bundles or []):
                    bname = str(b.get("bundle_name") or "").strip()
                    if not bname or bname not in bundle_present_cols:
                        continue
                    bcols = [str(x).upper() for x in (b.get("columns") or [])]
                    if bcols and any(tok in up for tok in bcols):
                        bundle_boost = True
                        bundles_detected.append(bname)
                        if b.get("category") and b.get("category") not in categories:
                            categories.append(str(b.get("category")))
            except Exception:
                bundle_boost = False
            # Compute per-category scores and final ensemble
            # Token score per category from token hits (EXACT > FUZZY weighting)
            token_score_dict: Dict[str, float] = {}
            try:
                for kw in (dyn_keywords or []):
                    tok_up = str(kw.get("token") or kw.get("keyword") or "").upper()
                    if tok_up and tok_up in token_hits:
                        cat = str(kw.get("category") or "")
                        mt = str(kw.get("match_type") or "FUZZY").upper()
                        w = 1.0 if mt == "EXACT" else 0.6
                        token_score_dict[cat] = token_score_dict.get(cat, 0.0) + w
            except Exception:
                token_score_dict = {}
            # Regex score per category using adaptive threshold
            regex_score_dict: Dict[str, float] = {}
            try:
                rc = max(1, len(series_vals))
                thr = float(regex_threshold_applied if regex_threshold_applied is not None else 0.15)
                for cat, hits in (regex_hits_map.items() or []):
                    ratio = float(hits) / float(rc)
                    regex_score_dict[cat] = float(min(1.0, ratio / max(1e-6, thr)))
            except Exception:
                regex_score_dict = {}
            # Semantic scores using precomputed name embeddings; fallback to per-text encoding with few samples
            try:
                if self._embedding_backend != 'none' and self._embedder is not None and np is not None and getattr(self, "_category_embeds", None):
                    vec = name_vecs.get(cname)
                    if vec is None:
                        # Fallback to encode combined text (slower)
                        text_bits = [re.sub(r"[_\-]+", " ", str(cname)).strip()]
                        for s in series_vals[:3]:
                            if s:
                                text_bits.append(str(s)[:64])
                        text = " | ".join([t for t in text_bits if t])
                        vec = self._get_embedding(text) if text else None
                    if vec is not None:
                        best_cat = None
                        best_sc = 0.0
                        for cat, items in (self._category_embeds or {}).items():
                            cat_best = 0.0
                            for _tok, v in items:
                                try:
                                    sc = float(np.dot(vec, v) / (np.linalg.norm(vec) * np.linalg.norm(v) + 1e-12))
                                    if sc > cat_best:
                                        cat_best = sc
                                except Exception:
                                    continue
                            if cat_best > 0:
                                semantic_score_dict[cat] = float(max(0.0, min(1.0, cat_best)))
                                if cat_best > best_sc:
                                    best_sc = cat_best
                                    best_cat = cat
                        semantic_top_cat = best_cat
                        semantic_top_conf = float(max(0.0, min(1.0, best_sc)))
            except Exception:
                semantic_score_dict = {}
            # Optional Zero-Shot Classification fallback when regex/token signals are weak
            zsc_score_dict: Dict[str, float] = {}
            zsc_top_cat: Optional[str] = None
            zsc_top_conf: float = 0.0
            try:
                regex_signal = float(max(regex_score_dict.values()) if regex_score_dict else 0.0)
                token_signal = float(max(token_score_dict.values()) if token_score_dict else 0.0)
                # Use when low-signal and column name has >=2 tokens
                name_norm = re.sub(r"[^A-Za-z0-9]+", " ", cname).strip()
                name_token_count = len([t for t in name_norm.split(" ") if t])
                if (regex_signal < 0.3 and token_signal < 0.3 and name_token_count >= 2):
                    self._ensure_zsc()
                    if self._zsc is not None:
                        candidates = sorted(set(list((cfg.get("categories") or {}).keys()) + list((self._category_centroids or {}).keys())))
                        if candidates:
                            res = self._zsc(name_norm, candidate_labels=candidates)
                            if isinstance(res, dict) and (res.get("labels") and res.get("scores")):
                                zsc_top_cat = str(res["labels"][0])
                                zsc_top_conf = float(res["scores"][0] or 0.0)
                                if zsc_top_cat:
                                    zsc_score_dict[zsc_top_cat] = float(max(0.0, min(1.0, zsc_top_conf)))
            except Exception:
                zsc_score_dict = {}
            # Aggregate to final per-category score
            agg_scores: Dict[str, float] = {}
            for cat in set(list(token_score_dict.keys()) + list(regex_score_dict.keys()) + list(categories) + list(semantic_score_dict.keys()) + list(zsc_score_dict.keys())):
                agg_scores[cat] = (
                    w_regex * float(regex_score_dict.get(cat, 0.0)) +
                    w_token * float(token_score_dict.get(cat, 0.0)) +
                    w_sem * float(semantic_score_dict.get(cat, 0.0)) +
                    w_ml * float(max(ml_score, zsc_score_dict.get(cat, 0.0)))
                )
            # Fallback overall signals for confidence if no per-cat scores
            regex_signal = float(max(regex_score_dict.values()) if regex_score_dict else 0.0)
            token_signal = float(max(token_score_dict.values()) if token_score_dict else 0.0)
            sem_sig = float(max(semantic_score_dict.values()) if semantic_score_dict else 0.0)
            ml_sig = max(0.0, min(1.0, float(max(ml_score, zsc_top_conf))))
            conf = (
                w_regex * regex_signal +
                w_token * token_signal +
                w_sem * sem_sig +
                w_ml * ml_sig
            )
            # Rare-value boost: few regex-matching rows but strong indicators
            try:
                if regex_hits_count > 0 and isinstance(series_vals, list) and series_vals:
                    ratio = float(regex_match_rows) / float(min(len(series_vals), 200))
                    if 0 < ratio <= 0.05:
                        rv_boost = float((cfg.get("weights_table") or {}).get("rare_value", 0.05))
                        conf = min(1.0, conf + max(0.0, rv_boost))
            except Exception:
                pass
            # Cap confidence for names-only generic identifier columns (softer; avoid suppressing true sensitive IDs)
            try:
                is_names_only = (regex_signal == 0.0) and (ml_sig <= 0.2) and (name_hits > 0)
                has_specific_hint = any(tok in token_hits for tok in ["EMAIL","PHONE","MOBILE","DOB","SSN","PAN","AADHAAR","Aadhar","Aadhaar"]) or bool(luhn_flag)
                if is_names_only and not has_specific_hint and (up.endswith("_ID") or up.endswith("ID") or "_NO" in up or "_NUM" in up):
                    conf = min(conf, generic_id_cap)
            except Exception:
                pass
            # Apply bundle-specific boost when available from dynamic config
            if bundle_boost:
                try:
                    # Use the max boost among matching bundles that include this column
                    boosts = []
                    for b in dyn_bundles:
                        bcols = [str(x).upper() for x in (b.get("columns") or [])]
                        if bcols and any(tok in up for tok in bcols):
                            boosts.append(float(b.get("boost") or 0.0))
                    if boosts:
                        conf += max(0.0, min(bundle_max_boost, max(boosts)))
                except Exception:
                    pass
            # Apply model thresholds: require_multiple_evidence (consider enabled modalities only)
            try:
                if require_multi:
                    sem_enabled = (self._embedding_backend != 'none') and (self._embedder is not None)
                    modalities = int(regex_signal > 0) + int(token_signal > 0) + int(ml_sig > 0)
                    if sem_enabled:
                        modalities += int(semantic_top_conf > 0.0)
                    # Only penalize if at least two modalities are realistically available and we still saw <2
                    total_possible = 3 + (1 if sem_enabled else 0)
                    if total_possible >= 2 and modalities < 2:
                        conf *= require_multi_scale
            except Exception:
                pass
            # Negative patterns functionality has been removed
            conf = max(0.0, min(1.0, conf))

            # Determine dominant category via weighted voting (regex/token/semantic)
            try:
                if agg_scores:
                    dominant_scored = sorted(agg_scores.items(), key=lambda kv: kv[1], reverse=True)
                    dominant_from_scores = dominant_scored[0][0]
                    if dominant_from_scores and dominant_from_scores not in categories:
                        categories.append(dominant_from_scores)
            except Exception:
                pass

            # Override dominance when semantic is strong and others are weak
            try:
                if semantic_top_cat and semantic_top_conf > 0.6:
                    if float(regex_signal) < 0.3 and float(token_signal) < 0.3:
                        if semantic_top_cat not in categories:
                            categories.append(semantic_top_cat)
            except Exception:
                pass

            norm_cats = sorted(set(categories))
            try:
                norm_cats, conf = self._apply_feedback_overrides(table_name, cname, norm_cats, conf)
            except Exception:
                pass
            dominant = norm_cats[0] if norm_cats else None
            # CIA suggestion strictly from dynamic category map
            suggested_cia = {"C": 0, "I": 0, "A": 0}
            try:
                if dominant and (cfg.get("categories") or {}).get(dominant):
                    suggested_cia = (cfg.get("categories") or {}).get(dominant) or {"C": 0, "I": 0, "A": 0}
            except Exception:
                pass

            # Related columns: all other members from any detected bundle(s)
            related: List[str] = []
            try:
                rel_set = set()
                for bname in bundles_detected:
                    for rc in (bundle_present_cols.get(bname) or []):
                        if rc != up:
                            rel_set.add(rc)
                related = sorted(list(rel_set))
            except Exception:
                related = []

            out.append({
                'column': cname,
                'categories': norm_cats,
                'dominant_category': dominant,
                'confidence': int(round(conf * 100)),
                'suggested_cia': suggested_cia,
                'bundle_boost': bool(bundle_boost),
                'related_columns': related,
                'bundles_detected': sorted(list(set(bundles_detected))),
                'regex_hits': regex_hits_count,
                'pattern_ids': pattern_ids,
                'token_hits': token_hits,
                'ml_score': float(ml_score),
                'negative_caps': negative_caps,
                'luhn_match': bool(luhn_flag),
                # Observability
                'sample_size_used': int(len(series_vals) or 0),
                'regex_threshold': float(regex_threshold_applied or 0.0),
                'regex_hits_map': regex_hits_map,
                'semantic_scores': semantic_score_dict,
                'semantic_top_category': semantic_top_cat,
                'semantic_top_confidence': float(semantic_top_conf),
                'zsc_top_category': zsc_top_cat,
                'zsc_top_confidence': float(zsc_top_conf),
            })

        try:
            # Default to persisting when Snowflake is available, unless explicitly disabled in config
            persist_flag = True
            try:
                cfg_flag = bool((cfg.get("model_metadata") or {}).get("persist_detect_sensitive", True) or cfg.get("persist_detect_sensitive", True))
                persist_flag = cfg_flag
            except Exception:
                pass
            if persist_flag and snowflake_connector is not None and self.use_snowflake:
                schema_fqn = "DATA_CLASSIFICATION_GOVERNANCE"
                try:
                    if settings is not None:
                        _db = getattr(settings, "SCAN_CATALOG_DB", None) or getattr(settings, "SNOWFLAKE_DATABASE", None)
                        if _db:
                            schema_fqn = f"{_db}.DATA_CLASSIFICATION_GOVERNANCE"
                except Exception:
                    pass
                try:
                    snowflake_connector.execute_non_query(
                        f"""
                        create table if not exists {schema_fqn}.SENSITIVE_AUDIT (
                          audit_id number autoincrement,
                          table_name string,
                          column_name string,
                          category string,
                          confidence number,
                          cia string,
                          bundle_detected boolean,
                          scanned_at timestamp_ntz default current_timestamp(),
                          primary key (audit_id)
                        )
                        """
                    )
                except Exception:
                    pass
                try:
                    snowflake_connector.execute_non_query(
                        f"""
                        create table if not exists {schema_fqn}.CLASSIFICATION_AI_RESULTS (
                          result_id number autoincrement,
                          table_name string,
                          column_name string,
                          ai_category string,
                          regex_confidence float,
                          keyword_confidence float,
                          ml_confidence float,
                          semantic_confidence float,
                          final_confidence float,
                          semantic_category string,
                          model_version string,
                          details variant,
                          created_at timestamp_ntz default current_timestamp(),
                          primary key (result_id)
                        )
                        """
                    )
                except Exception:
                    pass
                for r in out:
                    try:
                        cia = r.get("suggested_cia") or {"C":0,"I":0,"A":0}
                        snowflake_connector.execute_non_query(
                            f"""
                            insert into {schema_fqn}.SENSITIVE_AUDIT (table_name, column_name, category, confidence, cia, bundle_detected)
                            values (%(t)s, %(c)s, %(cat)s, %(conf)s, %(cia)s, %(bb)s)
                            """,
                            {
                                "t": str(table_name),
                                "c": str(r.get("column") or ""),
                                "cat": str(r.get("dominant_category") or ""),
                                "conf": int(r.get("confidence") or 0),
                                "cia": f"{int(cia.get('C',0))}/{int(cia.get('I',0))}/{int(cia.get('A',0))}",
                                "bb": bool(r.get("bundle_boost")),
                            },
                        )
                    except Exception:
                        pass
                    try:
                        det = {
                            "regex_hits_map": r.get("regex_hits_map"),
                            "pattern_ids": r.get("pattern_ids"),
                            "token_hits": r.get("token_hits"),
                            "sample_size_used": r.get("sample_size_used"),
                            "regex_threshold": r.get("regex_threshold"),
                            "semantic_scores": r.get("semantic_scores"),
                            "semantic_top_category": r.get("semantic_top_category"),
                            "semantic_top_confidence": r.get("semantic_top_confidence"),
                        }
                        # Confidence fields
                        regex_conf = 0.0
                        try:
                            rhm = r.get("regex_hits_map") or {}
                            rc = float(r.get("sample_size_used") or 0) or 0.0
                            thr = float(r.get("regex_threshold") or 0.15)
                            if rhm and rc > 0:
                                best_ratio = max((float(v)/rc) for v in rhm.values() if v is not None)
                                regex_conf = float(min(1.0, best_ratio / max(1e-6, thr))) * 100.0
                        except Exception:
                            regex_conf = 0.0
                        token_conf = 0.0
                        try:
                            token_conf = float(min(1.0, (len(r.get("token_hits") or []) / max(1.0, len(r.get("token_hits") or []))))) * 100.0 if r.get("token_hits") else 0.0
                        except Exception:
                            token_conf = 0.0
                        semantic_conf = 0.0
                        semantic_cat = r.get("semantic_top_category") or ""
                        try:
                            if r.get("semantic_top_confidence") is not None:
                                semantic_conf = float(r.get("semantic_top_confidence") or 0.0) * 100.0
                        except Exception:
                            semantic_conf = 0.0
                        snowflake_connector.execute_non_query(
                            f"""
                            insert into {schema_fqn}.CLASSIFICATION_AI_RESULTS (
                              table_name, column_name, ai_category, regex_confidence, keyword_confidence, ml_confidence, semantic_confidence, final_confidence, semantic_category, model_version, details
                            ) values (%(t)s, %(c)s, %(ai)s, %(r)s, %(k)s, %(m)s, %(s)s, %(f)s, %(scat)s, %(ver)s, PARSE_JSON(%(det)s))
                            """,
                            {
                                "t": str(table_name),
                                "c": str(r.get("column") or ""),
                                "ai": str(r.get("dominant_category") or ""),
                                "r": float(regex_conf),
                                "k": float(token_conf),
                                "m": float(r.get("ml_score") or 0.0) * 100.0,
                                "s": float(semantic_conf),
                                "f": float(r.get("confidence") or 0) * 1.0,
                                "scat": str(semantic_cat),
                                "ver": "v1.0",
                                "det": json.dumps(det).replace("'", "''"),
                            },
                        )
                    except Exception:
                        pass
        except Exception:
            pass
        # Sort by confidence desc
        out.sort(key=lambda r: r['confidence'], reverse=True)
        return out

    def classify_columns_probabilistic(self, table_name: str, sample_size: int = 200) -> List[Dict[str, Any]]:
        """Classify each column using regex, name hints, and optional embeddings to produce per-category probabilities.

        Steps per column:
        1) Sample 100–500 values
        2) Regex/pattern detection for categories
        3) Name analysis for keyword hints (column and table names)
        4) If embeddings available, semantic similarity-based boosts
        5) Merge signals into probabilities per category
        6) Determine dominant category via priority: PHI > Financial > SOX > Regulatory > Operational > TradeSecret > PII
        7) Return: {column, dominant_type, probabilities, sensitive_flag, justification}
        """
        cols_meta = self.get_column_metadata(table_name) or []
        df = self.get_sample_data(table_name, sample_size)
        # Build pattern dictionary dynamically from governance config
        cfg = self.load_sensitivity_config()
        patterns_list = cfg.get("patterns") or []
        # Derive categories dynamically from config
        cat_set = sorted({str(p.get("category") or "Other") for p in patterns_list if p.get("category")}) or ["Other"]
        patterns: Dict[str, Dict[str, Any]] = {k: {"value_regex": []} for k in cat_set}
        for p in patterns_list:
            try:
                cat = str(p.get("category") or "Other").strip() or "Other"
                rx = str(p.get("regex") or "").strip()
                if not rx:
                    continue
                patterns.setdefault(cat, {"value_regex": []})
                patterns[cat].setdefault("value_regex", []).append(rx)
            except Exception:
                continue
        base_table = (table_name.split('.')[-1] if table_name else '').upper()

        # Ensure embedding backend and category embeddings (best-effort)
        try:
            self._ensure_embedder()
            if self._embedding_backend != 'none':
                self._ensure_category_embeddings(patterns)
        except Exception:
            pass

        # Priority order for dominant type
        PRIORITY = {"PHI": 0, "Financial": 1, "SOX": 2, "Regulatory": 3, "Operational": 4, "TradeSecret": 5, "PII": 6}

        def _sample_series(col: str) -> List[str]:
            if df.empty or col not in df.columns:
                return []
            n = min(500, max(100, int(sample_size or 0)))
            try:
                return df[col].astype(str).dropna().head(n).tolist()
            except Exception:
                return []

        def _regex_signal(col_vals: List[str]) -> Dict[str, float]:
            # Load categories from config or use default
            categories = list((cfg.get("categories") or {}).keys())
            if not categories:
                categories = ["PII", "PHI", "Financial", "SOX", "Regulatory", "Operational", "TradeSecret"]
                
            scores: Dict[str, float] = {k: 0.0 for k in categories}
            if not col_vals:
                return scores
                
            total = 0
            match_count: Dict[str, int] = {k: 0 for k in categories}
            
            # Get patterns from config
            patterns_list = cfg.get("patterns") or []
            category_patterns: Dict[str, List[str]] = {}
            
            # Group patterns by category
            for p in patterns_list:
                try:
                    cat = str(p.get("category") or "").strip()
                    pattern = str(p.get("pattern") or "").strip()
                    if not cat or not pattern:
                        continue
                    category_patterns.setdefault(cat, []).append(pattern)
                except Exception:
                    continue
            
            # Process each value
            for v in col_vals:
                vv = v.strip()
                if not vv:
                    continue
                    
                total += 1
                
                # Check patterns for each category
                for cat, cat_patterns in category_patterns.items():
                    if cat not in scores:
                        continue
                    for rx in cat_patterns:
                        try:
                            if re.search(rx, vv, re.IGNORECASE):
                                match_count[cat] = match_count.get(cat, 0) + 1
                                break  # Count at most one match per category per value
                        except Exception:
                            continue
            
            # Calculate scores
            if total > 0:
                for cat in scores:
                    scores[cat] = min(1.0, float(match_count.get(cat, 0)) / float(total))
                    
            return scores

        def _name_hints(col_name: str) -> Dict[str, float]:
            upc = (col_name or '').upper()
            hints = {k: 0.0 for k in (categories or [])}
            
            # Load name tokens from database config
            name_tokens = cfg.get('name_tokens', {})
            
            # Column-level name token matches
            for cat, tokens in name_tokens.items():
                if not isinstance(tokens, list):
                    continue
                for token in tokens:
                    if not isinstance(token, str):
                        continue
                    if token.upper() in upc and cat in hints:
                        hints[cat] = max(hints[cat], 1.0)
            
            # Table-level context hints from database config
            table_patterns = cfg.get('table_patterns', {})
            for category, patterns in table_patterns.items():
                if not isinstance(patterns, list):
                    continue
                if any(k in base_table for k in patterns):
                    hints[category] = max(hints.get(category, 0), 0.6)
            
            # No hardcoded fallbacks - only use patterns from governance tables
            # If no database config found, return empty hints to enforce governance-driven approach
            
            return hints

        def _embedding_boost(col_name: str, sample_vals: List[str]) -> Dict[str, float]:
            boosts = {k: 0.0 for k in ["PII","PHI","Financial","SOX","Regulatory","Operational","TradeSecret"]}
            if self._embedding_backend == 'none' or self._embedder is None or np is None:
                return boosts
            try:
                # Name vector
                text_bits = [re.sub(r"[_\-]+"," ", str(col_name)).strip()]
                # Add a few sample values to context for robustness (shortened)
                for s in sample_vals[:5]:
                    if s:
                        text_bits.append(str(s)[:80])
                text = " | ".join([t for t in text_bits if t])
                col_vec = self._get_embedding(text) if text else None
                if col_vec is None:
                    return boosts
                # Compare with precomputed token embeddings per category
                for cat, items in (self._category_embeds or {}).items():
                    best = 0.0
                    for _, v in items:
                        try:
                            sim = float(np.dot(col_vec, v) / (np.linalg.norm(col_vec) * np.linalg.norm(v) + 1e-12))
                            if sim > best:
                                best = sim
                        except Exception:
                            continue
                    if cat in boosts:
                        # Convert similarity to a modest probability boost
                        # Thresholded; typical sim ~0.3-0.8 depending on model
                        if best >= 0.75:
                            boosts[cat] = 0.6
                        elif best >= 0.65:
                            boosts[cat] = 0.4
                        elif best >= 0.55:
                            boosts[cat] = 0.25
            except Exception:
                return boosts
            return boosts

        results: List[Dict[str, Any]] = []
        for cm in cols_meta:
            cname = str(cm.get('COLUMN_NAME') or '')
            samples = _sample_series(cname)
            regex_scores = _regex_signal(samples)
            name_scores = _name_hints(cname)
            emb_boosts = _embedding_boost(cname, samples)

            # Load categories from database
            cfg = self.load_sensitivity_config()
            categories = list((cfg.get("categories") or {}).keys())
            if not categories:
                categories = ["PII", "PHI", "Financial", "SOX", "Regulatory", "Operational", "TradeSecret"]
                
            # Merge signals: simple capped additive fusion
            probs: Dict[str, float] = {}
            just: List[str] = []
            for cat in categories:
                base = 0.0
                r = float(regex_scores.get(cat, 0.0))
                n = float(name_scores.get(cat, 0.0))
                e = float(emb_boosts.get(cat, 0.0))
                # Weighted merge: regex 0.5, names 0.3, embeddings 0.2
                p = (0.5 * r) + (0.3 * n) + (0.2 * e)
                probs[cat] = round(min(1.0, p), 3)
                if r > 0:
                    just.append(f"regex:{cat}={round(r,3)}")
                if n > 0:
                    just.append(f"name:{cat}={round(n,3)}")
                if e > 0:
                    just.append(f"embed:{cat}={round(e,3)}")

            # Determine dominant category using required priority
            def _dom_key(item):
                cat, p = item
                return (PRIORITY.get(cat, 99), -p)
            dominant_type, _ = sorted(probs.items(), key=_dom_key)[0]

            sensitive_flag = any(probs.get(k, 0.0) >= 0.5 for k in probs.keys())

            results.append({
                'column': cname,
                'dominant_type': dominant_type,
                'probabilities': probs,
                'sensitive_flag': bool(sensitive_flag and dominant_type in probs and probs[dominant_type] >= 0.4),
                'justification': just,
            })

        return results

    def assess_compliance(self, classification_label: str, c_level: int, detected_categories: List[str]) -> Dict[str, Any]:
        """Assess compliance against policy minimums based on detected categories.

        Rules:
        - PII/PHI/Financial => C >= 2 (Restricted)
        - SOX/Financial reporting cues => C >= 3 for SOX-relevant
        """
        issues = []
        cls = (classification_label or 'Internal').title()
        c = int(c_level or 0)
        cats = set([str(x) for x in (detected_categories or [])])

        def ensure(min_c: int, reason: str):
            if c < min_c:
                issues.append({'min_c': min_c, 'reason': reason})

        if any(x in cats for x in ['PII','PHI','Financial']):
            ensure(2, 'PII/PHI/Financial detected requires at least Restricted (C2)')
        # Enforce SOX minimum; keep Financial as potential SOX proxy otherwise
        if 'SOX' in cats and c < 3:
            ensure(3, 'SOX-relevant data requires Confidential (C3)')
        elif 'Financial' in cats and c < 3:
            issues.append({'min_c': 3, 'reason': 'Potential SOX-relevant data; consider Confidential (C3)'})

        return {
            'label': cls,
            'c_level': c,
            'issues': issues,
            'compliant': (len([i for i in issues if i.get('min_c', 0) > c]) == 0)
        }

    # --- Value-level classification and column aggregation ---
    def classify_value(self, value: str) -> Dict[str, Any]:
        """Classify a single value using dynamic governance patterns only.

        Returns: {"types": [..], "confidence": float, "signals": {...}, "requires_review": bool}
        """
        try:
            v = (value or "").strip()
            types: List[str] = []
            conf: float = 0.0
            signals: Dict[str, Any] = {}
            import re
            pats = self._sensitivity_patterns()
            # Flatten dynamic patterns per category
            matched: List[str] = []
            total_pattern_count = 0
            try:
                for cat, spec in (pats or {}).items():
                    rx_list = spec.get("value_regex") or []
                    total_pattern_count += len(rx_list)
                    for rx in rx_list:
                        try:
                            if re.search(rx, v):
                                matched.append(cat)
                                break
                        except Exception:
                            continue
            except Exception:
                matched = []
            if matched:
                types = sorted(set(matched))
                conf = 0.9 if len(matched) > 0 else 0.0
            # requires_review when no dynamic patterns are configured (neutral fallback)
            requires_review = False
            if total_pattern_count == 0:
                requires_review = True
            return {"types": types, "confidence": round(conf, 2), "signals": signals, "requires_review": requires_review}
        except Exception:
            return {"types": [], "confidence": 0.0, "signals": {}, "requires_review": False}

    def classify_values_batch(self, values: List[str]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for v in values or []:
            try:
                out.append(self.classify_value(str(v)))
            except Exception:
                out.append({"types": [], "confidence": 0.0, "signals": {}})
        return out

    def _suggest_cia_from_type(self, dominant_type: str) -> Dict[str, int]:
        """Centralized CIA mapping via governance config (categories/cia_rules)."""
        try:
            dt = str(dominant_type or "").upper()
            cfg = self.load_sensitivity_config()
            # Prefer explicit CIA rules
            try:
                rule = (cfg.get("cia_rules") or {}).get(dt) or (cfg.get("cia_rules") or {}).get(dominant_type)
                if rule:
                    return {"C": int(rule.get("C", 0)), "I": int(rule.get("I", 0)), "A": int(rule.get("A", 0))}
            except Exception:
                pass
            # Fallback to category table mapping
            try:
                cat_map = cfg.get("categories") or {}
                if dt in cat_map:
                    cdef = cat_map.get(dt) or {}
                    return {"C": int(cdef.get("C", 0)), "I": int(cdef.get("I", 0)), "A": int(cdef.get("A", 0))}
            except Exception:
                pass
        except Exception:
            pass
        # Unknown or no config => neutral CIA
        return {"C": 0, "I": 0, "A": 0}

    def _policy_cia_minimum_from_category(self, category: str) -> Tuple[Dict[str, int], Optional[str]]:
        """
        Step 6 helper: CIA baseline and policy label by category.
        Falls back to static mapping when governance config is unavailable.
        Returns (cia_min, label_suggested).
        """
        cat = (category or "").upper()
        mapping = {
            "PERSONAL_DATA": ({"C": 2, "I": 3, "A": 2}, "Restricted"),
            "FINANCIAL_DATA": ({"C": 2, "I": 3, "A": 2}, "Restricted"),
            "REGULATORY_DATA": ({"C": 3, "I": 3, "A": 2}, "Confidential"),
            "PROPRIETARY_DATA": ({"C": 2, "I": 2, "A": 1}, "Restricted"),
            "INTERNAL_DATA": ({"C": 1, "I": 1, "A": 1}, "Internal"),
        }
        # Governance-configured override when available
        try:
            cfg = self.load_sensitivity_config() or {}
            cats = cfg.get("categories") or {}
            if cat in cats and isinstance(cats[cat], dict):
                c = int(cats[cat].get("cia_c", cats[cat].get("C", mapping.get(cat, ({"C":1,"I":1,"A":1}, None))[0]["C"])) )
                i = int(cats[cat].get("cia_i", cats[cat].get("I", mapping.get(cat, ({"C":1,"I":1,"A":1}, None))[0]["I"])) )
                a = int(cats[cat].get("cia_a", cats[cat].get("A", mapping.get(cat, ({"C":1,"I":1,"A":1}, None))[0]["A"])) )
                lab = cats[cat].get("policy_label") or mapping.get(cat, ({"C":1,"I":1,"A":1}, None))[1]
                return {"C": c, "I": i, "A": a}, (str(lab) if lab else None)
        except Exception:
            pass
        return mapping.get(cat, ({"C": 1, "I": 1, "A": 1}, None))

    def _suggest_cia_from_sensitivity(self, sensitivity_score: float) -> Dict[str, int]:
        """Map 0–10 sensitivity score to CIA levels via decision thresholds.

        Thresholds:
        - 7–10: C3/I3/A3 (High)
        - 4–6:  C2/I2/A2 (Medium)
        - 1–3:  C1/I1/A1 (Low)
        - 0:    C0/I1/A1 (Public)
        """
        try:
            s = float(sensitivity_score or 0.0)
        except Exception:
            s = 0.0
        if s >= 7.0:
            return {"C": 3, "I": 3, "A": 3}
        if s >= 4.0:
            return {"C": 2, "I": 2, "A": 2}
        if s >= 1.0:
            return {"C": 1, "I": 1, "A": 1}
        # s == 0
        return {"C": 0, "I": 1, "A": 1}

    def aggregate_column_from_values(self, values: List[str]) -> Dict[str, Any]:
        """Aggregate value-level classifications to a column-level decision.

        Returns: {"dominant_type", "type_counts", "coverage_pct", "risk_score", "suggested_cia"}
        """
        if not values:
            return {"dominant_type": None, "type_counts": {}, "coverage_pct": 0.0, "risk_score": 0.0, "suggested_cia": {"C":0,"I":0,"A":0}}
        preds = self.classify_values_batch(values)
        from collections import Counter
        counts = Counter()
        total = 0
        any_sensitive = 0
        # Load category weights from governance configuration (no hardcoded defaults)
        cfg = self.load_sensitivity_config()
        category_weights = cfg.get("weights", {}) or {}
        # Get category-specific weights from SENSITIVITY_WEIGHTS table
        weight_map = {}
        for cat, weight_data in category_weights.items():
            if isinstance(weight_data, dict):
                weight_map[cat] = float(weight_data.get("weight", 0.5))
            else:
                weight_map[cat] = float(weight_data) if isinstance(weight_data, (int, float)) else 0.5
        
        # Use default weight of 0.5 if no config found (config-driven, not hardcoded)
        default_weight = 0.5
        risk_acc = 0.0
        for p in preds:
            ts = p.get("types") or []
            if ts:
                any_sensitive += 1
            for t in ts:
                counts[t] += 1
                risk_acc += weight_map.get(str(t), default_weight) * max(0.5, float(p.get("confidence") or 0.0))
            total += 1
        # determine dominant type at a coarse category level preference
        # collapse subtypes into categories
        category_alias = {
            "SSN": "PII",
            "Email": "PII",
            "Phone": "PII",
        }
        cat_counts = Counter()
        for k, v in counts.items():
            cat = category_alias.get(str(k), str(k))
            cat_counts[cat] += v
        # Priority: PCI > PHI > PII > Financial > Auth > other, then by count
        if cat_counts:
            def _priority_key(item):
                cat, cnt = item
                order = {"PCI": 0, "PHI": 1, "PII": 2, "Financial": 3, "Auth": 4}
                return (order.get(str(cat), 9), -cnt)
            dominant_type = sorted(cat_counts.items(), key=_priority_key)[0][0]
        else:
            dominant_type = None
        coverage = (float(any_sensitive) / float(total)) if total else 0.0
        # simple normalized risk 0..1
        max_possible = float(total) * 1.0
        risk_score = min(1.0, (risk_acc / max(1.0, max_possible)))
        cia = self._suggest_cia_from_type(dominant_type or "")
        return {
            "dominant_type": dominant_type,
            "type_counts": dict(cat_counts),
            "coverage_pct": round(coverage, 2),
            "risk_score": round(risk_score, 2),
            "suggested_cia": cia,
        }

    def map_compliance_categories(self, detected_type: str) -> List[str]:
        """Return a prioritized list of frameworks for a detected category.
        Rules:
        - PCI -> PCI DSS
        - PHI -> HIPAA
        - PII -> GDPR, CCPA
        - Financial (generic) -> SOX
        - SOX -> SOX
        - SOC -> SOC (security)
        - Confidential catch-all -> SOC
        """
        dt = (detected_type or '').upper()
        if dt == 'PCI':
            return ["PCI DSS"]
        if dt == 'PHI':
            return ["HIPAA"]
        if dt == 'PII':
            return ["GDPR", "CCPA"]
        if dt == 'FINANCIAL':
            return ["SOX"]
        if dt == 'SOX':
            return ["SOX"]
        if dt == 'SOC':
            return ["SOC"]
        if dt == 'CONFIDENTIAL':
            return ["SOC"]
        return ["Internal/Other"]

    def summarize_most_relevant(self, table_name: str, sample_size: int = 200) -> Dict[str, Any]:
        """Return one most relevant category per column and for the table.

        Priority order: SOX > Financial > PII. Tie-breakers by frequency then cumulative confidence.
        Confidence normalization: accepts 0..1 or 0..100 and normalizes to 0..100.
        """
        PRIORITY = {"SOX": 0, "Financial": 1, "PII": 2}

        def _norm_conf(c: Any) -> int:
            try:
                v = float(c or 0)
                if v <= 1.0:
                    v *= 100.0
                return int(round(max(0.0, min(100.0, v))))
            except Exception:
                return 0

        def _best_category(cats: List[str]) -> Optional[str]:
            if not cats:
                return None
            wanted = [c for c in cats if c in PRIORITY]
            if not wanted:
                return None
            return min(wanted, key=lambda c: PRIORITY[c])

        column_detections = self.detect_sensitive_columns(table_name, sample_size=sample_size) or []
        from collections import Counter, defaultdict
        col_best: Dict[str, Optional[str]] = {}
        col_conf: Dict[str, int] = {}
        col_cia: Dict[str, Dict[str, int]] = {}
        table_votes: List[str] = []
        conf_acc: Dict[str, int] = defaultdict(int)

        for d in detections:
            col = str(d.get("column") or "")
            cats: List[str] = list(d.get("categories") or [])
            conf = _norm_conf(d.get("confidence"))
            best = _best_category(cats)
            if best:
                col_best[col] = best
                col_conf[col] = conf
                table_votes.append(best)
                conf_acc[best] += conf
            # CIA suggestion
            scia = d.get("suggested_cia")
            if not scia:
                scia = self._suggest_cia_from_type(best or "")
            col_cia[col] = scia

        # Table-level best category
        if table_votes:
            freq = Counter(table_votes)
            def _sort_key(cat: str):
                return (PRIORITY.get(cat, 99), -freq[cat], -conf_acc[cat])
            table_category = sorted(set(table_votes), key=_sort_key)[0]
        else:
            table_category = None

        # CIA max rule across columns
        table_cia = {"C": 0, "I": 0, "A": 0}
        for scia in col_cia.values():
            for k in ("C", "I", "A"):
                try:
                    table_cia[k] = max(int(table_cia.get(k, 0)), int(scia.get(k, 0)))
                except Exception:
                    pass
        label_map = ["Public", "Internal", "Restricted", "Confidential"]
        label = label_map[min(max(int(table_cia.get("C", 0)), 0), 3)]

        return {
            "table": table_name,
            "table_category": table_category,
            "table_cia": table_cia,
            "table_label": label,
            "columns": [
                {
                    "column": c,
                    "category": col_best.get(c),
                    "confidence": col_conf.get(c, 0),
                    "cia": col_cia.get(c, {"C": 0, "I": 0, "A": 0}),
                }
                for c in sorted(col_best.keys())
            ],
        }

    # --- Deprecated Snowflake/Cortex integration removed in platform-agnostic mode ---
    def _cortex_available(self) -> bool:
        return False

    def _cortex_enhanced_classification(self, table_meta: Dict[str, Any], sample_df: pd.DataFrame) -> Dict[str, Any]:
        return {}

    # --- AI-only hybrid scan (no external DB calls) ---
    def _suggest_tags_for_levels(self, label: str, cia: Dict[str, int]) -> Dict[str, Any]:
        return {
            "data_classification": (label or "Internal"),
            "confidentiality_level": int(cia.get("C", 0)),
            "integrity_level": int(cia.get("I", 0)),
            "availability_level": int(cia.get("A", 0)),
        }

    def _suggest_column_tags(self, category: str, cia: Dict[str, int], special: Optional[str] = None) -> Dict[str, Any]:
        return {
            "DATA_CLASSIFICATION": (category or "Internal"),
            "CONFIDENTIALITY_LEVEL": int(cia.get("C", 0)),
            "INTEGRITY_LEVEL": int(cia.get("I", 0)),
            "AVAILABILITY_LEVEL": int(cia.get("A", 0)),
            "SPECIAL_CATEGORY": (special or None),
        }

    def hybrid_scan(self, table_name: str, sample_size: int = 200) -> Dict[str, Any]:
        """AI-only sensitive-data scan using heuristics/regex/semantics.
        Returns a dict with table-level CIA/label and per-column rows including category, CIA, confidence, and tag suggestions."""
        cols_meta = self.get_column_metadata(table_name)
        _ = self.get_sample_data(table_name, sample_size)  # used by detect_sensitive_columns
        heuristics = {d["column"]: d for d in (self.detect_sensitive_columns(table_name, sample_size=sample_size) or [])}

        rows: List[Dict[str, Any]] = []
        order = {"PCI":0, "PHI":1, "PII":2, "SOX":3, "Financial":4, "Regulatory":5, "Trade Secret":6, "Operational":7, "SOC":8}
        for cm in cols_meta or []:
            cname = str(cm.get("COLUMN_NAME") or "")
            h = heuristics.get(cname) or {}
            h_cat = str(h.get("dominant_category") or (h.get("categories") or [""])[0] or "")
            if h_cat == "TradeSecret":
                h_cat = "Trade Secret"
            category = h_cat
            cia = self._suggest_cia_from_type(category)
            conf = int(round(min(100, int(h.get("confidence") or 0))))
            special = category if category in ["PII","Financial","SOX","SOC","Regulatory","Operational","Trade Secret","PCI","PHI"] else None
            rows.append({
                "column_name": cname,
                "column_category": category or "",
                "cia": cia,
                "confidence": conf,
                "tags": self._suggest_column_tags(category or "Internal", cia, special),
                "special_category": special,
            })

        table_cia = {"C": 0, "I": 0, "A": 0}
        for r in rows:
            for k in ("C","I","A"):
                try:
                    table_cia[k] = max(int(table_cia.get(k,0)), int(r.get("cia",{}).get(k,0)))
                except Exception:
                    pass
        label_map = ["Public","Internal","Restricted","Confidential"]
        table_label = label_map[min(max(int(table_cia.get("C",0)),0),3)]

        from collections import Counter
        freq = Counter([r.get("special_category") for r in rows if r.get("special_category")])
        special_category = (sorted(freq.items(), key=lambda kv: (-kv[1], order.get(kv[0], 99)))[0][0]) if freq else None

        return {
            "table_name": table_name,
            "table_label": table_label,
            "table_cia": table_cia,
            "table_tags": self._suggest_tags_for_levels(table_label, table_cia),
            "special_category": special_category,
            "columns": rows,
        }

    def _profile_series_stats_full(self, s: pd.Series) -> Dict[str, Any]:
        try:
            v = s.dropna()
        except Exception:
            v = s
        n_total = int(len(s)) if s is not None else 0
        null_count = int(s.isna().sum()) if n_total else 0
        null_ratio = float(null_count) / float(n_total) if n_total else 0.0

        # Type flags
        is_num = pd.api.types.is_numeric_dtype(s)
        is_dt = pd.api.types.is_datetime64_any_dtype(s)
        is_str_like = pd.api.types.is_string_dtype(s) or pd.api.types.is_object_dtype(s)

        # Unique stats
        try:
            uniq_count = int(s.nunique(dropna=True))
        except Exception:
            uniq_count = 0
        uniq_ratio = (float(uniq_count) / float(n_total)) if n_total else 0.0

        # String stats and patterns
        str_stats: Dict[str, Any] = {}
        pattern_matches: Dict[str, Any] = {}
        entropy_stats: Dict[str, Any] = {}
        if is_str_like:
            ss = s.dropna().astype(str)
            lens = ss.str.len()
            str_stats = {
                "length_min": (int(lens.min()) if not lens.empty else None),
                "length_max": (int(lens.max()) if not lens.empty else None),
                "length_mean": (float(lens.mean()) if not lens.empty else None),
                "length_std": (float(lens.std()) if not lens.empty else None),
            }
            # Entropy on sample
            from collections import Counter
            def _ent(txt: str) -> float:
                if not txt:
                    return 0.0
                try:
                    m = ss.str.match(rx, na=False)
                    cnt = int(m.sum())
                    if cnt > 0:
                        pattern_matches[pname] = {
                            "count": cnt,
                            "ratio": float(cnt) / float(len(ss)) if len(ss) else 0.0,
                            "examples": ss[m].head(3).tolist(),
                        }
                except Exception:
                    pass

            # Categories
            vc = ss.value_counts()
            str_stats.update({
                "categories_count": int(len(vc)),
                "top_categories": (vc.head(10).to_dict()),
            })

        # Numeric stats
        num_stats: Dict[str, Any] = {}
        if is_num:
            nn = pd.to_numeric(s, errors="coerce")
            nn = nn.dropna()
            if not nn.empty:
                num_stats = {
                    "min": float(nn.min()),
                    "max": float(nn.max()),
                    "mean": float(nn.mean()),
                    "std": float(nn.std()),
                    "range": float(nn.max() - nn.min()),
                    "p1": float(nn.quantile(0.01)),
                    "p25": float(nn.quantile(0.25)),
                    "p50": float(nn.quantile(0.50)),
                    "p75": float(nn.quantile(0.75)),
                    "p99": float(nn.quantile(0.99)),
                    "skewness": float(nn.skew()),
                    "kurtosis": float(nn.kurtosis()),
                }
                num_stats["outliers"] = self._detect_outliers(nn)
                num_stats["is_sequential"] = self._is_sequential(nn)

        # Datetime stats
        dt_stats: Dict[str, Any] = {}
        try:
            if is_dt or is_str_like:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", category=UserWarning)
                    dt = None
                    # Try strict ISO8601 first (pandas >= 2.0 supports 'ISO8601')
                    try:
                        dt = pd.to_datetime(s, errors="coerce", utc=True, format="ISO8601")
                    except Exception:
                        dt = None
                    # Fallback to a few common explicit formats to avoid per-element dateutil parsing
                    if dt is None or dt.dropna().empty:
                        common_formats = [
                            "%Y-%m-%d",
                            "%Y/%m/%d",
                            "%d-%m-%Y",
                            "%m/%d/%Y",
                            "%Y-%m-%d %H:%M:%S",
                            "%Y/%m/%d %H:%M:%S",
                        ]
                        for fmt in common_formats:
                            try:
                                dt = pd.to_datetime(s, errors="coerce", utc=True, format=fmt)
                                if not dt.dropna().empty:
                                    break
                            except Exception:
                                continue
                    # Final fallback with coercion (suppress warnings)
                    if dt is None or dt.dropna().empty:
                        dt = pd.to_datetime(s, errors="coerce", utc=True)
                dt = dt.dropna() if dt is not None else dt
                if dt is not None and not dt.empty:
                    dt_stats = {
                        "min": dt.min().isoformat(),
                        "max": dt.max().isoformat(),
                        "range_days": int((dt.max() - dt.min()).days),
                    }
        except Exception:
            dt_stats = {}

        return {
            "count": n_total,
            "null_count": null_count,
            "null_ratio": round(null_ratio, 4),
            "unique_count": uniq_count,
            "unique_ratio": round(uniq_ratio, 4),
            "is_numeric": bool(is_num),
            "is_datetime": bool(is_dt),
            "is_string": bool(is_str_like),
            "string": str_stats,
            "patterns": pattern_matches,
            "entropy": entropy_stats,
            "numeric": num_stats,
            "datetime": dt_stats,
            # Back-compat fields used by existing scoring
            "avg_len": round(float(str_stats.get("length_mean") or 0.0), 2),
            "avg_entropy": round(float(entropy_stats.get("entropy_mean") or 0.0), 4),
            "num_min": (num_stats.get("min") if num_stats else None),
            "num_max": (num_stats.get("max") if num_stats else None),
            "stddev": (num_stats.get("std") if num_stats else None),
        }

    def _detect_outliers(self, s: pd.Series) -> Dict[str, Any]:
        """Detect outliers using the IQR rule. Returns count, ratio, and bounds."""
        try:
            if s is None or s.empty:
                return {"count": 0, "ratio": 0.0, "lower_bound": None, "upper_bound": None}
            q1 = float(s.quantile(0.25))
            q3 = float(s.quantile(0.75))
            iqr = q3 - q1
            lb = q1 - 1.5 * iqr
            ub = q3 + 1.5 * iqr
            mask = (s < lb) | (s > ub)
            cnt = int(mask.sum())
            ratio = float(cnt) / float(len(s)) if len(s) else 0.0
            return {"count": cnt, "ratio": ratio, "lower_bound": lb, "upper_bound": ub}
        except Exception:
            return {"count": 0, "ratio": 0.0, "lower_bound": None, "upper_bound": None}

    def _is_sequential(self, s: pd.Series) -> bool:
        """Heuristic: values strictly increasing or decreasing when sorted indicate sequential IDs."""
        try:
            if s is None or s.empty:
                return False
            ss = s.sort_values()
            diffs = ss.diff().dropna()
            if diffs.empty:
                return False
            return bool((diffs > 0).all() or (diffs < 0).all())
        except Exception:
            return False

    def _keyword_score_from_name(self, name: str) -> Tuple[float, List[str]]:
        pats = self._sensitivity_patterns()
        up = (name or "").upper()
        hits = []
        for cat, spec in pats.items():
            for tok in spec.get("name_tokens", []) or []:
                if tok in up:
                    hits.append(cat)
                    break
        score = 1.0 if hits else 0.0
        return score, sorted(list(set(hits)))

    def _semantic_score_from_name(self, name: str) -> float:
        try:
            if not name:
                return 0.0
            self._ensure_embedder()
            if self._embedding_backend == 'none' or self._embedder is None or np is None:
                return 0.0
            # normalize column name
            text = re.sub(r"[\W_]+", " ", str(name).lower()).strip()
            v = self._get_embedding(text)
            if v is None or not getattr(self, "_category_centroids", None):
                return 0.0
            best = 0.0
            for cat, c in (self._category_centroids or {}).items():
                try:
                    if c is None:
                        continue
                    sc = float(np.dot(v, c) / (float(np.linalg.norm(v)) * float(np.linalg.norm(c)) + 1e-12))
                    if sc > best:
                        best = sc
                except Exception:
                    continue
            return float(max(0.0, min(1.0, best)))
        except Exception:
            return 0.0

    def _pattern_score_from_series(self, cname: str, df: pd.DataFrame) -> Tuple[float, Dict[str, int]]:
        if df is None or df.empty or cname not in df.columns:
            return 0.0, {}
        pats = self._sensitivity_patterns()
        series = df[cname].astype(str).fillna("")
        n = min(1000, len(series))
        series = series.head(n)
        cat_hits: Dict[str, int] = {}
        total = 0
        for v in series:
            v = v.strip()
            if not v:
                continue
            total += 1
            for cat, spec in pats.items():
                for rx in spec.get("value_regex", []) or []:
                    try:
                        if re.search(rx, v):
                            cat_hits[cat] = cat_hits.get(cat, 0) + 1
                            break
                    except Exception:
                        continue
        if total == 0:
            return 0.0, cat_hits
        max_hit = max(cat_hits.values()) if cat_hits else 0
        score = 1.0 if (max_hit / float(total)) >= 0.1 else (0.5 if max_hit > 0 else 0.0)
        return score, cat_hits

    def _profiling_score_from_stats(self, stats: Dict[str, Any]) -> float:
        try:
            u = float(stats.get("uniq_ratio", 0.0))
            e = float(stats.get("avg_entropy", 0.0))
            l = float(stats.get("avg_len", 0.0))
            s = 0.0
            if u >= 0.6 and l >= 5:
                s += 0.6
            if e >= 2.5:
                s += 0.4
            return min(1.0, s)
        except Exception:
            return 0.0

    def _column_policy_and_label(self, dominant: str, confidence: int, cia: Dict[str, int]) -> Tuple[str, str]:
        dt = (dominant or "").upper()
        label_map = ["Public","Internal","Restricted","Confidential"]
        label = label_map[min(max(int(cia.get("C", 0)), 0), 3)]
        # Policy mapping per specification
        if dt == "PII":
            pol = "Masking + RBAC + Audit"
        elif dt == "FINANCIAL":
            pol = "Encryption + RBAC + Audit"
        elif dt == "SOX":
            pol = "Encryption + Restricted Access"
        elif dt == "REGULATORY" or dt == "PHI":
            pol = "Masking + Encryption + Audit"
        elif dt == "OPERATIONAL":
            pol = "RBAC + Read-only Access"
        elif dt == "TRADESECRET" or dt == "TRADE SECRET":
            pol = "Encryption + Strict RBAC"
        elif dt == "SOC":
            pol = "Encryption + Restricted Access + Monitoring"
        elif dt == "PCI":
            pol = "Encryption + RBAC + Audit"
        else:
            pol = "Standard controls, least privilege"
        return pol, label

    def generate_sensitive_report(self, table_name: str, sample_size: int = 200, total_row_count: Optional[int] = None) -> Dict[str, Any]:
        meta = self.get_table_metadata(table_name) or {}
        cols_meta = self.get_column_metadata(table_name) or []
        # Dynamic sample sizing: scale with table size (sqrt heuristic with caps)
        row_est = 0
        try:
            for k in ("ROW_COUNT","TABLE_ROWS","ROW_ESTIMATE","ROWS"):
                if k in meta and meta[k] is not None:
                    row_est = int(meta[k])
                    break
        except Exception:
            row_est = 0
        try:
            if total_row_count is not None:
                row_est = int(total_row_count)
        except Exception:
            pass
        try:
            dyn_sample = sample_size
            if row_est and row_est > 0:
                import math as _m
                dyn_sample = int(min(5000, max(100, round(_m.sqrt(row_est) * 25))))
            # Prefer larger of requested vs dynamic to avoid under-sampling big tables
            sample_size_used = int(max(int(sample_size or 0), int(dyn_sample or 0)))
        except Exception:
            sample_size_used = int(sample_size or 200)
        df = self.get_sample_data(table_name, sample_size_used)
        detections = {d["column"]: d for d in (self.detect_sensitive_columns(table_name, sample_size=sample_size_used) or [])}
        # Load dynamic thresholds/flags/bundles for table-level aggregation
        try:
            cfg = self.load_sensitivity_config()
        except Exception:
            cfg = {}
        col_rows: List[Dict[str, Any]] = []
        keyword_hits_table = 0
        pattern_hits_table = 0
        profiling_hits_table = 0
        type_votes: List[str] = []
        for cm in cols_meta:
            cname = str(cm.get("COLUMN_NAME") or "")
            dtype = str(cm.get("DATA_TYPE") or "")
            d = detections.get(cname) or {}
            kw_score, kw_cats = self._keyword_score_from_name(cname)
            sem_score = self._semantic_score_from_name(cname)
            patt_score, cat_hits = self._pattern_score_from_series(cname, df)
            stats = self._profile_series_stats_full(df[cname]) if (df is not None and not df.empty and cname in df.columns) else {"uniq_ratio":0.0,"avg_entropy":0.0,"avg_len":0.0,"null_ratio":0.0}
            prof_score = self._profiling_score_from_stats(stats)
            keyword_hits_table += 1 if kw_score > 0 else 0
            pattern_hits_table += 1 if patt_score > 0 else 0
            profiling_hits_table += 1 if prof_score > 0 else 0
            cats = list(sorted(set(list(d.get("categories") or []) + kw_cats + list(cat_hits.keys()))))
            # Evidence-weighted dominant category selection
            # PII must have strong evidence: concrete regex (PII) or explicit name token (EMAIL/PHONE/SSN), else deprioritize
            PRIORITY = {"PHI":0, "PCI":1, "Financial":2, "SOX":3, "PII":4, "Regulatory":5, "TradeSecret":6, "Operational":7, "SOC":8}
            def _strong_pii() -> bool:
                try:
                    # regex-based PII hit from pattern analysis
                    rx_pii = any(k for k in (cat_hits.keys() if isinstance(cat_hits, dict) else []) if str(k) == "PII")
                    # name-based strong hints captured in kw_cats (already derived from tokens)
                    name_pii = "PII" in (kw_cats or [])
                    # composite evidence not computed here; rely on detect_sensitive_columns categories already merged
                    return bool(rx_pii or name_pii)
                except Exception:
                    return False
            dominant = None
            if cats:
                # Build simple evidence scores per category
                evid: Dict[str, float] = {}
                for ccat in cats:
                    s = 0.0
                    if ccat in (cat_hits.keys() if isinstance(cat_hits, dict) else []):
                        s = max(s, min(1.0, patt_score))  # pattern strength
                    if ccat in (kw_cats or []):
                        s = max(s, 0.8 * min(1.0, kw_score))  # name hint
                    # borrow detector dominant/category presence as light evidence
                    if str(d.get("dominant_category") or "") == ccat:
                        s = max(s, 0.6)
                    evid[ccat] = s
                # If PII lacks strong evidence, down-weight it for dominance selection
                if "PII" in evid and not _strong_pii():
                    evid["PII"] = min(evid.get("PII", 0.0), 0.2)
                # Pick by evidence score; priority only as tie-breaker
                dominant = sorted(evid.items(), key=lambda kv: (-kv[1], PRIORITY.get(kv[0], 99)))[0][0]
            cia = self._suggest_cia_from_type(str(dominant or ""))
            # Rebalance: reduce name keyword reliance; favor value patterns
            conf = kw_score*0.15 + patt_score*0.55 + sem_score*0.15 + prof_score*0.15
            conf_int = int(round(100*min(1.0, max(0.0, conf))))
            pol, label = self._column_policy_and_label(str(dominant or ""), conf_int, cia)
            type_votes.append(str(dominant or "Internal"))
            reasoning_bits: List[str] = []
            if kw_score > 0:
                reasoning_bits.append("name keywords")
            if patt_score > 0:
                reasoning_bits.append("pattern matches")
            if prof_score > 0:
                reasoning_bits.append("profiling anomalies")
            if sem_score > 0:
                reasoning_bits.append("semantic hint")
            col_rows.append({
                "column_name": cname,
                "data_type": dtype,
                "sensitive_type": (dominant or "Internal"),
                "confidence_score": conf_int,
                "CIA (C/I/A)": cia,
                "classification_label": label,
                "policy_suggestion": pol,
                "reasoning": ", ".join(reasoning_bits) if reasoning_bits else "no strong signals",
                "requires_review": bool(conf_int < 75),
            })
        row_count = int(total_row_count) if total_row_count is not None else (int(len(df)) if isinstance(df, pd.DataFrame) else 0)
        keyword_score_tbl = min(1.0, float(keyword_hits_table) / max(1.0, float(len(cols_meta))))
        pattern_score_tbl = min(1.0, float(pattern_hits_table) / max(1.0, float(len(cols_meta))))
        profiling_score_tbl = min(1.0, float(profiling_hits_table) / max(1.0, float(len(cols_meta))))
        # Rebalance table score: emphasize pattern evidence over keywords
        table_sensitivity_score = (keyword_score_tbl*0.25 + pattern_score_tbl*0.55 + profiling_score_tbl*0.2)
        tbl_conf = int(round(100*table_sensitivity_score))
        from collections import Counter
        vote_cnt = Counter(type_votes)
        if vote_cnt:
            prio = {"PII":0, "Financial":1, "Regulatory":2, "SOX":3, "PCI":4, "PHI":5, "Operational":6, "TradeSecret":7, "SOC":8, "Internal":9}
            predominant_type = sorted(vote_cnt.items(), key=lambda kv: (prio.get(kv[0], 99), -kv[1]))[0][0]
        else:
            predominant_type = "Internal"
        # Align with classify_table() multi-category aggregation
        try:
            cls_tbl = self.classify_table(table_name)
            cls_feats = (cls_tbl or {}).get('features') or {}
            # Prefer multi-category for readability; fallback to dominant if absent
            predominant_type = cls_feats.get('sensitivity_multi') or cls_feats.get('dominant_table_category') or predominant_type
            # Align confidence and label with classifier output
            table_sensitivity_score = float(cls_feats.get('table_sensitivity_score', table_sensitivity_score))
            tbl_conf = int(round(100 * table_sensitivity_score))
            table_label = str((cls_tbl or {}).get('classification') or table_label)
            low_risk_floor_applied = bool(cls_feats.get('low_risk_floor_applied', False))
            table_composite_bundles = int(cls_feats.get('table_composite_bundles', 0))
        except Exception:
            low_risk_floor_applied = False
            table_composite_bundles = 0
        max_cia = {"C":0, "I":0, "A":0}
        for r in col_rows:
            cia = r.get("CIA (C/I/A)") or {}
            for k in ("C","I","A"):
                try:
                    max_cia[k] = max(int(max_cia.get(k,0)), int(cia.get(k,0)))
                except Exception:
                    pass
        label_map = ["Public","Internal","Restricted","Confidential"]
        table_label = label_map[min(max(int(max_cia.get("C",0)),0),3)]
        comp = self.assess_compliance(table_label, int(max_cia.get("C",0)), [predominant_type])
        policy_ok = comp.get("compliant", True)
        # Policy suggestion aligned with CIA and detected categories
        any_sensitive = predominant_type in ("PII","PHI","Financial","PCI","SOX","Regulatory")
        C_level = int(max_cia.get("C",0))
        if any_sensitive and C_level >= 2:
            if predominant_type in ("Financial","SOX","PCI"):
                pol_tbl = "RBAC restrict, audit, encryption, segregation"
            elif predominant_type in ("PII","PHI"):
                pol_tbl = "Mask/tokenize, RBAC restrict, audit"
            elif predominant_type in ("Regulatory",):
                pol_tbl = "Regulatory controls, retention, DLP"
            else:
                pol_tbl = "RBAC restrict, audit"
        else:
            pol_tbl = "Standard controls"
        reasoning_tbl_bits = []
        if keyword_hits_table:
            reasoning_tbl_bits.append("name keyword hits")
        if pattern_hits_table:
            reasoning_tbl_bits.append("pattern matches in samples")
        if profiling_hits_table:
            reasoning_tbl_bits.append("high uniqueness/entropy")
        # Borderline review band: 65–75 by default
        _review_flag = bool(65 <= tbl_conf < 75)
        tbl_row = {
            "fullname": f"{meta.get('TABLE_CATALOG', '')}.{meta.get('TABLE_SCHEMA', '')}.{meta.get('TABLE_NAME', '')}",
            "predominant_type": predominant_type,
            "confidence_score": tbl_conf,
            "reasoning": ", ".join(reasoning_tbl_bits) if reasoning_tbl_bits else "no strong signals",
            "classification_label": table_label,
            "policy_suggestion": pol_tbl,
            "policy_ok": bool(policy_ok),
            "row_count": row_count,
            "requires_review": _review_flag,
            "cia": max_cia,
            "C": int(max_cia.get("C", 0)),
            "I": int(max_cia.get("I", 0)),
            "A": int(max_cia.get("A", 0)),
            # expose multi-category and table-level boosts for UI grids
            "sensitivity_multi": cls_feats.get('sensitivity_multi') if 'cls_feats' in locals() else None,
            "table_composite_bundles": table_composite_bundles,
            "low_risk_floor_applied": low_risk_floor_applied,
        }
        # --- Dynamic table aggregation & thresholds ---
        try:
            # Weighted average of column confidences (0..1)
            col_confs = [float((detections.get(str(r.get('column_name') or ''), {}) or {}).get('confidence', 0)) / 100.0 for r in col_rows]
            avg_conf = sum(col_confs) / float(len(col_confs)) if col_confs else 0.0
            # Bundle boost: count unique bundles detected across columns
            bundles = []
            for d in detections.values():
                for b in (d.get('bundles_detected') or []):
                    if b not in bundles:
                        bundles.append(b)
            bundle_boost = min(0.3, 0.05 * float(len(bundles)))
            # Inventory flag score from dynamic flags mapping (proportional to flags hit)
            flags_cfg = cfg.get('flags') or []
            # Build per-category evidence from columns
            cat_scores: Dict[str, float] = {}
            for d in detections.values():
                dom = d.get('dominant_category')
                c = float(d.get('confidence', 0)) / 100.0
                if dom:
                    cat_scores[dom] = cat_scores.get(dom, 0.0) + c
            # Determine dynamic flags hit
            active_flags = []
            for f in flags_cfg:
                fcat = str(f.get('category') or '')
                if fcat and cat_scores.get(fcat, 0.0) > 0.0:
                    active_flags.append(str(f.get('flag_name') or fcat))
            inv_flag_score = min(0.2, 0.05 * float(len(active_flags)))
            # Final dynamic table score
            table_score_dyn = max(0.0, min(1.0, (0.8 * avg_conf) + bundle_boost + inv_flag_score))
            # Dominant category by weighted contribution with tie-break priority
            PRIORITY = {"PHI":0, "Financial":1, "SOX":2, "Regulatory":3, "TradeSecret":4, "Operational":5, "PII":6}
            dom_cat = None
            if cat_scores:
                dom_cat = sorted(cat_scores.items(), key=lambda kv: (-kv[1], PRIORITY.get(kv[0], 99)))[0][0]
            dom_cat = dom_cat or predominant_type
            # Apply per-category dynamic threshold
            thr_map = cfg.get('thresholds_category') or {}
            thr = float(thr_map.get(dom_cat, 0.6)) if dom_cat else 0.6
            is_sensitive = bool(table_score_dyn >= thr)
            requires_review = bool((table_score_dyn >= max(0.0, thr - 0.05)) and (table_score_dyn < thr))
            # Attach dynamic fields
            tbl_row.update({
                "dominant_category": dom_cat,
                "table_sensitivity_score": round(table_score_dyn, 3),
                "threshold_applied": thr,
                "sensitive": is_sensitive,
                "requires_review": bool(tbl_row.get("requires_review") or requires_review),
                "flags_active": active_flags,
            })
        except Exception:
            pass
        # --- Persist recomputed flags to ASSET_INVENTORY (AI_* columns) ---
        try:
            db = None
            if settings is not None:
                db = getattr(settings, "SCAN_CATALOG_DB", None) or getattr(settings, "SNOWFLAKE_DATABASE", None)
            inv_fqn_candidates = []
            if db:
                inv_fqn_candidates.append(f"{db}.DATA_CLASSIFICATION_GOVERNANCE.ASSETS")
            inv_fqn_candidates.append("DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE.ASSETS")
            # Ensure AI columns exist and update JSON flags
            full_name = tbl_row.get("fullname") or table_name
            for inv_fqn in inv_fqn_candidates:
                try:
                    snowflake_connector.execute_non_query(
                        f"alter table {inv_fqn} add column if not exists AI_FLAGS variant"
                    )
                    snowflake_connector.execute_non_query(
                        f"alter table {inv_fqn} add column if not exists AI_DOMINANT_CATEGORY string"
                    )
                    snowflake_connector.execute_non_query(
                        f"alter table {inv_fqn} add column if not exists AI_SENSITIVITY_SCORE float"
                    )
                    flags_json = __import__('json').dumps({"flags": active_flags}) if 'active_flags' in locals() else __import__('json').dumps({"flags": []})
                    snowflake_connector.execute_non_query(
                        f"update {inv_fqn} set AI_FLAGS = PARSE_JSON(%(f)s), AI_DOMINANT_CATEGORY=%(c)s, AI_SENSITIVITY_SCORE=%(s)s where FULLY_QUALIFIED_NAME=%(n)s",
                        {"f": flags_json, "c": str(tbl_row.get("dominant_category") or ""), "s": float(tbl_row.get("table_sensitivity_score") or 0.0), "n": str(full_name)},
                    )
                    break
                except Exception:
                    continue
        except Exception:
            pass
        # --- Suggested keyword feedback loop (persist inactive suggestions) ---
        try:
            cfg_kw = set()
            try:
                cfg = self.load_sensitivity_config()
                for it in (cfg.get("keywords") or []):
                    t = str(it.get("token") or it.get("keyword") or "").upper().strip()
                    if t:
                        cfg_kw.add(t)
            except Exception:
                cfg_kw = set()
            # Extract candidate tokens from high-confidence columns
            sugg: set[tuple[str,str]] = set()
            for d in detections.values():
                conf = float(d.get("confidence", 0.0)) / 100.0
                dom = str(d.get("dominant_category") or "").strip()
                col = str(d.get("column") or "")
                if conf >= 0.9 and dom:
                    import re as _re
                    parts = [p for p in _re.split(r"[^A-Za-z0-9]+", col.upper()) if p and len(p) >= 3]
                    for p in parts:
                        if p not in cfg_kw and p not in {"COLUMN","FIELD","VALUE","TABLE","DATA","NAME","TYPE","CODE","NUMBER","ID","NO","NUM"}:
                            sugg.add((dom, p))
            if sugg and snowflake_connector is not None:
                # Ensure table exists
                db = None
                if settings is not None:
                    db = getattr(settings, "SCAN_CATALOG_DB", None) or getattr(settings, "SNOWFLAKE_DATABASE", None)
                schema_fqn = f"{db}.DATA_CLASSIFICATION_GOVERNANCE" if db else "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE"
                snowflake_connector.execute_non_query(
                    f"""
                    create table if not exists {schema_fqn}.SENSITIVE_KEYWORDS (
                      category string,
                      keyword string,
                      priority number default 0,
                      is_active boolean default true,
                      source string,
                      updated_at timestamp_ntz default current_timestamp()
                    )
                    """
                )
                # Insert suggestions as inactive
                for cat, tok in list(sugg)[:100]:
                    try:
                        snowflake_connector.execute_non_query(
                            f"insert into {schema_fqn}.SENSITIVE_KEYWORDS (category, keyword, priority, is_active, source) values (%(c)s, %(k)s, 0, false, 'suggested')",
                            {"c": cat, "k": tok},
                        )
                    except Exception:
                        continue
        except Exception:
            pass
        # --- Audit low-confidence and requires-review items ---
        try:
            db = None
            if settings is not None:
                db = getattr(settings, "SCAN_CATALOG_DB", None) or getattr(settings, "SNOWFLAKE_DATABASE", None)
            schema_fqn = f"{db}.DATA_CLASSIFICATION_GOVERNANCE" if db else "DATA_CLASSIFICATION_DB.DATA_CLASSIFICATION_GOVERNANCE"
            snowflake_connector.execute_non_query(
                f"""
                create table if not exists {schema_fqn}.SENSITIVE_AUDIT (
                  audit_id number autoincrement,
                  table_name string,
                  column_name string,
                  category string,
                  confidence number,
                  cia string,
                  bundle_detected boolean,
                  requires_review boolean,
                  scanned_at timestamp_ntz default current_timestamp(),
                  primary key (audit_id)
                )
                """
            )
            for r in col_rows:
                cname = str(r.get("column_name") or "")
                d = detections.get(cname) or {}
                conf = int(d.get("confidence") or r.get("confidence_score") or 0)
                dom = str(d.get("dominant_category") or r.get("sensitive_type") or "")
                req = bool(r.get("requires_review") or (conf < 75))
                cia = r.get("CIA (C/I/A)") or {}
                snowflake_connector.execute_non_query(
                    f"insert into {schema_fqn}.SENSITIVE_AUDIT (table_name, column_name, category, confidence, cia, bundle_detected, requires_review) values (%(t)s, %(c)s, %(cat)s, %(conf)s, %(cia)s, %(bb)s, %(rv)s)",
                    {
                        "t": str(table_name),
                        "c": cname,
                        "cat": dom,
                        "conf": int(conf),
                        "cia": f"{cia.get('C',0)}/{cia.get('I',0)}/{cia.get('A',0)}",
                        "bb": bool((d.get("bundle_boost") if isinstance(d, dict) else False) or False),
                        "rv": req,
                    },
                )
        except Exception:
            pass
        return {"table": tbl_row, "columns": col_rows}

    def register_uploaded_dataframe(self, table_name: str, df: pd.DataFrame) -> None:
        cols = [{"name": c, "type": None} for c in list(df.columns)]
        self.set_virtual_table_profile(table_name, columns=cols, samples=df)

    def classify_sensitive(self, table_name: str, sample_size: int = 200) -> Dict[str, Any]:
        meta = self.get_table_metadata(table_name) or {}
        cols = self.get_column_metadata(table_name) or []
        df = self.get_sample_data(table_name, sample_size)
        det = self.detect_sensitive_columns(table_name, sample_size=sample_size) or []
        by_col = {str(d.get("column") or ""): d for d in det}
        out_cols: List[Dict[str, Any]] = []
        domain = meta.get("TABLE_DOMAIN")
        # Table context analysis (names, FKs, co-occurrence, embeddings)
        try:
            ctx = self._table_context_analysis(table_name, cols, df)
        except Exception:
            ctx = {"score": 0.0, "categories": [], "signals": {}}
        # New: run enhanced sensitive detection (regex+ML ensemble)
        try:
            sd = _sd_classify(table_name, df) if isinstance(df, pd.DataFrame) and not df.empty else {"columns": [], "sensitive": False, "score": 0.0}
        except Exception:
            sd = {"columns": [], "sensitive": False, "score": 0.0}
        _sd_map = {str(r.get("column") or ""): r for r in (sd.get("columns") or [])}
        # Optional: compute table-name-to-category semantic similarity using embeddings
        table_name_semantic_max = 0.0
        try:
            self._ensure_embedder()
            if self._embedding_backend != 'none' and self._embedder is not None and np is not None:
                # Build a temporary category token list if not present
                self._ensure_category_embeddings(self._sensitivity_patterns())
                tbl_text = re.sub(r"[_\-]+", " ", str(table_name or "").split('.')[-1]).strip()
                vec = self._get_embedding(tbl_text) if tbl_text else None
                if vec is not None and self._category_embeds:
                    for items in self._category_embeds.values():
                        for _, v in items:
                            try:
                                sim = float(np.dot(vec, v) / (np.linalg.norm(vec) * np.linalg.norm(v) + 1e-12))
                                if sim > table_name_semantic_max:
                                    table_name_semantic_max = sim
                            except Exception:
                                continue
        except Exception:
            table_name_semantic_max = 0.0
        for cm in cols:
            cname = str(cm.get("COLUMN_NAME") or "")
            d = by_col.get(cname) or {}
            cats = list(d.get("categories") or [])
            name_hits = 1.0 if int(d.get("name_score") or 0) > 0 else 0.0
            value_hits = 1.0 if int(d.get("value_score") or 0) > 0 else 0.0
            stats_hits = 1.0 if ("PII" in cats and int(d.get("value_score") or 0) == 0) else 0.0
            # Context score from table-level analysis + legacy domain signal
            dom_bonus = 1.0 if domain in ("Finance","HR","Healthcare") else 0.0
            ctx_score = max(float(ctx.get("score", 0.0)), 0.0)
            ctx_hits = min(1.0, 0.5*dom_bonus + 0.5*ctx_score)
            # Merge context categories (if any) to influence dominant selection
            for cc in (ctx.get("categories") or []):
                if cc not in cats:
                    cats.append(cc)
            # Hybrid Rule + ML-style ensemble probability
            try:
                series = df[cname] if (isinstance(df, pd.DataFrame) and cname in df.columns) else None
                stats = self._profile_series_stats_full(series) if series is not None else {}
                name_score, _name_cats = self._keyword_score_from_name(cname)
                patt_score, _cat_hits = self._pattern_score_from_series(cname, df) if (isinstance(df, pd.DataFrame)) else (0.0, {})
                ml_prob_row = self._ml_sensitivity_probability(
                    cname,
                    series,
                    stats,
                    name_score,
                    patt_score,
                    ctx_score,
                ) if series is not None else {"prob": 0.0, "category": None, "reasons": []}
                # Optional zero-shot classification fusion
                try:
                    from transformers import pipeline  # type: ignore
                    zsc = pipeline("zero-shot-classification", model="typeform/distilbert-base-uncased-mnli")
                    candidates = ["PII","PHI","Financial","SOX","Regulatory","Operational","TradeSecret"]
                    sample_vals = []
                    try:
                        sample_vals = series.dropna().astype(str).head(5).tolist() if isinstance(series, pd.Series) else []
                    except Exception:
                        sample_vals = []
                    hypothesis = f"This column in table {table_name} relates to category"
                    text = f"col:{cname} domain:{domain} ctx:{','.join(ctx.get('categories', []))} samples:{' | '.join(sample_vals)}"
                    zr = zsc(text, candidate_labels=candidates, multi_label=True)
                    z_scores = {lbl: float(scr) for lbl, scr in zip(zr.get('labels', []), zr.get('scores', []))}
                    z_top = [k for k,v in z_scores.items() if v >= 0.5]
                    for zc in z_top:
                        if zc not in cats:
                            cats.append(zc)
                    # modest confidence bump if zero-shot strongly agrees
                    if any(v >= 0.7 for v in z_scores.values()):
                        ctx_hits = min(1.0, ctx_hits + 0.05)
                except Exception:
                    pass
                # If ML sees high probability, push category and boost confidence
                if float(ml_prob_row.get("prob", 0.0)) >= 0.6:
                    pred_cat = ml_prob_row.get("category") or None
                    if pred_cat and pred_cat not in cats:
                        cats.append(pred_cat)
                    # light confidence bump (max 5%)
                    ctx_hits = min(1.0, ctx_hits + 0.05)
                # Compute unified sensitivity score (0-10)
                sens = self._sensitivity_score_ensemble(
                    name_match=(name_score > 0),
                    metadata_match=(patt_score > 0 or (stats.get("patterns") or {})),
                    regex_ai_match=(patt_score >= 0.5 or float(ml_prob_row.get("prob", 0.0)) >= 0.6),
                    context_score=ctx_score,
                    unique_ratio=float(stats.get("unique_ratio") or stats.get("uniq_ratio") or 0.0),
                )
                sensitivity_score = sens.get("score", 0.0)
                sensitivity_prob = sens.get("prob", 0.0)
            except Exception:
                sensitivity_score = 0.0
                sensitivity_prob = 0.0
            conf = min(1.0, 0.40*name_hits + 0.30*value_hits + 0.20*stats_hits + 0.10*ctx_hits)
            dom_cat = d.get("dominant_category")
            if not dom_cat and cats:
                order = {"PCI":0, "PHI":1, "PII":2, "SOX":3, "Financial":4, "Regulatory":5, "TradeSecret":6, "Operational":7, "SOC":8}
                dom_cat = sorted(set(cats), key=lambda x: order.get(str(x), 99))[0]
            cia = self._suggest_cia_from_type(str(dom_cat or ""))
            # Map sensitivity score to CIA and take max with type-based CIA
            try:
                cia_from_sens = self._suggest_cia_from_sensitivity(float(sensitivity_score))
                cia = {
                    "C": max(int(cia.get("C", 0)), int(cia_from_sens.get("C", 0))),
                    "I": max(int(cia.get("I", 0)), int(cia_from_sens.get("I", 0))),
                    "A": max(int(cia.get("A", 0)), int(cia_from_sens.get("A", 0))),
                }
            except Exception:
                pass
            # Merge with enhanced detector results, prioritizing high recall
            try:
                sd_row = _sd_map.get(cname)
                if sd_row:
                    # placeholder: merge logic could take max probability across detectors
                    pass
            except Exception:
                pass
            agg_weights = {"PCI":0, "PHI":1, "PII":2, "SOX":3, "Financial":4, "Regulatory":5, "TradeSecret":6, "Operational":7, "SOC":8}
        from collections import defaultdict
        score_sum: Dict[str, int] = defaultdict(int)
        count_sum: Dict[str, int] = defaultdict(int)
        table_cia = {"C":0, "I":0, "A":0}
        for r in out_cols:
            lab = str(r.get("classification_label") or "Internal")
            sc = int(r.get("confidence_score") or 0)
            score_sum[lab] += sc
            count_sum[lab] += 1
            c = r.get("cia") or {}
            for k in ("C","I","A"):
                try:
                    table_cia[k] = max(int(table_cia.get(k,0)), int(c.get(k,0)))
                except Exception:
                    pass
        best_cat = None
        if score_sum:
            def _key(cat: str):
                return (agg_weights.get(cat, 99), -(score_sum[cat] // max(1, count_sum[cat])))
            best_cat = sorted(score_sum.keys(), key=_key)[0]
        # Determine table sensitivity via new policy
        try:
            total_cols = max(1, len(out_cols))
            sd_sensitive_ratio = float(sum(1 for c in (sd.get("columns") or []) if c.get("sensitive")))/float(total_cols) if isinstance(sd, dict) else 0.0
        except Exception:
            sd_sensitive_ratio = 0.0
        # Sensitive if name semantic >0.8 OR >30% columns sensitive
        table_sensitive_gate = (table_name_semantic_max > 0.80) or (sd_sensitive_ratio > 0.30)
        # CIA->Label mapping per policy
        C, I, A = int(table_cia.get("C",0)), int(table_cia.get("I",0)), int(table_cia.get("A",0))
        if C <= 1 and I <= 1 and A <= 1:
            table_label = "Public"
        elif (C >= 2 and I >= 2 and C < 3 and I < 3):
            table_label = "Internal"
        elif C >= 2:
            table_label = "Restricted"
        else:
            table_label = "Internal"
        # Escalate to Confidential if C3 or multiple strong categories
        try:
            cat_set = set([str(r.get("classification_label") or "") for r in out_cols if int(r.get("confidence_score") or 0) >= 85])
            if C == 3 or len([c for c in cat_set if c in ("PII","PHI","Financial","Regulatory","SOX","TradeSecret")]) >= 2:
                table_label = "Confidential"
        except Exception:
            pass
        avg_conf = 0
        if out_cols:
            avg_conf = int(round(sum([int(c.get("confidence_score") or 0) for c in out_cols]) / max(1, len(out_cols))))
        overall_conf = max(avg_conf, int(round(max(score_sum.values())/max(1, len(out_cols)))) if score_sum else 0)
        requires_review = overall_conf < 85
        # Policy recommendation
        if table_label in ("Confidential","Restricted"):
            if any(c in ("PII","PHI") for c in (ctx.get("categories") or [])):
                policy_rec = "Mask/tokenize, RBAC restrict, audit"
            elif any(c in ("Financial","SOX") for c in (ctx.get("categories") or [])):
                policy_rec = "RBAC restrict, audit, encryption, segregation"
            elif any(c in ("Regulatory",) for c in (ctx.get("categories") or [])):
                policy_rec = "Regulatory controls, retention, DLP"
            else:
                policy_rec = "Standard controls"
        else:
            policy_rec = "Standard controls"
        mode = "snowflake" if (self.use_snowflake and snowflake_connector is not None) else "virtual"
        return {
            "mode": mode,
            "table": {
                "table_name": table_name,
                "overall_classification_label": (best_cat or table_label or "Internal"),
                "confidence_score": overall_conf,
                "requires_review": requires_review or (not table_sensitive_gate),
                "cia": table_cia,
                "context_signals": (ctx.get("signals") if isinstance(ctx, dict) else {}),
                # expose enhanced detector table signals
                "sd_sensitive": bool(sd.get("sensitive", False)) if isinstance(sd, dict) else False,
                "sd_score": float(sd.get("score", 0.0)) if isinstance(sd, dict) else 0.0,
                "sd_composites": (sd.get("composites") if isinstance(sd, dict) else []),
                "policy_recommendation": policy_rec,
                "table_name_semantic_max": round(float(table_name_semantic_max), 3),
                "sd_sensitive_ratio": round(float(sd_sensitive_ratio), 3),
            },
            "columns": out_cols,
        }

    # ---- Table Context Analysis (names, FKs, co-occurrence, embeddings-lite) ----
    def _table_context_analysis(self, table_name: str, cols: List[Dict[str, Any]], df: Optional[pd.DataFrame]) -> Dict[str, Any]:
        """Analyze table/schema names and surrounding signals to infer sensitive context.

        - Name keywords on table/schema
        - Foreign key references to sensitive tables (Snowflake if available)
        - Column co-occurrence clusters (e.g., emp_id with salary)
        - Embedding-lite similarity using token-set Jaccard to seed terms
        """
        try:
            parts = str(table_name or "").split('.')
            tokens = []
            for p in parts:
                tokens.extend(self._tokenize(p))
            col_names = [str(c.get("COLUMN_NAME") or c.get("name") or "") for c in (cols or [])]
            for cn in col_names:
                tokens.extend(self._tokenize(cn))
            tok_set = set([t for t in tokens if t])

            seed: Dict[str, List[str]] = {
                "HR": ["hr","employee","emp","payroll","salary","wage","staff","worker","benefit","ssn"],
                "Finance": ["finance","fin","invoice","gl","ledger","account","payment","payslip","revenue","expense","bank","routing","iban","card"],
                "Healthcare": ["health","medical","patient","icd","diagnosis","rx","mrn","hipaa"],
                "PII": ["user","customer","client","person","email","phone","address","passport","tax","aadhaar","pan","national","license","zip"],
                "SOX": ["sox","gl","journal","ledger","trial","balance","audit","ifrs","gaap"],
            }

            # Name keyword / embedding-lite score per category
            cat_scores: Dict[str, float] = {}
            for cat, seeds in seed.items():
                sim = self._jaccard_similarity(tok_set, set(seeds))
                # Boost by direct keyword hits in table name tokens
                dir_hits = len([t for t in parts if any(k in t.lower() for k in seeds)])
                score = min(1.0, sim * 0.8 + (0.2 if dir_hits > 0 else 0.0))
                if score > 0:
                    cat_scores[cat] = score

            # FK references (Snowflake only)
            fk_refs: List[str] = []
            fk_score = 0.0
            if self.use_snowflake and snowflake_connector is not None:
                try:
                    db, sch, tbl = (parts + [None, None, None])[:3]
                    if db and sch and tbl:
                        rows = snowflake_connector.execute_query(
                            f"""
                            SELECT DISTINCT rc.UNIQUE_CONSTRAINT_NAME, kcu2.TABLE_SCHEMA AS REF_SCHEMA, kcu2.TABLE_NAME AS REF_TABLE
                            FROM {db}.INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS rc
                            JOIN {db}.INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu1
                              ON rc.CONSTRAINT_NAME = kcu1.CONSTRAINT_NAME AND rc.CONSTRAINT_SCHEMA = kcu1.CONSTRAINT_SCHEMA
                            JOIN {db}.INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu2
                              ON rc.UNIQUE_CONSTRAINT_NAME = kcu2.CONSTRAINT_NAME AND rc.UNIQUE_CONSTRAINT_SCHEMA = kcu2.CONSTRAINT_SCHEMA
                            WHERE kcu1.TABLE_SCHEMA = %(s)s AND kcu1.TABLE_NAME = %(t)s
                            LIMIT 50
                            """,
                            {"s": sch, "t": tbl},
                        ) or []
                        for r in rows:
                            ref = f"{db}.{r.get('REF_SCHEMA')}.{r.get('REF_TABLE')}"
                            fk_refs.append(ref)
                    # Score FK targets by same category seeds
                    fk_tokens = set()
                    for r in fk_refs:
                        for p in str(r).split('.'):
                            fk_tokens.update(self._tokenize(p))
                    for cat, seeds in seed.items():
                        fk_score = max(fk_score, self._jaccard_similarity(fk_tokens, set(seeds)))
                except Exception:
                    fk_refs = []

            # Column co-occurrence clusters
            clusters_hit: List[str] = []
            cn_up = [c.lower() for c in col_names]
            def has_any(keys: List[str]) -> bool:
                return any(k in cn_up for k in keys)
            # HR pattern: emp_id + salary/payroll
            if has_any(["emp_id","employee_id"]) and has_any(["salary","wage","payroll"]):
                clusters_hit.append("HR_PAYROLL")
                cat_scores["HR"] = max(cat_scores.get("HR", 0.0), 0.7)
            # Finance pattern: account/card + amount
            if has_any(["account_id","account","card","pan"]) and has_any(["amount","total","balance"]):
                clusters_hit.append("FIN_ACCOUNT_AMOUNT")
                cat_scores["Finance"] = max(cat_scores.get("Finance", 0.0), 0.6)
            # PII pattern: email/phone/address alongside name
            if has_any(["email"]) and has_any(["phone","address"]) and has_any(["name","first_name","last_name"]):
                clusters_hit.append("PII_CONTACT")
                cat_scores["PII"] = max(cat_scores.get("PII", 0.0), 0.6)

            # Combine scores
            name_embed_score = max(cat_scores.values()) if cat_scores else 0.0
            combined = min(1.0, 0.5*name_embed_score + 0.3*fk_score + 0.2*(1.0 if clusters_hit else 0.0))
            # Categories above threshold
            cats = [k for k, v in cat_scores.items() if v >= 0.35]
            # Map to global category names used elsewhere
            mapped = []
            for c in cats:
                if c == "HR":
                    mapped.append("PII")  # HR data often contains PII
                else:
                    mapped.append(c if c != "Finance" else "Financial")

            return {
                "score": round(combined, 3),
                "categories": sorted(set(mapped)),
                "signals": {
                    "name_tokens": list(sorted(tok_set))[:50],
                    "fk_refs": fk_refs,
                    "clusters": clusters_hit,
                    "per_category_name_scores": {k: round(v, 3) for k, v in cat_scores.items()},
                    "fk_score": round(fk_score, 3),
                },
            }
        except Exception:
            return {"score": 0.0, "categories": [], "signals": {}}

    def _tokenize(self, text: str) -> List[str]:
        try:
            parts = re.split(r"[^A-Za-z0-9]+", str(text or "").lower())
            return [p for p in parts if p]
        except Exception:
            return []

    def _jaccard_similarity(self, a: set, b: set) -> float:
        try:
            if not a or not b:
                return 0.0
            inter = len(a & b)
            union = len(a | b)
            return float(inter) / float(union) if union else 0.0
        except Exception:
            return 0.0

    def _ml_sensitivity_probability(
        self,
        col_name: str,
        series: Optional[pd.Series],
        stats: Dict[str, Any],
        name_score: float,
        patt_score: float,
        ctx_score: float,
    ) -> Dict[str, Any]:
        """Hybrid rule + ML-style sensitivity probability for a column.

        No external ML dep: uses a calibrated logistic-like function over engineered features.
        Returns {prob: float, category: Optional[str], reasons: List[str]}.
        """
        reasons: List[str] = []
        try:
            # Derived features
            uniq_ratio = float(stats.get("unique_ratio") or stats.get("uniq_ratio") or 0.0)
            null_ratio = float(stats.get("null_ratio") or 0.0)
            avg_len = float(stats.get("avg_len") or 0.0)
            entropy_mean = float((stats.get("entropy") or {}).get("entropy_mean") or stats.get("avg_entropy") or 0.0)
            is_num = bool(stats.get("is_numeric") or False)
            is_str = bool(stats.get("is_string") or False)
            num = stats.get("numeric") or {}
            outliers = (num.get("outliers") or {}) if isinstance(num, dict) else {}
            outlier_ratio = float(outliers.get("ratio") or 0.0)
            skewness = float(num.get("skewness") or 0.0) if isinstance(num, dict) else 0.0
            kurtosis = float(num.get("kurtosis") or 0.0) if isinstance(num, dict) else 0.0
            patterns = stats.get("patterns") or {}

            # Rule-based category candidates from patterns
            cat = None
            if any(k in patterns for k in ["email","phone","ssn"]):
                cat = "PII"; reasons.append("regex: contact/identity pattern")
            if "credit_card" in patterns:
                cat = "PCI"; reasons.append("regex: credit card")
            # If pattern_score came from _sensitivity_patterns, may imply Financial/PII/PHI
            if patt_score >= 0.5 and cat is None:
                # fall back to PII as generic sensitive type
                cat = "PII"; reasons.append("sample patterns strong")

            # Encoding detection: small unique cardinality vs N suggests categorical
            enc_flag = False
            enc_sensitive_flag = False
            valset = set()
            if isinstance(series, pd.Series):
                try:
                    ss = series.dropna().head(1000)
                    # Collect a small set for checks without heavy memory
                    vals = ss.astype(str).tolist()
                    valset = set([v.strip().lower() for v in vals if v.strip()])
                except Exception:
                    valset = set()
            unique_count = int(stats.get("unique_count") or round(uniq_ratio * float(stats.get("count") or 0)))
            if unique_count > 0 and (stats.get("count") or 0) and (unique_count / max(1.0, float(stats.get("count") or 0))) <= 0.05:
                enc_flag = True
            if enc_flag:
                # Check for binary/ternary typical code sets
                common_bin = {"0","1","y","n","true","false","m","f"}
                if valset and valset.issubset(common_bin | set(list("012"))):
                    enc_sensitive_flag = True
                    reasons.append("encoded categorical (binary/ternary)")
                # Name cues for sensitive encoding
                up = (col_name or "").upper()
                if any(k in up for k in ["GENDER","SEX","MINOR","PREGNANT","DISABILITY","HIPAA","MED","HEALTH"]):
                    cat = cat or ("PHI" if any(k in up for k in ["HIPAA","MED","HEALTH"]) else "PII")
                    reasons.append("name indicates sensitive encoding")

            # Numeric outlier-based hints (e.g., salary)
            if is_num and outlier_ratio >= 0.05 and (num.get("range") or 0) and float(num.get("range", 0)) > 0:
                up = (col_name or "").upper()
                if any(k in up for k in ["SALARY","WAGE","PAY","AMOUNT","TOTAL"]):
                    cat = cat or "Financial"
                    reasons.append("numeric outliers + financial term")

            # Logistic-like ensemble
            def sigmoid(z: float) -> float:
                try:
                    return 1.0 / (1.0 + math.exp(-z))
                except Exception:
                    return 0.5

            # Weights tuned for reasonable heuristics
            z = (
                -1.2
                + 1.8 * float(name_score)
                + 2.2 * float(patt_score)
                + 0.9 * float(ctx_score)
                + 0.8 * float(min(1.0, uniq_ratio))
                + 0.6 * float(min(1.0, entropy_mean / 3.0))
                + 0.5 * float(min(1.0, outlier_ratio * 4.0))
                + (0.5 if enc_sensitive_flag else 0.0)
            )
            prob = float(round(sigmoid(z), 4))

            return {"prob": prob, "category": cat, "reasons": reasons}
        except Exception:
            return {"prob": 0.0, "category": None, "reasons": []}

    def _sensitivity_score_ensemble(
        self,
        name_match: bool,
        metadata_match: bool,
        regex_ai_match: bool,
        context_score: float,
        unique_ratio: float,
    ) -> Dict[str, Any]:
        """Combine discrete feature flags into a 0–10 sensitivity score and probability.

        Weights per requirement:
        - Column name match: +2
        - Metadata pattern match: +2
        - Regex / AI prediction match: +3
        - Table context analysis: up to +2 (linear scale from 0..1 -> 0..2)
        - Unique/high cardinality: +1 (applied if unique_ratio >= 0.6)
        """
        try:
            score = 0.0
            if name_match:
                score += 2.0
            if metadata_match:
                score += 2.0
            if regex_ai_match:
                score += 3.0
            # Context up to +2
            score += max(0.0, min(2.0, 2.0 * float(context_score or 0.0)))
            # High cardinality bonus
            if float(unique_ratio or 0.0) >= 0.6:
                score += 1.0
            # Clamp 0..10
            score = max(0.0, min(10.0, score))
            prob = round(score / 10.0, 4)
            return {"score": score, "prob": prob}
        except Exception:
            return {"score": 0.0, "prob": 0.0}

    # ---- New AI methods (mapping to old ones) ----
    def infer_table_metadata_from_context(self, table_name: str) -> Dict[str, Any]:
        """New method replacing get_table_metadata() via AI inference."""
        return self.get_table_metadata(table_name)
    def analyze_column_semantics(self, table_name: str, sample_size: int = 100) -> List[Dict[str, Any]]:
        """New method replacing get_column_metadata() for semantic analysis of columns."""
        return self.detect_sensitive_columns(table_name, sample_size=sample_size)

    def generate_virtual_data_profile(self, table_name: str, sample_size: int = 200) -> Dict[str, Any]:
        """Return profiling output (stats + detections) for virtual mode."""
        df = self.get_sample_data(table_name, sample_size)
        det = self.detect_sensitive_columns(table_name, sample_size=sample_size)
        return {
            "row_count": int(len(df) if isinstance(df, pd.DataFrame) else 0),
            "columns": [c.get("column") for c in (det or [])],
            "detections": det,
        }

    # ---------------- Dynamic SDD (runtime-configurable) ----------------
    def set_sdd_config(self, cfg: Dict[str, Any]) -> None:
        if not hasattr(self, "_sdd_config"):
            self._sdd_config: Dict[str, Any] = {}
        self._sdd_config.update(cfg or {})
        pats = (self._sdd_config.get("regex_patterns") or {})
        comp: Dict[str, Any] = {}
        for name, rx in pats.items():
            try:
                comp[name] = re.compile(str(rx))
            except Exception:
                continue
        self._sdd_config["_compiled_patterns"] = comp
        if not hasattr(self, "_sdd_scanned"):
            self._sdd_scanned: Dict[str, float] = {}

    def _sdd_cfg(self) -> Dict[str, Any]:
        if not hasattr(self, "_sdd_config"):
            self._sdd_config = {
                "keywords": {},
                "regex_patterns": {},
                "weights": {"keyword": 0.3, "pattern": 0.5, "profiling": 0.2},
                "thresholds": {"confidence": 85, "sample_size": 200},
                "cia_policy": {},
                "global_table_filters": [],
                "_compiled_patterns": {},
            }
        return self._sdd_config

    def _sdd_like_any(self, value: str, patterns: List[str]) -> bool:
        s = str(value or "")
        for p in patterns or []:
            p = str(p or "")
            if not p:
                continue
            if "%" in p or "_" in p:
                rx = re.escape(p).replace("%", ".*").replace("_", ".")
                if re.fullmatch(rx, s, flags=re.IGNORECASE):
                    return True
            elif s.lower() == p.lower():
                return True
        return False

    def discover_sensitive_tables(
        self,
        source: str = "snowflake",
        database: Optional[str] = None,
        schema_glob: str = "%",
        include_virtual: bool = True,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        cfg = self._sdd_cfg()
        tables: List[str] = []
        if source == "snowflake" and self.use_snowflake and snowflake_connector is not None:
            if not database:
                if settings is None:
                    raise ValueError("database is required for snowflake discovery")
                database = settings.SNOWFLAKE_DATABASE
            try:
                rows = snowflake_connector.execute_query(
                    f"""
                    SELECT "TABLE_CATALOG"||'.'||"TABLE_SCHEMA"||'.'||"TABLE_NAME" AS FULL
                    FROM {database}.INFORMATION_SCHEMA.TABLES
                    WHERE "TABLE_SCHEMA" NOT IN ('INFORMATION_SCHEMA')
                      AND ("TABLE_TYPE" IN ('BASE TABLE','VIEW'))
                      AND ("TABLE_SCHEMA" ILIKE %(sc)s)
                    ORDER BY 1
                    LIMIT %(lim)s
                    """,
                    {"sc": schema_glob, "lim": int(limit)},
                ) or []
                tables.extend([str(r.get("FULL")) for r in rows if r.get("FULL")])
            except Exception:
                tables = []
        elif source == "virtual":
            tables.extend(list(self._virtual_catalog.keys()))
        else:
            raise ValueError("source must be 'snowflake' or 'virtual'")
        if include_virtual and source == "snowflake":
            tables.extend(list(self._virtual_catalog.keys()))
        filters = cfg.get("global_table_filters") or []
        tables = [t for t in tables if not self._sdd_like_any(t, filters)]
        out: List[Dict[str, Any]] = []
        for t in tables:
            try:
                rep = self.generate_table_report(t, quick=True)
                if not hasattr(self, "_sdd_scanned"):
                    self._sdd_scanned = {}
                self._sdd_scanned[t] = self._sdd_scanned.get(t) or 0.0
                out.append(rep)
            except Exception:
                continue
        return out

    def _sdd_keyword_score(self, column_name: str) -> Tuple[float, List[str]]:
        cfg = self._sdd_cfg()
        kws = cfg.get("keywords") or {}
        up = (column_name or "").upper()
        hits: List[str] = []
        for cat, arr in kws.items():
            for tok in arr or []:
                if tok and str(tok).upper() in up:
                    hits.append(str(cat))
                    break
        score = 1.0 if hits else 0.0
        return score, hits

    def _sdd_pattern_score(self, values: List[str]) -> Tuple[float, Dict[str, int]]:
        cfg = self._sdd_cfg()
        comp = cfg.get("_compiled_patterns") or {}
        if not values:
            return 0.0, {}
        counts: Dict[str, int] = {k: 0 for k in comp.keys()}
        total = 0
        for v in values:
            s = "" if v is None else str(v)
            if not s:
                continue
            total += 1
            for name, cre in comp.items():
                try:
                    if cre.search(s):
                        counts[name] = counts.get(name, 0) + 1
                except Exception:
                    continue
        if total == 0:
            return 0.0, counts
        hit_any = sum(1 for c in counts.values() if c > 0)
        score = min(1.0, float(hit_any) / max(1.0, math.sqrt(float(total))))
        return score, counts

    def _sdd_profiling_score(self, series_values: List[Any]) -> float:
        if not series_values:
            return 0.0
        try:
            vals = [v for v in series_values if v is not None]
            n = float(len(vals))
            if n == 0:
                return 0.0
            uniq = len(set(vals))
            null_ratio = 1.0 - (n / float(len(series_values)))
            avg_len = sum(len(str(v)) for v in vals) / max(1.0, n)
            u = min(1.0, uniq / max(1.0, n))
            a = min(1.0, avg_len / 64.0)
            r = min(1.0, null_ratio)
            return max(0.0, min(1.0, 0.6*u + 0.3*a + 0.1*(1.0 - r)))
        except Exception:
            return 0.0

    def _sdd_cia_policy(self, category: str) -> Tuple[Dict[str, int], str]:
        cfg = self._sdd_cfg()
        mapping = cfg.get("cia_policy") or {}
        m = mapping.get(str(category)) or {}
        if m:
            return {"C": int(m.get("C", 0)), "I": int(m.get("I", 0)), "A": int(m.get("A", 0))}, str(m.get("policy", ""))
        cia = self._suggest_cia_from_type(str(category)) if hasattr(self, "_suggest_cia_from_type") else {"C": 0, "I": 0, "A": 0}
        return cia, ""

    def generate_column_report(self, table_name: str, sample_size: Optional[int] = None) -> List[Dict[str, Any]]:
        cfg = self._sdd_cfg()
        # Load weights from SENSITIVITY_WEIGHTS table (no hardcoded defaults)
        weights_config = cfg.get("weights", {}) or {}
        # Extract detection method weights if available, otherwise use empty dict
        weights = weights_config.get("detection_methods", {}) or {}
        ss = int(cfg.get("thresholds", {}).get("sample_size", 200)) if sample_size is None else int(sample_size)
        cols = self.get_column_metadata(table_name) or []
        df = self.get_sample_data(table_name, ss)
        out: List[Dict[str, Any]] = []
        for cm in cols:
            cname = str(cm.get("COLUMN_NAME") or "")
            values: List[str] = []
            if df is not None and not df.empty and cname in df.columns:
                try:
                    values = [None if pd.isna(v) else v for v in df[cname].tolist()]
                except Exception:
                    values = []
            k_score, k_hits = self._sdd_keyword_score(cname)
            p_score, p_hits = self._sdd_pattern_score(values)
            pr_score = self._sdd_profiling_score(values)
            # Use weights from governance config, or 0 if not available (no hardcoded defaults)
            w_keyword = float(weights.get("keyword", 0.0))
            w_pattern = float(weights.get("pattern", 0.0))
            w_profiling = float(weights.get("profiling", 0.0))
            # Normalize weights if they sum to zero to avoid division by zero
            total_weight = w_keyword + w_pattern + w_profiling
            if total_weight == 0:
                # If no weights configured, use equal distribution (config-driven, not hardcoded category values)
                w_keyword = w_pattern = w_profiling = 1.0 / 3.0
            conf = max(0.0, min(1.0, w_keyword*k_score + w_pattern*p_score + w_profiling*pr_score))
            cats = list(set(k_hits))
            if not cats and p_hits:
                for pat_name, count in sorted(p_hits.items(), key=lambda kv: -kv[1]):
                    for cat, arr in (cfg.get("keywords") or {}).items():
                        if pat_name.upper() in str(cat).upper() or any(tok and str(tok).upper() in pat_name.upper() for tok in arr or []):
                            cats.append(str(cat))
                            break
                    if cats:
                        break
            cat = (cats[0] if cats else "Internal")
            cia, policy = self._sdd_cia_policy(cat)
            label = "Confidential" if int(cia.get("C",0)) >= 3 else ("Restricted" if int(cia.get("C",0)) == 2 else ("Internal" if int(cia.get("C",0)) == 1 else "Public"))
            conf_int = int(round(conf*100))
            requires_review = bool(conf_int < int(cfg.get("thresholds", {}).get("confidence", 85)))
            reasoning_bits: List[str] = []
            if k_score > 0: reasoning_bits.append("keyword match")
            if p_score > 0: reasoning_bits.append("pattern match")
            if pr_score > 0: reasoning_bits.append("profiling uniqueness/length")
            out.append({
                "column_name": cname,
                "category": cat,
                "confidence_score": conf_int,
                "C": int(cia.get("C",0)),
                "I": int(cia.get("I",0)),
                "A": int(cia.get("A",0)),
                "classification_label": label,
                "policy_suggestion": (policy or ("Encrypt" if label in ("Restricted","Confidential") else "")),
                "requires_review": requires_review,
                "reasoning": ", ".join(reasoning_bits) if reasoning_bits else "no strong signals",
            })
        return out

    def generate_table_report(self, table_name: str, quick: bool = False) -> Dict[str, Any]:
        cfg = self._sdd_cfg()
        ss = int(cfg.get("thresholds", {}).get("sample_size", 200))
        col_report = self.generate_column_report(table_name, sample_size=(0 if quick else ss))
        from collections import Counter
        type_votes = Counter([c.get("category") for c in col_report])
        if type_votes:
            prio = {"PII":0, "Financial":1, "Health":2, "Regulatory":3, "PCI":4, "PHI":5, "Internal":9}
            predominant_type = sorted(type_votes.items(), key=lambda kv: (prio.get(str(kv[0]), 99), -kv[1]))[0][0]
        else:
            predominant_type = "Internal"
        max_cia = {"C":0, "I":0, "A":0}
        for r in col_report:
            for k in ("C","I","A"):
                try:
                    max_cia[k] = max(int(max_cia.get(k,0)), int(r.get(k,0)))
                except Exception:
                    pass
        label = "Confidential" if int(max_cia.get("C",0)) >= 3 else ("Restricted" if int(max_cia.get("C",0)) == 2 else ("Internal" if int(max_cia.get("C",0)) == 1 else "Public"))
        if col_report:
            conf_tbl = int(round(sum(int(r.get("confidence_score",0)) for r in col_report) / max(1, len(col_report))))
        else:
            conf_tbl = 0
        requires_review = bool(conf_tbl < int(cfg.get("thresholds", {}).get("confidence", 85)))
        reasoning_bits = []
        if any("keyword" in (r.get("reasoning") or "") for r in col_report):
            reasoning_bits.append("name keyword hits")
        if any("pattern" in (r.get("reasoning") or "") for r in col_report):
            reasoning_bits.append("pattern matches in samples")
        if any("profiling" in (r.get("reasoning") or "") for r in col_report):
            reasoning_bits.append("high uniqueness/entropy")
        policy = ""
        if predominant_type:
            _, policy = self._sdd_cia_policy(str(predominant_type))
        if not policy:
            if predominant_type in ("PII","Health"):
                policy = "Mask/Tokenize"
            elif predominant_type in ("Financial",):
                policy = "Encrypt"
            else:
                policy = "Standard controls"
        meta = self.get_table_metadata(table_name) or {}
        row = {
            "table_name": f"{meta.get('TABLE_CATALOG','')}.{meta.get('TABLE_SCHEMA','')}.{meta.get('TABLE_NAME','')}",
            "predominant_type": predominant_type,
            "confidence_score": conf_tbl,
            "C": int(max_cia.get("C",0)),
            "I": int(max_cia.get("I",0)),
            "A": int(max_cia.get("A",0)),
            "classification_label": label,
            "policy_suggestion": policy,
            "requires_review": requires_review,
            "reasoning": ", ".join(reasoning_bits) if reasoning_bits else "no strong signals",
        }
        return row

    # ---- Persist classification outcomes to SENSITIVE_AUDIT ----
    def _ensure_sensitive_audit_table(self) -> None:
        try:
            if not (self.use_snowflake and snowflake_connector is not None):
                return
            fqn = self._gov_schema_fqn()
            snowflake_connector.execute_non_query(
                f"create schema if not exists {fqn}"
            )
            snowflake_connector.execute_non_query(
                f"""
                create table if not exists {fqn}.SENSITIVE_AUDIT (
                  AUDIT_ID number autoincrement,
                  TABLE_NAME string,
                  COLUMN_NAME string,
                  CATEGORY string,
                  CONFIDENCE number,
                  CIA string,
                  BUNDLE_DETECTED boolean,
                  DETAILS variant,
                  SCANNED_AT timestamp_ntz default current_timestamp(),
                  SAMPLE_HASH string,
                  SAMPLING_METHOD string,
                  SAMPLE_FRACTION float,
                  CREATED_BY string,
                  CREATED_AT timestamp_ntz default current_timestamp(),
                  primary key (AUDIT_ID)
                )
                """
            )
        except Exception:
            pass

    def snapshot_classification_audit(self, table_name: str, sample_size: int = 200) -> Dict[str, Any]:
        """Run detection and persist per-column outcomes into DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_AUDIT.

        Writes: table_name, column_name, data_type, sensitive_type, CIA, scan_timestamp, confidence.
        Creator/updater and feedback remain NULL for this write path (metadata snapshot handles created/updated fields).
        """
        if not (self.use_snowflake and snowflake_connector is not None):
            return {"inserted": 0, "mode": "virtual"}
        self._ensure_sensitive_audit_table()
        try:
            report = self.generate_sensitive_report(table_name, sample_size=sample_size) or {}
            cols = report.get("columns") or []
            # Derive data types map from column metadata to persist data_type
            types_map: Dict[str, str] = {}
            try:
                for cm in (self.get_column_metadata(table_name) or []):
                    cname = str(cm.get("COLUMN_NAME") or "")
                    types_map[cname] = str(cm.get("DATA_TYPE") or "")
            except Exception:
                types_map = {}
            inserted = 0
            for r in cols:
                try:
                    col = str(r.get("column_name") or r.get("column") or "")
                    if not col:
                        continue
                    cia_obj = r.get("CIA (C/I/A)") or r.get("cia") or {}
                    cia_str = None
                    try:
                        # Store as compact C/I/A string, e.g., "2/2/1"
                        c = int((cia_obj or {}).get("C", 0))
                        i = int((cia_obj or {}).get("I", 0))
                        a = int((cia_obj or {}).get("A", 0))
                        cia_str = f"{c}/{i}/{a}"
                    except Exception:
                        cia_str = None
                    schema_fqn = self._gov_schema_fqn()
                    snowflake_connector.execute_non_query(
                        f"""
                            INSERT INTO {schema_fqn}.CLASSIFICATION_DECISIONS (
                            table_name, column_name, data_type, sensitive_type, CIA,
                            created_by, created_on, updated_by, updated_on, scan_timestamp, confidence, feedback
                        ) values (
                            %(t)s, %(col)s, %(dt)s, %(stype)s, %(cia)s,
                            %(cb)s, %(con)s, %(ub)s, %(uon)s, current_timestamp(), %(conf)s, %(fb)s
                        )
                        """,
                        {
                            "t": str(table_name),
                            "col": col,
                            "dt": types_map.get(col),
                            "stype": r.get("sensitive_type") or r.get("classification_label"),
                            "cia": cia_str,
                            "cb": None,
                            "con": None,
                            "ub": None,
                            "uon": None,
                            "conf": (r.get("confidence_score") if isinstance(r.get("confidence_score"), int) else None),
                            "fb": None,
                        },
                    )
                    inserted += 1
                except Exception:
                    continue
            return {"inserted": inserted, "mode": "snowflake"}
        except Exception as e:
            return {"error": str(e)}

    def list_sensitive_tables(self) -> List[str]:
        """List tables with sensitive data, either from Snowflake audit table or from local cache."""
        if self.use_snowflake and snowflake_connector is not None:
            try:
                schema_fqn = self._gov_schema_fqn()
                rows = snowflake_connector.execute_query(
                    f"SELECT DISTINCT TABLE_NAME FROM {schema_fqn}.AI_ASSISTANT_SENSITIVE_ASSETS"
                )
                return [str(r["TABLE_NAME"]) for r in rows]
            except Exception:
                pass
        # Fallback to local cache
        return [str(t) for t in self.get_sensitive_tables()]

    def list_sensitive_columns_for_ui(self, table_name: str) -> List[str]:
        """List columns with sensitive data for a given table, either from Snowflake audit table or from local cache."""
        if self.use_snowflake and snowflake_connector is not None:
            try:
                schema_fqn = self._gov_schema_fqn()
                rows = snowflake_connector.execute_query(
                    f"SELECT DISTINCT COLUMN_NAME FROM {schema_fqn}.SENSITIVE_AUDIT WHERE TABLE_NAME = %(t)s",
                    {"t": table_name},
                )
                return [str(r["COLUMN_NAME"]) for r in rows]
            except Exception:
                pass
        # Fallback to local cache
        return [str(c) for c in self.get_sensitive_columns(table_name)]

    def persist_column_overrides(self, table_name: str, column_name: str, override: Dict[str, Any]) -> Dict[str, Any]:
        """Persist column override to Snowflake audit table if available, otherwise to local cache."""
        if self.use_snowflake and snowflake_connector is not None:
            try:
                schema_fqn = self._gov_schema_fqn()
                snowflake_connector.execute_non_query(
                    f"""
                        INSERT INTO {schema_fqn}.COLUMN_OVERRIDES (
                            TABLE_NAME, COLUMN_NAME, OVERRIDE
                        ) values (
                            %(t)s, %(col)s, %(ov)s
                        )
                    """,
                    {
                        "t": table_name,
                        "col": column_name,
                        "ov": json.dumps(override),
                    },
                )
                return {"success": True}
            except Exception as e:
                return {"error": str(e)}
        # Fallback to local cache
        self.set_column_override(table_name, column_name, override)
        return {"success": True}

    def audit_change(self, table_name: str, column_name: str, change_type: str, change_data: Dict[str, Any]) -> Dict[str, Any]:
        """Audit change to Snowflake audit table if available, otherwise to local cache."""
        if self.use_snowflake and snowflake_connector is not None:
            try:
                schema_fqn = self._gov_schema_fqn()
                snowflake_connector.execute_non_query(
                    f"""
                        INSERT INTO {schema_fqn}.AUDIT_LOG (
                            TABLE_NAME, COLUMN_NAME, CHANGE_TYPE, CHANGE_DATA
                        ) values (
                            %(t)s, %(col)s, %(ct)s, %(cd)s
                        )
                    """,
                    {
                        "t": table_name,
                        "col": column_name,
                        "ct": change_type,
                        "cd": json.dumps(change_data),
                    },
                )
                return {"success": True}
            except Exception as e:
                return {"error": str(e)}
        # Fallback to local cache
        self.log_change(table_name, column_name, change_type, change_data)
        return {"success": True}

    def classify_texts(self, texts: List[str], categories: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Classify a list of texts using AI/ML models.
        
        Args:
            texts: List of text strings to classify
            categories: Optional list of categories to classify against
            
        Returns:
            List of classification results with confidence scores
        """
        results = []
        for text in texts:
            try:
                # Simple keyword-based classification as fallback
                result = {
                    "text": text,
                    "category": "UNKNOWN",
                    "confidence": 0.0,
                    "method": "keyword_fallback"
                }
                
                # Check for common sensitive patterns
                text_lower = str(text).lower()
                if any(keyword in text_lower for keyword in ['email', 'mail']):
                    result.update({"category": "PII", "confidence": 0.8})
                elif any(keyword in text_lower for keyword in ['phone', 'tel', 'mobile']):
                    result.update({"category": "PII", "confidence": 0.8})
                elif any(keyword in text_lower for keyword in ['ssn', 'social', 'tax_id']):
                    result.update({"category": "PII", "confidence": 0.9})
                elif any(keyword in text_lower for keyword in ['credit', 'card', 'payment', 'bank']):
                    result.update({"category": "FINANCIAL", "confidence": 0.8})
                elif any(keyword in text_lower for keyword in ['password', 'token', 'key', 'secret']):
                    result.update({"category": "AUTHENTICATION", "confidence": 0.9})
                elif any(keyword in text_lower for keyword in ['address', 'street', 'city', 'zip']):
                    result.update({"category": "PII", "confidence": 0.7})
                
                results.append(result)
            except Exception as e:
                results.append({
                    "text": text,
                    "category": "ERROR",
                    "confidence": 0.0,
                    "error": str(e),
                    "method": "error"
                })
        
        return results

# Global instance
ai_classification_service = AIClassificationService()
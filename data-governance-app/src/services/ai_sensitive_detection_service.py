"""
AI-Assisted Sensitive Data Detection Service

This service provides comprehensive sensitive data detection across Snowflake by combining:
1. Metadata analysis
2. AI-enhanced keyword matching
3. Pattern-based content sampling
4. Contextual sensitivity inference
5. Table-level classification
"""
import logging
import re
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
import numpy as np
from collections import defaultdict

from src.connectors.snowflake_connector import snowflake_connector
from src.services.sensitive_detection import SensitiveDataDetector
from src.config.settings import settings

logger = logging.getLogger(__name__)

@dataclass
class DetectionResult:
    """Container for detection results for a single column."""
    database_name: str
    schema_name: str
    table_name: str
    column_name: str
    data_type: str
    confidence: float = 0.0
    sensitivity_score: float = 0.0
    sensitivity_level: str = "NONE"
    detected_categories: Set[str] = field(default_factory=set)
    detection_methods: List[str] = field(default_factory=list)
    sample_values: List[Any] = field(default_factory=list)
    ai_confidence: Optional[Dict[str, float]] = None
    keyword_matches: List[Dict] = field(default_factory=list)
    pattern_matches: List[Dict] = field(default_factory=list)
    semantic_matches: List[Dict] = field(default_factory=list)
    table_context: Dict[str, Any] = field(default_factory=dict)

class AISensitiveDetectionService:
    """
    AI-Enhanced Sensitive Data Detection Service that combines multiple detection methods:
    1. Metadata Discovery
    2. AI-Enhanced Keyword Detection
    3. Pattern-Based Detection
    4. AI Contextual Sensitivity Inference
    5. Table-Level Classification
    """
    
    def __init__(self, 
                 sample_size: int = 100,
                 min_confidence: float = 0.3,
                 use_ai: bool = True):
        """Initialize the detection service.
        
        Args:
            sample_size: Number of rows to sample for pattern matching
            min_confidence: Minimum confidence threshold (0-1) for detection
            use_ai: Whether to use AI-based classification
        """
        self.sample_size = sample_size
        self.min_confidence = min_confidence
        self.use_ai = use_ai
        
        # Initialize base detector
        self.detector = SensitiveDataDetector()
        # Lazy import to avoid circular dependency with ai_classification_service
        if use_ai:
            try:
                from src.services.ai_classification_service import ai_classification_service
                self.ai_service = ai_classification_service
            except Exception:
                self.ai_service = None
        else:
            self.ai_service = None

        # Config caches loaded from governance views
        self.weights = {"AI": 0.35, "REGEX": 0.30, "KEYWORD": 0.35}
        self.thresholds = {"FINAL_MIN_CONF": 0.7, "GRAY_ZONE_LOW": 0.5, "AI_CATEGORY_MIN": 0.6}
        self.keyword_rows: List[Dict[str, Any]] = []
        self.pattern_rows: List[Dict[str, Any]] = []
        self.categories: Set[str] = set()
        self.compliance_map: Dict[str, List[str]] = {}
        self._load_configs_safely()
        
        # Cache for table metadata to avoid repeated queries
        self._metadata_cache: Dict[str, Dict] = {}

    def _normalize_db(self, db: Optional[str]) -> str:
        """Normalize database name and prevent 'NONE' errors."""
        try:
            s = (db or "").strip()
            if not s or s.upper() in ("NONE", "NULL", "(NONE)", "UNKNOWN"):
                # Try to get from governance resolver
                try:
                    from src.services.governance_db_resolver import resolve_governance_db
                    resolved = resolve_governance_db()
                    if resolved and str(resolved).strip().upper() not in ("NONE", "NULL", "(NONE)", "UNKNOWN"):
                        return str(resolved).strip()
                except Exception:
                    pass
                
                # Try to get from Snowflake context
                try:
                    rows = snowflake_connector.execute_query("SELECT CURRENT_DATABASE() AS DB") or []
                    if rows and rows[0].get("DB"):
                        current_db = str(rows[0].get("DB")).strip()
                        if current_db.upper() not in ("NONE", "NULL", "(NONE)", "UNKNOWN"):
                            return current_db
                except Exception:
                    pass
                
                # Fallback to settings
                try:
                    settings_db = getattr(settings, "SNOWFLAKE_DATABASE", None)
                    if settings_db and str(settings_db).strip().upper() not in ("NONE", "NULL", "(NONE)", "UNKNOWN"):
                        return str(settings_db).strip()
                except Exception:
                    pass
                
                # Last resort fallback
                return "DATA_CLASSIFICATION_DB"
            return s
        except Exception:
            return "DATA_CLASSIFICATION_DB"

    def _gov_db(self) -> str:
        """Get governance database with comprehensive fallback."""
        try:
            # Try settings first
            settings_db = getattr(settings, "SNOWFLAKE_DATABASE", None)
            if settings_db:
                normalized = self._normalize_db(settings_db)
                if normalized and normalized.upper() not in ("NONE", "NULL", "(NONE)", "UNKNOWN"):
                    return normalized
        except Exception:
            pass
        
        # Fallback to normalization logic
        return self._normalize_db(None)
        
    def discover_metadata(self, database: str, 
                         schema_filter: Optional[str] = None,
                         table_filter: Optional[str] = None) -> List[Dict]:
        """Discover all tables and columns from Snowflake metadata.
        
        Args:
            database: Database name
            schema_filter: Optional schema name filter
            table_filter: Optional table name filter
            
        Returns:
            List of column metadata dictionaries
        """
        database = self._normalize_db(database)
        if not database:
            logger.warning("discover_metadata called without a valid database; skipping.")
            return []
        cache_key = f"{database}.{schema_filter or '*'}.{table_filter or '*'}"
        if cache_key in self._metadata_cache:
            return self._metadata_cache[cache_key]
            
        query = """
        SELECT 
            table_schema,
            table_name,
            column_name,
            data_type,
            comment as column_comment
        FROM {database}.information_schema.columns
        WHERE table_schema NOT IN ('INFORMATION_SCHEMA', 'SNOWFLAKE', 'DATA_CLASSIFICATION_GOVERNANCE')
        """
        
        if schema_filter:
            query += f" AND table_schema = '{schema_filter}'"
            
        if table_filter:
            query += f" AND table_name = '{table_filter}'"
            
        query += " ORDER BY table_schema, table_name, ordinal_position"
        
        try:
            results = snowflake_connector.execute_query(query.format(database=database))
            self._metadata_cache[cache_key] = results or []
            return self._metadata_cache[cache_key]
        except Exception as e:
            logger.error(f"Error discovering metadata: {e}")
            return []
    
    def detect_sensitive_columns(self, 
                               database: str,
                               schema_name: Optional[str] = None,
                               table_name: Optional[str] = None,
                               column_name: Optional[str] = None) -> List[DetectionResult]:
        """Detect sensitive columns using multi-layered analysis.
        
        Args:
            database: Database name
            schema_name: Optional schema filter
            table_name: Optional table filter
            column_name: Optional column filter
            
        Returns:
            List of DetectionResult objects
        """
        database = self._normalize_db(database)
        if not database:
            logger.warning("detect_sensitive_columns called without a valid database; skipping.")
            return []
        
        # 1. Discover metadata
        columns = self.discover_metadata(database, schema_name, table_name)
        if column_name:
            columns = [col for col in columns if col.get('column_name', '').lower() == column_name.lower()]
        
        results = []
        
        # Process columns in batches for efficiency
        for col in columns:
            try:
                result = self._analyze_column(
                    database=database,
                    schema=str(col.get('table_schema') or ""),
                    table=str(col.get('table_name') or ""),
                    column=str(col.get('column_name') or ""),
                    data_type=str(col.get('data_type') or "")
                )
                
                if result.confidence >= self.min_confidence:
                    results.append(result)
                    
            except Exception as e:
                logger.error(f"Error analyzing column {col.get('table_schema')}.{col.get('table_name')}.{col.get('column_name')}: {e}")
        
        return results
    
    def _analyze_column(self, 
                       database: str, 
                       schema: str, 
                       table: str, 
                       column: str,
                       data_type: str) -> DetectionResult:
        """Analyze a single column using all available detection methods."""
        result = DetectionResult(
            database_name=database,
            schema_name=schema,
            table_name=table,
            column_name=column,
            data_type=data_type
        )
        
        # 1. Check for keyword matches in column/table names (governance-driven)
        result.keyword_matches = self._detect_keyword_matches(column, table, schema)
        
        # 2. Sample data and check for pattern matches
        sample_values = self._sample_column_data(database, schema, table, column)
        result.sample_values = sample_values
        
        # 3. Run pattern matching on sampled data (governance-driven)
        if sample_values:
            result.pattern_matches = self._detect_pattern_matches(sample_values)
        
        # 4. AI-based classification if enabled
        if self.use_ai and self.ai_service and sample_values:
            try:
                # Convert samples to strings for AI processing
                text_samples = [str(v) for v in sample_values if v is not None]
                if text_samples:
                    # Get AI classification with context
                    context = {
                        'column_name': column,
                        'table_name': table,
                        'schema_name': schema,
                        'data_type': data_type,
                        'sample_values': text_samples[:5]  # Limit samples for efficiency
                    }
                    
                    # Get semantic matches using embeddings
                    result.semantic_matches = self._detect_semantic_matches(column, table, text_samples)
                    
                    # Get AI classification
                    ai_result = self.ai_service.classify_texts(
                        texts=text_samples,
                        context=context
                    )
                    result.ai_confidence = ai_result
                    
                    # Add AI-detected categories
                    if 'categories' in ai_result:
                        for cat, score in ai_result['categories'].items():
                            if score >= float(self.thresholds.get('AI_CATEGORY_MIN', 0.7)):
                                result.detected_categories.add(cat.upper())
                                result.detection_methods.append(f"AI_{cat.upper()}")
            
            except Exception as e:
                logger.error(f"AI classification failed for {schema}.{table}.{column}: {e}")
        
        # 5. Calculate final confidence and sensitivity (weights/thresholds from governance)
        self._calculate_final_scores(result)

        return result
    
    def _detect_keyword_matches(self, column: str, table: str, schema: str) -> List[Dict]:
        """Detect sensitive keywords using governance table VW_SENSITIVE_KEYWORDS_CANONICAL."""
        try:
            col_l = (column or "").lower()
            tbl_l = (table or "").lower()
            sch_l = (schema or "").lower()
            out: List[Dict] = []
            seen = set()
            for r in self.keyword_rows:
                kw = (r.get("KEYWORD") or "").lower().strip()
                scope = (r.get("SCOPE") or "column_name").lower()
                if not kw or not r.get("IS_ACTIVE", True):
                    continue
                matched = False
                if scope == "column_name" and kw and kw in col_l:
                    matched = True
                elif scope == "table_name" and kw in tbl_l:
                    matched = True
                elif scope == "comment":
                    # comments not available here reliably; skip
                    matched = False
                if matched:
                    key = (r.get("KEYWORD_ID"), r.get("SENSITIVITY_TYPE"))
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append({
                        "keyword_id": r.get("KEYWORD_ID"),
                        "category_id": r.get("SENSITIVITY_TYPE"),
                        "category_name": r.get("SENSITIVITY_TYPE"),
                        "keyword": r.get("KEYWORD"),
                        "weight": int(max(0.0, min(1.0, float(r.get("SCORE") or 0.0))) * 100)
                    })
            return out
        except Exception as e:
            logger.warning(f"Keyword detection failed: {e}")
            return []
    
    def _sample_column_data(self, database: str, schema: str, table: str, column: str) -> List[Any]:
        """Sample data from a column for pattern matching."""
        if self.sample_size <= 0:
            return []
            
        query = f"""
        SELECT "{column}" as sample_value
        FROM "{database}"."{schema}"."{table}"
        SAMPLE ({self.sample_size} ROWS)
        WHERE "{column}" IS NOT NULL
        """
        
        try:
            results = snowflake_connector.execute_query(query) or []
            return [row['SAMPLE_VALUE'] for row in results if row['SAMPLE_VALUE'] is not None]
        except Exception as e:
            logger.warning(f"Error sampling data from {database}.{schema}.{table}.{column}: {e}")
            return []
    
    def _detect_pattern_matches(self, values: List[Any]) -> List[Dict]:
        """Detect sensitive patterns using governance patterns (regex)."""
        if not values:
            return []
        try:
            compiled: List[Tuple[str, str, re.Pattern]] = []
            for p in self.pattern_rows:
                # Try PATTERN_REGEX first (new schema), fall back to PATTERN_STRING (legacy)
                pat = p.get("PATTERN_REGEX") or p.get("PATTERN_STRING")
                if not pat or not p.get("IS_ACTIVE", True):
                    continue
                try:
                    compiled.append((p.get("PATTERN_ID"), p.get("SENSITIVITY_TYPE") or p.get("CATEGORY_ID"), re.compile(pat)))
                except Exception:
                    continue
            matches: List[Dict] = []
            seen = set()
            for v in values:
                s = str(v)
                for (pid, cat, rx) in compiled:
                    if rx.search(s):
                        key = (pid, cat)
                        if key in seen:
                            continue
                        seen.add(key)
                        weight_cfg = None
                        try:
                            for pr in self.pattern_rows:
                                if pr.get("PATTERN_ID") == pid:
                                    weight_cfg = pr.get("SCORE") or pr.get("WEIGHT")
                                    break
                        except Exception:
                            weight_cfg = None
                        w = float(weight_cfg) if weight_cfg is not None else 0.75
                        w = max(0.0, min(1.0, w))
                        matches.append({
                            "pattern_id": pid,
                            "category_id": cat,
                            "category_name": cat,
                            "weight": int(w * 100)
                        })
            return matches
        except Exception as e:
            logger.warning(f"Pattern detection failed: {e}")
            return []
    
    def _detect_semantic_matches(self, column: str, table: str, samples: List[str]) -> List[Dict]:
        """Use embeddings to find semantic matches for sensitive data."""
        if not self.ai_service or not hasattr(self.ai_service, 'get_semantic_matches'):
            return []
            
        try:
            # Get semantic matches for column name and table name
            context = f"{table}.{column}"
            # Pass valid category list (or None) instead of sample strings
            categories = list(self.categories) if getattr(self, 'categories', None) else None
            return self.ai_service.get_semantic_matches(context, categories)
        except Exception as e:
            logger.warning(f"Semantic matching failed: {e}")
            return []
    
    def _calculate_final_scores(self, result: DetectionResult) -> None:
        """Calculate final confidence and sensitivity scores using governance weights/thresholds."""
        kw = max((m.get('weight', 0) / 100.0 for m in result.keyword_matches), default=0.0)
        rx = max((m.get('weight', 0) / 100.0 for m in result.pattern_matches), default=0.0)
        ai = 0.0
        if result.ai_confidence and isinstance(result.ai_confidence, dict):
            ai = float(result.ai_confidence.get('overall_confidence') or 0.0)
        # Weighted combination
        w_kw = float(self.weights.get("KEYWORD", 0.2))
        w_rx = float(self.weights.get("REGEX", 0.3))
        w_ai = float(self.weights.get("AI", 0.5))
        combined = (kw * w_kw) + (rx * w_rx) + (ai * w_ai)
        combined = max(0.0, min(1.0, combined))
        result.confidence = combined
        result.sensitivity_score = combined * 100.0
        # Levels from thresholds
        final_min = float(self.thresholds.get("FINAL_MIN_CONF", 0.7))
        gray_low = float(self.thresholds.get("GRAY_ZONE_LOW", 0.55))
        if combined >= final_min:
            result.sensitivity_level = "MEDIUM"
            result.detection_methods.append("FINAL_THRESHOLD")
            if combined >= max(0.9, final_min + 0.15):
                result.sensitivity_level = "HIGH"
        elif combined >= gray_low:
            result.sensitivity_level = "LOW"
        else:
            result.sensitivity_level = "NONE"
        # Categories from matches
        for match in result.keyword_matches + result.pattern_matches + result.semantic_matches:
            if 'category_name' in match and match['category_name']:
                result.detected_categories.add(str(match['category_name']).upper())

    # --- Persistence ---
    def _persist_results(self, run_id: str, rows: List[DetectionResult]) -> None:
        """Persist results to AI_ASSISTANT_SENSITIVE_ASSETS (idempotent per table per run)."""
        try:
            db = self._gov_db()
            if not db:
                logger.warning("_persist_results called without a valid database; skipping.")
                return
            gv = "DATA_CLASSIFICATION_GOVERNANCE"
            fqn = f"{db}.{gv}.AI_ASSISTANT_SENSITIVE_ASSETS"
            fqn_hist = f"{db}.{gv}.AI_ASSISTANT_SENSITIVE_ASSETS_HISTORY"
            # Ensure schema and tables exist
            try:
                snowflake_connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {db}.{gv}")
            except Exception:
                pass
            try:
                snowflake_connector.execute_non_query(
                    f"""
                    CREATE TABLE IF NOT EXISTS {fqn} (
                        RUN_ID STRING,
                        DATABASE_NAME STRING,
                        SCHEMA_NAME STRING,
                        TABLE_NAME STRING,
                        COLUMN_NAME STRING,
                        DETECTED_CATEGORY STRING,
                        DETECTED_TYPE STRING,
                        COMBINED_CONFIDENCE FLOAT,
                        METHODS_USED VARIANT,
                        COMPLIANCE_TAGS VARIANT,
                        SAMPLE_METADATA VARIANT,
                        DETECTION_REASON STRING,
                        CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            except Exception:
                pass
            try:
                snowflake_connector.execute_non_query(
                    f"""
                    CREATE TABLE IF NOT EXISTS {fqn_hist} LIKE {fqn}
                    """
                )
            except Exception:
                pass
            # Group by table
            by_tbl: Dict[Tuple[str,str,str], List[DetectionResult]] = {}
            for r in rows:
                key = (r.database_name, r.schema_name, r.table_name)
                by_tbl.setdefault(key, []).append(r)
            for (d, s, t), cols in by_tbl.items():
                # Optional: clean existing rows for this table/run
                try:
                    snowflake_connector.execute_non_query(
                        f"DELETE FROM {fqn} WHERE DATABASE_NAME = %(d)s AND SCHEMA_NAME = %(s)s AND TABLE_NAME = %(t)s AND RUN_ID = %(r)s",
                        {"d": d, "s": s, "t": t, "r": run_id},
                    )
                except Exception:
                    pass
                for c in cols:
                    try:
                        methods_used = c.detection_methods or []
                        comp_tags = []
                        try:
                            cats_u = [str(x).upper() for x in (c.detected_categories or [])]
                            tags_set = set()
                            for cu in cats_u:
                                for tg in self.compliance_map.get(cu, []):
                                    tags_set.add(str(tg))
                            comp_tags = sorted(list(tags_set))
                        except Exception:
                            comp_tags = []
                        snowflake_connector.execute_non_query(
                            f"""
                            INSERT INTO {fqn}
                              (RUN_ID, DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, COLUMN_NAME,
                               DETECTED_CATEGORY, DETECTED_TYPE, COMBINED_CONFIDENCE,
                               METHODS_USED, COMPLIANCE_TAGS, SAMPLE_METADATA, DETECTION_REASON)
                            SELECT %(run)s, %(db)s, %(sc)s, %(tb)s, %(col)s,
                                   %(cat)s, %(typ)s, %(conf)s,
                                   PARSE_JSON(%(methods)s), PARSE_JSON(%(tags)s), NULL, NULL
                            """,
                            {
                                "run": run_id,
                                "db": d,
                                "sc": s,
                                "tb": t,
                                "col": c.column_name,
                                "cat": (next(iter(c.detected_categories)) if c.detected_categories else None),
                                "typ": (next(iter(c.detected_categories)) if c.detected_categories else None),
                                "conf": float(c.confidence),
                                "methods": __import__("json").dumps(methods_used),
                                "tags": __import__("json").dumps(comp_tags),
                            },
                        )
                        try:
                            snowflake_connector.execute_non_query(
                                f"""
                                INSERT INTO {fqn_hist}
                                  (RUN_ID, DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, COLUMN_NAME,
                                   DETECTED_CATEGORY, DETECTED_TYPE, COMBINED_CONFIDENCE,
                                   METHODS_USED, COMPLIANCE_TAGS)
                                SELECT %(run)s, %(db)s, %(sc)s, %(tb)s, %(col)s,
                                       %(cat)s, %(typ)s, %(conf)s,
                                       PARSE_JSON(%(methods)s), PARSE_JSON(%(tags)s)
                                """,
                                {
                                    "run": run_id,
                                    "db": d,
                                    "sc": s,
                                    "tb": t,
                                    "col": c.column_name,
                                    "cat": (next(iter(c.detected_categories)) if c.detected_categories else None),
                                    "typ": (next(iter(c.detected_categories)) if c.detected_categories else None),
                                    "conf": float(c.confidence),
                                    "methods": __import__("json").dumps(methods_used),
                                    "tags": __import__("json").dumps(comp_tags),
                                },
                            )
                        except Exception as he:
                            logger.warning(f"Persist history failed for {d}.{s}.{t}.{c.column_name}: {he}")
                    except Exception as ie:
                        logger.warning(f"Persist row failed for {d}.{s}.{t}.{c.column_name}: {ie}")
        except Exception as e:
            logger.warning(f"Persist results failed: {e}")

    def run_scan_and_persist(self, database: str, schema_name: Optional[str] = None, table_name: Optional[str] = None) -> Dict[str, Any]:
        """Public orchestration: detect sensitive columns and persist.
        Returns a summary with counts.
        """
        try:
            run_id = datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
            cols = self.detect_sensitive_columns(database, schema_name, table_name)
            if cols:
                self._persist_results(run_id, cols)
            summary = {
                "run_id": run_id,
                "database": database,
                "schema": schema_name,
                "table": table_name,
                "columns_detected": len(cols or []),
            }
            return summary
        except Exception as e:
            logger.error(f"run_scan_and_persist failed: {e}")
            return {"error": str(e)}

    # --- Config loading ---
    def _load_configs_safely(self) -> None:
        """Load governance configs; tolerate missing objects/privileges."""
        db = self._gov_db()
        gv = "DATA_CLASSIFICATION_GOVERNANCE"
        gv_fqn = f"{db}.{gv}"
        # Weights
        try:
            rows = snowflake_connector.execute_query(
                f"SELECT SOURCE, WEIGHT, IS_ACTIVE FROM {gv_fqn}.VW_SENSITIVITY_WEIGHTS_CANONICAL"
            ) or []
            w = { (r.get("SOURCE") or "").upper(): float(r.get("WEIGHT") or 0) for r in rows if r.get("IS_ACTIVE", True) }
            for k, v in w.items():
                if k:
                    self.weights[k] = v
        except Exception as e:
            logger.warning(f"Weights load failed: {e}")
        # Thresholds
        try:
            thr = snowflake_connector.execute_query(
                f"SELECT NAME, VALUE, IS_ACTIVE FROM {gv_fqn}.VW_SENSITIVITY_THRESHOLDS_CANONICAL"
            ) or []
            for r in thr:
                if r.get("IS_ACTIVE", True) and r.get("NAME"):
                    self.thresholds[str(r["NAME"]).upper()] = float(r.get("VALUE", 0))
        except Exception as e:
            logger.warning(f"Thresholds load failed: {e}")
        # Keywords
        try:
            self.keyword_rows = snowflake_connector.execute_query(
                f"SELECT * FROM {gv_fqn}.VW_SENSITIVE_KEYWORDS_CANONICAL WHERE IS_ACTIVE"
            ) or []
        except Exception as e:
            logger.warning(f"Keywords load failed: {e}")
            self.keyword_rows = []
        if not self.keyword_rows:
            # Fallback strong signals
            self.keyword_rows = [
                {"KEYWORD_ID": 1, "KEYWORD": "SSN", "SENSITIVITY_TYPE": "PII", "SCORE": 0.9, "IS_ACTIVE": True},
                {"KEYWORD_ID": 2, "KEYWORD": "SOCIAL SECURITY", "SENSITIVITY_TYPE": "PII", "SCORE": 0.9, "IS_ACTIVE": True},
                {"KEYWORD_ID": 3, "KEYWORD": "CUSTOMER CONTACT", "SENSITIVITY_TYPE": "PII", "SCORE": 0.8, "IS_ACTIVE": True},
                {"KEYWORD_ID": 4, "KEYWORD": "EMAIL", "SENSITIVITY_TYPE": "PII", "SCORE": 0.75, "IS_ACTIVE": True},
                {"KEYWORD_ID": 5, "KEYWORD": "PHONE", "SENSITIVITY_TYPE": "PII", "SCORE": 0.75, "IS_ACTIVE": True},
                {"KEYWORD_ID": 6, "KEYWORD": "ACCOUNT NUMBER", "SENSITIVITY_TYPE": "FINANCIAL", "SCORE": 0.85, "IS_ACTIVE": True},
                {"KEYWORD_ID": 7, "KEYWORD": "INVOICE", "SENSITIVITY_TYPE": "FINANCIAL", "SCORE": 0.8, "IS_ACTIVE": True},
                {"KEYWORD_ID": 8, "KEYWORD": "GDPR", "SENSITIVITY_TYPE": "REGULATORY", "SCORE": 0.85, "IS_ACTIVE": True},
                {"KEYWORD_ID": 9, "KEYWORD": "HIPAA", "SENSITIVITY_TYPE": "REGULATORY", "SCORE": 0.9, "IS_ACTIVE": True},
                {"KEYWORD_ID": 10, "KEYWORD": "PCI DSS", "SENSITIVITY_TYPE": "REGULATORY", "SCORE": 0.9, "IS_ACTIVE": True},
            ]
        # Patterns
        try:
            self.pattern_rows = snowflake_connector.execute_query(
                f"SELECT * FROM {gv_fqn}.VW_SENSITIVE_PATTERNS_CANONICAL WHERE IS_ACTIVE"
            ) or []
        except Exception as e:
            logger.warning(f"Patterns load failed: {e}")
            self.pattern_rows = []
        if not self.pattern_rows:
            # Fallback regex patterns
            self.pattern_rows = [
                {"PATTERN_ID": "PII_SSN", "PATTERN_REGEX": r"\\b(\d{3}-\d{2}-\d{4})\\b", "SENSITIVITY_TYPE": "PII", "SCORE": 0.9, "IS_ACTIVE": True},
                {"PATTERN_ID": "PII_EMAIL", "PATTERN_REGEX": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", "SENSITIVITY_TYPE": "PII", "SCORE": 0.8, "IS_ACTIVE": True},
                {"PATTERN_ID": "FIN_ACCOUNT", "PATTERN_REGEX": r"ACCOUNT\s*NUMBER|IBAN|SWIFT", "SENSITIVITY_TYPE": "FINANCIAL", "SCORE": 0.8, "IS_ACTIVE": True},
                {"PATTERN_ID": "REG_GDPR", "PATTERN_REGEX": r"GDPR|HIPAA|PCI\s*DSS", "SENSITIVITY_TYPE": "REGULATORY", "SCORE": 0.85, "IS_ACTIVE": True},
            ]
        # Categories and high-risk list
        try:
            cats = snowflake_connector.execute_query(
                f"SELECT CATEGORY_NAME, IS_HIGH_RISK FROM {gv_fqn}.VW_SENSITIVITY_CATEGORIES_CANONICAL WHERE IS_ACTIVE"
            ) or []
            self.categories = set([(r.get("CATEGORY_NAME") or "").upper() for r in cats if r.get("CATEGORY_NAME")])
            high_flags = { (r.get("CATEGORY_NAME") or "").upper(): bool(r.get("IS_HIGH_RISK")) for r in cats if r.get("CATEGORY_NAME") }
            self.thresholds.setdefault("HIGH_RISK_CATEGORIES", [k for k, v in high_flags.items() if v])
        except Exception as e:
            logger.warning(f"Categories load failed: {e}")
            self.categories = self.categories or set()
        # Compliance mapping
        try:
            cmap = snowflake_connector.execute_query(
                f"SELECT CATEGORY_NAME, COMPLIANCE_TAG FROM {gv_fqn}.VW_COMPLIANCE_MAPPING_CANONICAL WHERE IS_ACTIVE"
            ) or []
            m: Dict[str, List[str]] = {}
            for r in cmap:
                cat = (r.get("CATEGORY_NAME") or "").upper()
                tag = r.get("COMPLIANCE_TAG")
                if not cat or not tag:
                    continue
                m.setdefault(cat, []).append(str(tag))
            self.compliance_map = m
        except Exception as e:
            logger.warning(f"Compliance mapping load failed: {e}")
            self.compliance_map = {}

    def detect_sensitive_tables(self,
                              database: str,
                              schema_name: Optional[str] = None,
                              table_name: Optional[str] = None) -> List[Dict]:
        """Detect sensitive tables based on column analysis.
        
        A table is considered sensitive if it contains multiple sensitive columns
        or columns that together indicate sensitive information.
        """
        # First, detect sensitive columns
        column_results = self.detect_sensitive_columns(database, schema_name, table_name)
        
        # Group by table
        table_results = {}
        
        for col_result in column_results:
            table_key = f"{col_result.schema_name}.{col_result.table_name}"
            
            if table_key not in table_results:
                table_results[table_key] = {
                    'database': database,
                    'schema': col_result.schema_name,
                    'table': col_result.table_name,
                    'sensitive_columns': [],
                    'sensitivity_score': 0,
                    'sensitivity_level': 'NONE',
                    'categories': set(),
                    'detection_methods': set(),
                    'last_scanned': datetime.utcnow().isoformat()
                }
            
            # Add column info
            table_results[table_key]['sensitive_columns'].append({
                'column_name': col_result.column_name,
                'data_type': col_result.data_type,
                'sensitivity_score': col_result.sensitivity_score,
                'sensitivity_level': col_result.sensitivity_level,
                'confidence': col_result.confidence,
                'detected_categories': list(col_result.detected_categories),
                'detection_methods': col_result.detection_methods
            })
            
            # Track categories and detection methods
            table_results[table_key]['categories'].update(col_result.detected_categories)
            table_results[table_key]['detection_methods'].update(col_result.detection_methods)
            
            # Update max score
            table_results[table_key]['sensitivity_score'] = max(
                table_results[table_key]['sensitivity_score'],
                col_result.sensitivity_score
            )
        
        # Calculate table-level sensitivity
        final_results = []
        
        for table_key, table_info in table_results.items():
            sensitive_cols = [c for c in table_info['sensitive_columns'] 
                             if c['sensitivity_level'] in ['MEDIUM', 'HIGH']]
            
            total_cols = len(table_info['sensitive_columns'])
            sensitive_ratio = len(sensitive_cols) / total_cols if total_cols > 0 else 0
            
            high_risk_categories = set([str(x).upper() for x in self.thresholds.get("HIGH_RISK_CATEGORIES", [])])
            category_overlap = high_risk_categories.intersection(set(table_info['categories']))

            ratio_high = float(self.thresholds.get("TABLE_SENSITIVE_RATIO_HIGH", 0.4))
            ratio_med = float(self.thresholds.get("TABLE_SENSITIVE_RATIO_MED", 0.2))
            cat_high = int(self.thresholds.get("CATEGORY_OVERLAP_HIGH", 2))
            cat_med = int(self.thresholds.get("CATEGORY_OVERLAP_MED", 1))

            if (sensitive_ratio >= ratio_high or len(category_overlap) >= cat_high):
                table_info['sensitivity_level'] = 'HIGH'
                table_info['sensitivity_score'] = max(90, table_info['sensitivity_score'])
            elif (sensitive_ratio >= ratio_med or len(category_overlap) >= cat_med):
                table_info['sensitivity_level'] = 'MEDIUM'
                table_info['sensitivity_score'] = max(70, table_info['sensitivity_score'])
            else:
                table_info['sensitivity_level'] = 'LOW'
            
            # Convert sets to lists for JSON serialization
            table_info['categories'] = list(table_info['categories'])
            table_info['detection_methods'] = list(table_info['detection_methods'])
            
            final_results.append(table_info)
        
        return final_results
    
    def ensure_governance_tables(self) -> None:
        """Ensure governance tables exist with proper schema (idempotent)."""
        try:
            db = self._gov_db()
            gv = "DATA_CLASSIFICATION_GOVERNANCE"
            
            # Create schema
            try:
                snowflake_connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {db}.{gv}")
            except Exception as e:
                logger.warning(f"Schema creation skipped: {e}")
            
            # Create AI_ASSISTANT_SENSITIVE_ASSETS table
            try:
                snowflake_connector.execute_non_query(
                    f"""
                    CREATE TABLE IF NOT EXISTS {db}.{gv}.AI_ASSISTANT_SENSITIVE_ASSETS (
                        RUN_ID STRING,
                        DATABASE_NAME STRING,
                        SCHEMA_NAME STRING,
                        TABLE_NAME STRING,
                        COLUMN_NAME STRING,
                        DETECTED_CATEGORY STRING,
                        DETECTED_TYPE STRING,
                        COMBINED_CONFIDENCE FLOAT,
                        METHODS_USED VARIANT,
                        COMPLIANCE_TAGS VARIANT,
                        SAMPLE_METADATA VARIANT,
                        DETECTION_REASON STRING,
                        LAST_SCAN_TS TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
                        CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
                    )
                    """
                )
            except Exception as e:
                logger.warning(f"Table creation skipped: {e}")
            
            # Add columns if they don't exist (handle "already exists" errors gracefully)
            try:
                snowflake_connector.execute_non_query(
                    f"ALTER TABLE {db}.{gv}.AI_ASSISTANT_SENSITIVE_ASSETS ADD COLUMN IF NOT EXISTS PREV_SHA256_HEX STRING"
                )
            except Exception as e:
                if "already exists" not in str(e).lower():
                    logger.warning(f"Column PREV_SHA256_HEX add failed: {e}")
            
            try:
                snowflake_connector.execute_non_query(
                    f"ALTER TABLE {db}.{gv}.AI_ASSISTANT_SENSITIVE_ASSETS ADD COLUMN IF NOT EXISTS CHAIN_SHA256_HEX STRING"
                )
            except Exception as e:
                if "already exists" not in str(e).lower():
                    logger.warning(f"Column CHAIN_SHA256_HEX add failed: {e}")
            
            logger.info("Governance tables verified/created successfully")
            
        except Exception as e:
            logger.warning(f"Governance table setup failed: {e}")

# Singleton instance
ai_sensitive_detection_service = AISensitiveDetectionService()

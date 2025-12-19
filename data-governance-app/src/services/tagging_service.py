"""
Snowflake Tagging Service
- Ensures standardized tag schema exists (DATA_CLASSIFICATION, CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, AVAILABILITY_LEVEL)
- Validates allowed values and applies tags to Snowflake objects (TABLE/VIEW/COLUMN)
- Retrieves tags for objects
- Adds lifecycle review tags (LAST_CLASSIFIED_DATE, LAST_REVIEW_DATE, REVIEW_STATUS) and auto-populates
  LAST_CLASSIFIED_DATE/REVIEW_STATUS when classification/CIA tags are applied.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple
import logging
from datetime import date
import re

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)


def _load_allowed_values(connector, value_type: str) -> List[str]:
    """Load allowed values for a specific tag type from the database"""
    defaults = {
        "CLASSIFICATION": ["Public", "Internal", "Restricted", "Confidential"],
        "CIA_LEVEL": ["0", "1", "2", "3"],
        "CONFIDENTIALITY_LEVEL": ["C0", "C1", "C2", "C3"],
        "INTEGRITY_LEVEL": ["I0", "I1", "I2", "I3"],
        "AVAILABILITY_LEVEL": ["A0", "A1", "A2", "A3"],
        "SPECIAL_CATEGORY": ["PII", "PHI", "PCI", "SOX", "Financial", "Auth", "Confidential", "Other"],
        "COMPLIANCE_FRAMEWORKS": ["PII", "SOX", "SOC2", "GDPR", "CCPA", "HIPAA", "PCI DSS", "Internal/Other"],
        "REVIEW_STATUS": ["Pending Reclassification", "Due Soon", "Overdue", "Reviewed"]
    }
    
    # Resolve active DB from settings; bail out early if invalid to avoid noisy errors
    active_db = getattr(settings, "SNOWFLAKE_DATABASE", None)
    if not active_db or str(active_db).strip().upper() in {"", "NONE", "(NONE)", "NULL", "UNKNOWN"}:
        return defaults.get(value_type, [])
    try:
        fqn = f"{active_db}.DATA_CLASSIFICATION_GOVERNANCE.TAG_ALLOWED_VALUES"
        rows = connector.execute_query(
            f"""
            SELECT VALUE
            FROM {fqn}
            WHERE TAG_TYPE = %(type)s
            ORDER BY DISPLAY_ORDER, VALUE
            """,
            {"type": value_type}
        ) or []
        
        # Consistent fallback to defaults if result is empty
        if not rows:
             return defaults.get(value_type, [])
             
        return [str(r.get("VALUE")) for r in rows]
    except Exception as e:
        print(f"Warning: Could not load allowed values for {value_type}: {str(e)}")
        return defaults.get(value_type, [])

from src.services.governance_db_resolver import resolve_governance_db

# Default fallback values
DEFAULT_TAG_DB = "DATA_CLASSIFICATION_DB"
DEFAULT_TAG_SCHEMA = "DATA_GOVERNANCE"

def get_tag_definitions() -> Dict[str, Any]:
    """Load all tag definitions from the database with fallback to defaults."""
    return {
        # Classification and CIA levels
        "DATA_CLASSIFICATION": _load_allowed_values(snowflake_connector, "CLASSIFICATION"),
        "CONFIDENTIALITY_LEVEL": _load_allowed_values(snowflake_connector, "CONFIDENTIALITY_LEVEL"),
        "INTEGRITY_LEVEL": _load_allowed_values(snowflake_connector, "INTEGRITY_LEVEL"),
        "AVAILABILITY_LEVEL": _load_allowed_values(snowflake_connector, "AVAILABILITY_LEVEL"),
        
        # Data categories and compliance
        "SPECIAL_CATEGORY": _load_allowed_values(snowflake_connector, "SPECIAL_CATEGORY"),
        "COMPLIANCE_FRAMEWORKS": _load_allowed_values(snowflake_connector, "COMPLIANCE_FRAMEWORKS"),
        
        # Lifecycle & Review tags
        "LAST_CLASSIFIED_DATE": "__DATE__",
        "LAST_REVIEW_DATE": "__DATE__",
        "REVIEW_STATUS": _load_allowed_values(snowflake_connector, "REVIEW_STATUS"),
        
        # Explicit enforcement override for masking (TRUE/FALSE)
        "MASKING_OVERRIDE": ["TRUE", "FALSE"],
        
        # Additional metadata tags
        "DATA_OWNER": "__TEXT__",
        "DATA_STEWARD": "__TEXT__",
        "RETENTION_DAYS": "__NUMBER__",
    }

# Initialize tag definitions
TAG_DEFINITIONS = get_tag_definitions()
TAG_DEFINITIONS.update({
    "MASKING_EXEMPT": ["TRUE", "FALSE"]
})
# Public constant for allowed classification labels (kept for backward-compatibility)
# Used by pages (e.g., Administration) and within this module.
ALLOWED_CLASSIFICATIONS = TAG_DEFINITIONS.get(
    "DATA_CLASSIFICATION",
    ["Public", "Internal", "Restricted", "Confidential"],
)


class TaggingService:
    def __init__(self):
        self.connector = snowflake_connector

    @property
    def tag_db(self) -> str:
        """Resolve the database where tags are stored."""
        try:
            # Dynamically resolve governance DB (handles UI filters/session state)
            config_db = resolve_governance_db()
            if config_db and str(config_db).upper() not in ('NONE', 'NULL', '', 'UNKNOWN'):
                return config_db
            
            # Fallback to settings
            setting_db = getattr(settings, "SNOWFLAKE_DATABASE", None)
            if setting_db and str(setting_db).upper() not in ('NONE', 'NULL', '', 'UNKNOWN'):
                return setting_db
        except Exception:
            pass
        return DEFAULT_TAG_DB

    @property
    def tag_schema(self) -> str:
        """Resolve the schema where tags are stored."""
        # Could be dynamic, but defaulting to fixed schema for now
        return DEFAULT_TAG_SCHEMA

    # --- Identifier helpers ---
    def _split_fqn(self, fq: str) -> Tuple[str, str, str]:
        s = str(fq or "")
        if not s:
            raise ValueError("Empty FQN")
        parts: List[str] = []
        buf: List[str] = []
        in_q = False
        for ch in s:
            if in_q:
                if ch == '"':
                    in_q = False
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
            parts = s.split('.')
            if len(parts) != 3:
                raise ValueError(f"Expected DB.SCHEMA.OBJECT, got: {fq}")
        return parts[0], parts[1], parts[2]

    def _q(self, ident: str) -> str:
        ident = str(ident)
        return '"' + ident.replace('"', '""') + '"'

    def _load_sensitivity_patterns(self) -> Dict[str, Dict]:
        """Load sensitivity patterns and categories from database"""
        try:
            active_db = self.tag_db
        except Exception:
            active_db = None
            
        if not active_db or str(active_db).strip().upper() in {"", "NONE", "(NONE)", "NULL", "UNKNOWN", "DATA_CLASSIFICATION_DB"}:  
             # Check if we have a valid default via resolve_governance_db even if tag_db fallback logic returned default
             pass 

        if not active_db or str(active_db).strip().upper() in {"", "NONE", "(NONE)", "NULL", "UNKNOWN"}:
            # No valid DB context; return defaults to avoid noisy errors
            return {
                'patterns': {
                    'PII_STRICT': {
                        'sensitivity_level': 3,
                        'is_strict': True,
                        'keywords': ["SSN", "NATIONAL_ID", "PASSPORT", "PAN", "AADHAAR"]
                    },
                    'PII': {
                        'sensitivity_level': 2,
                        'is_strict': False,
                        'keywords': ["SSN", "EMAIL", "PHONE", "ADDRESS", "DOB", "PII", "PERSON", "EMPLOYEE", "CUSTOMER"]
                    },
                    'FINANCIAL': {
                        'sensitivity_level': 2,
                        'is_strict': False,
                        'keywords': ["GL", "LEDGER", "REVENUE", "EXPENSE", "PAYROLL"]
                    },
                    'SOX': {
                        'sensitivity_level': 3,
                        'is_strict': True,
                        'keywords': ["SOX", "FINANCIAL_REPORT", "AUDIT", "IFRS", "GAAP"]
                    }
                },
                'levels': {
                    1: {'name': 'INTERNAL', 'display': 'Internal'},
                    2: {'name': 'RESTRICTED', 'display': 'Restricted'},
                    3: {'name': 'CONFIDENTIAL', 'display': 'Confidential'}
                }
            }
        try:
            # Load patterns from database (use active DB prefix)
            patterns: Dict[str, Dict] = {}
            fqn_patterns = f"{active_db}.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS"
            rows = self.connector.execute_query(
                f"""
                SELECT 
                    CATEGORY,
                    PATTERN,
                    SENSITIVITY_LEVEL,
                    IS_STRICT,
                    COALESCE(PRIORITY, 0) AS PRIORITY
                FROM {fqn_patterns}
                WHERE COALESCE(IS_ACTIVE, TRUE) = TRUE
                ORDER BY PRIORITY DESC
                """
            ) or []
            for row in rows:
                try:
                    category = str(row.get('CATEGORY'))
                    if not category:
                        continue
                    if category not in patterns:
                        patterns[category] = {
                            'sensitivity_level': int(row.get('SENSITIVITY_LEVEL', 1) or 1),
                            'is_strict': bool(row.get('IS_STRICT', False)),
                            'keywords': []
                        }
                    patterns[category]['keywords'].append(str(row.get('PATTERN') or '').upper())
                except Exception:
                    continue
            # Load sensitivity levels (optional table)
            levels = {}
            try:
                fqn_levels = f"{active_db}.DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_LEVELS"
                lvl_rows = self.connector.execute_query(
                    f"""
                    SELECT LEVEL_NAME, LEVEL_VALUE, DISPLAY_NAME
                    FROM {fqn_levels}
                    ORDER BY LEVEL_VALUE
                    """
                ) or []
                for row in lvl_rows:
                    try:
                        levels[int(row.get('LEVEL_VALUE') or 0)] = {
                            'name': str(row.get('LEVEL_NAME') or ''),
                            'display': str(row.get('DISPLAY_NAME') or '')
                        }
                    except Exception:
                        continue
            except Exception:
                # If SENSITIVITY_LEVELS missing, provide defaults
                levels = {
                    1: {'name': 'INTERNAL', 'display': 'Internal'},
                    2: {'name': 'RESTRICTED', 'display': 'Restricted'},
                    3: {'name': 'CONFIDENTIAL', 'display': 'Confidential'}
                }
            return {'patterns': patterns, 'levels': levels}
        except Exception as e:
            print(f"Warning: Failed to load sensitivity patterns: {str(e)}")
            # Fallback to default patterns
            return {
                'patterns': {
                    'PII_STRICT': {
                        'sensitivity_level': 3,
                        'is_strict': True,
                        'keywords': ["SSN", "NATIONAL_ID", "PASSPORT", "PAN", "AADHAAR"]
                    },
                    'PII': {
                        'sensitivity_level': 2,
                        'is_strict': False,
                        'keywords': ["SSN", "EMAIL", "PHONE", "ADDRESS", "DOB", "PII", "PERSON", "EMPLOYEE", "CUSTOMER"]
                    },
                    'FINANCIAL': {
                        'sensitivity_level': 2,
                        'is_strict': False,
                        'keywords': ["GL", "LEDGER", "REVENUE", "EXPENSE", "PAYROLL"]
                    },
                    'SOX': {
                        'sensitivity_level': 3,
                        'is_strict': True,
                        'keywords': ["SOX", "FINANCIAL_REPORT", "AUDIT", "IFRS", "GAAP"]
                    }
                },
                'levels': {
                    1: {'name': 'INTERNAL', 'display': 'Internal'},
                    2: {'name': 'RESTRICTED', 'display': 'Restricted'},
                    3: {'name': 'CONFIDENTIAL', 'display': 'Confidential'}
                }
            }
    
    # --- Policy 5.5 enforcement helper ---
    def _required_minimums(self, asset_full_name: str) -> Tuple[int, str]:
        """Return (min_confidentiality_level, min_label) based on asset name heuristics.
        Heuristics mirror UI logic and Policy 5.5 for PII/Financial/SOX.
        """
        up = (asset_full_name or "").upper()
        min_c = 1
        min_label = "Internal"
        
        # Load patterns from database
        patterns = self._load_sensitivity_patterns()
        
        # Check each pattern category
        for category, config in patterns['patterns'].items():
            keywords = config.get('keywords', [])
            level = config.get('sensitivity_level', 1)
            is_strict = config.get('is_strict', False)
            
            # Check if any keyword matches
            if any(k in up for k in keywords):
                min_c = max(min_c, level)
                if is_strict:
                    min_c = max(min_c, 3)  # Strict patterns always get highest level
                
                # Update label if needed
                if min_c > 1:
                    min_label = patterns['levels'].get(min_c, {}).get('display', 'Restricted')
        
        return min_c, min_label

    def _enforce_policy_minimums(self, asset_full_name: str, tags: Dict[str, str]) -> None:
        """Raise ValueError if proposed tags violate Policy 5.5 minimums based on heuristics.
        Applies to both object and column tagging.
        """
        try:
            proposed_cls = (tags.get("DATA_CLASSIFICATION") or "Internal").title()
            c_val = int(tags.get("CONFIDENTIALITY_LEVEL") or 1)
        except Exception:
            # If parse fails, let validate_tags() handle
            return
        req_c, req_label = self._required_minimums(asset_full_name)
        # Regulatory-driven overrides: enforce stronger minimums when special/compliance categories indicate PCI/PHI/HIPAA
        try:
            special = (tags.get("SPECIAL_CATEGORY") or "").strip()
            compliance = (tags.get("COMPLIANCE_FRAMEWORKS") or "").strip()
            # Normalize to set for easy checks (COMPLIANCE_FRAMEWORKS may be CSV)
            special_set = {s.strip() for s in special.split(',') if s.strip()}
            compliance_set = {c.strip() for c in compliance.split(',') if c.strip()}
        except Exception:
            special_set, compliance_set = set(), set()
        # If PCI/PHI explicitly present, or HIPAA/PCI DSS compliance present, require C>=3 Confidential
        if ({"PCI", "PHI"} & special_set) or ({"HIPAA", "PCI DSS"} & compliance_set):
            req_c = max(req_c, 3)
            req_label = "Confidential"
        if c_val < req_c or ALLOWED_CLASSIFICATIONS.index(proposed_cls) < ALLOWED_CLASSIFICATIONS.index(req_label):
            raise ValueError(
                f"Proposed classification below policy minimums for {asset_full_name}. "
                f"Requires at least {req_label} (C≥{req_c}) per Policy 5.5."
            )

    def initialize_tagging(self) -> None:
        """Create schema and tag objects if missing."""
        # Create schema for governance artifacts (idempotent)
        current_db = self.tag_db
        current_schema = self.tag_schema
        
        try:
            self.connector.execute_non_query(
                f"CREATE SCHEMA IF NOT EXISTS {current_db}.{current_schema}"
            )
        except Exception as e:
            logger.warning(f"Error ensuring schema {current_db}.{current_schema}: {e}")

        # Ensure each tag exists
        for tag_name in TAG_DEFINITIONS.keys():
            fq_tag = f"{current_db}.{current_schema}.{tag_name}"
            try:
                exists = self._tag_exists(current_db, current_schema, tag_name)
                if not exists:
                    self.connector.execute_non_query(f"CREATE TAG {fq_tag}")
                    logger.info(f"Created tag {fq_tag}")
            except Exception as e:
                logger.error(f"Failed creating tag {fq_tag}: {e}")

    def _tag_exists(self, database: str, schema: str, tag_name: str) -> bool:
        try:
            rows = self.connector.execute_query(
                """
                SELECT 1
                FROM SNOWFLAKE.ACCOUNT_USAGE.TAGS
                WHERE TAG_DATABASE = %(db)s AND TAG_SCHEMA = %(schema)s AND TAG_NAME = %(name)s
                LIMIT 1
                """,
                {"db": database, "schema": schema, "name": tag_name},
            )
            return len(rows) > 0
        except Exception:
            # Fallback: attempt to show tags and filter
            try:
                rows = self.connector.execute_query("SHOW TAGS")
                for r in rows:
                    if (
                        r.get("name", "").upper() == tag_name.upper()
                        and r.get("database_name", "").upper() == database.upper()
                        and r.get("schema_name", "").upper() == schema.upper()
                    ):
                        return True
            except Exception:
                pass
            return False

    def validate_tags(self, tags: Dict[str, str]) -> None:
        for k, v in tags.items():
            if k not in TAG_DEFINITIONS:
                raise ValueError(f"Unsupported tag: {k}")
            allowed = TAG_DEFINITIONS[k]
            # Allow any valid YYYY-MM-DD for date tags
            if allowed == "__DATE__":
                sv = str(v)
                if not re.match(r"^\d{4}-\d{2}-\d{2}$", sv):
                    raise ValueError(f"Invalid date format for {k}: '{v}'. Expected YYYY-MM-DD")
                continue
            # Standard enumeration validation (supports CSV for COMPLIANCE_FRAMEWORKS)
            if isinstance(allowed, list):
                sv = str(v)
                if k == "COMPLIANCE_FRAMEWORKS" and ("," in sv):
                    parts = [p.strip() for p in sv.split(",") if p.strip()]
                    bad = [p for p in parts if p not in allowed]
                    if bad:
                        raise ValueError(f"Invalid value(s) {bad} for tag {k}. Allowed: {allowed}")
                else:
                    if sv not in allowed:
                        raise ValueError(f"Invalid value '{v}' for tag {k}. Allowed: {allowed}")
            else:
                # Fallback: treat as free-form (shouldn't happen)
                pass

    def apply_tags_to_object(
        self,
        full_name: str,
        object_type: str,
        tags: Dict[str, str],
    ) -> None:
        """
        Apply tags to a Snowflake object.
        full_name: database.schema.object
        object_type: TABLE|VIEW|SCHEMA|DATABASE
        tags: dict of {TAG_NAME: value}
        """
        # Auto-augment lifecycle tags when classification/CIA present
        augmented = dict(tags)
        if any(k in augmented for k in ("DATA_CLASSIFICATION", "CONFIDENTIALITY_LEVEL", "INTEGRITY_LEVEL", "AVAILABILITY_LEVEL")):
            today = date.today().isoformat()
            augmented.setdefault("LAST_CLASSIFIED_DATE", today)
            augmented.setdefault("REVIEW_STATUS", "Reviewed")
        self.validate_tags(augmented)
        self._enforce_policy_minimums(full_name, augmented)
        self.initialize_tagging()

        db, schema, obj = self._split_fqn(full_name)
        
        current_tag_db = self.tag_db
        current_tag_schema = self.tag_schema
        
        assignments = ", ".join(
            [
                f"{current_tag_db}.{current_tag_schema}.{k} = '{v}'"
                for k, v in augmented.items()
            ]
        )
        sql = f"ALTER {object_type} {self._q(db)}.{self._q(schema)}.{self._q(obj)} SET TAG {assignments}"
        logger.info(f"Applying tags to {object_type} {full_name}: {tags}")
        self.connector.execute_non_query(sql)

    def apply_tags_to_column(
        self,
        full_table_name: str,
        column_name: str,
        tags: Dict[str, str],
    ) -> None:
        # Auto-augment lifecycle tags when classification/CIA present
        augmented = dict(tags)
        if any(k in augmented for k in ("DATA_CLASSIFICATION", "CONFIDENTIALITY_LEVEL", "INTEGRITY_LEVEL", "AVAILABILITY_LEVEL")):
            today = date.today().isoformat()
            augmented.setdefault("LAST_CLASSIFIED_DATE", today)
            augmented.setdefault("REVIEW_STATUS", "Reviewed")
        self.validate_tags(augmented)
        self._enforce_policy_minimums(full_table_name, augmented)
        self.initialize_tagging()
        db, schema, table = self._split_fqn(full_table_name)
        
        current_tag_db = self.tag_db
        current_tag_schema = self.tag_schema

        assignments = ", ".join(
            [
                f"{current_tag_db}.{current_tag_schema}.{k} = '{v}'"
                for k, v in augmented.items()
            ]
        )
        sql = (
            f"ALTER TABLE {self._q(db)}.{self._q(schema)}.{self._q(table)} MODIFY COLUMN {self._q(column_name)} SET TAG {assignments}"
        )
        logger.info(f"Applying tags to column {full_table_name}.{column_name}: {tags}")
        self.connector.execute_non_query(sql)

    def get_object_tags(self, full_name: str, object_type: str = "TABLE") -> List[Dict]:
        """Return tags applied to object and its columns using ACCOUNT_USAGE.TAG_REFERENCES.
        Falls back to empty list if ACCOUNT_USAGE is not accessible.
        """
        try:
            db, schema, obj = full_name.split(".")
        except ValueError:
            return []
        try:
            # Object-level refs (COLUMN_NAME is NULL)
            object_refs = self.connector.execute_query(
                """
                SELECT OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, NULL AS COLUMN_NAME, TAG_NAME, TAG_VALUE
                FROM "SNOWFLAKE"."ACCOUNT_USAGE"."TAG_REFERENCES"
                WHERE OBJECT_DATABASE = %(db)s AND OBJECT_SCHEMA = %(schema)s AND OBJECT_NAME = %(obj)s
                  AND COLUMN_NAME IS NULL
                """,
                {"db": db, "schema": schema, "obj": obj},
            ) or []
        except Exception as e:
            logger.warning(f"ACCOUNT_USAGE.TAG_REFERENCES object-level failed for {full_name}: {e}")
            object_refs = []
        try:
            # Column-level refs (COLUMN_NAME is NOT NULL)
            column_refs = self.connector.execute_query(
                """
                SELECT OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME, TAG_NAME, TAG_VALUE
                FROM "SNOWFLAKE"."ACCOUNT_USAGE"."TAG_REFERENCES"
                WHERE OBJECT_DATABASE = %(db)s AND OBJECT_SCHEMA = %(schema)s AND OBJECT_NAME = %(obj)s
                  AND COLUMN_NAME IS NOT NULL
                """,
                {"db": db, "schema": schema, "obj": obj},
            ) or []
        except Exception as e:
            logger.warning(f"ACCOUNT_USAGE.TAG_REFERENCES column-level failed for {full_name}: {e}")
            column_refs = []
        return object_refs + column_refs

    def get_bulk_object_tags(self, full_names: List[str]) -> List[Dict]:
        """Return tags for multiple objects and their columns in a single batch query."""
        if not full_names:
            return []
        
        # Group objects by database to handle potential account-wide scale efficiently
        db_groups = {}
        for fn in full_names:
            try:
                db = fn.split(".")[0]
                db_groups.setdefault(db, []).append(fn)
            except Exception:
                continue
                
        results = []
        for db, fns in db_groups.items():
            # Process in chunks of 50 to avoid excessively long SQL strings or parameter limits
            for i in range(0, len(fns), 50):
                chunk = fns[i:i+50]
                try:
                    # Construct matching predicates for database, schema, and object name
                    # Filter by DB first to narrow down ACCOUNT_USAGE scan if possible
                    in_list = ", ".join([f"'{x}'" for x in chunk])
                    rows = self.connector.execute_query(
                        f"""
                        SELECT OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME, TAG_NAME, TAG_VALUE
                        FROM "SNOWFLAKE"."ACCOUNT_USAGE"."TAG_REFERENCES"
                        WHERE OBJECT_DATABASE = %(db)s
                          AND (OBJECT_DATABASE || '.' || OBJECT_SCHEMA || '.' || OBJECT_NAME) IN ({in_list})
                        """,
                        {"db": db}
                    ) or []
                    results.extend(rows)
                except Exception as e:
                    logger.warning(f"Bulk tag retrieval failed for DB {db}, chunk starting {i}: {e}")
        return results

    def bulk_apply_classification(
        self,
        schema_full_name: str,
        classification: str,
        cia_conf: int,
        cia_int: int,
        cia_avail: int,
    ) -> int:
        """Apply same classification tags to all tables in a schema. Returns count updated."""
        self.validate_tags({
            "DATA_CLASSIFICATION": classification,
            "CONFIDENTIALITY_LEVEL": str(cia_conf),
            "INTEGRITY_LEVEL": str(cia_int),
            "AVAILABILITY_LEVEL": str(cia_avail),
        })
        db, schema = schema_full_name.split(".")
        tables = self.connector.execute_query(
            f"""
            SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME
            FROM {db}.INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = '{schema}' AND TABLE_TYPE IN ('BASE TABLE','VIEW')
            """
        )
        count = 0
        for r in tables:
            full = f"{r['TABLE_CATALOG']}.{r['TABLE_SCHEMA']}.{r['TABLE_NAME']}"
            try:
                self.apply_tags_to_object(
                    full,
                    "TABLE",
                    {
                        "DATA_CLASSIFICATION": classification,
                        "CONFIDENTIALITY_LEVEL": str(cia_conf),
                        "INTEGRITY_LEVEL": str(cia_int),
                        "AVAILABILITY_LEVEL": str(cia_avail),
                    },
                )
                count += 1
            except Exception as e:
                logger.error(f"Failed to tag {full}: {e}")
        return count

    def generate_tag_sql_for_object(self, full_name: str, object_type: str, tags: Dict[str, str]) -> str:
        db, schema, obj = self._split_fqn(full_name)
        tag_db = self.tag_db
        tag_schema = self.tag_schema
        assignments = ", ".join([f"{tag_db}.{tag_schema}.{k} = '{v}'" for k, v in tags.items()])
        return f"ALTER {object_type} {self._q(db)}.{self._q(schema)}.{self._q(obj)} SET TAG {assignments}"

    def generate_tag_sql_for_column(self, full_table_name: str, column_name: str, tags: Dict[str, str]) -> str:
        db, schema, table = self._split_fqn(full_table_name)
        tag_db = self.tag_db
        tag_schema = self.tag_schema
        assignments = ", ".join([f"{tag_db}.{tag_schema}.{k} = '{v}'" for k, v in tags.items()])
        return (
            f"ALTER TABLE {self._q(db)}.{self._q(schema)}.{self._q(table)} "
            f"MODIFY COLUMN {self._q(column_name)} SET TAG {assignments}"
        )

    def suggest_tags_from_criteria(self, classification: str, c: int, i: int, a: int) -> Dict[str, str]:
        classification = (classification or "Internal").title()
        c = max(0, min(3, int(c)))
        i = max(0, min(3, int(i)))
        a = max(0, min(3, int(a)))
        return {
            "DATA_CLASSIFICATION": classification,
            "CONFIDENTIALITY_LEVEL": str(c),
            "INTEGRITY_LEVEL": str(i),
            "AVAILABILITY_LEVEL": str(a),
        }

    def explain_tag(self, tag_name: str, value: Optional[str] = None) -> Dict:
        tag = str(tag_name or "").upper()
        allowed = TAG_DEFINITIONS.get(tag, [])
        info = {
            "tag": tag,
            "allowed_values": allowed,
            "value": value,
        }
        desc = {
            "DATA_CLASSIFICATION": "Overall data sensitivity label",
            "CONFIDENTIALITY_LEVEL": "C level: 0 Public, 1 Internal, 2 Restricted, 3 Confidential",
            "INTEGRITY_LEVEL": "I level: 0 Low, 1 Standard, 2 High, 3 Critical",
            "AVAILABILITY_LEVEL": "A level: 0 Low, 1 Standard, 2 High, 3 Critical",
            "SPECIAL_CATEGORY": "Sensitive category such as PII/PHI/PCI/SOX",
            "COMPLIANCE_CATEGORY": "Applicable regulations (e.g., GDPR, HIPAA, PCI DSS)",
            "LAST_CLASSIFIED_DATE": "YYYY-MM-DD date when last classified",
            "LAST_REVIEW_DATE": "YYYY-MM-DD date when last reviewed",
            "REVIEW_STATUS": "Review workflow status",
            "MASKING_OVERRIDE": "Whether to override masking enforcement",
            "MASKING_EXEMPT": "Whether object/column is exempt from masking",
        }
        info["description"] = desc.get(tag, "")
        if value is not None and isinstance(allowed, list) and allowed and value not in allowed and allowed != "__DATE__":
            info["validation"] = f"Invalid value '{value}'. Allowed: {allowed}"
        return info

    def diagnose(self, full_name: Optional[str], object_type: Optional[str], tags: Optional[Dict[str, str]], error_message: str) -> List[str]:
        msg = str(error_message or "")
        suggestions: List[str] = []
        try:
            if tags:
                try:
                    self.validate_tags(tags)
                except Exception as e:
                    suggestions.append(str(e))
            if full_name and object_type and tags:
                try:
                    if object_type.upper() in ("TABLE", "VIEW"):
                        db, schema, obj = self._split_fqn(full_name)
                        _ = self.connector.execute_query(
                            f"SELECT 1 FROM {self._q(db)}.INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = '{schema}' AND TABLE_NAME = '{obj}' LIMIT 1"
                        )
                except Exception:
                    pass
            m = msg.lower()
            if "not authorized" in m or "insufficient privileges" in m or "not enough privileges" in m:
                suggestions.append("Grant OWNERSHIP or ALTER on the object and USAGE on database/schema; use a role with privileges")
            if "does not exist" in m or "object does not exist" in m:
                suggestions.append("Verify DB.SCHEMA.OBJECT and case/quoting; ensure object exists in current account")
            if "tag" in m and "does not exist" in m:
                if tags:
                    current_db = self.tag_db
                    current_schema = self.tag_schema
                    for k in tags.keys():
                        if not self._tag_exists(current_db, current_schema, k):
                            suggestions.append(f"Tag {current_db}.{current_schema}.{k} is missing; initialize tagging or create tag")
            if "invalid identifier" in m:
                suggestions.append("Quote identifiers with double quotes if mixed-case or special chars")
            if "cannot modify" in m and "column" in m:
                suggestions.append("Ensure column exists and you used ALTER TABLE ... MODIFY COLUMN syntax")
            if not suggestions:
                suggestions.append("Check current role, warehouse, and context; confirm tag allowed values and object existence")
        except Exception:
            pass
        return suggestions


tagging_service = TaggingService()

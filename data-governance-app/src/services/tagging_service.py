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
    try:
        rows = connector.execute_query(
            """
            SELECT VALUE 
            FROM DATA_CLASSIFICATION_GOVERNANCE.TAG_ALLOWED_VALUES
            WHERE TAG_TYPE = %(type)s
            ORDER BY DISPLAY_ORDER, VALUE
            """,
            {"type": value_type}
        ) or []
        return [str(r["VALUE"]) for r in rows]
    except Exception as e:
        print(f"Warning: Could not load allowed values for {value_type}: {str(e)}")
        # Default fallback values if database is not available
        defaults = {
            "CLASSIFICATION": ["Public", "Internal", "Restricted", "Confidential"],
            "CIA_LEVEL": ["0", "1", "2", "3"],
            "SPECIAL_CATEGORY": ["PII", "PHI", "PCI", "SOX", "Financial", "Auth", "Confidential", "Other"],
            "COMPLIANCE_CATEGORY": ["GDPR", "CCPA", "HIPAA", "SOX", "PCI DSS", "SOC", "Internal/Other"],
            "REVIEW_STATUS": ["Pending Reclassification", "Due Soon", "Overdue", "Reviewed"]
        }
        return defaults.get(value_type, [])

TAG_DB = settings.SNOWFLAKE_DATABASE
TAG_SCHEMA = "DATA_GOVERNANCE"

def get_tag_definitions() -> Dict[str, Any]:
    """Load all tag definitions from the database with fallback to defaults."""
    return {
        # Classification and CIA levels
        "DATA_CLASSIFICATION": _load_allowed_values(snowflake_connector, "CLASSIFICATION"),
        "CONFIDENTIALITY_LEVEL": _load_allowed_values(snowflake_connector, "CIA_LEVEL"),
        "INTEGRITY_LEVEL": _load_allowed_values(snowflake_connector, "CIA_LEVEL"),
        "AVAILABILITY_LEVEL": _load_allowed_values(snowflake_connector, "CIA_LEVEL"),
        
        # Data categories and compliance
        "SPECIAL_CATEGORY": _load_allowed_values(snowflake_connector, "SPECIAL_CATEGORY"),
        "COMPLIANCE_CATEGORY": _load_allowed_values(snowflake_connector, "COMPLIANCE_CATEGORY"),
        
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


class TaggingService:
    def __init__(self):
        self.connector = snowflake_connector

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
            # Load patterns from database
            patterns = {}
            
            # Load sensitive patterns
            rows = self.connector.execute_query("""
                SELECT 
                    CATEGORY,
                    PATTERN,
                    SENSITIVITY_LEVEL,
                    IS_STRICT
                FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVE_PATTERNS
                WHERE IS_ACTIVE = TRUE
                ORDER BY PRIORITY DESC
            """) or []
            
            # Group patterns by category
            for row in rows:
                category = str(row['CATEGORY'])
                if category not in patterns:
                    patterns[category] = {
                        'sensitivity_level': int(row['SENSITIVITY_LEVEL']),
                        'is_strict': bool(row['IS_STRICT']),
                        'keywords': []
                    }
                patterns[category]['keywords'].append(str(row['PATTERN']).upper())
            
            # Load sensitivity levels
            levels = {}
            rows = self.connector.execute_query("""
                SELECT 
                    LEVEL_NAME,
                    LEVEL_VALUE,
                    DISPLAY_NAME
                FROM DATA_CLASSIFICATION_GOVERNANCE.SENSITIVITY_LEVELS
                ORDER BY LEVEL_VALUE
            """) or []
            
            for row in rows:
                levels[int(row['LEVEL_VALUE'])] = {
                    'name': str(row['LEVEL_NAME']),
                    'display': str(row['DISPLAY_NAME'])
                }
            
            return {
                'patterns': patterns,
                'levels': levels
            }
            
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
            compliance = (tags.get("COMPLIANCE_CATEGORY") or "").strip()
            # Normalize to set for easy checks (COMPLIANCE_CATEGORY may be CSV)
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
        try:
            self.connector.execute_non_query(
                f"CREATE SCHEMA IF NOT EXISTS {TAG_DB}.{TAG_SCHEMA}"
            )
        except Exception as e:
            logger.warning(f"Error ensuring schema {TAG_DB}.{TAG_SCHEMA}: {e}")

        # Ensure each tag exists
        for tag_name in TAG_DEFINITIONS.keys():
            fq_tag = f"{TAG_DB}.{TAG_SCHEMA}.{tag_name}"
            try:
                exists = self._tag_exists(TAG_DB, TAG_SCHEMA, tag_name)
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
            # Standard enumeration validation (supports CSV for COMPLIANCE_CATEGORY)
            if isinstance(allowed, list):
                sv = str(v)
                if k == "COMPLIANCE_CATEGORY" and ("," in sv):
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
        assignments = ", ".join(
            [
                f"{TAG_DB}.{TAG_SCHEMA}.{k} = '{v}'"
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
        assignments = ", ".join(
            [
                f"{TAG_DB}.{TAG_SCHEMA}.{k} = '{v}'"
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


tagging_service = TaggingService()

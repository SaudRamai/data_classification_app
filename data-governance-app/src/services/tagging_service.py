"""
Snowflake Tagging Service
- Ensures standardized tag schema exists (DATA_CLASSIFICATION, CONFIDENTIALITY_LEVEL, INTEGRITY_LEVEL, AVAILABILITY_LEVEL)
- Validates allowed values and applies tags to Snowflake objects (TABLE/VIEW/COLUMN)
- Retrieves tags for objects
- Adds lifecycle review tags (LAST_CLASSIFIED_DATE, LAST_REVIEW_DATE, REVIEW_STATUS) and auto-populates
  LAST_CLASSIFIED_DATE/REVIEW_STATUS when classification/CIA tags are applied.
"""
from typing import Dict, List, Optional
import logging
from datetime import date
import re

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)


ALLOWED_CLASSIFICATIONS = ["Public", "Internal", "Restricted", "Confidential"]
ALLOWED_CIA = ["0", "1", "2", "3"]  # store as strings in tags
ALLOWED_SPECIAL_CATEGORIES = [
    "PII", "PHI", "PCI", "Financial", "Auth", "Confidential", "Other"
]
ALLOWED_COMPLIANCE_CATEGORIES = [
    "GDPR", "CCPA", "HIPAA", "SOX", "PCI DSS", "SOC", "Internal/Other"
]
ALLOWED_REVIEW_STATUS = [
    "Pending Reclassification", "Due Soon", "Overdue", "Reviewed"
]

TAG_DB = settings.SNOWFLAKE_DATABASE
TAG_SCHEMA = "DATA_GOVERNANCE"

TAG_DEFINITIONS = {
    "DATA_CLASSIFICATION": ALLOWED_CLASSIFICATIONS,
    "CONFIDENTIALITY_LEVEL": ALLOWED_CIA,
    "INTEGRITY_LEVEL": ALLOWED_CIA,
    "AVAILABILITY_LEVEL": ALLOWED_CIA,
    # New tags to capture detected sensitive category and mapped compliance frameworks
    "SPECIAL_CATEGORY": ALLOWED_SPECIAL_CATEGORIES,
    # COMPLIANCE_CATEGORY supports multi-valued CSV (e.g., "GDPR,CCPA"). Validation ensures each value is allowed.
    "COMPLIANCE_CATEGORY": ALLOWED_COMPLIANCE_CATEGORIES,
    # Lifecycle & Review tags
    # Dates must be YYYY-MM-DD; REVIEW_STATUS from ALLOWED_REVIEW_STATUS
    "LAST_CLASSIFIED_DATE": "__DATE__",
    "LAST_REVIEW_DATE": "__DATE__",
    "REVIEW_STATUS": ALLOWED_REVIEW_STATUS,
    # Explicit enforcement override for masking (TRUE/FALSE)
    "MASKING_EXEMPT": ["TRUE", "FALSE"],
}


class TaggingService:
    def __init__(self):
        self.connector = snowflake_connector

    # --- Identifier helpers ---
    def _split_fqn(self, fq: str) -> tuple[str, str, str]:
        s = str(fq or "")
        if not s:
            raise ValueError("Empty FQN")
        parts: list[str] = []
        buf: list[str] = []
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

    # --- Policy 5.5 enforcement helper ---
    def _required_minimums(self, asset_full_name: str) -> tuple[int, str]:
        """Return (min_confidentiality_level, min_label) based on asset name heuristics.
        Heuristics mirror UI logic and Policy 5.5 for PII/Financial/SOX.
        """
        up = (asset_full_name or "").upper()
        min_c = 1
        min_label = "Internal"
        # Sensitive PII keys => C3 Confidential
        if any(k in up for k in ["SSN","NATIONAL_ID","PASSPORT","PAN","AADHAAR"]):
            min_c = max(min_c, 3)
            min_label = "Confidential"
        # PII baseline => C2 Restricted
        if any(k in up for k in ["SSN","EMAIL","PHONE","ADDRESS","DOB","PII","PERSON","EMPLOYEE","CUSTOMER"]):
            min_c = max(min_c, 2)
            if min_c < 3:
                min_label = "Restricted"
        # Financial/SOX cues => at least C2 Restricted (elevate to C3 for strong cues)
        if any(k in up for k in ["SOX","FINANCIAL_REPORT","GL","LEDGER","REVENUE","EXPENSE","PAYROLL","AUDIT","IFRS","GAAP"]):
            min_c = max(min_c, 2)
            if "SOX" in up or "FINANCIAL_REPORT" in up or "AUDIT" in up or "IFRS" in up or "GAAP" in up:
                min_c = max(min_c, 3)
            min_label = "Confidential" if min_c >= 3 else "Restricted"
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

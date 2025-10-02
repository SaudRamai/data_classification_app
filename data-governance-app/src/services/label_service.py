"""
Label Management Service
- Centralized label registry with visual indicators and automated enforcement mappings
- Integrates with Snowflake tags via TaggingService
"""
from typing import List, Dict, Any, Optional
import logging

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

logger = logging.getLogger(__name__)

DB = settings.SNOWFLAKE_DATABASE
SCHEMA = "DATA_GOVERNANCE"
TABLE = "LABEL_REGISTRY"


class LabelService:
    def __init__(self) -> None:
        self.connector = snowflake_connector
        self._ensure_table()

    def _ensure_table(self) -> None:
        try:
            self.connector.execute_non_query(f"CREATE SCHEMA IF NOT EXISTS {DB}.{SCHEMA}")
            self.connector.execute_non_query(
                f"""
                CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.{TABLE} (
                    LABEL_NAME STRING PRIMARY KEY,
                    DESCRIPTION STRING,
                    COLOR STRING,
                    DEFAULT_C NUMBER,
                    DEFAULT_I NUMBER,
                    DEFAULT_A NUMBER,
                    ENFORCEMENT_POLICY STRING
                )
                """
            )
            # Seed defaults if empty
            cnt = self.connector.execute_query(
                f"SELECT COUNT(*) AS C FROM {DB}.{SCHEMA}.{TABLE}"
            )[0]["C"]
            if cnt == 0:
                self.seed_defaults()
        except Exception as e:
            logger.error(f"Failed ensuring label registry: {e}")

    def seed_defaults(self) -> None:
        defaults = [
            ("Public", "Low sensitivity data; open access", "#2ECC71", 0, 0, 0, "ROW_ACCESS=NONE;MASKING=NONE"),
            ("Internal", "Company-internal data", "#F1C40F", 1, 1, 1, "ROW_ACCESS=STANDARD;MASKING=LIGHT"),
            ("Restricted", "Sensitive business data", "#E67E22", 2, 2, 2, "ROW_ACCESS=STRICT;MASKING=STRONG"),
            ("Confidential", "Highly sensitive data (PII/SOX)", "#E74C3C", 3, 3, 3, "ROW_ACCESS=VERY_STRICT;MASKING=MAX"),
        ]
        for name, desc, color, c, i, a, pol in defaults:
            try:
                self.connector.execute_non_query(
                    f"""
                    MERGE INTO {DB}.{SCHEMA}.{TABLE} t
                    USING (SELECT %(n)s AS LABEL_NAME) s
                    ON t.LABEL_NAME = s.LABEL_NAME
                    WHEN NOT MATCHED THEN INSERT (LABEL_NAME, DESCRIPTION, COLOR, DEFAULT_C, DEFAULT_I, DEFAULT_A, ENFORCEMENT_POLICY)
                    VALUES (%(n)s, %(d)s, %(col)s, %(c)s, %(i)s, %(a)s, %(p)s)
                    """,
                    {"n": name, "d": desc, "col": color, "c": c, "i": i, "a": a, "p": pol},
                )
            except Exception as e:
                logger.warning(f"Failed seeding label {name}: {e}")

    def list_labels(self) -> List[Dict[str, Any]]:
        try:
            return self.connector.execute_query(
                f"SELECT * FROM {DB}.{SCHEMA}.{TABLE} ORDER BY LABEL_NAME"
            )
        except Exception as e:
            logger.error(f"Failed listing labels: {e}")
            return []

    def upsert_label(
        self,
        label_name: str,
        description: str,
        color: str,
        default_c: int,
        default_i: int,
        default_a: int,
        policy: str,
    ) -> None:
        self.connector.execute_non_query(
            f"""
            MERGE INTO {DB}.{SCHEMA}.{TABLE} t
            USING (SELECT %(n)s AS LABEL_NAME) s
            ON t.LABEL_NAME = s.LABEL_NAME
            WHEN MATCHED THEN UPDATE SET DESCRIPTION=%(d)s, COLOR=%(col)s, DEFAULT_C=%(c)s, DEFAULT_I=%(i)s, DEFAULT_A=%(a)s, ENFORCEMENT_POLICY=%(p)s
            WHEN NOT MATCHED THEN INSERT (LABEL_NAME, DESCRIPTION, COLOR, DEFAULT_C, DEFAULT_I, DEFAULT_A, ENFORCEMENT_POLICY)
            VALUES (%(n)s, %(d)s, %(col)s, %(c)s, %(i)s, %(a)s, %(p)s)
            """,
            {"n": label_name, "d": description, "col": color, "c": default_c, "i": default_i, "a": default_a, "p": policy},
        )

    def delete_label(self, label_name: str) -> None:
        self.connector.execute_non_query(
            f"DELETE FROM {DB}.{SCHEMA}.{TABLE} WHERE LABEL_NAME = %(n)s",
            {"n": label_name},
        )

# Lazy singleton accessor to avoid executing DB operations at import time
_label_service: Optional[LabelService] = None

def get_label_service() -> LabelService:
    global _label_service
    if _label_service is None:
        _label_service = LabelService()
    return _label_service

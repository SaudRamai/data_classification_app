"""
Testing Service for governance app
- Connectivity test
- Table/column search
- Table health tests (row count, sample, tag presence)
"""
from typing import List, Dict, Any, Optional
import logging

from src.connectors.snowflake_connector import snowflake_connector
from src.services.tagging_service import tagging_service
from src.config.settings import settings

logger = logging.getLogger(__name__)


class TestingService:
    def __init__(self) -> None:
        self.connector = snowflake_connector

    def connectivity_test(self) -> bool:
        try:
            self.connector.execute_query("SELECT CURRENT_ACCOUNT(), CURRENT_ROLE(), CURRENT_WAREHOUSE()")
            return True
        except Exception as e:
            logger.error(f"Connectivity test failed: {e}")
            return False

    def search_tables(self, query: str, limit: int = 200) -> List[Dict[str, Any]]:
        like = f"%{query}%"
        sql = f"""
        SELECT 
            TABLE_CATALOG || '.' || TABLE_SCHEMA || '.' || TABLE_NAME AS FULL_NAME,
            TABLE_SCHEMA AS SCHEMA_NAME,
            TABLE_NAME,
            ROW_COUNT,
            LAST_ALTERED
        FROM {settings.SNOWFLAKE_DATABASE}.INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA')
          AND (TABLE_NAME ILIKE %(q)s OR TABLE_SCHEMA ILIKE %(q)s)
        ORDER BY TABLE_SCHEMA, TABLE_NAME
        LIMIT %(lim)s
        """
        return self.connector.execute_query(sql, {"q": like, "lim": limit})

    def search_columns(self, query: str, limit: int = 500) -> List[Dict[str, Any]]:
        like = f"%{query}%"
        sql = f"""
        SELECT 
            TABLE_CATALOG || '.' || TABLE_SCHEMA || '.' || TABLE_NAME AS FULL_NAME,
            COLUMN_NAME,
            DATA_TYPE
        FROM {settings.SNOWFLAKE_DATABASE}.INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA NOT IN ('INFORMATION_SCHEMA')
          AND (COLUMN_NAME ILIKE %(q)s OR TABLE_NAME ILIKE %(q)s)
        ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION
        LIMIT %(lim)s
        """
        return self.connector.execute_query(sql, {"q": like, "lim": limit})

    def sample_table(self, full_name: str, limit: int = 100) -> List[Dict[str, Any]]:
        return self.connector.execute_query(f"SELECT * FROM {full_name} LIMIT {limit}")

    def table_row_count(self, full_name: str) -> int:
        res = self.connector.execute_query(f"SELECT COUNT(*) AS C FROM {full_name}")
        return int(res[0]["C"]) if res else 0

    def has_governance_tags(self, full_name: str) -> bool:
        refs = tagging_service.get_object_tags(full_name, object_type="TABLE")
        needed = {"DATA_CLASSIFICATION", "CONFIDENTIALITY_LEVEL", "INTEGRITY_LEVEL", "AVAILABILITY_LEVEL"}
        present = {r.get("TAG_NAME", "").upper() for r in refs}
        return bool(needed & present)

    def run_table_tests(self, full_name: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "table": full_name,
            "connectivity": False,
            "row_count": 0,
            "has_tags": False,
            "sample_ok": False,
        }
        results["connectivity"] = self.connectivity_test()
        try:
            results["row_count"] = self.table_row_count(full_name)
            sample = self.sample_table(full_name, limit=5)
            results["sample_ok"] = len(sample) >= 0  # succeeds even with 0 rows
            results["has_tags"] = self.has_governance_tags(full_name)
        except Exception as e:
            results["error"] = str(e)
        return results


testing_service = TestingService()

"""
Setup Service
- Executes SQL installation scripts for governance artifacts (schema, tags/policies, tasks, RBAC)
- Replaces placeholders with configured Snowflake database/warehouse
"""
from __future__ import annotations

import os
from typing import Dict, Optional, List

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings


SQL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sql")


class SetupService:
    def __init__(self) -> None:
        self.db = settings.SNOWFLAKE_DATABASE
        self.wh = settings.SNOWFLAKE_WAREHOUSE
        self.connector = snowflake_connector

    def _load_sql(self, filename: str) -> str:
        path = os.path.join(SQL_DIR, filename)
        if not os.path.exists(path):
            raise FileNotFoundError(f"SQL file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def _parametrize(self, sql: str, extra_params: Optional[Dict[str, str]] = None) -> str:
        """Replace placeholders like $DATABASE and $WAREHOUSE with settings.
        Also supports any additional keys from extra_params as $KEY.
        """
        out = sql.replace("$DATABASE", self.db).replace("$WAREHOUSE", self.wh)
        if extra_params:
            for k, v in extra_params.items():
                out = out.replace(f"${k}", v)
        return out

    def run_sql_text(self, sql_text: str) -> None:
        # Split on ; while preserving statements (simple split)
        stmts: List[str] = [s.strip() for s in sql_text.split(";") if s.strip()]
        for s in stmts:
            # Ignore line-only comments
            if s.startswith("--"):
                continue
            try:
                self.connector.execute_non_query(s)
            except Exception as e:
                # Continue on errors to be idempotent; callers can review logs
                # You may choose to raise depending on strictness
                raise

    def install_all(self) -> None:
        """Run the full governance install: 001..004 in order."""
        for fname in [
            "001_governance_schema.sql",
            "002_tags_and_policies.sql",
            "004_rbac_scaffolding.sql",
            "003_streams_and_tasks.sql",
        ]:
            sql = self._parametrize(self._load_sql(fname))
            self.run_sql_text(sql)

    def enable_tasks(self) -> None:
        """Resume core tasks."""
        for task in [
            f"{self.db}.DATA_GOVERNANCE.TASK_DISCOVERY_SCAN",
            f"{self.db}.DATA_GOVERNANCE.TASK_QUEUE_PRIORITY",
            f"{self.db}.DATA_GOVERNANCE.TASK_SLA_ALERTS",
        ]:
            try:
                self.connector.execute_non_query(f"ALTER TASK {task} RESUME")
            except Exception:
                # Ignore if insufficient privileges or task missing
                pass


setup_service = SetupService()

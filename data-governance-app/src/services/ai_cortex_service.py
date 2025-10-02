"""
AI Cortex Service
- Uses Snowflake Cortex AISQL to recommend classification tags for a given table
- Produces a structured JSON recommendation with rationale

This service does not change Snowflake state; it only returns recommendations.
"""
from __future__ import annotations

from typing import Dict, Any, List
import json

from src.connectors.snowflake_connector import snowflake_connector


class AICortexService:
    def _get_table_context(self, full_name: str, sample_rows: int = 20) -> Dict[str, Any]:
        """Collect lightweight context about a table to feed to AISQL.
        Context includes column names/types and a tiny content sample (if accessible).
        """
        ctx: Dict[str, Any] = {"full_name": full_name, "columns": [], "sample": []}
        try:
            db, schema, table = full_name.split(".", 2)
        except ValueError:
            # Expect fully qualified name
            return ctx
        # columns (use fully-qualified INFORMATION_SCHEMA; avoid complex binds for compatibility)
        cols = snowflake_connector.execute_query(
            f"""
            SELECT COLUMN_NAME, DATA_TYPE
            FROM {db}.INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = '{schema}' AND TABLE_NAME = '{table}'
            ORDER BY ORDINAL_POSITION
            """
        )
        ctx["columns"] = [{"name": c.get("COLUMN_NAME"), "type": c.get("DATA_TYPE")} for c in cols or []]
        # sample (best effort)
        try:
            rows = snowflake_connector.execute_query(
                f"SELECT * FROM {full_name} LIMIT {int(sample_rows)}"
            )
            # Convert DictCursor rows to plain dicts
            ctx["sample"] = [dict(r) for r in rows]
        except Exception:
            # ignore if no access
            pass
        return ctx

    def recommend_tags_for_table(self, full_name: str) -> Dict[str, Any]:
        """Use SNOWFLAKE.CORTEX.AISQL to recommend classification and CIA tags.
        Returns: { tags: {...}, rationale: str, raw: str }
        """
        ctx = self._get_table_context(full_name)
        # Build prompt that asks for strict JSON
        prompt = (
            "You are a data governance assistant. Given a table description, "
            "recommend Snowflake tag values for classification. Return STRICT JSON with keys: "
            "tags (object), rationale (string). Allowed tags and values: "
            "DATA_GOVERNANCE.DATA_CLASSIFICATION in ['Public','Internal','Restricted','Confidential']; "
            "DATA_GOVERNANCE.INTEGRITY_LEVEL in ['0','1','2','3']; "
            "DATA_GOVERNANCE.AVAILABILITY_LEVEL in ['0','1','2','3'].\n"
            "Set levels using CIA impact based on sensitivity inferred from names, types, and small samples.\n"
            "Example response: {\"tags\":{\"DATA_GOVERNANCE.DATA_CLASSIFICATION\":\"Restricted\",\"DATA_GOVERNANCE.CONFIDENTIALITY_LEVEL\":\"2\",\"DATA_GOVERNANCE.INTEGRITY_LEVEL\":\"1\",\"DATA_GOVERNANCE.AVAILABILITY_LEVEL\":\"1\"},\"rationale\":\"...\"}"
        )
        # Provide context as JSON inside the prompt for simplicity
        ctx_json = json.dumps(ctx, default=str)
        full_prompt = (prompt + "\nContext (JSON):\n" + ctx_json)
        # Escape single quotes for SQL literal
        safe_prompt = full_prompt.replace("'", "''")
        sql = f"SELECT SNOWFLAKE.CORTEX.AISQL('{safe_prompt}') AS RESPONSE"
        rows = snowflake_connector.execute_query(sql)
        raw = rows[0].get("RESPONSE") if rows else ""
        # Try to extract JSON from the model output
        rec: Dict[str, Any] = {"tags": {}, "rationale": "", "raw": raw}
        try:
            # If AISQL returned a JSON string, parse it
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                rec.update({
                    "tags": parsed.get("tags") or {},
                    "rationale": parsed.get("rationale") or "",
                })
        except Exception:
            # Best effort: leave raw
            pass
        return rec


ai_cortex = AICortexService()

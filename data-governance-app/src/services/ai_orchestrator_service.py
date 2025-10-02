"""
AI Orchestrator Service
- End-to-end flow:
  1) Get AI recommendations via AICortexService (SNOWFLAKE.CORTEX.AISQL)
  2) Optionally apply tags via TaggingService
  3) Persist audit entries via AIAuditService

This module is UI-agnostic and safe to call from Streamlit pages.
"""
from __future__ import annotations

from typing import Dict, Any, Optional, Tuple

from src.services.ai_cortex_service import ai_cortex
from src.services.tagging_service import tagging_service
from src.services.ai_audit_service import ai_audit


class AIOrchestratorService:
    def recommend_only(self, table_full_name: str, acting_user: str) -> Dict[str, Any]:
        """Return AI recommendation without mutating tags. Also writes an audit record for transparency."""
        rec = ai_cortex.recommend_tags_for_table(table_full_name)
        tags = rec.get("tags") or {}
        rationale = rec.get("rationale") or ""
        ai_audit.log_decision(
            asset_full_name=table_full_name,
            user_id=acting_user,
            action="AI_RECOMMEND",
            tags=tags,
            rationale=rationale,
            details={"raw": rec.get("raw", "")},
        )
        return rec

    def recommend_and_apply(
        self,
        table_full_name: str,
        acting_user: str,
        object_type: str = "TABLE",
        override_tags: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Get recommendation, optionally override tags, apply to object, and audit both steps.
        Returns the final tags and rationale used.
        """
        # Step 1: recommend
        rec = ai_cortex.recommend_tags_for_table(table_full_name)
        tags = dict(rec.get("tags") or {})
        if override_tags:
            tags.update(override_tags)
        rationale = rec.get("rationale") or ""

        # Audit recommendation regardless of apply success
        ai_audit.log_decision(
            asset_full_name=table_full_name,
            user_id=acting_user,
            action="AI_RECOMMEND",
            tags=tags,
            rationale=rationale,
            details={"raw": rec.get("raw", ""), "override": override_tags or {}},
        )

        # Step 2: apply to object
        tagging_service.apply_tags_to_object(
            full_name=table_full_name,
            object_type=object_type,
            tags=tags,
        )

        # Step 3: audit apply
        ai_audit.log_decision(
            asset_full_name=table_full_name,
            user_id=acting_user,
            action="APPLY_TAGS",
            tags=tags,
            rationale=rationale,
            details={"source": "AI"},
        )

        return {"tags": tags, "rationale": rationale}


ai_orchestrator = AIOrchestratorService()
